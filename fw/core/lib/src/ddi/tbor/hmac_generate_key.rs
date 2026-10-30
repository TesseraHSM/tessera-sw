// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `HmacGenerateKey` command handler.
//!
//! Within an open session, generate a fresh random **variable-length**
//! HMAC key of the caller-selected SHA variant and `key_length`, mask it
//! (AEAD-GCM-256) under the requested
//! [`KeyScope`](tsra_fw_ddi_tbor_types::KeyScope)'s masking key, and
//! return the masked blob.  The key is stamped as the variable-length
//! `VarLenHmacSha*` kind; its length must fall in the variant's
//! `[min, max]` range (SHA-256: 32–64, SHA-384: 48–128, SHA-512: 64–128).
//! The key is **not** persisted on-device: the caller holds the masked
//! blob and passes it back to [`Hmac`](super::hmac) (unmask-on-use),
//! exactly like the security-domain sealing key.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.  The scope's
//! masking key is resolved by [`resolve_masking_key`](super::resolve_masking_key):
//! `Session` scope uses the per-session masking key; `Ephemeral` / `Local`
//! / `SecurityDomain` use the partition / SD masking keys provisioned by
//! `PartFinal` / the SD lifecycle — an unavailable scope fails cheaply
//! before any key is generated.

use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::masked_blob_len;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::TborHmacGenerateKeyReq;
use tsra_fw_ddi_tbor_types::TborHmacGenerateKeyResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmPartState;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::validate_active_session;
use crate::part_state;

/// Map the wire [`HashAlgo`] onto the firmware hash algorithm, the
/// variable-length HMAC vault kind stamped into the masked blob's
/// metadata, and the `[min, max]` key-length range for the variant
/// (matching the reference firmware's `VarLenHmacSha*` bounds:
/// SHA-256 → 32..=64, SHA-384 → 48..=128, SHA-512 → 64..=128).  An
/// unrecognized `HashAlgo` discriminant is rejected with
/// [`HsmError::InvalidArg`].
fn hmac_variant(algo: HashAlgo) -> HsmResult<(HsmHashAlgo, HsmVaultKeyKind, usize, usize)> {
    match algo {
        HashAlgo::Sha256 => Ok((
            HsmHashAlgo::Sha256,
            HsmVaultKeyKind::VarLenHmacSha256,
            32,
            64,
        )),
        HashAlgo::Sha384 => Ok((
            HsmHashAlgo::Sha384,
            HsmVaultKeyKind::VarLenHmacSha384,
            48,
            128,
        )),
        HashAlgo::Sha512 => Ok((
            HsmHashAlgo::Sha512,
            HsmVaultKeyKind::VarLenHmacSha512,
            64,
            128,
        )),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Validate the caller-requested key length against the variant's
/// `[min, max]` range, returning it as a `usize`.  Out-of-range lengths
/// (including `0`) are rejected with [`HsmError::InvalidKeyLength`].
fn validate_key_len(key_length: u8, min: usize, max: usize) -> HsmResult<usize> {
    let len = usize::from(key_length);
    if len < min || len > max {
        return Err(HsmError::InvalidKeyLength);
    }
    Ok(len)
}

/// Attributes recorded in the masked blob's metadata (re-applied on
/// unmask).  An HMAC MAC key is a `C_Sign` / `C_Verify` symmetric key
/// generated on-device; `scope` records the lifecycle / visibility domain
/// selecting the masking key.
fn hmac_key_attrs(scope: HsmKeyScope) -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_sign(true)
        .with_verify(true)
        .with_scope(scope)
}

/// Handle a TBOR `HmacGenerateKey` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it generates a key, masks it, and returns the blob.  It
/// makes no observable state change, so a concurrently-dispatched command
/// can neither observe it half-done nor require its rollback on failure.
/// The masked blob is written straight into the reserved response slot (no
/// scratch copy); IO teardown scrubs the raw key.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<usize> {
        let req = TborHmacGenerateKeyReq::decode(cmd_buf.request())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));

        // Losslessly map the wire `KeyScope` onto the PAL `HsmKeyScope`
        // (byte-identical discriminants; unknown values round-trip and are
        // rejected by `resolve_masking_key`).
        let scope = HsmKeyScope(req.scope().0);
        validate_active_session(pal, io, sess_id)?;

        // Session-scoped keys are masked under the per-session masking key,
        // available to any Active session.  Every other scope's masking key is
        // provisioned by `PartFinal` / the SD lifecycle, so require an
        // `Initialized` partition to fail cheaply and clearly before keygen.
        if scope != HsmKeyScope::Session
            && part_state::part_state(pal, io)? != HsmPartState::Initialized
        {
            return Err(HsmError::InvalidArg);
        }

        let (algo, kind, min_len, max_len) = hmac_variant(req.hash_algo())?;
        let key_len = validate_key_len(req.key_length(), min_len, max_len)?;
        // Caller-supplied label stamped into the masked metadata (≤ 128 B,
        // bounded by the wire `max_len`); empty for an unlabeled key.
        let caller_label = req.key_label();
        // The masked-blob length is fixed by the requested key length
        // (32..=128 B → 264..=360 B), so the response slot can be reserved up
        // front, before any key material exists.
        let masked_len = masked_blob_len(AeadAlg::AesGcm256Iv16, key_len);

        // Platform identity that binds the masked blob (anti-rollback on
        // re-import): SVN (BKS1 lineage) and owner-seed id (BKS2 lineage).
        let svn = part_state::part_mfgr_svn(pal);
        let owner =
            u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
        let attrs = hmac_key_attrs(scope);

        let key_label = alloc.dma_alloc(caller_label.len())?;
        key_label.copy_from_slice(caller_label);
        let len = cmd_buf.encode_response(|buf| {
            Ok(TborHmacGenerateKeyResp::encode(buf, 0, false)?
                .masked_key_reserve(masked_len)?
                .finish()
                .as_bytes()
                .len())
        })?;

        // Generate the key and mask it straight into its final slot.
        {
            let out = TborHmacGenerateKeyResp::decode_mut(&mut cmd_buf.buffer_mut()[..len])?;
            // Generate the random HMAC key into scratch.
            let key_buf = alloc.dma_alloc(key_len)?;
            let mask_res = async {
                pal.hmac_gen_key(io, algo, key_buf).await?;
                let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
                let params = MaskParams {
                    key_kind: kind,
                    key_attrs: attrs,
                    svn,
                    owner_seed_id: owner,
                    key_label,
                };
                // Mask straight into the reserved response slot.
                mask(
                    pal,
                    io,
                    alloc,
                    AeadAlg::AesGcm256Iv16,
                    masking_key,
                    &params,
                    key_buf,
                    Some(out.masked_key),
                )
                .await
            }
            .await;
            // `mask` leaves any trailing bytes of the reserved slot
            // untouched; the slot was reserved to exactly `masked_len`, so a
            // short write would leave uninitialized bytes in the response.
            let written = mask_res?;
            if written != masked_len {
                return Err(HsmError::InternalError);
            }
        }

        Ok(len)
    })
    .await
}
