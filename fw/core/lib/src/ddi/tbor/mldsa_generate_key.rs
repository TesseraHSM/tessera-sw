// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaGenerateKey` command handler.
//!
//! Generates into the shared exchange's final response slots, then masks
//! the seed and expanded private key in place. IO teardown scrubs the exchange.

use tsra_fw_core_crypto_key_masking::aead::mask_in_place;
use tsra_fw_core_crypto_key_masking::aead::masked_blob_len;
use tsra_fw_core_crypto_key_masking::aead::payload_offset;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::MlDsaKeyKind;
use tsra_fw_ddi_tbor_types::TborMlDsaGenerateKeyReq;
use tsra_fw_ddi_tbor_types::TborMlDsaGenerateKeyResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::validate_active_session;
use crate::part_state;

/// Handle a TBOR `MlDsaGenerateKey` request.
///
/// Persists nothing, so it needs neither a partition lock nor an undo log.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    async {
        let req = TborMlDsaGenerateKeyReq::decode(cmd_buf.request())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_active_session(pal, io, sess_id)?;
        let scope = req.scope();
        let key_kind = req.key_kind();

        // The wire is seed-only: the expanded (`Private`) kinds are not
        // offered, so anything outside the three seed kinds is malformed.
        match key_kind {
            MlDsaKeyKind::MlDsa44Seed | MlDsaKeyKind::MlDsa65Seed | MlDsaKeyKind::MlDsa87Seed => {}
            _ => return Err(HsmError::InvalidArg),
        }

        // No scope gate here: the masking key for `scope` is resolved (and its
        // availability validated per-scope) at mask time by
        // `resolve_masking_key`, which returns `UnsupportedKeyScope` for a
        // scope whose masking key has not been provisioned.  Mirrors
        // `EccGenerateKey` / `EcdhDerive` / `UnwrapKey`.  The old
        // `Ephemeral | Local` gate dated from the out-of-session bring-up,
        // when there was no session to scope a key to; these commands are
        // in-session now, so the restriction no longer has a reason.

        // Map the wire kind onto the vault kind the PAL speaks. Byte-identical
        // discriminants, and the match above already rejected anything else.
        let vault_kind = HsmVaultKeyKind(key_kind.0);
        let pub_len = mldsa_pub_key_len(vault_kind)?;

        // Platform identity bound into the masked blob (anti-rollback on
        // re-import): SVN and owner-seed id.
        let svn = part_state::part_mfgr_svn(pal);
        let owner =
            u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
        let attrs = mldsa_key_attrs(HsmKeyScope(scope.0));

        // One contiguous blob holding the seed followed by the expanded secret
        // key, masked as a unit. Keeping the seed means the public key can
        // still be regenerated from the blob alone; keeping the expanded key
        // means signing never has to re-derive it.
        let sec_len = mldsa_sec_key_len(vault_kind)?;
        let plain_len = MLDSA_SEED_LEN + sec_len;

        // IO teardown wipes the allocation,
        // including partially written secrets.
        let masked_len = masked_blob_len(AeadAlg::AesGcm256Iv16, plain_len);
        let payload_at = payload_offset(AeadAlg::AesGcm256Iv16);

        // Reserve both output slots up front so the fastpath core can write
        // the public key straight into the response. A temporary buffer
        // would cost another `pub_len` bytes of the per-IO DMA heap, and
        // ML-DSA-87 no longer has that to spare now the masked blob carries
        // the expanded secret key.
        let resp = cmd_buf.buffer_mut();
        let len = TborMlDsaGenerateKeyResp::encode(resp, 0, false)?
            .masked_key_reserve(masked_len)?
            .pub_key_reserve(pub_len)?
            .finish()
            .as_bytes()
            .len();
        let resp = &mut resp[..len];

        {
            let out = TborMlDsaGenerateKeyResp::decode_mut(resp)?;

            // The PAL fills the seed from the device TRNG and hands it to an
            // FP core, which derives the key pair and returns both halves.
            {
                // Generate straight into the masked-key slot's payload
                // region, where the ciphertext will land: `mask_in_place`
                // seals over it without a second copy. A separate plaintext
                // blob would cost another `plain_len` bytes of the 16 KB
                // per-IO DMA heap, which ML-DSA-87 does not have.
                let end = payload_at + plain_len;
                if end > out.masked_key.len() {
                    return Err(HsmError::InternalError);
                }
                let payload = &mut out.masked_key[payload_at..end];
                let (seed, sec_key) = payload.split_at_mut(MLDSA_SEED_LEN);
                pal.mldsa_gen_key(io, vault_kind, seed, out.pub_key, sec_key)
                    .await?;
            }

            // Mask the seed+expanded key as one unit, straight into the
            // reserved response slot.
            pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
                let masking_key = resolve_masking_key(pal, io, HsmKeyScope(scope.0), sess_id)?;
                let key_label = alloc.dma_alloc(MLDSA_KEY_LABEL.len())?;
                key_label.copy_from_slice(MLDSA_KEY_LABEL);
                let params = MaskParams {
                    key_kind: vault_kind,
                    key_attrs: attrs,
                    svn,
                    owner_seed_id: owner,
                    key_label,
                };
                let written = mask_in_place(
                    pal,
                    io,
                    alloc,
                    AeadAlg::AesGcm256Iv16,
                    masking_key,
                    &params,
                    plain_len,
                    out.masked_key,
                )
                .await?;
                // A short write would leave uninitialized bytes in the slot,
                // which was reserved to exactly `masked_len`.
                if written != masked_len {
                    return Err(HsmError::InternalError);
                }
                Ok(())
            })
            .await?;
        }

        Ok(len)
    }
    .await
}

/// Attributes recorded in the masked blob's metadata and re-applied on
/// unmask.  An ML-DSA key is a signing key created on-device; `scope`
/// records the lifecycle domain that selects the masking key.
fn mldsa_key_attrs(scope: HsmKeyScope) -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_sign(true)
        .with_scope(scope)
}

/// Envelope key-label recorded in the masked blob's metadata.
const MLDSA_KEY_LABEL: &[u8] = b"MlDsaKey";

/// Length of the compact ML-DSA private seed (`xi`), identical across
/// parameter sets.
pub(crate) const MLDSA_SEED_LEN: usize = 32;

/// Public key length per parameter set (FIPS 204 Table 2).
/// Expanded ML-DSA secret-key length for a parameter set (FIPS 204).
///
/// Carried in the masked blob after the seed, so signing does not have to
/// re-derive the key pair.
pub(crate) fn mldsa_sec_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(2560),
        HsmVaultKeyKind::MlDsa65Seed => Ok(4032),
        HsmVaultKeyKind::MlDsa87Seed => Ok(4896),
        _ => Err(HsmError::InvalidArg),
    }
}

fn mldsa_pub_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(1312),
        HsmVaultKeyKind::MlDsa65Seed => Ok(1952),
        HsmVaultKeyKind::MlDsa87Seed => Ok(2592),
        _ => Err(HsmError::InvalidArg),
    }
}
