// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlKemGenerateKey` command handler.
//!
//! Generates an ML-KEM (FIPS 203) key pair and returns the decapsulation
//! key as a **masked** blob plus the encapsulation key.  Nothing is stored
//! on-device: the caller holds the masked blob and passes it back to
//! [`MlKemDecapsulate`](super::mlkem_decapsulate).
//!
//! The wire ships seed-only keys, so the caller never handles an expanded
//! key.  The blob itself carries the 64-byte `(d ‖ z)` seed pair followed
//! by the expanded decapsulation key, masked as one unit: the seeds
//! regenerate the encapsulation key, and the expanded half keeps a full
//! key generation out of every [`MlKemDecapsulate`](super::mlkem_decapsulate).
//! That trade was measured with masking bypassed (`f0bf65c4`); with real
//! masking the larger blob costs CP1 time on every call, so it is worth
//! re-measuring if key generation throughput matters more than
//! decapsulation.

use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::masked_blob_len;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::MlKemKeyKind;
use tsra_fw_ddi_tbor_types::TborMlKemGenerateKeyReq;
use tsra_fw_ddi_tbor_types::TborMlKemGenerateKeyResp;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
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

/// Length of the ML-KEM seed pair `(d ‖ z)`.
pub(crate) const MLKEM_SEED_LEN: usize = 64;

/// Envelope key-label recorded in the masked blob's metadata.
const MLKEM_KEY_LABEL: &[u8] = b"MlKemKey";

/// Encapsulation-key length per ML-KEM parameter set (FIPS 203 Table 3).
/// ML-KEM decapsulation-key length for a parameter set (FIPS 203).
///
/// Carried in the masked blob after the `(d, z)` seed pair, so
/// decapsulation does not have to re-derive the key pair.
pub(crate) fn mlkem_sec_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlKem512Seed => Ok(1632),
        HsmVaultKeyKind::MlKem768Seed => Ok(2400),
        HsmVaultKeyKind::MlKem1024Seed => Ok(3168),
        _ => Err(HsmError::InvalidArg),
    }
}

fn mlkem_pub_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlKem512Seed => Ok(800),
        HsmVaultKeyKind::MlKem768Seed => Ok(1184),
        HsmVaultKeyKind::MlKem1024Seed => Ok(1568),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Attributes recorded in the masked blob's metadata and re-applied on
/// unmask.  An ML-KEM key is used to derive a shared secret, so it is a
/// deriving key rather than a signing one.
fn mlkem_key_attrs(scope: HsmKeyScope) -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_derive(true)
        .with_scope(scope)
}

/// Handle a TBOR `MlKemGenerateKey` request.
///
/// Persists nothing and holds no lock: it generates a key pair, masks the
/// seed pair, and returns the blob with the encapsulation key.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborMlKemGenerateKeyReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    validate_active_session(pal, io, sess_id)?;
    let scope = req.scope();
    let key_kind = req.key_kind();

    // The wire is seed-only: anything outside the three seed kinds is
    // malformed.
    match key_kind {
        MlKemKeyKind::MlKem512Seed | MlKemKeyKind::MlKem768Seed | MlKemKeyKind::MlKem1024Seed => {}
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

    let vault_kind = HsmVaultKeyKind(key_kind.0);
    let pub_len = mlkem_pub_key_len(vault_kind)?;

    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    let attrs = mlkem_key_attrs(HsmKeyScope(scope.0));

    // One contiguous blob: the `(d, z)` seed pair followed by the expanded
    // decapsulation key, masked as a unit. The seeds still regenerate the
    // encapsulation key; the expanded key keeps a full key generation out
    // of every decapsulation.
    let sec_len = mlkem_sec_key_len(vault_kind)?;
    let key_blob = pal.dma_alloc(io, MLKEM_SEED_LEN + sec_len)?;
    let pub_key = pal.dma_alloc(io, pub_len)?;

    // Generate and mask inside a block that yields a `Result`, so every
    // path falls through to the seed wipe below: the seed pair is the
    // private key, and scope exit does not zero freed DMA memory.
    let outcome: HsmResult<&'p DmaBuf> = async {
        {
            let (seed, sec_key) = key_blob.split_at_mut(MLKEM_SEED_LEN);
            pal.mlkem_gen_key(
                io,
                vault_kind,
                &mut seed[..],
                &mut pub_key[..],
                &mut sec_key[..],
            )
            .await?;
        }

        let masked_len = masked_blob_len(AeadAlg::AesGcm256, MLKEM_SEED_LEN + sec_len);

        let resp = pal.dma_alloc_var(io, |buf| {
            let frame = TborMlKemGenerateKeyResp::encode(buf, 0, false)?
                .masked_key_reserve(masked_len)?
                .pub_key(&pub_key[..pub_len])?
                .finish();
            Ok(frame.as_bytes().len())
        })?;

        {
            let out = TborMlKemGenerateKeyResp::decode_mut(resp)?;
            // Mask the seed+expanded decapsulation key as one unit, straight
            // into the reserved response slot.
            pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
                let masking_key = resolve_masking_key(pal, io, HsmKeyScope(scope.0), sess_id)?;
                let key_label = alloc.dma_alloc(MLKEM_KEY_LABEL.len())?;
                key_label.copy_from_slice(MLKEM_KEY_LABEL);
                let params = MaskParams {
                    key_kind: vault_kind,
                    key_attrs: attrs,
                    svn,
                    owner_seed_id: owner,
                    key_label,
                };
                let written = mask(
                    pal,
                    io,
                    alloc,
                    AeadAlg::AesGcm256,
                    masking_key,
                    &params,
                    key_blob,
                    Some(out.masked_key),
                )
                .await?;
                if written != masked_len {
                    return Err(HsmError::InternalError);
                }
                Ok(())
            })
            .await?;
        }

        let resp: &'p DmaBuf = resp;
        Ok(resp)
    }
    .await;

    key_blob.zeroize();
    outcome
}
