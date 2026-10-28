// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaSign` command handler.
//!
//! Signs a host-supplied message with a caller-held **masked** ML-DSA key
//! (from [`MlDsaGenerateKey`](super::mldsa_generate_key)).  The key is
//! unmasked on-device, the signature is produced on a fastpath core, and
//! nothing is persisted: the caller holds the masked blob and passes it
//! back each time.
//!
//! The wire ships seed-only keys, so the caller never handles an expanded
//! key.  The blob carries the 32-byte `xi` seed followed by the expanded
//! secret key, and the fastpath core signs with the expanded half
//! directly rather than re-deriving the key pair (`f0bf65c4`).

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::TborMlDsaSignReq;
use tsra_fw_ddi_tbor_types::TborMlDsaSignResp;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::resolve_masking_key;
use super::validate_active_session;
use crate::ddi::tbor::mldsa_generate_key::mldsa_sec_key_len;
use crate::ddi::tbor::mldsa_generate_key::MLDSA_SEED_LEN;

/// Signature length per ML-DSA parameter set (FIPS 204 Table 2).
fn mldsa_sig_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(2420),
        HsmVaultKeyKind::MlDsa65Seed => Ok(3309),
        HsmVaultKeyKind::MlDsa87Seed => Ok(4627),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Handle a TBOR `MlDsaSign` request.
///
/// Persists nothing and takes no partition lock: it reads the caller's
/// key, signs, and returns.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    req_buf: &mut DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let req = TborMlDsaSignReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));
    validate_active_session(pal, io, sess_id)?;

    if req.ctx.len() > 255 {
        return Err(HsmError::InvalidArg);
    }

    // Unmask, sign and build the response inside a block that yields a
    // `Result`, so every post-unmask path falls through to the wipe below:
    // the recovered seed is the private key and must not survive in the
    // request buffer, which scope exit does not zero.
    // The scope that masked this key is recorded (cleartext, tag-bound) in
    // the blob metadata; resolve its masking key before unmasking. The peek
    // borrow is transient -- it ends before the in-place unmask.
    let scope = peek_scope(req.masked_key)?;
    let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;

    let outcome: HsmResult<&'p DmaBuf> = async {
        // Unmask in place. The AAD carries the parameter set, so the kind
        // comes from the envelope rather than being inferred from length.
        let view = unmask(pal, io, masking_key, req.masked_key).await?;
        let kind = view.key_kind;
        if !view.key_attrs.sign() {
            return Err(HsmError::InvalidPermissions);
        }
        let sig_len = mldsa_sig_len(kind)?;
        let sec_len = mldsa_sec_key_len(kind)?;
        if view.target_key.len() != MLDSA_SEED_LEN + sec_len {
            return Err(HsmError::InvalidArg);
        }
        let key_blob: &DmaBuf = view.target_key;

        // Reserve the signature slot and have the PAL sign straight into it.
        let resp = pal.dma_alloc_var(io, |buf| {
            let frame = TborMlDsaSignResp::encode(buf, 0, false)?
                .signature_reserve(sig_len)?
                .finish();
            Ok(frame.as_bytes().len())
        })?;

        {
            let out = TborMlDsaSignResp::decode_mut(resp)?;
            let signed = pal
                .mldsa_sign(
                    io,
                    kind,
                    &key_blob[MLDSA_SEED_LEN..],
                    req.message,
                    req.ctx,
                    out.signature,
                )
                .await;
            signed?;
        }

        let resp: &'p DmaBuf = resp;
        Ok(resp)
    }
    .await;

    // The key is read in place, so the request buffer is the only copy --
    // wiped here on every path out of the block above.
    req.masked_key.zeroize();
    outcome
}
