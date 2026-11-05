// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EccSign` command handler.
//!
//! Within an open session, produce a raw ECDSA `r ‖ s` signature over a
//! host-supplied **pre-computed digest** using a caller-held **masked**
//! ECC private key (from [`EccGenerateKey`](super::ecc_generate_key) or
//! imported via [`UnwrapKey`](super::unwrap_key)).  The key is unmasked
//! **in place** in the request buffer (no scratch copy), its curve is
//! recovered from the blob's key kind, and the signature is written
//! straight into the reserved response slot.  Firmware does **no**
//! hashing — the caller supplies the digest.  This is the TBOR analogue of
//! MBOR `EccSign`, keyed by a masked blob instead of a vault id.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use tsra_fw_core_crypto_key_masking::aead::peek_scope;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::TborEccSignReq;
use tsra_fw_ddi_tbor_types::TborEccSignResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::from_pal::ecc_private_curve;
use super::resolve_masking_key;
use super::validate_active_session;

/// Handle a TBOR `EccSign` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and **persists nothing** — it unmasks the caller's key,
/// signs, and returns the signature in consumed envelope metadata storage.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    async {
        let base = cmd_buf.request().as_ptr() as usize;
        let (curve, key_at, key_len, digest_at, digest_len) = {
            let req = TborEccSignReq::decode_mut(cmd_buf.request_mut())?;
            let sess_id = HsmSessId::from(u16::from(req.session_id));
            validate_active_session(pal, io, sess_id)?;
            if ![
                HsmHashAlgo::Sha256,
                HsmHashAlgo::Sha384,
                HsmHashAlgo::Sha512,
            ]
            .iter()
            .any(|algo| algo.digest_len() == req.digest.len())
            {
                return Err(HsmError::InvalidArg);
            }
            let scope = peek_scope(req.masked_key)?;
            let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
            let view = unmask(pal, io, masking_key, req.masked_key).await?;
            let curve = ecc_private_curve(view.key_kind)?;
            if !view.key_attrs.sign() {
                return Err(HsmError::InvalidPermissions);
            }
            (
                curve,
                (view.target_key.as_ptr() as usize)
                    .checked_sub(base)
                    .ok_or(HsmError::InvalidArg)?,
                view.target_key.len(),
                (req.digest.as_ptr() as usize)
                    .checked_sub(base)
                    .ok_or(HsmError::InvalidArg)?,
                req.digest.len(),
            )
        };

        let digest_end = digest_at
            .checked_add(digest_len)
            .ok_or(HsmError::InvalidArg)?;
        let digest_offset = digest_at.checked_sub(key_at).ok_or(HsmError::InvalidArg)?;
        let len = tsra_fw_ddi_tbor::RESP_HEADER_LEN
            + TborEccSignResp::TOC_COUNT * 4
            + curve.wire_sig_len();
        // Authenticated envelope metadata is dead; the private key and
        // digest remain live beyond it. Check disjointness before encoding.
        let buffer = cmd_buf.buffer_mut();
        if len > key_at || key_at > digest_end || digest_end > buffer.len() {
            return Err(HsmError::InvalidArg);
        }
        let (response, input) = buffer[..digest_end].split_at_mut(key_at);
        let response = &mut response[..len];
        TborEccSignResp::encode(response, 0, false)?
            .signature_reserve(curve.wire_sig_len())?
            .finish();
        if key_len > input.len() || digest_offset > input.len() {
            return Err(HsmError::InvalidArg);
        }
        let key = &input[..key_len];
        let supplied_digest = &input[digest_offset..];

        // The PKA DMA-reads the full curve operand width for the digest
        // (`wire_coord_len` = 32 / 48 / 68), which exceeds the ECDSA digest
        // width for P-521 (68 vs 64). ECDSA keeps the most significant bits
        // of longer digests: the trailing bytes of the wire-LE digest.
        // Zero-pad shorter digests and the backing operand so the engine's
        // full-width reads stay in bounds.
        let sign_len = curve.ecdsa_digest_len();
        let digest = supplied_digest
            .get(supplied_digest.len().saturating_sub(sign_len)..)
            .ok_or(HsmError::InvalidArg)?;
        // When the digest already fills the operand width the request
        // buffer *is* a valid operand -- it is DMA-backed and the engine's
        // read stays inside the declared digest. That is the P-256 and
        // P-384 case (32/32 and 48/48), so the common path needs neither
        // the allocation nor the copy. Only P-521 genuinely differs
        // (64-byte digest, 68-byte operand) and still needs zero pad.
        let operand: &HsmDmaBuf = if supplied_digest.len() == curve.wire_coord_len() {
            supplied_digest
        } else {
            let staged = pal.dma_alloc_zeroed(io, curve.wire_coord_len())?;
            staged
                .get_mut(..digest.len())
                .ok_or(HsmError::InvalidArg)?
                .copy_from_slice(digest);
            staged
        };

        let out = TborEccSignResp::decode_mut(response)?;
        pal.ecc_sign(io, curve, key, &operand[..sign_len], out.signature)
            .await?;
        Ok(len)
    }
    .await
}
