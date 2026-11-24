// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `EccSign` command handler.
//!
//! Within an open session, produce a raw ECDSA `r ‖ s` signature over a
//! host-supplied **pre-computed digest** using a caller-held **masked**
//! ECC private key (from [`EccGenerateKey`](super::ecc_generate_key) or
//! imported via [`UnwrapKey`](super::unwrap_key)).  The key is unmasked
//! **in place** in the request buffer (no scratch copy), its curve is
//! recovered from the blob's key kind, and the PAL signs straight from the
//! request's packed `k ‖ digest` input into the reserved response slot.
//! Firmware does **no** hashing — the caller supplies the digest.  This is the TBOR analogue of
//! MBOR `EccSign`, keyed by a masked blob instead of a vault id.
//!
//! Available to both Crypto-Officer and Crypto-User sessions.

use tsra_fw_core_crypto_key_masking::aead::peek_frame;
use tsra_fw_core_crypto_key_masking::aead::unmask_framed;
use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::TborEccSignReq;
use tsra_fw_ddi_tbor_types::TborEccSignResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmEcdsaNonce;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::from_pal::ecc_private_curve;
use super::resolve_masking_key;
use super::validate_active_session;

/// Map the wire [`HashAlgo`] onto the firmware hash algorithm: ECDSA over
/// SHA-256, SHA-384 or SHA-512.
fn ecdsa_hsm_hash(algo: HashAlgo) -> HsmResult<HsmHashAlgo> {
    match algo {
        HashAlgo::Sha256 => Ok(HsmHashAlgo::Sha256),
        HashAlgo::Sha384 => Ok(HsmHashAlgo::Sha384),
        HashAlgo::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

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
        let (curve, hash, key_at, key_len, input_at, input_len) = {
            let req = TborEccSignReq::decode_mut(cmd_buf.request_mut())?;
            let sess_id = HsmSessId::from(u16::from(req.session_id));
            validate_active_session(pal, io, sess_id)?;
            let hash = ecdsa_hsm_hash(HashAlgo(req.hash_algo))?;
            let (scope, frame) = peek_frame(req.masked_key)?;
            let masking_key = resolve_masking_key(pal, io, scope, sess_id)?;
            let view = unmask_framed(pal, io, masking_key, req.masked_key, frame).await?;
            let curve = ecc_private_curve(view.key_kind)?;
            if !view.key_attrs.sign() {
                return Err(HsmError::InvalidPermissions);
            }
            (
                curve,
                hash,
                (view.target_key.as_ptr() as usize)
                    .checked_sub(base)
                    .ok_or(HsmError::InvalidArg)?,
                view.target_key.len(),
                (req.input.as_ptr() as usize)
                    .checked_sub(base)
                    .ok_or(HsmError::InvalidArg)?,
                req.input.len(),
            )
        };

        let key_end = key_at.checked_add(key_len).ok_or(HsmError::InvalidArg)?;
        let input_end = input_at
            .checked_add(input_len)
            .ok_or(HsmError::InvalidArg)?;
        let sig_len = curve.wire_sig_len(P::ECC_COORD_PAD);
        let len = tsra_fw_ddi_tbor::RESP_HEADER_LEN + TborEccSignResp::TOC_COUNT * 4 + sig_len;
        // Authenticated envelope metadata is dead; the private key and the
        // input remain live beyond it. Check disjointness before encoding.
        let buffer = cmd_buf.buffer_mut();
        if len > key_at || key_end > input_at || input_end > buffer.len() {
            return Err(HsmError::TborNonCanonicalLayout);
        }
        let (response, rest) = buffer[..input_end].split_at_mut(key_at);
        let (key, input) = rest.split_at_mut(input_at - key_at);
        let response = &mut response[..len];
        TborEccSignResp::encode_for_request(response, 0, false)?
            .signature_reserve(sig_len)?
            .finish();

        // `response` is exactly header, TOC and the one reserved field, so the
        // signature slot is its tail; taking it there spares re-decoding the
        // frame just encoded from DMA memory. The PAL checks the input's
        // shape against `curve` and `hash`.
        let signature = &mut response[len - sig_len..];
        pal.ecc_sign(
            io,
            curve,
            hash,
            &key[..key_len],
            HsmEcdsaNonce::Generated,
            input,
            Some(signature),
        )
        .await?;
        Ok(len)
    }
    .await
}
