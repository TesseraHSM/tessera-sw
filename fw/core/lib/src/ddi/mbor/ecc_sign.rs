// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EccSign command handler.
//!
//! Within an open session, look up an ECC private key by id and
//! produce a raw `r || s` signature over the host-supplied digest.
//! The digest must already be hashed by the host — firmware does no
//! hashing here.

use tsra_fw_ddi_mbor_types::ecc_sign::DdiEccSignReq;
use tsra_fw_ddi_mbor_types::ecc_sign::DdiEccSignResp;

use super::*;

/// Handle `DdiEccSignCmd`.
pub(crate) async fn ecc_sign<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p HsmDmaBuf> {
    let body: DdiEccSignReq<'_> = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // Validate the digest_algo enum is supported and read the algo's native
    // digest size — the host's `digest_pre_encode` LE-reverses
    // `input_array.len()` bytes and zero-pads the rest to 68 wire bytes, so
    // the leading `real_digest_len` bytes are the actual digest in wire-LE
    // form and the remainder is zero. The digest is staged into the PAL's
    // packed ECDSA input below; each PAL is responsible for any endianness
    // flip its underlying primitive requires (e.g. std PAL reverses to BE
    // for OpenSSL; real-HW PALs pass through to the PKA engine).
    let pal_algo = super::from_ddi::hash(body.digest_algo)?;
    let real_digest_len = pal_algo.digest_len();
    if body.digest.len() < real_digest_len {
        return Err(HsmError::InvalidArg);
    }

    let key_id = HsmKeyId::from(body.key_id);
    let vault_kind = pal.vault_key_kind(io, key_id)?;
    let curve = super::from_pal::ecc_curve(vault_kind)?;
    let vault_attrs = pal.vault_key_attrs(io, key_id)?;
    if !vault_attrs.sign() {
        return Err(HsmError::InvalidPermissions);
    }
    let priv_key = pal.vault_key(io, key_id)?;

    // Sign directly into the wire-format signature slot.  The PAL
    // emits `r || s` in LE with P-521 trailing pad bytes, so we just
    // reserve `curve.wire_sig_len(P::ECC_COORD_PAD)` bytes and hand the slot through.
    let wire_len = curve.wire_sig_len(P::ECC_COORD_PAD);
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder =
            super::encode_resp_hdr(&super::success_hdr_sess(hdr, DdiOp::EccSign, sess_id), buf)?;
        let layout = DdiEccSignResp::reserve(&mut encoder, wire_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiEccSignResp::from_layout(resp, &layout);

    // The host zero-pads `digest` to the P-521 operand width
    // (`digest_pre_encode` always emits 68 wire bytes). Keep rejecting a
    // frame shorter than the curve's operand width, or with a non-zero byte
    // between the declared digest and that width, as before the packed
    // ECDSA input.
    let operand_len = curve.wire_coord_len(P::ECC_COORD_PAD);
    if body.digest.len() < operand_len
        || body.digest[real_digest_len.min(operand_len)..operand_len]
            .iter()
            .any(|&b| b != 0)
    {
        return Err(HsmError::InvalidArg);
    }

    // Stage the packed `k ‖ digest` input the PAL consumes: a zero `k` lane
    // (the PAL generates `k`) and the digest at the start of its zeroed lane.
    // The PAL truncates an over-long digest to the curve order.
    let input = pal.dma_alloc(io, curve.ecdsa_sign_input_len(pal_algo, P::ECC_COORD_PAD))?;
    input.fill(0);
    input[operand_len..operand_len + real_digest_len]
        .copy_from_slice(&body.digest[..real_digest_len]);
    pal.ecc_sign(
        io,
        curve,
        pal_algo,
        priv_key,
        HsmEcdsaNonce::Generated,
        input,
        Some(frame.signature),
    )
    .await?;

    Ok(resp)
}
