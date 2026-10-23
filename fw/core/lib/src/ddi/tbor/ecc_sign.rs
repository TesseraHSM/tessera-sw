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

use tsra_fw_core_crypto_key_masking::aead::peek_head;
use tsra_fw_core_crypto_key_masking::aead::unmask_with_head;
use tsra_fw_ddi_tbor::RequestHead;
use tsra_fw_ddi_tbor_types::TborEccSignReq;
use tsra_fw_ddi_tbor_types::TborEccSignResp;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmIo;
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
/// signs, and returns the signature.  Takes `req_buf: &mut DmaBuf` so the
/// masked key can be unmasked in place (`decode_mut`).
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
    head: &RequestHead,
) -> HsmResult<&'p DmaBuf> {
    let req = TborEccSignReq::decode_mut_with(req_buf, head)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));
    validate_active_session(pal, io, sess_id)?;

    // EccSign consumes a host pre-computed digest.  ECDSA here uses only
    // fixed-length SHA-2 digests, so the hash algorithm is implied by the
    // digest length (there is no SHAKE/XOF variant); reject any length that
    // is not a supported SHA-2 digest length rather than carrying a
    // redundant algorithm selector on the wire. The digest stays in wire
    // little-endian order when normalized to the signing operand below.
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

    // The scope that masked this key is recorded (cleartext, tag-bound) in
    // the blob metadata; resolve its masking key before unmasking.  The
    // peek borrow is transient — it ends before the in-place unmask.
    let head = peek_head(req.masked_key)?;
    let masking_key = resolve_masking_key(pal, io, head.scope(), sess_id)?;

    // Unmask the private key in place, sign, and build the response inside a
    // block that yields a `Result`, so **every** post-unmask path (success
    // or error) falls through to the `masked_key` wipe below — the recovered
    // plaintext must never survive in the request buffer.
    let outcome: HsmResult<&'p DmaBuf> = async {
        let view = unmask_with_head(pal, io, masking_key, req.masked_key, &head).await?;
        let curve = ecc_private_curve(view.key_kind)?;
        if !view.key_attrs.sign() {
            return Err(HsmError::InvalidPermissions);
        }

        // The PKA DMA-reads the full curve operand width for the digest
        // (`wire_coord_len` = 32 / 48 / 68), which exceeds the ECDSA digest
        // width for P-521 (68 vs 64). ECDSA keeps the most significant bits
        // of longer digests: the trailing bytes of the wire-LE digest.
        // Zero-pad shorter digests and the backing operand so the engine's
        // full-width reads stay in bounds.
        let sign_len = curve.ecdsa_digest_len();
        let digest = req
            .digest
            .get(req.digest.len().saturating_sub(sign_len)..)
            .ok_or(HsmError::InvalidArg)?;
        // When the digest already fills the operand width the request
        // buffer *is* a valid operand -- it is DMA-backed and the engine's
        // read stays inside the declared digest. That is the P-256 and
        // P-384 case (32/32 and 48/48), so the common path needs neither
        // the allocation nor the copy. Only P-521 genuinely differs
        // (64-byte digest, 68-byte operand) and still needs zero pad.
        let operand: &DmaBuf = if req.digest.len() == curve.wire_coord_len() {
            req.digest
        } else {
            let staged = pal.dma_alloc_zeroed(io, curve.wire_coord_len())?;
            staged
                .get_mut(..digest.len())
                .ok_or(HsmError::InvalidArg)?
                .copy_from_slice(digest);
            staged
        };

        // Reserve the wire-format signature slot (`r ‖ s`, curve-sized) and
        // have the PAL sign straight into it — no scratch, no copy.
        let (resp, signature) = pal.dma_alloc_var_with(io, |buf| {
            let (enc, signature) = TborEccSignResp::encode(buf, 0, false)?
                .signature_reserve_range(curve.wire_sig_len())?;
            Ok((enc.finish().as_bytes().len(), signature))
        })?;
        pal.ecc_sign(
            io,
            curve,
            view.target_key,
            &operand[..sign_len],
            &mut resp[signature],
        )
        .await?;
        // Coerce the `&mut` response buffer to a shared `&DmaBuf` (preserving
        // the `'p` allocator lifetime) so the async block's output matches
        // the handler's `&'p DmaBuf` return.
        let resp: &'p DmaBuf = resp;
        Ok(resp)
    }
    .await;

    // Scrub the recovered plaintext key from the request buffer.
    req.masked_key.zeroize();
    outcome
}
