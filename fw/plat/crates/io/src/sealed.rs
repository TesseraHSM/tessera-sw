// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno in-band session transport frame.
//!
//! The Uno SQE and CQE have no room for an IV or tag, so a TBOR request
//! that runs within a session ([`HsmSessCtrl::InSession`] or
//! [`HsmSessCtrl::Close`]) and its response carry the AES-256-GCM
//! protection in-band, as a trailer:
//!
//! ```text
//! frame     = ct ‖ iv(12) ‖ tag(16)
//! plaintext = msg ‖ 0^p ‖ p(1)          // p = pad_len, 0..=15
//! ```
//!
//! The plaintext is padded to whole AES blocks, so the engine never takes
//! a partial-block path; the padding count is its last byte, encrypted
//! and authenticated with the message, so the frame needs no AAD. The
//! ciphertext starts the frame, so it is opened in place and the message
//! is left at offset 0 of the exchange buffer.
//!
//! Requests are opened with the session's VM→HSM transport key, responses
//! sealed with the HSM→VM key under a fresh random IV.

use tsra_fw_hsm_pal_traits::HsmAesGcm;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRng;
use tsra_fw_hsm_pal_traits::HsmSessCtrl;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionManager;
use tsra_fw_hsm_pal_traits::HsmSessionTransportDir;
use tsra_fw_hsm_pal_traits::HsmSqe;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_IV_LEN;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_TAG_LEN;

use crate::SqeEntry;
use crate::OP_TBOR;

/// AES block size; the sealed plaintext is a multiple of it.
pub const SEALED_BLOCK_LEN: usize = 16;

/// Length of the `iv ‖ tag` frame trailer.
pub const SEALED_TRAILER_LEN: usize = SESSION_TRANSPORT_IV_LEN + SESSION_TRANSPORT_TAG_LEN;

/// Whether `sqe`'s request and response travel in a sealed frame: a TBOR
/// command that runs within (or closes) a session.
#[inline]
pub fn sqe_is_sealed(sqe: &SqeEntry) -> bool {
    sqe.opcode() == OP_TBOR
        && matches!(
            sqe.session_ctrl(),
            HsmSessCtrl::InSession | HsmSessCtrl::Close
        )
}

/// Session of a sealed `sqe`, `None` for a plaintext one.
///
/// # Errors
///
/// [`HsmError::SessionTransportError`] if a sealed SQE names no session.
#[inline]
pub fn sealed_session(sqe: &SqeEntry) -> HsmResult<Option<HsmSessId>> {
    if !sqe_is_sealed(sqe) {
        return Ok(None);
    }
    let id = sqe.session_id().ok_or(HsmError::SessionTransportError)?;
    Ok(Some(HsmSessId::from(id)))
}

/// Length of the sealed frame of a `msg_len`-byte message.
#[inline]
pub const fn sealed_frame_len(msg_len: usize) -> usize {
    (msg_len + 1).next_multiple_of(SEALED_BLOCK_LEN) + SEALED_TRAILER_LEN
}

/// Largest message whose sealed frame fits `frame_capacity` bytes.
#[inline]
pub const fn sealed_msg_capacity(frame_capacity: usize) -> usize {
    match frame_capacity.checked_sub(SEALED_TRAILER_LEN) {
        Some(pt) if pt >= SEALED_BLOCK_LEN => pt - pt % SEALED_BLOCK_LEN - 1,
        _ => 0,
    }
}

/// Opens the sealed request `frame` in place with session `id`'s VM→HSM
/// key, returning the message length; the message is left at the start of
/// `frame`.
///
/// # Errors
///
/// [`HsmError::SessionTransportError`] if the frame is malformed, the
/// session has no transport key, the tag does not verify, or the padding
/// is invalid.
pub async fn sealed_open<P>(
    pal: &P,
    io: &P::Io,
    id: HsmSessId,
    frame: &mut HsmDmaBuf,
) -> HsmResult<usize>
where
    P: HsmAesGcm + HsmSessionManager,
{
    let ct_len = frame
        .len()
        .checked_sub(SEALED_TRAILER_LEN)
        .filter(|&n| n != 0 && n % SEALED_BLOCK_LEN == 0)
        .ok_or(HsmError::SessionTransportError)?;
    let key = pal
        .session_transport_key(io, id, HsmSessionTransportDir::H2m)
        .map_err(|_| HsmError::SessionTransportError)?;
    let (ct, trailer) = frame.split_at_mut(ct_len);
    let (iv, tag) = trailer.split_at(SESSION_TRANSPORT_IV_LEN);
    pal.gcm_decrypt_in_place(io, key, iv, 0, tag, ct)
        .await
        .map_err(|_| HsmError::SessionTransportError)?;
    unpad(ct).ok_or(HsmError::SessionTransportError)
}

/// Seals the response `msg` with session `id`'s HSM→VM key under a fresh
/// IV, returning the frame in a new DMA buffer.
///
/// # Errors
///
/// [`HsmError::SessionTransportError`] if the session has no transport
/// key or the encryption fails; `NotEnoughSpace` if the frame cannot be
/// allocated; the RNG's error if it fails.
pub async fn sealed_seal<'a, P>(
    pal: &'a P,
    io: &P::Io,
    id: HsmSessId,
    msg: &HsmDmaBuf,
) -> HsmResult<&'a HsmDmaBuf>
where
    P: HsmAesGcm + HsmSessionManager + HsmAlloc + HsmRng,
{
    let frame_len = sealed_frame_len(msg.len());
    let pt_len = frame_len - SEALED_TRAILER_LEN;
    let frame = pal.dma_alloc(io, frame_len)?;
    let (pt, trailer) = frame.split_at_mut(pt_len);
    pt[..msg.len()].copy_from_slice(msg);
    pt[msg.len()..pt_len - 1].fill(0);
    pt[pt_len - 1] = (pt_len - 1 - msg.len()) as u8;
    let (iv, tag) = trailer.split_at_mut(SESSION_TRANSPORT_IV_LEN);
    pal.rng_fill_bytes(io, iv)?;
    let key = pal
        .session_transport_key(io, id, HsmSessionTransportDir::M2h)
        .map_err(|_| HsmError::SessionTransportError)?;
    pal.gcm_encrypt_in_place(io, key, iv, 0, pt, tag)
        .await
        .map_err(|_| HsmError::SessionTransportError)?;
    Ok(frame)
}

/// Message length of the padded plaintext `pt`, or `None` if its padding
/// is invalid.
fn unpad(pt: &[u8]) -> Option<usize> {
    let (&pad, body) = pt.split_last()?;
    let pad = pad as usize;
    if pad >= SEALED_BLOCK_LEN {
        return None;
    }
    let msg_len = body.len().checked_sub(pad)?;
    body[msg_len..].iter().all(|&b| b == 0).then_some(msg_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_and_capacity_agree() {
        for msg in 0..200 {
            let frame = sealed_frame_len(msg);
            assert_eq!((frame - SEALED_TRAILER_LEN) % SEALED_BLOCK_LEN, 0);
            assert!(sealed_msg_capacity(frame) >= msg);
            assert!(sealed_frame_len(sealed_msg_capacity(frame)) <= frame);
        }
        assert_eq!(sealed_msg_capacity(SEALED_TRAILER_LEN + 15), 0);
    }

    #[test]
    fn unpad_checks_padding() {
        let mut pt = [0u8; 16];
        pt[..5].copy_from_slice(b"hello");
        pt[15] = 10;
        assert_eq!(unpad(&pt), Some(5));
        pt[15] = 11;
        assert_eq!(unpad(&pt), None);
        pt[15] = 16;
        assert_eq!(unpad(&pt), None);
        pt[15] = 10;
        pt[14] = 1;
        assert_eq!(unpad(&pt), None);
    }
}
