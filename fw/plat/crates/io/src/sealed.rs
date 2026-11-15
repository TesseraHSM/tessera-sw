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
//! iv        = salt(4) ‖ seq(8)          // salt and counter of the sender
//! ```
//!
//! The plaintext is padded to whole AES blocks, so the engine never takes
//! a partial-block path; the padding count is its last byte, encrypted
//! and authenticated with the message. An implicit 32-byte AAD binds the
//! request IV and transport context, with distinct request/response domains.
//! AAD is local, not part of the frame. Receive DMA leaves headroom for it,
//! so opening needs no additional message copy.
//!
//! Requests are opened with the session's VM→HSM transport key, responses
//! sealed with the HSM→VM key. The sender builds the IV from its
//! direction's salt and big-endian message counter, so no per-message
//! randomness is needed and nonces never repeat under a key. As on Duo,
//! the receiver uses the IV it is given: it is read in place from the
//! frame. Responses use the original authenticated request context, so
//! concurrent responses can complete in any order without substitution.

use tsra_fw_hsm_pal_traits::HsmAesGcm;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
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

/// Exact AAD prefix size required by the Uno GCM engine.
pub const TRANSPORT_AAD_LEN: usize = 32;

/// Authenticated context retained for one request until its response is sealed.
#[derive(Clone, Copy, Debug)]
pub struct SessionTransportBinding([u8; 16]);

impl SessionTransportBinding {
    /// Uno context; the control byte matches the SQE wire encoding.
    pub fn uno(id: u16, control: HsmSessCtrl, iv: [u8; 12]) -> HsmResult<Self> {
        let control = match control {
            HsmSessCtrl::Close => 2,
            HsmSessCtrl::InSession => 3,
            _ => return Err(HsmError::SessionTransportError),
        };
        Ok(Self::new(id, control, 1, iv))
    }

    /// Duo declares session control inside TBOR, not its SQE.
    pub fn duo(id: u16, iv: [u8; 12]) -> Self {
        Self::new(id, 0, 2, iv)
    }

    fn new(id: u16, control: u8, protocol: u8, iv: [u8; 12]) -> Self {
        let mut context = [0; 16];
        context[..12].copy_from_slice(&iv);
        context[12..14].copy_from_slice(&id.to_le_bytes());
        context[14] = control;
        context[15] = protocol;
        Self(context)
    }

    /// Mirrors the host: domain(16), request IV(12), session id(2, LE),
    /// session control(1), protocol(1: Uno=1, Duo=2).
    pub fn aad(&self, response: bool) -> [u8; TRANSPORT_AAD_LEN] {
        let mut aad = [0; TRANSPORT_AAD_LEN];
        aad[..16].copy_from_slice(if response {
            b"TSRA-RSP-AAD-V1\0"
        } else {
            b"TSRA-REQ-AAD-V1\0"
        });
        aad[16..].copy_from_slice(&self.0);
        aad
    }
}

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

/// Opens `[AAD headroom(32) | frame]` in place with session `id`'s VM→HSM
/// key. Returns the message length and authenticated request binding.
/// The message remains immediately after the headroom.
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
    control: HsmSessCtrl,
    frame: &mut HsmDmaBuf,
) -> HsmResult<(usize, SessionTransportBinding)>
where
    P: HsmAesGcm + HsmSessionManager,
{
    if matches!(
        pal.session_state(io, id),
        tsra_fw_hsm_pal_traits::HsmSessionState::NeedsRenegotiation
    ) {
        return Err(HsmError::SessionNeedsRenegotiation);
    }
    let ct_len = frame
        .len()
        .checked_sub(TRANSPORT_AAD_LEN + SEALED_TRAILER_LEN)
        .filter(|&n| n != 0 && n % SEALED_BLOCK_LEN == 0)
        .ok_or(HsmError::SessionTransportError)?;
    let key = pal
        .session_transport_key(io, id, HsmSessionTransportDir::H2m)
        .map_err(|_| HsmError::SessionTransportError)?;
    let (data, trailer) = frame.split_at_mut(TRANSPORT_AAD_LEN + ct_len);
    let (iv, tag) = trailer.split_at(SESSION_TRANSPORT_IV_LEN);
    let mut request_iv = [0; SESSION_TRANSPORT_IV_LEN];
    request_iv.copy_from_slice(iv);
    let binding = SessionTransportBinding::uno(u16::from(id), control, request_iv)?;
    data[..TRANSPORT_AAD_LEN].copy_from_slice(&binding.aad(false));
    pal.gcm_decrypt_in_place(io, key.key(), iv, TRANSPORT_AAD_LEN, tag, data)
        .await
        .map_err(|_| HsmError::SessionTransportError)?;
    let len = unpad(&data[TRANSPORT_AAD_LEN..]).ok_or(HsmError::SessionTransportError)?;
    Ok((len, binding))
}

/// Seals the response `msg` with session `id`'s HSM→VM key under the
/// session's next HSM→VM sequence number, returning the frame in a new DMA
/// buffer.
///
/// # Errors
///
/// [`HsmError::SessionTransportError`] if the session has no transport
/// key, its sequence numbers are exhausted, or the encryption fails;
/// `NotEnoughSpace` if the frame cannot be allocated.
pub async fn sealed_seal<'a, P>(
    pal: &'a P,
    io: &P::Io,
    id: HsmSessId,
    binding: SessionTransportBinding,
    msg: &HsmDmaBuf,
) -> HsmResult<&'a HsmDmaBuf>
where
    P: HsmAesGcm + HsmSessionManager + HsmAlloc,
{
    let frame_len = sealed_frame_len(msg.len());
    let pt_len = frame_len - SEALED_TRAILER_LEN;
    let frame = pal.dma_alloc(io, TRANSPORT_AAD_LEN + frame_len)?;
    let (data, trailer) = frame.split_at_mut(TRANSPORT_AAD_LEN + pt_len);
    data[..TRANSPORT_AAD_LEN].copy_from_slice(&binding.aad(true));
    let pt = &mut data[TRANSPORT_AAD_LEN..];
    // Both buffers are DMA memory, which the CPU reads uncached: burst
    // copy rather than a load per word.
    msg.copy_to_slice(&mut pt[..msg.len()]);
    pt[msg.len()..pt_len - 1].fill(0);
    pt[pt_len - 1] = (pt_len - 1 - msg.len()) as u8;
    let key = pal
        .session_transport_key(io, id, HsmSessionTransportDir::M2h)
        .map_err(|_| HsmError::SessionTransportError)?;
    let seq = pal
        .session_transport_next_seq(io, id)
        .map_err(|_| HsmError::SessionTransportError)?;
    let (iv, tag) = trailer.split_at_mut(SESSION_TRANSPORT_IV_LEN);
    iv.copy_from_slice(&key.nonce(seq));
    pal.gcm_encrypt_in_place(io, key.key(), iv, TRANSPORT_AAD_LEN, data, tag)
        .await
        .map_err(|_| HsmError::SessionTransportError)?;
    Ok(&frame[TRANSPORT_AAD_LEN..])
}

/// Message length of the padded plaintext `pt`, whole blocks, or `None` if
/// its padding is invalid.
///
/// The padding lies within the last block, which is read out of DMA memory
/// (uncached on Uno) with one burst rather than a load per byte, and
/// checked a word at a time: the `p` bytes before the pad byte are zero iff
/// the block's last nonzero byte before it lies in the message.
fn unpad(pt: &HsmDmaBuf) -> Option<usize> {
    const WORDS: usize = SEALED_BLOCK_LEN / 4;
    let start = pt.len().checked_sub(SEALED_BLOCK_LEN)?;
    let (words, _) = pt.split_at(start).1.read_head_words();
    // Byte `i` of the block is bits `8 * (i % 4)..` of word `i / 4`.
    let mut block = words.map(u32::from_le);
    let pad = (block[WORDS - 1] >> 24) as usize;
    if pad >= SEALED_BLOCK_LEN {
        return None;
    }
    block[WORDS - 1] &= 0x00FF_FFFF;
    let msg = SEALED_BLOCK_LEN - 1 - pad;
    // One past the last nonzero byte before the pad byte, 0 if none.
    let end = block[..WORDS]
        .iter()
        .rposition(|&w| w != 0)
        .map_or(0, |k| 4 * k + 4 - (block[k].leading_zeros() / 8) as usize);
    (end <= msg).then_some(start + msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Views host bytes as a `&HsmDmaBuf`.
    #[allow(unsafe_code)]
    fn unpad_bytes(pt: &[u8]) -> Option<usize> {
        // SAFETY: `from_raw` requires DMA-addressable memory, which is vacuous
        // on the host: `unpad` only reads the bytes with the CPU, and
        // `HsmDmaBuf` is a `[u8]` newtype borrowed no longer than `pt`.
        unpad(unsafe { HsmDmaBuf::from_raw(pt) })
    }

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
        assert_eq!(unpad_bytes(&pt), Some(5));
        pt[15] = 11;
        assert_eq!(unpad_bytes(&pt), None);
        pt[15] = 16;
        assert_eq!(unpad_bytes(&pt), None);
        pt[15] = 10;
        pt[14] = 1;
        assert_eq!(unpad_bytes(&pt), None);
    }

    #[test]
    fn unpad_reads_the_last_block() {
        let mut pt = [0u8; 48];
        pt[..20].copy_from_slice(b"hello, sealed world!");
        pt[47] = 27;
        assert_eq!(unpad_bytes(&pt), None);
        pt[47] = 15;
        assert_eq!(unpad_bytes(&pt), Some(32));
        pt[32] = 1;
        assert_eq!(unpad_bytes(&pt), None);
        pt[47] = 14;
        assert_eq!(unpad_bytes(&pt), Some(33));
        pt[47] = 0;
        assert_eq!(unpad_bytes(&pt), Some(47));
        assert_eq!(unpad_bytes(&pt[..15]), None);
    }
}
