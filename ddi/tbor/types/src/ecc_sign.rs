// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `EccSign` command.
//!
//! `EccSign` is an **in-session** command (Crypto-Officer or Crypto-User)
//! that produces a raw ECDSA `r ‖ s` signature over a host-supplied
//! **pre-computed digest** using a caller-held **masked** ECC private key.
//! Firmware does no hashing — the caller supplies the digest in device
//! byte order, packed as `k ‖ digest` (see [`ecc_sign_input`]).

use alloc::vec::Vec;

use crate::codec::EncodeError;
use crate::tbor;
use crate::HASH_ALGO_SHA256;
use crate::HASH_ALGO_SHA384;
use crate::HASH_ALGO_SHA512;

/// TBOR opcode for `EccSign`.
pub const TBOR_OP_ECC_SIGN: u8 = 0x18;

/// Maximum packed `k ‖ digest` input length (bytes): P-521 with 8-byte
/// padded lanes.
pub const ECC_SIGN_INPUT_MAX_LEN: usize = 144;
/// Maximum wire ECDSA signature length (`r ‖ s`, P-521 8-byte-padded big-endian lanes).
pub const ECC_SIG_MAX_LEN: usize = 144;

/// Host-facing TBOR `EccSign` request.
#[tbor(opcode = TBOR_OP_ECC_SIGN, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEccSignReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Digest algorithm, 1-byte `HashAlgo`: `HASH_ALGO_SHA256`,
    /// `HASH_ALGO_SHA384` or `HASH_ALGO_SHA512`.
    pub hash_algo: u8,

    /// The masked ECC private key (from `EccGenerateKey` / `UnwrapKey`).
    #[tbor(align = 4, min_len = 264, max_len = 312)]
    pub masked_key: Vec<u8>,

    /// The packed `k ‖ digest` operand in device byte order; build it with
    /// [`ecc_sign_input`].
    #[tbor(align = 4, max_len = 144)]
    pub input: Vec<u8>,
}

/// Returns the `HashAlgo` discriminant of the SHA-2 digest `digest_len`
/// bytes long, or `None` for any other length.
pub fn ecc_sign_hash_algo(digest_len: usize) -> Option<u8> {
    match digest_len {
        32 => Some(HASH_ALGO_SHA256),
        48 => Some(HASH_ALGO_SHA384),
        64 => Some(HASH_ALGO_SHA512),
        _ => None,
    }
}

/// Builds the packed `EccSign` input `k ‖ digest`.
///
/// * `coord_len` — the curve's wire coordinate length (32 / 48 / 68 on
///   little-endian devices, 32 / 48 / 72 on big-endian ones).
/// * `lane_pad` — the device's lane padding: 4 on little-endian devices, 8
///   on big-endian ones.
/// * `digest` — the digest in device byte order.
///
/// The `k` lane is zero (the device generates `k`); the digest sits at the
/// head of a zero-padded lane of `max(coord_len, digest rounded up to
/// lane_pad)` bytes.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidAlignment`] unless `lane_pad` is 4 or 8,
/// or [`EncodeError::DataTooLarge`] if the packed input exceeds
/// [`ECC_SIGN_INPUT_MAX_LEN`] or its length cannot be represented.
pub fn ecc_sign_input(
    coord_len: usize,
    lane_pad: usize,
    digest: &[u8],
) -> Result<Vec<u8>, EncodeError> {
    if !matches!(lane_pad, 4 | 8) {
        return Err(EncodeError::InvalidAlignment);
    }
    let lane = coord_len.max(
        digest
            .len()
            .checked_next_multiple_of(lane_pad)
            .ok_or(EncodeError::DataTooLarge)?,
    );
    let len = coord_len
        .checked_add(lane)
        .filter(|&len| len <= ECC_SIGN_INPUT_MAX_LEN)
        .ok_or(EncodeError::DataTooLarge)?;
    let mut input = alloc::vec![0u8; len];
    input[coord_len..coord_len + digest.len()].copy_from_slice(digest);
    Ok(input)
}

/// Host-facing TBOR `EccSign` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborEccSignResp {
    /// Raw ECDSA `r ‖ s`, each component in device byte order and sized to
    /// the curve wire coordinate length (64 / 96 / 136-or-144 B).
    #[tbor(max_len = 144)]
    pub signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_input() {
        let req = TborEccSignReq {
            session_id: 7,
            hash_algo: HASH_ALGO_SHA256,
            masked_key: alloc::vec![0x11u8; 264],
            input: ecc_sign_input(32, 4, &[0x22u8; 32]).expect("valid ECC layout"),
        };
        let mut buf = [0u8; 512];
        let frame = req.encode_request(&mut buf, (1, 1)).expect("encode");
        assert!(
            frame.windows(32).any(|w| w == [0x22u8; 32]),
            "encoded frame must carry the digest bytes",
        );
    }

    #[test]
    fn input_pads_digest_lane() {
        // P-521 on a big-endian device: 72-byte lanes, SHA-256 digest.
        let input = ecc_sign_input(72, 8, &[0x33u8; 32]).expect("valid ECC layout");
        assert_eq!(input.len(), 144);
        assert!(input[..72].iter().all(|&b| b == 0));
        assert_eq!(&input[72..104], &[0x33u8; 32]);
        assert!(input[104..].iter().all(|&b| b == 0));
        // SHA-512 with P-256: the digest lane widens to the digest.
        assert_eq!(
            ecc_sign_input(32, 4, &[1u8; 64])
                .expect("valid ECC layout")
                .len(),
            96
        );
    }

    #[test]
    fn input_rejects_unsupported_padding() {
        for pad in [0, 1, 2, 3, 5, 16, usize::MAX] {
            assert_eq!(
                ecc_sign_input(32, pad, &[0; 32]),
                Err(EncodeError::InvalidAlignment),
            );
        }
    }

    #[test]
    fn input_rejects_unrepresentable_or_oversized_lengths() {
        for pad in [4, 8] {
            for coord in [usize::MAX, usize::MAX / 2 + 1] {
                assert_eq!(
                    ecc_sign_input(coord, pad, &[0; 32]),
                    Err(EncodeError::DataTooLarge),
                );
            }
            assert_eq!(
                ecc_sign_input(32, pad, &[0; ECC_SIGN_INPUT_MAX_LEN]),
                Err(EncodeError::DataTooLarge),
            );
        }
    }
}
