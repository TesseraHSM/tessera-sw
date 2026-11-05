// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `Hash` command.
//!
//! `Hash` is an **in-session** command (Crypto-Officer or
//! Crypto-User) that computes a SHA-1 / 256 / 384 / 512 digest, or
//! SHAKE128 / SHAKE256 output of a requested length, of a host-supplied
//! message and returns it.  It carries no key and touches no partition
//! state — a pure hashing utility.
//!
//! `algo` is a raw 1-byte discriminant (the firmware types it as the
//! `HashAlgo` open-enum; this host crate is firewalled from the firmware
//! PAL types).

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `Hash`.
pub const TBOR_OP_HASH: u8 = 0x1B;

/// Maximum message length (bytes) accepted by `Hash`.
pub const HASH_MSG_MAX_LEN: usize = 3072;
/// Maximum output length (bytes): the largest SHAKE `out_len`.  Fixed-length
/// digests are at most 64 B (SHA-512).
pub const HASH_DIGEST_MAX_LEN: usize = 256;

/// `HashAlgo` discriminant for SHA-1 (20-byte digest).
pub const HASH_ALGO_SHA1: u8 = 0;
/// `HashAlgo` discriminant for SHA-256 (32-byte digest).
pub const HASH_ALGO_SHA256: u8 = 1;
/// `HashAlgo` discriminant for SHA-384 (48-byte digest).
pub const HASH_ALGO_SHA384: u8 = 2;
/// `HashAlgo` discriminant for SHA-512 (64-byte digest).
pub const HASH_ALGO_SHA512: u8 = 3;
/// `HashAlgo` discriminant for SHAKE128 (`out_len`-byte output; `Hash` only).
pub const HASH_ALGO_SHAKE128: u8 = 7;
/// `HashAlgo` discriminant for SHAKE256 (`out_len`-byte output; `Hash` only).
pub const HASH_ALGO_SHAKE256: u8 = 8;

/// Host-facing TBOR `Hash` request.
#[tbor(opcode = TBOR_OP_HASH, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborHashReq {
    /// Session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Digest algorithm, 1-byte `HashAlgo` (see `HASH_ALGO_*`).
    pub algo: u8,

    /// Output length in bytes: required for SHAKE (1 to
    /// `HASH_DIGEST_MAX_LEN`), `None` for the fixed-length digests.
    pub out_len: Option<u16>,

    /// The message to hash, up to `HASH_MSG_MAX_LEN` bytes.
    #[tbor(max_len = 3072)]
    pub msg: Vec<u8>,
}

/// Host-facing TBOR `Hash` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborHashResp {
    /// The natural (big-endian) digest, exactly the algorithm's length
    /// (20 / 32 / 48 / 64 B for SHA-1 / 256 / 384 / 512), or `out_len` bytes
    /// of SHAKE output.
    #[tbor(max_len = 256)]
    pub digest: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborHashReq {
            session_id: 9,
            algo: HASH_ALGO_SHA384,
            out_len: None,
            msg: alloc::vec![0x61u8; 64],
        };
        let mut buf = [0u8; 512];
        let frame = req.encode_request(&mut buf).expect("encode");
        assert!(
            frame.contains(&HASH_ALGO_SHA384),
            "encoded frame must carry the sha-mode discriminant",
        );
    }

    /// The worst-case request, staging included, stays within 4 KiB.
    #[test]
    fn max_sized_request_fits_in_4_kib() {
        let req = TborHashReq {
            session_id: 7,
            algo: HASH_ALGO_SHAKE256,
            out_len: Some(HASH_DIGEST_MAX_LEN as u16),
            msg: alloc::vec![0x61u8; HASH_MSG_MAX_LEN],
        };
        let mut buf = [0u8; 4096];
        let frame = req.encode_request(&mut buf).expect("encode");
        // header(8) + 4 TOC entries * 4 + data(3072).
        assert_eq!(frame.len(), 3096);
    }
}
