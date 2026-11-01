// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `AesXtsGenerateKey` wire schema.
//!
//! `AesXtsGenerateKey` is an in-session command that generates a fresh
//! random AES-256-XTS key — the double-wide `K1 ‖ K2` (64 bytes, with
//! `K1 ≠ K2`) — and returns it **masked** under the requested
//! [`KeyScope`]'s masking key, stamped with the `AesXts512` key kind.  The
//! key is not stored on-device; the caller passes the masked blob to
//! [`AesXtsEncryptDecrypt`](crate::aes_xts_encrypt_decrypt).
//!
//! The masked key is an AEAD-GCM-256 envelope `header(8) ‖ iv(16) ‖
//! aad(192) ‖ pt(64) ‖ tag(16)` = [`MASKED_AES_XTS_KEY_LEN`] (296) bytes.

use tsra_fw_ddi_tbor_api::tbor;

use crate::key_props::KeyScope;
use crate::key_props::KeyUsage;

/// TBOR opcode for `AesXtsGenerateKey`.
pub const TBOR_OP_AES_XTS_GENERATE_KEY: u8 = 0x2E;

/// AES-256-XTS key length in bytes (`K1 ‖ K2`).
pub const AES_XTS_KEY_LEN: usize = 64;

/// Masked AES-256-XTS key envelope length.  Pinned into the
/// `#[tbor(buffer, len = 296)]` literals on the `masked_key` fields.
pub const MASKED_AES_XTS_KEY_LEN: usize = 8 + 16 + 192 + AES_XTS_KEY_LEN + 16;

/// `AesXtsGenerateKey` request schema.
#[tbor(opcode = 0x2E, pair = TborAesXtsGenerateKeyResp)]
pub struct TborAesXtsGenerateKeyReq<'a> {
    /// CO/CU session id this request is bound to.  The dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (lifecycle / visibility domain), carried as
    /// the 1-byte [`KeyScope`] discriminant.
    #[tbor(U8)]
    pub scope: KeyScope,

    /// Requested key-usage permissions, [`KeyUsage`] bitfield (u64) — a
    /// generated XTS key carries exactly `ENCRYPT | DECRYPT`.
    #[tbor(U64)]
    pub key_usage: KeyUsage,

    /// Caller-supplied key label recorded in the masked blob's
    /// `MaskedKeyMetadata.key_label`, up to 128 bytes.  Empty for an
    /// unlabeled key.
    #[tbor(buffer, max_len = 128)]
    pub key_label: &'a [u8],
}

/// `AesXtsGenerateKey` response schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can reserve the slot
/// and mask the generated key straight into it.
#[tbor(response, pair = TborAesXtsGenerateKeyReq)]
pub struct TborAesXtsGenerateKeyResp<'a> {
    /// The freshly generated XTS key, masked (AEAD-GCM-256) under the
    /// requested scope's masking key; 296 B.
    #[tbor(buffer, len = 296, mutable)]
    pub masked_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 256];
        let label = b"my-xts-key";
        let usage = KeyUsage::from_bits(KeyUsage::ENCRYPT | KeyUsage::DECRYPT);
        let frame = TborAesXtsGenerateKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(5))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .key_usage(usage)
            .unwrap()
            .key_label(label)
            .unwrap()
            .finish();

        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.key_usage(), usage);
        assert_eq!(frame.key_label(), label);
    }

    #[test]
    fn response_round_trips_masked_key() {
        let mut buf = [0u8; 512];
        let masked = [0xABu8; MASKED_AES_XTS_KEY_LEN];
        let frame = TborAesXtsGenerateKeyResp::encode(&mut buf, 0, true)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
    }

    #[test]
    fn masked_key_len_matches_pinned_value() {
        const _: () = assert!(296 == MASKED_AES_XTS_KEY_LEN);
    }
}
