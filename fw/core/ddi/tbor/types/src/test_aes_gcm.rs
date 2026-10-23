// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `TestAesGcm` wire schema (test-only).
//!
//! `TestAesGcm` AES-256-GCM encrypts or decrypts up to
//! [`TEST_AES_GCM_DATA_MAX_LEN`] bytes under a **raw** key carried in the
//! request, through the platform's `HsmAes` bulk GCM path. It exists to
//! bring up and validate a platform GCM engine end to end without key
//! provisioning or a session. The firmware dispatches it only when built
//! with the `tbor-test-cmds` feature: it is an encryption oracle under
//! host-chosen keys and must never ship in a production image.
//!
//! Inputs:
//!
//! * `op` — the [`AesOp`] selecting encrypt or decrypt.
//! * `key` — the 32-byte AES-256 key.
//! * `iv` — the 12-byte (96-bit) GCM IV.
//! * `aad` — additional authenticated data, up to
//!   [`TEST_AES_GCM_AAD_MAX_LEN`] bytes (may be empty).
//! * `data` — plaintext (encrypt) or ciphertext (decrypt), up to
//!   [`TEST_AES_GCM_DATA_MAX_LEN`] bytes (may be empty).
//! * `tag` — the expected 16-byte tag (decrypt); ignored on encrypt.
//!
//! Outputs:
//!
//! * `data` — the transformed text (same length as the input `data`).
//! * `tag` — the computed tag (encrypt) or the verified tag (decrypt).

use tsra_fw_ddi_tbor_api::tbor;

use crate::aes_encrypt_decrypt::AesOp;

/// TBOR opcode for the test-only `TestAesGcm` command.
pub const TBOR_OP_TEST_AES_GCM: u8 = 0xF0;

/// AES-256 key length in bytes.
pub const TEST_AES_GCM_KEY_LEN: usize = 32;

/// GCM IV length in bytes (96-bit IV).
pub const TEST_AES_GCM_IV_LEN: usize = 12;

/// GCM tag length in bytes.
pub const TEST_AES_GCM_TAG_LEN: usize = 16;

/// Maximum AAD length in bytes.
pub const TEST_AES_GCM_AAD_MAX_LEN: usize = 256;

/// Maximum plaintext / ciphertext length in bytes.
pub const TEST_AES_GCM_DATA_MAX_LEN: usize = 2048;

/// `TestAesGcm` request schema.
#[tbor(opcode = 0xF0)]
pub struct TborTestAesGcmReq<'a> {
    /// The direction, carried as the 1-byte [`AesOp`] discriminant.
    #[tbor(U8)]
    pub op: AesOp,

    /// The 32-byte AES-256 key.
    #[tbor(buffer, len = 32)]
    pub key: &'a [u8],

    /// The 12-byte GCM IV.
    #[tbor(buffer, len = 12)]
    pub iv: &'a [u8],

    /// Additional authenticated data, up to 256 bytes.
    #[tbor(buffer, max_len = 256)]
    pub aad: &'a [u8],

    /// Plaintext (encrypt) or ciphertext (decrypt), up to 2048 bytes.
    #[tbor(buffer, max_len = 2048)]
    pub data: &'a [u8],

    /// Expected tag for decrypt; ignored on encrypt.
    #[tbor(buffer, len = 16)]
    pub tag: &'a [u8],
}

/// `TestAesGcm` response schema.
///
/// Both slots are `#[tbor(mutable)]` so the handler can reserve them and
/// fill them in place after the GCM operation.
#[tbor(response)]
pub struct TborTestAesGcmResp<'a> {
    /// The transformed text (same length as the request `data`).
    #[tbor(buffer, max_len = 2048, mutable)]
    pub data: &'a [u8],

    /// The computed (encrypt) or verified (decrypt) tag.
    #[tbor(buffer, len = 16, mutable)]
    pub tag: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let mut buf = [0u8; 2560];
        let key = [0x11u8; TEST_AES_GCM_KEY_LEN];
        let iv = [0x22u8; TEST_AES_GCM_IV_LEN];
        let aad = [0x33u8; 20];
        let data = [0x44u8; 60];
        let tag = [0x55u8; TEST_AES_GCM_TAG_LEN];
        let frame = TborTestAesGcmReq::encode(&mut buf)
            .unwrap()
            .op(AesOp::Decrypt)
            .unwrap()
            .key(&key)
            .unwrap()
            .iv(&iv)
            .unwrap()
            .aad(&aad)
            .unwrap()
            .data(&data)
            .unwrap()
            .tag(&tag)
            .unwrap()
            .finish();

        assert_eq!(frame.op(), AesOp::Decrypt);
        assert_eq!(frame.key(), &key[..]);
        assert_eq!(frame.iv(), &iv[..]);
        assert_eq!(frame.aad(), &aad[..]);
        assert_eq!(frame.data(), &data[..]);
        assert_eq!(frame.tag(), &tag[..]);
    }

    #[test]
    fn request_accepts_empty_aad_and_data() {
        let mut buf = [0u8; 256];
        let frame = TborTestAesGcmReq::encode(&mut buf)
            .unwrap()
            .op(AesOp::Encrypt)
            .unwrap()
            .key(&[0u8; TEST_AES_GCM_KEY_LEN])
            .unwrap()
            .iv(&[0u8; TEST_AES_GCM_IV_LEN])
            .unwrap()
            .aad(&[])
            .unwrap()
            .data(&[])
            .unwrap()
            .tag(&[0u8; TEST_AES_GCM_TAG_LEN])
            .unwrap()
            .finish();
        assert!(frame.aad().is_empty());
        assert!(frame.data().is_empty());
    }

    #[test]
    fn response_reserve_matches_value_layout() {
        let mut buf_v = [0u8; 2560];
        let data = [0x66u8; 60];
        let tag = [0x77u8; TEST_AES_GCM_TAG_LEN];
        let len_v = TborTestAesGcmResp::encode(&mut buf_v, 0, false)
            .unwrap()
            .data(&data)
            .unwrap()
            .tag(&tag)
            .unwrap()
            .finish()
            .as_bytes()
            .len();

        let mut buf_r = [0u8; 2560];
        let frame_r = TborTestAesGcmResp::encode(&mut buf_r, 0, false)
            .unwrap()
            .data_reserve(60)
            .unwrap()
            .tag_reserve(TEST_AES_GCM_TAG_LEN)
            .unwrap()
            .finish();
        assert_eq!(frame_r.as_bytes().len(), len_v);
        assert_eq!(frame_r.data().len(), 60);
        assert_eq!(frame_r.tag().len(), TEST_AES_GCM_TAG_LEN);
    }

    #[test]
    fn lengths_match_pinned_values() {
        // The `#[tbor(...)]` attributes must stay numeric literals; pin
        // them against the exported consts.
        const _: () = assert!(TBOR_OP_TEST_AES_GCM == 0xF0);
        const _: () = assert!(TEST_AES_GCM_KEY_LEN == 32);
        const _: () = assert!(TEST_AES_GCM_IV_LEN == 12);
        const _: () = assert!(TEST_AES_GCM_TAG_LEN == 16);
        const _: () = assert!(TEST_AES_GCM_AAD_MAX_LEN == 256);
        const _: () = assert!(TEST_AES_GCM_DATA_MAX_LEN == 2048);
    }
}
