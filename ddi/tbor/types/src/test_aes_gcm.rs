// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the test-only TBOR `TestAesGcm` command.
//!
//! `TestAesGcm` is an **out-of-session** command that AES-256-GCM
//! encrypts or decrypts `data` under a **raw** key carried in the
//! request, through the device's regular HSM GCM path.  It exists to
//! bring up and validate a platform GCM engine end to end, without key
//! provisioning or a session.  The firmware only dispatches it when
//! built with the `tbor-test-cmds` feature; production images reject
//! the opcode.

use alloc::vec::Vec;

use crate::tbor;

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

/// Host-facing TBOR `TestAesGcm` request.
#[tbor(opcode = TBOR_OP_TEST_AES_GCM, session_ctrl = no_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborTestAesGcmReq {
    /// The direction as the 1-byte `AesOp` discriminant (see
    /// [`AES_OP_ENCRYPT`](crate::AES_OP_ENCRYPT) /
    /// [`AES_OP_DECRYPT`](crate::AES_OP_DECRYPT)).
    pub op: u8,

    /// The raw AES-256 key.
    pub key: [u8; 32],

    /// The 96-bit GCM IV.
    pub iv: [u8; 12],

    /// Additional authenticated data, up to [`TEST_AES_GCM_AAD_MAX_LEN`]
    /// bytes (may be empty).
    #[tbor(max_len = 256)]
    pub aad: Vec<u8>,

    /// Plaintext (encrypt) or ciphertext (decrypt), up to
    /// [`TEST_AES_GCM_DATA_MAX_LEN`] bytes (may be empty).
    #[tbor(max_len = 2048)]
    pub data: Vec<u8>,

    /// The expected tag for decrypt; ignored on encrypt.
    pub tag: [u8; 16],
}

/// Host-facing TBOR `TestAesGcm` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborTestAesGcmResp {
    /// The transformed text (same length as the request `data`).
    #[tbor(max_len = 2048)]
    pub data: Vec<u8>,

    /// The computed (encrypt) or verified (decrypt) tag.
    pub tag: [u8; 16],
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::AES_OP_ENCRYPT;

    #[test]
    fn request_encodes_max_lengths() {
        let req = TborTestAesGcmReq {
            op: AES_OP_ENCRYPT,
            key: [0x11u8; TEST_AES_GCM_KEY_LEN],
            iv: [0x22u8; TEST_AES_GCM_IV_LEN],
            aad: alloc::vec![0x33u8; TEST_AES_GCM_AAD_MAX_LEN],
            data: alloc::vec![0x44u8; TEST_AES_GCM_DATA_MAX_LEN],
            tag: [0x55u8; TEST_AES_GCM_TAG_LEN],
        };

        let mut buf = [0u8; 4096];
        let frame = req.encode_request(&mut buf).expect("encode");

        assert!(
            frame
                .windows(TEST_AES_GCM_DATA_MAX_LEN)
                .any(|w| w.iter().all(|&b| b == 0x44)),
            "encoded frame must carry the data bytes",
        );
    }

    #[test]
    fn opcode_and_session_ctrl() {
        let req = TborTestAesGcmReq::default();
        assert_eq!(TborTestAesGcmReq::OPCODE, TBOR_OP_TEST_AES_GCM);
        assert_eq!(req.get_session_id(), None);
        assert_eq!(
            req.session_ctrl(),
            tsra_ddi_tbor_types::SessionControlKind::NoSession
        );
    }
}
