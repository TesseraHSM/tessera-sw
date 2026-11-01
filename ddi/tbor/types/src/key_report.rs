// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `KeyReport` command.
//!
//! `KeyReport` is an **in-session** command that takes a **masked key**
//! (e.g. the `masked_key` returned by `SdSealingKeyGen`), unmasks it,
//! derives the attested key's public component on-device, and returns a
//! signed COSE_Sign1 key-attestation report over it. The report is signed
//! by the partition-identity (PID) key.
//!
//! The request carries the masked-key envelope to attest plus a
//! caller-supplied 128-byte `report_data` bound into the report payload.
//! Both active Crypto-Officer and Crypto-User sessions may attest keys on
//! a finalized partition after rotating their role's default PSK.
//! CU requests also prove possession of their session parameter key through
//! `auth_envelope`; both roles must use their current TBOR credential.

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `KeyReport`.
///
/// `0x0A..=0x0F` are reserved by the Security-Domain backup schema family
/// (`SdCreateRemoteBackup` .. `SdRestorePeerBackup`), so `KeyReport`
/// takes the next free opcode, `0x10`.
pub const TBOR_OP_KEY_REPORT: u8 = 0x10;

/// Maximum wire length of the `masked_key` request buffer (a masked-key
/// AEAD envelope), matching the largest key returned by `UnwrapKey`.
pub const KEY_REPORT_MASKED_KEY_MAX_LEN: usize = crate::UNWRAP_MASKED_KEY_MAX_LEN;

/// Length of the caller-supplied `report_data` bound into the report.
pub const KEY_REPORT_DATA_LEN: usize = 128;

/// AEAD authentication envelope: 32 B AAD and a 48 B request digest.
pub const KEY_REPORT_AUTH_ENVELOPE_LEN: usize = 120;

/// Bind request authentication to this command and session.
pub fn build_key_report_auth_aad(session_id: u16) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[..13].copy_from_slice(b"key-report-v1");
    aad[13..15].copy_from_slice(&session_id.to_le_bytes());
    aad
}

/// Maximum wire length of the returned COSE_Sign1 `report`.
pub const KEY_REPORT_MAX_LEN: usize = 1024;

/// Host-facing TBOR `KeyReport` request.
#[tbor(opcode = TBOR_OP_KEY_REPORT, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborKeyReportReq {
    /// Session id this request is bound to. Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked-key envelope to attest. Variable length up to
    /// [`KEY_REPORT_MASKED_KEY_MAX_LEN`].
    #[tbor(max_len = 3168)]
    pub masked_key: Vec<u8>,

    /// Caller-supplied [`KEY_REPORT_DATA_LEN`] (128 B) report data.
    pub report_data: [u8; KEY_REPORT_DATA_LEN],

    /// Session-param-key AEAD envelope of SHA-384(masked_key || report_data).
    /// Required for CU requests; CO may omit it with an empty buffer.
    #[tbor(max_len = 160)]
    pub auth_envelope: Vec<u8>,
}

/// Host-facing TBOR `KeyReport` response.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborKeyReportResp {
    /// The tagged COSE_Sign1 key-attestation report, signed by the PID
    /// key. Variable length up to [`KEY_REPORT_MAX_LEN`].
    #[tbor(max_len = 1024)]
    pub report: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_and_masked_key() {
        let req = TborKeyReportReq {
            auth_envelope: Vec::new(),
            session_id: 9,
            masked_key: alloc::vec![0xCD; 180],
            report_data: [0xAB; KEY_REPORT_DATA_LEN],
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The masked-key bytes must appear in the encoded frame.
        assert!(
            frame.windows(4).any(|w| w == [0xCD; 4]),
            "encoded frame must carry the masked key",
        );
    }
}
