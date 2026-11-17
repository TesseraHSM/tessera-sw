// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-owned DARC export request and encrypted-envelope/report response.

use alloc::vec::Vec;

use crate::darc_tmk_import::DARC_REPORT_MAX_LEN;
use crate::darc_tmk_import::MASKED_TMK_LEN;
use crate::darc_tmk_import::SEALED_TMK_LEN;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `DarcTmkExport`.
pub const TBOR_OP_DARC_TMK_EXPORT: u8 = 0x24;

/// Export a local TMK to a DATA-endorsed recipient using HPKE Base.
#[tbor(opcode = TBOR_OP_DARC_TMK_EXPORT, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborDarcTmkExportReq {
    /// Crypto-Officer session.
    #[tbor(session_id)]
    pub session_id: u16,
    /// Local masked TMK, not a caller-supplied plaintext or report claim.
    #[tbor(align = 4)]
    pub masked_tmk: [u8; MASKED_TMK_LEN],
    /// Bound policy whose DATA key authorizes the target KEX certificate.
    #[tbor(max_len = 384)]
    pub policy: Vec<u8>,
    /// Target chain descriptors for 1..=2 out-of-band certificates.
    #[tbor(min_len = 3, max_len = 6)]
    pub target_cert_chain: Vec<CertDescriptor>,
}

/// Canonical encrypted TMK and separate PID-signed operation report.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborDarcTmkExportResp {
    /// `header(113) || enc(97) || ciphertext(32) || tag(16)`.
    pub sealed_tmk: [u8; SEALED_TMK_LEN],
    /// Version-2 `Darc` report binding this envelope and its recipient.
    #[tbor(min_len = 1, max_len = 896)]
    pub report: Vec<u8>,
}

const _: () = assert!(DARC_REPORT_MAX_LEN == 896);

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::tbor_int::U16;

    #[test]
    fn request_encodes_all_fields() {
        let req = TborDarcTmkExportReq {
            session_id: 9,
            masked_tmk: [0; MASKED_TMK_LEN],
            policy: alloc::vec![0; crate::policy::PART_POLICY_MAX_LEN],
            target_cert_chain: alloc::vec![CertDescriptor {
                index: 0,
                length: U16::new(32)
            }],
        };
        let mut buf = [0; 2048];
        assert!(
            req.encode_request(&mut buf).expect("encode").len()
                > crate::policy::PART_POLICY_MAX_LEN + MASKED_TMK_LEN
        );
    }
}
