// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-owned DARC export request and encrypted-envelope response; the
//! PID-signed report is written to out-of-band item
//! [`DARC_REPORT_OOB_INDEX`](crate::DARC_REPORT_OOB_INDEX).

use alloc::vec::Vec;

use crate::darc_tmk_import::MASKED_TMK_LEN;
use crate::tbor;
use crate::tbor_int::U16;
use crate::CertDescriptor;
use crate::ReportDescriptor;

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
    /// Bound policy whose DATA key authorizes the target PID chain.
    #[tbor(max_len = 384)]
    pub policy: Vec<u8>,
    /// DATA-anchored target PID chain descriptors (1..=3 out-of-band
    /// certificates, normally DATA -> PTA -> PID).
    #[tbor(min_len = 3, max_len = 9)]
    pub target_cert_chain: Vec<CertDescriptor>,
    /// Descriptor of the out-of-band key report, signed by the target PID,
    /// attesting the device-generated DARC KEX recipient key.
    pub target_key_report: ReportDescriptor,
}

/// Directly PID-signed encrypted TMK.
#[tbor(response)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborDarcTmkExportResp {
    /// Length of the one complete signed artifact in OOB output item 0.
    pub report_len: U16,
}

#[cfg(test)]
mod tests {
    use tsra_ddi_tbor_types::TborOpReq;

    use super::*;

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
            target_key_report: ReportDescriptor {
                index: 1,
                length: U16::new(4700),
            },
        };
        let mut buf = [0; 2048];
        assert!(
            req.encode_request(&mut buf, (1, 1)).expect("encode").len()
                > crate::policy::PART_POLICY_MAX_LEN + MASKED_TMK_LEN
        );
    }
}
