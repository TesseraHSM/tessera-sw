// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Export a locally masked DARC TMK using P-384 HPKE Base and a PID-signed
//! signature. The target KEX key must be DATA-endorsed.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::darc_tmk_import::DARC_REPORT_MAX_LEN;
pub use crate::darc_tmk_import::DARC_REPORT_OOB_INDEX;
pub use crate::darc_tmk_import::MASKED_TMK_LEN;
pub use crate::darc_tmk_import::SEALED_TMK_LEN;
pub use crate::darc_tmk_import::SEALED_TMK_MAX_LEN;
pub use crate::darc_tmk_import::TMK_LEN;
use crate::evidence::CertDescriptor;
use crate::evidence::ReportDescriptor;
pub use crate::policy::PART_POLICY_MAX_LEN;
use crate::tbor_int::U16;

/// TBOR opcode for `DarcTmkExport`.
pub const TBOR_OP_DARC_TMK_EXPORT: u8 = 0x24;

const _: () = assert!(MASKED_TMK_LEN == 264);
const _: () = assert!(PART_POLICY_MAX_LEN == 384);
const _: () = assert!(SEALED_TMK_LEN == 367);
const _: () = assert!(crate::evidence::CERT_DESCRIPTOR_LEN == 3);
const _: () = assert!(crate::evidence::REPORT_DESCRIPTOR_LEN == 3);

/// CO-only request. All operation-report claims are derived on-device.
#[tbor(opcode = 0x24, pair = TborDarcTmkExportResp)]
pub struct TborDarcTmkExportReq<'a> {
    /// Session id, cross-checked against the SQE by the dispatcher.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Locally masked TMK from `DarcTmkGen` or `DarcTmkImport`.
    #[tbor(align = 4, buffer, len = 264)]
    pub masked_tmk: &'a [u8],

    /// Exact bound partition policy; its DATA key authorizes the target.
    #[tbor(buffer, max_len = 384)]
    pub policy: &'a [u8],

    /// DATA-anchored target PID certificates (normally DATA -> PTA -> PID),
    /// root first, carried out of band. The leaf is P-384 or ML-DSA-87.
    #[tbor(buffer, min_len = 3, max_len = 9)]
    pub target_cert_chain: &'a [CertDescriptor],

    /// Out-of-band key report signed by the target PID leaf attesting a
    /// device-generated DARC KEX key, which becomes the HPKE recipient.
    #[tbor(buffer, len = 3)]
    pub target_key_report: &'a ReportDescriptor,
}

/// Directly signed encrypted TMK envelope.
#[tbor(response, pair = TborDarcTmkExportReq)]
pub struct TborDarcTmkExportResp {
    /// Complete signed-artifact length in OOB output item 0.
    pub report_len: U16,
}

#[cfg(test)]
mod tests {
    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let masked_tmk = [0; MASKED_TMK_LEN];
        let policy = [0; PART_POLICY_MAX_LEN];
        let descs = [CertDescriptor {
            index: 0,
            length: U16::new(32),
        }; 3];
        let report = ReportDescriptor {
            index: 4,
            length: U16::new(4700),
        };
        let mut buf = [0; 2048];
        let frame = TborDarcTmkExportReq::encode(&mut buf, (1, 1))
            .expect("encode")
            .session_id(SessionId(7))
            .expect("session")
            .masked_tmk(&masked_tmk)
            .expect("TMK")
            .policy(&policy)
            .expect("policy")
            .target_cert_chain(&descs)
            .expect("chain")
            .target_key_report(&report)
            .expect("report")
            .finish();
        assert_eq!(frame.masked_tmk(), &masked_tmk[..]);
        assert_eq!(frame.policy(), &policy[..]);
        assert_eq!(frame.target_cert_chain().len(), 9);
        assert_eq!(
            frame.target_key_report(),
            zerocopy::IntoBytes::as_bytes(&report)
        );
    }

    #[test]
    fn response_round_trips_signed_tmk_length() {
        let mut buf = [0; 1024];
        let frame = TborDarcTmkExportResp::encode(&mut buf, (1, 1), 0, true)
            .expect("encode")
            .report_len(U16::new(6467))
            .expect("artifact length")
            .finish();
        assert_eq!(frame.report_len().get(), 6467);
    }
}
