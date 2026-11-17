// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Export a locally masked DARC TMK using P-384 HPKE Base and a PID-signed
//! operation report. The target KEX key must be DATA-endorsed.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::darc_tmk_import::DARC_REPORT_MAX_LEN;
pub use crate::darc_tmk_import::MASKED_TMK_LEN;
pub use crate::darc_tmk_import::SEALED_TMK_LEN;
pub use crate::darc_tmk_import::TMK_LEN;
use crate::evidence::CertDescriptor;
pub use crate::policy::PART_POLICY_MAX_LEN;

/// TBOR opcode for `DarcTmkExport`.
pub const TBOR_OP_DARC_TMK_EXPORT: u8 = 0x24;

const _: () = assert!(MASKED_TMK_LEN == 264);
const _: () = assert!(PART_POLICY_MAX_LEN == 384);
const _: () = assert!(SEALED_TMK_LEN == 258);
const _: () = assert!(DARC_REPORT_MAX_LEN == 896);
const _: () = assert!(crate::evidence::CERT_DESCRIPTOR_LEN == 3);
const _: () = assert!(crate::evidence::CERT_DESCRIPTORS_MAX_LEN == 6);

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

    /// DATA-anchored target KEX certificates, root first, carried out of band.
    #[tbor(buffer, min_len = 3, max_len = 6)]
    pub target_cert_chain: &'a [CertDescriptor],
}

/// Encrypted envelope and separate, operation-bound report.
#[tbor(response, pair = TborDarcTmkExportReq)]
pub struct TborDarcTmkExportResp<'a> {
    /// `header(113) || enc(97) || ciphertext(32) || GCM tag(16)`.
    #[tbor(buffer, len = 258)]
    pub sealed_tmk: &'a [u8],

    /// PID-signed version-2 `Darc` report for this exact envelope/recipient.
    #[tbor(buffer, min_len = 1, max_len = 896)]
    pub report: &'a [u8],
}

#[cfg(test)]
mod tests {
    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;
    use crate::tbor_int::U16;

    #[test]
    fn request_round_trips_fields() {
        let masked_tmk = [0; MASKED_TMK_LEN];
        let policy = [0; PART_POLICY_MAX_LEN];
        let descs = [CertDescriptor {
            index: 0,
            length: U16::new(32),
        }];
        let mut buf = [0; 2048];
        let frame = TborDarcTmkExportReq::encode(&mut buf)
            .expect("encode")
            .session_id(SessionId(7))
            .expect("session")
            .masked_tmk(&masked_tmk)
            .expect("TMK")
            .policy(&policy)
            .expect("policy")
            .target_cert_chain(&descs)
            .expect("chain")
            .finish();
        assert_eq!(frame.masked_tmk(), &masked_tmk[..]);
        assert_eq!(frame.policy(), &policy[..]);
        assert_eq!(
            frame.target_cert_chain().len(),
            crate::evidence::CERT_DESCRIPTOR_LEN
        );
    }

    #[test]
    fn response_round_trips_sealed_tmk_and_report() {
        let sealed = [0xCD; SEALED_TMK_LEN];
        let report = [0xAB; 320];
        let mut buf = [0; 1024];
        let frame = TborDarcTmkExportResp::encode(&mut buf, 0, true)
            .expect("encode")
            .sealed_tmk(&sealed)
            .expect("envelope")
            .report(&report)
            .expect("report")
            .finish();
        assert_eq!(frame.sealed_tmk(), &sealed[..]);
        assert_eq!(frame.report(), &report[..]);
    }
}
