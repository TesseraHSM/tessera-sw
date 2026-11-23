// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Import a P-384 HPKE Base TMK envelope after verifying its `Darc` report
//! against a POTA-endorsed source PID, then re-mask the TMK under the SDMK.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::darc_kex_key_gen::MASKED_KEX_KEY_LEN;
use crate::evidence::CertDescriptor;
pub use crate::policy::PART_POLICY_MAX_LEN;

/// TBOR opcode for `DarcTmkImport`.
pub const TBOR_OP_DARC_TMK_IMPORT: u8 = 0x21;
/// DARC TMK plaintext length.
pub const TMK_LEN: usize = 32;
/// Complete canonical P-384 DARC envelope, excluding its report.
pub const SEALED_TMK_LEN: usize = 113 + 97 + TMK_LEN + 16;
/// Maximum COSE_Sign1 operation-report size.
pub const DARC_REPORT_MAX_LEN: usize = 896;
/// Allow POTA -> PTA -> PID, without increasing other chain limits.
pub const DARC_SOURCE_CERT_CHAIN_MAX_CERTS: usize = 3;
/// Masked TMK: header, IV, metadata, ciphertext, and GCM tag.
pub const MASKED_TMK_LEN: usize = 8 + 16 + 192 + TMK_LEN + 16;

const _: () = assert!(MASKED_KEX_KEY_LEN == 280);
const _: () = assert!(PART_POLICY_MAX_LEN == 384);
const _: () = assert!(SEALED_TMK_LEN == 258);
const _: () = assert!(MASKED_TMK_LEN == 264);
const _: () = assert!(crate::evidence::CERT_DESCRIPTOR_LEN * DARC_SOURCE_CERT_CHAIN_MAX_CERTS == 9);

/// CO-only import request. A public-key attestation cannot replace `report`.
#[tbor(opcode = 0x21, pair = TborDarcTmkImportResp)]
pub struct TborDarcTmkImportReq<'a> {
    /// Session id, cross-checked against the SQE by the dispatcher.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Target's masked DARC recipient KEX key.
    #[tbor(align = 4, buffer, len = 280)]
    pub masked_kex_key: &'a [u8],

    /// Exact bound partition policy; its POTA authorizes the reporting PID.
    #[tbor(buffer, max_len = 384)]
    pub policy: &'a [u8],

    /// Canonical P-384 HPKE Base DARC envelope.
    #[tbor(buffer, len = 258)]
    pub sealed_tmk: &'a [u8],

    /// PID-signed version-2 `Darc` report returned by `DarcTmkExport`.
    #[tbor(buffer, min_len = 1, max_len = 896)]
    pub report: &'a [u8],

    /// POTA-endorsed source PID chain, root first, carried out of band.
    /// Normally POTA -> PTA -> PID, including the slot-2 PID leaf.
    #[tbor(buffer, min_len = 3, max_len = 9)]
    pub remote_cert_chain: &'a [CertDescriptor],
}

/// Imported TMK re-masked under the local security domain.
#[tbor(response, pair = TborDarcTmkImportReq)]
pub struct TborDarcTmkImportResp<'a> {
    /// Masked TMK compatible with `DarcTmkGen` and AES-KWP wrapping.
    #[tbor(align = 4, buffer, len = 264)]
    pub masked_tmk: &'a [u8],
}

#[cfg(test)]
mod tests {
    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;
    use crate::tbor_int::U16;

    #[test]
    fn request_round_trips_fields() {
        let masked_kex = [0; MASKED_KEX_KEY_LEN];
        let policy = [0; PART_POLICY_MAX_LEN];
        let sealed = [0xAB; SEALED_TMK_LEN];
        let report = [0xCD; 320];
        let descs = [CertDescriptor {
            index: 0,
            length: U16::new(32),
        }; 3];
        let mut buf = [0; 2048];
        let frame = TborDarcTmkImportReq::encode(&mut buf, (1, 1))
            .expect("encode")
            .session_id(SessionId(7))
            .expect("session")
            .masked_kex_key(&masked_kex)
            .expect("KEX")
            .policy(&policy)
            .expect("policy")
            .sealed_tmk(&sealed)
            .expect("envelope")
            .report(&report)
            .expect("report")
            .remote_cert_chain(&descs)
            .expect("chain")
            .finish();
        assert_eq!(frame.masked_kex_key(), &masked_kex[..]);
        assert_eq!(frame.sealed_tmk(), &sealed[..]);
        assert_eq!(frame.report(), &report[..]);
        assert_eq!(frame.remote_cert_chain().len(), 9);
    }

    #[test]
    fn response_round_trips_masked_tmk() {
        let masked = [0xCD; MASKED_TMK_LEN];
        let mut buf = [0; 512];
        let frame = TborDarcTmkImportResp::encode(&mut buf, (1, 1), 0, true)
            .expect("encode")
            .masked_tmk(&masked)
            .expect("TMK")
            .finish();
        assert_eq!(frame.masked_tmk(), &masked[..]);
    }
}
