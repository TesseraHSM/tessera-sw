// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Import an HPKE Base TMK envelope (P-384, ML-KEM-1024 or MLKEM1024-P384
//! recipient) after verifying its `Darc` report against a POTA-endorsed
//! source PID (P-384 or ML-DSA-87), then re-mask the TMK under the SDMK.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::darc_kex_key_gen::MASKED_KEX_KEY_LEN;
pub use crate::darc_kex_key_gen::MASKED_KEX_KEY_MAX_LEN;
pub use crate::darc_kex_key_gen::MASKED_KEX_KEY_MIN_LEN;
use crate::evidence::CertDescriptor;
use crate::evidence::ReportDescriptor;
pub use crate::policy::PART_POLICY_MAX_LEN;

/// TBOR opcode for `DarcTmkImport`.
pub const TBOR_OP_DARC_TMK_IMPORT: u8 = 0x21;
/// DARC TMK plaintext length.
pub const TMK_LEN: usize = 32;
/// ES384 COSE_Sign1 containing the canonical P-384 DARC envelope.
pub const SEALED_TMK_LEN: usize = 367;
/// Largest complete signed DARC artifact (hybrid recipient, ML-DSA-87 PID).
pub const SEALED_TMK_MAX_LEN: usize = 6467;
/// Maximum complete signed DARC artifact transferred out of band.
pub const DARC_REPORT_MAX_LEN: usize = SEALED_TMK_MAX_LEN;
/// Complete signed artifact output slot for DARC export.
pub const DARC_REPORT_OOB_INDEX: usize = 0;
/// Allow POTA -> PTA -> PID, without increasing other chain limits.
pub const DARC_SOURCE_CERT_CHAIN_MAX_CERTS: usize = 3;
/// Masked TMK: header, IV, metadata, ciphertext, and GCM tag.
pub const MASKED_TMK_LEN: usize = 8 + 16 + 192 + TMK_LEN + 16;

const _: () = assert!(MASKED_KEX_KEY_MIN_LEN == 264);
const _: () = assert!(MASKED_KEX_KEY_MAX_LEN == 296);
const _: () = assert!(PART_POLICY_MAX_LEN == 384);
const _: () = assert!(SEALED_TMK_LEN == 367);
const _: () = assert!(MASKED_TMK_LEN == 264);
const _: () = assert!(crate::evidence::CERT_DESCRIPTOR_LEN * DARC_SOURCE_CERT_CHAIN_MAX_CERTS == 9);

/// CO-only import request. A public-key attestation cannot replace the signed TMK.
#[tbor(opcode = 0x21, pair = TborDarcTmkImportResp)]
pub struct TborDarcTmkImportReq<'a> {
    /// Session id, cross-checked against the SQE by the dispatcher.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Target's masked DARC recipient KEX key (P-384, ML-KEM-1024 or
    /// MLKEM1024-P384).
    #[tbor(align = 4, buffer, min_len = 264, max_len = 296)]
    pub masked_kex_key: &'a [u8],

    /// Exact bound partition policy; its POTA authorizes the reporting PID.
    #[tbor(buffer, max_len = 384)]
    pub policy: &'a [u8],

    /// OOB complete PID-signed HPKE Base artifact.
    #[tbor(buffer, len = 3)]
    pub sealed_tmk: &'a ReportDescriptor,

    /// POTA-endorsed source PID chain, root first, carried out of band.
    /// Normally POTA -> PTA -> PID; the PID leaf is P-384 or ML-DSA-87.
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
        let masked_kex = [0; MASKED_KEX_KEY_MAX_LEN];
        let policy = [0; PART_POLICY_MAX_LEN];
        let sealed = ReportDescriptor {
            index: 4,
            length: U16::new(6467),
        };
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
            .remote_cert_chain(&descs)
            .expect("chain")
            .finish();
        assert_eq!(frame.masked_kex_key(), &masked_kex[..]);
        assert_eq!(frame.sealed_tmk(), zerocopy::IntoBytes::as_bytes(&sealed));
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
