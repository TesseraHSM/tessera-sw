// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COSE_Sign1 key-attestation report builder and parser for TSRA
//! firmware.
//!
//! Emits and parses CBOR / `COSE_Sign1` key-attestation reports whose
//! wire format matches the host report codec
//! (`ddi/mbor/test_helpers/src/report.rs`) byte-for-byte. The attested public key
//! may be ECC, RSA, ML-DSA-87, or symmetric; the report is signed with
//! ES384 (ECDSA-P384) or ML-DSA-87 ([`ReportSigner`]), named by the COSE
//! protected header. Signing and verification are routed through
//! the supplied [`HsmCrypto`](tsra_fw_hsm_pal_traits::HsmCrypto)
//! implementation, and all working buffers are
//! [`HsmDmaBuf`](tsra_fw_hsm_pal_traits::HsmDmaBuf) allocations.
//!
//! * [`key_report`] — build a signed report (query/copy convention).
//! * [`parse_key_report`] — zero-copy decode into a [`KeyReportView`].
//! * [`verify_key_report`] — check a report's ES384 signature.
//! * [`report`] / [`parse_report`] / [`verify_report`] — public-key
//!   attestations and directly signed DARC/SD transfer envelopes.

#![no_std]

mod codec;
mod consts;
mod cose_key;
mod decode;
mod encode;
mod report;
mod sig;
pub mod transfer;

pub use consts::KeyFlags;
pub use consts::APP_UUID_LEN;
pub use consts::KEM_KEY_REPORT_MAX_LEN;
pub use consts::KEY_REPORT_MAX_LEN;
pub use consts::MLDSA87_COSE_KEY_LEN;
pub use consts::MLDSA87_PUB_KEY_LEN;
pub use consts::MLDSA87_SIGNATURE_LEN;
pub use consts::MLDSA_SEED_LEN;
pub use consts::MLKEM1024P384_COSE_KEY_LEN;
pub use consts::MLKEM1024P384_PUB_KEY_LEN;
pub use consts::MLKEM1024_COSE_KEY_LEN;
pub use consts::MLKEM1024_PUB_KEY_LEN;
pub use consts::POLICY_HASH_LEN;
pub use consts::PRIV_KEY_LEN;
pub use consts::PUBLIC_KEY_MAX_SIZE;
pub use consts::REPORT_DATA_LEN;
pub use consts::REPORT_MAX_LEN;
pub use consts::REPORT_VERSION;
pub use consts::REPORT_VERSION_V2;
pub use consts::SIGNATURE_LEN;
pub use consts::VM_LAUNCH_ID_LEN;
pub use cose_key::parse_akp_cose_key;
pub use cose_key::parse_ec2_cose_key;
pub use cose_key::AttestedPubKey;
pub use cose_key::Ec2CoseKey;
pub use cose_key::COSE_ALG_MLKEM1024;
pub use cose_key::COSE_ALG_MLKEM1024_P384;
pub use decode::parse_key_report;
pub use decode::parse_report;
pub use decode::verify_key_report;
pub use decode::verify_key_report_with;
pub use decode::verify_report;
pub use decode::verify_report_with;
pub use decode::KeyReportView;
pub use encode::key_report;
pub use encode::key_report_with;
pub use encode::report;
pub use encode::report_with;
pub use encode::transfer_report_len;
pub use encode::KeyReportParams;
pub use report::ReportAlg;
pub use report::ReportKind;
pub use report::ReportParams;
pub use report::ReportSigner;
pub use report::ReportVerifier;
pub use report::ReportView;
pub use report::TransferReportView;
