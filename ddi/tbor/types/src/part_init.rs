// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `PartInit` command.
//!
//! `PartInit` is a CO-session command that derives the partition's
//! deterministic PTA keypair and records the merged security-domain
//! configuration params.  It persists the caller-asserted partition
//! policy (a CBOR document naming the POTA / SATA / optional SAPOTA
//! trust anchors by key thumbprint), and returns the PTA CSR and the
//! COSE_Sign1 PTA key-attestation report through out-of-band items
//! [`PART_INIT_CSR_OOB_INDEX`] and [`PART_INIT_REPORT_OOB_INDEX`].  The security-domain local
//! masking keys are derived later by a future part-final command.  See
//! `tsra_fw_ddi_tbor_types::part_init` for the full wire schema.

use alloc::vec::Vec;

use crate::tbor;
use crate::tbor_int::U16;

/// TBOR opcode for `PartInit`.
pub const TBOR_OP_PART_INIT: u8 = 0x07;

/// Length of the raw `mach_seed` plaintext (32 B).
pub const MACH_SEED_LEN: usize = 32;

/// AAD label prefix bound into the `mach_seed_envelope` AAD.
pub const PART_INIT_MACH_SEED_AAD_LABEL: &[u8; 17] = b"part-init-seed-v1";

/// Total AAD length bound into the `mach_seed_envelope` (label + session_id LE + zero-padding).
pub const PART_INIT_MACH_SEED_AAD_LEN: usize = 32;

/// Maximum on-the-wire length of the `mach_seed_envelope`.
pub const MACH_SEED_ENVELOPE_MAX_LEN: usize = 160;

/// Maximum on-the-wire length of the partition policy document.
pub use crate::policy::PART_POLICY_MAX_LEN;

/// Maximum length of the PTA CSR (ML-DSA-87 worst case).
pub const PTA_CSR_MAX_LEN: usize = 8192;

/// Maximum length of the PTA attestation report (ML-DSA-87 worst case).
pub const PTA_REPORT_MAX_LEN: usize = 8192;

/// Out-of-band item that receives the PTA CSR.
pub const PART_INIT_CSR_OOB_INDEX: usize = 0;

/// Out-of-band item that receives the PTA report.
pub const PART_INIT_REPORT_OOB_INDEX: usize = 1;

/// Host-facing TBOR `PartInit` request.
///
/// Field sizes are pinned to the FW schema; passing a slice of the
/// wrong length produces a host-side encode error before the request
/// reaches the device.
#[tbor(opcode = TBOR_OP_PART_INIT, session_ctrl = in_session)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TborPartInitReq {
    /// CO session id this request is bound to.  Cross-checked
    /// against the SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// AEAD-GCM envelope wrapping the 32-byte `mach_seed` plaintext
    /// under the active session's `param_key`.  Construct via the
    /// `encrypt_mach_seed_envelope` test harness helper, or by sealing
    /// directly under the canonical AAD layout
    /// pinned by [`PART_INIT_MACH_SEED_AAD_LABEL`] /
    /// [`PART_INIT_MACH_SEED_AAD_LEN`].
    #[tbor(max_len = 160)]
    pub mach_seed_envelope: Vec<u8>,

    /// Caller-asserted partition policy: a deterministic CBOR document
    /// of at most [`PART_POLICY_MAX_LEN`] bytes.
    #[tbor(max_len = 384)]
    pub part_policy: Vec<u8>,
}

/// Host-facing TBOR `PartInit` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TborPartInitResp {
    /// Bytes written to out-of-band item [`PART_INIT_CSR_OOB_INDEX`]
    /// (DER-encoded PKCS#10 CSR for the PTA public key).
    pub pta_csr_len: U16,

    /// Bytes written to out-of-band item [`PART_INIT_REPORT_OOB_INDEX`]
    /// (COSE_Sign1 PTA key-attestation report signed by the PID).
    pub pta_report_len: U16,
}
