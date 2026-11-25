// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartInit` wire schema (partition-provisioning Phase 1).
//!
//! `PartInit` is a CO-session command that derives the Partition Trust
//! Anchor (PTA) and Partition Identity (PID) keypairs, persists the
//! caller-asserted partition policy, and returns the
//! PTA CSR plus the PTA key-attestation report (`PTAReport`).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried CO session id; the dispatcher
//!   cross-checks it against the SQE-carried session id (parity with
//!   `PskChange` / `SessionClose`).
//! * `mach_seed` — 32-byte machine/host entropy contribution mixed
//!   into the partition's internal key-derivation.
//! * `part_policy` — caller-asserted partition policy bound into
//!   the partition's attested state.  Layout owned by
//!   [`crate::policy::PartPolicy`]; wire length bounded by
//!   [`PART_POLICY_MAX_LEN`].  Identifies the POTA / SATA / SAPOTA
//!   trust anchors by public-key thumbprint.
//!
//! Outputs:
//!
//! * Out-of-band item [`PART_INIT_CSR_OOB_INDEX`] — DER-encoded PKCS#10
//!   CertificationRequest for the PTA public key (≤ [`PTA_CSR_MAX_LEN`]
//!   bytes), signed by the PTA with the policy's `pta_alg`.
//! * Out-of-band item [`PART_INIT_REPORT_OOB_INDEX`] — COSE_Sign1 PTA
//!   key-attestation report (≤ [`PTA_REPORT_MAX_LEN`] bytes), signed by
//!   the partition identity key of the same algorithm.
//!
//! The inline response carries only the written length of each item.

use tsra_fw_ddi_tbor_api::tbor;

use crate::tbor_int::U16;

/// TBOR opcode for `PartInit`.
pub const TBOR_OP_PART_INIT: u8 = 0x07;

/// Length of the machine/host entropy contribution mixed into the
/// partition's internal key-derivation.
pub const MACH_SEED_LEN: usize = 32;

/// Domain/version label embedded in the AEAD envelope's AAD that
/// wraps the `mach_seed` plaintext.  Pinned per spec to bind the
/// envelope to this command + version.
pub const PART_INIT_MACH_SEED_AAD_LABEL: &[u8; 17] = b"part-init-seed-v1";

/// Length of the AAD bound into the `mach_seed` AEAD envelope.
///
/// Pinned to 32 B to satisfy the AEAD-envelope crate's AAD-granularity
/// invariant.  Layout: `label(17) ‖ session_id(2 LE) ‖ rsv0(13)`.
pub const PART_INIT_MACH_SEED_AAD_LEN: usize = 32;

/// Exact on-the-wire length of the wrapped `mach_seed_envelope`.
///
/// The envelope is fully deterministic: an AEAD-GCM envelope around the
/// 32-byte `mach_seed` plaintext with a 32-byte AAD —
/// `header(8) + iv(16) + aad(32) + ct(32) + tag(16)` = 104 B. Pinned as
/// a fixed-length field so a malformed length is rejected at decode.
pub const MACH_SEED_ENVELOPE_LEN: usize = 8 + 16 + PART_INIT_MACH_SEED_AAD_LEN + 32 + 16;

// Pin the computed envelope length to the `#[tbor(... = 104)]` literal on
// the `mach_seed_envelope` field (the derive requires an integer
// literal). If the envelope layout changes, update both.
const _: () = assert!(MACH_SEED_ENVELOPE_LEN == 104);

/// Maximum bytes the wrapped `mach_seed_envelope` may occupy on the
/// wire.
///
/// Retained as the documented upper bound (and for the host encoder,
/// which keeps a permissive `max_len` so negative tests can ship
/// wrong-length envelopes). The firmware schema itself pins the exact
/// [`MACH_SEED_ENVELOPE_LEN`].
pub const MACH_SEED_ENVELOPE_MAX_LEN: usize = 160;

/// Maximum byte length of the caller-asserted [`PartPolicy`] document
/// carried on the `PartInit` wire.
///
/// Re-exported from [`crate::policy`] — single source of truth.  The
/// `#[tbor(max_len = 384)]` attribute on [`TborPartInitReq::part_policy`]
/// must remain a numeric literal (TBOR derive requirement); the
/// `const _: () = assert!(384 == PART_POLICY_MAX_LEN)` guard in the
/// `tests` module below fails the build if the two ever drift.
///
/// [`PartPolicy`]: crate::policy::PartPolicy
pub use crate::policy::PART_POLICY_MAX_LEN;

/// Upper bound on the DER-encoded PTA CSR: an ML-DSA-87 CSR carries a
/// 2592-byte public key and a 4627-byte signature.
pub const PTA_CSR_MAX_LEN: usize = 8192;

/// Upper bound on the COSE_Sign1 PTA key-attestation report.  The
/// firmware handler pins this `>= KEY_REPORT_MAX_LEN` from the
/// key-report crate and rejects any larger report at runtime.
pub const PTA_REPORT_MAX_LEN: usize = 8192;

/// Out-of-band item that receives the PTA CSR.
pub const PART_INIT_CSR_OOB_INDEX: usize = 0;

/// Out-of-band item that receives the PTA report.
pub const PART_INIT_REPORT_OOB_INDEX: usize = 1;

/// `PartInit` request schema.
///
/// Initiates partition provisioning with the merged security-domain
/// configuration parameters: supplies the machine-seed entropy, the
/// unified caller-asserted [`PartPolicy`] (which carries both
/// partition-level and security-domain fields, including the POTA /
/// SATA / optional SAPOTA public-key thumbprints).  The security-domain local
/// masking keys are *not* derived here — that is deferred to a future
/// part-final command.
///
/// [`PartPolicy`]: crate::policy::PartPolicy
#[tbor(opcode = 0x07, pair = TborPartInitResp)]
pub struct TborPartInitReq<'a> {
    /// CO session id this request is bound to.  Typed
    /// [`SessionId`](tsra_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// AEAD-GCM envelope wrapping the 32-byte `mach_seed` plaintext
    /// under the active session's `param_key`.  Fixed length
    /// [`MACH_SEED_ENVELOPE_LEN`] (104 B); a malformed length is
    /// rejected at decode with `TborInvalidFixedLength`.  AAD layout is
    /// pinned to `label(17) ‖ session_id(2 LE) ‖ rsv0(13)` —
    /// see [`PART_INIT_MACH_SEED_AAD_LABEL`] and
    /// [`PART_INIT_MACH_SEED_AAD_LEN`].
    ///
    /// Marked `#[tbor(mutable)]` so the FW handler can AEAD-open the
    /// envelope in place — the field is exposed as the
    /// `mach_seed_envelope` member of the generated
    /// `TborPartInitReqViewMut` destructured view.
    #[tbor(buffer, len = 104, mutable)]
    pub mach_seed_envelope: &'a [u8],

    /// Caller-asserted unified [`PartPolicy`] blob bound into the
    /// partition's attested state.  Length bounded by
    /// [`PART_POLICY_MAX_LEN`].
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, max_len = 384)]
    pub part_policy: &'a [u8],
}

/// `PartInit` response schema.
///
/// The CSR and report travel out of band; the response carries their
/// written lengths.
#[tbor(response, pair = TborPartInitReq)]
pub struct TborPartInitResp {
    /// Bytes written to out-of-band item [`PART_INIT_CSR_OOB_INDEX`].
    pub pta_csr_len: U16,

    /// Bytes written to out-of-band item [`PART_INIT_REPORT_OOB_INDEX`].
    pub pta_report_len: U16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_policy_len_matches_pinned_value() {
        // The `#[tbor(max_len = 384)]` attribute on `part_policy` must
        // remain a numeric literal; this pins it against the
        // canonical `PART_POLICY_MAX_LEN` from `crate::policy`.
        const _: () = assert!(384 == PART_POLICY_MAX_LEN);
        assert_eq!(PART_POLICY_MAX_LEN, 384);
    }
}
