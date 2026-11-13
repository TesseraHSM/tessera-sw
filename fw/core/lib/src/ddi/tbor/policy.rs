// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Firmware-side parser for the partition policy ([`PartPolicy`]).
//!
//! The policy is a deterministic CBOR document whose schema and
//! decoder live in [`tsra_fw_ddi_tbor_types::policy`] (see
//! `docs/tbor-ddi/part_policy.md`).  That crate stays free of firmware
//! deps (`HsmDmaBuf`, `HsmError`), so this thin adapter maps every
//! decode failure to [`HsmError::InvalidArg`].

use tsra_fw_ddi_tbor_types::policy::PartPolicy;
use tsra_fw_ddi_tbor_types::policy::PART_POLICY_MAX_LEN;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;

// `tsra_fw_hsm_pal_traits` has no dependency on the TBOR types crate, so
// pin the two copies of the policy size cap together at build time.
const _: () = assert!(tsra_fw_hsm_pal_traits::PART_POLICY_MAX_LEN == PART_POLICY_MAX_LEN);

/// Decode and validate a `PartPolicy` document resident in `buf`.
///
/// The returned view borrows `buf`; callers that also need the raw bytes
/// for hashing keep the same `&HsmDmaBuf`.
///
/// # Errors
///
/// - [`HsmError::InvalidArg`] — `buf` is not a valid, canonically
///   encoded policy document.
pub fn from_bytes(buf: &HsmDmaBuf) -> HsmResult<PartPolicy<'_>> {
    PartPolicy::decode(buf).map_err(|_| HsmError::InvalidArg)
}
