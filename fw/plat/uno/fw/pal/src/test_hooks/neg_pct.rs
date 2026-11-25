// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `TestAction::TriggerNegativePctFailure` (action 15) support.
//!
//! The action arms a partition with a PCT kind and a skip count. Only
//! pairwise consistency tests (PCTs) of that kind count down: the first
//! `skip` of them run normally, and the next one runs against a public key
//! that is valid but does not belong to the private key under test, so the
//! PCT itself detects the inconsistency and the module enters the FIPS error
//! state. PCTs of other kinds are not affected. Each kind matches one PCT
//! failure code, so the error state's log line shows which PCT failed.
//!
//! The substitute keys are well-formed so that the PCT reports a mismatch
//! (`Ok(false)`) rather than a validation error (`Err`): an error discards
//! the key without entering the error state, which would not exercise the
//! failure path under test.
//!
//! Enabled only when both `tsra_test_hooks` and `fips_validation_hooks` are
//! enabled. Never enable either feature in a production build.

use core::cell::Cell;

use tsra_fw_ddi_mbor::MborDecoder;
use tsra_fw_ddi_mbor_derive::Ddi;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmEccPct;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRsa;
use tsra_fw_hsm_pal_traits::HsmRsaKey;
use tsra_fw_hsm_pal_traits::HsmRsaPct;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_uno_drivers_part_store::HsmPartId;
use tsra_fw_uno_pct::rsa_pct;
use tsra_fw_uno_pct::scratch;

use super::common::ReqHdr;
use super::test_action::decode_payload;
use super::test_action::encode_success;
use crate::UnoHsmIo;
use crate::pal::UnoHsmPal;

/// Action-specific `TriggerNegativePctFailure` request data.
///
/// Mirrors the host test-hooks `DdiTestActionNegativePctFailureReqInfo`
/// field-for-field without introducing a PAL-to-host dependency.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionNegativePctFailureReqInfo {
    /// Number of PCTs of the selected kind to let pass before the one that
    /// is corrupted.
    #[ddi(id = 1)]
    neg_pct_skip_cnt: u8,
    /// PCT kind to corrupt; a [`NegPctKind`] value.
    #[ddi(id = 2)]
    pct_kind: u32,
}

/// The kind of PCT that `TriggerNegativePctFailure` targets.
///
/// Mirrors the host test-hooks `DdiTestActionNegativePctKind`. Each kind is
/// one injection site and one PCT failure code. The host's ML-DSA (6) and
/// ML-KEM (7) kinds have no injection site yet, so they are not listed here
/// and arming them fails with [`HsmError::InvalidArg`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum NegPctKind {
    /// ECC key generation: `PctValidationEccGenKeyFailed`.
    EccKeyGen = 1,
    /// Partition identity key: `PartitionIdKeyGenerationPctFailed`.
    PartitionIdKey = 2,
    /// Establish-credential key: `PctValidationEstablishCredEncKeyFailed`.
    EstablishCredKey = 3,
    /// Session-encryption key: `PctValidationSessionEncKeyFailed`.
    SessionEncKey = 4,
    /// RSA unwrapping key: `PctValidationUnwrappingKeyFailed`.
    UnwrappingKey = 5,
}

impl TryFrom<u32> for NegPctKind {
    type Error = HsmError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        [
            Self::EccKeyGen,
            Self::PartitionIdKey,
            Self::EstablishCredKey,
            Self::SessionEncKey,
            Self::UnwrappingKey,
        ]
        .into_iter()
        .find(|kind| *kind as u32 == value)
        .ok_or(HsmError::InvalidArg)
    }
}

impl NegPctKind {
    /// The kind of an internal partition key's PCT, matching the failure
    /// code that `create_internal_ecc384` reports for `kind`.
    pub(crate) fn partition_key(kind: HsmVaultKeyKind) -> Self {
        match kind {
            HsmVaultKeyKind::EstablishCred => Self::EstablishCredKey,
            HsmVaultKeyKind::SessionEncryption => Self::SessionEncKey,
            _ => Self::PartitionIdKey,
        }
    }
}

/// An armed partition: the PCT kind to corrupt and how many PCTs of that
/// kind still run normally first.
#[derive(Debug, Copy, Clone)]
pub(crate) struct NegPctArm {
    /// PCT kind to corrupt.
    kind: NegPctKind,
    /// PCTs of `kind` still to let pass.
    skip: u8,
}

/// Validates and executes `TestAction::TriggerNegativePctFailure`.
///
/// Arms negative-PCT injection for the requesting IO's partition. For
/// [`NegPctKind::UnwrappingKey`] it also asks for the unwrapping key's PCT to
/// run again, since that key is otherwise tested only once. The request is
/// validated and the response allocated before any state changes, so a
/// request that fails leaves the partition as it was.
///
/// # Returns
///
/// - `Ok(&HsmDmaBuf)` — the success response; the partition is armed.
/// - `Err(HsmError::DdiDecodeFailed)` — malformed request or payload.
/// - `Err(HsmError::InvalidArg)` — unknown `pct_kind`.
/// - `Err(_)` — the response could not be allocated, or the partition is
///   out of range; the partition is not armed.
pub(super) fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &UnoHsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    request_field_count: u8,
    request_len: usize,
) -> HsmResult<&'p HsmDmaBuf> {
    let request: DdiTestActionNegativePctFailureReqInfo =
        decode_payload(decoder, request_field_count, request_len)?;
    let kind = NegPctKind::try_from(request.pct_kind)?;
    let response = encode_success(pal, io, hdr)?;
    let pid = io.pid();
    pal.neg_pct_arm(pid, kind, request.neg_pct_skip_cnt)?;
    pal.set_neg_pct_retest(pid, kind == NegPctKind::UnwrappingKey);
    Ok(response)
}

/// Substitute P-256 public key: `x ‖ y`, 32-byte little-endian coordinates.
///
/// NIST CAVP ECC CDH primitive test vectors (`ecccdhtestvectors.zip`),
/// curve P-256, `COUNT = 1`, `QIUTx`/`QIUTy`.
pub(crate) static NEG_PCT_ECC_P256_PUB: [u8; 64] = [
    0xd0, 0xf6, 0xa3, 0xb0, 0x95, 0xba, 0xdd, 0x02, 0x6b, 0xc0, 0x99, 0xca, 0x29, 0x48, 0x96, 0x9b,
    0xeb, 0xf5, 0xaf, 0x54, 0x7a, 0xe2, 0xc9, 0xb0, 0x2a, 0x78, 0x02, 0x79, 0x04, 0x2f, 0x9f, 0x11,
    0x1d, 0x4d, 0x70, 0x45, 0x94, 0x1b, 0xd4, 0x71, 0x46, 0x54, 0xcb, 0x5a, 0x2e, 0x96, 0xbd, 0x2c,
    0x68, 0xb2, 0x12, 0xa0, 0xc7, 0x8a, 0xc9, 0x6f, 0x36, 0xac, 0x4c, 0x66, 0x26, 0xb7, 0x52, 0x8f,
];

/// Substitute P-384 public key: `x ‖ y`, 48-byte little-endian coordinates.
///
/// NIST CAVP ECC CDH primitive test vectors (`ecccdhtestvectors.zip`),
/// curve P-384, `COUNT = 1`, `QIUTx`/`QIUTy`.
pub(crate) static NEG_PCT_ECC_P384_PUB: [u8; 96] = [
    0x66, 0x6b, 0x41, 0x3c, 0xb0, 0x0e, 0xaa, 0x19, 0x93, 0x3c, 0x80, 0xd4, 0xc9, 0xe2, 0xf7, 0x91,
    0x97, 0x41, 0x43, 0x52, 0xa3, 0x8a, 0x83, 0xfb, 0x66, 0x3a, 0x06, 0xdf, 0xd4, 0xb7, 0xee, 0xeb,
    0xce, 0xce, 0xd2, 0x2f, 0xa6, 0xf6, 0x0b, 0x18, 0x79, 0xc3, 0x07, 0xa3, 0xf5, 0x18, 0x40, 0xea,
    0xa6, 0xa1, 0x78, 0x58, 0xa7, 0x0c, 0x77, 0x68, 0x7b, 0x8a, 0x32, 0xa8, 0x40, 0xd3, 0x10, 0x3d,
    0x20, 0x37, 0xfb, 0xbc, 0xa1, 0x35, 0x67, 0x3e, 0x13, 0xb0, 0x9a, 0xd6, 0xcd, 0xab, 0xeb, 0xff,
    0x88, 0xfb, 0x36, 0x64, 0xdf, 0x84, 0x82, 0x02, 0xef, 0x05, 0x4f, 0x48, 0x91, 0x5a, 0x83, 0x68,
];

/// Substitute P-521 public key: `x ‖ y`, 68-byte little-endian coordinates.
///
/// NIST CAVP ECC CDH primitive test vectors (`ecccdhtestvectors.zip`),
/// curve P-521, `COUNT = 1`, `QIUTx`/`QIUTy`.
/// Each 66-byte coordinate is zero-padded to the 68-byte PAL word width.
pub(crate) static NEG_PCT_ECC_P521_PUB: [u8; 136] = [
    0x55, 0xd2, 0x45, 0xba, 0xc8, 0xda, 0x30, 0xd9, 0x51, 0x05, 0x9d, 0x87, 0xb6, 0xc9, 0x9e, 0x30,
    0x05, 0x11, 0x67, 0xf4, 0xe9, 0x3f, 0x3b, 0xc7, 0x7b, 0xb5, 0xa8, 0x45, 0x49, 0x6d, 0xd9, 0xab,
    0x91, 0x12, 0x10, 0xbd, 0xfb, 0x50, 0x64, 0x0d, 0xe0, 0x5f, 0x00, 0x31, 0xed, 0x85, 0x8f, 0xdd,
    0xbe, 0x76, 0xba, 0x43, 0xcd, 0x62, 0x0a, 0x61, 0x99, 0xe6, 0xfd, 0x37, 0x5d, 0xed, 0x15, 0x56,
    0xd4, 0x00, 0x00, 0x00, 0xfa, 0xa7, 0xe3, 0x8c, 0xed, 0x10, 0xd9, 0x3b, 0xc3, 0x9b, 0xb1, 0x2f,
    0x68, 0x33, 0x5b, 0xf2, 0x82, 0xce, 0x35, 0x36, 0x47, 0xc6, 0x90, 0xcf, 0x56, 0x9a, 0x94, 0x49,
    0x2e, 0xc2, 0xdf, 0x99, 0x8c, 0x2c, 0x7c, 0xd6, 0x4d, 0x2d, 0x17, 0x42, 0xa2, 0x46, 0xcd, 0x19,
    0xdf, 0x32, 0x67, 0xc0, 0x31, 0x64, 0x52, 0xd1, 0x2a, 0x97, 0x27, 0x00, 0x0c, 0x44, 0x2b, 0x59,
    0x4e, 0x84, 0x32, 0x53, 0x42, 0x01, 0x00, 0x00,
];

/// Substitute RSA-2048 modulus `n`, 256 bytes, little-endian.
///
/// Generated with:
///
/// ```text
/// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
///     -pkeyopt rsa_keygen_pubexp:65537 -out rsa_2048.pem
/// ```
pub(crate) static NEG_PCT_RSA_2048_N: [u8; 256] = [
    0x13, 0x3d, 0x2d, 0xe9, 0x7c, 0x6b, 0x8f, 0x87, 0xbc, 0x93, 0x20, 0x62, 0xa9, 0xd5, 0xbc, 0xec,
    0x4f, 0x0a, 0x35, 0xd1, 0x48, 0xc0, 0x85, 0xb6, 0x9b, 0x38, 0xf3, 0x42, 0x75, 0xca, 0x9c, 0x34,
    0xb5, 0xb4, 0x46, 0x22, 0x21, 0x91, 0x3e, 0xef, 0x6f, 0x80, 0x4f, 0x07, 0x23, 0x55, 0xda, 0x30,
    0xc3, 0x40, 0x20, 0x2f, 0xb1, 0x54, 0x78, 0xea, 0xb3, 0x56, 0xe2, 0x3f, 0x0c, 0x7b, 0x5b, 0x34,
    0x04, 0x62, 0xbb, 0xaa, 0x22, 0x68, 0xe0, 0xc1, 0x93, 0xfa, 0x82, 0xe1, 0xd7, 0x45, 0xb6, 0x09,
    0xf7, 0xe0, 0x28, 0x14, 0xd3, 0x8d, 0x37, 0xf4, 0xd4, 0x59, 0x32, 0xf4, 0x4c, 0xf8, 0x46, 0x1d,
    0x15, 0x70, 0x70, 0x3c, 0xec, 0x51, 0x5d, 0xd1, 0x0e, 0x0c, 0xe4, 0xb3, 0xb5, 0x61, 0xd0, 0xe5,
    0xc2, 0xe0, 0xa7, 0xdb, 0xa0, 0x0c, 0xe1, 0x2f, 0x4b, 0x1d, 0x50, 0x11, 0x7c, 0xa6, 0x70, 0xd7,
    0xc7, 0x8f, 0xbd, 0xdb, 0x28, 0xc1, 0xb4, 0x3a, 0xc8, 0xad, 0xcc, 0x5a, 0xe3, 0x80, 0xc6, 0xde,
    0x7a, 0x08, 0x74, 0x0d, 0xf6, 0xb2, 0x54, 0x53, 0xb9, 0x25, 0xb5, 0xed, 0x72, 0x6a, 0xe3, 0x39,
    0x2e, 0x13, 0xe7, 0x15, 0x5a, 0x6d, 0x6e, 0x17, 0x7f, 0x1d, 0xc7, 0xb2, 0x6b, 0x55, 0x7b, 0xdc,
    0x62, 0x33, 0xc4, 0xc0, 0xb3, 0x9e, 0x85, 0x5e, 0xb2, 0xcf, 0x46, 0xcd, 0x40, 0xd9, 0x31, 0xe5,
    0xd6, 0xb9, 0xf3, 0x4d, 0x64, 0x85, 0xad, 0xec, 0x7c, 0x80, 0x9d, 0x8c, 0x4d, 0x31, 0xa5, 0xff,
    0xc9, 0x17, 0x62, 0xb7, 0x0a, 0x5a, 0x4b, 0xba, 0x3a, 0x5f, 0xcd, 0x82, 0xf3, 0x2a, 0xae, 0x92,
    0x3b, 0xc3, 0x2c, 0xf5, 0x50, 0x97, 0x3a, 0x13, 0xe3, 0x0c, 0x60, 0xad, 0xba, 0xda, 0x30, 0x54,
    0x22, 0x74, 0xfb, 0x26, 0xa4, 0xeb, 0x70, 0xf2, 0x92, 0x37, 0x96, 0xe9, 0x93, 0x6f, 0x74, 0xbe,
];

/// Returns the substitute public key for `curve`, in the PAL ECC wire format.
pub(crate) fn neg_pct_ecc_pub(curve: HsmEccCurve) -> &'static [u8] {
    match curve {
        HsmEccCurve::P256 => &NEG_PCT_ECC_P256_PUB,
        HsmEccCurve::P384 => &NEG_PCT_ECC_P384_PUB,
        HsmEccCurve::P521 => &NEG_PCT_ECC_P521_PUB,
    }
}

impl UnoHsmPal {
    /// Arms negative-PCT injection for partition `pid`: the next `skip` PCTs
    /// of `kind` on the partition run normally and the one after them is
    /// corrupted. Re-arming replaces any arm that is still pending.
    ///
    /// Returns [`HsmError::InvalidArg`] when `pid` is out of range.
    pub(crate) fn neg_pct_arm(&self, pid: HsmPartId, kind: NegPctKind, skip: u8) -> HsmResult<()> {
        let slot = self
            .neg_pct_skip
            .get(usize::from(u8::from(pid)))
            .ok_or(HsmError::InvalidArg)?;
        slot.set(Some(NegPctArm { kind, skip }));
        Ok(())
    }

    /// Consumes one step of partition `pid`'s arm for a PCT of `kind`.
    ///
    /// Call this exactly once per PCT that is about to run, and only for a
    /// PCT that will run. It returns `true` when that PCT must be corrupted,
    /// which also disarms the partition:
    ///
    /// - not armed, or armed for another kind → `false`, arm unchanged
    /// - armed for `kind` with count `0` → `true`, and the partition is no
    ///   longer armed
    /// - armed for `kind` with count `n > 0` → `false`, and the count becomes
    ///   `n - 1`
    ///
    /// The arm is read and written with no `.await` in between, so the
    /// cooperative executor cannot interleave two consumers.
    pub(crate) fn neg_pct_fire(&self, pid: HsmPartId, kind: NegPctKind) -> bool {
        let Some(slot) = self.neg_pct_skip.get(usize::from(u8::from(pid))) else {
            return false;
        };
        match slot.get() {
            Some(arm) if arm.kind == kind => match arm.skip.checked_sub(1) {
                None => {
                    slot.set(None);
                    true
                }
                Some(skip) => {
                    slot.set(Some(NegPctArm { kind, skip }));
                    false
                }
            },
            _ => false,
        }
    }
}

impl UnoHsmPal {
    /// Negative-PCT injection point for a freshly generated ECC key pair.
    ///
    /// Call it after the key pair is generated and before its PCT runs.
    /// When `pct` selects a test and partition `pid` is armed for `kind` with
    /// its count used up, `pub_key` is overwritten with the substitute public
    /// key for `curve`. The PCT then checks the private key against a public key it
    /// doesn't belong to, reports the pair as inconsistent, and the caller
    /// enters the FIPS error state. The overwritten public key never reaches
    /// the host, because the module halts first.
    ///
    /// No PCT runs for [`HsmEccPct::None`], so the count is left alone. A
    /// `pub_key` whose length doesn't match the curve is left alone, and the
    /// count isn't consumed.
    pub(crate) fn neg_pct_ecc_gen(
        &self,
        pid: HsmPartId,
        kind: NegPctKind,
        curve: HsmEccCurve,
        pct: &HsmEccPct,
        pub_key: &mut [u8],
    ) {
        if matches!(pct, HsmEccPct::None) {
            return;
        }
        let substitute = neg_pct_ecc_pub(curve);
        if pub_key.len() != substitute.len() {
            return;
        }
        if self.neg_pct_fire(pid, kind) {
            pub_key.copy_from_slice(substitute);
        }
    }
}

impl UnoHsmPal {
    /// Whether partition `pid`'s unwrapping-key PCT is due to run again.
    pub(crate) fn neg_pct_retest(&self, pid: HsmPartId) -> bool {
        self.neg_pct_retest
            .get(usize::from(u8::from(pid)))
            .is_some_and(Cell::get)
    }

    /// Sets or clears partition `pid`'s unwrapping-key retest request.
    pub(crate) fn set_neg_pct_retest(&self, pid: HsmPartId, retest: bool) {
        if let Some(flag) = self.neg_pct_retest.get(usize::from(u8::from(pid))) {
            flag.set(retest);
        }
    }

    /// Records that partition `pid`'s unwrapping-key retest passed.
    ///
    /// The retest stays requested while the partition is still armed for
    /// [`NegPctKind::UnwrappingKey`]: a nonzero skip count lets this PCT pass,
    /// and a later IO must run it again until the arm fires. Call this after
    /// the PCT's last await, so an arm installed while the PCT ran is kept.
    pub(crate) fn neg_pct_retest_passed(&self, pid: HsmPartId) {
        let armed = self
            .neg_pct_skip
            .get(usize::from(u8::from(pid)))
            .and_then(Cell::get)
            .is_some_and(|arm| arm.kind == NegPctKind::UnwrappingKey);
        self.set_neg_pct_retest(pid, armed);
    }

    /// Runs the unwrapping key's PCT with negative-PCT injection.
    ///
    /// What `UnoHsmPal::unwrapping_key_pct` runs in these builds: the same
    /// RSA-2048 encrypt/decrypt test, against the `n ‖ e` that `key` stores.
    /// When the requesting IO's partition is armed for
    /// [`NegPctKind::UnwrappingKey`]
    /// and its count is used up, `n` is replaced with a substitute modulus,
    /// so the round trip no longer returns its input and the test fails.
    ///
    /// # Returns
    ///
    /// As `unwrapping_key_pct`: `Ok(true)` pass, `Ok(false)` inconsistent,
    /// `Err(_)` the test didn't finish.
    pub(crate) async fn neg_pct_unwrapping_key_pct(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        self.alloc_scoped_async(io, async |alloc| -> HsmResult<bool> {
            let pub_len = self.rsa_priv_pub_key(io, key, None)?;
            let pub_key = scratch(alloc, pub_len)?;
            self.rsa_priv_pub_key(io, key, Some(&mut *pub_key))?;
            if let Some(n) = pub_key.get_mut(..NEG_PCT_RSA_2048_N.len())
                && self.neg_pct_fire(io.pid(), NegPctKind::UnwrappingKey)
            {
                n.copy_from_slice(&NEG_PCT_RSA_2048_N);
            }
            rsa_pct(
                self,
                io,
                alloc,
                HsmRsaKey::Rsa2048Priv,
                &HsmRsaPct::EncryptDecrypt,
                key,
                pub_key,
            )
            .await
        })
        .await
    }
}
