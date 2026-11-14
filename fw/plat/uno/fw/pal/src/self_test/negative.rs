// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Negative self-test IDs and, with `fips_validation_hooks`, one-shot selection.
//!
//! The selected test ID lives in one DTCM word shared with Admin: Admin
//! reaches it at global `0x6063_F834`, the HSM at local `0x2003_F834`.
//! Admin clears it at boot and, before sending `Start`, writes the ID from
//! the SP pre-operational marker. The HSM writes HSM IDs for periodic
//! requests. Each core clears only IDs of the self-tests it runs, so the HSM
//! never touches an Admin ID.

#[cfg(feature = "fips_validation_hooks")]
use core::sync::atomic::Ordering;
#[cfg(feature = "fips_validation_hooks")]
use core::sync::atomic::fence;

use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
#[cfg(feature = "fips_validation_hooks")]
use tsra_fw_uno_reg_soc::hsm_dtcm::HSM_DTCM_BASE;
#[cfg(feature = "fips_validation_hooks")]
use tsra_fw_uno_reg_soc::hsm_dtcm::NEGATIVE_SELF_TEST_ID_OFFSET;

use super::SelfTest;

/// Value of the shared word when no self-test is selected to fail.
#[cfg(any(test, feature = "fips_validation_hooks"))]
const NO_NEGATIVE_SELF_TEST: u32 = u32::MAX;

pub(crate) enum NegativeTarget {
    Admin,
    Hsm(SelfTest),
}

pub(crate) fn classify(id: u32) -> HsmResult<NegativeTarget> {
    Ok(match id {
        0..=4 | 6 | 7 => NegativeTarget::Admin,
        5 => NegativeTarget::Hsm(SelfTest::AesCbc),
        8 => NegativeTarget::Hsm(SelfTest::Rng),
        9..=72 => {
            let n = id - 9;
            let engine = (n / 4) as u8;
            NegativeTarget::Hsm(match n % 4 {
                0 => SelfTest::Ecdh(engine),
                1 => SelfTest::Ecdsa(engine),
                2 => SelfTest::RsaModExp(engine),
                _ => SelfTest::RsaModExpCrt(engine),
            })
        }
        73 => NegativeTarget::Hsm(SelfTest::Hkdf),
        74 => NegativeTarget::Hsm(SelfTest::Kbkdf),
        75 => NegativeTarget::Hsm(SelfTest::AesEcb),
        76 => NegativeTarget::Hsm(SelfTest::AesKwp),
        _ => return Err(HsmError::InvalidArg),
    })
}

#[cfg(any(test, feature = "fips_validation_hooks"))]
fn test_id(test: SelfTest) -> u32 {
    match test {
        SelfTest::AesCbc => 5,
        SelfTest::Rng => 8,
        SelfTest::Ecdh(n) => 9 + 4 * u32::from(n),
        SelfTest::Ecdsa(n) => 10 + 4 * u32::from(n),
        SelfTest::RsaModExp(n) => 11 + 4 * u32::from(n),
        SelfTest::RsaModExpCrt(n) => 12 + 4 * u32::from(n),
        SelfTest::Hkdf => 73,
        SelfTest::Kbkdf => 74,
        SelfTest::AesEcb => 75,
        SelfTest::AesKwp => 76,
    }
}

#[cfg(feature = "fips_validation_hooks")]
fn negative_self_test_id() -> *mut u32 {
    (HSM_DTCM_BASE + NEGATIVE_SELF_TEST_ID_OFFSET) as *mut u32
}

#[cfg(feature = "fips_validation_hooks")]
#[allow(unsafe_code)]
fn read() -> u32 {
    fence(Ordering::SeqCst);
    // SAFETY: Aligned DTCM word reserved for this selection; see module docs.
    unsafe { negative_self_test_id().read_volatile() }
}

#[cfg(feature = "fips_validation_hooks")]
#[allow(unsafe_code)]
fn write(id: u32) {
    // SAFETY: Aligned DTCM word reserved for this selection; see module docs.
    unsafe { negative_self_test_id().write_volatile(id) };
    fence(Ordering::SeqCst);
}

/// Returns the HSM self-test selected to fail, leaving the word unchanged.
///
/// Returns `None` when nothing is selected or the ID belongs to Admin.
#[cfg(feature = "fips_validation_hooks")]
pub(super) fn selected_hsm_test() -> HsmResult<Option<SelfTest>> {
    match read() {
        NO_NEGATIVE_SELF_TEST => Ok(None),
        id => Ok(match classify(id)? {
            NegativeTarget::Hsm(test) => Some(test),
            NegativeTarget::Admin => None,
        }),
    }
}

/// Selects `test` to fail on its next run; the word must be empty.
#[cfg(feature = "fips_validation_hooks")]
pub(super) fn stage(test: SelfTest) -> HsmResult<()> {
    if read() != NO_NEGATIVE_SELF_TEST {
        return Err(HsmError::PendingIo);
    }
    write(test_id(test));
    if read() != test_id(test) {
        return Err(HsmError::InternalError);
    }
    Ok(())
}

/// Clears the word and returns `true` when `test` is the selected test.
#[cfg(feature = "fips_validation_hooks")]
pub(super) fn take_negative_self_test(test: SelfTest) -> HsmResult<bool> {
    if selected_hsm_test()? == Some(test) {
        write(NO_NEGATIVE_SELF_TEST);
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_ids_map_to_distinct_kats() {
        for id in 0..=76 {
            match classify(id).unwrap() {
                NegativeTarget::Admin => assert!(matches!(id, 0..=4 | 6 | 7)),
                NegativeTarget::Hsm(test) => assert_eq!(test_id(test), id),
            }
        }
        assert!(classify(77).is_err());
        assert!(classify(NO_NEGATIVE_SELF_TEST).is_err());
    }
}
