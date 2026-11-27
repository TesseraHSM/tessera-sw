// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the `TestAction::ForcePkaInstance` FIPS-validation
//! hook.
//!
//! The hook pins every later any-engine PKA request to one UPKA engine until
//! released. ECC key generation (an engine held across steps) and ECC sign (a
//! staged command) cover both any-engine paths the pin restricts.
//!
//! These require a device whose firmware is built with
//! `fips_validation_hooks`; otherwise the action is `UnsupportedCmd` and each
//! test skips. The pin is device-global and outlives the session, so every
//! test that sets it releases it on exit, including on panic.

#![allow(clippy::unwrap_used)]

mod common;

use std::panic::AssertUnwindSafe;

use common::*;
use test_with_tracing::test;
use tsra_ddi::Ddi;
use tsra_ddi::DdiDev;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::DdiTestAction;
use tsra_ddi_mbor_test_hooks::DdiTestActionCmdReq;
use tsra_ddi_mbor_test_hooks::DdiTestActionReq;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_test_hooks::DDI_OP_TEST_ACTION;
use tsra_ddi_mbor_types::DdiApiRev;
use tsra_ddi_mbor_types::DdiEccCurve;
use tsra_ddi_mbor_types::DdiHashAlgorithm;
use tsra_ddi_mbor_types::DdiKeyAvailability;
use tsra_ddi_mbor_types::DdiKeyUsage;
use tsra_ddi_mbor_types::DdiReqHdr;
use tsra_ddi_mbor_types::DdiStatus;

/// Number of UPKA engines on the device.
const PKA_ENGINES: u8 = 16;

const API_REV: Option<DdiApiRev> = Some(DdiApiRev { major: 1, minor: 0 });

type Dev = <DdiTest as Ddi>::Dev;

fn force_pka_instance(dev: &mut Dev, session_id: u16, engine: Option<u8>) -> Result<(), DdiError> {
    helper_test_action_cmd(dev, session_id, TestActionRequest::ForcePkaInstance(engine)).map(|_| ())
}

/// Whether the firmware implements the hook. Releasing the pin is harmless,
/// so it doubles as the probe.
fn hook_supported(dev: &mut Dev, session_id: u16) -> bool {
    match force_pka_instance(dev, session_id, None) {
        Ok(()) => true,
        Err(err) if is_unsupported_cmd(&err) => false,
        Err(err) => panic!("Unexpected ForcePkaInstance error: {err:?}"),
    }
}

/// Run `body` with any-engine PKA work pinned to `engine`, then release the
/// pin even if `body` panics.
fn with_pin(dev: &mut Dev, session_id: u16, engine: u8, body: impl FnOnce(&mut Dev)) {
    force_pka_instance(dev, session_id, Some(engine))
        .unwrap_or_else(|err| panic!("pin to engine {engine} failed: {err:?}"));
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| body(dev)));
    let release = force_pka_instance(dev, session_id, None);
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
    release.expect("release pin");
}

/// Generate an ECC key pair (held-engine path), sign with it (staged path),
/// and delete it.
fn ecc_keygen_sign(dev: &Dev, session_id: u16, curve: DdiEccCurve) {
    let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
    let key = helper_ecc_generate_key_pair(dev, Some(session_id), API_REV, curve, key_props)
        .unwrap_or_else(|err| panic!("{curve:?} key generation failed: {err:?}"));
    let key_id = key.data.private_key_id;

    let digest = MborByteArray::from_slice(&[0xA5; 32]).unwrap();
    let sign = helper_ecc_sign(
        dev,
        Some(session_id),
        API_REV,
        key_id,
        digest,
        DdiHashAlgorithm::Sha256,
    );
    let delete = helper_delete_key(dev, Some(session_id), API_REV, key_id);
    sign.unwrap_or_else(|err| panic!("{curve:?} sign failed: {err:?}"));
    delete.expect("delete key");
}

/// Pin engine 0, generate P-256/P-384/P-521 key pairs, then release the pin.
#[test]
fn test_ecc_generate_with_fixed_engine_instance() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Force the PKA instance to a fixed instance ID
            let resp = force_pka_instance(dev, session_id, Some(0));
            match resp {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("fips_validation_hooks not enabled in the device firmware");
                    return;
                }
                Err(_) => panic!("Unexpected error {:?}", resp),
                Ok(()) => (),
            }

            for curve in [DdiEccCurve::P256, DdiEccCurve::P384, DdiEccCurve::P521] {
                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
                let resp =
                    helper_ecc_generate_key_pair(dev, Some(session_id), API_REV, curve, key_props);
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Release the force PKA instance allocation
            let resp = force_pka_instance(dev, session_id, None);
            match resp {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("fips_validation_hooks not enabled in the device firmware")
                }
                Err(_) => panic!("Unexpected error {:?}", resp),
                Ok(()) => (),
            }
        },
    );
}

#[test]
fn test_force_pka_instance_each_engine() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !hook_supported(dev, session_id) {
                return;
            }
            for engine in 0..PKA_ENGINES {
                with_pin(dev, session_id, engine, |dev| {
                    ecc_keygen_sign(dev, session_id, DdiEccCurve::P256);
                });
            }
        },
    );
}

#[test]
fn test_force_pka_instance_ecc_curves() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !hook_supported(dev, session_id) {
                return;
            }
            with_pin(dev, session_id, 0, |dev| {
                for curve in [DdiEccCurve::P256, DdiEccCurve::P384, DdiEccCurve::P521] {
                    ecc_keygen_sign(dev, session_id, curve);
                }
            });
        },
    );
}

#[test]
fn test_force_pka_instance_sequential_ops() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !hook_supported(dev, session_id) {
                return;
            }
            with_pin(dev, session_id, 3, |dev| {
                for _ in 0..20 {
                    ecc_keygen_sign(dev, session_id, DdiEccCurve::P256);
                }
            });
        },
    );
}

#[test]
fn test_force_pka_instance_repin_and_release() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !hook_supported(dev, session_id) {
                return;
            }
            // Moving the pin directly to another engine, without a release in
            // between, must leave PKA work runnable.
            with_pin(dev, session_id, 2, |dev| {
                ecc_keygen_sign(dev, session_id, DdiEccCurve::P256);
                force_pka_instance(dev, session_id, Some(7)).expect("re-pin to engine 7");
                ecc_keygen_sign(dev, session_id, DdiEccCurve::P256);
            });

            // Releasing an already-released pin succeeds.
            force_pka_instance(dev, session_id, None).expect("second release");
            ecc_keygen_sign(dev, session_id, DdiEccCurve::P256);
        },
    );
}

#[test]
fn test_force_pka_instance_out_of_range() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !hook_supported(dev, session_id) {
                return;
            }
            with_pin(dev, session_id, 1, |dev| {
                for engine in [PKA_ENGINES, u8::MAX] {
                    let resp = force_pka_instance(dev, session_id, Some(engine));
                    assert!(
                        matches!(resp, Err(DdiError::DdiStatus(DdiStatus::InvalidArg))),
                        "engine {engine}: {resp:?}"
                    );
                }
                // The rejected requests leave the existing pin usable.
                ecc_keygen_sign(dev, session_id, DdiEccCurve::P256);
            });
        },
    );
}

#[test]
fn test_force_pka_instance_malformed_payload() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !hook_supported(dev, session_id) {
                return;
            }
            // Not an MBOR map: the payload must be `{1: u8}` or empty.
            let req = DdiTestActionCmdReq {
                hdr: DdiReqHdr {
                    op: DDI_OP_TEST_ACTION,
                    sess_id: Some(session_id),
                    rev: API_REV,
                },
                data: DdiTestActionReq {
                    action: DdiTestAction::ForcePkaInstance,
                    payload: MborByteArray::from_slice(&[0xFF]).unwrap(),
                },
                ext: None,
            };
            let resp = dev.exec_op_mbor(&req, &mut None);
            assert!(
                matches!(resp, Err(DdiError::DdiStatus(DdiStatus::DdiDecodeFailed))),
                "resp {resp:?}"
            );
        },
    );
}

#[test]
fn test_force_pka_instance_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            if !hook_supported(dev, session_id) {
                return;
            }
            let resp = force_pka_instance(dev, session_id ^ 1, Some(0));
            assert!(
                matches!(
                    resp,
                    Err(DdiError::DdiStatus(
                        DdiStatus::FileHandleSessionIdDoesNotMatch
                    ))
                ),
                "resp {resp:?}"
            );
        },
    );
}
