// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR rows for the BK3 provisioning opcodes.
//!
//! NSSR keeps a partition's provisioning: the sealed BK3 survives
//! byte-identical and the one-shot `InitBk3` / `SetSealedBk3` stay spent
//! (hardware `part_migrate` / `clear_state(Migrate)`,
//! fw/plat/uno/fw/drivers/part_store/src/part_store.rs:671-676 and :744-760;
//! `secure_provision_lm_sim.rs:6-16`). These rows run only against this
//! process's auto-started emulator because the one-shot state cannot be reset
//! on hardware, where `secure_provision_lm_sim.rs` covers the contract.
//!
//! NOTE(nssr): `nssr_init_bk3`, `nssr_get_sealed_bk3` and `nssr_set_sealed_bk3`
//! fail on the emulator. Its NSSR is a partition disable + enable
//! (ddi/sock/server/src/lib.rs:723-735), which wipes the sealed BK3 and
//! re-arms both one-shots (`clear_enabled_state`,
//! fw/plat/std/pal/src/part.rs:1170-1178, and `part_enable_internal`,
//! part.rs:948-949) instead of modelling a `Migrate`.

#![cfg(test)]

use test_with_tracing::test;

use super::*;

#[test]
fn nssr_init_bk3() {
    if !ddi_sock_server::autostarted() {
        return;
    }
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            common_cleanup(dev, ddi, path, None);
            let init = |dev: &Dev| helper_init_bk3(dev, HARD_CODED_BK3.to_vec());
            init(dev).expect("InitBk3");
            assert_status(
                init(dev),
                DdiStatus::Bk3AlreadyInitialized,
                "one-shot before NSSR",
            );
            nssr(dev);
            assert_status(
                init(dev),
                DdiStatus::Bk3AlreadyInitialized,
                "one-shot after NSSR",
            );
        },
    );
}

#[test]
fn nssr_get_sealed_bk3() {
    if !ddi_sock_server::autostarted() {
        return;
    }
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let sealed = helper_get_sealed_bk3(dev)
                .expect("GetSealedBk3")
                .data
                .sealed_bk3;
            assert_eq!(sealed, lm.0.masked_bk3);
            nssr(dev);
            let after = helper_get_sealed_bk3(dev)
                .expect("GetSealedBk3 after NSSR")
                .data
                .sealed_bk3;
            assert_eq!(after, sealed, "sealed BK3 must survive NSSR byte-identical");
        },
    );
}

#[test]
fn nssr_set_sealed_bk3() {
    if !ddi_sock_server::autostarted() {
        return;
    }
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let lm = Lm::new(dev, ddi, path);
            let blob = lm.0.masked_bk3.as_slice().to_vec();
            let set = |dev: &Dev| helper_set_sealed_bk3(dev, blob.clone());
            assert_status(
                set(dev),
                DdiStatus::SealedBk3AlreadySet,
                "write-once before NSSR",
            );
            nssr(dev);
            assert_status(
                set(dev),
                DdiStatus::SealedBk3AlreadySet,
                "write-once after NSSR",
            );
        },
    );
}

// NOTE(nssr): the host classifies SetInitBk3Pin / SecureInitBk3 as NoSession
// (ddi/mbor/types/src/sessctrl.rs:58-59), but the firmware `DdiOp` lacks both
// opcodes (fw/core/ddi/mbor/types/src/lib.rs:67-99) and `SessionCtrl::from_op`
// maps unknown opcodes to InSession (fw/core/lib/src/op.rs:243), so
// `validate_session` rejects the NoSession SQE with `InvalidArg`
// (fw/core/lib/src/io.rs:652-655) before dispatch. `common.rs:1487-1502,1595`
// expects `UnsupportedCmd` here. Hardware semantics across NSSR are covered by
// `secure_provision_lm_sim.rs`.

#[test]
fn nssr_set_init_bk3_pin() {
    if !ddi_sock_server::autostarted() {
        return;
    }
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            common_cleanup(dev, ddi, path, None);
            let set_pin = |dev: &Dev| set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN);
            assert_status(set_pin(dev), DdiStatus::InvalidArg, "before NSSR");
            nssr(dev);
            assert_status(set_pin(dev), DdiStatus::InvalidArg, "after NSSR");
        },
    );
}

#[test]
fn nssr_secure_init_bk3() {
    if !ddi_sock_server::autostarted() {
        return;
    }
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            common_cleanup(dev, ddi, path, None);
            let secure_init = |dev: &Dev| {
                let (bk3, pub_key) = build_secure_init_bk3_payload(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    &HARD_CODED_BK3,
                )
                .expect("SecureInitBk3 payload");
                helper_secure_init_bk3(dev, bk3, pub_key)
            };
            assert_status(secure_init(dev), DdiStatus::InvalidArg, "before NSSR");
            nssr(dev);
            assert_status(secure_init(dev), DdiStatus::InvalidArg, "after NSSR");
        },
    );
}
