// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SetSealedBk3 / GetSealedBk3 smoke tests for the auto-started simulator.

#![cfg(test)]

use test_with_tracing::test;
use tsra_ddi::*;
use tsra_ddi_mbor_types::*;

use super::common::*;

/// Whether `setup` can give each case a fresh partition. Only this process's
/// auto-started simulator qualifies, through its factory reset: an NSSR keeps
/// the one-shot BK3 state and sealed BK3, as a live migration does, and
/// `transport=sock` alone isn't enough because `sock=` may front hardware.
fn fresh_partition_available() -> bool {
    ddi_sock_server::autostarted()
}

/// Reset the partition so each case starts with fresh one-shot BK3 state.
pub fn setup(_dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    let resp = simulator_factory_reset(&ddi.open_dev(path).unwrap());
    assert!(resp.is_ok(), "resp {:?}", resp);
    0
}

/// Leave the partition fresh for the cases that follow: an NSSR keeps the
/// one-shot BK3 state these cases leave behind.
pub fn cleanup(
    _dev: &mut <DdiTest as Ddi>::Dev,
    ddi: &DdiTest,
    path: &str,
    _setup_session_id: Option<u16>,
) {
    let resp = simulator_factory_reset(&ddi.open_dev(path).unwrap());
    assert!(resp.is_ok(), "resp {:?}", resp);
}

fn ensure_bk3_provisioned(dev: &<DdiTest as Ddi>::Dev) {
    match helper_init_bk3(dev, vec![0u8; 48]) {
        Ok(_) | Err(DdiError::DdiStatus(DdiStatus::Bk3AlreadyInitialized)) => {}
        Err(err) => panic!("InitBk3 must provision BK3 or report it already initialized: {err:?}"),
    }
}

#[test]
fn test_set_then_get_sealed_bk3() {
    if !fresh_partition_available() {
        return;
    }
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        ensure_bk3_provisioned(dev);
        let blob: Vec<u8> = (10..73u8).collect();

        let set_resp = helper_set_sealed_bk3(dev, blob.clone()).unwrap();
        assert_eq!(set_resp.hdr.op, DdiOp::SetSealedBk3);
        assert_eq!(set_resp.hdr.status, DdiStatus::Success);

        let get_resp = helper_get_sealed_bk3(dev).unwrap();
        assert_eq!(get_resp.hdr.op, DdiOp::GetSealedBk3);
        assert_eq!(get_resp.data.sealed_bk3.as_slice(), blob.as_slice());
    });
}

#[test]
fn test_set_sealed_bk3_twice_fails() {
    if !fresh_partition_available() {
        return;
    }
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        ensure_bk3_provisioned(dev);
        let blob: Vec<u8> = (10..73u8).collect();

        let set_resp = helper_set_sealed_bk3(dev, blob.clone()).unwrap();
        assert_eq!(set_resp.hdr.status, DdiStatus::Success);

        let err = helper_set_sealed_bk3(dev, blob).unwrap_err();
        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet)),
            "expected SealedBk3AlreadySet, got {:?}",
            err
        );
        let err = helper_set_sealed_bk3(dev, vec![0xA5; 513]).unwrap_err();
        assert!(matches!(
            err,
            DdiError::DdiStatus(DdiStatus::SealedBk3AlreadySet)
        ));
    });
}

#[test]
fn test_oversized_first_sealed_bk3_write_is_retryable() {
    if !fresh_partition_available() {
        return;
    }
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        ensure_bk3_provisioned(dev);
        assert!(matches!(
            helper_set_sealed_bk3(dev, vec![0xA5; 513]),
            Err(DdiError::DdiStatus(DdiStatus::SealedBk3TooLarge))
        ));
        let blob = vec![0x51; 64];
        helper_set_sealed_bk3(dev, blob.clone()).unwrap();
        assert_eq!(
            helper_get_sealed_bk3(dev)
                .unwrap()
                .data
                .sealed_bk3
                .as_slice(),
            blob.as_slice()
        );
    });
}

#[test]
fn test_get_sealed_bk3_before_set_fails() {
    if !fresh_partition_available() {
        return;
    }
    ddi_dev_test(setup, cleanup, |dev, _ddi, _path, _| {
        ensure_bk3_provisioned(dev);
        let err = helper_get_sealed_bk3(dev).unwrap_err();
        assert!(matches!(
            err,
            DdiError::DdiStatus(DdiStatus::SealedBk3NotPresent)
        ));
    });
}
