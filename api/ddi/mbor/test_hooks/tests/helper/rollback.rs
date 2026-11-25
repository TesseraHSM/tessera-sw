// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared capacity checks for the native rollback tests.
//! Firmware without `tsra_test_hooks` is detected before any key is created,
//! and the scenario is skipped.
//!
//! Test flow:
//! 0. Probe TriggerIoFailure; skip on UnsupportedCmd, otherwise disarm it.
//! 1. Prepare and track command-specific input keys, then create outputs until
//!    the vault is full (NotEnoughSpace or DefragmentationNeeded). Retain one output and delete another to free an allocation.
//! 2. Arm TriggerIoFailure and require InvalidKeyType from the next creation.
//! 3. Retry in the same session: exactly one creation must succeed before
//!    the vault is full again, checking rollback before teardown can hide leaks.
//! 4. Run the caller's retained/recovered-key verification. The ordinary AES
//!    wrapper uses encrypt/decrypt round trips; bulk tests supply their own checks.
//! 5. Attempt deletion of every tracked output and input, including on panic.
#![allow(dead_code)]

use std::panic::AssertUnwindSafe;

use tsra_ddi::Ddi;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_types::*;

use crate::common::*;

/// The vault cannot fit another key of this size. On a fragmented vault the
/// firmware reports DefragmentationNeeded instead of NotEnoughSpace.
pub fn vault_full(err: &DdiError) -> bool {
    matches!(
        err,
        DdiError::DdiStatus(DdiStatus::NotEnoughSpace | DdiStatus::DefragmentationNeeded)
    )
}

pub fn check_key_rollback<T>(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    setup: impl FnOnce(&<DdiTest as Ddi>::Dev, &mut Vec<u16>) -> T,
    create: impl Fn(&<DdiTest as Ddi>::Dev, &T) -> Result<u16, DdiError>,
) {
    check_key_rollback_with_verify(
        dev,
        session_id,
        setup,
        create,
        |key_id| key_id,
        |dev, _, retained, recovered| {
            assert_aes_key(dev, session_id, retained);
            assert_aes_key(dev, session_id, recovered);
        },
    );
}

pub fn check_key_rollback_with_verify<T, K: Copy + std::fmt::Debug>(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    setup: impl FnOnce(&<DdiTest as Ddi>::Dev, &mut Vec<u16>) -> T,
    create: impl Fn(&<DdiTest as Ddi>::Dev, &T) -> Result<K, DdiError>,
    key_id: impl Fn(K) -> u16,
    verify: impl Fn(&<DdiTest as Ddi>::Dev, &T, K, K),
) {
    if !rollback_hooks_supported(dev, session_id) {
        return;
    }
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let mut input_keys = Vec::new();
    let mut keys = Vec::new();
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let input = setup(dev, &mut input_keys);
        let mut full = false;
        // Key IDs are u16; exceeding their namespace is not exhaustion.
        for _ in 0..=u16::MAX {
            match create(dev, &input) {
                Ok(key_id) => keys.push(key_id),
                Err(err) if vault_full(&err) => {
                    full = true;
                    break;
                }
                Err(err) => panic!("Unexpected key creation error: {err:?}"),
            }
        }
        assert!(full, "Vault did not reach its capacity limit");
        assert!(keys.len() >= 2, "Need retained and reclaimable output keys");
        let retained = keys[0];
        let released = *keys.last().expect("reclaimable key");
        helper_delete_key(dev, Some(session_id), rev, key_id(released))
            .expect("free one allocation");
        keys.pop();

        arm_io_failure(dev, session_id);

        let failed = create(dev, &input);
        if let Ok(key_id) = &failed {
            keys.push(*key_id);
        }
        assert!(
            matches!(failed, Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType))),
            "Expected post-create injected failure, got {failed:?}"
        );

        let recovered = create(dev, &input).expect("rollback must reclaim the allocation");
        keys.push(recovered);
        let full_again = create(dev, &input);
        if let Ok(key_id) = &full_again {
            keys.push(*key_id);
        }
        assert!(
            full_again.as_ref().is_err_and(vault_full),
            "Expected exactly one reclaimed allocation, got {full_again:?}"
        );
        verify(dev, &input, retained, recovered);
    }));

    // Attempt every deletion before resuming an assertion panic.
    let cleanup_errors: Vec<_> = keys
        .into_iter()
        .map(key_id)
        .chain(input_keys)
        .filter_map(|key_id| helper_delete_key(dev, Some(session_id), rev, key_id).err())
        .collect();
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
    assert!(cleanup_errors.is_empty(), "Key cleanup: {cleanup_errors:?}");
}

/// Returns false, after printing the standard skip message, when the firmware
/// lacks `tsra_test_hooks`. Otherwise the probe arms TriggerIoFailure, so one
/// ECC generation (which checks the flag) consumes it before the caller starts.
pub fn rollback_hooks_supported(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16) -> bool {
    let resp = helper_test_action_cmd(dev, session_id, TestActionRequest::TriggerIoFailure);
    if matches!(&resp, Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))) {
        println!("Firmware is not built with tsra_test_hooks.");
        return false;
    }
    assert_eq!(
        resp.expect("probe rollback injection").hdr.status,
        DdiStatus::Success
    );
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let disarm = helper_ecc_generate_key_pair(
        dev,
        Some(session_id),
        rev,
        DdiEccCurve::P256,
        helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
    );
    if let Ok(resp) = &disarm {
        helper_delete_key(dev, Some(session_id), rev, resp.data.private_key_id)
            .expect("delete unexpected probe key");
    }
    assert!(
        matches!(disarm, Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType))),
        "Probe must consume the armed injection, got {disarm:?}"
    );
    true
}

/// Arms TriggerIoFailure on firmware already probed for `tsra_test_hooks`.
pub fn arm_io_failure(dev: &mut <DdiTest as Ddi>::Dev, session_id: u16) {
    let resp = helper_test_action_cmd(dev, session_id, TestActionRequest::TriggerIoFailure)
        .expect("arm rollback injection");
    assert_eq!(resp.hdr.status, DdiStatus::Success);
}

pub fn kdf_input(dev: &<DdiTest as Ddi>::Dev, session_id: u16, keys: &mut Vec<u16>) -> u16 {
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let properties = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
    let input =
        helper_ecc_generate_key_pair(dev, Some(session_id), rev, DdiEccCurve::P256, properties)
            .expect("generate KDF input ECC key");
    keys.push(input.data.private_key_id);
    let peer =
        helper_ecc_generate_key_pair(dev, Some(session_id), rev, DdiEccCurve::P256, properties)
            .expect("generate peer ECC key");
    keys.push(peer.data.private_key_id);
    let secret = helper_ecdh_key_exchange(
        dev,
        Some(session_id),
        rev,
        input.data.private_key_id,
        MborByteArray::from_slice(peer.data.pub_key.der.as_slice()).expect("peer public key"),
        DdiKeyType::Secret256,
        properties,
    )
    .expect("derive KDF input secret");
    keys.push(secret.data.key_id);
    secret.data.key_id
}

pub fn assert_aes_key(dev: &<DdiTest as Ddi>::Dev, session_id: u16, key_id: u16) {
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let plaintext = [0x42; 16];
    let iv = MborByteArray::from_slice(&[0; 16]).expect("AES IV");
    let encrypted = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        rev,
        key_id,
        DdiAesOp::Encrypt,
        MborByteArray::from_slice(&plaintext).expect("AES plaintext"),
        iv,
    )
    .expect("retained AES key must encrypt");
    let decrypted = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        rev,
        key_id,
        DdiAesOp::Decrypt,
        encrypted.data.msg,
        iv,
    )
    .expect("retained AES key must decrypt");
    assert_eq!(decrypted.data.msg.as_slice(), plaintext);
}

pub fn measure_aes_capacity(dev: &<DdiTest as Ddi>::Dev, session_id: u16) -> usize {
    let rev = Some(DdiApiRev { major: 1, minor: 0 });
    let mut keys = Vec::new();
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| {
        for _ in 0..=u16::MAX {
            match helper_aes_generate(
                dev,
                Some(session_id),
                rev,
                DdiAesKeySize::Aes256,
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App),
            ) {
                Ok(resp) => keys.push(resp.data.key_id),
                Err(err) if vault_full(&err) => return keys.len(),
                Err(err) => panic!("Unexpected capacity probe error: {err:?}"),
            }
        }
        panic!("Vault did not reach its capacity limit");
    }));
    let cleanup_errors: Vec<_> = keys
        .into_iter()
        .filter_map(|key_id| helper_delete_key(dev, Some(session_id), rev, key_id).err())
        .collect();
    let capacity = match outcome {
        Ok(capacity) => capacity,
        Err(payload) => std::panic::resume_unwind(payload),
    };
    assert!(
        cleanup_errors.is_empty(),
        "Probe cleanup: {cleanup_errors:?}"
    );
    capacity
}
