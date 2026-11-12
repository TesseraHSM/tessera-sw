// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NSSR between two steps of one host flow.

#![cfg(test)]

use test_with_tracing::test;

use super::*;

/// GetEstablishCredEncryptionKey → NSSR → EstablishCredential.
#[test]
fn nssr_mid_establish_credential() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            common_cleanup(dev, ddi, path, None);
            let masked_bk3 = helper_get_or_init_bk3(dev);
            let establish = |dev: &Dev, (credential, pub_key)| {
                let (signature, pota_pub_key) = helper_get_pota_endorsement(dev);
                helper_establish_credential(
                    dev,
                    None,
                    REV,
                    credential,
                    pub_key,
                    masked_bk3,
                    empty(),
                    empty(),
                    MborByteArray::from_slice(&signature).expect("POTA signature"),
                    DdiDerPublicKey {
                        der: MborByteArray::from_slice(&pota_pub_key).expect("POTA public key"),
                        key_kind: DdiKeyType::Ecc384Public,
                    },
                )
            };
            let tunnel =
                |dev: &Dev| encrypt_userid_pin_for_establish_cred(dev, TEST_CRED_ID, TEST_CRED_PIN);
            let stale = tunnel(dev);
            nssr(dev);
            assert_status(
                establish(dev, stale),
                DdiStatus::NonceMismatch,
                "payload from the pre-NSSR tunnel",
            );
            establish(dev, tunnel(dev)).expect("EstablishCredential over a fresh tunnel");
        },
    );
}

/// GetCertChainInfo → NSSR → GetCertificate: the fetch completes, and the
/// host's re-read of the thumbprint detects the reissued chain.
#[test]
fn nssr_mid_get_certificate() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let _lm = Lm::new(dev, ddi, path);
            let (count, thumbprint) = helper_get_cert_chain_info_data(dev);
            let leaf = helper_get_certificate(dev, count - 1)
                .expect("GetCertificate")
                .data
                .certificate;
            nssr(dev);
            let chain: Vec<Vec<u8>> = (0..count)
                .map(|id| {
                    let cert = helper_get_certificate(dev, id).expect("GetCertificate after NSSR");
                    cert.data.certificate.as_slice().to_vec()
                })
                .collect();
            assert_ne!(chain[usize::from(count) - 1], leaf.as_slice());
            assert!(helper_verify_cert_chain(&chain).is_ok());
            let (count_after, thumbprint_after) = helper_get_cert_chain_info_data(dev);
            assert_eq!(count_after, count);
            assert_ne!(thumbprint_after, thumbprint, "the host must refetch");
        },
    );
}

/// SetInitBk3Pin → NSSR → SecureInitBk3 (emulator only; see `bk3.rs`).
#[test]
fn nssr_mid_secure_init_bk3() {
    if !ddi_sock_server::autostarted() {
        return;
    }
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            common_cleanup(dev, ddi, path, None);
            // NOTE(nssr): both opcodes are unknown to firmware (see `bk3.rs`), so
            // the Bk3PinNotSet / NonceMismatch contract of
            // `secure_provision_lm_sim.rs` is unreachable on the emulator.
            assert_status(
                set_init_bk3_pin(dev, TEST_CRED_ID, TEST_CRED_PIN),
                DdiStatus::InvalidArg,
                "SetInitBk3Pin",
            );
            let (bk3, pub_key) =
                build_secure_init_bk3_payload(dev, TEST_CRED_ID, TEST_CRED_PIN, &HARD_CODED_BK3)
                    .expect("SecureInitBk3 payload");
            nssr(dev);
            assert_status(
                helper_secure_init_bk3(dev, bk3, pub_key),
                DdiStatus::InvalidArg,
                "SecureInitBk3",
            );
        },
    );
}
