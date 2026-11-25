// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the out-of-session TBOR `GetCertificate`
//! command.
//!
//! `GetCertificate` is the TBOR analogue of MBOR `GetCertificate`: it
//! returns a single DER-encoded X.509 certificate from the caller's
//! partition at a `(slot_id, cert_id)`, without first establishing a
//! session. The tests fetch every certificate in the chain, cross-check
//! each against the MBOR path (same underlying cert store), and confirm
//! that an out-of-range index or slot is rejected.

use tsra_ddi_interface::TborOobItem;
use tsra_ddi_tbor_test_harness::SessionSuite;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_test_harness::CU_PSK_ID as CU;
use tsra_ddi_tbor_types::TborGetCertChainInfoReq;
use tsra_ddi_tbor_types::TborGetCertReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::CERT_BANK_ECC;
use tsra_ddi_tbor_types::CERT_BANK_MLDSA;
use tsra_ddi_tbor_types::CERT_MAX_LEN;
use x509::X509Certificate;
use x509::X509CertificateOp;

/// Fetch the chain length via TBOR `GetCertChainInfo`.
fn num_certs(ctx: &TestCtx) -> u8 {
    ctx.tbor(&TborGetCertChainInfoReq::new(0, CERT_BANK_ECC))
        .expect("GetCertChainInfo")
        .num_certs
}

#[test]
fn all_indices_round_trip() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);
    assert!(count > 0, "chain must be non-empty");

    for cert_id in 0..count {
        let resp = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("TBOR GetCertificate failed");
        assert!(
            !resp.is_empty(),
            "certificate at index {cert_id} must be non-empty DER",
        );
        // DER-encoded X.509 certificates start with a SEQUENCE tag.
        assert_eq!(
            resp[0], 0x30,
            "certificate at index {cert_id} must be a DER SEQUENCE",
        );
        assert!(
            resp.len() <= CERT_MAX_LEN,
            "certificate at index {cert_id} exceeds the wire limit",
        );
        X509Certificate::from_der(&resp).expect("certificate must be valid X.509");
    }
}

/// The TBOR certificate bytes must be identical to the MBOR path for
/// every index — both read the same underlying cert store.
#[test]
fn matches_mbor_path() {
    let ctx = TestCtx::new();
    if ctx.is_duo() {
        // Duo has no MBOR channel.
        return;
    }
    let count = num_certs(&ctx);

    for cert_id in 0..count {
        let tbor = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("TBOR GetCertificate");
        let mbor = ctx.get_certificate(cert_id).expect("MBOR GetCertificate");
        assert_eq!(
            tbor.as_slice(),
            mbor.data.certificate.as_slice(),
            "TBOR and MBOR certificate bytes must match at index {cert_id}",
        );
    }
}

/// Repeated reads of every advertised certificate return identical bytes.
#[test]
fn repeated_reads_are_stable() {
    let ctx = TestCtx::new();

    for cert_id in 0..num_certs(&ctx) {
        let first = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("first certificate read");
        let second = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("second certificate read");

        assert_eq!(
            first, second,
            "certificate {cert_id} must be stable across reads",
        );
    }
}

/// Distinct indices in a multi-certificate chain must not alias the same
/// certificate bytes.
#[test]
fn certificate_indices_do_not_alias() {
    let ctx = TestCtx::new();
    let mut certificates = Vec::new();

    for cert_id in 0..num_certs(&ctx) {
        let cert = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("certificate read");

        for (previous_id, previous) in certificates.iter().enumerate() {
            assert_ne!(
                &cert, previous,
                "certificate {cert_id} aliases certificate {previous_id}",
            );
        }

        certificates.push(cert);
    }
}

/// The first index beyond the chain and the largest representable index are
/// rejected with `InvalidArg`.
#[test]
fn invalid_indices_rejected() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    for cert_id in [count, u8::MAX] {
        ctx.expect_get_cert_reject(0, CERT_BANK_ECC, cert_id, TborStatus::InvalidArg);
    }
}

/// The std/emu PAL only provisions chain slot 0; any other slot is
/// rejected with `InvalidArg`.
#[test]
fn invalid_slots_rejected() {
    let ctx = TestCtx::new();

    for slot_id in [1, 2, 127, 254, u8::MAX] {
        ctx.expect_get_cert_reject(slot_id, CERT_BANK_ECC, 0, TborStatus::InvalidArg);
    }
}

/// Rejected requests must not disturb a certificate that can be read from the
/// valid chain.
#[test]
fn rejected_requests_do_not_affect_valid_certificate() {
    let ctx = TestCtx::new();
    let before = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("valid certificate before rejects");

    ctx.expect_get_cert_reject(u8::MAX, CERT_BANK_ECC, 0, TborStatus::InvalidArg);
    ctx.expect_get_cert_reject(0, CERT_BANK_ECC, u8::MAX, TborStatus::InvalidArg);

    let after = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("valid certificate after rejects");
    assert_eq!(
        before, after,
        "rejected requests must not mutate the valid certificate chain",
    );
}

/// `GetCertificate` is out-of-session and remains callable while an unrelated
/// authenticated session is active.
#[test]
fn callable_while_session_active() {
    let ctx = TestCtx::new();
    let before = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("certificate before session");

    let session = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("open CO authenticated session");
    let during = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("certificate while session is active");

    assert_eq!(
        before, during,
        "active session must not affect out-of-session certificate reads",
    );
    session.close().expect("close CO authenticated session");
}

/// Every certificate index advertised by `GetCertChainInfo` is readable, and
/// the first index beyond the advertised chain is rejected.
#[test]
fn chain_info_count_matches_get_certificate_boundary() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    assert!(count > 0, "chain must contain at least one certificate");

    for cert_id in 0..count {
        ctx.get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("GetCertChainInfo-advertised certificate must be readable");
    }

    ctx.expect_get_cert_reject(0, CERT_BANK_ECC, count, TborStatus::InvalidArg);
}

/// Reading other certificates in the chain must not affect a previously read
/// certificate.
#[test]
fn interleaved_reads_are_stable() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    let first = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("initial certificate 0 read");

    for cert_id in 0..count {
        ctx.get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("interleaved certificate read");
    }

    let after = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("certificate 0 after interleaved reads");

    assert_eq!(
        first, after,
        "reading other certificates must not affect certificate 0",
    );
}

/// Opening and closing an authenticated session must not affect subsequent
/// out-of-session certificate reads.
#[test]
fn stable_across_session_lifecycle() {
    let ctx = TestCtx::new();

    let before = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("certificate before opening session");

    let session = ctx
        .open_session(CO, SessionSuite::EcdhP384)
        .expect("open CO authenticated session");

    let during = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("certificate while session is active");

    session.close().expect("close CO authenticated session");

    let after = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("certificate after closing session");

    assert_eq!(
        before, during,
        "opening a session must not affect GetCertificate",
    );
    assert_eq!(
        before, after,
        "closing a session must not affect GetCertificate",
    );
}

/// A failed certificate lookup must not affect later reads of any valid
/// certificate in the chain.
#[test]
fn rejected_request_does_not_affect_entire_chain() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    let before: Vec<_> = (0..count)
        .map(|cert_id| {
            ctx.get_cert(0, CERT_BANK_ECC, cert_id)
                .expect("initial certificate read")
        })
        .collect();

    ctx.expect_get_cert_reject(u8::MAX, CERT_BANK_ECC, u8::MAX, TborStatus::InvalidArg);

    for (cert_id, expected) in before.iter().enumerate() {
        let actual = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id as u8)
            .expect("certificate read after rejected request");

        assert_eq!(
            &actual, expected,
            "rejected request must not modify certificate {cert_id}",
        );
    }
}

/// Reading certificates must not change the metadata reported by
/// `GetCertChainInfo`.
#[test]
fn certificate_reads_do_not_change_chain_info() {
    let ctx = TestCtx::new();

    let before = ctx
        .tbor(&TborGetCertChainInfoReq::new(0, CERT_BANK_ECC))
        .expect("chain info before certificate reads");

    for cert_id in 0..before.num_certs {
        ctx.get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("certificate read failed");
    }

    let after = ctx
        .tbor(&TborGetCertChainInfoReq::new(0, CERT_BANK_ECC))
        .expect("chain info after certificate reads");

    assert_eq!(
        before, after,
        "GetCertificate reads must not modify certificate-chain metadata",
    );
}

/// Certificates may be fetched in arbitrary order; reads do not depend on
/// sequential traversal of the chain.
#[test]
fn certificates_can_be_read_in_reverse_order() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    for cert_id in (0..count).rev() {
        let cert = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("reverse certificate read");

        assert!(!cert.is_empty(), "certificate {cert_id} must be non-empty",);
    }
}

/// Both ends of the advertised certificate-index range are readable.
#[test]
fn first_and_last_valid_indices_succeed() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    assert!(count > 0, "certificate chain must be non-empty");

    ctx.get_cert(0, CERT_BANK_ECC, 0)
        .expect("first certificate must be readable");

    ctx.get_cert(0, CERT_BANK_ECC, count - 1)
        .expect("last advertised certificate must be readable");
}

/// Interleaving MBOR and TBOR certificate reads must not alter the
/// certificate returned by either interface.
#[test]
fn mbor_tbor_interleaved_reads_remain_identical() {
    let ctx = TestCtx::new();
    if ctx.is_duo() {
        // Duo has no MBOR channel.
        return;
    }

    for cert_id in 0..num_certs(&ctx) {
        let tbor_before = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("initial TBOR certificate read");

        let mbor = ctx.get_certificate(cert_id).expect("MBOR certificate read");

        let tbor_after = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id)
            .expect("final TBOR certificate read");

        assert_eq!(
            tbor_before.as_slice(),
            mbor.data.certificate.as_slice(),
            "initial TBOR and MBOR certificate must match at index {cert_id}",
        );

        assert_eq!(
            tbor_before, tbor_after,
            "MBOR read must not affect TBOR certificate {cert_id}",
        );
    }
}

/// Invalid slot and invalid certificate-index failures must not affect any
/// certificate in the valid chain.
#[test]
fn all_reject_classes_preserve_entire_chain() {
    let ctx = TestCtx::new();
    let count = num_certs(&ctx);

    let before: Vec<_> = (0..count)
        .map(|cert_id| {
            ctx.get_cert(0, CERT_BANK_ECC, cert_id)
                .expect("initial certificate read")
        })
        .collect();

    ctx.expect_get_cert_reject(u8::MAX, CERT_BANK_ECC, 0, TborStatus::InvalidArg);

    ctx.expect_get_cert_reject(0, CERT_BANK_ECC, u8::MAX, TborStatus::InvalidArg);

    for (cert_id, expected) in before.iter().enumerate() {
        let actual = ctx
            .get_cert(0, CERT_BANK_ECC, cert_id as u8)
            .expect("certificate read after rejects");

        assert_eq!(
            &actual, expected,
            "rejects must not modify certificate {cert_id}",
        );
    }
}

/// `GetCertificate` is out-of-session and remains callable while an unrelated
/// CU PlainText session is active. This complements the CO-session case
/// and verifies that partition-user session identity does not affect the
/// certificate store lookup.
#[test]
fn callable_while_cu_session_active() {
    let ctx = TestCtx::new();
    let before = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("certificate before CU session");

    let session = ctx
        .open_session(CU, SessionSuite::EcdhP384)
        .expect("open CU PlainText session");

    let during = ctx
        .get_cert(0, CERT_BANK_ECC, 0)
        .expect("certificate while CU session is active");

    assert_eq!(
        before, during,
        "active CU session must not affect out-of-session certificate reads",
    );

    session.close().expect("close CU PlainText session");
}

/// `GetCert` remains stable for the entire certificate chain across both
/// supported CO and CU session lifecycles.
#[test]
fn entire_chain_stable_across_co_and_cu_session_lifecycles() {
    let ctx = TestCtx::new();

    let info = ctx
        .tbor(&TborGetCertChainInfoReq::new(0, CERT_BANK_ECC))
        .expect("GetCertChainInfo");

    assert!(info.num_certs > 0, "chain must be non-empty");

    let before: Vec<_> = (0..info.num_certs)
        .map(|cert_id| {
            ctx.get_cert(0, CERT_BANK_ECC, cert_id)
                .expect("GetCert before session activity")
        })
        .collect();

    for (role, session_type) in [(CO, SessionSuite::EcdhP384), (CU, SessionSuite::EcdhP384)] {
        let session = ctx
            .open_session(role, session_type)
            .unwrap_or_else(|e| panic!("open session role {role} type {session_type:?}: {e:?}"));

        for (cert_id, expected) in before.iter().enumerate() {
            let during = ctx
                .get_cert(0, CERT_BANK_ECC, cert_id as u8)
                .expect("GetCert while session is active");

            assert_eq!(
                &during, expected,
                "active role {role} session must not affect certificate {cert_id}",
            );
        }

        session
            .close()
            .unwrap_or_else(|e| panic!("close session role {role}: {e:?}"));

        for (cert_id, expected) in before.iter().enumerate() {
            let after = ctx
                .get_cert(0, CERT_BANK_ECC, cert_id as u8)
                .expect("GetCert after session close");

            assert_eq!(
                &after, expected,
                "role {role} session lifecycle must not affect certificate {cert_id}",
            );
        }
    }
}

/// Read every certificate of `bank` in slot 0, root first.
fn bank_chain(ctx: &TestCtx, bank: u8) -> Vec<Vec<u8>> {
    let info = ctx
        .tbor(&TborGetCertChainInfoReq::new(0, bank))
        .expect("GetCertChainInfo");
    (0..info.num_certs)
        .map(|cert_id| {
            ctx.get_cert(0, bank, cert_id)
                .expect("bank certificate read")
        })
        .collect()
}

/// The ML-DSA bank serves a full chain that validates leaf → root, and
/// it does not alias the ECC bank.
#[test]
fn mldsa_bank_chain_validates() {
    let ctx = TestCtx::new();
    let mut ders = bank_chain(&ctx, CERT_BANK_MLDSA);
    assert_eq!(ders.len(), 4, "ML-DSA bank must carry a 4-cert chain");
    for der in &ders {
        assert!(der.len() <= CERT_MAX_LEN);
    }
    let ecc = bank_chain(&ctx, CERT_BANK_ECC);
    assert_ne!(ders.last(), ecc.last(), "ML-DSA and ECC leaves must differ");

    let leaf = X509Certificate::from_der(&ders.pop().expect("leaf")).expect("leaf DER");
    let issuers: Vec<_> = ders
        .iter()
        .rev()
        .map(|der| X509Certificate::from_der(der).expect("issuer DER"))
        .collect();
    assert!(
        leaf.validate_chain(&issuers).expect("validate chain"),
        "ML-DSA certificate chain must validate",
    );
}

/// The two banks report distinct chain thumbprints.
#[test]
fn bank_thumbprints_differ() {
    let ctx = TestCtx::new();
    let ecc = ctx
        .tbor(&TborGetCertChainInfoReq::new(0, CERT_BANK_ECC))
        .expect("ECC chain info");
    let mldsa = ctx
        .tbor(&TborGetCertChainInfoReq::new(0, CERT_BANK_MLDSA))
        .expect("ML-DSA chain info");
    assert_ne!(ecc.thumbprint, mldsa.thumbprint);
}

/// An unknown bank is rejected.
#[test]
fn invalid_bank_rejected() {
    let ctx = TestCtx::new();
    for bank in [2, u8::MAX] {
        ctx.expect_get_cert_reject(0, bank, 0, TborStatus::InvalidArg);
        ctx.expect_fw_reject(
            &TborGetCertChainInfoReq::new(0, bank),
            TborStatus::InvalidArg,
        );
    }
}

/// An out-of-band buffer smaller than the certificate is rejected.
#[test]
fn undersized_oob_rejected() {
    let ctx = TestCtx::new();
    let mut small = [0u8; 16];
    ctx.expect_fw_reject_oob_io(
        &TborGetCertReq::new(0, CERT_BANK_ECC, 0),
        &mut [TborOobItem::Out(&mut small)],
        TborStatus::InsufficientBuffer,
    );
}
