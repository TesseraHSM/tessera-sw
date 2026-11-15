// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `PartFinal` with ML-DSA-87 at either level of the POTA → PTA chain.
//!
//! The policy `pta_alg` selects the PTA algorithm, and the POTA algorithm
//! is independent of it: every combination of P-384 / ML-DSA-87 POTA and
//! PTA must finalize, and the PartOwner slot (2) then serves the PID leaf
//! in the PTA's bank only.

use tsra_crypto::ImportableKey;
use tsra_crypto::MlDsaAlgo;
use tsra_crypto::MlDsaPublicKey;
use tsra_crypto::VerifyOp;
use tsra_ddi_tbor_test_harness::x509_fixture::csr_public_key;
use tsra_ddi_tbor_test_harness::x509_fixture::AnchorKey;
use tsra_ddi_tbor_test_harness::x509_fixture::AnyPotaFixture;
use tsra_ddi_tbor_test_harness::x509_fixture::PtaChain;
use tsra_ddi_tbor_types::POLICY_PTA_ALG_ES384;
use tsra_ddi_tbor_types::POLICY_PTA_ALG_MLDSA87;

use super::*;
use crate::commands::key_report::mldsa_pid_pub_key;
use crate::commands::part_init::known_good_test_policy;

/// Policy anchored to `pota` with PTA algorithm `pta_alg`.
fn policy_for(pota: &AnyPotaFixture, pta_alg: i64) -> Vec<u8> {
    let mut policy = known_good_test_policy().with_pta_alg(pta_alg);
    policy.pota_spki_thumbprint = pota.spki_thumbprint();
    policy.encode()
}

/// Run PartInit under `policy` and return the session plus the PTA key
/// (PTAID form) from the returned CSR.
fn init(ctx: &TestCtx, policy: &[u8]) -> (SessionHandshake, Vec<u8>) {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, &mach_seed(), policy)
        .expect("PartInit roundtrip");
    let pta_pub = csr_public_key(&init.pta_csr).to_vec();
    (session, pta_pub)
}

/// Read one DER TLV with the expected `tag` at the start of `der`,
/// returning `(contents, total_len)`.
fn der_tlv(der: &[u8], tag: u8) -> (&[u8], usize) {
    assert_eq!(der[0], tag, "unexpected DER tag");
    let (len, header) = if der[1] & 0x80 == 0 {
        (usize::from(der[1]), 2)
    } else {
        let n = usize::from(der[1] & 0x7f);
        let len = der[2..2 + n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, 2 + n)
    };
    (&der[header..header + len], header + len)
}

/// Split a certificate into `(tbs_tlv, tbs fields as full TLVs, signature)`.
fn split_cert(der: &[u8]) -> (&[u8], Vec<&[u8]>, &[u8]) {
    let (cert, _) = der_tlv(der, 0x30);
    let (tbs, tbs_len) = der_tlv(cert, 0x30);
    let (_, alg_len) = der_tlv(&cert[tbs_len..], 0x30);
    let (sig_bits, _) = der_tlv(&cert[tbs_len + alg_len..], 0x03);
    assert_eq!(sig_bits[0], 0, "signature BIT STRING has no unused bits");
    let mut fields = Vec::new();
    let mut rest = tbs;
    while !rest.is_empty() {
        let (_, len) = der_tlv(rest, rest[0]);
        fields.push(&rest[..len]);
        rest = &rest[len..];
    }
    (&cert[..tbs_len], fields, &sig_bits[1..])
}

/// Assert the slot-2 ML-DSA PID leaf is issued by the PTA certificate of
/// `chain`, signed by the ML-DSA PTA key `pta_pub`, and certifies the
/// partition's ML-DSA PID key.
fn assert_mldsa_pid_leaf(ctx: &TestCtx, chain: &PtaChain, pta_pub: &[u8]) {
    let info = ctx
        .tbor(&TborGetCertChainInfoReq::new(2, CERT_BANK_MLDSA))
        .expect("slot 2 ML-DSA metadata");
    assert_eq!(info.num_certs, 1);

    let leaf = ctx
        .get_cert(2, CERT_BANK_MLDSA, 0)
        .expect("ML-DSA PID leaf");
    let (tbs, fields, signature) = split_cert(&leaf);
    let (_, pta_fields, _) = split_cert(&chain.pta_der);
    // [0] version, serial, sigAlg, issuer, validity, subject, spki, ...
    assert_eq!(
        fields[3], pta_fields[5],
        "leaf issuer must be the PTA subject"
    );

    let pta = MlDsaPublicKey::from_bytes(pta_pub).expect("PTA ML-DSA key");
    assert!(
        MlDsaAlgo::new(&[])
            .expect("ML-DSA engine")
            .verify(&pta, tbs, signature)
            .expect("ML-DSA verify"),
        "PID leaf must verify under the ML-DSA PTA key",
    );

    let pid = mldsa_pid_pub_key(ctx);
    assert!(
        fields[6].ends_with(&pid),
        "leaf must certify the partition ML-DSA PID key",
    );

    ctx.expect_get_cert_reject(2, CERT_BANK_ECC, 0, TborStatus::InvalidArg);
    ctx.expect_fw_reject(
        &TborGetCertChainInfoReq::new(2, CERT_BANK_ECC),
        TborStatus::InvalidArg,
    );
}

/// ML-DSA-87 POTA → ML-DSA-87 PTA finalizes and serves an ML-DSA PID leaf.
#[test]
fn part_final_mldsa_pota_mldsa_pta() {
    let ctx = TestCtx::new();
    let pota = AnyPotaFixture::new(AnchorKey::mldsa87(&[7; 32]));
    let policy = policy_for(&pota, POLICY_PTA_ALG_MLDSA87);
    let (session, pta_pub) = init(&ctx, &policy);
    let chain = pota.chain_for(&pta_pub);

    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");
    assert_mldsa_pid_leaf(&ctx, &chain, &pta_pub);
}

/// P-384 POTA → ML-DSA-87 PTA: the POTA algorithm is independent of
/// `pta_alg`.
#[test]
fn part_final_ecc_pota_mldsa_pta() {
    let ctx = TestCtx::new();
    let pota = AnyPotaFixture::new(AnchorKey::p384());
    let policy = policy_for(&pota, POLICY_PTA_ALG_MLDSA87);
    let (session, pta_pub) = init(&ctx, &policy);
    let chain = pota.chain_for(&pta_pub);

    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");
    assert_mldsa_pid_leaf(&ctx, &chain, &pta_pub);
}

/// ML-DSA-87 POTA → P-384 PTA finalizes and serves the ECC PID leaf only.
#[test]
fn part_final_mldsa_pota_ecc_pta() {
    let ctx = TestCtx::new();
    let pota = AnyPotaFixture::new(AnchorKey::mldsa87(&[7; 32]));
    let policy = policy_for(&pota, POLICY_PTA_ALG_ES384);
    let (session, pta_pub) = init(&ctx, &policy);
    assert_eq!(pta_pub.len(), SEC1_PUB_LEN);
    let chain = pota.chain_for(&pta_pub);

    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    let leaf = ctx.get_cert(2, CERT_BANK_ECC, 0).expect("ECC PID leaf");
    let pta = X509Certificate::from_der(&chain.pta_der).expect("PTA DER");
    let leaf = X509Certificate::from_der(&leaf).expect("PID DER");
    assert!(
        leaf.verify_signature(&pta).expect("PID signature"),
        "PID leaf must verify under the ECC PTA key",
    );
    ctx.expect_get_cert_reject(2, CERT_BANK_MLDSA, 0, TborStatus::InvalidArg);
}

/// An ML-DSA PTA chain certifying a different ML-DSA-87 key than the
/// partition PTA is rejected.
#[test]
fn part_final_mldsa_reject_pta_mismatch() {
    let ctx = TestCtx::new();
    let pota = AnyPotaFixture::new(AnchorKey::mldsa87(&[7; 32]));
    let policy = policy_for(&pota, POLICY_PTA_ALG_MLDSA87);
    let (session, _) = init(&ctx, &policy);
    let chain = pota.chain_for(&AnchorKey::mldsa87(&[9; 32]).pub_key());

    let err = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a non-partition PTA key must be rejected");
    assert_fw_rejects(&err, TborStatus::PartFinalPtaMismatch);
}

/// A chain certifying a PTA key of the other algorithm than the policy
/// `pta_alg` is rejected.
#[test]
fn part_final_mldsa_reject_wrong_alg_pta() {
    let ctx = TestCtx::new();
    let pota = AnyPotaFixture::new(AnchorKey::p384());
    let policy = policy_for(&pota, POLICY_PTA_ALG_MLDSA87);
    let (session, _) = init(&ctx, &policy);
    let chain = pota.chain_for(&AnchorKey::p384().pub_key());

    let err = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("an ECC PTA cert under an ML-DSA pta_alg must be rejected");
    assert_fw_rejects(&err, TborStatus::PartFinalPtaMismatch);
}

/// An ML-DSA chain not anchored to the policy POTA is rejected.
#[test]
fn part_final_mldsa_reject_unanchored_chain() {
    let ctx = TestCtx::new();
    let pota = AnyPotaFixture::new(AnchorKey::mldsa87(&[7; 32]));
    let policy = policy_for(&pota, POLICY_PTA_ALG_MLDSA87);
    let (session, pta_pub) = init(&ctx, &policy);
    let rogue = AnyPotaFixture::new(AnchorKey::mldsa87(&[8; 32]));
    let chain = rogue.chain_for(&pta_pub);

    let err = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a chain not anchored to the policy POTA must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
}
