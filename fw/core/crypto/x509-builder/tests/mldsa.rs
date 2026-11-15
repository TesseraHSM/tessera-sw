// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA-87 certificates and CSRs built on the std PAL and checked with
//! OpenSSL.

#![allow(unsafe_code)]

use openssl::bn::BigNum;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
use openssl::pkey::KeyType;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::x509::X509Req;
use openssl::x509::X509;
use tokio::runtime::Handle;
use tsra_fw_core_crypto_x509_builder::cert_builder;
use tsra_fw_core_crypto_x509_builder::cert_builder::LeafCertParams;
use tsra_fw_core_crypto_x509_builder::cert_builder::MlDsa87Signer;
use tsra_fw_core_crypto_x509_builder::cert_builder::TbsSigner;
use tsra_fw_core_crypto_x509_builder::csr;
use tsra_fw_core_crypto_x509_builder::csr_builder;
use tsra_fw_core_crypto_x509_builder::leaf_cert;
use tsra_fw_core_crypto_x509_builder::retarget;
use tsra_fw_core_crypto_x509_builder::retarget::KeyAlg;
use tsra_fw_core_crypto_x509_builder::retarget::SigAlg;
use tsra_fw_core_crypto_x509_builder::retarget::SubjectKey;
use tsra_fw_core_crypto_x509_builder::retarget::TbsKind;
use tsra_fw_hsm_pal_std_uno::HsmPartId;
use tsra_fw_hsm_pal_std_uno::StdHsmIo;
use tsra_fw_hsm_pal_std_uno::StdHsmPal;
use tsra_fw_hsm_pal_traits::*;

const PK_LEN: usize = 2592;

fn pal_and_io() -> (StdHsmPal, StdHsmIo) {
    let (_tx, rx) = async_channel::bounded(1);
    let pal = StdHsmPal::new(rx, Handle::current());
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
    (pal, io)
}

fn dma(bytes: &[u8]) -> &HsmDmaBuf {
    // SAFETY: the std PAL emulates DMA without memory-region restrictions.
    unsafe { HsmDmaBuf::from_raw(bytes) }
}

fn dma_mut(bytes: &mut [u8]) -> &mut HsmDmaBuf {
    // SAFETY: the std PAL emulates DMA without memory-region restrictions.
    unsafe { HsmDmaBuf::from_raw_mut(bytes) }
}

/// A fresh ML-DSA-87 key pair: `(seed, public key)`.
async fn mldsa_keypair(pal: &StdHsmPal, io: &StdHsmIo) -> ([u8; MLDSA_SEED_LEN], Vec<u8>) {
    let mut seed = [0u8; MLDSA_SEED_LEN];
    let mut sk = vec![0u8; 4896];
    let mut pk = vec![0u8; PK_LEN];
    pal.mldsa_gen_keypair(
        io,
        HsmMlDsaParamSet::MlDsa87,
        HsmMlSeedSrc::Random,
        HsmMlDsaPct::None,
        dma_mut(&mut seed),
        Some((dma_mut(&mut sk), dma_mut(&mut pk))),
    )
    .await
    .expect("keygen");
    (seed, pk)
}

fn mldsa_pkey(pk: &[u8]) -> PKey<openssl::pkey::Public> {
    PKey::public_key_from_raw_bytes_ex(None, KeyType::ML_DSA_87, None, pk)
        .expect("ML-DSA-87 public key")
}

/// ECDSA-P384 [`TbsSigner`] backed by OpenSSL, emitting the std PAL's
/// operand order.
struct OsslEccSigner(EcKey<Private>);

impl TbsSigner<StdHsmIo> for OsslEccSigner {
    async fn sign_digest(
        &self,
        _io: &StdHsmIo,
        digest: &HsmDmaBuf,
        sig: &mut HsmDmaBuf,
    ) -> HsmResult<()> {
        let s = EcdsaSig::sign(digest, &self.0).expect("ecdsa sign");
        for (half, n) in sig.chunks_mut(48).zip([s.r(), s.s()]) {
            let be = n.to_vec_padded(48).expect("pad");
            tsra_fw_hsm_byte_order::int_copy_from_be(StdHsmPal::BYTE_ORDER, half, &be)?;
        }
        Ok(())
    }
}

fn params<'a>(pk: &'a [u8; PK_LEN], issuer_cn: &'a [u8; 64]) -> LeafCertParams<'a, [u8; PK_LEN]> {
    LeafCertParams {
        public_key: pk,
        serial_number: &[0x11; 20],
        not_before: b"20250101000000Z",
        not_after: b"99991231235959Z",
        issuer_cn,
        subject_cn: &[b'S'; 32],
        subject_key_id: &[0x22; 20],
        authority_key_id: &[0x33; 20],
    }
}

fn check_leaf(der: &[u8], pk: &[u8], issuer: &PKey<impl openssl::pkey::HasPublic>) {
    let cert = X509::from_der(der).expect("parse cert");
    assert!(cert.verify(issuer).expect("verify"), "signature");
    assert_eq!(
        cert.public_key()
            .expect("spki")
            .raw_public_key()
            .expect("raw"),
        pk
    );
    assert_eq!(cert.subject_key_id().expect("ski").as_slice(), &[0x22; 20]);
    assert_eq!(
        cert.authority_key_id().expect("aki").as_slice(),
        &[0x33; 20]
    );
    assert_eq!(
        cert.serial_number().to_bn().expect("sn"),
        BigNum::from_slice(&[0x11; 20]).expect("bn")
    );
}

#[tokio::test]
async fn mldsa_issuer_leaf_verifies() {
    let (pal, io) = pal_and_io();
    let (issuer_seed, issuer_pk) = mldsa_keypair(&pal, &io).await;
    let (_, pk) = mldsa_keypair(&pal, &io).await;
    let pk: [u8; PK_LEN] = pk.try_into().expect("pk len");
    let params = params(&pk, &[b'I'; 64]);
    let der = pal
        .alloc_scoped_async(&io, async |alloc| {
            let signer = MlDsa87Signer::new(&pal, HsmMlDsaPrivKey::Seed(dma(&issuer_seed)));
            let len =
                cert_builder::build_mldsa_leaf_cert(&io, alloc, &params, &signer, None).await?;
            let mut out = vec![0u8; len];
            let written = cert_builder::build_mldsa_leaf_cert(
                &io,
                alloc,
                &params,
                &signer,
                Some(dma_mut(&mut out)),
            )
            .await?;
            assert_eq!(written, len, "query size is exact");
            HsmResult::Ok(out)
        })
        .await
        .expect("build");
    check_leaf(&der, &pk, &mldsa_pkey(&issuer_pk));
}

#[tokio::test]
async fn ecc_issuer_mldsa_leaf_verifies() {
    let (pal, io) = pal_and_io();
    let (_, pk) = mldsa_keypair(&pal, &io).await;
    let pk: [u8; PK_LEN] = pk.try_into().expect("pk len");
    let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("group");
    let ec = EcKey::generate(&group).expect("ec key");
    let issuer = PKey::from_ec_key(ec.clone()).expect("pkey");
    let signer = OsslEccSigner(ec);
    let params = params(&pk, &[b'E'; 64]);
    let der = pal
        .alloc_scoped_async(&io, async |alloc| {
            let max = cert_builder::build_mldsa_leaf_cert_ecc_issuer(
                &pal, &io, alloc, &params, &signer, None,
            )
            .await?;
            let mut out = vec![0u8; max];
            let len = cert_builder::build_mldsa_leaf_cert_ecc_issuer(
                &pal,
                &io,
                alloc,
                &params,
                &signer,
                Some(&mut out),
            )
            .await?;
            out.truncate(len);
            HsmResult::Ok(out)
        })
        .await
        .expect("build");
    check_leaf(&der, &pk, &issuer);
    let cert = X509::from_der(&der).expect("parse");
    assert_eq!(
        cert.signature_algorithm().object().nid(),
        Nid::ECDSA_WITH_SHA384
    );
}

#[tokio::test]
async fn mldsa_csr_verifies() {
    let (pal, io) = pal_and_io();
    let (seed, pk) = mldsa_keypair(&pal, &io).await;
    let pk: [u8; PK_LEN] = pk.try_into().expect("pk len");
    let cn = [b'C'; csr::SUBJECT_CN_LEN];
    let der = pal
        .alloc_scoped_async(&io, async |alloc| {
            let signer = MlDsa87Signer::new(&pal, HsmMlDsaPrivKey::Seed(dma(&seed)));
            let len = csr_builder::build_mldsa_csr(&io, alloc, &pk, &cn, &signer, None).await?;
            let mut out = vec![0u8; len];
            assert_eq!(
                csr_builder::build_mldsa_csr(
                    &io,
                    alloc,
                    &pk,
                    &cn,
                    &signer,
                    Some(dma_mut(&mut out))
                )
                .await?,
                len
            );
            HsmResult::Ok(out)
        })
        .await
        .expect("build");
    let req = X509Req::from_der(&der).expect("parse csr");
    let pkey = req.public_key().expect("spki");
    assert_eq!(pkey.raw_public_key().expect("raw"), pk);
    assert!(req.verify(&pkey).expect("verify"), "self-signature");
    let name = req
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .expect("cn");
    assert_eq!(name.data().as_slice(), &cn);
}

/// Retargeting a template to its own algorithms is the identity.
#[test]
fn p384_retarget_is_identity() {
    for (tbs, kind, off) in [
        (
            &leaf_cert::TBS_TEMPLATE[..],
            TbsKind::Certificate,
            leaf_cert::PUBLIC_KEY_OFFSET,
        ),
        (&csr::TBS_TEMPLATE[..], TbsKind::Csr, csr::PUBLIC_KEY_OFFSET),
    ] {
        let key: &[u8; 97] = tbs[off..off + 97].try_into().expect("key");
        let len =
            retarget::retarget_len(tbs, kind, SigAlg::EcdsaP384Sha384, KeyAlg::P384).expect("len");
        assert_eq!(len, tbs.len());
        let mut out = vec![0u8; len];
        let written = retarget::retarget_tbs(
            tbs,
            kind,
            SigAlg::EcdsaP384Sha384,
            SubjectKey::P384(key),
            &mut out,
        )
        .expect("tbs");
        assert_eq!(written, len);
        assert_eq!(out, tbs);
    }
}

#[test]
fn retarget_rejects_short_output_and_non_template() {
    let tbs = &leaf_cert::TBS_TEMPLATE[..];
    let pk = [0u8; PK_LEN];
    let len = retarget::retarget_len(tbs, TbsKind::Certificate, SigAlg::MlDsa87, KeyAlg::MlDsa87)
        .expect("len");
    let mut out = vec![0u8; len - 1];
    assert!(retarget::retarget_tbs(
        tbs,
        TbsKind::Certificate,
        SigAlg::MlDsa87,
        SubjectKey::MlDsa87(&pk),
        &mut out
    )
    .is_none());
    assert!(retarget::retarget_len(
        &csr::TBS_TEMPLATE,
        TbsKind::Certificate,
        SigAlg::MlDsa87,
        KeyAlg::MlDsa87
    )
    .is_none());
    assert!(retarget::retarget_len(
        &tbs[..tbs.len() - 1],
        TbsKind::Certificate,
        SigAlg::MlDsa87,
        KeyAlg::MlDsa87
    )
    .is_none());
}
