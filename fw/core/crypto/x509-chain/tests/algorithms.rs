// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(unsafe_code)]

use tsra_crypto::*;
use tsra_fw_core_crypto_x509_chain::*;
use tsra_fw_ddi_tbor_types::CertDescriptor;
use tsra_fw_hsm_pal_traits::*;

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let length = value.len().to_be_bytes();
        let first = length.iter().position(|&b| b != 0).expect("nonzero length");
        out.push(0x80 | (length.len() - first) as u8);
        out.extend_from_slice(&length[first..]);
    }
    out.extend_from_slice(value);
    out
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(value: &str) -> Vec<u8> {
    tlv(
        6,
        der::asn1::ObjectIdentifier::new(value)
            .expect("OID")
            .as_bytes(),
    )
}

fn integer(value: &[u8]) -> Vec<u8> {
    let first = value
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(value.len() - 1);
    let value = &value[first..];
    let mut positive = Vec::new();
    if value[0] & 0x80 != 0 {
        positive.push(0);
    }
    positive.extend_from_slice(value);
    tlv(2, &positive)
}

fn bits(value: &[u8]) -> Vec<u8> {
    tlv(3, &[&[0], value].concat())
}

fn hash_oid(hash: HsmHashAlgo) -> &'static str {
    match hash {
        HsmHashAlgo::Sha256 => "2.16.840.1.101.3.4.2.1",
        HsmHashAlgo::Sha384 => "2.16.840.1.101.3.4.2.2",
        HsmHashAlgo::Sha512 => "2.16.840.1.101.3.4.2.3",
        _ => panic!("test requires SHA-2"),
    }
}

fn crypto_hash(hash: HsmHashAlgo) -> HashAlgo {
    match hash {
        HsmHashAlgo::Sha256 => HashAlgo::sha256(),
        HsmHashAlgo::Sha384 => HashAlgo::sha384(),
        HsmHashAlgo::Sha512 => HashAlgo::sha512(),
        _ => panic!("test requires SHA-2"),
    }
}

fn mldsa_oid(param: HsmMlDsaParamSet) -> &'static str {
    match param {
        HsmMlDsaParamSet::MlDsa44 => "2.16.840.1.101.3.4.3.17",
        HsmMlDsaParamSet::MlDsa65 => "2.16.840.1.101.3.4.3.18",
        HsmMlDsaParamSet::MlDsa87 => "2.16.840.1.101.3.4.3.19",
    }
}

fn pss_params(params: PssParams) -> Vec<u8> {
    let hash = sequence(&[oid(hash_oid(params.hash)), tlv(5, &[])]);
    let mut fields = vec![
        tlv(0xa0, &hash),
        tlv(0xa1, &sequence(&[oid("1.2.840.113549.1.1.8"), hash])),
    ];
    if params.salt_len != 20 {
        fields.push(tlv(0xa2, &integer(&params.salt_len.to_be_bytes())));
    }
    sequence(&fields)
}

fn algorithm(algo: SigAlgo) -> Vec<u8> {
    match algo {
        SigAlgo::EcdsaSha256 => sequence(&[oid("1.2.840.10045.4.3.2")]),
        SigAlgo::EcdsaSha384 => sequence(&[oid("1.2.840.10045.4.3.3")]),
        SigAlgo::EcdsaSha512 => sequence(&[oid("1.2.840.10045.4.3.4")]),
        SigAlgo::RsaPkcs1(hash) => sequence(&[
            oid(match hash {
                HsmHashAlgo::Sha256 => "1.2.840.113549.1.1.11",
                HsmHashAlgo::Sha384 => "1.2.840.113549.1.1.12",
                HsmHashAlgo::Sha512 => "1.2.840.113549.1.1.13",
                _ => panic!("test requires SHA-2"),
            }),
            tlv(5, &[]),
        ]),
        SigAlgo::RsaPss(params) => sequence(&[oid("1.2.840.113549.1.1.10"), pss_params(params)]),
        SigAlgo::MlDsa(param) => sequence(&[oid(mldsa_oid(param))]),
    }
}

fn exported(key: &impl ExportableKey) -> Vec<u8> {
    let mut bytes = vec![0; key.to_bytes(None).expect("export length")];
    key.to_bytes(Some(&mut bytes)).expect("export key");
    bytes
}

enum TestKey {
    Ec(EccPrivateKey),
    Rsa(RsaPrivateKey),
    MlDsa(MlDsaPrivateKey),
}

impl TestKey {
    fn ec() -> Self {
        Self::Ec(EccPrivateKey::generate(48).expect("P-384 key"))
    }

    fn rsa(bytes: usize) -> Self {
        Self::Rsa(RsaPrivateKey::generate(bytes).expect("RSA key"))
    }

    fn mldsa(param: HsmMlDsaParamSet) -> Self {
        let variant = match param {
            HsmMlDsaParamSet::MlDsa44 => MlDsaVariant::MlDsa44,
            HsmMlDsaParamSet::MlDsa65 => MlDsaVariant::MlDsa65,
            HsmMlDsaParamSet::MlDsa87 => MlDsaVariant::MlDsa87,
        };
        Self::MlDsa(MlDsaPrivateKey::from_seed(variant, &[7; 32]).expect("ML-DSA key"))
    }

    fn spki(&self) -> Vec<u8> {
        match self {
            Self::Ec(key) => exported(&key.public_key().expect("EC public key")),
            Self::Rsa(key) => {
                let key = key.public_key().expect("RSA public key");
                let raw = sequence(&[
                    integer(&key.n_vec().expect("modulus")),
                    integer(&key.e_vec().expect("exponent")),
                ]);
                sequence(&[
                    sequence(&[oid("1.2.840.113549.1.1.1"), tlv(5, &[])]),
                    bits(&raw),
                ])
            }
            Self::MlDsa(key) => {
                let param = match key.variant() {
                    MlDsaVariant::MlDsa44 => HsmMlDsaParamSet::MlDsa44,
                    MlDsaVariant::MlDsa65 => HsmMlDsaParamSet::MlDsa65,
                    MlDsaVariant::MlDsa87 => HsmMlDsaParamSet::MlDsa87,
                };
                sequence(&[
                    sequence(&[oid(mldsa_oid(param))]),
                    bits(&exported(&key.public_key().expect("ML-DSA public key"))),
                ])
            }
        }
    }

    fn sign(&self, algo: SigAlgo, tbs: &[u8]) -> Vec<u8> {
        match (self, algo) {
            (Self::Ec(key), SigAlgo::EcdsaSha256 | SigAlgo::EcdsaSha384 | SigAlgo::EcdsaSha512) => {
                let mut algorithm =
                    EcdsaAlgo::new(crypto_hash(algo.hash_algo().expect("ECDSA hash")));
                let len = Signer::sign(&mut algorithm, key, tbs, None).expect("ECDSA length");
                let mut raw = vec![0; len];
                Signer::sign(&mut algorithm, key, tbs, Some(&mut raw)).expect("ECDSA signature");
                sequence(&[integer(&raw[..len / 2]), integer(&raw[len / 2..])])
            }
            (Self::Rsa(key), SigAlgo::RsaPkcs1(hash) | SigAlgo::RsaPss(PssParams { hash, .. })) => {
                let mut hash = crypto_hash(hash);
                let digest = Hasher::hash_vec(&mut hash, tbs).expect("digest");
                let mut algorithm = match algo {
                    SigAlgo::RsaPss(params) => {
                        RsaSignAlgo::with_pss_padding(hash, usize::from(params.salt_len))
                    }
                    _ => RsaSignAlgo::with_pkcs1_padding(hash),
                };
                let len = Signer::sign(&mut algorithm, key, &digest, None).expect("RSA length");
                let mut signature = vec![0; len];
                Signer::sign(&mut algorithm, key, &digest, Some(&mut signature))
                    .expect("RSA signature");
                signature
            }
            (Self::MlDsa(key), SigAlgo::MlDsa(_)) => {
                let mut algorithm = MlDsaAlgo::new(&[]).expect("empty context").deterministic();
                let len = Signer::sign(&mut algorithm, key, tbs, None).expect("ML-DSA length");
                let mut signature = vec![0; len];
                Signer::sign(&mut algorithm, key, tbs, Some(&mut signature))
                    .expect("ML-DSA signature");
                signature
            }
            _ => panic!("signing key / algorithm mismatch"),
        }
    }
}

fn name(value: &[u8]) -> Vec<u8> {
    sequence(&[tlv(0x31, &sequence(&[oid("2.5.4.3"), tlv(0x0c, value)]))])
}

fn certificate(
    subject: &[u8],
    issuer: &[u8],
    spki: Vec<u8>,
    signer: &TestKey,
    algo: SigAlgo,
    ca: bool,
) -> Vec<u8> {
    certificate_with_key_usage(
        subject,
        issuer,
        spki,
        signer,
        algo,
        ca,
        &[tlv(3, &[if ca { 2 } else { 7 }, if ca { 4 } else { 0x80 }])],
    )
}

fn certificate_with_key_usage(
    subject: &[u8],
    issuer: &[u8],
    spki: Vec<u8>,
    signer: &TestKey,
    algo: SigAlgo,
    ca: bool,
    usages: &[Vec<u8>],
) -> Vec<u8> {
    let constraints = sequence(&[
        oid("2.5.29.19"),
        tlv(1, &[0xff]),
        tlv(
            4,
            &sequence(&if ca { vec![tlv(1, &[0xff])] } else { vec![] }),
        ),
    ]);
    let skid = sequence(&[oid("2.5.29.14"), tlv(4, &tlv(4, subject))]);
    let akid = sequence(&[oid("2.5.29.35"), tlv(4, &sequence(&[tlv(0x80, issuer)]))]);
    let mut extensions = vec![constraints, skid, akid];
    extensions.extend(
        usages
            .iter()
            .map(|value| sequence(&[oid("2.5.29.15"), tlv(1, &[0xff]), tlv(4, value)])),
    );
    let tbs = sequence(&[
        tlv(0xa0, &integer(&[2])),
        integer(&[1]),
        algorithm(algo),
        name(issuer),
        sequence(&[tlv(0x17, b"250101000000Z"), tlv(0x17, b"350101000000Z")]),
        name(subject),
        spki,
        tlv(0xa3, &sequence(&extensions)),
    ]);
    sequence(&[tbs.clone(), algorithm(algo), bits(&signer.sign(algo, &tbs))])
}

fn dma(bytes: &[u8]) -> &HsmDmaBuf {
    // SAFETY: the standard PAL operates on host memory without physical DMA.
    unsafe { HsmDmaBuf::from_raw(bytes) }
}

async fn walk<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    certs: &[Vec<u8>],
    anchor: Option<&[u8]>,
    issuing: bool,
) -> HsmResult<()> {
    let descriptors: Vec<_> = certs
        .iter()
        .enumerate()
        .map(|(i, cert)| CertDescriptor {
            index: i.try_into().expect("test index"),
            length: u16::try_from(cert.len())
                .expect("test certificate length")
                .into(),
        })
        .collect();
    let expected = parse_cert(dma(certs.last().expect("test chain")))?
        .pub_key
        .as_bytes()
        .to_vec();
    let mut leaf = vec![0xa5; expected.len()];
    let max_pair_len = certs
        .windows(2)
        .map(|pair| pair[0].len() + pair[1].len())
        .max()
        .unwrap_or(certs[0].len());
    let result = pal
        .alloc_scoped_async(io, async |scope| {
            let mut previous_range: Option<core::ops::Range<usize>> = None;
            let fetch = async |index: usize, out: &mut HsmDmaBuf| {
                let range = out.as_ptr() as usize..out.as_ptr() as usize + out.len();
                assert_eq!(range.start % 4, 0, "unaligned DMA receive view");
                if let Some(previous) = &previous_range {
                    assert!(
                        range.end <= previous.start || previous.end <= range.start,
                        "receiving a certificate would overwrite its issuer DER"
                    );
                    assert!(
                        range.end.max(previous.end) - range.start.min(previous.start)
                            <= max_pair_len + 6,
                        "DER receive storage exceeds the largest adjacent pair and alignment"
                    );
                }
                previous_range = Some(range);
                out.copy_from_slice(&certs[index]);
                Ok(())
            };
            if issuing {
                validate_issuing_chain(pal, io, scope, &descriptors, anchor, &mut leaf, fetch).await
            } else {
                validate_chain(pal, io, scope, &descriptors, anchor, &mut leaf, fetch).await
            }
        })
        .await;
    if result.is_ok() {
        assert_eq!(leaf, expected);
    } else {
        assert!(
            leaf.iter().all(|&b| b == 0xa5),
            "failure published a leaf key"
        );
    }
    result
}

async fn zero_copy_cases<P: HsmPal>(pal: &P, io: &P::Io) {
    let key = TestKey::ec();
    let root_name = vec![b'a'; 1200];
    let leaf_name = vec![b'b'; 2000];
    let mut certs = Vec::new();
    for (subject, issuer, ca) in [
        (root_name.as_slice(), root_name.as_slice(), true),
        (b"one".as_slice(), root_name.as_slice(), true),
        (b"two".as_slice(), b"one".as_slice(), true),
        (leaf_name.as_slice(), b"two".as_slice(), false),
    ] {
        certs.push(certificate(
            subject,
            issuer,
            key.spki(),
            &key,
            SigAlgo::EcdsaSha384,
            ca,
        ));
    }
    walk(pal, io, &certs, None, false)
        .await
        .expect("zero-copy chain with nonadjacent large certificates");
}

async fn rsa_cases<P: HsmPal>(pal: &P, io: &P::Io) {
    let leaf = TestKey::ec();
    for k in [256, 384, 512] {
        let root = TestKey::rsa(k);
        for hash in [
            HsmHashAlgo::Sha256,
            HsmHashAlgo::Sha384,
            HsmHashAlgo::Sha512,
        ] {
            for algo in [
                SigAlgo::RsaPkcs1(hash),
                SigAlgo::RsaPss(PssParams {
                    hash,
                    salt_len: hash.digest_len() as u16,
                }),
                SigAlgo::RsaPss(PssParams { hash, salt_len: 0 }),
                SigAlgo::RsaPss(PssParams {
                    hash,
                    salt_len: (k - hash.digest_len() - 2) as u16,
                }),
            ] {
                let root_cert = certificate(b"root", b"root", root.spki(), &root, algo, true);
                let leaf_cert = certificate(b"leaf", b"root", leaf.spki(), &root, algo, false);
                walk(pal, io, &[root_cert, leaf_cert], None, false)
                    .await
                    .expect("RSA -> EC chain");
            }
        }
        let algo = SigAlgo::RsaPss(PssParams {
            hash: HsmHashAlgo::Sha384,
            salt_len: 20,
        });
        let root_cert = certificate(b"root", b"root", root.spki(), &root, algo, true);
        walk(pal, io, &[root_cert], None, false)
            .await
            .expect("RSA leaf and default salt");
    }
}

async fn mldsa_cases<P: HsmPal>(pal: &P, io: &P::Io) {
    let ec = TestKey::ec();
    for param in [
        HsmMlDsaParamSet::MlDsa44,
        HsmMlDsaParamSet::MlDsa65,
        HsmMlDsaParamSet::MlDsa87,
    ] {
        let root = TestKey::mldsa(param);
        let algo = SigAlgo::MlDsa(param);
        let root_cert = certificate(b"root", b"root", root.spki(), &root, algo, true);
        assert!(root_cert.len() > 2048);
        let ca_cert = certificate(b"ca", b"root", ec.spki(), &root, algo, true);
        let leaf_cert = certificate(
            b"leaf",
            b"ca",
            root.spki(),
            &ec,
            SigAlgo::EcdsaSha384,
            false,
        );
        let anchor = parse_cert(dma(&ca_cert))
            .expect("parse CA")
            .pub_key
            .as_bytes()
            .to_vec();
        let certs = vec![root_cert, ca_cert, leaf_cert];
        walk(pal, io, &certs, Some(&anchor), false)
            .await
            .expect("mixed ML-DSA / EC chain");
        assert_eq!(
            walk(pal, io, &certs, Some(&[0; 96]), false).await,
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            walk(pal, io, &certs, None, true).await,
            Err(HsmError::X509NotCa)
        );
        let mut tampered = certs.clone();
        *tampered[0].last_mut().expect("signature byte") ^= 1;
        assert_eq!(
            walk(pal, io, &tampered, None, false).await,
            Err(HsmError::X509SignatureInvalid)
        );
    }
}

fn usage_bits(usage: u16) -> Vec<u8> {
    if usage == 0 {
        return tlv(3, &[0]);
    }
    let bytes = usage.to_be_bytes();
    let len = if bytes[1] == 0 { 1 } else { 2 };
    tlv(
        3,
        &[&[(usage.trailing_zeros() % 8) as u8], &bytes[..len]].concat(),
    )
}

async fn mldsa_key_usage_cases<P: HsmPal>(pal: &P, io: &P::Io) {
    let ec = TestKey::ec();
    let ec_algo = SigAlgo::EcdsaSha384;
    let ec_root = certificate(b"root", b"root", ec.spki(), &ec, ec_algo, true);
    for param in [
        HsmMlDsaParamSet::MlDsa44,
        HsmMlDsaParamSet::MlDsa65,
        HsmMlDsaParamSet::MlDsa87,
    ] {
        let ml = TestKey::mldsa(param);
        let ml_algo = SigAlgo::MlDsa(param);
        let leaf = |ca, usages: &[Vec<u8>]| {
            certificate_with_key_usage(b"leaf", b"root", ml.spki(), &ec, ec_algo, ca, usages)
        };
        for usage in [0x8000, 0x4000, 0x0200, 0x0400, 0xc600] {
            let ca = usage & key_usage::KEY_CERT_SIGN != 0;
            walk(
                pal,
                io,
                &[ec_root.clone(), leaf(ca, &[usage_bits(usage)])],
                None,
                ca,
            )
            .await
            .expect("permitted ML-DSA KeyUsage");
        }
        walk(pal, io, &[ec_root.clone(), leaf(false, &[])], None, false)
            .await
            .expect("optional ML-DSA KeyUsage");
        assert_eq!(
            walk(
                pal,
                io,
                &[ec_root.clone(), leaf(false, &[usage_bits(0)])],
                None,
                false
            )
            .await,
            Err(HsmError::X509KeyUsageInvalid)
        );
        for forbidden in [0x2000, 0x1000, 0x0800, 0x0100, 0x0080] {
            let invalid_leaf = leaf(false, &[usage_bits(0x8000 | forbidden)]);
            assert_eq!(
                walk(pal, io, &[ec_root.clone(), invalid_leaf], None, false).await,
                Err(HsmError::X509KeyUsageInvalid),
                "ML-DSA leaf accepted forbidden usage {forbidden:#06x}"
            );
            let invalid_ca = certificate_with_key_usage(
                b"root",
                b"root",
                ml.spki(),
                &ml,
                ml_algo,
                true,
                &[usage_bits(0x0400 | forbidden)],
            );
            assert_eq!(
                walk(pal, io, &[invalid_ca], None, true).await,
                Err(HsmError::X509KeyUsageInvalid),
                "ML-DSA CA accepted forbidden usage {forbidden:#06x}"
            );
        }
        for usages in [
            vec![tlv(5, &[])],
            vec![tlv(3, &[])],
            vec![bits(&[0x80, 0, 0x80])],
            vec![usage_bits(0x8000), usage_bits(0x8000)],
        ] {
            assert_eq!(
                walk(
                    pal,
                    io,
                    &[ec_root.clone(), leaf(false, &usages)],
                    None,
                    false
                )
                .await,
                Err(HsmError::X509ParseError)
            );
        }
        let ml_root = certificate(b"root", b"root", ml.spki(), &ml, ml_algo, true);
        let ec_leaf = certificate_with_key_usage(
            b"leaf",
            b"root",
            ec.spki(),
            &ml,
            ml_algo,
            false,
            &[usage_bits(0x8800)],
        );
        walk(pal, io, &[ml_root, ec_leaf], None, false)
            .await
            .expect("EC subject usage must not inherit ML-DSA issuer restrictions");
    }
}

async fn ecdsa_cases<P: HsmPal>(pal: &P, io: &P::Io) {
    let leaf = TestKey::ec();
    for size in [32, 48, 66] {
        let root = TestKey::Ec(EccPrivateKey::generate(size).expect("EC key"));
        for algo in [
            SigAlgo::EcdsaSha256,
            SigAlgo::EcdsaSha384,
            SigAlgo::EcdsaSha512,
        ] {
            let root_cert = certificate(b"root", b"root", root.spki(), &root, algo, true);
            let mut leaf_cert = certificate(b"leaf", b"root", leaf.spki(), &root, algo, false);
            walk(
                pal,
                io,
                &[root_cert.clone(), leaf_cert.clone()],
                None,
                false,
            )
            .await
            .expect("ECDSA curve/hash combination");
            *leaf_cert.last_mut().expect("signature byte") ^= 1;
            assert_eq!(
                walk(pal, io, &[root_cert, leaf_cert], None, false).await,
                Err(HsmError::X509SignatureInvalid)
            );
        }
    }
}

async fn profile_key_usage_cases<P: HsmPal>(pal: &P, io: &P::Io, pss: bool) {
    let (key, algo) = if pss {
        (
            TestKey::rsa(256),
            SigAlgo::RsaPss(PssParams {
                hash: HsmHashAlgo::Sha256,
                salt_len: 32,
            }),
        )
    } else {
        (TestKey::ec(), SigAlgo::EcdsaSha384)
    };
    let spki = if pss {
        let cert = certificate(b"root", b"root", key.spki(), &key, algo, true);
        let parsed = parse_cert(dma(&cert)).expect("RSA certificate");
        let PubKey::Rsa(public) = parsed.pub_key else {
            panic!("RSA key")
        };
        sequence(&[
            sequence(&[oid("1.2.840.113549.1.1.10")]),
            bits(public.encoded),
        ])
    } else {
        key.spki()
    };
    let root = certificate(b"root", b"root", spki.clone(), &key, algo, true);
    let leaf = |ca, usages: &[Vec<u8>]| {
        certificate_with_key_usage(b"leaf", b"root", spki.clone(), &key, algo, ca, usages)
    };
    for usage in [0x8000, 0x4000, 0xc000, 0x0400, 0x0600, 0xc600] {
        let ca = usage & (key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN) != 0;
        walk(
            pal,
            io,
            &[root.clone(), leaf(ca, &[usage_bits(usage)])],
            None,
            ca,
        )
        .await
        .expect("permitted EC/RSA-PSS subject KeyUsage");
    }
    walk(pal, io, &[root.clone(), leaf(false, &[])], None, false)
        .await
        .expect("optional EC/RSA-PSS KeyUsage");
    for usage in [0, 0x8100, 0x8080, 0x0400, 0x0200, 0xa000, 0x9000] {
        assert_eq!(
            walk(
                pal,
                io,
                &[root.clone(), leaf(false, &[usage_bits(usage)])],
                None,
                false
            )
            .await,
            Err(HsmError::X509KeyUsageInvalid)
        );
    }
    for usage in [0x2400, 0x1400, 0x0500, 0x0480] {
        assert_eq!(
            walk(
                pal,
                io,
                &[root.clone(), leaf(true, &[usage_bits(usage)])],
                None,
                true
            )
            .await,
            Err(HsmError::X509KeyUsageInvalid)
        );
    }
    for usage in [0x0800, 0x0900, 0x0880, 0x8800] {
        let result = walk(
            pal,
            io,
            &[root.clone(), leaf(false, &[usage_bits(usage)])],
            None,
            false,
        )
        .await;
        if pss {
            assert_eq!(result, Err(HsmError::X509KeyUsageInvalid));
        } else {
            result.expect("permitted EC key agreement usage");
        }
    }
    if pss {
        for usage in [0x2000, 0x1000] {
            let unrestricted = certificate_with_key_usage(
                b"leaf",
                b"root",
                key.spki(),
                &key,
                algo,
                false,
                &[usage_bits(usage)],
            );
            walk(pal, io, &[root.clone(), unrestricted], None, false)
                .await
                .expect("rsaEncryption subject must retain encryption usages");
        }
    }
}

async fn rejection_cases<P: HsmPal>(pal: &P, io: &P::Io) {
    let root = TestKey::rsa(256);
    let ec = TestKey::ec();
    let algo = SigAlgo::RsaPkcs1(HsmHashAlgo::Sha256);
    let root_cert = certificate(b"root", b"root", root.spki(), &root, algo, true);
    let leaf = certificate(b"leaf", b"root", ec.spki(), &root, algo, false);
    let mut bad = leaf.clone();
    *bad.last_mut().expect("signature byte") ^= 1;
    assert_eq!(
        walk(pal, io, &[root_cert.clone(), bad], None, false).await,
        Err(HsmError::X509SignatureInvalid)
    );
    let wrong_issuer = certificate(b"leaf", b"other", ec.spki(), &root, algo, false);
    assert_eq!(
        walk(pal, io, &[root_cert.clone(), wrong_issuer], None, false).await,
        Err(HsmError::X509IssuerMismatch)
    );
    let not_ca = certificate(b"root", b"root", root.spki(), &root, algo, false);
    assert_eq!(
        walk(pal, io, &[not_ca, leaf.clone()], None, false).await,
        Err(HsmError::X509NotCa)
    );
    let mismatch = certificate(b"bad", b"bad", ec.spki(), &root, algo, false);
    assert_eq!(
        walk(pal, io, &[mismatch], None, false).await,
        Err(HsmError::X509UnsupportedAlgorithm)
    );

    let mut mismatch = root_cert;
    let sha256 = oid("1.2.840.113549.1.1.11");
    let at = mismatch
        .windows(sha256.len())
        .position(|v| v == sha256)
        .expect("TBS algorithm");
    mismatch[at + sha256.len() - 1] = 12;
    assert_eq!(
        parse_cert(dma(&mismatch)).err(),
        Some(HsmError::X509ParseError)
    );

    let param = HsmMlDsaParamSet::MlDsa44;
    let ml = TestKey::mldsa(param);
    let raw = exported(&match &ml {
        TestKey::MlDsa(key) => key.public_key().expect("key"),
        _ => unreachable!(),
    });
    for spki in [
        sequence(&[sequence(&[oid(mldsa_oid(param)), tlv(5, &[])]), bits(&raw)]),
        sequence(&[
            sequence(&[oid(mldsa_oid(param))]),
            bits(&raw[..raw.len() - 1]),
        ]),
    ] {
        let cert = certificate(b"bad", b"bad", spki, &ml, SigAlgo::MlDsa(param), false);
        assert!(
            parse_cert(dma(&cert)).is_err(),
            "invalid ML-DSA SPKI accepted"
        );
    }

    let params = PssParams {
        hash: HsmHashAlgo::Sha384,
        salt_len: 48,
    };
    let mut pss = certificate(
        b"root",
        b"root",
        root.spki(),
        &root,
        SigAlgo::RsaPss(params),
        true,
    );
    let parsed = parse_cert(dma(&pss)).expect("PSS certificate");
    let raw = match parsed.pub_key {
        PubKey::Rsa(key) => key.encoded.to_vec(),
        _ => panic!("RSA key"),
    };
    for restrictions in [None, Some(params)] {
        let mut key_algorithm = vec![oid("1.2.840.113549.1.1.10")];
        if let Some(params) = restrictions {
            key_algorithm.push(pss_params(params));
        }
        let spki = sequence(&[sequence(&key_algorithm), bits(&raw)]);
        let restricted = certificate(b"root", b"root", spki, &root, SigAlgo::RsaPss(params), true);
        assert_eq!(
            walk(pal, io, &[restricted.clone(), leaf.clone()], None, false).await,
            Err(HsmError::X509UnsupportedAlgorithm),
            "PSS-only key accepted PKCS#1"
        );
        for (hash, salt_len) in [
            (HsmHashAlgo::Sha384, 64),
            (HsmHashAlgo::Sha384, 32),
            (HsmHashAlgo::Sha256, 32),
        ] {
            let algorithm = SigAlgo::RsaPss(PssParams { hash, salt_len });
            let leaf = certificate(b"leaf", b"root", ec.spki(), &root, algorithm, false);
            let result = walk(pal, io, &[restricted.clone(), leaf], None, false).await;
            if restrictions.is_none() || (hash == params.hash && salt_len >= params.salt_len) {
                result.expect("permitted PSS signature");
            } else {
                assert_eq!(result, Err(HsmError::X509UnsupportedAlgorithm));
            }
        }
    }

    let hash_id = sequence(&[oid(hash_oid(params.hash)), tlv(5, &[])]);
    for trailer in [2u16, 256, 257, u16::MAX] {
        let algorithm = sequence(&[
            oid("1.2.840.113549.1.1.10"),
            sequence(&[
                tlv(0xa0, &hash_id),
                tlv(
                    0xa1,
                    &sequence(&[oid("1.2.840.113549.1.1.8"), hash_id.clone()]),
                ),
                tlv(0xa2, &integer(&params.salt_len.to_be_bytes())),
                tlv(0xa3, &integer(&trailer.to_be_bytes())),
            ]),
        ]);
        let certificate = sequence(&[parsed.tbs_raw.to_vec(), algorithm, bits(parsed.signature)]);
        assert_eq!(
            parse_cert(dma(&certificate)).err(),
            Some(if trailer > u16::from(u8::MAX) {
                HsmError::X509ParseError
            } else {
                HsmError::X509UnsupportedAlgorithm
            }),
            "invalid PSS trailer"
        );
    }
    for (trailing_hash, trailing_mgf) in [(true, false), (false, true)] {
        let mut hash_field = hash_id.clone();
        let mut mgf_field = sequence(&[oid("1.2.840.113549.1.1.8"), hash_id.clone()]);
        if trailing_hash {
            hash_field.extend([5, 0]);
        }
        if trailing_mgf {
            mgf_field.extend([5, 0]);
        }
        let algorithm = sequence(&[
            oid("1.2.840.113549.1.1.10"),
            sequence(&[
                tlv(0xa0, &hash_field),
                tlv(0xa1, &mgf_field),
                tlv(0xa2, &integer(&params.salt_len.to_be_bytes())),
            ]),
        ]);
        let certificate = sequence(&[parsed.tbs_raw.to_vec(), algorithm, bits(parsed.signature)]);
        assert_eq!(
            parse_cert(dma(&certificate)).err(),
            Some(HsmError::X509ParseError),
            "trailing bytes in PSS wrapper"
        );
    }
    let duplicate = sequence(&[
        oid("1.2.840.113549.1.1.10"),
        sequence(&[
            tlv(0xa0, &hash_id),
            tlv(
                0xa1,
                &sequence(&[oid("1.2.840.113549.1.1.8"), hash_id.clone()]),
            ),
            tlv(0xa2, &integer(&[48])),
            tlv(0xa0, &hash_id),
        ]),
    ]);
    let duplicate = sequence(&[parsed.tbs_raw.to_vec(), duplicate, bits(parsed.signature)]);
    assert_eq!(
        parse_cert(dma(&duplicate)).err(),
        Some(HsmError::X509ParseError)
    );

    let mut unaligned_bits = pss.clone();
    let signature_offset = parsed.signature.as_ptr() as usize - pss.as_ptr() as usize;
    unaligned_bits[signature_offset - 1] = 1;
    *unaligned_bits.last_mut().expect("signature byte") &= 0xfe;
    assert_eq!(
        parse_cert(dma(&unaligned_bits)).err(),
        Some(HsmError::X509ParseError)
    );

    let sha384 = oid(hash_oid(params.hash));
    let at = pss
        .windows(sha384.len())
        .position(|v| v == sha384)
        .expect("PSS hash");
    pss[at + sha384.len() - 1] = 1;
    assert_eq!(
        parse_cert(dma(&pss)).err(),
        Some(HsmError::X509UnsupportedAlgorithm)
    );

    let descriptors = [CertDescriptor {
        index: 0,
        length: ((MAX_CERT_DER_LEN + 1) as u16).into(),
    }];
    pal.alloc_scoped_async(io, async |scope| {
        let mut leaf = [0; 96];
        assert_eq!(
            validate_chain(
                pal,
                io,
                scope,
                &descriptors,
                None,
                &mut leaf,
                async |_, _| panic!("oversized certificate was fetched")
            )
            .await,
            Err(HsmError::InvalidArg)
        );
    })
    .await;
}

macro_rules! platform_tests {
    ($name:ident, $platform:ident) => {
        mod $name {
            use $platform as platform;

            use super::*;

            async fn run(case: u8) {
                let (tx, rx) = async_channel::bounded(1);
                let pal = platform::StdHsmPal::new(rx, tokio::runtime::Handle::current());
                pal.part_alloc_internal(0, 1)
                    .await
                    .expect("allocate partition");
                pal.part_enable_internal(0).await.expect("enable partition");
                let (reply, _) = tokio::sync::oneshot::channel();
                tx.send(platform::HsmIoRequest::cmd(
                    platform::HsmPartId::from(0u8),
                    0,
                    0,
                    Default::default(),
                    reply,
                ))
                .await
                .expect("submit IO");
                let io = pal.poll_io().await.expect("poll IO");
                // Reserve representative request/undo space before walking.
                pal.dma_alloc(&io, 2048).expect("request space").fill(0);
                match case {
                    0 => rsa_cases(&pal, &io).await,
                    1 => mldsa_cases(&pal, &io).await,
                    3 => mldsa_key_usage_cases(&pal, &io).await,
                    4 => ecdsa_cases(&pal, &io).await,
                    5 => profile_key_usage_cases(&pal, &io, false).await,
                    6 => profile_key_usage_cases(&pal, &io, true).await,
                    8 => zero_copy_cases(&pal, &io).await,
                    _ => rejection_cases(&pal, &io).await,
                }
                pal.drop_io(io).await.expect("drop IO");
            }

            fn check(case: u8) {
                std::thread::Builder::new()
                    .stack_size(8 * 1024 * 1024)
                    .spawn(move || {
                        tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("runtime")
                            .block_on(run(case));
                    })
                    .expect("thread")
                    .join()
                    .expect("certificate checks");
            }

            #[test]
            fn rsa_chains() {
                check(0);
            }
            #[test]
            fn mldsa_and_mixed_chains() {
                check(1);
            }
            #[test]
            fn malformed_and_invalid_chains() {
                check(2);
            }
            #[test]
            fn mldsa_key_usage() {
                check(3);
            }
            #[test]
            fn ecdsa_curve_hash_combinations() {
                check(4);
            }
            #[test]
            fn ecc_key_usage() {
                check(5);
            }
            #[test]
            fn rsa_pss_key_usage() {
                check(6);
            }
            #[test]
            fn zero_copy_varied_certificate_sizes() {
                check(8);
            }
        }
    };
}

platform_tests!(uno, tsra_fw_hsm_pal_std_uno);
platform_tests!(duo, tsra_fw_hsm_pal_std_duo);
