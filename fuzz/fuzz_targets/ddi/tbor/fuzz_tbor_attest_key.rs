// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::EccCurve;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_crypto::AesKey;
use tsra_crypto::AesKeyWrapPadAlgo;
use tsra_crypto::Encrypter;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::RsaEncryptAlgo;
use tsra_crypto::RsaKeyOp;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaPublicKey;
use tsra_ddi_interface::DdiError;
use tsra_ddi_mbor_test_helpers::CoseSign1Object;
use tsra_ddi_mbor_test_helpers::KeyAttestationReport;
use tsra_ddi_mbor_test_helpers::encode_sig_struct;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_types::*;
use x509::X509Certificate;
use x509::X509CertificateOp;

/// Key types generated as masked blobs for the TBOR `KeyReport` request.
#[derive(Arbitrary, Debug)]
enum KeySource {
    EccGenerated(EccCurve),
    BuiltInUnwrappingKey,
    ImportedRsaKey,
    GeneratedAesKey(common::AesKeySize),
    HmacKey(HmacHash),
    GeneratedSecretKey(EccCurve),
}

#[derive(Arbitrary, Debug)]
enum HmacHash {
    Sha256,
    Sha384,
    Sha512,
}

impl HmacHash {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::Sha256 => HMAC_HASH_SHA256,
            Self::Sha384 => HMAC_HASH_SHA384,
            Self::Sha512 => HMAC_HASH_SHA512,
        }
    }

    fn valid_key_length(&self, fuzzed_length: u8) -> u8 {
        let (min, max) = match self {
            Self::Sha256 => (32, 64),
            Self::Sha384 => (48, 128),
            Self::Sha512 => (64, 128),
        };
        min + (fuzzed_length % (max - min + 1))
    }
}

/// Persisted key scopes whose masking keys `PartFinal` provisions, and
/// therefore the only scopes `KeyReport` can resolve.
#[derive(Arbitrary, Debug)]
enum MaskingScope {
    Ephemeral,
    Local,
}

impl MaskingScope {
    fn to_tbor(&self) -> u8 {
        match self {
            Self::Ephemeral => common::KEY_SCOPE_EPHEMERAL,
            Self::Local => common::KEY_SCOPE_LOCAL,
        }
    }
}

/// Fuzz input for TBOR `KeyReport` (the TBOR equivalent of MBOR `AttestKey`).
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Generate a supported TBOR key and use its masked blob.
    use_generated_key: bool,
    /// Selects the key generator used when `use_generated_key` is true.
    key_source: KeySource,
    /// Masking scope used for generated keys.
    scope: MaskingScope,
    /// Used as-is when generating is disabled; used to choose a valid
    /// HMAC key length when `key_source` selects HMAC.
    fuzzed_key_data: FuzzKeyReportData,
}

#[derive(Arbitrary, Debug)]
struct FuzzKeyReportData {
    masked_key: Vec<u8>,
    report_data: [u8; KEY_REPORT_DATA_LEN],
    hmac_key_length: u8,
}

const RSA_OAEP_SHA256: u8 = 1;

/// Outcome the firmware must produce for the masked key being attested.
enum Expected {
    /// Attestable ECC private key; carries the wire-LE `x ‖ y` public key
    /// and the curve's raw coordinate length.
    Report { pub_key: Vec<u8>, coord_len: usize },
    /// Attestable RSA private key; carries the host's big-endian public components.
    RsaReport { n: Vec<u8>, e: Vec<u8> },
    /// Valid masked key of a non-attestable kind.
    UnsupportedKeyType,
    /// Not a valid masked blob (raw fuzz bytes or a public key).
    Rejected,
}

fn generate_masked_key(ctx: &TestCtx, session_id: u16, input: &FuzzInput) -> (Vec<u8>, Expected) {
    let scope = input.scope.to_tbor();
    match &input.key_source {
        KeySource::EccGenerated(curve) => {
            let resp = ctx
                .tbor(&TborEccGenerateKeyReq {
                    session_id,
                    scope,
                    curve: curve.to_tbor(),
                    key_usage: KEY_USAGE_SIGN,
                    key_label: Vec::new(),
                })
                .expect("ECC key generation should succeed");
            let expected = Expected::Report {
                pub_key: resp.pub_key.to_vec(),
                coord_len: curve.coord_len(),
            };
            (resp.masked_key, expected)
        }
        KeySource::BuiltInUnwrappingKey => {
            let pub_key = ctx
                .tbor(&TborGetUnwrappingKeyReq { session_id })
                .expect("get built-in unwrapping public key")
                .pub_key
                .to_vec();
            (pub_key, Expected::Rejected)
        }
        KeySource::ImportedRsaKey => import_rsa_key(ctx, session_id, scope),
        KeySource::GeneratedAesKey(key_size) => {
            let masked_key = ctx
                .tbor(&TborAesGenerateKeyReq {
                    session_id,
                    scope,
                    key_size: key_size.to_tbor(),
                    key_usage: KEY_USAGE_ENCRYPT | KEY_USAGE_DECRYPT,
                    key_label: Vec::new(),
                })
                .expect("AES key generation should succeed")
                .masked_key;
            (masked_key, Expected::UnsupportedKeyType)
        }
        KeySource::HmacKey(hash) => {
            let masked_key = ctx
                .tbor(&TborHmacGenerateKeyReq {
                    session_id,
                    scope,
                    hash_algo: hash.to_tbor(),
                    key_length: hash.valid_key_length(input.fuzzed_key_data.hmac_key_length),
                    key_label: Vec::new(),
                })
                .expect("HMAC key generation should succeed")
                .masked_key;
            (masked_key, Expected::UnsupportedKeyType)
        }
        KeySource::GeneratedSecretKey(curve) => {
            let gen_derive_key = || {
                ctx.tbor(&TborEccGenerateKeyReq {
                    session_id,
                    scope,
                    curve: curve.to_tbor(),
                    key_usage: KEY_USAGE_DERIVE,
                    key_label: Vec::new(),
                })
                .expect("ECDH key generation should succeed")
            };
            let private_key = gen_derive_key();
            let peer_key = gen_derive_key();
            let masked_secret = ctx
                .tbor(&TborEcdhDeriveReq {
                    session_id,
                    scope,
                    masked_key: private_key.masked_key,
                    peer_pub_key: peer_key.pub_key,
                    key_label: Vec::new(),
                })
                .expect("ECDH secret derivation should succeed")
                .masked_secret;
            (masked_secret, Expected::UnsupportedKeyType)
        }
    }
}

fn import_rsa_key(ctx: &TestCtx, session_id: u16, scope: u8) -> (Vec<u8>, Expected) {
    let key = RsaPrivateKey::generate(256).expect("generate host RSA-2048 key");
    let expected = Expected::RsaReport {
        n: key.n_vec().expect("host RSA modulus"),
        e: key.e_vec().expect("host RSA exponent"),
    };
    let private_der = key.to_vec().expect("export host RSA private key");
    let unwrapping_key = ctx
        .tbor(&TborGetUnwrappingKeyReq { session_id })
        .expect("get built-in unwrapping public key")
        .pub_key;

    // Convert HSM little-endian (n ‖ e) to the crypto crate's big-endian form.
    let mut public_key_be = Vec::with_capacity(unwrapping_key.len());
    public_key_be.extend(unwrapping_key[..256].iter().rev());
    public_key_be.extend(unwrapping_key[256..].iter().rev());
    let public_key =
        RsaPublicKey::from_hsm_bytes(&public_key_be).expect("parse unwrapping public key");

    let kek = [0xA7; 32];
    let mut encrypted_kek = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &public_key,
        &kek,
    )
    .expect("RSA-OAEP wrap AES key");
    encrypted_kek.reverse();

    let kek = AesKey::from_bytes(&kek).expect("construct AES key-encryption key");
    let encrypted_private_key =
        Encrypter::encrypt_vec(&mut AesKeyWrapPadAlgo::default(), &kek, &private_der)
            .expect("AES-KWP wrap RSA private key");
    let mut wrapped_blob = encrypted_kek;
    wrapped_blob.extend(encrypted_private_key);

    let masked_key = ctx
        .tbor(&TborUnwrapKeyReq {
            session_id,
            scope,
            key_class: KEY_CLASS_RSA,
            key_usage: KEY_USAGE_SIGN | KEY_USAGE_VERIFY,
            oaep_hash_algo: RSA_OAEP_SHA256,
            wrapped_blob,
            key_label: Vec::new(),
        })
        .expect("import host RSA key through UnwrapKey")
        .masked_key;
    (masked_key, expected)
}

/// Walk a COSE_Key CBOR map and return its `(x, y)` byte strings
/// (labels -2 / -3). Mirrors the integration-suite helper in
/// `ddi/tbor/types/tests/commands/key_report.rs`.
fn cose_key_xy(cose_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use minicbor::data::Type as CborType;

    let mut decoder = minicbor::Decoder::new(cose_key);
    let entries = decoder
        .map()
        .expect("COSE_Key is a CBOR map")
        .expect("COSE_Key map length is known");
    let (mut x_bytes, mut y_bytes): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
    for _ in 0..entries {
        let label_ty = decoder.datatype().expect("COSE_Key entry has datatype");
        let label = match label_ty {
            CborType::I8 | CborType::I16 | CborType::I32 | CborType::I64 => {
                decoder.i64().expect("COSE_Key label decodes as int")
            }
            CborType::U8 | CborType::U16 | CborType::U32 | CborType::U64 => {
                decoder.u64().expect("COSE_Key label decodes as uint") as i64
            }
            other => panic!("unexpected COSE_Key label type {other:?}"),
        };
        match label {
            -2 => x_bytes = Some(decoder.bytes().expect("pk_x bytes").to_vec()),
            -3 => y_bytes = Some(decoder.bytes().expect("pk_y bytes").to_vec()),
            _ => decoder.skip().expect("skip non-XY label value"),
        }
    }
    (
        x_bytes.expect("COSE_Key carries pk_x (label -2)"),
        y_bytes.expect("COSE_Key carries pk_y (label -3)"),
    )
}

/// Verify the PID signature and report data before checking the attested key.
fn verify_signed_report(
    ctx: &TestCtx,
    report: &[u8],
    expected_report_data: &[u8; KEY_REPORT_DATA_LEN],
) -> KeyAttestationReport {
    // 1. PID pubkey from the slot-0 chain leaf.
    let info = ctx.cert_chain_info().expect("GetCertChainInfo");
    let num_certs = info.data.num_certs;
    assert!(num_certs >= 1, "cert chain must contain the PID leaf");
    let leaf = ctx
        .get_certificate(num_certs - 1)
        .expect("GetCertificate(PID leaf)");
    let leaf_bytes = leaf.data.certificate.as_slice();
    let leaf = X509Certificate::from_der(leaf_bytes).expect("PID leaf parses as X.509");
    let pid_spki = leaf.get_public_key_der().expect("PID leaf SPKI extracts");
    let pid_pub =
        tsra_crypto::EccPublicKey::from_bytes(&pid_spki).expect("PID pubkey loads from leaf SPKI");

    // 2. COSE_Sign1 signature verify under PID pubkey (ES384 over the COSE
    //    Sig_structure).
    let cose = CoseSign1Object::decode(report).expect("report parses as COSE_Sign1");
    let mut tbs = vec![0u8; 64 + cose.protected_header.len() + cose.payload.len()];
    let tbs_len = encode_sig_struct(&cose.protected_header, cose.payload, &mut tbs)
        .expect("encode COSE Sig_structure");
    let digest =
        tsra_crypto::Hasher::hash_vec(&mut HashAlgo::sha384(), &tbs[..tbs_len]).expect("SHA-384");
    let ok = tsra_crypto::Verifier::verify(
        &mut tsra_crypto::EccAlgo::default(),
        &pid_pub,
        &digest,
        &cose.signature,
    )
    .expect("ECDSA verify");
    assert!(ok, "KeyReport must be signed by the partition PID key");

    let decoded: KeyAttestationReport =
        minicbor::decode(cose.payload).expect("report payload decodes as KeyAttestationReport");

    assert_eq!(
        &decoded.report_data[..],
        &expected_report_data[..],
        "report_data must round-trip into the report payload",
    );

    decoded
}

/// Bind the signed COSE_Key to the generated ECC public point.
fn verify_key_report(
    ctx: &TestCtx,
    report: &[u8],
    expected_report_data: &[u8; KEY_REPORT_DATA_LEN],
    pub_key_le: &[u8],
    coord_len: usize,
) {
    let decoded = verify_signed_report(ctx, report, expected_report_data);
    let cose_key = &decoded.public_key[..decoded.public_key_size as usize];
    let (x_be, y_be) = cose_key_xy(cose_key);

    // COSE_Key coordinates are big-endian; the wire public key is LE
    // `x ‖ y`, with each coordinate zero-padded to the wire width (P-521:
    // 66 -> 68 bytes). Reverse each COSE_Key coordinate and compare it with
    // the unpadded prefix of the corresponding wire half.
    assert_eq!(
        x_be.len(),
        coord_len,
        "COSE_Key pk_x matches the curve width"
    );
    assert_eq!(
        y_be.len(),
        coord_len,
        "COSE_Key pk_y matches the curve width"
    );
    assert!(
        pub_key_le.len().is_multiple_of(2) && pub_key_le.len() / 2 >= coord_len,
        "wire public key length must hold two padded coordinates",
    );
    let wire_coord_len = pub_key_le.len() / 2;
    let (wire_x, wire_y) = pub_key_le.split_at(wire_coord_len);
    assert!(
        wire_x[coord_len..]
            .iter()
            .chain(&wire_y[coord_len..])
            .all(|&b| b == 0),
        "wire public key coordinate padding must be zero",
    );
    let x_le: Vec<u8> = x_be.iter().rev().copied().collect();
    let y_le: Vec<u8> = y_be.iter().rev().copied().collect();
    assert_eq!(
        x_le.as_slice(),
        &wire_x[..coord_len],
        "attested COSE_Key pk_x must re-derive the key's X",
    );
    assert_eq!(
        y_le.as_slice(),
        &wire_y[..coord_len],
        "attested COSE_Key pk_y must re-derive the key's Y",
    );
}

/// Bind the signed RSA COSE_Key to the independently generated host key.
fn verify_rsa_key_report(
    ctx: &TestCtx,
    report: &[u8],
    expected_report_data: &[u8; KEY_REPORT_DATA_LEN],
    expected_n: &[u8],
    expected_e: &[u8],
) {
    let decoded = verify_signed_report(ctx, report, expected_report_data);
    let cose_key = &decoded.public_key[..decoded.public_key_size as usize];
    let mut decoder = minicbor::Decoder::new(cose_key);
    let entries = decoder
        .map()
        .expect("COSE_Key is a CBOR map")
        .expect("COSE_Key map length is known");
    let (mut kty, mut n, mut e) = (None, None, None);
    for _ in 0..entries {
        match decoder.i64().expect("COSE_Key label decodes as int") {
            1 => kty = Some(decoder.u8().expect("COSE key type")),
            -1 => n = Some(decoder.bytes().expect("RSA modulus")),
            -2 => e = Some(decoder.bytes().expect("RSA exponent")),
            _ => decoder.skip().expect("skip unknown COSE field"),
        }
    }
    assert_eq!(kty, Some(3), "COSE key type must be RSA");
    assert_eq!(
        n.expect("COSE_Key carries RSA modulus"),
        expected_n,
        "attested RSA modulus must match the host key",
    );
    let e = e.expect("COSE_Key carries RSA exponent");
    // The firmware's four-byte exponent may have leading zero padding.
    let e = &e[e.iter().position(|&b| b != 0).unwrap_or(e.len())..];
    assert_eq!(
        e, expected_e,
        "attested RSA exponent must match the host key"
    );
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        common::finalize_partition(ctx, &session);

        let (masked_key, expected) = if input.use_generated_key {
            generate_masked_key(ctx, session.session_id, &input)
        } else {
            (input.fuzzed_key_data.masked_key.clone(), Expected::Rejected)
        };
        let req = TborKeyReportReq {
            session_id: session.session_id,
            masked_key,
            report_data: input.fuzzed_key_data.report_data,
            auth_envelope: Vec::new(),
        };
        let result = ctx.tbor(&req);

        let oversized = req.masked_key.len() > KEY_REPORT_MASKED_KEY_MAX_LEN;
        match (&result, expected) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Err(err), _) if oversized => assert!(
                matches!(
                    err,
                    DdiError::TborEncodeError
                        | DdiError::TborStatus(TborStatus::TborInvalidFixedLength)
                ),
                "oversized masked key must be rejected, got {err}"
            ),
            (Ok(resp), Expected::Report { pub_key, coord_len }) => {
                verify_key_report(ctx, &resp.report, &req.report_data, &pub_key, coord_len)
            }
            (Ok(resp), Expected::RsaReport { n, e }) => {
                verify_rsa_key_report(ctx, &resp.report, &req.report_data, &n, &e)
            }
            (Err(err), Expected::Report { .. }) => {
                panic!("KeyReport of a generated ECC key must succeed, got {err}")
            }
            (Err(err), Expected::RsaReport { .. }) => {
                panic!("KeyReport of an imported RSA key must succeed, got {err}")
            }
            (Err(err), Expected::UnsupportedKeyType) => assert!(
                matches!(err, DdiError::TborStatus(TborStatus::UnsupportedKeyType)),
                "non-attestable masked key must be rejected with UnsupportedKeyType, got {err}"
            ),
            (Err(err), Expected::Rejected) => assert!(
                matches!(err, DdiError::TborStatus(_)),
                "invalid masked key must be rejected by firmware, got {err}"
            ),
            (Ok(_), _) => {
                panic!("KeyReport unexpectedly succeeded for an invalid key")
            }
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
