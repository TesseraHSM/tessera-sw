// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Object;
use openssl::asn1::Asn1OctetString;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::x509::X509;
use openssl::x509::X509Extension;
use openssl::x509::X509NameBuilder;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::KeyUsage;

use super::*;

const DICE: &str = "2.23.133.5.4.1";
const EKU: &str = "2.5.29.37";
const LAYER_ZERO: &[u8] = &[0x30, 0x03, 0x84, 0x01, 0x00];
const TESSERA_EKU: &[u8] = &[
    0x30, 0x0D, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x01, 0x32, 0x01,
];
const PROFILE: &[(&str, &[u8])] = &[(DICE, LAYER_ZERO), (EKU, TESSERA_EKU)];

fn certificate(
    name: &str,
    issuer: Option<(&X509, &PKey<Private>)>,
    ca: bool,
    extensions: &[(&str, &[u8])],
) -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).expect("curve");
    let key = PKey::from_ec_key(EcKey::generate(&group).expect("key")).expect("PKey");
    let mut subject = X509NameBuilder::new().expect("name builder");
    subject.append_entry_by_text("CN", name).expect("CN");
    let subject = subject.build();
    let mut cert = X509::builder().expect("certificate builder");
    cert.set_version(2).expect("version");
    let serial = Asn1Integer::from_bn(&BigNum::from_u32(1).expect("serial")).expect("ASN.1 serial");
    cert.set_serial_number(&serial).expect("serial");
    cert.set_subject_name(&subject).expect("subject");
    cert.set_issuer_name(issuer.map_or(subject.as_ref(), |(cert, _)| cert.subject_name()))
        .expect("issuer");
    cert.set_pubkey(&key).expect("public key");
    cert.set_not_before(&Asn1Time::days_from_now(0).expect("not before"))
        .expect("not before");
    cert.set_not_after(&Asn1Time::days_from_now(365).expect("not after"))
        .expect("not after");
    let mut constraints = BasicConstraints::new();
    constraints.critical();
    if ca {
        constraints.ca();
    }
    cert.append_extension(constraints.build().expect("constraints"))
        .expect("constraints");
    let mut usage = KeyUsage::new();
    usage.critical().digital_signature();
    if ca {
        usage.key_cert_sign().crl_sign();
    }
    cert.append_extension(usage.build().expect("key usage"))
        .expect("key usage");
    for (oid, value) in extensions {
        let extension = X509Extension::new_from_der(
            &Asn1Object::from_str(oid).expect("OID"),
            false,
            &Asn1OctetString::new_from_bytes(value).expect("extension value"),
        )
        .expect("extension");
        cert.append_extension(extension).expect("extension");
    }
    cert.sign(issuer.map_or(&key, |(_, key)| key), MessageDigest::sha384())
        .expect("sign certificate");
    (cert.build(), key)
}

fn root_pin(root: &X509) -> [u8; 48] {
    let cert = X509Certificate::from_der(&root.to_der().expect("DER")).expect("root");
    Hasher::hash_vec(
        &mut HashAlgo::sha384(),
        cert.subject_public_key_info_der().expect("SPKI"),
    )
    .expect("SHA-384")
    .try_into()
    .expect("digest length")
}

fn chain(certificates: &[&X509]) -> String {
    certificates
        .iter()
        .map(|certificate| String::from_utf8(certificate.to_pem().expect("PEM")).expect("UTF-8"))
        .collect()
}

fn rejected(pem: &str, pin: &[u8; 48]) {
    assert!(matches!(
        validate_part_cert_chain(pem, pin),
        Err(HsmError::InvalidSignature)
    ));
}

#[test]
fn pinned_root_and_tessera_profile_authenticate_the_pid_key() {
    let (root, root_key) = certificate("root", None, true, &[]);
    let (device, device_key) = certificate("device", Some((&root, &root_key)), true, PROFILE);
    let (leaf, _) = certificate("PID", Some((&device, &device_key)), false, &[]);
    let pem = chain(&[&leaf, &device, &root]);
    let pin = root_pin(&root);
    let key = validate_part_cert_chain(&pem, &pin).expect("authenticated PID");
    assert_eq!(
        key.coord_vec().expect("PID key"),
        EccPublicKey::from_bytes(
            &leaf
                .public_key()
                .expect("key")
                .public_key_to_der()
                .expect("SPKI")
        )
        .expect("PID key")
        .coord_vec()
        .expect("key bytes")
    );
    let mut wrong_pin = pin;
    wrong_pin[0] ^= 1;
    rejected(&pem, &wrong_pin);
    let cert_hash: [u8; 48] =
        Hasher::hash_vec(&mut HashAlgo::sha384(), &root.to_der().expect("DER"))
            .expect("hash")
            .try_into()
            .expect("length");
    rejected(&pem, &cert_hash);
    rejected(&chain(&[&root]), &pin);
    rejected("", &pin);

    let mut corrupt_leaf = leaf.to_der().expect("DER");
    *corrupt_leaf.last_mut().expect("signature") ^= 1;
    let corrupt_leaf = X509::from_der(&corrupt_leaf).expect("corrupt signature, intact DER");
    rejected(&chain(&[&corrupt_leaf, &device, &root]), &pin);
}

#[test]
fn tessera_profile_requires_explicit_layer_zero_and_matching_eku() {
    let (root, root_key) = certificate("root", None, true, &[]);
    let pin = root_pin(&root);
    let invalid_profiles: &[&[(&str, &[u8])]] = &[
        &[],
        &[(DICE, LAYER_ZERO)],
        &[(EKU, TESSERA_EKU)],
        &[(DICE, &[0x30, 0]), (EKU, TESSERA_EKU)],
        &[(DICE, &[0x30, 3, 0x83, 1, 0]), (EKU, TESSERA_EKU)], // SVN is not layer.
        &[(DICE, &[0x30, 3, 0x84, 1, 1]), (EKU, TESSERA_EKU)],
        &[(DICE, &[0x30, 3, 0x84, 1, 0xFF]), (EKU, TESSERA_EKU)],
        &[
            (DICE, &[0x30, 6, 0x84, 1, 0, 0x84, 1, 0]),
            (EKU, TESSERA_EKU),
        ],
        &[(DICE, &[0x30, 5, 0xA4, 3, 2, 1, 0]), (EKU, TESSERA_EKU)],
        &[(DICE, LAYER_ZERO), (DICE, LAYER_ZERO), (EKU, TESSERA_EKU)],
        &[(DICE, LAYER_ZERO), (EKU, &[0x30, 3, 6, 1, 0x2A])],
        &[(DICE, LAYER_ZERO), (EKU, &[0x30, 1, 6])],
    ];
    for profile in invalid_profiles {
        let (device, key) = certificate("device", Some((&root, &root_key)), true, profile);
        let (leaf, _) = certificate("PID", Some((&device, &key)), false, &[]);
        rejected(&chain(&[&leaf, &device, &root]), &pin);
    }
}

#[test]
fn profile_must_be_on_one_non_pid_certificate_in_the_verified_path() {
    let (root, root_key) = certificate("root", None, true, &[(EKU, TESSERA_EKU)]);
    let (device, device_key) = certificate(
        "device",
        Some((&root, &root_key)),
        true,
        &[(DICE, LAYER_ZERO)],
    );
    let (leaf, _) = certificate("PID", Some((&device, &device_key)), false, PROFILE);
    let (unrelated, _) = certificate("unrelated", Some((&root, &root_key)), true, PROFILE);
    // Neither split properties, a profiled PID, nor an unused signed CA may qualify.
    rejected(
        &chain(&[&leaf, &device, &unrelated, &root]),
        &root_pin(&root),
    );
}

#[test]
fn root_profile_requires_an_authentic_self_signature_not_just_a_matching_key() {
    let layer_one = [0x30, 3, 0x84, 1, 1];
    let (root, root_key) = certificate(
        "root",
        None,
        true,
        &[(DICE, &layer_one), (EKU, TESSERA_EKU)],
    );
    let (leaf, _) = certificate("PID", Some((&root, &root_key)), false, &[]);
    let mut der = root.to_der().expect("DER");
    let offset = der
        .windows(layer_one.len())
        .position(|bytes| bytes == layer_one)
        .expect("layer extension");
    der[offset + 4] = 0; // Forge layer zero without possessing the trusted root key.
    let forged = X509::from_der(&der).expect("forged root DER");
    rejected(&chain(&[&leaf, &forged]), &root_pin(&root));
}
