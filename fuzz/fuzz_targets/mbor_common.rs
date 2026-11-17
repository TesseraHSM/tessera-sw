// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared setup and request generation for MBOR fuzz targets.

#![allow(dead_code)]

use ddi_sock_server as _;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use tsra_cred_encrypt::DeviceCredKey;
use tsra_crypto::*;
use tsra_ddi::*;
use tsra_ddi_mbor_codec::*;
pub use tsra_ddi_mbor_test_helpers::helper_get_or_init_bk3;
use tsra_ddi_mbor_test_helpers::*;
use tsra_ddi_mbor_types::*;
use x509::X509Certificate;
use x509::X509CertificateOp;

#[path = "mbor_requests.rs"]
mod requests;
pub use requests::*;

pub type DdiTest = TsraDdi;
type Dev = <DdiTest as Ddi>::Dev;

pub const TEST_CRED_ID: [u8; 16] = [1; 16];
pub const TEST_CRED_PIN: [u8; 16] = [2; 16];
const REV: Option<DdiApiRev> = Some(DdiApiRev { major: 1, minor: 0 });

#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum RsaKeySize {
    Rsa2k = 2048,
    Rsa3k = 3072,
    Rsa4k = 4096,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
pub enum HmacKeyType {
    Hmac256,
    Hmac384,
    Hmac512,
    VarHmac256(u8),
    VarHmac384(u8),
    VarHmac512(u8),
}

pub fn cleanup(ddi: &DdiTest, path: &str, session: Option<u16>) {
    let dev = ddi.open_dev(path).expect("Failed to open cleanup device");
    cleanup_with_session(&dev, session);
    dev.erase().expect("Failed to reset device");
}

pub fn cleanup_with_session(dev: &Dev, session: Option<u16>) {
    if session.is_some() {
        helper_close_session(dev, session, REV).expect("Failed to close session");
    }
}

pub fn encrypt_userid_pin_for_establish_cred(
    dev: &Dev,
    id: [u8; 16],
    pin: [u8; 16],
) -> (DdiEncryptedEstablishCredential, DdiDerPublicKey) {
    let resp = helper_get_establish_cred_encryption_key(dev, None, REV)
        .expect("Failed to get credential encryption key");
    let key = DeviceCredKey::new(&resp.data.pub_key, resp.data.nonce).unwrap();
    let (key, public_key) = key.generate_ephemeral_encryption_key().unwrap();
    (
        key.encrypt_establish_credential(id, pin, resp.data.nonce)
            .unwrap(),
        public_key,
    )
}

pub fn get_pota_endorsement(dev: &Dev) -> (Vec<u8>, Vec<u8>) {
    let info = helper_get_cert_chain_info(dev).expect("Failed to get certificate chain");
    let cert = helper_get_certificate(dev, info.data.num_certs - 1)
        .expect("Failed to get partition certificate");
    let cert = X509Certificate::from_der(cert.data.certificate.as_slice()).unwrap();
    let der = cert.get_public_key_der().unwrap();
    let public_key = DerEccPublicKey::from_der(&der).unwrap();
    let mut point = vec![4];
    point.extend_from_slice(public_key.x());
    point.extend_from_slice(public_key.y());

    let pota = EccPrivateKey::from_curve(EccCurve::P384).unwrap();
    let signature = Signer::sign_vec(&mut EcdsaAlgo::new(HashAlgo::sha384()), &pota, &point)
        .expect("Failed to sign partition public key");
    (signature, pota.public_key().unwrap().to_vec().unwrap())
}

pub fn helper_common_establish_credential(dev: &mut Dev, id: [u8; 16], pin: [u8; 16]) {
    let (encrypted, public_key) = encrypt_userid_pin_for_establish_cred(dev, id, pin);
    let masked_bk3 = helper_get_or_init_bk3(dev);
    let (signature, pota) = get_pota_endorsement(dev);
    helper_establish_credential(
        dev,
        None,
        REV,
        encrypted,
        public_key,
        masked_bk3,
        MborByteArray::from_slice(&[]).unwrap(),
        MborByteArray::from_slice(&[]).unwrap(),
        MborByteArray::from_slice(&signature).unwrap(),
        DdiDerPublicKey {
            der: MborByteArray::from_slice(&pota).unwrap(),
            key_kind: DdiKeyType::Ecc384Public,
        },
    )
    .expect("Failed to establish credential");
}

pub fn helper_common_open_session(dev: &mut Dev) -> Result<u16, DdiError> {
    let resp = helper_get_session_encryption_key(dev, None, REV)?;
    let key = DeviceCredKey::new(&resp.data.pub_key, resp.data.nonce).unwrap();
    let (key, public_key) = key.generate_ephemeral_encryption_key().unwrap();
    let encrypted = key
        .encrypt_session_credential(TEST_CRED_ID, TEST_CRED_PIN, [3; 48], resp.data.nonce)
        .unwrap();
    helper_open_session(dev, None, REV, encrypted, public_key)?
        .hdr
        .sess_id
        .ok_or(DdiError::InvalidParameter)
}

pub fn wrap_data(public_key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let public_key = RsaPublicKey::from_bytes(public_key)?;
    let key = AesKey::from_bytes(&[4; 32])?;
    let mut wrapped = Encrypter::encrypt_vec(
        &mut RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None),
        &public_key,
        &[4; 32],
    )?;
    wrapped.extend(Encrypter::encrypt_vec(
        &mut AesKeyWrapPadAlgo::default(),
        &key,
        data,
    )?);
    Ok(wrapped)
}

pub fn import_rsa_key(
    dev: &Dev,
    session: u16,
    availability: DdiKeyAvailability,
    rev: Option<DdiApiRev>,
    bits: u16,
) -> Option<u16> {
    let unwrapping = helper_get_unwrapping_key(dev, Some(session), rev).ok()?;
    let key = RsaPrivateKey::generate(bits as usize).ok()?;
    let wrapped = wrap_data(unwrapping.data.pub_key.der.as_slice(), &key.to_vec().ok()?).ok()?;
    helper_rsa_unwrap(
        dev,
        Some(session),
        rev,
        unwrapping.data.key_id,
        MborByteArray::from_slice(&wrapped).ok()?,
        DdiKeyClass::Rsa,
        DdiRsaCryptoPadding::Oaep,
        DdiHashAlgorithm::Sha256,
        helper_key_properties(DdiKeyUsage::SignVerify, availability),
    )
    .ok()
    .map(|resp| resp.data.key_id)
}

pub fn create_secret_key(
    dev: &Dev,
    session: u16,
    rev: Option<DdiApiRev>,
    curve: DdiEccCurve,
    availability: DdiKeyAvailability,
) -> Result<u16, DdiError> {
    let secret_type = match curve {
        DdiEccCurve::P256 => DdiKeyType::Secret256,
        DdiEccCurve::P384 => DdiKeyType::Secret384,
        DdiEccCurve::P521 => DdiKeyType::Secret521,
        _ => return Err(DdiError::InvalidParameter),
    };
    let properties = helper_key_properties(DdiKeyUsage::Derive, availability);
    let first = helper_ecc_generate_key_pair(dev, Some(session), rev, curve, properties)?;
    let second = helper_ecc_generate_key_pair(dev, Some(session), rev, curve, properties)?;
    let result = helper_ecdh_key_exchange(
        dev,
        Some(session),
        rev,
        first.data.private_key_id,
        MborByteArray::from_slice(second.data.pub_key.der.as_slice())
            .map_err(|_| DdiError::InvalidParameter)?,
        secret_type,
        properties,
    );
    helper_delete_key(dev, Some(session), rev, first.data.private_key_id)?;
    helper_delete_key(dev, Some(session), rev, second.data.private_key_id)?;
    result.map(|resp| resp.data.key_id)
}

pub fn helper_create_hmac_key(
    dev: &Dev,
    session: u16,
    rev: Option<DdiApiRev>,
    availability: DdiKeyAvailability,
    curve: DdiEccCurve,
    kind: HmacKeyType,
    hash: DdiHashAlgorithm,
) -> Result<u16, DdiError> {
    let (key_type, length) = match kind {
        HmacKeyType::Hmac256 => (DdiKeyType::HmacSha256, None),
        HmacKeyType::Hmac384 => (DdiKeyType::HmacSha384, None),
        HmacKeyType::Hmac512 => (DdiKeyType::HmacSha512, None),
        HmacKeyType::VarHmac256(len) => (DdiKeyType::VarHmac256, Some(32 + len % 33)),
        HmacKeyType::VarHmac384(len) => (DdiKeyType::VarHmac384, Some(48 + len % 81)),
        HmacKeyType::VarHmac512(len) => (DdiKeyType::VarHmac512, Some(64 + len % 65)),
    };
    let secret = create_secret_key(dev, session, rev, curve, availability)?;
    let result = helper_hkdf_derive(
        dev,
        Some(session),
        rev,
        secret,
        hash,
        None,
        None,
        key_type,
        helper_key_properties(DdiKeyUsage::SignVerify, availability),
        length,
    );
    helper_delete_key(dev, Some(session), rev, secret)?;
    result.map(|resp| resp.data.key_id)
}

pub fn check_driver_error<T>(result: Result<T, DdiError>) {
    if let Err(err @ (DdiError::DriverError(_) | DdiError::DdiError(_) | DdiError::IoError(_))) =
        result
    {
        panic!("Crash Detected: {err}");
    }
}

pub fn fuzz_cmd_reqs(requests: Vec<TestDdiReqs>, seed: u64, valid_header: bool) {
    let ddi = DdiTest::default();
    let devices = ddi.dev_info_list();
    let path = std::env::var("FUZZ_DEVICE")
        .unwrap_or_else(|_| devices.first().expect("No devices found").path.clone());
    let mut dev = ddi.open_dev(&path).expect("Failed to open device");
    cleanup(&ddi, &path, None);
    helper_common_establish_credential(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);
    let session = helper_common_open_session(&mut dev).expect("Failed to open session");
    for (index, request) in requests.into_iter().enumerate() {
        let seed = seed.wrapping_add(index as u64);
        let Ok(header) = request.header(Some(session), REV, seed, valid_header) else {
            continue;
        };
        check_driver_error(request.execute(&dev, header, seed, valid_header));
    }
    // A fuzzed request may already have closed this session.
    check_driver_error(helper_close_session(&dev, Some(session), REV));
}

#[derive(Arbitrary, Debug)]
pub enum TestAppOps {
    Open,
    Close,
    Request(TestDdiReqs, u64),
}

pub fn fuzz_app_ops(ops: Vec<TestAppOps>) {
    let ddi = DdiTest::default();
    let devices = ddi.dev_info_list();
    let path = std::env::var("FUZZ_DEVICE")
        .unwrap_or_else(|_| devices.first().expect("No devices found").path.clone());
    let mut dev = ddi.open_dev(&path).expect("Failed to open device");
    cleanup(&ddi, &path, None);
    helper_common_establish_credential(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);
    let mut session = None;
    for op in ops {
        match op {
            TestAppOps::Open => match helper_common_open_session(&mut dev) {
                Ok(id) => session = Some(id),
                Err(err) => check_driver_error::<()>(Err(err)),
            },
            TestAppOps::Close => {
                check_driver_error(helper_close_session(&dev, session.take(), REV));
            }
            TestAppOps::Request(request, seed) => {
                let Ok(header) = request.header(session, REV, seed, true) else {
                    continue;
                };
                check_driver_error(request.execute(&dev, header, seed, true));
            }
        }
    }
    check_driver_error(helper_close_session(&dev, session, REV));
}
