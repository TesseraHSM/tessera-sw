// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MBOR app session for keyed MBOR operations, set up as the MBOR DDI
//! integration tests do: factory reset, establish a credential, open a
//! session with it, then generate keys in the session.
//!
//! `EstablishCredential` is only compiled into firmware built with the
//! `mbor` feature.

use std::collections::BTreeMap;

use tsra_cred_encrypt::DeviceCredKey;
use tsra_crypto::DerEccPublicKey;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EccPublicKey;
use tsra_crypto::EcdsaAlgo;
use tsra_crypto::HashAlgo;
use tsra_crypto::ImportableKey;
use tsra_crypto::Signer;
use tsra_ddi::TsraDdi;
use tsra_ddi_interface::Ddi;
use tsra_ddi_interface::DdiDev;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_test_helpers::helper_ecc_generate_key_pair;
use tsra_ddi_mbor_test_helpers::helper_establish_credential;
use tsra_ddi_mbor_test_helpers::helper_get_cert_chain_info;
use tsra_ddi_mbor_test_helpers::helper_get_certificate;
use tsra_ddi_mbor_test_helpers::helper_get_establish_cred_encryption_key;
use tsra_ddi_mbor_test_helpers::helper_get_or_init_bk3;
use tsra_ddi_mbor_test_helpers::helper_get_session_encryption_key;
use tsra_ddi_mbor_test_helpers::helper_key_properties;
use tsra_ddi_mbor_test_helpers::helper_open_session;
use tsra_ddi_mbor_types::DdiApiRev;
use tsra_ddi_mbor_types::DdiDerPublicKey;
use tsra_ddi_mbor_types::DdiEccCurve;
use tsra_ddi_mbor_types::DdiKeyAvailability;
use tsra_ddi_mbor_types::DdiKeyType;
use tsra_ddi_mbor_types::DdiKeyUsage;
use x509::X509Certificate;
use x509::X509CertificateOp;

use crate::mbor_keys::TEST_ECC_384_PRIVATE_KEY;
use crate::mbor_keys::TEST_POTA_ECC_PRIVATE_KEY;
use crate::mbor_keys::TEST_POTA_ECC_PUB_KEY;

/// MBOR API revision the requests carry.
pub(crate) const REV: DdiApiRev = DdiApiRev { major: 1, minor: 0 };

const CRED_ID: [u8; 16] = [0x70; 16];
const CRED_PIN: [u8; 16] = [0xDB; 16];
const SESSION_SEED: [u8; 48] = [0xE5; 48];

/// A device-generated MBOR ECC key.
pub(crate) struct MborEccKey {
    pub(crate) id: u16,
    pub(crate) public: EccPublicKey,
}

/// The MBOR session keyed MBOR operations share.
pub(crate) struct MborSession {
    /// The fd the session was opened on; requests for it must use it.
    pub(crate) dev: <TsraDdi as Ddi>::Dev,
    pub(crate) session_id: u16,
    /// Keyed by curve: 1 = P-256, 2 = P-384.
    pub(crate) ecc: BTreeMap<u8, Vec<MborEccKey>>,
}

/// The MBOR curve for a TBOR-style curve number.
pub(crate) fn curve(tag: u8) -> DdiEccCurve {
    match tag {
        1 => DdiEccCurve::P256,
        _ => DdiEccCurve::P384,
    }
}

impl MborSession {
    /// Factory-reset the device, establish a credential, open a session
    /// and generate `keys` ECC keys on each of `curves`.
    pub(crate) fn open(path: &str, curves: &[u8], keys: usize) -> Result<Self, String> {
        let ddi = TsraDdi::default();
        let open = || {
            ddi.open_dev(path)
                .map_err(|e| format!("open {path}: {e:?}"))
        };
        open()?
            .erase()
            .map_err(|e| format!("factory reset: {e:?}"))?;
        establish_credential(&open()?)?;

        let dev = open()?;
        let session_id = open_session(&dev)?;
        let mut ecc = BTreeMap::new();
        for &tag in curves {
            let pool = (0..keys)
                .map(|_| {
                    let resp = helper_ecc_generate_key_pair(
                        &dev,
                        Some(session_id),
                        Some(REV),
                        curve(tag),
                        None,
                        helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App),
                    )
                    .map_err(|e| format!("MBOR EccGenerateKeyPair: {e:?}"))?;
                    let public = EccPublicKey::from_bytes(resp.data.pub_key.der.as_slice())
                        .map_err(|e| format!("MBOR ECC public key: {e:?}"))?;
                    Ok(MborEccKey {
                        id: resp.data.private_key_id,
                        public,
                    })
                })
                .collect::<Result<_, String>>()?;
            ecc.insert(tag, pool);
        }
        Ok(Self {
            dev,
            session_id,
            ecc,
        })
    }
}

fn cred_err(e: impl std::fmt::Debug) -> String {
    format!("credential encryption: {e:?}")
}

fn array<const N: usize>(bytes: &[u8]) -> Result<MborByteArray<N>, String> {
    MborByteArray::from_slice(bytes).map_err(|e| format!("MBOR byte array: {e:?}"))
}

fn establish_credential(dev: &<TsraDdi as Ddi>::Dev) -> Result<(), String> {
    let resp = helper_get_establish_cred_encryption_key(dev, None, Some(REV))
        .map_err(|e| format!("GetEstablishCredEncryptionKey: {e:?}"))?;
    let nonce = resp.data.nonce;
    let (key, pub_key) = DeviceCredKey::new(&resp.data.pub_key, nonce)
        .map_err(cred_err)?
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .map_err(cred_err)?;
    let credential = key
        .encrypt_establish_credential(CRED_ID, CRED_PIN, nonce)
        .map_err(cred_err)?;
    let masked_bk3 = helper_get_or_init_bk3(dev);
    let signed_pid = pota_endorsement(dev)?;

    helper_establish_credential(
        dev,
        None,
        Some(REV),
        credential,
        pub_key,
        masked_bk3,
        array(&[])?,
        array(&[])?,
        array(&signed_pid)?,
        DdiDerPublicKey {
            der: array(&TEST_POTA_ECC_PUB_KEY)?,
            key_kind: DdiKeyType::Ecc384Public,
        },
    )
    .map_err(|e| format!("EstablishCredential (firmware needs the `mbor` feature): {e:?}"))?;
    Ok(())
}

/// The partition owner's endorsement of the partition identity key: an
/// ECDSA P-384 signature over the uncompressed public key of the last
/// certificate in the chain.
fn pota_endorsement(dev: &<TsraDdi as Ddi>::Dev) -> Result<Vec<u8>, String> {
    let info = helper_get_cert_chain_info(dev).map_err(|e| format!("GetCertChainInfo: {e:?}"))?;
    let last = info
        .data
        .num_certs
        .checked_sub(1)
        .ok_or("empty certificate chain")?;
    let cert = helper_get_certificate(dev, last).map_err(|e| format!("GetCertificate: {e:?}"))?;
    let cert = X509Certificate::from_der(cert.data.certificate.as_slice())
        .map_err(|e| format!("certificate: {e:?}"))?;
    let der = cert
        .get_public_key_der()
        .map_err(|e| format!("certificate key: {e:?}"))?;
    let key = DerEccPublicKey::from_der(&der).map_err(|e| format!("certificate key: {e:?}"))?;
    let mut point = vec![0x04u8];
    point.extend_from_slice(key.x());
    point.extend_from_slice(key.y());

    let pota = EccPrivateKey::from_bytes(&TEST_POTA_ECC_PRIVATE_KEY)
        .map_err(|e| format!("POTA key: {e:?}"))?;
    let mut algo = EcdsaAlgo::new(HashAlgo::sha384());
    let len = Signer::sign(&mut algo, &pota, &point, None).map_err(|e| format!("POTA: {e:?}"))?;
    let mut sig = vec![0u8; len];
    let len = Signer::sign(&mut algo, &pota, &point, Some(&mut sig))
        .map_err(|e| format!("POTA: {e:?}"))?;
    sig.truncate(len);
    Ok(sig)
}

fn open_session(dev: &<TsraDdi as Ddi>::Dev) -> Result<u16, String> {
    let resp = helper_get_session_encryption_key(dev, None, Some(REV))
        .map_err(|e| format!("GetSessionEncryptionKey: {e:?}"))?;
    let nonce = resp.data.nonce;
    let (key, pub_key) = DeviceCredKey::new(&resp.data.pub_key, nonce)
        .map_err(cred_err)?
        .create_credential_key_from_der(&TEST_ECC_384_PRIVATE_KEY)
        .map_err(cred_err)?;
    let credential = key
        .encrypt_session_credential(CRED_ID, CRED_PIN, SESSION_SEED, nonce)
        .map_err(cred_err)?;
    helper_open_session(dev, None, Some(REV), credential, pub_key)
        .map_err(|e| format!("OpenSession: {e:?}"))?
        .hdr
        .sess_id
        .ok_or_else(|| "OpenSession returned no session id".to_owned())
}
