// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate storage and generation for the standard PAL.
//!
//! Generates a 4-certificate chain for slot 0 in each bank:
//!
//! | Index | Certificate | Scope |
//! |-------|-------------|-------|
//! | 0 | Root CA (self-signed) | Shared |
//! | 1 | DeviceId CA (Intermediate, path_len=1, DICE layer 0, Tessera EKU) | Shared |
//! | 2 | Alias CA (Intermediate, path_len=0) | Shared |
//! | 3 | Partition Id Leaf | Per-partition (on-demand) |
//!
//! The [`HsmCertBank::Ecc`] chain is all P-384; the [`HsmCertBank::MlDsa`]
//! chain is all ML-DSA-87, its leaf certifying the partition's ML-DSA-87
//! identity key.  The first 3 certificates of each bank are generated
//! during PAL initialization via [`StdHsmPal::init_cert_store`] when the
//! crypto backend supports that bank. The leaf
//! certs are generated lazily on first access per partition.
//!
//! Sideband paths (init / leaf-cert generation / chain hashing) call the
//! underlying [`StdHash`](crate::drivers::hash::StdHash) and
//! [`StdEcc`](crate::drivers::ecc::StdEcc) and
//! [`StdPqc`](crate::drivers::pqc::StdPqc) drivers directly — they have
//! no `HsmIo` context to satisfy the new PAL crypto trait surface, so
//! they bypass it entirely. The trait impl ([`HsmCertStore`]) at the
//! bottom of this file is the only path the core uses.

use der::asn1::AnyRef;
use der::asn1::ContextSpecific;
use der::Encode;
use der::Reader;
use der::SliceReader;
use der::Tag;
use der::TagNumber;
use tsra_crypto::x509_builder::cert_builder;
use tsra_crypto::x509_builder::cert_builder::*;
use tsra_crypto::x509_builder::der_helpers::MLDSA87_PUBLIC_KEY_LEN;
use tsra_crypto::x509_builder::der_helpers::MLDSA87_SIGNATURE_LEN;
use tsra_crypto::x509_builder::retarget;
use tsra_crypto::x509_builder::retarget::KeyAlg;
use tsra_crypto::x509_builder::retarget::SigAlg;
use tsra_crypto::x509_builder::retarget::SubjectKey;
use tsra_crypto::x509_builder::retarget::TbsKind;
use tsra_crypto::EccCurve;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::ExportableHsmKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::MlDsaVariant;
use tsra_crypto::PrivateKey;
use zeroize::Zeroizing;

use super::*;
use crate::drivers::ecc::EccForm;
use crate::part::P384_PUB_KEY_LEN;
use crate::StdHsmPal;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ROOT_CN: &str = "TSRA Root CA";
const ROOT_SN: &str = "ROOTCA01";
const DEVICEID_CN: &str = "TSRA DeviceId CA";
const DEVICEID_SN: &str = "DEVICEIDCA01";
const ALIAS_CN: &str = "TSRA Alias CA";
const ALIAS_SN: &str = "ALIASCA01";
const LEAF_CN: &str = "TSRA Partition";
const MLDSA_ROOT_CN: &str = "TSRA ML-DSA Root CA";
const MLDSA_DEVICEID_CN: &str = "TSRA ML-DSA DeviceId CA";
const MLDSA_ALIAS_CN: &str = "TSRA ML-DSA Alias CA";
const MLDSA_LEAF_CN: &str = "TSRA ML-DSA Partition";

/// Placeholder P-384 key for the templates; retargeting replaces it.
const PLACEHOLDER_P384_KEY: [u8; P384_UNCOMPRESSED_LEN] = [0x04; P384_UNCOMPRESSED_LEN];

const NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const NOT_AFTER: &[u8; 15] = b"20350101000000Z";

const DEVICEID_EXTENSIONS: &[u8] = &[
    // tcg-dice-TcbInfo (2.23.133.5.4.1): SEQUENCE { layer [4] IMPLICIT INTEGER 0 }.
    0x30, 0x0F, 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x01, 0x04, 0x05, 0x30, 0x03, 0x84, 0x01,
    0x00, // ExtendedKeyUsage (2.5.29.37): Tessera device (1.3.6.1.4.1.311.102.1.50.1).
    0x30, 0x16, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x0F, 0x30, 0x0D, 0x06, 0x0B, 0x2B, 0x06, 0x01,
    0x04, 0x01, 0x82, 0x37, 0x66, 0x01, 0x32, 0x01,
];

/// Maximum DER-encoded certificate size.
pub(crate) const MAX_CERT_DER_LEN: usize = 2048;

/// P-384 ECDSA signature component size (r or s).
const P384_SIG_COMPONENT: usize = 48;

/// Uncompressed P-384 public key length (0x04 || x || y).
const P384_UNCOMPRESSED_LEN: usize = 97;

/// Number of certs in slot 0 chain.
pub(crate) const SLOT0_CERT_COUNT: u8 = 4;

// ---------------------------------------------------------------------------
// Pure helpers (no crypto)
// ---------------------------------------------------------------------------

/// Generate a deterministic serial number for cert at `index` (1-based).
fn make_serial(index: u8) -> [u8; 20] {
    let mut serial = [0u8; 20];
    serial[0] = index;
    for (i, byte) in serial.iter_mut().enumerate().skip(1) {
        *byte = (i as u8).wrapping_mul(index.wrapping_mul(7));
    }
    serial
}

/// Generate a hex-encoded serial number string for a partition leaf cert.
fn make_leaf_sn(pid: u8) -> [u8; 4] {
    let hi = pid >> 4;
    let lo = pid & 0x0F;
    let to_hex = |n: u8| if n < 10 { b'0' + n } else { b'A' + n - 10 };
    [b'P', b'D', to_hex(hi), to_hex(lo)]
}

/// Build uncompressed public key (0x04 || x || y) from raw coords.
fn to_uncompressed(raw: &[u8; P384_PUB_KEY_LEN]) -> [u8; P384_UNCOMPRESSED_LEN] {
    let mut out = [0u8; P384_UNCOMPRESSED_LEN];
    out[0] = 0x04;
    out[1..].copy_from_slice(raw);
    out
}

// ---------------------------------------------------------------------------
// TBS patching helpers
// ---------------------------------------------------------------------------

fn patch_tbs_root(tbs: &mut [u8], params: &RootCertParams<'_>) {
    use tsra_crypto::x509_builder::root_cert::*;
    let cn = cert_builder::pad_cn(params.subject_cn).expect("valid CN");
    let sn = cert_builder::pad_sn(params.subject_sn).expect("valid SN");
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
}

fn patch_tbs_intermediate(tbs: &mut [u8], params: &IntermediateCertParams<'_>) {
    use tsra_crypto::x509_builder::intermediate_cert::*;
    let s_cn = cert_builder::pad_cn(params.subject_cn).expect("valid CN");
    let i_cn = cert_builder::pad_cn(params.issuer_cn).expect("valid CN");
    let s_sn = cert_builder::pad_sn(params.subject_sn).expect("valid SN");
    let i_sn = cert_builder::pad_sn(params.issuer_sn).expect("valid SN");
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&i_cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&s_cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&i_sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&s_sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
    tbs[AUTHORITY_KEY_ID_OFFSET..AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[PATH_LEN_OFFSET] = params.path_len;
}

/// Extend the DeviceId TBS before signing, without changing the Alias CA profile.
fn deviceid_tbs(tbs: &[u8]) -> der::Result<Vec<u8>> {
    let extensions_tag = Tag::ContextSpecific {
        constructed: true,
        number: TagNumber::N3,
    };
    let mut reader = SliceReader::new(tbs)?;
    let body = reader.sequence(|fields| {
        let mut body = Vec::new();
        while fields.peek_tag()? != extensions_tag {
            body.extend_from_slice(fields.tlv_bytes()?);
        }
        let extensions = ContextSpecific::<AnyRef<'_>>::decode_explicit(fields, TagNumber::N3)?
            .ok_or(der::ErrorKind::Value {
                tag: extensions_tag,
            })?;
        let mut values = extensions
            .value
            .sequence(|r| Ok(r.read_slice(r.remaining_len())?.to_vec()))?;
        values.extend_from_slice(DEVICEID_EXTENSIONS);
        let sequence = encode_der_value(Tag::Sequence, &values)?;
        body.extend_from_slice(&encode_der_value(extensions_tag, &sequence)?);
        Ok(body)
    })?;
    reader.finish(())?;
    encode_der_value(Tag::Sequence, &body)
}

fn encode_der_value(tag: Tag, value: &[u8]) -> der::Result<Vec<u8>> {
    let value = AnyRef::new(tag, value)?;
    let mut out = vec![0u8; value.encoded_len()?.try_into()?];
    value.encode_to_slice(&mut out)?;
    Ok(out)
}

fn patch_tbs_leaf(tbs: &mut [u8], params: &LeafCertParams<'_>) {
    use tsra_crypto::x509_builder::leaf_cert::*;
    let s_cn = cert_builder::pad_cn(params.subject_cn).expect("valid CN");
    let i_cn = cert_builder::pad_cn(params.issuer_cn).expect("valid CN");
    let s_sn = cert_builder::pad_sn(params.subject_sn).expect("valid SN");
    let i_sn = cert_builder::pad_sn(params.issuer_sn).expect("valid SN");
    tbs[PUBLIC_KEY_OFFSET..PUBLIC_KEY_OFFSET + 97].copy_from_slice(params.public_key);
    tbs[SERIAL_NUMBER_OFFSET..SERIAL_NUMBER_OFFSET + 20].copy_from_slice(params.serial_number);
    tbs[NOT_BEFORE_OFFSET..NOT_BEFORE_OFFSET + 15].copy_from_slice(params.not_before);
    tbs[NOT_AFTER_OFFSET..NOT_AFTER_OFFSET + 15].copy_from_slice(params.not_after);
    tbs[ISSUER_CN_OFFSET..ISSUER_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&i_cn);
    tbs[SUBJECT_CN_OFFSET..SUBJECT_CN_OFFSET + cert_builder::CN_LEN].copy_from_slice(&s_cn);
    tbs[ISSUER_SN_OFFSET..ISSUER_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&i_sn);
    tbs[SUBJECT_SN_OFFSET..SUBJECT_SN_OFFSET + cert_builder::SN_LEN].copy_from_slice(&s_sn);
    tbs[SUBJECT_KEY_ID_OFFSET..SUBJECT_KEY_ID_OFFSET + 20].copy_from_slice(params.subject_key_id);
    tbs[AUTHORITY_KEY_ID_OFFSET..AUTHORITY_KEY_ID_OFFSET + 20]
        .copy_from_slice(params.authority_key_id);
    tbs[KEY_USAGE_OFFSET..KEY_USAGE_OFFSET + 2].copy_from_slice(&params.key_usage.to_bytes());
}

// ---------------------------------------------------------------------------
// SharedCertStore — holds generated certs + alias key for leaf signing
// ---------------------------------------------------------------------------

/// Shared certificate storage for the 3 common certs (Root, DeviceId, Alias)
/// plus the Alias key material needed for on-demand leaf cert signing.
///
/// Initialized lazily via [`StdHsmPal::init_cert_store`] during PAL init.
pub(crate) struct SharedCertStore {
    root_cert: [u8; MAX_CERT_DER_LEN],
    root_cert_len: usize,
    deviceid_cert: [u8; MAX_CERT_DER_LEN],
    deviceid_cert_len: usize,
    alias_cert: [u8; MAX_CERT_DER_LEN],
    alias_cert_len: usize,
    /// Alias CA private key DER — for signing leaf certs.
    alias_priv_key: Vec<u8>,
    /// Alias CA Subject Key Identifier.
    pub(crate) alias_ski: [u8; 20],
    /// Precomputed SHA-256(root_cert || deviceid_cert).
    root_deviceid_hash: [u8; 32],
    /// The [`HsmCertBank::MlDsa`] chain.
    mldsa: MlDsaCertBank,
}

/// Shared ML-DSA-87 certificates (Root, DeviceId, Alias) plus the Alias key
/// that signs the ML-DSA partition leaves.
#[derive(Default)]
struct MlDsaCertBank {
    /// Root, DeviceId and Alias certificates, in chain order.
    certs: [Vec<u8>; 3],
    /// Alias CA expanded ML-DSA-87 private key.
    alias_sk: Zeroizing<Vec<u8>>,
    /// Alias CA Subject Key Identifier.
    alias_ski: [u8; 20],
    /// Precomputed SHA-256(root_cert || deviceid_cert).
    root_deviceid_hash: [u8; 32],
}

impl SharedCertStore {
    /// Create an empty (uninitialized) cert store.
    pub(crate) fn new() -> Self {
        Self {
            root_cert: [0u8; MAX_CERT_DER_LEN],
            root_cert_len: 0,
            deviceid_cert: [0u8; MAX_CERT_DER_LEN],
            deviceid_cert_len: 0,
            alias_cert: [0u8; MAX_CERT_DER_LEN],
            alias_cert_len: 0,
            alias_priv_key: Vec::new(),
            alias_ski: [0u8; 20],
            root_deviceid_hash: [0u8; 32],
            mldsa: MlDsaCertBank::default(),
        }
    }

    pub(crate) fn shared_cert(&self, idx: u8) -> Option<&[u8]> {
        match idx {
            0 => Some(&self.root_cert[..self.root_cert_len]),
            1 => Some(&self.deviceid_cert[..self.deviceid_cert_len]),
            2 => Some(&self.alias_cert[..self.alias_cert_len]),
            _ => None,
        }
    }

    /// Shared certificate `idx` of `bank`.
    fn bank_cert(&self, bank: HsmCertBank, idx: u8) -> Option<&[u8]> {
        match bank {
            HsmCertBank::Ecc => self.shared_cert(idx),
            HsmCertBank::MlDsa => self.mldsa.certs.get(usize::from(idx)).map(Vec::as_slice),
            _ => None,
        }
    }

    /// Precomputed SHA-256(root_cert || deviceid_cert) of `bank`.
    fn bank_root_deviceid_hash(&self, bank: HsmCertBank) -> &[u8; 32] {
        if bank == HsmCertBank::MlDsa {
            &self.mldsa.root_deviceid_hash
        } else {
            &self.root_deviceid_hash
        }
    }

    pub(crate) fn alias_priv_key(&self) -> &[u8] {
        &self.alias_priv_key
    }
}

// ---------------------------------------------------------------------------
// Async cert generation on StdHsmPal (uses PAL traits)
// ---------------------------------------------------------------------------

/// Temporary key pair: raw pub coords + private DER.
struct CertKeyPair {
    priv_key: Vec<u8>,
    uncompressed: [u8; P384_UNCOMPRESSED_LEN],
    ski: [u8; 20],
}

/// Temporary ML-DSA-87 key pair: expanded private key, public key, SKI.
struct MlDsaCertKeyPair {
    sk: Zeroizing<Vec<u8>>,
    pk: [u8; MLDSA87_PUBLIC_KEY_LEN],
    ski: [u8; 20],
}

impl StdHsmPal {
    /// Initialize the shared cert store by generating all 3 certs.
    ///
    /// Must be called during PAL initialization before any cert access.
    /// Uses [`HsmEcc::ecc_gen_keypair`] and [`HsmHash`] via PAL traits.
    pub async fn init_cert_store(&self) -> HsmResult<()> {
        // --- Generate 3 key pairs ---
        let root_kp = self.gen_cert_keypair().await?;
        let deviceid_kp = self.gen_cert_keypair().await?;
        let alias_kp = self.gen_cert_keypair().await?;

        // --- Root CA ---
        let root_serial = make_serial(1);
        let root_params = RootCertParams {
            public_key: &root_kp.uncompressed,
            serial_number: &root_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: ROOT_CN,
            subject_sn: ROOT_SN,
            subject_key_id: &root_kp.ski,
        };
        let mut tbs = tsra_crypto::x509_builder::root_cert::TBS_TEMPLATE;
        patch_tbs_root(&mut tbs, &root_params);
        let (r, s) = self.hash_and_sign(&root_kp.priv_key, &tbs).await?;
        let mut root_cert = [0u8; MAX_CERT_DER_LEN];
        let root_cert_len = cert_builder::build_root_cert(&root_params, &r, &s, &mut root_cert)
            .ok_or(HsmError::InternalError)?;

        // --- DeviceId CA ---
        let deviceid_serial = make_serial(2);
        let deviceid_params = IntermediateCertParams {
            public_key: &deviceid_kp.uncompressed,
            serial_number: &deviceid_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: DEVICEID_CN,
            subject_sn: DEVICEID_SN,
            issuer_cn: ROOT_CN,
            issuer_sn: ROOT_SN,
            subject_key_id: &deviceid_kp.ski,
            authority_key_id: &root_kp.ski,
            path_len: 1,
        };
        let mut tbs = tsra_crypto::x509_builder::intermediate_cert::TBS_TEMPLATE;
        patch_tbs_intermediate(&mut tbs, &deviceid_params);
        let tbs = deviceid_tbs(&tbs).map_err(|_| HsmError::InternalError)?;
        let (r, s) = self.hash_and_sign(&root_kp.priv_key, &tbs).await?;
        let mut deviceid_cert = [0u8; MAX_CERT_DER_LEN];
        let deviceid_cert_len = cert_builder::assemble_cert(&tbs, &r, &s, &mut deviceid_cert)
            .ok_or(HsmError::InternalError)?;

        // --- Alias CA ---
        let alias_serial = make_serial(3);
        let alias_params = IntermediateCertParams {
            public_key: &alias_kp.uncompressed,
            serial_number: &alias_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: ALIAS_CN,
            subject_sn: ALIAS_SN,
            issuer_cn: DEVICEID_CN,
            issuer_sn: DEVICEID_SN,
            subject_key_id: &alias_kp.ski,
            authority_key_id: &deviceid_kp.ski,
            path_len: 0,
        };
        let mut tbs = tsra_crypto::x509_builder::intermediate_cert::TBS_TEMPLATE;
        patch_tbs_intermediate(&mut tbs, &alias_params);
        let (r, s) = self.hash_and_sign(&deviceid_kp.priv_key, &tbs).await?;
        let mut alias_cert = [0u8; MAX_CERT_DER_LEN];
        let alias_cert_len =
            cert_builder::build_intermediate_cert(&alias_params, &r, &s, &mut alias_cert)
                .ok_or(HsmError::InternalError)?;

        // Precompute SHA-256(root_cert || deviceid_cert).
        let mut rd_concat = vec![0u8; root_cert_len + deviceid_cert_len];
        rd_concat[..root_cert_len].copy_from_slice(&root_cert[..root_cert_len]);
        rd_concat[root_cert_len..].copy_from_slice(&deviceid_cert[..deviceid_cert_len]);
        let mut root_deviceid_hash = [0u8; 32];
        self.hash
            .hash(HashAlgo::sha256(), &rd_concat, &mut root_deviceid_hash)
            .await?;

        // Commit to store.
        let store = &mut *self.cert_store_mut();
        store.root_cert = root_cert;
        store.root_cert_len = root_cert_len;
        store.deviceid_cert = deviceid_cert;
        store.deviceid_cert_len = deviceid_cert_len;
        store.alias_cert = alias_cert;
        store.alias_cert_len = alias_cert_len;
        store.alias_priv_key = alias_kp.priv_key;
        store.alias_ski = alias_kp.ski;
        store.root_deviceid_hash = root_deviceid_hash;

        match self.init_mldsa_bank().await {
            Ok(mldsa) => self.cert_store_mut().mldsa = mldsa,
            Err(HsmError::UnsupportedCmd) => {
                tsra_fw_hsm_core_tracing::warn!(
                    "cert",
                    "ML-DSA certificate bank is unavailable on this crypto backend"
                );
            }
            Err(error) => return Err(error),
        }

        Ok(())
    }

    /// Generate the shared ML-DSA-87 Root, DeviceId and Alias certificates.
    async fn init_mldsa_bank(&self) -> HsmResult<MlDsaCertBank> {
        let root_kp = self.gen_mldsa_cert_keypair(None).await?;
        let deviceid_kp = self.gen_mldsa_cert_keypair(None).await?;
        let alias_kp = self.gen_mldsa_cert_keypair(None).await?;

        let tbs = cert_builder::root_cert_tbs(&RootCertParams {
            public_key: &PLACEHOLDER_P384_KEY,
            serial_number: &make_serial(4),
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: MLDSA_ROOT_CN,
            subject_sn: ROOT_SN,
            subject_key_id: &root_kp.ski,
        })
        .ok_or(HsmError::InternalError)?;
        let root_cert = self.mldsa_certify(&tbs, &root_kp.pk, &root_kp.sk).await?;

        let tbs = cert_builder::intermediate_cert_tbs(&IntermediateCertParams {
            public_key: &PLACEHOLDER_P384_KEY,
            serial_number: &make_serial(5),
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: MLDSA_DEVICEID_CN,
            subject_sn: DEVICEID_SN,
            issuer_cn: MLDSA_ROOT_CN,
            issuer_sn: ROOT_SN,
            subject_key_id: &deviceid_kp.ski,
            authority_key_id: &root_kp.ski,
            path_len: 1,
        })
        .ok_or(HsmError::InternalError)?;
        let tbs = deviceid_tbs(&tbs).map_err(|_| HsmError::InternalError)?;
        let deviceid_cert = self
            .mldsa_certify(&tbs, &deviceid_kp.pk, &root_kp.sk)
            .await?;

        let tbs = cert_builder::intermediate_cert_tbs(&IntermediateCertParams {
            public_key: &PLACEHOLDER_P384_KEY,
            serial_number: &make_serial(6),
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: MLDSA_ALIAS_CN,
            subject_sn: ALIAS_SN,
            issuer_cn: MLDSA_DEVICEID_CN,
            issuer_sn: DEVICEID_SN,
            subject_key_id: &alias_kp.ski,
            authority_key_id: &deviceid_kp.ski,
            path_len: 0,
        })
        .ok_or(HsmError::InternalError)?;
        let alias_cert = self
            .mldsa_certify(&tbs, &alias_kp.pk, &deviceid_kp.sk)
            .await?;

        let mut root_deviceid_hash = [0u8; 32];
        self.hash
            .hash(
                HashAlgo::sha256(),
                &[root_cert.as_slice(), deviceid_cert.as_slice()].concat(),
                &mut root_deviceid_hash,
            )
            .await?;

        Ok(MlDsaCertBank {
            certs: [root_cert, deviceid_cert, alias_cert],
            alias_sk: alias_kp.sk,
            alias_ski: alias_kp.ski,
            root_deviceid_hash,
        })
    }

    /// Derive an ML-DSA-87 key pair from `seed`, or from a fresh random
    /// seed, and compute its SKI (SHA-1 of the raw public key).
    async fn gen_mldsa_cert_keypair(&self, seed: Option<&[u8]>) -> HsmResult<MlDsaCertKeyPair> {
        let mut random = Zeroizing::new([0u8; MLDSA_SEED_LEN]);
        let seed = match seed {
            Some(seed) => seed,
            None => {
                tsra_crypto::Rng::rand_bytes(&mut random[..])
                    .map_err(|_| HsmError::InternalError)?;
                &random[..]
            }
        };
        let (pk, sk) = self.pqc.mldsa_keygen(MlDsaVariant::MlDsa87, seed).await?;
        let sk = Zeroizing::new(sk);
        let pk: [u8; MLDSA87_PUBLIC_KEY_LEN] =
            pk.try_into().map_err(|_| HsmError::InternalError)?;
        let mut ski = [0u8; 20];
        self.hash.hash(HashAlgo::sha1(), &pk, &mut ski).await?;
        Ok(MlDsaCertKeyPair { sk, pk, ski })
    }

    /// Retarget the P-384 template `tbs` to an ML-DSA-87 issuer and the
    /// subject key `pk`, sign it with hedging using `issuer_sk`, and
    /// assemble the certificate.
    async fn mldsa_certify(
        &self,
        tbs: &[u8],
        pk: &[u8; MLDSA87_PUBLIC_KEY_LEN],
        issuer_sk: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let len =
            retarget::retarget_len(tbs, TbsKind::Certificate, SigAlg::MlDsa87, KeyAlg::MlDsa87)
                .ok_or(HsmError::InternalError)?;
        let mut ml_tbs = vec![0u8; len];
        retarget::retarget_tbs(
            tbs,
            TbsKind::Certificate,
            SigAlg::MlDsa87,
            SubjectKey::MlDsa87(pk),
            &mut ml_tbs,
        )
        .filter(|&n| n == len)
        .ok_or(HsmError::InternalError)?;
        let sig = self
            .pqc
            .mldsa_sign(MlDsaVariant::MlDsa87, issuer_sk, false, false, &ml_tbs, &[])
            .await?;
        let sig: &[u8; MLDSA87_SIGNATURE_LEN] = sig
            .as_slice()
            .try_into()
            .map_err(|_| HsmError::InternalError)?;
        let mut cert = vec![0u8; cert_builder::mldsa_cert_len(len)];
        let written = cert_builder::assemble_cert_mldsa(&ml_tbs, sig, &mut cert)
            .ok_or(HsmError::InternalError)?;
        cert.truncate(written);
        Ok(cert)
    }

    /// Generate a P-384 key pair and compute SKI for cert construction.
    ///
    /// Bypasses the [`HsmEcc`] trait (which requires an `HsmIo`) and
    /// drives the [`StdEcc`] driver directly, mirroring what the trait
    /// impl in `crate::ecc` would do.
    async fn gen_cert_keypair(&self) -> HsmResult<CertKeyPair> {
        // Generate the keypair, then serialize: the public key as raw
        // big-endian `x ∥ y`, the private key as raw HSM scalar bytes.
        let (pk, pub_key) = self.ecc.gen_keypair(EccCurve::P384).await?;
        let mut pub_raw = [0u8; P384_PUB_KEY_LEN];
        self.ecc
            .pub_coords(&pub_key, EccForm::BE, &mut pub_raw)
            .await?;
        let priv_len = pk.hsm_bytes_len();
        let mut priv_key = vec![0u8; priv_len];
        pk.to_hsm_bytes(&mut priv_key[..priv_len])
            .map_err(|_| HsmError::EccExportError)?;

        let uncompressed = to_uncompressed(&pub_raw);
        let mut ski = [0u8; 20];
        self.hash
            .hash(HashAlgo::sha1(), &uncompressed, &mut ski)
            .await?;

        Ok(CertKeyPair {
            priv_key,
            uncompressed,
            ski,
        })
    }

    /// Hash TBS with SHA-384, then sign with ECC P-384. Returns (r, s).
    ///
    /// Sideband helper that bypasses the PAL crypto trait surface
    /// (no `HsmIo` available during cert init / leaf-cert generation).
    async fn hash_and_sign(
        &self,
        priv_key: &[u8],
        tbs: &[u8],
    ) -> HsmResult<([u8; P384_SIG_COMPONENT], [u8; P384_SIG_COMPONENT])> {
        let mut tbs_hash = [0u8; 48];
        self.hash
            .hash(HashAlgo::sha384(), tbs, &mut tbs_hash)
            .await?;

        let key = EccPrivateKey::from_hsm_bytes(priv_key).map_err(|_| HsmError::InvalidArg)?;
        let sig = self.ecc.ecc_sign(&key, &tbs_hash).await?;
        if sig.len() < 2 * P384_SIG_COMPONENT {
            return Err(HsmError::EccSignFailed);
        }

        let mut r = [0u8; P384_SIG_COMPONENT];
        let mut s = [0u8; P384_SIG_COMPONENT];
        r.copy_from_slice(&sig[..P384_SIG_COMPONENT]);
        s.copy_from_slice(&sig[P384_SIG_COMPONENT..2 * P384_SIG_COMPONENT]);
        Ok((r, s))
    }

    pub(crate) fn mldsa_cert_bank_available(&self) -> bool {
        !self.cert_store().mldsa.certs[0].is_empty()
    }

    fn check_cert_bank(&self, slot: HsmCertSlot, bank: HsmCertBank) -> HsmResult<()> {
        if slot != HsmCertSlot::Mfgr || !matches!(bank, HsmCertBank::Ecc | HsmCertBank::MlDsa) {
            return Err(HsmError::InvalidArg);
        }
        if bank == HsmCertBank::MlDsa && !self.mldsa_cert_bank_available() {
            return Err(HsmError::UnsupportedCmd);
        }
        Ok(())
    }

    /// Check that partition `pid` has a live identity to certify.
    fn check_leaf_state(&self, pid: u8) -> HsmResult<()> {
        let table = unsafe { &*self.part_table.get() };
        let entry = table
            .entries
            .get(usize::from(pid))
            .ok_or(HsmError::InvalidArg)?;
        // Unallocated and Disabled have no live identity key.
        if entry.state == HsmPartState::Unallocated || entry.state == HsmPartState::Disabled {
            return Err(HsmError::InvalidArg);
        }
        Ok(())
    }

    /// Ensure the partition's leaf cert for `bank` is cached and return it.
    async fn bank_leaf_cert(&self, pid: u8, bank: HsmCertBank) -> HsmResult<&[u8]> {
        if bank == HsmCertBank::MlDsa {
            self.ensure_mldsa_leaf_cert(pid).await?;
        } else {
            self.ensure_leaf_cert(pid).await?;
        }
        let table = unsafe { &*self.part_table.get() };
        let entry = &table.entries[pid as usize];
        Ok(if bank == HsmCertBank::MlDsa {
            &entry.mldsa_leaf_cert
        } else {
            &entry.leaf_cert[..entry.leaf_cert_len]
        })
    }

    /// Ensure the partition's ML-DSA-87 leaf cert is cached.
    async fn ensure_mldsa_leaf_cert(&self, pid: u8) -> HsmResult<()> {
        self.check_leaf_state(pid)?;
        let seed = {
            let table = unsafe { &*self.part_table.get() };
            let entry = &table.entries[pid as usize];
            if !entry.mldsa_leaf_cert.is_empty() {
                return Ok(());
            }
            let key_id = entry
                .id_mldsa_seed_key_id
                .ok_or(HsmError::PartPropNotFound)?;
            Zeroizing::new(entry.vault.key(key_id)?.to_vec())
        };
        let kp = self.gen_mldsa_cert_keypair(Some(&seed)).await?;

        // Serial derived from the SKI as for the P-384 leaf.
        let mut leaf_serial = kp.ski;
        leaf_serial[0] = (leaf_serial[0] & 0x3f) | 0x40;
        let sn_bytes = make_leaf_sn(pid);
        let leaf_sn = core::str::from_utf8(&sn_bytes).map_err(|_| HsmError::InternalError)?;
        let store = self.cert_store();
        let tbs = cert_builder::leaf_cert_tbs(&LeafCertParams {
            public_key: &PLACEHOLDER_P384_KEY,
            serial_number: &leaf_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: MLDSA_LEAF_CN,
            subject_sn: leaf_sn,
            issuer_cn: MLDSA_ALIAS_CN,
            issuer_sn: ALIAS_SN,
            subject_key_id: &kp.ski,
            authority_key_id: &store.mldsa.alias_ski,
            key_usage: KeyUsage::DIGITAL_SIGNATURE,
        })
        .ok_or(HsmError::InternalError)?;
        let cert = self
            .mldsa_certify(&tbs, &kp.pk, &store.mldsa.alias_sk)
            .await?;

        let table = unsafe { &mut *self.part_table.get() };
        table.entries[pid as usize].mldsa_leaf_cert = cert;
        Ok(())
    }

    /// Ensure the partition's leaf cert is cached.
    async fn ensure_leaf_cert(&self, pid: u8) -> HsmResult<()> {
        self.check_leaf_state(pid)?;
        {
            let table = unsafe { &*self.part_table.get() };
            if table.entries[pid as usize].leaf_cert_len > 0 {
                return Ok(());
            }
        }

        let public_key = {
            let table = unsafe { &*self.part_table.get() };
            let entry = &table.entries[pid as usize];
            let key_id = entry.id_key_id.ok_or(HsmError::PartPropNotFound)?;
            EccPrivateKey::from_hsm_bytes(entry.vault.key(key_id)?)
                .map_err(|_| HsmError::InvalidArg)?
                .public_key()
                .map_err(|_| HsmError::EccGetCoordinatesError)?
        };
        let mut pub_raw = [0u8; P384_PUB_KEY_LEN];
        self.ecc
            .pub_coords(&public_key, EccForm::BE, &mut pub_raw)
            .await?;
        let uncompressed = to_uncompressed(&pub_raw);

        // SKI = SHA-1(uncompressed pubkey).
        let mut ski = [0u8; 20];
        self.hash
            .hash(HashAlgo::sha1(), &uncompressed, &mut ski)
            .await?;

        // Prepare TBS.
        //
        // Bind the leaf serial to the partition identity key (via its SHA-1
        // subject key identifier) so this PAL-provisioned slot-0 leaf and the
        // firmware's on-demand slot-2 PID leaf — both certifying this same PID
        // key — carry the same serial.  Keep a positive DER INTEGER leading
        // byte (bit 7 clear, bit 6 set), matching the firmware derivation.
        let mut leaf_serial = [0u8; 20];
        leaf_serial.copy_from_slice(&ski);
        leaf_serial[0] = (leaf_serial[0] & 0x3f) | 0x40;
        let sn_bytes = make_leaf_sn(pid);
        let leaf_sn = core::str::from_utf8(&sn_bytes).map_err(|_| HsmError::InternalError)?;
        let params = LeafCertParams {
            public_key: &uncompressed,
            serial_number: &leaf_serial,
            not_before: NOT_BEFORE,
            not_after: NOT_AFTER,
            subject_cn: LEAF_CN,
            subject_sn: leaf_sn,
            issuer_cn: ALIAS_CN,
            issuer_sn: ALIAS_SN,
            subject_key_id: &ski,
            authority_key_id: &self.cert_store().alias_ski,
            key_usage: KeyUsage::DIGITAL_SIGNATURE,
        };
        let mut tbs = tsra_crypto::x509_builder::leaf_cert::TBS_TEMPLATE;
        patch_tbs_leaf(&mut tbs, &params);

        // Sign via PAL.
        let (r, s) = self
            .hash_and_sign(self.cert_store().alias_priv_key(), &tbs)
            .await?;

        // Build final cert and cache.
        let table = unsafe { &mut *self.part_table.get() };
        let entry = &mut table.entries[pid as usize];
        let len = cert_builder::build_leaf_cert(&params, &r, &s, &mut entry.leaf_cert)
            .ok_or(HsmError::InternalError)?;
        entry.leaf_cert_len = len;
        Ok(())
    }

    /// Get mutable reference to cert store (for init).
    #[allow(clippy::mut_from_ref)]
    fn cert_store_mut(&self) -> &mut SharedCertStore {
        // SAFETY: only called during init, single-threaded.
        unsafe { &mut *self.cert_store.get() }
    }

    /// Get immutable reference to cert store.
    fn cert_store(&self) -> &SharedCertStore {
        // SAFETY: single-threaded Embassy executor.
        unsafe { &*self.cert_store.get() }
    }
}

// ---------------------------------------------------------------------------
// CertificateStore trait implementation
// ---------------------------------------------------------------------------

impl HsmCertStore for StdHsmPal {
    async fn get_cert_chain_info(
        &self,
        io: &StdHsmIo,
        slot: HsmCertSlot,
        bank: HsmCertBank,
    ) -> HsmResult<HsmCertChainInfo> {
        let pid = u8::from(io.pid());
        self.check_cert_bank(slot, bank)?;

        let leaf = self.bank_leaf_cert(pid, bank).await?;
        let store = self.cert_store();

        // Thumbprint = SHA-256(SHA-256(root||devid) || SHA-256(alias) || SHA-256(leaf))
        let mut alias_hash = [0u8; 32];
        self.hash
            .hash(
                HashAlgo::sha256(),
                store.bank_cert(bank, 2).ok_or(HsmError::InternalError)?,
                &mut alias_hash,
            )
            .await?;

        let mut leaf_hash = [0u8; 32];
        self.hash
            .hash(HashAlgo::sha256(), leaf, &mut leaf_hash)
            .await?;

        let mut combined = [0u8; 96];
        combined[..32].copy_from_slice(store.bank_root_deviceid_hash(bank));
        combined[32..64].copy_from_slice(&alias_hash);
        combined[64..96].copy_from_slice(&leaf_hash);

        let mut thumbprint = [0u8; 32];
        self.hash
            .hash(HashAlgo::sha256(), &combined, &mut thumbprint)
            .await?;

        Ok(HsmCertChainInfo {
            count: SLOT0_CERT_COUNT,
            thumbprint,
        })
    }

    async fn get_cert(
        &self,
        io: &StdHsmIo,
        slot: HsmCertSlot,
        bank: HsmCertBank,
        idx: u8,
        cert: Option<&mut [u8]>,
    ) -> HsmResult<usize> {
        let pid = u8::from(io.pid());
        self.check_cert_bank(slot, bank)?;

        let src = match idx {
            // Shared certs (idx 0–2).
            0..=2 => self
                .cert_store()
                .bank_cert(bank, idx)
                .ok_or(HsmError::InvalidArg)?,
            // Partition leaf cert (idx 3).
            3 => self.bank_leaf_cert(pid, bank).await?,
            _ => return Err(HsmError::InvalidArg),
        };
        if let Some(buf) = cert {
            if buf.len() < src.len() {
                return Err(HsmError::InvalidArg);
            }
            buf[..src.len()].copy_from_slice(src);
        }
        Ok(src.len())
    }
}

#[cfg(test)]
mod tests {
    use der::asn1::ObjectIdentifier;
    use der::asn1::OctetStringRef;
    use der::Decode;
    use der::Tagged;

    use super::*;

    fn certificate_extensions(cert: &[u8]) -> der::Result<Vec<(ObjectIdentifier, &[u8])>> {
        AnyRef::from_der(cert)?.sequence(|certificate| {
            let values = certificate.sequence(|fields| {
                for _ in 0..7 {
                    fields.tlv_bytes()?;
                }
                let extensions =
                    ContextSpecific::<AnyRef<'_>>::decode_explicit(fields, TagNumber::N3)?
                        .ok_or(der::ErrorKind::Value { tag: Tag::Sequence })?;
                extensions.value.sequence(|reader| {
                    let mut values = Vec::new();
                    while !reader.is_finished() {
                        values.push(reader.sequence(|ext| {
                            let oid = ObjectIdentifier::decode(ext)?;
                            if ext.peek_tag()? == Tag::Boolean {
                                bool::decode(ext)?;
                            }
                            let value = OctetStringRef::decode(ext)?;
                            Ok((oid, value.as_bytes()))
                        })?);
                    }
                    Ok(values)
                })
            })?;
            certificate.tlv_bytes()?;
            certificate.tlv_bytes()?;
            Ok(values)
        })
    }

    #[tokio::test]
    async fn deviceid_certificate_has_layer_zero_and_tessera_eku() -> HsmResult<()> {
        let (_, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        pal.init_cert_store().await?;

        let tcb_oid = ObjectIdentifier::new_unwrap("2.23.133.5.4.1");
        let eku_oid = ObjectIdentifier::new_unwrap("2.5.29.37");
        let tessera_oid = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.102.1.50.1");
        for idx in 0..3 {
            let cert = pal.cert_store().shared_cert(idx).expect("shared cert");
            let extensions = certificate_extensions(cert).expect("certificate extensions");
            let tcb = extensions.iter().find(|(oid, _)| *oid == tcb_oid);
            let eku = extensions.iter().find(|(oid, _)| *oid == eku_oid);
            if idx != 1 {
                assert!(tcb.is_none(), "only DeviceId should assert DICE layer 0");
                assert!(eku.is_none(), "only DeviceId should have the Tessera EKU");
                continue;
            }

            let layer = AnyRef::from_der(tcb.expect("DICE TCB Info").1)
                .expect("TCB SEQUENCE")
                .sequence(AnyRef::decode)
                .expect("DICE layer");
            assert_eq!(
                layer.tag(),
                Tag::ContextSpecific {
                    constructed: false,
                    number: TagNumber::N4,
                }
            );
            assert_eq!(layer.value(), &[0]);

            assert_eq!(
                AnyRef::from_der(eku.expect("EKU").1)
                    .expect("EKU SEQUENCE")
                    .sequence(ObjectIdentifier::decode)
                    .expect("Tessera EKU OID"),
                tessera_oid
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn unsupported_slots_and_banks_reject_metadata_queries_and_certificate_reads() {
        let (_, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (tx, _) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, tx);

        for (slot, bank) in [
            (HsmCertSlot::DevOwner, HsmCertBank::Ecc),
            (HsmCertSlot::PartOwner, HsmCertBank::Ecc),
            (HsmCertSlot(u8::MAX), HsmCertBank::Ecc),
            (HsmCertSlot::PartOwner, HsmCertBank::MlDsa),
            (HsmCertSlot::Mfgr, HsmCertBank(u8::MAX)),
        ] {
            assert_eq!(
                pal.get_cert_chain_info(&io, slot, bank).await,
                Err(HsmError::InvalidArg)
            );
            for idx in [0, SLOT0_CERT_COUNT - 1] {
                assert_eq!(
                    pal.get_cert(&io, slot, bank, idx, None).await,
                    Err(HsmError::InvalidArg)
                );
                let mut out = [0xA5; MAX_CERT_DER_LEN];
                assert_eq!(
                    pal.get_cert(&io, slot, bank, idx, Some(&mut out)).await,
                    Err(HsmError::InvalidArg)
                );
                assert!(out.iter().all(|&byte| byte == 0xA5));
            }
        }
    }

    #[tokio::test]
    async fn unavailable_mldsa_bank_rejects_queries_without_affecting_ecc() -> HsmResult<()> {
        let (_, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (tx, _) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, tx);
        pal.init_cert_store().await?;
        pal.cert_store_mut().mldsa = MlDsaCertBank::default();

        assert_eq!(
            pal.get_cert_chain_info(&io, HsmCertSlot::Mfgr, HsmCertBank::MlDsa)
                .await,
            Err(HsmError::UnsupportedCmd)
        );
        for idx in 0..SLOT0_CERT_COUNT {
            assert_eq!(
                pal.get_cert(&io, HsmCertSlot::Mfgr, HsmCertBank::MlDsa, idx, None)
                    .await,
                Err(HsmError::UnsupportedCmd)
            );
            let mut out = [0xA5; MAX_CERT_DER_LEN];
            assert_eq!(
                pal.get_cert(
                    &io,
                    HsmCertSlot::Mfgr,
                    HsmCertBank::MlDsa,
                    idx,
                    Some(&mut out)
                )
                .await,
                Err(HsmError::UnsupportedCmd)
            );
            assert!(out.iter().all(|&byte| byte == 0xA5));
        }
        assert!(
            pal.get_cert(&io, HsmCertSlot::Mfgr, HsmCertBank::Ecc, 0, None)
                .await?
                > 0
        );
        Ok(())
    }

    #[tokio::test]
    async fn ecc_bank_preserves_certificate_query_and_copy() -> HsmResult<()> {
        let (_, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (tx, _) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, tx);
        pal.init_cert_store().await?;

        let len = pal
            .get_cert(&io, HsmCertSlot::Mfgr, HsmCertBank::Ecc, 0, None)
            .await?;
        let mut out = [0xA5; MAX_CERT_DER_LEN];
        assert_eq!(
            pal.get_cert(&io, HsmCertSlot::Mfgr, HsmCertBank::Ecc, 0, Some(&mut out))
                .await?,
            len
        );
        assert_eq!(
            &out[..len],
            pal.cert_store()
                .shared_cert(0)
                .ok_or(HsmError::InternalError)?
        );
        assert!(out[len..].iter().all(|&byte| byte == 0xA5));
        Ok(())
    }

    #[tokio::test]
    async fn mldsa_bank_returns_its_own_chain() -> HsmResult<()> {
        let (_, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let (tx, _) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, tx);
        pal.init_cert_store().await?;

        for idx in 0..SLOT0_CERT_COUNT - 1 {
            let len = pal
                .get_cert(&io, HsmCertSlot::Mfgr, HsmCertBank::MlDsa, idx, None)
                .await?;
            // An ML-DSA-87 signature alone exceeds the P-384 bound.
            assert!(len > MAX_CERT_DER_LEN);
            let mut out = vec![0xA5; len + 1];
            assert_eq!(
                pal.get_cert(
                    &io,
                    HsmCertSlot::Mfgr,
                    HsmCertBank::MlDsa,
                    idx,
                    Some(&mut out)
                )
                .await?,
                len
            );
            assert_eq!(out[0], 0x30);
            assert_eq!(out[len], 0xA5);
            assert_ne!(
                Some(&out[..len]),
                pal.cert_store().shared_cert(idx),
                "banks must not alias"
            );
            assert_eq!(
                pal.get_cert(
                    &io,
                    HsmCertSlot::Mfgr,
                    HsmCertBank::MlDsa,
                    idx,
                    Some(&mut out[..len - 1])
                )
                .await,
                Err(HsmError::InvalidArg)
            );
        }
        // Partition 0 is unallocated: no leaf in either bank.
        assert_eq!(
            pal.get_cert(&io, HsmCertSlot::Mfgr, HsmCertBank::MlDsa, 3, None)
                .await,
            Err(HsmError::InvalidArg)
        );
        Ok(())
    }
}
