// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Types for X.509 certificate chain validation.
//!
//! All types are `no_std`-compatible and zero-allocation. Parsed
//! certificate fields borrow from the input DER buffer.

use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmMlDsaParamSet;
use tsra_fw_hsm_pal_traits::HsmRsaKey;

/// Supported certificate signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlgo {
    /// ECDSA with SHA-256 (OID 1.2.840.10045.4.3.2).
    EcdsaSha256,

    /// ECDSA with SHA-384 (OID 1.2.840.10045.4.3.3).
    EcdsaSha384,

    /// ECDSA with SHA-512 (OID 1.2.840.10045.4.3.4).
    EcdsaSha512,

    /// RSASSA-PKCS1-v1_5 with SHA-256, SHA-384, or SHA-512.
    RsaPkcs1(HsmHashAlgo),

    /// RSASSA-PSS with SHA-2 and the same digest for MGF1.
    RsaPss(PssParams),

    /// Pure ML-DSA with an empty context string.
    MlDsa(HsmMlDsaParamSet),
}

impl SigAlgo {
    /// Return the underlying hash algorithm of this signature
    /// algorithm.
    ///
    /// Used by the chain validator to know which digest to compute
    /// over the TBSCertificate before invoking ECDSA or RSA verify.
    ///
    /// # Parameters
    /// * `self` — the signature algorithm variant (consumed by value
    ///   since `SigAlgo` is `Copy`).
    ///
    /// # Returns
    /// The matching SHA-2 algorithm, or `None` for pure ML-DSA.
    pub fn hash_algo(self) -> Option<HsmHashAlgo> {
        match self {
            SigAlgo::EcdsaSha256 => Some(HsmHashAlgo::Sha256),
            SigAlgo::EcdsaSha384 => Some(HsmHashAlgo::Sha384),
            SigAlgo::EcdsaSha512 => Some(HsmHashAlgo::Sha512),
            SigAlgo::RsaPkcs1(hash) => Some(hash),
            SigAlgo::RsaPss(params) => Some(params.hash),
            SigAlgo::MlDsa(_) => None,
        }
    }
}

/// Supported RSASSA-PSS parameters (RFC 4055).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PssParams {
    /// SHA-2 digest used for the message and MGF1.
    pub hash: HsmHashAlgo,
    /// Signature salt length, or minimum salt length on a restricted key.
    pub salt_len: u16,
}

/// RSA public key borrowed from a PKCS#1 RSAPublicKey.
#[derive(Debug, Clone, Copy)]
pub struct RsaPubKey<'a> {
    /// Modulus-size selector.
    pub key_size: HsmRsaKey,
    /// Big-endian modulus without the DER sign-padding byte.
    pub modulus: &'a HsmDmaBuf,
    /// Big-endian public exponent, at most four bytes.
    pub exponent: &'a HsmDmaBuf,
    /// Complete DER RSAPublicKey.
    pub encoded: &'a HsmDmaBuf,
    /// Whether SubjectPublicKeyInfo restricts this key to PSS.
    pub pss_only: bool,
    /// Optional PSS key restrictions; an absent value is unrestricted.
    pub pss_params: Option<PssParams>,
}

/// Public key borrowed from a certificate's SubjectPublicKeyInfo.
#[derive(Debug, Clone, Copy)]
pub enum PubKey<'a> {
    /// NIST P-256, P-384, or P-521.
    Ec(EcPubKey<'a>),
    /// RSA-2048, RSA-3072, or RSA-4096.
    Rsa(RsaPubKey<'a>),
    /// An encoded FIPS 204 public key.
    MlDsa {
        /// ML-DSA parameter set.
        param: HsmMlDsaParamSet,
        /// Raw public-key bytes.
        key: &'a HsmDmaBuf,
    },
}

impl PubKey<'_> {
    /// Public-key bytes: EC `X || Y`, DER RSAPublicKey, or raw ML-DSA.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ec(key) => key.point,
            Self::Rsa(key) => key.encoded,
            Self::MlDsa { key, .. } => key,
        }
    }
}

/// ECC public key extracted from a certificate's SubjectPublicKeyInfo.
///
/// `point` is the uncompressed EC point **without** the 0x04 prefix —
/// just the raw X || Y coordinate bytes, matching the format expected
/// by [`HsmEcc::ecc_verify`].
#[derive(Debug, Clone, Copy)]
pub struct EcPubKey<'a> {
    /// The named curve.
    pub curve: HsmEccCurve,

    /// Raw X || Y coordinates (no 0x04 prefix), in DMA-accessible memory.
    pub point: &'a HsmDmaBuf,
}

/// BasicConstraints extension fields.
#[derive(Debug, Clone, Copy)]
pub struct BasicConstraints {
    /// `true` if this certificate is a CA certificate.
    pub ca: bool,

    /// Maximum number of intermediate CA certificates that may
    /// follow this certificate in a valid chain. `None` means
    /// unlimited.
    pub path_len: Option<u16>,
}

/// KeyUsage bit positions (RFC 5280 §4.2.1.3).
///
/// Each constant is a 16-bit mask matching the layout used in
/// [`CertInfo::key_usage`]: the BIT STRING is loaded big-endian into
/// a `u16`, with byte 0 in the high byte and byte 1 in the low byte.
/// Use bitwise-AND to test whether a usage is asserted, e.g.
/// `key_usage & key_usage::KEY_CERT_SIGN != 0`.
pub mod key_usage {
    /// `digitalSignature` (bit 0): the subject public key may be
    /// used to verify digital signatures other than certificate or
    /// CRL signatures.
    pub const DIGITAL_SIGNATURE: u16 = 0x8000;

    /// `nonRepudiation` / `contentCommitment` (bit 1).
    pub const NON_REPUDIATION: u16 = 0x4000;

    /// `keyEncipherment` (bit 2).
    pub const KEY_ENCIPHERMENT: u16 = 0x2000;

    /// `dataEncipherment` (bit 3).
    pub const DATA_ENCIPHERMENT: u16 = 0x1000;

    /// `keyAgreement` (bit 4).
    pub const KEY_AGREEMENT: u16 = 0x0800;

    /// `keyCertSign` (bit 5): the subject public key may sign
    /// certificates. Required on intermediate and root CA
    /// certificates.
    pub const KEY_CERT_SIGN: u16 = 0x0400;

    /// `cRLSign` (bit 6): the subject public key may sign
    /// Certificate Revocation Lists.
    pub const CRL_SIGN: u16 = 0x0200;

    /// `encipherOnly` (bit 7), meaningful only with `keyAgreement`.
    pub const ENCIPHER_ONLY: u16 = 0x0100;

    /// `decipherOnly` (bit 8), meaningful only with `keyAgreement`.
    pub const DECIPHER_ONLY: u16 = 0x0080;
}

/// Fields extracted from one DER-encoded X.509 certificate.
///
/// All byte slices borrow from the input `HsmDmaBuf`. The struct is
/// valid only as long as the DER buffer it was parsed from.
#[derive(Debug)]
pub struct CertInfo<'a> {
    /// Raw DER bytes of the TBSCertificate SEQUENCE (tag + length +
    /// value). This is the data that was signed and must be hashed
    /// for signature verification. Points into DMA-accessible memory.
    pub tbs_raw: &'a HsmDmaBuf,

    /// Signature algorithm used to sign this certificate.
    pub sig_algo: SigAlgo,

    /// Signature bytes from the certificate's signatureValue BIT STRING.
    /// ECDSA uses a DER SEQUENCE of two INTEGERs; RSA and ML-DSA use raw bytes.
    /// Points into DMA-accessible memory.
    pub signature: &'a HsmDmaBuf,

    /// Raw DER encoding of the issuer Name SEQUENCE.
    /// Used for byte-exact name chaining comparison.
    /// Points into DMA-accessible memory.
    pub issuer_raw: &'a HsmDmaBuf,

    /// Raw DER encoding of the subject Name SEQUENCE.
    /// Used for byte-exact name chaining comparison.
    /// Points into DMA-accessible memory.
    pub subject_raw: &'a HsmDmaBuf,

    /// The certificate's public key.
    pub pub_key: PubKey<'a>,

    /// Complete DER SubjectPublicKeyInfo, used to retain issuer metadata.
    pub spki_raw: &'a HsmDmaBuf,

    /// Authority Key Identifier keyIdentifier value, if present.
    pub akid: Option<&'a [u8]>,

    /// Subject Key Identifier value, if present.
    pub skid: Option<&'a [u8]>,

    /// BasicConstraints extension, if present.
    pub basic_constraints: Option<BasicConstraints>,

    /// KeyUsage extension as a big-endian bit field, if present.
    /// Use constants from [`key_usage`] to test individual bits.
    pub key_usage: Option<u16>,
}

/// Result of processing one certificate in the chain.
#[derive(Debug)]
pub enum StepResult<'a> {
    /// Chain validation is not yet complete. The caller should
    /// provide the next certificate.
    NeedNext,

    /// The entire chain has been validated. The leaf certificate's
    /// public key and subject are available.
    Valid {
        /// The validated leaf certificate's public key.
        leaf_pub_key: &'a PubKey<'a>,

        /// Raw DER of the leaf certificate's subject Name.
        leaf_subject: &'a HsmDmaBuf,
    },

    /// Validation failed.
    Invalid(HsmError),
}
