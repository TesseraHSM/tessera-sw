// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host operation-report verification and explicitly software-authority signing.

use anyhow::Context;
use anyhow::Result;
use minicbor::Decoder;
use minicbor::Encoder;
use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EccPublicKey;
use tsra_crypto::EcdsaAlgo;
use tsra_crypto::ExportableKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_crypto::HpkePublicKey;
use tsra_crypto::HpkeSuite;
use tsra_crypto::ImportableKey;
use tsra_crypto::Signer;
use tsra_crypto::VerifyOp;

pub const SD_HEADER_LEN: usize = 161;
pub const SD_ENVELOPE_LEN: usize = 322;
pub const SD_SIGNED_ENVELOPE_LEN: usize = 431;
const TRANSFER_PROTECTED_HEADER: &[u8] = b"\xa1\x01\x38\x22";
const SD_EXTERNAL_AAD: &[u8; 32] = b"TSRA-SdBackup-v1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const MAGIC: &[u8] = b"TSRA-XFER\x01\x02";
/// Sealed 48-byte BKS3 plus its AES-256-GCM tag.
const SEALED_LEN: usize = 48 + 16;
/// Masked sealing-key overhead: AEAD envelope header, IV, metadata and tag.
const MASKED_KEY_OVERHEAD: usize = 232;
const P384_RAW_LEN: usize = 96;
const MLKEM1024_PUBLIC_LEN: usize = 1568;
const MLKEM1024_P384_PUBLIC_LEN: usize = MLKEM1024_PUBLIC_LEN + 1 + P384_RAW_LEN;

/// Security-domain transfer KEM, selected by the recipient sealing key.
///
/// Recipient keys are passed as raw P-384 `X || Y` (96 bytes) or as the
/// ML-KEM-1024 (1568 bytes) / MLKEM1024-P384 (1665 bytes) HPKE public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferKem {
    /// DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM.
    P384,
    /// HPKE-13: ML-KEM-1024, SHAKE256, AES-256-GCM.
    MlKem1024,
    /// HPKE-10: MLKEM1024-P384, SHAKE256, AES-256-GCM.
    MlKem1024P384,
}

impl TransferKem {
    /// Every supported transfer KEM.
    pub const ALL: [Self; 3] = [Self::P384, Self::MlKem1024, Self::MlKem1024P384];

    /// Command-line name.
    pub fn name(self) -> &'static str {
        match self {
            Self::P384 => "p384",
            Self::MlKem1024 => "mlkem1024",
            Self::MlKem1024P384 => "mlkem1024-p384",
        }
    }

    /// Parse a command-line name.
    pub fn from_name(name: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kem| kem.name() == name)
            .with_context(|| {
                format!("unknown KEM {name}; expected p384, mlkem1024 or mlkem1024-p384")
            })
    }

    /// Sealing key props bit length that selects this KEM.
    pub fn sealing_key_bits(self) -> u32 {
        match self {
            Self::P384 => 384,
            Self::MlKem1024 => 1024,
            Self::MlKem1024P384 => 1408,
        }
    }

    /// HPKE suite sealing to this KEM.
    pub fn suite(self) -> HpkeSuite {
        match self {
            Self::P384 => HpkeSuite::DHKemP384Sha384AesGcm256,
            Self::MlKem1024 => HpkeSuite::MlKem1024Shake256AesGcm256,
            Self::MlKem1024P384 => HpkeSuite::MlKem1024P384Shake256AesGcm256,
        }
    }

    /// Recipient key length in this module's representation.
    pub fn recipient_len(self) -> usize {
        match self {
            Self::P384 => P384_RAW_LEN,
            Self::MlKem1024 => MLKEM1024_PUBLIC_LEN,
            Self::MlKem1024P384 => MLKEM1024_P384_PUBLIC_LEN,
        }
    }

    /// HPKE encapsulation length.
    pub fn enc_len(self) -> usize {
        self.suite().nenc()
    }

    /// Complete SD envelope length.
    pub fn envelope_len(self) -> usize {
        SD_HEADER_LEN + self.enc_len() + SEALED_LEN
    }

    /// Private seed length inside a masked sealing key.
    pub fn seed_len(self) -> usize {
        match self {
            Self::P384 => 48,
            Self::MlKem1024 => 64,
            Self::MlKem1024P384 => 32,
        }
    }

    /// Masked sealing-key length.
    pub fn masked_key_len(self) -> usize {
        MASKED_KEY_OVERHEAD + self.seed_len()
    }

    /// KEM of a masked sealing key, identified by its length.
    pub fn from_masked_key_len(len: usize) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|kem| kem.masked_key_len() == len)
            .context("invalid masked sealing-key length")
    }

    /// COSE `alg` of an AKP key report; `None` for EC2 P-384.
    pub fn cose_alg(self) -> Option<i32> {
        match self {
            Self::P384 => None,
            Self::MlKem1024 => Some(-65537),
            Self::MlKem1024P384 => Some(-65538),
        }
    }

    fn suite_bytes(self) -> [u8; 6] {
        let suite = self.suite();
        let [k0, k1] = suite.kem_id().to_be_bytes();
        let [d0, d1] = suite.kdf_id().to_be_bytes();
        let [a0, a1] = suite.aead_id().to_be_bytes();
        [k0, k1, d0, d1, a0, a1]
    }

    fn key_id_domain(self) -> &'static [u8] {
        match self {
            Self::P384 => b"",
            Self::MlKem1024 => b"TSRA-MLKEM1024-KEY-v1",
            Self::MlKem1024P384 => b"TSRA-MLKEM1024-P384-KEY-v1",
        }
    }

    /// Identify and shape-check a recipient key by its length. ECC points
    /// are validated; ML-KEM coefficients are checked when sealing.
    pub fn from_recipient(recipient: &[u8]) -> Result<Self> {
        let kem = Self::ALL
            .into_iter()
            .find(|kem| kem.recipient_len() == recipient.len())
            .context("unsupported recipient key length")?;
        if kem == Self::MlKem1024P384 {
            anyhow::ensure!(
                recipient[MLKEM1024_PUBLIC_LEN] == 4,
                "hybrid recipient must carry an uncompressed P-384 point"
            );
            p384_point(&recipient[MLKEM1024_PUBLIC_LEN + 1..])?;
        } else if kem == Self::P384 {
            p384_point(recipient)?;
        }
        Ok(kem)
    }

    /// Run `f` with the recipient as an HPKE public key.
    pub fn with_hpke_public<R>(
        recipient: &[u8],
        f: impl FnOnce(TransferKem, HpkePublicKey<'_>) -> Result<R>,
    ) -> Result<R> {
        match Self::from_recipient(recipient)? {
            Self::P384 => f(Self::P384, HpkePublicKey::Ecc(&p384_point(recipient)?)),
            Self::MlKem1024 => f(Self::MlKem1024, HpkePublicKey::MlKem1024(recipient)),
            Self::MlKem1024P384 => f(Self::MlKem1024P384, HpkePublicKey::MlKem1024P384(recipient)),
        }
    }
}

fn p384_point(raw: &[u8]) -> Result<EccPublicKey> {
    anyhow::ensure!(raw.len() == P384_RAW_LEN, "expected raw P-384 X||Y");
    Ok(EccPublicKey::from_coordinates(
        EccCurve::P384,
        &raw[..48],
        &raw[48..],
    )?)
}

pub struct SdTransferReport<'a> {
    pub source_pid_spki_thumbprint: &'a [u8],
    pub recipient_spki_thumbprint: &'a [u8],
    pub policy_hash: &'a [u8],
    pub envelope: &'a [u8],
    signature: &'a [u8],
}

pub fn sha384(bytes: &[u8]) -> Result<[u8; 48]> {
    let mut digest = [0; 48];
    HashAlgo::sha384().hash(bytes, Some(&mut digest))?;
    Ok(digest)
}

pub fn p384_spki_from_raw(raw: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(raw.len() == 96, "signer/recipient must be raw P-384 X||Y");
    Ok(EccPublicKey::from_coordinates(EccCurve::P384, &raw[..48], &raw[48..])?.to_vec()?)
}

pub fn p384_raw_from_spki(spki: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(spki.len() == 120, "expected canonical P-384 DER SPKI");
    let public = EccPublicKey::from_bytes(spki)?;
    anyhow::ensure!(public.curve() == EccCurve::P384, "expected P-384");
    let (x, y) = public.coord_vec()?;
    let raw = [x, y].concat();
    anyhow::ensure!(p384_spki_from_raw(&raw)? == spki, "noncanonical P-384 SPKI");
    Ok(raw)
}

pub fn sd_spki_thumbprint(raw: &[u8]) -> Result<[u8; 48]> {
    sha384(&p384_spki_from_raw(raw)?)
}

/// Transfer key ID of a recipient key of any supported KEM.
pub fn recipient_key_id(recipient: &[u8]) -> Result<[u8; 48]> {
    match TransferKem::from_recipient(recipient)? {
        TransferKem::P384 => sd_spki_thumbprint(recipient),
        kem => sha384(&[kem.key_id_domain(), recipient].concat()),
    }
}

pub fn sd_header(signer: &[u8], recipient: &[u8], policy: &[u8]) -> Result<Vec<u8>> {
    let kem = TransferKem::from_recipient(recipient)?;
    Ok([
        MAGIC,
        &kem.suite_bytes(),
        &sd_spki_thumbprint(signer)?,
        &recipient_key_id(recipient)?,
        &sha384(policy)?,
    ]
    .concat())
}

/// Check an HPKE Base SD envelope's framing and return its KEM.
pub fn validate_sd_envelope(envelope: &[u8]) -> Result<TransferKem> {
    let kem = envelope
        .get(MAGIC.len()..MAGIC.len() + 6)
        .filter(|_| envelope.starts_with(MAGIC))
        .and_then(|suite| {
            TransferKem::ALL
                .into_iter()
                .find(|kem| kem.suite_bytes() == suite)
        })
        .context("invalid HPKE Base SD envelope (legacy Auth backups are unsupported)")?;
    anyhow::ensure!(
        envelope.len() == kem.envelope_len(),
        "invalid {} SD envelope length",
        kem.name()
    );
    let enc = &envelope[SD_HEADER_LEN..SD_HEADER_LEN + kem.enc_len()];
    let ecc = match kem {
        TransferKem::P384 => Some(enc),
        TransferKem::MlKem1024 => None,
        TransferKem::MlKem1024P384 => Some(&enc[MLKEM1024_PUBLIC_LEN..]),
    };
    if let Some(ecc) = ecc {
        anyhow::ensure!(ecc[0] == 4, "SD envelope ECC share must be uncompressed");
        p384_point(&ecc[1..])?;
    }
    Ok(kem)
}

pub fn parse_sd_transfer_report(bytes: &[u8]) -> Result<SdTransferReport<'_>> {
    let mut outer = Decoder::new(bytes);
    anyhow::ensure!(
        outer.tag()? == minicbor::data::Tag::Unassigned(18),
        "expected COSE_Sign1"
    );
    anyhow::ensure!(outer.array()? == Some(4), "invalid COSE array");
    anyhow::ensure!(
        outer.bytes()? == TRANSFER_PROTECTED_HEADER,
        "unsupported protected header"
    );
    anyhow::ensure!(outer.map()? == Some(0), "unexpected unprotected claims");
    let payload = outer.bytes()?;
    let signature = outer.bytes()?;
    anyhow::ensure!(
        signature.len() == 96 && outer.position() == bytes.len(),
        "invalid COSE signature or trailing data"
    );
    validate_sd_envelope(payload)?;
    Ok(SdTransferReport {
        source_pid_spki_thumbprint: &payload[17..65],
        recipient_spki_thumbprint: &payload[65..113],
        policy_hash: &payload[113..161],
        envelope: payload,
        signature,
    })
}

fn signature_input(payload: &[u8]) -> Result<Vec<u8>> {
    let mut input = Encoder::new(Vec::new());
    input
        .array(4)?
        .str("Signature1")?
        .bytes(TRANSFER_PROTECTED_HEADER)?
        .bytes(SD_EXTERNAL_AAD)?
        .bytes(payload)?;
    Ok(input.into_writer())
}

pub fn verify_sd_report_signature<'a>(
    bytes: &'a [u8],
    signer: &[u8],
) -> Result<SdTransferReport<'a>> {
    let report = parse_sd_transfer_report(bytes)?;
    anyhow::ensure!(
        report.source_pid_spki_thumbprint == sd_spki_thumbprint(signer)?,
        "operation signer mismatch"
    );
    let key = EccPublicKey::from_coordinates(EccCurve::P384, &signer[..48], &signer[48..])?;
    anyhow::ensure!(
        EcdsaAlgo::new(HashAlgo::sha384()).verify(
            &key,
            &signature_input(report.envelope)?,
            report.signature
        )?,
        "invalid operation report signature"
    );
    Ok(report)
}

/// Signature and transfer binding only; this does not authenticate SA identity
/// or assert trusted HSM provenance. Callers authenticate PID chains separately.
pub fn verify_sd_transfer_report<'a>(
    bytes: &'a [u8],
    signer: &[u8],
    policy: &[u8],
    recipient: Option<&[u8]>,
) -> Result<SdTransferReport<'a>> {
    let report = verify_sd_report_signature(bytes, signer)?;
    anyhow::ensure!(
        report.policy_hash == sha384(policy)?,
        "transferred SD policy mismatch"
    );
    if let Some(recipient) = recipient {
        anyhow::ensure!(
            report.recipient_spki_thumbprint == recipient_key_id(recipient)?,
            "operation recipient mismatch"
        );
    }
    Ok(report)
}

/// Software authority signature-only report; never supplies hardware identity chains.
pub fn sign_software_sd_transfer(
    key: &EccPrivateKey,
    signer: &[u8],
    recipient: &[u8],
    policy: &[u8],
    envelope: &[u8],
) -> Result<Vec<u8>> {
    validate_sd_envelope(envelope)?;
    anyhow::ensure!(
        envelope[..SD_HEADER_LEN] == sd_header(signer, recipient, policy)?,
        "software report header mismatch"
    );
    let signature = Signer::sign_vec(
        &mut EcdsaAlgo::new(HashAlgo::sha384()),
        key,
        &signature_input(envelope)?,
    )?;
    let mut report = Encoder::new(Vec::new());
    report
        .tag(minicbor::data::Tag::Unassigned(18))?
        .array(4)?
        .bytes(TRANSFER_PROTECTED_HEADER)?
        .map(0)?
        .bytes(envelope)?
        .bytes(&signature)?;
    let report = report.into_writer();
    verify_sd_transfer_report(&report, signer, policy, Some(recipient))?;
    Ok(report)
}
