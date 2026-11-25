// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deterministic PTA subject shared by CSR generation, certificate issuance,
//! and on-demand PID certificates. PTA certificates preserve this exact DER
//! subject and use SHA-1 of the SEC1 public key as their SKID.

use tsra_fw_core_crypto_x509_builder::cert_builder;
use tsra_fw_core_crypto_x509_builder::cert_builder::LeafCertParams;
use tsra_fw_core_crypto_x509_builder::cert_builder::MlDsa87Signer;
use tsra_fw_core_crypto_x509_builder::csr;
use tsra_fw_core_crypto_x509_chain::key_usage;
use tsra_fw_core_crypto_x509_chain::CertInfo;
use tsra_fw_core_crypto_x509_chain::PubKey;
use tsra_fw_core_crypto_x509_chain::MLDSA87_PUB_KEY_LEN;
use tsra_fw_hsm_pal_traits::HsmCertBank;
use tsra_fw_hsm_pal_traits::HsmCertChainInfo;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmMlDsaParamSet;
use tsra_fw_hsm_pal_traits::HsmMlDsaPct;
use tsra_fw_hsm_pal_traits::HsmMlDsaPrivKey;
use tsra_fw_hsm_pal_traits::HsmMlSeedSrc;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmPartState;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use super::mldsa_generate_key::MLDSA_SEED_LEN;
use crate::part_state;

const P384_PRIVATE_KEY_LEN: usize = 48;
const P384_RAW_PUBLIC_KEY_LEN: usize = 96;
const P384_SEC1_PUBLIC_KEY_LEN: usize = P384_RAW_PUBLIC_KEY_LEN + 1;
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
const SHA1_DIGEST_LEN: usize = 20;
const SHA256_DIGEST_LEN: usize = 32;
const SHA384_DIGEST_LEN: usize = 48;
const CERT_SERIAL_LEN: usize = 20;
const CERT_SUBJECT_CN_LEN: usize = 32;
const CERT_NOT_BEFORE: &[u8; 15] = b"20250101000000Z";
const CERT_NOT_AFTER: &[u8; 15] = b"20350101000000Z";
const PID_SUBJECT_CN: &[u8] = b"TSRA Partition";

/// Fixed PTA commonName prefix. The PTAID hex is appended to it inside the
/// single `commonName`, so the PTA subject is a one-RDN DN.
pub const PTA_SUBJECT_CN: &str = "Tessera Integrated HSM PTA";
/// Domain-separation label for SHA-384(label || SEC1 public key).
pub const PTAID_LABEL: &[u8] = b"TSRA-PTAID-v1";
/// Digest bytes encoded as hexadecimal inside the subject commonName.
pub const PTAID_LEN: usize = 16;

const _: () = assert!(PTA_SUBJECT_CN.len() + 1 + PTAID_LEN * 2 <= csr::SUBJECT_CN_LEN);
const _: () = assert!(PID_SUBJECT_CN.len() <= CERT_SUBJECT_CN_LEN);

/// Fixed DER prefix of the single-`commonName(64)` Name SEQUENCE shared by
/// the PTA subject and the on-demand PID leaf's issuer:
/// `SEQUENCE { SET { SEQUENCE { OID id-at-commonName, UTF8String(64) } } }`.
/// The 64 CN bytes follow this prefix.
const PTA_SUBJECT_DER_PREFIX: [u8; 13] = [
    0x30, 0x4b, 0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x40,
];
/// Total length of the PTA subject Name SEQUENCE DER (prefix + CN bytes).
const PTA_SUBJECT_DER_LEN: usize = PTA_SUBJECT_DER_PREFIX.len() + csr::SUBJECT_CN_LEN;

fn fixed_size<const N: usize>(bytes: &[u8]) -> HsmResult<&[u8; N]> {
    bytes.try_into().map_err(|_| HsmError::InternalError)
}

async fn sec1_public_key<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    key_id: HsmKeyId,
) -> HsmResult<&'a mut HsmDmaBuf> {
    // The SEC1 tag precedes a word-aligned PKA output point.
    let public_key = alloc
        .dma_alloc(P384_SEC1_PUBLIC_KEY_LEN + 3)?
        .split_at_mut(3)
        .1;
    public_key[0] = SEC1_UNCOMPRESSED_TAG;
    part_state::key_id_pub_key(pal, io, key_id, public_key.split_at_mut(1).1).await?;
    Ok(public_key)
}

async fn hash<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    algorithm: HsmHashAlgo,
    input: &HsmDmaBuf,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let digest = alloc.dma_alloc(algorithm.digest_len())?;
    pal.hash(io, algorithm, input, HsmDigestForm::Standard, Some(digest))
        .await?;
    Ok(digest)
}

/// The partition's PTA vault key, by algorithm.
#[derive(Clone, Copy)]
pub(crate) enum PtaKey {
    /// P-384 private scalar (`PTA_KEY_ID`).
    Ecc(HsmKeyId),
    /// ML-DSA-87 seed (`PTA_MLDSA_SEED_KEY_ID`).
    MlDsa87(HsmKeyId),
}

impl PtaKey {
    /// Certificate bank of the slot-2 PID leaf this PTA issues.
    pub(crate) fn bank(self) -> HsmCertBank {
        match self {
            Self::Ecc(_) => HsmCertBank::Ecc,
            Self::MlDsa87(_) => HsmCertBank::MlDsa,
        }
    }
}

/// The partition's provisioned PTA key.
pub(crate) fn pta_key<P: HsmPal>(pal: &P, io: &P::Io) -> HsmResult<PtaKey> {
    match part_state::part_pta_key_id(pal, io) {
        Ok(id) => return Ok(PtaKey::Ecc(id)),
        Err(HsmError::PartPropNotFound) => {}
        Err(e) => return Err(e),
    }
    part_state::part_pta_mldsa_seed_key_id(pal, io).map(PtaKey::MlDsa87)
}

/// Re-derive the ML-DSA-87 public key of the vaulted seed `seed_key_id`.
///
/// The expanded private key is scratch in a nested scope, so only the
/// public key remains allocated from `alloc`.
pub(crate) async fn mldsa87_public_key<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    seed_key_id: HsmKeyId,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let vaulted = pal.vault_key(io, seed_key_id)?;
    if vaulted.len() != MLDSA_SEED_LEN {
        return Err(HsmError::InternalError);
    }
    let public_key = alloc.dma_alloc(HsmMlDsaParamSet::MlDsa87.pk_len())?;
    pal.alloc_scoped_async(io, async |scope| -> HsmResult<()> {
        let seed = scope.dma_alloc(MLDSA_SEED_LEN)?;
        seed.copy_from_slice(vaulted);
        let private_key = scope.dma_alloc(HsmMlDsaParamSet::MlDsa87.sk_len())?;
        pal.mldsa_gen_keypair(
            io,
            HsmMlDsaParamSet::MlDsa87,
            HsmMlSeedSrc::Caller,
            HsmMlDsaPct::None,
            seed,
            Some((private_key, &mut *public_key)),
        )
        .await?;
        Ok(())
    })
    .await?;
    Ok(public_key)
}

/// PTA public key in its PTAID/SKID form: the SEC1 uncompressed point for
/// P-384 or the raw encoded key for ML-DSA-87.
async fn pta_public_key<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    key: PtaKey,
) -> HsmResult<&'a mut HsmDmaBuf> {
    match key {
        PtaKey::Ecc(id) => sec1_public_key(pal, io, alloc, id).await,
        PtaKey::MlDsa87(id) => mldsa87_public_key(pal, io, alloc, id).await,
    }
}

/// Subject `commonName` and SKID (SHA-1 of the PTAID-form key) for PTA
/// public key `public_key`, hashed in a nested scope.
async fn pta_names<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    public_key: &HsmDmaBuf,
) -> HsmResult<([u8; csr::SUBJECT_CN_LEN], [u8; SHA1_DIGEST_LEN])> {
    pal.alloc_scoped_async(io, async |scope| {
        let cn = subject_cn_for_key(pal, io, scope, public_key).await?;
        let skid = *fixed_size::<SHA1_DIGEST_LEN>(
            hash(pal, io, scope, HsmHashAlgo::Sha1, public_key).await?,
        )?;
        Ok((cn, skid))
    })
    .await
}

/// The identity a partition's PTA certificate must carry.
pub(crate) struct PtaIdentity<'a> {
    key: PtaKey,
    public_key: &'a HsmDmaBuf,
    subject_cn: [u8; csr::SUBJECT_CN_LEN],
    skid: [u8; SHA1_DIGEST_LEN],
}

impl PtaIdentity<'_> {
    /// Algorithm of the provisioned PTA key.
    pub(crate) fn key(&self) -> PtaKey {
        self.key
    }

    /// Whether certificate key `cert_key` is this PTA's public key.
    pub(crate) fn matches(&self, cert_key: &PubKey<'_>) -> bool {
        let expected: &[u8] = self.public_key;
        match (self.key, cert_key) {
            (PtaKey::Ecc(_), PubKey::Ec(ec)) if ec.curve == HsmEccCurve::P384 => {
                expected.get(1..) == Some(&**ec.point)
            }
            (
                PtaKey::MlDsa87(_),
                PubKey::MlDsa {
                    param: HsmMlDsaParamSet::MlDsa87,
                    key,
                },
            ) => expected == &***key,
            _ => false,
        }
    }
}

/// Compute the partition PTA identity (key, subject CN and SKID).
///
/// Only the public key stays allocated from `alloc`; ML-DSA-87 expansion
/// and hashing scratch are released before returning.
pub(crate) async fn pta_identity<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
) -> HsmResult<PtaIdentity<'a>> {
    let key = pta_key(pal, io)?;
    let public_key: &HsmDmaBuf = pta_public_key(pal, io, alloc, key).await?;
    let (subject_cn, skid) = pta_names(pal, io, public_key).await?;
    Ok(PtaIdentity {
        key,
        public_key,
        subject_cn,
        skid,
    })
}

/// Enforce the PTA certificate profile that the on-demand slot-2 PID leaf
/// depends on.
///
/// The PID leaf deterministically stamps its issuer DN and authority key
/// identifier from the partition PTA public key (see
/// [`build_pid_certificate`]). A PTA certificate can therefore anchor
/// future PID leaves only when it carries that exact subject DN (the
/// single-`commonName(64)` CSR profile), a SHA-1 subject key identifier of
/// the PTAID-form public key (SEC1 for P-384, raw for ML-DSA-87), and CA /
/// `keyCertSign` constraints. Rejecting a non-conformant PTA at
/// finalization fails fast instead of silently finalizing a partition
/// whose slot-2 PID leaf could never chain to the accepted PTA certificate.
///
/// The caller must already have matched the certificate key against
/// `identity` ([`PtaIdentity::matches`]).
pub(crate) fn validate_pta_profile(
    identity: &PtaIdentity<'_>,
    pta_cert: &CertInfo<'_>,
) -> HsmResult<()> {
    // Subject DN must byte-match the deterministic single-CN(64) profile
    // the PID leaf stamps as its issuer.
    let mut expected_subject = [0u8; PTA_SUBJECT_DER_LEN];
    expected_subject[..PTA_SUBJECT_DER_PREFIX.len()].copy_from_slice(&PTA_SUBJECT_DER_PREFIX);
    expected_subject[PTA_SUBJECT_DER_PREFIX.len()..].copy_from_slice(&identity.subject_cn);
    if **pta_cert.subject_raw != expected_subject[..] {
        return Err(HsmError::PartFinalPtaMismatch);
    }

    // The SKID is the value the PID leaf stamps as its authority key
    // identifier.
    if pta_cert.skid != Some(&identity.skid[..]) {
        return Err(HsmError::PartFinalPtaMismatch);
    }

    // The PTA must be a CA authorized to sign the PID leaf.
    match pta_cert.basic_constraints {
        Some(constraints) if constraints.ca => {}
        _ => return Err(HsmError::PartFinalPtaMismatch),
    }
    match pta_cert.key_usage {
        Some(bits) if bits & key_usage::KEY_CERT_SIGN != 0 => {}
        _ => return Err(HsmError::PartFinalPtaMismatch),
    }

    Ok(())
}

/// Leaf serial bound to the PID key via its SKID, with a positive leading
/// byte (bit 7 clear, bit 6 set) for a conformant DER INTEGER, so distinct
/// PID keys never share an issuer-and-serial identity across partition
/// resets.
fn pid_serial(subject_key_id: &[u8; SHA1_DIGEST_LEN]) -> [u8; CERT_SERIAL_LEN] {
    let mut serial_number = *subject_key_id;
    serial_number[0] = (serial_number[0] & 0x3f) | 0x40;
    serial_number
}

fn pid_subject_cn() -> [u8; CERT_SUBJECT_CN_LEN] {
    let mut subject_cn = [b' '; CERT_SUBJECT_CN_LEN];
    subject_cn[..PID_SUBJECT_CN.len()].copy_from_slice(PID_SUBJECT_CN);
    subject_cn
}

/// Build the PID leaf of the PTA's algorithm, signed by PTA `pta`.
///
/// Ordered for the per-IO DMA budget: the PTA names are computed (and their
/// key-expansion scratch released) first, the PID public key is derived
/// next, and only then is the output allocated.
async fn build_pid_certificate<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    pta: PtaKey,
) -> HsmResult<&'p HsmDmaBuf> {
    let (issuer_cn, authority_key_id) = pal
        .alloc_scoped_async(io, async |alloc| {
            let pta_public_key = pta_public_key(pal, io, alloc, pta).await?;
            pta_names(pal, io, pta_public_key).await
        })
        .await?;

    let (pid, public_key_len) = match pta {
        PtaKey::Ecc(_) => (
            PtaKey::Ecc(part_state::part_id_key_id(pal, io)?),
            P384_SEC1_PUBLIC_KEY_LEN,
        ),
        PtaKey::MlDsa87(_) => (
            PtaKey::MlDsa87(part_state::part_id_mldsa_seed_key_id(pal, io)?),
            HsmMlDsaParamSet::MlDsa87.pk_len(),
        ),
    };
    let public_key = pal.dma_alloc(io, public_key_len)?;
    let subject_key_id = pal
        .alloc_scoped_async(io, async |alloc| -> HsmResult<[u8; SHA1_DIGEST_LEN]> {
            let derived = pta_public_key(pal, io, alloc, pid).await?;
            if derived.len() != public_key.len() {
                return Err(HsmError::InternalError);
            }
            public_key.copy_from_slice(derived);
            let skid = hash(pal, io, alloc, HsmHashAlgo::Sha1, derived).await?;
            Ok(*fixed_size::<SHA1_DIGEST_LEN>(skid)?)
        })
        .await?;
    let serial_number = pid_serial(&subject_key_id);
    let subject_cn = pid_subject_cn();

    match pta {
        PtaKey::Ecc(pta_key_id) => {
            let params = LeafCertParams {
                public_key: fixed_size::<P384_SEC1_PUBLIC_KEY_LEN>(public_key)?,
                serial_number: &serial_number,
                not_before: CERT_NOT_BEFORE,
                not_after: CERT_NOT_AFTER,
                issuer_cn: &issuer_cn,
                subject_cn: &subject_cn,
                subject_key_id: &subject_key_id,
                authority_key_id: &authority_key_id,
            };
            let output = pal.dma_alloc(io, ECC_PID_CERT_MAX_LEN)?;
            let len = pal
                .alloc_scoped_async(io, async |alloc| {
                    let key = pal.vault_key(io, pta_key_id)?;
                    if key.len() != P384_PRIVATE_KEY_LEN {
                        return Err(HsmError::InternalError);
                    }
                    let private_key = alloc.dma_alloc(P384_PRIVATE_KEY_LEN)?;
                    private_key.copy_from_slice(key);
                    cert_builder::build_leaf_cert(
                        pal,
                        io,
                        alloc,
                        &params,
                        private_key,
                        Some(output),
                    )
                    .await
                })
                .await?;
            Ok(output.split_at(len).0)
        }
        PtaKey::MlDsa87(pta_seed_key_id) => {
            let params = LeafCertParams {
                public_key: fixed_size::<MLDSA87_PUB_KEY_LEN>(public_key)?,
                serial_number: &serial_number,
                not_before: CERT_NOT_BEFORE,
                not_after: CERT_NOT_AFTER,
                issuer_cn: &issuer_cn,
                subject_cn: &subject_cn,
                subject_key_id: &subject_key_id,
                authority_key_id: &authority_key_id,
            };
            let pta_seed = pal.vault_key(io, pta_seed_key_id)?;
            if pta_seed.len() != MLDSA_SEED_LEN {
                return Err(HsmError::InternalError);
            }
            let signer = MlDsa87Signer::new(pal, HsmMlDsaPrivKey::Seed(pta_seed));
            let len = pal
                .alloc_scoped_async(io, async |alloc| {
                    cert_builder::build_mldsa_leaf_cert(io, alloc, &params, &signer, None).await
                })
                .await?;
            let output = pal.dma_alloc(io, len)?;
            let written = pal
                .alloc_scoped_async(io, async |alloc| {
                    cert_builder::build_mldsa_leaf_cert(io, alloc, &params, &signer, Some(output))
                        .await
                })
                .await?;
            if written != len {
                return Err(HsmError::InternalError);
            }
            Ok(output)
        }
    }
}

/// Derive the PTA subject `commonName`: the fixed PTA name, a separating
/// space, and the lowercase-hex PTAID, space-padded to `csr::SUBJECT_CN_LEN`.
///
/// This single CN is the entire PTA subject DN. The on-demand slot-2 PID
/// leaf stamps it verbatim as its issuer CN (via the shared single-CN
/// `leaf_cert` template), so the leaf's issuer DER byte-matches the PTA
/// certificate's subject DER with no runtime DER manipulation.
pub fn subject_cn(digest: &[u8; 48]) -> [u8; csr::SUBJECT_CN_LEN] {
    let mut cn = [b' '; csr::SUBJECT_CN_LEN];
    cn[..PTA_SUBJECT_CN.len()].copy_from_slice(PTA_SUBJECT_CN.as_bytes());
    let hex = b"0123456789abcdef";
    let base = PTA_SUBJECT_CN.len() + 1;
    for (i, byte) in digest[..PTAID_LEN].iter().enumerate() {
        cn[base + 2 * i] = hex[usize::from(byte >> 4)];
        cn[base + 2 * i + 1] = hex[usize::from(byte & 15)];
    }
    cn
}

/// Derive the PTA subject `commonName` for public key `pub_key`: PTAID =
/// SHA-384(`PTAID_LABEL` || `pub_key`)[..`PTAID_LEN`], where `pub_key` is
/// the SEC1 uncompressed point (P-384) or the raw encoded key (ML-DSA-87).
pub(crate) async fn subject_cn_for_key<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    pub_key: &[u8],
) -> HsmResult<[u8; csr::SUBJECT_CN_LEN]> {
    let input = alloc.dma_alloc(PTAID_LABEL.len() + pub_key.len())?;
    input[..PTAID_LABEL.len()].copy_from_slice(PTAID_LABEL);
    input[PTAID_LABEL.len()..].copy_from_slice(pub_key);
    let digest = alloc.dma_alloc(SHA384_DIGEST_LEN)?;
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        input,
        HsmDigestForm::Standard,
        Some(digest),
    )
    .await?;
    let digest_bytes: &[u8] = digest;
    Ok(subject_cn(fixed_size::<SHA384_DIGEST_LEN>(digest_bytes)?))
}

/// Scratch bound for a PTA-signed P-384 PID leaf.
const ECC_PID_CERT_MAX_LEN: usize = 2048;

/// Generate one PTA-signed PID leaf in `bank` for this request, without
/// caching it. The bank must match the PTA algorithm: a P-384 PTA issues
/// the ECC-bank P-384 PID leaf, an ML-DSA-87 PTA the ML-DSA-bank
/// ML-DSA-87 PID leaf.
pub(crate) async fn pid_certificate<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    bank: HsmCertBank,
) -> HsmResult<&'p HsmDmaBuf> {
    if part_state::part_state(pal, io)? != HsmPartState::Initialized {
        return Err(HsmError::InvalidArg);
    }
    let key = pta_key(pal, io)?;
    if key.bank() != bank {
        return Err(HsmError::InvalidArg);
    }
    build_pid_certificate(pal, io, key).await
}

/// Fingerprint of a newly generated leaf; later reads generate different DER.
pub(crate) async fn chain_info<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    bank: HsmCertBank,
) -> HsmResult<HsmCertChainInfo> {
    let cert = pid_certificate(pal, io, bank).await?;
    let digest = pal.dma_alloc(io, SHA256_DIGEST_LEN)?;
    pal.hash(
        io,
        HsmHashAlgo::Sha256,
        cert,
        HsmDigestForm::Standard,
        Some(digest),
    )
    .await?;
    let thumbprint = *fixed_size::<SHA256_DIGEST_LEN>(digest)?;
    Ok(HsmCertChainInfo {
        count: 1,
        thumbprint,
    })
}
