// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Receiver attestation-evidence verification for Security-Domain (SD)
//! backup commands.
//!
//! Several TBOR SD commands (`SdCreateRemoteBackup`, `SdReseal`,
//! `SdRestore*`, `SdCreatePeerBackup`) carry an attestation **evidence**
//! context out of band: required manufacturer and partition-owner
//! X.509 chains with P-384 or ML-DSA-87 leaf keys, an optional device-owner chain, and a COSE_Sign1 key-
//! attestation report. [`verify_evidence`] validates one such context and
//! recovers the attested public key it vouches for.
//!
//! It enforces, in order:
//!
//! 1. the manufacturer and partition-owner chains are required; all supplied
//!    chains validate as X.509 chains (ECDSA, RSA or pure ML-DSA issuers);
//! 2. the manufacturer and optional owner chains are validated but **not** anchored;
//! 3. the partition-owner chain is anchored to a **caller-selected**
//!    public-key thumbprint passed in [`TrustAnchors`] (a non-leaf
//!    certificate's P-384 or ML-DSA-87 SPKI thumbprint must equal it — the anchor
//!    endorses the leaf directly or
//!    indirectly). The anchor is the POTA of the partition being attested:
//!    the evidence-based `SdReseal`, `SdCreatePeerBackup`, and
//!    `SdRestorePeerBackup` commands attest client/peer partitions and
//!    anchor to the policy **POTA** key; the **optional** evidence verified
//!    by `SdCreateRemoteBackup` / `SdRestoreRemoteBackup` (only when the
//!    policy sets `require_trusted_sa_key`) attests the Sealing Authority's
//!    partition and anchors to the policy **SAPOTA** key;
//! 4. all supplied chains share the **same** leaf public key;
//! 5. that shared leaf key signed the COSE_Sign1 attestation report.
//! 6. when requested by a peer/reseal consumer, the signed report proves
//!    HSM-generated SD-sealing-key provenance.
//!
//! A partition's report-signing PID key is endorsed by its PTA, which its
//! POTA endorses at `PartFinal`, so evidence chains terminate at the
//! attested partition's POTA. For the reseal and peer commands,
//! [`verify_evidence`] is the sole source of the peer key (recovered from
//! the attested COSE_Key). For `SdCreateRemoteBackup`, the authoritative
//! recipient key instead comes from a separate, always-required SATA chain (see
//! [`verify_receiver_cert_chain`]); the attestation evidence is optional
//! and, when present, SAPOTA-anchored.
//!
//! Transfer consumers use [`verify_evidence_signer`] to authorize PID
//! identity chains and verify the direct signature inside their `SdBackup`.
//! Remote restore has no SATA sender chain; SAPOTA is required only under
//! trusted-SA policy. Without it, report integrity does not authenticate SA identity.
//!
//! The bulk DER/COSE items travel out of band; the caller passes the
//! per-item descriptors (see [`EvidenceRefs`]) and each item is fetched
//! with [`HsmIoController::recv_oob`]. Each certificate is copied into a
//! nested, per-chain allocator scope that frees on return, so peak DMA use
//! stays bounded regardless of chain depth.
//!
//! Leaf (report-signer) keys are P-384 or ML-DSA-87, selected by the leaf
//! certificate; reports verify as ES384 or ML-DSA-87 accordingly, and the
//! trust anchors bind the algorithm. Attested SD sealing keys may be P-384,
//! ML-KEM-1024 or MLKEM1024-P384 (see [`TransferKem`]); a remote SATA
//! receiver proves a PQ key with a SATA-leaf-signed key report
//! ([`verify_receiver_key_report`]). Issuer keys may differ.

#![no_std]

use tsra_fw_core_crypto_key_report::parse_akp_cose_key;
use tsra_fw_core_crypto_key_report::parse_ec2_cose_key;
use tsra_fw_core_crypto_key_report::parse_key_report;
use tsra_fw_core_crypto_key_report::transfer::signer_alg;
use tsra_fw_core_crypto_key_report::transfer::signer_verifier;
use tsra_fw_core_crypto_key_report::transfer::TransferKem;
use tsra_fw_core_crypto_key_report::transfer::SIGNER_PUBLIC_KEY_MAX_LEN;
use tsra_fw_core_crypto_key_report::transfer::TRANSFER_PUBLIC_KEY_MAX_LEN;
use tsra_fw_core_crypto_key_report::verify_key_report_with;
use tsra_fw_core_crypto_key_report::KeyFlags;
use tsra_fw_core_crypto_key_report::COSE_ALG_MLKEM1024;
use tsra_fw_core_crypto_key_report::COSE_ALG_MLKEM1024_P384;
use tsra_fw_core_crypto_key_report::MLDSA87_PUB_KEY_LEN;
use tsra_fw_core_crypto_key_report::POLICY_HASH_LEN;
use tsra_fw_core_crypto_key_report::REPORT_MAX_LEN;
use tsra_fw_core_crypto_x509_chain::validate_chain_into;
use tsra_fw_core_crypto_x509_chain::LeafSink;
use tsra_fw_core_crypto_x509_chain::SPKI_THUMBPRINT_LEN;
use tsra_fw_ddi_tbor_types::CertDescriptor;
use tsra_fw_ddi_tbor_types::ReportDescriptor;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIoController;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

/// NIST curve of P-384 leaf / attested keys.
const CURVE: HsmEccCurve = HsmEccCurve::P384;

/// P-384 coordinate length (`priv_key_len`).
const COORD_LEN: usize = 48;

/// Length of a P-384 public point (`X ‖ Y`, big-endian).
const POINT_LEN: usize = 2 * COORD_LEN;

/// SEC1 uncompressed P-384 key length (`0x04 ‖ X ‖ Y`).
pub const ATTESTED_KEY_LEN: usize = 1 + POINT_LEN;

/// Largest report-signer (leaf) key: an encoded ML-DSA-87 key.
pub const SIGNER_KEY_MAX_LEN: usize = SIGNER_PUBLIC_KEY_MAX_LEN;

/// Largest accepted key / attestation report: an ML-DSA-87 signature over
/// a payload attesting the largest sealing key fits.
pub const EVIDENCE_REPORT_MAX_LEN: usize = REPORT_MAX_LEN;

/// Largest attested sealing key (MLKEM1024-P384 `ek_PQ ‖ SEC1(ek_T)`).
pub const ATTESTED_KEY_MAX_LEN: usize = TRANSFER_PUBLIC_KEY_MAX_LEN;

/// SEC1 uncompressed point tag (`0x04 ‖ X ‖ Y`).
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Out-of-band locations of one attestation context's items: the three
/// certificate-chain descriptor lists plus the attestation-report
/// descriptor. Obtained from a command's [`Evidence`] field-group view.
///
/// [`Evidence`]: tsra_fw_ddi_tbor_types::evidence::Evidence
pub struct EvidenceRefs<'a> {
    /// Manufacturer certificate-chain descriptors (root→leaf).
    pub mfgr_chain: &'a [CertDescriptor],
    /// Optional device-owner certificate-chain descriptors (root→leaf).
    /// An empty list omits this chain; a supplied chain must validate.
    pub owner_chain: &'a [CertDescriptor],
    /// Partition-owner certificate-chain descriptors (root→leaf).
    pub part_owner_chain: &'a [CertDescriptor],
    /// COSE_Sign1 attestation-report descriptor.
    pub report: &'a ReportDescriptor,
}

/// Identity chains authorizing a transfer signer; no separate operation report.
pub struct IdentityRefs<'a> {
    /// Manufacturer certificate-chain descriptors.
    pub mfgr_chain: &'a [CertDescriptor],
    /// Optional device-owner certificate-chain descriptors.
    pub owner_chain: &'a [CertDescriptor],
    /// Partition-owner certificate-chain descriptors.
    pub part_owner_chain: &'a [CertDescriptor],
}

/// Trust anchors the evidence must chain to, taken from the partition
/// policy. The manufacturer and owner chains are validated but unanchored;
/// the partition-owner chain must be endorsed (directly or indirectly) by
/// [`part_owner_anchor`](Self::part_owner_anchor).
pub struct TrustAnchors<'a> {
    /// Public-key thumbprint (SHA-384 of the canonical P-384 or ML-DSA-87
    /// SPKI) the
    /// partition-owner chain must chain to.  The **optional** evidence
    /// verified by [`SdCreateRemoteBackup`] and [`SdRestoreRemoteBackup`]
    /// anchors here to the policy **SAPOTA** key; the evidence-based
    /// `SdReseal`, `SdCreatePeerBackup`, and `SdRestorePeerBackup` commands
    /// anchor here to the policy **POTA** key.
    ///
    /// [`SdCreateRemoteBackup`]: tsra_fw_ddi_tbor_types::TborSdCreateRemoteBackupReq
    /// [`SdRestoreRemoteBackup`]: tsra_fw_ddi_tbor_types::TborSdRestoreRemoteBackupReq
    pub part_owner_anchor: &'a [u8; SPKI_THUMBPRINT_LEN],
    /// Require an HSM-generated SD sealing key, not an ordinary attested key.
    pub require_sd_sealing: bool,
}

/// Validate a receiver key certificate chain and recover its leaf key.
///
/// Validates `chain` as an X.509 chain (root→leaf) with a P-384 or
/// ML-DSA-87 leaf, requiring a **non-leaf** certificate's public-key
/// thumbprint to equal `anchor`, and writes the leaf public key — the
/// receiver public key (`RcvrPub`) — into `rcvr_pub` in signer form (see
/// [`signer_alg`]): SEC1 uncompressed big-endian P-384 ([`ATTESTED_KEY_LEN`]
/// bytes) or the encoded ML-DSA-87 key. Returns its length; `rcvr_pub` must
/// hold [`SIGNER_KEY_MAX_LEN`] bytes to accept either.
///
/// This is the spec `RcvrCertChain` step of `CreateSD` (anchored to the
/// policy SATA) and of DARC export / import (anchored to the policy DATA /
/// POTA): it authorizes the leaf key independently of any attestation report.
///
/// # Errors
///
/// * [`HsmError::InvalidArg`] — `rcvr_pub` is too small, the chain is empty,
///   the leaf is neither P-384 nor ML-DSA-87, or no non-leaf certificate
///   matches `anchor`.
/// * `X509…` errors — a certificate is malformed or its signature / chain
///   linkage is invalid (propagated from the chain validator).
pub async fn verify_receiver_cert_chain<P>(
    pal: &P,
    io: &P::Io,
    chain: &[CertDescriptor],
    anchor: &[u8; SPKI_THUMBPRINT_LEN],
    rcvr_pub: &mut HsmDmaBuf,
) -> HsmResult<usize>
where
    P: HsmIoController + HsmAlloc + HsmCrypto,
{
    let len = validate_chain(pal, io, chain, Some(anchor), LeafSink::Out(rcvr_pub)).await?;
    signer_leaf(rcvr_pub, len)
}

/// Verify a receiver key report signed by the anchor-authorized receiver
/// leaf and recover the KEM key it attests.
///
/// `rcvr_pub` is the leaf key from [`verify_receiver_cert_chain`]; the
/// report must verify under it (ES384 for P-384, ML-DSA-87 otherwise) and
/// attest a P-384, ML-KEM-1024 or MLKEM1024-P384 key, which is written to
/// `kem_pub` in its HPKE `SerializePublicKey` form.  Returns the key length.
/// With `require_darc_kex` the report must also flag the key as a
/// device-generated, never-imported DARC key-exchange key, so the receiver
/// cannot substitute a key whose private half left a device.
///
/// # Errors
///
/// * [`HsmError::InvalidArg`] — the report is empty, oversized, not signed
///   by `rcvr_pub`, attests an unsupported key or lacks the required DARC
///   KEX flags, or `kem_pub` is too small.
/// * Other [`HsmError`] values propagated from the PAL / OOB copy.
pub async fn verify_receiver_key_report<P>(
    pal: &P,
    io: &P::Io,
    rcvr_pub: &HsmDmaBuf,
    report: &ReportDescriptor,
    require_darc_kex: bool,
    kem_pub: &mut HsmDmaBuf,
) -> HsmResult<usize>
where
    P: HsmIoController + HsmAlloc + HsmCrypto,
{
    signer_alg(rcvr_pub)?;
    let report_len = report.length.get() as usize;
    if report_len == 0 || report_len > EVIDENCE_REPORT_MAX_LEN {
        return Err(HsmError::InvalidArg);
    }
    pal.alloc_scoped_async(io, async |ra| -> HsmResult<usize> {
        let buf = ra.dma_alloc(report_len)?;
        pal.recv_oob(io, report.index as usize, buf).await?;
        let verifier = signer_verifier::<P>(ra, rcvr_pub)?;
        if !verify_key_report_with(pal, io, ra, buf, verifier).await? {
            return Err(HsmError::InvalidArg);
        }
        let view = parse_key_report(buf)?;
        let flags = KeyFlags::from(view.flags);
        if require_darc_kex
            && (!flags.is_darc_kex() || !flags.is_generated() || flags.is_imported())
        {
            return Err(HsmError::InvalidArg);
        }
        attested_kem_key(
            &view.public_key[..view.public_key_size as usize],
            KeySink::Out(kem_pub),
        )
    })
    .await
}

/// What [`verify_evidence`] does with the attested key.
pub enum KeySink<'a> {
    /// Write it into the prefix of the buffer.
    Out(&'a mut HsmDmaBuf),
    /// Require it to equal these bytes, compared in place without a copy.
    Expect(&'a [u8]),
}

/// Decode an attested COSE_Key into its HPKE `SerializePublicKey` form:
/// SEC1 for an EC2 P-384 key, the raw `pub` for the ML-KEM AKP keys.
fn attested_kem_key(cose_key: &HsmDmaBuf, sink: KeySink<'_>) -> HsmResult<usize> {
    if let Ok(ec) = parse_ec2_cose_key(cose_key) {
        if ec.curve != CURVE {
            return Err(HsmError::InvalidArg);
        }
        match sink {
            KeySink::Out(out) => {
                if out.len() < ATTESTED_KEY_LEN {
                    return Err(HsmError::InvalidArg);
                }
                out[0] = SEC1_UNCOMPRESSED;
                out[1..1 + COORD_LEN].copy_from_slice(ec.x);
                out[1 + COORD_LEN..ATTESTED_KEY_LEN].copy_from_slice(ec.y);
            }
            KeySink::Expect(expected) => {
                if expected.len() != ATTESTED_KEY_LEN
                    || expected[0] != SEC1_UNCOMPRESSED
                    || expected[1..1 + COORD_LEN] != **ec.x
                    || expected[1 + COORD_LEN..] != **ec.y
                {
                    return Err(HsmError::InvalidArg);
                }
            }
        }
        return Ok(ATTESTED_KEY_LEN);
    }
    let (alg, pk) = parse_akp_cose_key(cose_key)?;
    let expected = match alg {
        COSE_ALG_MLKEM1024 => TransferKem::MlKem1024,
        COSE_ALG_MLKEM1024_P384 => TransferKem::MlKem1024P384,
        _ => return Err(HsmError::InvalidArg),
    };
    expected.check_public_key(pk)?;
    match sink {
        KeySink::Out(out) if out.len() >= pk.len() => out[..pk.len()].copy_from_slice(pk),
        KeySink::Expect(key) if *key == **pk => {}
        _ => return Err(HsmError::InvalidArg),
    }
    Ok(pk.len())
}

/// Verify a receiver's attestation evidence and recover the attested key.
///
/// Validates the required manufacturer and partition-owner chains and any
/// supplied device-owner chain in `refs`, anchors the
/// partition-owner chain to `anchors.part_owner_anchor`, requires a single shared leaf
/// key across the chains, and confirms that leaf key signed the report.
/// On success the attested public key recovered from the report's COSE_Key,
/// in its HPKE `SerializePublicKey` form — SEC1 uncompressed big-endian for
/// P-384 ([`ATTESTED_KEY_LEN`] bytes), the raw encapsulation key for
/// ML-KEM-1024 / MLKEM1024-P384 (at most [`ATTESTED_KEY_MAX_LEN`]) — is
/// written to or compared against `sink`, and its length is returned.
///
/// When `policy_hash_out` is `Some`, the report's v2 `policy_hash` (the
/// SHA-384 PartPolicy digest) is copied into it ([`POLICY_HASH_LEN`]
/// bytes); the report must be **v2** (a v1 report with no `policy_hash` is
/// rejected). This lets callers (e.g. the security-domain reseal flow) bind
/// the attested key to a specific policy. Pass `None` to ignore it.
///
/// # Errors
///
/// * [`HsmError::InvalidArg`] — a required chain is empty, the partition-owner chain
///   is not anchored to `anchors.part_owner_anchor`, the chains disagree on a leaf key,
///   the report signature does not verify, the attested key is not a
///   supported sealing KEM key, a [`KeySink::Out`] buffer is too small or a
///   [`KeySink::Expect`] key differs, or `policy_hash_out` is `Some` but the
///   report carries no v2 `policy_hash` (or the buffer is too small).
/// * `X509…` errors — a certificate is malformed or its signature / chain
///   linkage is invalid (propagated from the chain validator).
/// * Other [`HsmError`] values propagated from the PAL / OOB copy.
pub async fn verify_evidence<P>(
    pal: &P,
    io: &P::Io,
    refs: &EvidenceRefs<'_>,
    anchors: &TrustAnchors<'_>,
    sink: KeySink<'_>,
    policy_hash_out: Option<&mut HsmDmaBuf>,
) -> HsmResult<usize>
where
    P: HsmIoController + HsmAlloc + HsmCrypto,
{
    let report_index = refs.report.index as usize;
    let report_len = refs.report.length.get() as usize;
    if report_len == 0 || report_len > EVIDENCE_REPORT_MAX_LEN {
        return Err(HsmError::InvalidArg);
    }

    pal.alloc_scoped_async(io, async |ra| -> HsmResult<usize> {
        let signer = ra.dma_alloc(SIGNER_KEY_MAX_LEN)?;
        let signer_len = verify_evidence_signer(
            pal,
            io,
            &IdentityRefs {
                mfgr_chain: refs.mfgr_chain,
                owner_chain: refs.owner_chain,
                part_owner_chain: refs.part_owner_chain,
            },
            anchors.part_owner_anchor,
            signer,
        )
        .await?;

        // Req 5: the shared leaf key must endorse the attestation report.
        let report = ra.dma_alloc(report_len)?;
        pal.recv_oob(io, report_index, report).await?;
        let verifier = signer_verifier::<P>(ra, &signer[..signer_len])?;
        if !verify_key_report_with(pal, io, ra, report, verifier).await? {
            return Err(HsmError::InvalidArg);
        }
        let view = parse_key_report(report)?;
        let flags = KeyFlags::from(view.flags);
        if anchors.require_sd_sealing
            && (!flags.is_sd_sealing() || !flags.is_generated() || flags.is_imported())
        {
            return Err(HsmError::InvalidArg);
        }
        let len = attested_kem_key(&view.public_key[..view.public_key_size as usize], sink)?;
        if let Some(out) = policy_hash_out {
            let ph = view.policy_hash.ok_or(HsmError::InvalidArg)?;
            if out.len() < POLICY_HASH_LEN || ph.len() != POLICY_HASH_LEN {
                return Err(HsmError::InvalidArg);
            }
            out[..POLICY_HASH_LEN].copy_from_slice(&ph[..POLICY_HASH_LEN]);
        }
        Ok(len)
    })
    .await
}

/// Validate the identity chains shared by a report signer, without interpreting
/// the payload, and write the shared leaf key to `signer` in signer
/// form (see [`signer_alg`]). Returns its length; `signer` must hold
/// [`SIGNER_KEY_MAX_LEN`] bytes to accept an ML-DSA-87 leaf. Callers must
/// verify the complete signed transfer separately.
pub async fn verify_evidence_signer<P>(
    pal: &P,
    io: &P::Io,
    refs: &IdentityRefs<'_>,
    part_owner_anchor: &[u8; SPKI_THUMBPRINT_LEN],
    canonical: &mut [u8],
) -> HsmResult<usize>
where
    P: HsmIoController + HsmAlloc + HsmCrypto,
{
    // Reqs 1–2: the manufacturer chain (no anchor) fixes the canonical leaf
    // key; an optional owner chain (no anchor) must share it (req 4).
    let len = validate_chain(pal, io, refs.mfgr_chain, None, LeafSink::Out(canonical)).await?;
    let len = signer_leaf(canonical, len)?;
    // The other chains' leaves are compared in place against the raw form
    // (P-384 `X ‖ Y` without the SEC1 prefix), so no second signer-sized
    // buffer is needed.
    let raw = match len {
        ATTESTED_KEY_LEN => &canonical[1..len],
        _ => &canonical[..len],
    };

    if !refs.owner_chain.is_empty() {
        validate_chain(pal, io, refs.owner_chain, None, LeafSink::Expect(raw)).await?;
    }

    // Reqs 1, 3, 4: the partition-owner chain must validate, be anchored
    // to the caller-selected `part_owner_anchor` (the policy POTA key
    // for reseal/peer, the policy SAPOTA key for remote create/restore),
    // and share the canonical leaf key.
    validate_chain(
        pal,
        io,
        refs.part_owner_chain,
        Some(part_owner_anchor),
        LeafSink::Expect(raw),
    )
    .await?;
    Ok(len)
}

/// Convert a validated `len`-byte chain leaf in `out` to signer form in
/// place: SEC1 for a raw P-384 point, unchanged for ML-DSA-87.
fn signer_leaf(out: &mut [u8], len: usize) -> HsmResult<usize> {
    match len {
        POINT_LEN if out.len() >= ATTESTED_KEY_LEN => {
            out.copy_within(..POINT_LEN, 1);
            out[0] = SEC1_UNCOMPRESSED;
            Ok(ATTESTED_KEY_LEN)
        }
        MLDSA87_PUB_KEY_LEN => Ok(len),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Validate one DER certificate chain and recover its leaf public key.
///
/// Thin OOB adapter over the shared [`validate_chain_into`] walker: it
/// sources each certificate's DER from the OOB SGL page (by descriptor
/// index) and runs the whole walk inside a nested allocator scope that
/// frees on return, so only the caller's leaf buffer survives. The
/// walker borrows adjacent DER views without issuer copies, so peak DMA
/// stays bounded by the largest adjacent pair regardless of chain depth.
/// On success the validated leaf public key is handled by `leaf` (copied
/// out or compared in place) and its length returned.
///
/// When `anchor` is `Some`, at least one **non-leaf** certificate's P-384
/// or ML-DSA-87 public-key thumbprint must equal it — the trust-anchor binding.
/// A chain with no matching anchor is rejected with [`HsmError::InvalidArg`].
async fn validate_chain<P>(
    pal: &P,
    io: &P::Io,
    chain: &[CertDescriptor],
    anchor: Option<&[u8; SPKI_THUMBPRINT_LEN]>,
    leaf: LeafSink<'_>,
) -> HsmResult<usize>
where
    P: HsmIoController + HsmAlloc + HsmCrypto,
{
    pal.alloc_scoped_async(io, async |ca| -> HsmResult<usize> {
        validate_chain_into(
            pal,
            io,
            ca,
            chain,
            anchor,
            leaf,
            async |index: usize, buf: &mut HsmDmaBuf| pal.recv_oob(io, index, buf).await,
        )
        .await
    })
    .await
}
