// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SD and DARC transfer sealing (P-384, ML-KEM-1024 or MLKEM1024-P384
//! recipients), PID reports, and verification before opening.

use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_report::report_with;
use tsra_fw_core_crypto_key_report::transfer::*;
use tsra_fw_core_crypto_key_report::transfer_report_len;
use tsra_fw_core_crypto_key_report::ReportAlg;
use tsra_fw_core_crypto_key_report::ReportKind;
use tsra_fw_core_crypto_key_report::ReportSigner;
use tsra_fw_core_crypto_x509_chain::SPKI_THUMBPRINT_LEN;
use tsra_fw_core_evidence::verify_evidence_signer;
use tsra_fw_core_evidence::EvidenceRefs;
use tsra_fw_core_evidence::ATTESTED_KEY_LEN;
use tsra_fw_core_evidence::SIGNER_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::evidence::ReportDescriptor;
use tsra_fw_ddi_tbor_types::SD_BACKUP_REPORT_MAX_LEN;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::*;

use crate::part_state;

/// SHA-384 of the policy into a 48-byte `out`.
pub(super) async fn hash_policy<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    policy: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        policy,
        out,
        HsmDigestForm::Standard,
    )
    .await
}

/// Transfer KEM of a security-domain sealing-key vault kind.
pub(super) fn sealing_kem(kind: HsmVaultKeyKind) -> HsmResult<TransferKem> {
    match kind {
        HsmVaultKeyKind::SdSealing => Ok(TransferKem::P384),
        HsmVaultKeyKind::SdSealingMlKem1024 => Ok(TransferKem::MlKem1024),
        HsmVaultKeyKind::SdSealingMlKem1024P384 => Ok(TransferKem::MlKem1024P384),
        _ => Err(HsmError::UnsupportedKeyType),
    }
}

/// Transfer KEM of a DARC key-exchange-key vault kind.
pub(super) fn darc_kex_kem(kind: HsmVaultKeyKind) -> HsmResult<TransferKem> {
    match kind {
        HsmVaultKeyKind::DarcKex => Ok(TransferKem::P384),
        HsmVaultKeyKind::DarcKexMlKem1024 => Ok(TransferKem::MlKem1024),
        HsmVaultKeyKind::DarcKexMlKem1024P384 => Ok(TransferKem::MlKem1024P384),
        _ => Err(HsmError::UnsupportedKeyType),
    }
}

/// Wire-form public key of a sealing private key: SEC1 for P-384, the
/// HPKE `pkR` encoding for the ML-KEM suites.
pub(super) async fn sealing_public<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    kem: TransferKem,
    private: &HsmDmaBuf,
) -> HsmResult<&'a HsmDmaBuf> {
    let public = alloc.dma_alloc(kem.public_key_len())?;
    if kem == TransferKem::P384 {
        public[0] = 4;
        pal.ecc_pub_from_priv(io, HsmEccCurve::P384, private, &mut public[1..])
            .await?;
        byte_order::pair_to_be(P::BYTE_ORDER, HsmEccCurve::P384, &mut public[1..])?;
    } else {
        // Nested scope: release the ML-KEM keygen scratch before the caller's
        // decap/encap needs its own.
        pal.alloc_scoped_async(io, async |scratch| {
            tsra_fw_core_crypto_hpke::public_key(pal, io, kem.suite(), private, public, scratch)
                .await
        })
        .await?;
    }
    Ok(public)
}

/// Exact `(envelope, report)` lengths of a `kind` transfer (`Darc` or
/// `SdBackup`) sealed to `recipient` and signed by this partition's PID
/// under the policy `pta_alg`, so handlers can reserve response slots
/// before sealing.
pub(super) fn transfer_lens<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    kind: ReportKind,
    recipient: &[u8],
) -> HsmResult<(usize, usize)> {
    let kem = TransferKem::from_public_key(recipient)?;
    let alg = match super::pta::pta_key(pal, io)? {
        super::pta::PtaKey::Ecc(_) => ReportAlg::Es384,
        super::pta::PtaKey::MlDsa87(_) => ReportAlg::MlDsa87,
    };
    let envelope_len = match kind {
        ReportKind::Darc => darc_envelope_len(kem),
        _ => sd_backup_envelope_len(kem),
    };
    Ok((envelope_len, transfer_report_len(kind, alg)?))
}

/// Seals `secret` to `recipient` (any [`TransferKem`]) straight into the
/// caller's `envelope` response slot, then PID-signs the report into a
/// `report_len`-byte buffer from `alloc` (allocated only after sealing so
/// HPKE scratch and the report never coexist). A `policy_hash` makes an
/// SdBackup (48-byte BKS3) transfer; `None` a DARC (32-byte TMK) one. Both
/// lengths come from [`transfer_lens`].
#[allow(clippy::too_many_arguments)]
pub(super) async fn seal_signed<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    policy_hash: Option<&HsmDmaBuf>,
    recipient: &HsmDmaBuf,
    secret: &HsmDmaBuf,
    envelope: &mut HsmDmaBuf,
    report_len: usize,
) -> HsmResult<&'a HsmDmaBuf> {
    let kem = TransferKem::from_public_key(recipient)?;
    let ids = alloc.dma_alloc(96)?;
    let (source, destination) = ids.split_at_mut(48);
    // The PID signs with the policy `pta_alg`: the PTA's algorithm.
    let signer = match super::pta::pta_key(pal, io)? {
        super::pta::PtaKey::Ecc(_) => {
            let private = pal.vault_key(io, part_state::part_id_key_id(pal, io)?)?;
            let public = sealing_public(pal, io, alloc, TransferKem::P384, private).await?;
            p384_key_id(pal, io, public, source).await?;
            ReportSigner::Es384(private)
        }
        super::pta::PtaKey::MlDsa87(_) => {
            let seed = part_state::part_id_mldsa_seed_key_id(pal, io)?;
            // Scoped: only the key ID outlives the 2592-byte public key.
            pal.alloc_scoped_async(io, async |alloc| {
                let public = super::pta::mldsa87_public_key(pal, io, alloc, seed).await?;
                signer_key_id(pal, io, public, source).await
            })
            .await?;
            ReportSigner::MlDsa87Seed(pal.vault_key(io, seed)?)
        }
    };
    transfer_key_id(pal, io, recipient, destination).await?;
    let source: &[u8] = source;
    let destination: &[u8] = destination;
    let source_pid_key_id = source.try_into().map_err(|_| HsmError::InternalError)?;
    let recipient_key_id = destination
        .try_into()
        .map_err(|_| HsmError::InternalError)?;
    let header = match policy_hash {
        Some(hash) => {
            let hash: &[u8] = hash;
            TransferHeader::SdBackup {
                source_pid_key_id,
                recipient_key_id,
                policy_hash: hash.try_into().map_err(|_| HsmError::InternalError)?,
                kem,
            }
        }
        None => TransferHeader::Darc {
            source_pid_key_id,
            recipient_key_id,
            kem,
        },
    };
    let len = pal
        .alloc_scoped_async(io, async |scratch| {
            seal_transfer(pal, io, &header, recipient, secret, envelope, scratch).await
        })
        .await?;
    // A short write would publish uninitialized response bytes.
    if len != envelope.len() {
        return Err(HsmError::InternalError);
    }
    let envelope: &HsmDmaBuf = envelope;
    let digest = alloc.dma_alloc(48)?;
    transfer_envelope_hash(pal, io, envelope, digest).await?;
    let params = transfer_report_params(envelope, digest)?;
    let signed_report = alloc.dma_alloc(report_len)?;
    if report_with(pal, io, &params, signer, Some(signed_report)).await? != report_len {
        return Err(HsmError::InternalError);
    }
    Ok(signed_report)
}

/// Receives the out-of-band operation report `desc` (1..=`max_len` bytes)
/// into a buffer from `alloc`.
pub(super) async fn recv_report<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    desc: &ReportDescriptor,
    max_len: usize,
) -> HsmResult<&'a HsmDmaBuf> {
    let len = desc.length.get() as usize;
    if len == 0 || len > max_len {
        return Err(HsmError::InvalidArg);
    }
    let report = alloc.dma_alloc(len)?;
    pal.recv_oob(io, desc.index as usize, report).await?;
    Ok(report)
}

/// A received SdBackup: the recipient's masked sealing key, the source's
/// evidence, PID identity checks and the sealed envelope.
pub(super) struct BackupSource<'r> {
    /// Recipient's masked sealing key (unmasked in scratch).
    pub masked_key: &'r [u8],
    /// Source PID evidence carrying the SdBackup report.
    pub evidence: EvidenceRefs<'r>,
    /// Partition-owner anchor for the source; `None` is signature-only.
    pub anchor: Option<&'r [u8; SPKI_THUMBPRINT_LEN]>,
    /// Expected source PID public key, when supplied.
    pub pid_public: Option<&'r [u8]>,
    /// Sealed envelope.
    pub envelope: &'r HsmDmaBuf,
}

/// Unmask the recipient sealing key under `mk_id`, verify the source's
/// evidence and SdBackup report for `source.envelope` sealed under
/// `policy_hash` to that key, and open it into the 48-byte `bks3`. All
/// staging comes from `alloc`; the source key and report are staged in a
/// nested scope released before the (ML-KEM) decapsulation scratch. An
/// absent anchor is intentional signature-only SA operation verification.
pub(super) async fn unseal_backup<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    mk_id: HsmKeyId,
    source: &BackupSource<'_>,
    policy_hash: &HsmDmaBuf,
    bks3: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let blob = alloc.dma_alloc(source.masked_key.len())?;
    blob.copy_from_slice(source.masked_key);
    let key = unmask(pal, io, pal.vault_key(io, mk_id)?, blob).await?;
    let recipient =
        sealing_public(pal, io, alloc, sealing_kem(key.key_kind)?, key.target_key).await?;
    let hash: &[u8] = policy_hash;
    let expected_policy_hash = Some(hash.try_into().map_err(|_| HsmError::InternalError)?);
    let verified = pal
        .alloc_scoped_async(io, async |scratch| {
            let signer = scratch.dma_alloc(SIGNER_KEY_MAX_LEN)?;
            let signer_len = if let Some(anchor) = source.anchor {
                let len = verify_evidence_signer(pal, io, &source.evidence, anchor, signer).await?;
                if let Some(public) = source.pid_public {
                    // A P-384 PID travels as raw `X ‖ Y`, without the SEC1 tag.
                    let actual = if len == ATTESTED_KEY_LEN {
                        &signer[1..len]
                    } else {
                        &signer[..len]
                    };
                    if actual != public {
                        return Err(HsmError::InvalidArg);
                    }
                }
                len
            } else {
                let public = source.pid_public.ok_or(HsmError::InvalidArg)?;
                let len = match public.len() {
                    96 => {
                        signer[0] = 4;
                        signer[1..ATTESTED_KEY_LEN].copy_from_slice(public);
                        ATTESTED_KEY_LEN
                    }
                    SIGNER_KEY_MAX_LEN => {
                        signer.copy_from_slice(public);
                        SIGNER_KEY_MAX_LEN
                    }
                    _ => return Err(HsmError::InvalidArg),
                };
                signer_alg(&signer[..len])?;
                len
            };
            let report = recv_report(
                pal,
                io,
                scratch,
                source.evidence.report,
                SD_BACKUP_REPORT_MAX_LEN,
            )
            .await?;
            let config = TransferVerifyConfig {
                expected_kind: ReportKind::SdBackup,
                signer_public_key: &signer[..signer_len],
                recipient_public_key: recipient,
                expected_policy_hash,
            };
            verify_transfer(pal, io, &config, source.envelope, report, scratch).await
        })
        .await?;
    let len =
        open_verified_transfer(pal, io, &verified, key.target_key, recipient, bks3, alloc).await?;
    if len != 48 {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}
