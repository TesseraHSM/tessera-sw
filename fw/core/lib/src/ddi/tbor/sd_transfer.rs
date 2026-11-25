// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Complete PID-signed SD/DARC envelopes, including PQ and hybrid recipients.

use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_report::report_with;
use tsra_fw_core_crypto_key_report::transfer::*;
use tsra_fw_core_crypto_key_report::transfer_report_len;
use tsra_fw_core_crypto_key_report::ReportAlg;
use tsra_fw_core_crypto_key_report::ReportKind;
use tsra_fw_core_crypto_key_report::ReportParams;
use tsra_fw_core_crypto_key_report::ReportSigner;
use tsra_fw_core_crypto_x509_chain::mldsa87_key_from_spki;
use tsra_fw_core_crypto_x509_chain::p384_point_from_spki;
use tsra_fw_core_crypto_x509_chain::P384_SPKI_LEN;
use tsra_fw_core_crypto_x509_chain::SPKI_THUMBPRINT_LEN;
use tsra_fw_core_evidence::verify_evidence_signer;
use tsra_fw_core_evidence::IdentityRefs;
use tsra_fw_core_evidence::ATTESTED_KEY_LEN;
use tsra_fw_core_evidence::SIGNER_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::ReportDescriptor;
use tsra_fw_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_fw_ddi_tbor_types::POK_REMOTE_BACKUP_MAX_LEN;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::*;

use crate::part_state;

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
        HsmDigestForm::Standard,
        Some(out),
    )
    .await
    .map(|_| ())
}

pub(super) fn sealing_kem(kind: HsmVaultKeyKind) -> HsmResult<TransferKem> {
    match kind {
        HsmVaultKeyKind::SdSealing => Ok(TransferKem::P384),
        HsmVaultKeyKind::SdSealingMlKem1024 => Ok(TransferKem::MlKem1024),
        HsmVaultKeyKind::SdSealingMlKem1024P384 => Ok(TransferKem::MlKem1024P384),
        _ => Err(HsmError::UnsupportedKeyType),
    }
}

pub(super) fn darc_kex_kem(kind: HsmVaultKeyKind) -> HsmResult<TransferKem> {
    match kind {
        HsmVaultKeyKind::DarcKex => Ok(TransferKem::P384),
        HsmVaultKeyKind::DarcKexMlKem1024 => Ok(TransferKem::MlKem1024),
        HsmVaultKeyKind::DarcKexMlKem1024P384 => Ok(TransferKem::MlKem1024P384),
        _ => Err(HsmError::UnsupportedKeyType),
    }
}

pub(super) async fn sealing_public<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    kem: TransferKem,
    private: &HsmDmaBuf,
) -> HsmResult<&'a HsmDmaBuf> {
    let public = alloc.dma_alloc(kem.public_key_len())?;
    if kem == TransferKem::P384 {
        pal.ecc_pub_from_priv(io, HsmEccCurve::P384, private, Some(&mut public[..96]))
            .await?;
        byte_order::pair_to_be::<P>(HsmEccCurve::P384, &mut public[..96])?;
        public.copy_within(..96, 1);
        public[0] = 4;
    } else {
        pal.alloc_scoped_async(io, async |scratch| {
            tsra_fw_core_crypto_hpke::public_key(pal, io, kem.suite(), private, public, scratch)
                .await
        })
        .await?;
    }
    Ok(public)
}

/// Exact inner-envelope and complete signed-backup lengths.
pub(super) fn backup_lens<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    recipient: &[u8],
) -> HsmResult<(usize, usize)> {
    transfer_lens(pal, io, ReportKind::SdBackup, recipient)
}

/// Exact inner-envelope and complete signed-artifact lengths.
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
        ReportKind::SdBackup => sd_backup_envelope_len(kem),
        ReportKind::PublicKey => return Err(HsmError::InvalidArg),
    };
    Ok((envelope_len, transfer_report_len(kind, kem, alg)?))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn seal_backup<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    policy_hash: &HsmDmaBuf,
    recipient: &HsmDmaBuf,
    bks3: &HsmDmaBuf,
    signed_envelope: &mut HsmDmaBuf,
) -> HsmResult<()> {
    seal_signed(
        pal,
        io,
        alloc,
        Some(policy_hash),
        recipient,
        bks3,
        signed_envelope,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn seal_signed<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    policy_hash: Option<&HsmDmaBuf>,
    recipient: &HsmDmaBuf,
    secret: &HsmDmaBuf,
    signed_envelope: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let kem = TransferKem::from_public_key(recipient)?;
    let kind = if policy_hash.is_some() {
        ReportKind::SdBackup
    } else {
        ReportKind::Darc
    };
    let (envelope_len, signed_len) = transfer_lens(pal, io, kind, recipient)?;
    if signed_envelope.len() != signed_len {
        return Err(HsmError::InvalidArg);
    }
    let ids = alloc.dma_alloc(96)?;
    let (source, destination) = ids.split_at_mut(48);
    let signer = match super::pta::pta_key(pal, io)? {
        super::pta::PtaKey::Ecc(_) => {
            let private = pal.vault_key(io, part_state::part_id_key_id(pal, io)?)?;
            pal.alloc_scoped_async(io, async |scratch| {
                let public = sealing_public(pal, io, scratch, TransferKem::P384, private).await?;
                signer_key_id(pal, io, public, source).await
            })
            .await?;
            ReportSigner::Es384(private)
        }
        super::pta::PtaKey::MlDsa87(_) => {
            let seed = part_state::part_id_mldsa_seed_key_id(pal, io)?;
            pal.alloc_scoped_async(io, async |scratch| {
                let public = super::pta::mldsa87_public_key(pal, io, scratch, seed).await?;
                signer_key_id(pal, io, public, source).await
            })
            .await?;
            ReportSigner::MlDsa87Seed(pal.vault_key(io, seed)?)
        }
    };
    transfer_key_id(pal, io, recipient, destination).await?;
    let source: &[u8] = source;
    let destination: &[u8] = destination;
    let source_pid_spki_thumbprint = source.try_into().map_err(|_| HsmError::InternalError)?;
    let recipient_spki_thumbprint = destination
        .try_into()
        .map_err(|_| HsmError::InternalError)?;
    let header = match policy_hash {
        Some(hash) => {
            let hash: &[u8] = hash;
            TransferHeader::SdBackup {
                source_pid_spki_thumbprint,
                recipient_spki_thumbprint,
                policy_hash: hash.try_into().map_err(|_| HsmError::InternalError)?,
                kem,
            }
        }
        None => TransferHeader::Darc {
            source_pid_spki_thumbprint,
            recipient_spki_thumbprint,
            kem,
        },
    };
    let envelope = alloc.dma_alloc(envelope_len)?;
    let written = pal
        .alloc_scoped_async(io, async |scratch| {
            seal_transfer(pal, io, &header, recipient, secret, envelope, scratch).await
        })
        .await?;
    if written != envelope_len {
        return Err(HsmError::InternalError);
    }
    let written = report_with(
        pal,
        io,
        &ReportParams::Transfer(envelope),
        signer,
        Some(signed_envelope),
    )
    .await?;
    if written != signed_len {
        return Err(HsmError::InternalError);
    }
    Ok(())
}

/// Fetch the whole COSE artifact outside verification's scratch scope.
pub(super) async fn receive_backup<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    descriptor: &ReportDescriptor,
) -> HsmResult<&'a HsmDmaBuf> {
    let len = usize::from(descriptor.length.get());
    if !(POK_REMOTE_BACKUP_LEN..=POK_REMOTE_BACKUP_MAX_LEN).contains(&len) {
        return Err(HsmError::InvalidArg);
    }
    let backup = alloc.dma_alloc(len)?;
    pal.recv_oob(io, usize::from(descriptor.index), backup)
        .await?;
    Ok(backup)
}

/// Fetch a signed artifact into storage that outlives verification scratch.
pub(super) async fn recv_report<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    descriptor: &ReportDescriptor,
    max_len: usize,
) -> HsmResult<&'a HsmDmaBuf> {
    let len = usize::from(descriptor.length.get());
    if len == 0 || len > max_len {
        return Err(HsmError::InvalidArg);
    }
    let artifact = alloc.dma_alloc(len)?;
    pal.recv_oob(io, usize::from(descriptor.index), artifact)
        .await?;
    Ok(artifact)
}

/// An absent anchor intentionally requests signature-only SA verification.
pub(super) async fn source<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    evidence: &IdentityRefs<'_>,
    anchor: Option<&[u8; SPKI_THUMBPRINT_LEN]>,
    pid_public: Option<&[u8]>,
) -> HsmResult<&'a HsmDmaBuf> {
    let signer = alloc.dma_alloc(SIGNER_KEY_MAX_LEN)?;
    let len = if let Some(anchor) = anchor {
        let len = verify_evidence_signer(pal, io, evidence, anchor, signer).await?;
        if let Some(spki) = pid_public {
            let (actual, expected) = if len == ATTESTED_KEY_LEN {
                (&signer[1..len], p384_point_from_spki(spki)?)
            } else {
                (&signer[..len], mldsa87_key_from_spki(spki)?)
            };
            if actual != expected {
                return Err(HsmError::InvalidArg);
            }
        }
        len
    } else {
        let spki = pid_public.ok_or(HsmError::InvalidArg)?;
        if spki.len() == P384_SPKI_LEN {
            signer[0] = 4;
            signer[1..ATTESTED_KEY_LEN].copy_from_slice(p384_point_from_spki(spki)?);
            ATTESTED_KEY_LEN
        } else {
            signer.copy_from_slice(mldsa87_key_from_spki(spki)?);
            SIGNER_KEY_MAX_LEN
        }
    };
    signer_alg(&signer[..len])?;
    Ok(&signer[..len])
}

pub(super) struct BackupSource<'r> {
    pub masked_key: &'r [u8],
    pub evidence: IdentityRefs<'r>,
    pub anchor: Option<&'r [u8; SPKI_THUMBPRINT_LEN]>,
    /// Canonical DER SPKI, when separately supplied.
    pub pid_public: Option<&'r [u8]>,
    /// Complete signed artifact; must outlive verification scratch.
    pub envelope: &'r HsmDmaBuf,
}

pub(super) async fn unseal_backup<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    mk_id: HsmKeyId,
    backup: &BackupSource<'_>,
    policy_hash: &HsmDmaBuf,
    bks3: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let blob = alloc.dma_alloc(backup.masked_key.len())?;
    blob.copy_from_slice(backup.masked_key);
    let key = unmask(pal, io, pal.vault_key(io, mk_id)?, blob).await?;
    let recipient =
        sealing_public(pal, io, alloc, sealing_kem(key.key_kind)?, key.target_key).await?;
    let hash: &[u8] = policy_hash;
    let expected_policy_hash = Some(hash.try_into().map_err(|_| HsmError::InternalError)?);
    let verified = pal
        .alloc_scoped_async(io, async |scratch| {
            let signer = source(
                pal,
                io,
                scratch,
                &backup.evidence,
                backup.anchor,
                backup.pid_public,
            )
            .await?;
            let config = TransferVerifyConfig {
                expected_kind: ReportKind::SdBackup,
                signer_public_key: signer,
                recipient_public_key: recipient,
                expected_policy_hash,
            };
            verify_transfer(pal, io, &config, backup.envelope, scratch).await
        })
        .await?;
    let len =
        open_verified_transfer(pal, io, &verified, key.target_key, recipient, bks3, alloc).await?;
    if len != 48 {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}
