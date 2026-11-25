// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdCreateRemoteBackup` command.
//!
//! `SdCreateRemoteBackup` creates a security domain: it mints a fresh
//! BKS3 and a random security-domain masking key (`SDMK`), provisions
//! `SDMK` in the vault as the partition's SecurityDomain-scope masking
//! key, and writes one complete signed HPKE Base backup to OOB index 0.
//! The response carries its length, the 280-byte `pok_local_backup` (BKS3 masked
//! under `PartLocalMK`), and the 264-byte `sd_mk_backup` (`SDMK` masked
//! under the derived `SDBMK`).
//!
//! These tests run a **self-backup** (sender == receiver): one partition
//! mints an SD sealing key, attests it via `KeyReport`, then seals to its
//! own attested public key.  This exercises the full path — the OOB SGL
//! transport, the COSE_Key `RcvrPub` extraction, the sealing-key unmask,
//! the HPKE Base seal, and the SDMK provisioning — without a second
//! device.
//!
//! Coverage:
//! * Happy path — non-zero signed remote artifact (431 B), `pok_local_backup`
//!   (280 B), and `sd_mk_backup` (264 B).
//! * One-shot: a second create on the now-initialized partition →
//!   `SdAlreadyInitialized`.
//! * Missing OOB evidence → `InvalidArg`.
//! * Policy that does not name this partition as the backing partition
//!   (`backup_part_id` / `backup_part_pub_key` absent) → `InvalidArg`.
//!
//! # The SD one-shot
//!
//! The command provisions the SDMK behind a one-shot gate (see
//! `HsmError::SdAlreadyInitialized`), so a second create on an
//! already-initialized partition is rejected — that is the behaviour
//! `sd_create_remote_backup_is_one_shot` asserts.
//!
//! The gate is cleared by `clear_state` on every partition reset kind,
//! including the `Migrate` driven by the harness's NSSR, so each
//! test starts from an uninitialized security domain and the file is
//! self-isolating on hardware. That was not always true: uno previously
//! cleared the flag only on `Disable`, so it survived an NSSR while the
//! same reset dropped the SDMK handle — leaving the partition claiming a
//! security domain whose key was gone, permanently. Emulator builds never
//! saw it because the std PAL clears the flag on `part_enable` and
//! `clear_enabled_state`.

use tsra_ddi::DdiError;
use tsra_ddi::DdiResult;
use tsra_ddi::TborOobItem;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::dev_rev_in_place;
use tsra_ddi_tbor_test_harness::x509_fixture::make_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use tsra_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use tsra_ddi_tbor_test_harness::x509_fixture::spki_thumbprint;
use tsra_ddi_tbor_test_harness::x509_fixture::CaKey;
use tsra_ddi_tbor_test_harness::x509_fixture::GeneratedChain;
use tsra_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::TestPolicy;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_types::tbor_int::U16;
use tsra_ddi_tbor_types::CertDescriptor;
use tsra_ddi_tbor_types::PolicyFlags;
use tsra_ddi_tbor_types::ReportDescriptor;
use tsra_ddi_tbor_types::TborDarcKexKeyGenReq;
use tsra_ddi_tbor_types::TborKeyReportReq;
use tsra_ddi_tbor_types::TborOpReq;
use tsra_ddi_tbor_types::TborPartInfoReq;
use tsra_ddi_tbor_types::TborSdCreateRemoteBackupReq;
use tsra_ddi_tbor_types::TborSdSealingKeyGenReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::KEY_REPORT_DATA_LEN;
use tsra_ddi_tbor_types::MASKED_SD_LEN;
use tsra_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use tsra_ddi_tbor_types::POLICY_BACKUP_PART_ID_LEN;
use tsra_ddi_tbor_types::SD_BACKUP_REPORT_MAX_LEN;
use tsra_ddi_tbor_types::SD_BACKUP_REPORT_OOB_INDEX;
use tsra_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::commands::part_info::assert_part_state;
use crate::commands::part_info::PART_STATE_ENABLED;
use crate::commands::part_info::PART_STATE_INITIALIZED;
use crate::commands::part_init::known_good_part_policy;
use crate::commands::part_init::known_good_test_policy;
use crate::commands::part_init::mach_seed;
use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant (wire mirror of the firmware
/// `HsmKeyScope`).
const SCOPE_LOCAL: u8 = 0b011;

/// Build a policy naming **this** partition as the backing partition
/// (`backup_part_id = PID`, `backup_part_spki_thumbprint = SPKI thumbprint
/// of the PID public key`) and
/// anchoring the security domain to `sata_pub` (raw `X ‖ Y`, big-endian).
///
/// The caller learns the PID / PID public key from `PartInfo` (before
/// `PartInit`); the SATA key is a synthetic trust anchor the test also
/// uses to sign the partition-owner certificate chain.
pub(crate) fn backing_part_policy(
    pid: &[u8],
    pid_pub: &[u8],
    sata_pub: &[u8; RAW_PUB_LEN],
    pota_pub: &[u8; RAW_PUB_LEN],
) -> Vec<u8> {
    backing_test_policy(pid, pid_pub, sata_pub, pota_pub).encode()
}

/// The [`TestPolicy`] behind [`backing_part_policy`], for callers that
/// add further anchors before encoding.  Every trust anchor is bound by
/// the SPKI thumbprint of its real P-384 key: POTA so `PartFinal` can
/// validate a PTA chain, SATA for the receiver chain, and the PID key
/// for the backing-partition check.
pub(crate) fn backing_test_policy(
    pid: &[u8],
    pid_pub: &[u8],
    sata_pub: &[u8; RAW_PUB_LEN],
    pota_pub: &[u8; RAW_PUB_LEN],
) -> TestPolicy {
    let pid: [u8; POLICY_BACKUP_PART_ID_LEN] = pid.try_into().expect("PID is 16 bytes");
    let pid_pub: &[u8; RAW_PUB_LEN] = pid_pub.try_into().expect("PID public key is raw X || Y");
    let mut p = known_good_test_policy().with_backup_part(pid, spki_thumbprint(pid_pub));
    p.pota_spki_thumbprint = spki_thumbprint(pota_pub);
    p.sata_spki_thumbprint = spki_thumbprint(sata_pub);
    p
}

/// Drive `PartInit → PartFinal` with a backing-partition policy anchored
/// to `sata_key` and return the live CO session, the exact policy image
/// (needed verbatim by `SdCreateRemoteBackup` for the `policy_hash`
/// re-check), and the partition-identity (PID) public key that every
/// evidence leaf certificate must carry.
pub(crate) fn finalized_backing_session(
    ctx: &TestCtx,
    sata_key: &CaKey,
) -> (SessionHandshake, Vec<u8>, [u8; RAW_PUB_LEN]) {
    finalized_backing_session_with_pota(ctx, sata_key, &CaKey::generate())
}

/// [`finalized_backing_session`] with a caller-held POTA key, for commands
/// whose evidence must chain to the partition's POTA.
pub(crate) fn finalized_backing_session_with_pota(
    ctx: &TestCtx,
    sata_key: &CaKey,
    pota: &CaKey,
) -> (SessionHandshake, Vec<u8>, [u8; RAW_PUB_LEN]) {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

    // PID / PID public key are materialized before PartInit.
    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);

    // POTA anchor for the PTA certificate chain `PartFinal` validates.
    let policy = backing_part_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata_key.raw_pub(),
        &pota.raw_pub(),
    );

    let init = ctx
        .part_init(&session, &mach_seed(), &policy)
        .expect("PartInit");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    (session, policy, pid_pub)
}

/// Build a backing-partition policy that additionally **requires a trusted
/// Sealing Authority key** (`require_trusted_sa_key` set): like
/// [`backing_part_policy`] but with the SAPOTA anchor thumbprint populated
/// and the flag set. Under this policy `SdCreateRemoteBackup` validates the
/// three-chain evidence (partition-owner chain anchored to SAPOTA) in
/// addition to the always-required receiver certificate chain.
pub(crate) fn backing_part_policy_trusted(
    pid: &[u8],
    pid_pub: &[u8],
    sata_pub: &[u8; RAW_PUB_LEN],
    sapota_pub: &[u8; RAW_PUB_LEN],
    pota_pub: &[u8; RAW_PUB_LEN],
) -> Vec<u8> {
    backing_test_policy(pid, pid_pub, sata_pub, pota_pub)
        .with_sapota(spki_thumbprint(sapota_pub))
        .with_flags(PolicyFlags::REQUIRE_TRUSTED_SA_KEY)
        .encode()
}

/// Like [`finalized_backing_session`], but provisions the partition under a
/// **trusted-SA-key** policy (`require_trusted_sa_key` set, anchored to
/// `sapota_key` for attestation and `sata_key` for the receiver chain).
pub(crate) fn finalized_backing_session_trusted(
    ctx: &TestCtx,
    sata_key: &CaKey,
    sapota_key: &CaKey,
) -> (SessionHandshake, Vec<u8>, [u8; RAW_PUB_LEN]) {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);

    let pota = CaKey::generate();
    let policy = backing_part_policy_trusted(
        &info.pid,
        &info.pid_pub_key,
        &sata_key.raw_pub(),
        &sapota_key.raw_pub(),
        &pota.raw_pub(),
    );

    let init = ctx
        .part_init(&session, &mach_seed(), &policy)
        .expect("PartInit");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    (session, policy, pid_pub)
}

/// Mint an SD sealing key and attest it, returning
/// `(masked_sealing_key, key_report_bytes)`.  In the self-backup tests
/// this key supplies the receiver's `RcvrPub` via its PID-signed report;
/// the source authenticates its transfer with the separate PID private key.
pub(crate) fn masked_key_and_report(ctx: &TestCtx, session_id: u16) -> (Vec<u8>, Vec<u8>) {
    let (masked, report, _pub) = masked_key_report_and_pub(ctx, session_id);
    (masked, report)
}

/// As [`masked_key_and_report`], but also returns the sealing key's public
/// point as big-endian raw `X ‖ Y` coordinates (spec `RcvrPub`).  The wire
/// `pub_key` is little-endian per coordinate; certificate chain leaves and
/// the report's COSE_Key attest big-endian, so each 48-byte coordinate is
/// reversed.
pub(crate) fn masked_key_report_and_pub(
    ctx: &TestCtx,
    session_id: u16,
) -> (Vec<u8>, Vec<u8>, [u8; RAW_PUB_LEN]) {
    let seal = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id,
            scope: SCOPE_LOCAL,
            kem: tsra_ddi_tbor_types::TRANSFER_KEM_P384,
        })
        .expect("SdSealingKeyGen");
    let masked = seal.masked_key.clone();

    const COORD_LEN: usize = RAW_PUB_LEN / 2;
    let mut rcvr_pub = [0u8; RAW_PUB_LEN];
    rcvr_pub.copy_from_slice(&seal.pub_key);
    dev_rev_in_place(&mut rcvr_pub[..COORD_LEN]);
    dev_rev_in_place(&mut rcvr_pub[COORD_LEN..]);

    let report = ctx
        .key_report(&TborKeyReportReq {
            session_id,
            auth_envelope: Vec::new(),
            masked_key: masked.clone(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("KeyReport");

    (masked, report, rcvr_pub)
}

/// Re-sign the payload of the COSE_Sign1 key report `report` under
/// `signer` (ES384), as a SATA-certified receiver leaf would sign a receiver
/// key report over its KEM key.
pub(crate) fn resign_key_report(report: &[u8], signer: &CaKey) -> Vec<u8> {
    use tsra_ddi_mbor_test_helpers::encode_sig_struct;

    let mut dec = minicbor::Decoder::new(report);
    dec.tag().expect("COSE_Sign1 tag");
    dec.array().expect("COSE_Sign1 array");
    let protected = dec.bytes().expect("protected header");
    let unprotected_at = dec.position();
    dec.skip().expect("unprotected header");
    let unprotected = &report[unprotected_at..dec.position()];
    let payload = dec.bytes().expect("payload");

    let mut tbs = vec![0u8; 64 + protected.len() + payload.len()];
    let tbs_len = encode_sig_struct(protected, payload, &mut tbs).expect("Sig_structure");
    let sig = signer.sign_es384(&tbs[..tbs_len]);

    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);
    enc.tag(minicbor::data::Tag::Unassigned(18))
        .expect("tag")
        .array(4)
        .expect("array")
        .bytes(protected)
        .expect("protected");
    out.extend_from_slice(unprotected);
    let mut enc = minicbor::Encoder::new(&mut out);
    enc.bytes(payload)
        .expect("payload")
        .bytes(&sig)
        .expect("signature");
    out
}

/// Generate a local SD sealing key of `kem` and its PID-signed key report.
/// Returns `(masked_key, report)`.
pub(crate) fn kem_sealing_key_and_report(
    ctx: &TestCtx,
    session_id: u16,
    kem: u8,
) -> (Vec<u8>, Vec<u8>) {
    let seal = ctx
        .tbor(&TborSdSealingKeyGenReq {
            session_id,
            scope: SCOPE_LOCAL,
            kem,
        })
        .expect("SdSealingKeyGen");
    let report = ctx
        .key_report(&TborKeyReportReq {
            session_id,
            auth_envelope: Vec::new(),
            masked_key: seal.masked_key.clone(),
            report_data: [0u8; KEY_REPORT_DATA_LEN],
        })
        .expect("KeyReport");
    (seal.masked_key, report)
}

/// Response of an SD backup-family command plus the out-of-band report it
/// returned at [`SD_BACKUP_REPORT_OOB_INDEX`] (empty for restores).
/// The report is the complete signed encrypted backup, not detached evidence.
#[derive(Debug)]
pub(crate) struct SdOut<T> {
    pub(crate) resp: T,
    pub(crate) report: Vec<u8>,
}

impl<T> core::ops::Deref for SdOut<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.resp
    }
}

/// Response types of the SD backup family: how many report bytes the
/// firmware wrote to the out-of-band report slot.
pub(crate) trait SdReportLen: core::fmt::Debug {
    fn sd_report_len(&self) -> usize;
    fn creates_report() -> bool {
        true
    }
}

macro_rules! sd_report_len {
    ($($ty:ty => $len:expr),* $(,)?) => {
        $(impl SdReportLen for $ty {
            fn sd_report_len(&self) -> usize {
                #[allow(clippy::redundant_closure_call)]
                ($len)(self)
            }
        })*
    };
}

sd_report_len! {
    tsra_ddi_tbor_types::TborSdCreateRemoteBackupResp => |r: &tsra_ddi_tbor_types::TborSdCreateRemoteBackupResp| usize::from(r.report_len.get()),
    tsra_ddi_tbor_types::TborSdCreatePeerBackupResp => |r: &tsra_ddi_tbor_types::TborSdCreatePeerBackupResp| usize::from(r.report_len.get()),
    tsra_ddi_tbor_types::TborSdResealRemoteBackupResp => |r: &tsra_ddi_tbor_types::TborSdResealRemoteBackupResp| usize::from(r.report_len.get()),
    tsra_ddi_tbor_types::TborDarcTmkExportResp => |r: &tsra_ddi_tbor_types::TborDarcTmkExportResp| usize::from(r.report_len.get()),
}

macro_rules! sd_restore_report_len {
    ($($ty:ty),* $(,)?) => {
        $(impl SdReportLen for $ty {
            fn sd_report_len(&self) -> usize { 0 }
            fn creates_report() -> bool { false }
        })*
    };
}

sd_restore_report_len! {
    tsra_ddi_tbor_types::TborSdRestoreRemoteBackupResp,
    tsra_ddi_tbor_types::TborSdRestorePeerBackupResp,
    tsra_ddi_tbor_types::TborSdRestoreLocalBackupResp,
}

/// Issue SD backup-family commands whose OOB item
/// [`SD_BACKUP_REPORT_OOB_INDEX`] is the report output slot for creation;
/// restores keep every input slot available without installing an output.
pub(crate) trait SdOob {
    fn sd_oob<R: TborOpReq>(&self, req: &R, items: &[&[u8]]) -> DdiResult<SdOut<R::OpResp>>
    where
        R::OpResp: SdReportLen;

    #[track_caller]
    fn expect_sd_reject<R: TborOpReq>(
        &self,
        req: &R,
        items: &[&[u8]],
        expected: TborStatus,
    ) -> DdiError
    where
        R::OpResp: SdReportLen;
}

impl SdOob for TestCtx {
    fn sd_oob<R: TborOpReq>(&self, req: &R, items: &[&[u8]]) -> DdiResult<SdOut<R::OpResp>>
    where
        R::OpResp: SdReportLen,
    {
        if !R::OpResp::creates_report() {
            let resp = self.tbor_oob(req, items)?;
            return Ok(SdOut {
                resp,
                report: Vec::new(),
            });
        }
        let mut report = vec![0u8; SD_BACKUP_REPORT_MAX_LEN];
        let mut oob: Vec<TborOobItem<'_>> = vec![TborOobItem::Out(&mut report)];
        oob.extend(
            items
                .iter()
                .skip(SD_BACKUP_REPORT_OOB_INDEX + 1)
                .map(|item| TborOobItem::In(item)),
        );
        let resp = self.tbor_oob_io(req, &mut oob)?;
        drop(oob);
        report.truncate(resp.sd_report_len());
        Ok(SdOut { resp, report })
    }

    #[track_caller]
    fn expect_sd_reject<R: TborOpReq>(
        &self,
        req: &R,
        items: &[&[u8]],
        expected: TborStatus,
    ) -> DdiError
    where
        R::OpResp: SdReportLen,
    {
        if !R::OpResp::creates_report() {
            return self.expect_fw_reject_oob(req, items, expected);
        }
        let mut report = vec![0u8; SD_BACKUP_REPORT_MAX_LEN];
        let mut oob: Vec<TborOobItem<'_>> = vec![TborOobItem::Out(&mut report)];
        oob.extend(
            items
                .iter()
                .skip(SD_BACKUP_REPORT_OOB_INDEX + 1)
                .map(|item| TborOobItem::In(item)),
        );
        self.expect_fw_reject_oob_io(req, &mut oob, expected)
    }
}

/// Fresh OOB item list with the report output slot reserved. A nonempty
/// placeholder also permits borrowing the list as inputs during restore.
pub(crate) fn sd_oob_items() -> Vec<Vec<u8>> {
    vec![vec![0]]
}

/// Receiver attestation evidence: the OOB items (the receiver key chain,
/// then the three evidence cert chains, then the report, in index order)
/// plus the descriptors referencing them.
#[derive(Clone)]
pub(crate) struct ReceiverEvidence {
    /// OOB SGL items in index order: `[receiver root, receiver leaf, mfgr
    /// root, mfgr leaf, owner root, owner leaf, part-owner root, part-owner
    /// leaf, report]`.
    oob_items: Vec<Vec<u8>>,
    /// Receiver key certificate chain (spec `RcvrCertChain`): SATA-anchored,
    /// always validated; its leaf is the recipient key the seal targets.
    pub(crate) receiver: Vec<CertDescriptor>,
    pub(crate) mfgr: Vec<CertDescriptor>,
    pub(crate) owner: Vec<CertDescriptor>,
    pub(crate) part_owner: Vec<CertDescriptor>,
    pub(crate) report: ReportDescriptor,
}

impl ReceiverEvidence {
    /// Append a PublicKey report or signed backup as an extra OOB input.
    pub(crate) fn push_report(&mut self, report: &[u8]) -> ReportDescriptor {
        let desc = push_item(&mut self.oob_items, report);
        ReportDescriptor {
            index: desc.index,
            length: desc.length,
        }
    }

    pub(crate) fn with_report(mut self, report: &[u8]) -> Self {
        self.oob_items[self.report.index as usize] = report.to_vec();
        self.report.length = U16::new(report.len().try_into().expect("report fits descriptor"));
        self
    }

    /// Borrow the OOB items as the `&[&[u8]]` slice `tbor_oob` expects.
    pub(crate) fn oob(&self) -> Vec<&[u8]> {
        self.oob_items.iter().map(Vec::as_slice).collect()
    }

    /// Copy this evidence, replacing only the partition-owner chain with
    /// `part_owner` (appended as new OOB items).
    pub(crate) fn with_part_owner_chain(&self, part_owner: &GeneratedChain) -> Self {
        let mut oob_items = self.oob_items.clone();
        let part_owner_desc = vec![
            push_item(&mut oob_items, &part_owner.root_der),
            push_item(&mut oob_items, &part_owner.leaf_der),
        ];
        Self {
            oob_items,
            receiver: self.receiver.clone(),
            mfgr: self.mfgr.clone(),
            owner: self.owner.clone(),
            part_owner: part_owner_desc,
            report: self.report,
        }
    }
}

/// Append `der` as the next OOB item and return a descriptor for it.
fn push_item(items: &mut Vec<Vec<u8>>, der: &[u8]) -> CertDescriptor {
    let index = items.len() as u8;
    items.push(der.to_vec());
    CertDescriptor {
        index,
        length: U16::new(der.len() as u16),
    }
}

/// Assemble receiver evidence from the receiver key chain plus the three
/// evidence chains and the report, laying the DER items out in the OOB page
/// in index order (receiver chain first).
pub(crate) fn evidence_from_chains(
    receiver: &GeneratedChain,
    mfgr: &GeneratedChain,
    owner: &GeneratedChain,
    part_owner: &GeneratedChain,
    report: &[u8],
) -> ReceiverEvidence {
    let mut items = sd_oob_items();
    let receiver_desc = vec![
        push_item(&mut items, &receiver.root_der),
        push_item(&mut items, &receiver.leaf_der),
    ];
    let mfgr_desc = vec![
        push_item(&mut items, &mfgr.root_der),
        push_item(&mut items, &mfgr.leaf_der),
    ];
    let owner_desc = vec![
        push_item(&mut items, &owner.root_der),
        push_item(&mut items, &owner.leaf_der),
    ];
    let part_owner_desc = vec![
        push_item(&mut items, &part_owner.root_der),
        push_item(&mut items, &part_owner.leaf_der),
    ];
    let report_desc = push_item(&mut items, report);

    ReceiverEvidence {
        oob_items: items,
        receiver: receiver_desc,
        mfgr: mfgr_desc,
        owner: owner_desc,
        part_owner: part_owner_desc,
        report: ReportDescriptor {
            index: report_desc.index,
            length: report_desc.length,
        },
    }
}

/// Build the receiver evidence for the default (flag-clear) path.
///
/// The receiver key certificate chain (spec `RcvrCertChain`) roots at the
/// policy `sata_key` and its leaf certifies `rcvr_pub` — the receiver
/// sealing key `RcvrPub` the backup is sealed to and unmasked with on
/// restore. The three evidence chains' leaves certify `pid_pub` (the report
/// signer): the manufacturer and owner chains root at fresh CAs and the
/// partition-owner chain roots at `sata_key`.
pub(crate) fn build_receiver_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    rcvr_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    report: &[u8],
) -> ReceiverEvidence {
    build_evidence(pid_pub, rcvr_pub, sata_key, sata_key, report)
}

/// Like [`build_receiver_evidence`], but roots the partition-owner chain at
/// `part_owner_anchor` (the policy POTA key for peer and reseal evidence)
/// while the receiver chain stays rooted at `sata_key`.
pub(crate) fn build_evidence(
    pid_pub: &[u8; RAW_PUB_LEN],
    rcvr_pub: &[u8; RAW_PUB_LEN],
    sata_key: &CaKey,
    part_owner_anchor: &CaKey,
    report: &[u8],
) -> ReceiverEvidence {
    let receiver = make_chain(sata_key, rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), pid_pub);
    let owner = make_chain(&CaKey::generate(), pid_pub);
    let part_owner = make_chain(part_owner_anchor, pid_pub);
    evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, report)
}

/// Assemble a `SdCreateRemoteBackup` request carrying the three receiver
/// certificate chains and the attestation-report descriptor.
pub(crate) fn backup_request(
    session_id: u16,
    evidence: &ReceiverEvidence,
    policy: &[u8],
) -> TborSdCreateRemoteBackupReq {
    TborSdCreateRemoteBackupReq {
        session_id,
        receiver_cert_chain: evidence.receiver.clone(),
        receiver_mfgr_cert_chain: evidence.mfgr.clone(),
        receiver_owner_cert_chain: evidence.owner.clone(),
        receiver_part_owner_cert_chain: evidence.part_owner.clone(),
        receiver_report: evidence.report,
        receiver_key_report: Vec::new(),
        policy: policy.to_vec(),
    }
}

/// Minimal evidence (one report OOB item, empty cert chains) for reject
/// tests that fail **before** evidence validation — missing OOB page, or a
/// policy whose backing-partition binding is rejected first.
fn dummy_evidence(report: &[u8]) -> ReceiverEvidence {
    ReceiverEvidence {
        oob_items: vec![Vec::new(), report.to_vec()],
        receiver: Vec::new(),
        mfgr: Vec::new(),
        owner: Vec::new(),
        part_owner: Vec::new(),
        report: ReportDescriptor {
            index: 1,
            length: U16::new(report.len() as u16),
        },
    }
}

#[test]
fn sd_create_remote_backup_roundtrip() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let req = backup_request(session.session_id, &evidence, &policy);
    let resp = ctx
        .sd_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup roundtrip");
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
    let _ = masked_key_report_and_pub(&ctx, session.session_id);
    ctx.tbor(&TborDarcKexKeyGenReq {
        session_id: session.session_id,
        scope: SCOPE_LOCAL,
        kem: tsra_ddi_tbor_types::TRANSFER_KEM_P384,
    })
    .expect("DarcKexKeyGen must remain available after SD provisioning");

    // Canonical header, encapsulation, BKS3 ciphertext, and tag.
    assert_eq!(resp.report.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        resp.report.iter().any(|&b| b != 0),
        "pok_remote_backup must not be all-zero",
    );

    // Local backup: BKS3 masked under PartLocalMK, 280 B, non-zero.
    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );

    // Masking-key backup: SDMK masked under the derived SDBMK, 264 B,
    // non-zero.
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

#[test]
fn sd_create_remote_backup_is_one_shot() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let req = backup_request(session.session_id, &evidence, &policy);
    let first = ctx.sd_oob(&req, &evidence.oob()).expect("first create");
    assert!(
        first.report.iter().any(|&b| b != 0),
        "first backup must be a real seal",
    );

    // The security domain is now initialized (SDMK provisioned); a second
    // create on the same partition is rejected by the one-shot gate.
    ctx.expect_sd_reject(&req, &evidence.oob(), TborStatus::SdAlreadyInitialized);
    assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
}

#[test]
fn sd_create_remote_backup_state_clears_on_erase() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();

    for _ in 0..2 {
        assert_part_state(&ctx, PART_STATE_ENABLED, false);
        let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
        assert_part_state(&ctx, PART_STATE_INITIALIZED, false);
        let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
        let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);
        let req = backup_request(session.session_id, &evidence, &policy);
        ctx.sd_oob(&req, &evidence.oob())
            .expect("SdCreateRemoteBackup after reset");
        assert_part_state(&ctx, PART_STATE_INITIALIZED, true);
        ctx.session_close(session.session_id)
            .expect("close CO session before erase");
        ctx.erase().expect("erase an SD-provisioned partition");
    }
    assert_part_state(&ctx, PART_STATE_ENABLED, false);
}

#[test]
fn sd_create_remote_backup_rejects_missing_oob() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, _pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report) = masked_key_and_report(&ctx, session.session_id);

    // The receiver evidence descriptors reference OOB items, but no OOB
    // page is supplied → the handler rejects before any crypto.
    let evidence = dummy_evidence(&report);
    let req = backup_request(session.session_id, &evidence, &policy);
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

#[test]
fn sd_create_remote_backup_rejects_non_backing_policy() {
    let ctx = TestCtx::new();

    // `finalized_co_session` binds `known_good_part_policy` — POTA/SATA
    // populated but the backing-partition fields left absent.  The policy
    // hash re-check passes (same policy), but the backing-partition
    // identity binding fails (before any evidence validation) because
    // `backup_part_id` / `backup_part_pub_key` do not name this partition.
    let session = finalized_co_session(&ctx);
    let (_, report) = masked_key_and_report(&ctx, session.session_id);

    let policy = known_good_part_policy();
    let evidence = dummy_evidence(&report);
    let req = backup_request(session.session_id, &evidence, &policy);
    ctx.expect_sd_reject(&req, &evidence.oob(), TborStatus::InvalidArg);
}

/// Flip the final byte of a DER/COSE blob — corrupts the trailing ECDSA
/// signature value without disturbing the outer length-prefixed structure.
fn flip_last_byte(mut bytes: Vec<u8>) -> Vec<u8> {
    let n = bytes.len();
    bytes[n - 1] ^= 0xFF;
    bytes
}

#[test]
fn sd_create_remote_backup_rejects_wrong_sata_anchor() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report) = masked_key_and_report(&ctx, session.session_id);

    // The receiver certificate chain is internally valid but rooted at a CA
    // the policy SATA key does not match → the anchor binding fails.  The
    // receiver chain is the always-required recipient source, so this is
    // rejected even with the trusted-SA flag clear.
    let receiver = make_chain(&CaKey::generate(), &pid_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sata_key, &pid_pub);
    let evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    let req = backup_request(session.session_id, &evidence, &policy);
    ctx.expect_sd_reject(&req, &evidence.oob(), TborStatus::InvalidArg);
}

#[test]
fn sd_create_remote_backup_rejects_tampered_cert_sig() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report) = masked_key_and_report(&ctx, session.session_id);

    // Corrupt the receiver leaf's signature: the chain is structurally valid
    // but the leaf's ECDSA signature no longer verifies.
    let mut receiver = make_chain(&sata_key, &pid_pub);
    receiver.leaf_der = flip_last_byte(receiver.leaf_der);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sata_key, &pid_pub);
    let evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    let req = backup_request(session.session_id, &evidence, &policy);
    ctx.expect_sd_reject(&req, &evidence.oob(), TborStatus::X509SignatureInvalid);
}

#[test]
fn sd_create_remote_backup_trusted_sa_roundtrip() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();
    let (session, policy, pid_pub) =
        finalized_backing_session_trusted(&ctx, &sata_key, &sapota_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    // The receiver chain leaf is the attested sealing key (`RcvrPub`),
    // SATA-anchored; the evidence part-owner chain is SAPOTA-anchored and
    // every evidence leaf certifies `pid_pub` (the report signer).  The
    // report attests `RcvrPub`, so the handler's `report_pk == pk_r` check
    // holds and the create succeeds.
    let receiver = make_chain(&sata_key, &rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sapota_key, &pid_pub);
    let evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    let req = backup_request(session.session_id, &evidence, &policy);
    let resp = ctx
        .sd_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup trusted-SA roundtrip");

    assert_eq!(resp.report.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        resp.report.iter().any(|&b| b != 0),
        "pok_remote_backup must not be all-zero",
    );
    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
}

#[test]
fn sd_create_remote_backup_trusted_sa_rejects_evidence_leaf_mismatch() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();
    let (session, policy, pid_pub) =
        finalized_backing_session_trusted(&ctx, &sata_key, &sapota_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    // Under `require_trusted_sa_key` the three-chain evidence is validated
    // (partition-owner chain anchored to SAPOTA).  The owner chain certifies
    // a *different* leaf key, so the chains do not agree on a single leaf →
    // reject.  The receiver chain is valid and certifies the attested
    // sealing key (`RcvrPub`), so this case isolates the evidence-leaf
    // disagreement rather than the `report_pk == pk_r` binding.
    let other_pub = CaKey::generate().raw_pub();
    let receiver = make_chain(&sata_key, &rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &other_pub);
    let part_owner = make_chain(&sapota_key, &pid_pub);
    let evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    let req = backup_request(session.session_id, &evidence, &policy);
    ctx.expect_sd_reject(&req, &evidence.oob(), TborStatus::InvalidArg);
}

#[test]
fn sd_create_remote_backup_trusted_sa_rejects_rcvr_pub_mismatch() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();
    let (session, policy, pid_pub) =
        finalized_backing_session_trusted(&ctx, &sata_key, &sapota_key);
    let (_, report, _rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    // Under `require_trusted_sa_key`, the receiver certificate chain
    // certifies an unrelated key, so the recovered `RcvrPub` differs from
    // the sealing key the evidence report attests → the handler's
    // `report_pk == pk_r` check fails.
    let wrong_rcvr_pub = CaKey::generate().raw_pub();
    let receiver = make_chain(&sata_key, &wrong_rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sapota_key, &pid_pub);
    let evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    let req = backup_request(session.session_id, &evidence, &policy);
    ctx.expect_sd_reject(&req, &evidence.oob(), TborStatus::InvalidArg);
}

#[test]
fn sd_create_remote_backup_trusted_sa_rejects_tampered_report() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();
    let (session, policy, pid_pub) =
        finalized_backing_session_trusted(&ctx, &sata_key, &sapota_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    // Under `require_trusted_sa_key`, all chains are valid and the receiver
    // chain certifies the attested sealing key (`RcvrPub`), so the
    // `report_pk == pk_r` binding holds; the report's signature no longer
    // verifies against its leaf key → reject, isolating the tampered report.
    let tampered_report = flip_last_byte(report);
    let receiver = make_chain(&sata_key, &rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sapota_key, &pid_pub);
    let evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &tampered_report);

    let req = backup_request(session.session_id, &evidence, &policy);
    ctx.expect_sd_reject(&req, &evidence.oob(), TborStatus::InvalidArg);
}

/// Verifies that an unknown session ID cannot create a remote backup.
#[test]
fn sd_create_remote_backup_rejects_invalid_session_id() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let mut req = backup_request(session.session_id, &evidence, &policy);
    req.session_id = u16::MAX;

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "unknown session ID must be rejected",
    );
}

/// A PID report does not substitute for SATA authorization of the recipient.
#[test]
fn sd_create_remote_backup_rejects_missing_recipient_authorization() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let mut req = backup_request(session.session_id, &evidence, &policy);
    req.receiver_cert_chain.clear();

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "missing recipient authorization must be rejected",
    );
}

/// Corruption of the SATA recipient certificate is rejected.
#[test]
fn sd_create_remote_backup_rejects_tampered_recipient_certificate() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let mut evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let req = backup_request(session.session_id, &evidence, &policy);
    let leaf = &mut evidence.oob_items[req.receiver_cert_chain[1].index as usize];
    let last = leaf.len() - 1;
    leaf[last] ^= 0xFF;

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "tampered recipient certificate must be rejected",
    );
}

/// Verifies that a request policy differing from the finalized policy is rejected.
#[test]
fn sd_create_remote_backup_rejects_policy_hash_mismatch() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    // Flip a byte inside the trailing `info` value: still a valid policy,
    // but with a different hash.
    let mut modified_policy = policy;
    let last = modified_policy.len() - 1;
    modified_policy[last] ^= 0x01;

    let req = backup_request(session.session_id, &evidence, &modified_policy);

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "policy hash mismatch must be rejected",
    );
}

/// Verifies that an out-of-range receiver certificate descriptor is rejected.
#[test]
fn sd_create_remote_backup_rejects_invalid_receiver_cert_index() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let mut req = backup_request(session.session_id, &evidence, &policy);
    req.receiver_cert_chain[0].index = u8::MAX;

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "out-of-range receiver certificate index must be rejected",
    );
}

/// Verifies that a receiver certificate descriptor with an incorrect length is rejected.
#[test]
fn sd_create_remote_backup_rejects_receiver_cert_length_mismatch() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);
    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let mut req = backup_request(session.session_id, &evidence, &policy);
    req.receiver_cert_chain[0].length = U16::new(0);

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "receiver certificate length mismatch must be rejected",
    );
}

/// Verifies that trusted-SA validation rejects an invalid attestation-report index.
#[test]
fn sd_create_remote_backup_rejects_invalid_report_index() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();

    let (session, policy, pid_pub) =
        finalized_backing_session_trusted(&ctx, &sata_key, &sapota_key);

    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    let receiver = make_chain(&sata_key, &rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sapota_key, &pid_pub);

    let evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    let mut req = backup_request(session.session_id, &evidence, &policy);

    req.receiver_report.index = u8::MAX;

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "invalid trusted receiver report index must be rejected",
    );
}

/// Verifies that trusted-SA validation rejects an incorrect attestation-report length.
#[test]
fn sd_create_remote_backup_rejects_report_length_mismatch() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();

    let (session, policy, pid_pub) =
        finalized_backing_session_trusted(&ctx, &sata_key, &sapota_key);

    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    let receiver = make_chain(&sata_key, &rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sapota_key, &pid_pub);

    let evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    let mut req = backup_request(session.session_id, &evidence, &policy);

    req.receiver_report.length = U16::new(0);

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "trusted receiver report length mismatch must be rejected",
    );
}

/// Verifies that an empty receiver certificate chain is rejected.
#[test]
fn sd_create_remote_backup_rejects_empty_receiver_cert_chain() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);

    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let mut req = backup_request(session.session_id, &evidence, &policy);

    req.receiver_cert_chain.clear();

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "empty receiver certificate chain must be rejected",
    );
}

/// Verifies that corrupted receiver certificate data is rejected.
#[test]
fn sd_create_remote_backup_rejects_corrupted_receiver_cert() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);

    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    let receiver = make_chain(&sata_key, &rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sata_key, &pid_pub);

    let mut evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    evidence.oob_items[usize::from(evidence.receiver[0].index)][0] ^= 0xFF;

    let req = backup_request(session.session_id, &evidence, &policy);

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "corrupted receiver certificate must be rejected",
    );
}

/// Verifies that trusted-SA validation rejects a missing attestation-report OOB item.
#[test]
fn sd_create_remote_backup_rejects_missing_report_oob() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();

    let (session, policy, pid_pub) =
        finalized_backing_session_trusted(&ctx, &sata_key, &sapota_key);

    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    let receiver = make_chain(&sata_key, &rcvr_pub);
    let mfgr = make_chain(&CaKey::generate(), &pid_pub);
    let owner = make_chain(&CaKey::generate(), &pid_pub);
    let part_owner = make_chain(&sapota_key, &pid_pub);

    let mut evidence = evidence_from_chains(&receiver, &mfgr, &owner, &part_owner, &report);

    evidence.oob_items.pop();

    let req = backup_request(session.session_id, &evidence, &policy);

    assert!(
        ctx.sd_oob(&req, &evidence.oob()).is_err(),
        "missing trusted receiver report must be rejected",
    );
}

/// Verifies that a rejected create leaves the security domain uninitialized.
#[test]
fn sd_create_remote_backup_failed_create_allows_retry() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();

    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);

    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let valid_req = backup_request(session.session_id, &evidence, &policy);

    let mut invalid_req = valid_req.clone();
    invalid_req.receiver_cert_chain.clear();

    assert!(
        ctx.sd_oob(&invalid_req, &evidence.oob()).is_err(),
        "invalid create request must be rejected",
    );

    let resp = ctx
        .sd_oob(&valid_req, &evidence.oob())
        .expect("valid create must succeed after rejected request");

    assert_eq!(resp.report.len(), POK_REMOTE_BACKUP_LEN,);

    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN,);

    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN,);

    assert!(
        resp.report.iter().any(|&b| b != 0),
        "remote backup must not be all-zero",
    );

    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "local backup must not be all-zero",
    );

    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "SD masking-key backup must not be all-zero",
    );

    ctx.expect_sd_reject(
        &valid_req,
        &evidence.oob(),
        TborStatus::SdAlreadyInitialized,
    );
}

/// Verifies that duplicate receiver certificate descriptors are accepted by the current firmware.
#[test]
fn sd_create_remote_backup_accepts_duplicate_receiver_cert_descriptor() {
    let ctx = TestCtx::new();
    let sata_key = CaKey::generate();

    let (session, policy, pid_pub) = finalized_backing_session(&ctx, &sata_key);

    let (_, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session.session_id);

    let evidence = build_receiver_evidence(&pid_pub, &rcvr_pub, &sata_key, &report);

    let mut req = backup_request(session.session_id, &evidence, &policy);

    req.receiver_cert_chain[1] = req.receiver_cert_chain[0];

    let resp = ctx
        .sd_oob(&req, &evidence.oob())
        .expect("current firmware accepts duplicate receiver descriptors");

    assert_eq!(resp.report.len(), POK_REMOTE_BACKUP_LEN,);

    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN,);

    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN,);
}
