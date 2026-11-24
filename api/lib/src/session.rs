// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM session management.
//!
//! This module provides structures and operations for managing HSM sessions.
//! Sessions represent authenticated connections to an HSM partition, providing
//! a context for performing cryptographic operations.

use std::fmt;
use std::sync::Arc;

use parking_lot::Mutex;
use parking_lot::RwLock;
use tracing::*;
use tsra_crypto::AesKey;
use zeroize::Zeroize;

use super::*;

#[derive(Debug, Clone)]
pub struct HsmSession {
    inner: Arc<RwLock<HsmSessionInner>>,
}

/// Marker trait for HSM sessions.
impl Session for HsmSession {}

impl HsmSession {
    #[instrument(skip_all, fields(session_id = id))]
    pub(crate) fn new(
        id: u16,
        app_id: u8,
        rev: HsmApiRev,
        partition: HsmPartition,
        ddi_cookie: Option<u64>,
        seed: [u8; 48],
        bmk_session: Vec<u8>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HsmSessionInner::new(
                id,
                app_id,
                rev,
                partition,
                ddi_cookie,
                seed,
                bmk_session,
            ))),
        }
    }

    /// Wraps a successful `open_session_ex` (V2) result in a session
    /// handle.
    pub(crate) fn new_ex(
        rev: HsmApiRev,
        partition: HsmPartition,
        result: ddi::OpenSessionExResult,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HsmSessionInner::new_ex(rev, partition, result))),
        }
    }

    delegate::delegate! {
        to self.inner.read() {
            pub fn id(&self) -> u16;
            pub(crate) fn _app_id(&self) -> u8;
            pub fn api_rev(&self) -> HsmApiRev;

            pub(crate) fn with_dev<F, R>(&self, f: F) -> HsmResult<R>
            where
                F: FnOnce(&ddi::HsmDev) -> HsmResult<R>;

            pub(crate) fn with_dev_no_cookie<F, R>(&self, f: F) -> HsmResult<R>
            where
                F: FnOnce(&ddi::HsmDev) -> HsmResult<R>;
        }
    }

    /// Returns the partition restore epoch at which this session
    /// was last reopened.
    pub(crate) fn last_restore_epoch(&self) -> u64 {
        self.inner.read().last_restore_epoch()
    }

    pub(crate) fn ddi_cookie(&self) -> Option<u64> {
        *self.inner.read().ddi_cookie.lock()
    }

    /// Updates the session's continuity cookie after a successful
    /// `reopen_session`. The backend may return a refreshed token bound
    /// to the new connection/generation; callers that keep using the
    /// pre-reopen cookie would have every subsequent in-session call
    /// (and the eventual close) rejected as belonging to an unknown
    /// session.
    pub(crate) fn set_ddi_cookie(&self, ddi_cookie: Option<u64>) {
        *self.inner.read().ddi_cookie.lock() = ddi_cookie;
    }

    /// Serializes session-reopen attempts for a given epoch.
    ///
    /// Acquires the session write lock and checks whether the session
    /// has already been reopened to `part_restore_epoch`.  If so, returns
    /// `Ok(None)` without calling `f`.  Otherwise, executes `f` under
    /// the lock and, on success, advances the session epoch to
    /// `part_restore_epoch` before releasing the lock.
    ///
    /// This ensures that only one thread performs the DDI `reopen_session`
    /// call for a given a resiliency event; racing threads block on the write lock
    /// and then observe the updated epoch.
    pub(crate) fn with_reopen_guard<F, R>(
        &self,
        part_restore_epoch: u64,
        f: F,
    ) -> HsmResult<Option<R>>
    where
        F: FnOnce() -> HsmResult<R>,
    {
        let mut inner = self.inner.write();
        if inner.last_restore_epoch == part_restore_epoch {
            return Ok(None);
        } else if inner.last_restore_epoch > part_restore_epoch {
            // This should never happen — session cannot be newer than the partition's epoch.
            return Err(HsmError::InternalError);
        }

        // Session is stale, execute the reopen under the lock.
        // If it succeeds, update the session's last_restore_epoch.
        let result = f()?;
        inner.last_restore_epoch = part_restore_epoch;
        Ok(Some(result))
    }

    /// Returns the partition handle associated with this session.
    pub(crate) fn partition(&self) -> HsmPartition {
        self.inner.read().partition().clone()
    }

    /// Returns the 48-byte V1 session seed needed for
    /// `reopen_session`, or `None` for a V2 session (whose stale
    /// state must be re-established via a fresh handshake, not the
    /// V1 reopen path).
    pub(crate) fn seed(&self) -> Option<[u8; 48]> {
        self.inner.read().seed()
    }

    /// Returns a clone of the backed-up session masking key.
    pub(crate) fn bmk_session(&self) -> Vec<u8> {
        self.inner.read().bmk_session()
    }

    /// Updates the backed-up session masking key after a successful reopen.
    pub(crate) fn set_bmk_session(&self, bmk_session: Vec<u8>) {
        self.inner.write().set_bmk_session(bmk_session);
    }

    /// Returns the active TBOR (V2, security-domain) session id.
    ///
    /// Yields the session id for a V2 session, or
    /// [`HsmError::InvalidSession`] for a V1 session. Used by the DDI
    /// layer to bind security-domain commands to the session.
    pub(crate) fn ex_session_id(&self) -> HsmResult<u16> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => Ok(inner.id),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Returns `true` for a V2 (security-domain / TBOR) session.
    ///
    /// Used by the DDI layer to route key operations to the TBOR
    /// (masked, non-resident) path vs. the MBOR (device-resident) path.
    pub(crate) fn is_ex(&self) -> bool {
        matches!(self.inner.read().kind, SessionKind::Ver2 { .. })
    }

    /// Issues TBOR `PskChange` (opcode `0x06`) on this session.
    ///
    /// Rotates this session's own partition PSK to `new_psk`, sealed
    /// under the session `param_key`. The slot is implied by the session
    /// role (CO session → CO, CU session → CU). Required once on a fresh
    /// partition to move past the default-PSK gate before provisioning.
    /// Only valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn change_psk(&self, new_psk: &[u8; PSK_LEN]) -> HsmResult<()> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { param_key, .. } => ddi::psk_change(
                &inner.partition,
                inner.rev,
                inner.id,
                param_key,
                new_psk,
                &inner.ddi_cookie,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Recover this migrated TBOR session with the current role PSK, which a
    /// migration returns to the role's default (`None`) until a session
    /// rotates it again.
    ///
    /// Uses a fresh authenticated handshake while restoring the original
    /// masking key. Reopen neither grants another PSK change nor retries the
    /// interrupted application command; the migration restored the
    /// session's PSK change, so a session reopened under the default PSK
    /// rotates its role PSK. Only valid for a stale V2 session.
    pub fn reopen_ex(
        &self,
        root_spki_thumbprint: &[u8; 48],
        psk: Option<&[u8; PSK_LEN]>,
    ) -> HsmResult<()> {
        let mut inner = self.inner.write();
        let SessionKind::Ver2 {
            psk_id,
            suite,
            seed,
            bmk_session,
            ..
        } = &inner.kind
        else {
            return Err(HsmError::InvalidSession);
        };
        let result = ddi::reopen_session_ex(
            &inner.partition,
            inner.rev,
            root_spki_thumbprint,
            *psk_id,
            psk,
            *suite,
            inner.id,
            seed,
            bmk_session,
        )?;
        inner.kind = SessionKind::Ver2 {
            psk_id: result.psk_id,
            suite: result.suite,
            param_key: result.param_key,
            bmk_session: result.bmk_session.to_vec(),
            seed: result.seed,
        };
        *inner.ddi_cookie.lock() = result.ddi_cookie;
        Ok(())
    }

    pub(crate) fn key_report_auth(
        &self,
        request: &tsra_ddi_tbor_types::TborKeyReportReq,
    ) -> HsmResult<Vec<u8>> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { param_key, .. } => {
                tsra_session_ex_crypto::seal_key_report_auth(param_key, request)
                    .map_err(|_| HsmError::InternalError)
            }
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `PartInit` (opcode `0x07`) on this CO session.
    ///
    /// Seals `mach_seed` under the session `param_key` and ships it
    /// alongside `part_policy` (the partition policy CBOR document).
    /// Only valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn part_init_ex(
        &self,
        part_policy: &[u8],
        mach_seed: &[u8],
    ) -> HsmResult<HsmPartInitExResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { param_key, .. } => ddi::part_init_ex(
                &inner.partition,
                inner.id,
                param_key,
                mach_seed,
                part_policy,
                &inner.ddi_cookie,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `PartFinal` (opcode `0x08`) on this CO session.
    ///
    /// Re-supplies `part_policy` (for the POTA trust anchor)
    /// and the PTA certificate chain (as a list of [`HsmCert`]s),
    /// optionally restoring a prior `local_mk` backup. Only valid on a V2
    /// session; a V1 session returns [`HsmError::InvalidSession`].
    pub fn part_final_ex(
        &self,
        part_policy: &[u8],
        pta_cert_chain: &[HsmCert<'_>],
        prev_local_mk_backup: Option<&[u8]>,
    ) -> HsmResult<HsmPartFinalExResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::part_final_ex(
                &inner.partition,
                inner.id,
                part_policy,
                pta_cert_chain,
                prev_local_mk_backup,
                &inner.ddi_cookie,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdCreateRemoteBackup` (opcode `0x0A`) on this CO
    /// session.
    ///
    /// Creates a new security domain from the caller-supplied
    /// `part_policy`, using the sender's `masked_sealing_key` (from
    /// `SdSealingKeyGen`). The receiver public key is always recovered from
    /// the authoritative `receiver_cert_chain` (anchored to the policy SATA
    /// key thumbprint); `receiver_evidence` is optional and verified only when the
    /// policy sets `require_trusted_sa_key` (pass an empty evidence
    /// otherwise). Returns the remote backup together with the device-local
    /// backups. Only valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn sd_create_remote_backup(
        &self,
        part_policy: &[u8],
        masked_sealing_key: &[u8],
        receiver_cert_chain: &[HsmCert<'_>],
        receiver_evidence: &HsmSdEvidence<'_>,
    ) -> HsmResult<HsmSdRemoteBackupResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_create_remote_backup_ex(
                &inner.partition,
                inner.rev,
                inner.id,
                masked_sealing_key,
                receiver_cert_chain,
                receiver_evidence,
                part_policy,
                &inner.ddi_cookie,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `DarcKexKeyGen` (opcode `0x20`) on this CO session.
    ///
    /// Generates a new DARC key-exchange key (ECC-P384) and returns the
    /// masked private key plus its raw P-384 public key (`x ‖ y`, 96
    /// bytes, big-endian per coordinate). Run on the target it yields the HPKE receiver identity; run
    /// on the source it yields the HPKE sender-auth identity. Only valid on
    /// a V2 session; a V1 session returns [`HsmError::InvalidSession`].
    pub fn darc_kex_key_gen(
        &self,
        scope: u8,
    ) -> HsmResult<([u8; MASKED_KEX_KEY_LEN], [u8; KEX_PUB_KEY_LEN])> {
        ddi::darc_kex_key_gen(self, scope)
    }

    /// Issues TBOR `DarcTmkGen` (opcode `0x23`) on this CO session.
    ///
    /// Mints a fresh 256-bit Transfer Masking Key (TMK) on the source and
    /// returns it masked under the partition SDMK. Only valid on a V2
    /// session; a V1 session returns [`HsmError::InvalidSession`].
    pub fn darc_tmk_gen(&self) -> HsmResult<Vec<u8>> {
        ddi::darc_tmk_gen(self)
    }

    /// Issues TBOR `DarcTmkExport` (opcode `0x24`) on this CO session.
    ///
    /// Seals the TMK to an authenticated target: validates
    /// `target_cert_chain` against the policy DATA key thumbprint, then HPKE-Auth
    /// seals the TMK to the target's KEX key. Returns the sealed TMK. Only
    /// valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn darc_tmk_export(
        &self,
        masked_sender_key: &[u8],
        masked_tmk: &[u8],
        policy: &[u8],
        target_cert_chain: &[HsmCert<'_>],
    ) -> HsmResult<[u8; SEALED_TMK_LEN]> {
        ddi::darc_tmk_export(
            self,
            masked_sender_key,
            masked_tmk,
            policy,
            target_cert_chain,
        )
    }

    /// Issues TBOR `DarcTmkImport` (opcode `0x21`) on this CO session.
    ///
    /// Opens a `sealed_tmk` on the target: validates `remote_cert_chain`
    /// against the policy POTA key thumbprint, HPKE-Auth opens the sealed TMK, and
    /// re-masks it under the partition SDMK. Returns the masked TMK. Only
    /// valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn darc_tmk_import(
        &self,
        masked_kex_key: &[u8],
        policy: &[u8],
        sealed_tmk: &[u8],
        remote_cert_chain: &[HsmCert<'_>],
    ) -> HsmResult<Vec<u8>> {
        ddi::darc_tmk_import(self, masked_kex_key, policy, sealed_tmk, remote_cert_chain)
    }

    /// Issues TBOR `SdResealRemoteBackup` (opcode `0x0B`) on this CO
    /// session.
    ///
    /// HPKE-opens `src_remote_backup` with the receiver's
    /// `masked_sealing_key` (authenticated by the source sender in
    /// `src_evidence`) and reseals the recovered backup to the destination
    /// receiver (`dest_evidence`), returning the resealed remote backup.
    /// Only valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn sd_reseal_remote_backup(
        &self,
        part_policy: &[u8],
        masked_sealing_key: &[u8],
        src_evidence: &HsmSdEvidence<'_>,
        dest_evidence: &HsmSdEvidence<'_>,
        src_remote_backup: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_reseal_remote_backup_ex(
                &inner.partition,
                inner.rev,
                inner.id,
                masked_sealing_key,
                src_evidence,
                dest_evidence,
                part_policy,
                src_remote_backup,
                &inner.ddi_cookie,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdRestoreRemoteBackup` (opcode `0x0C`) on this CO
    /// session.
    ///
    /// HPKE-opens `src_remote_backup` with the receiver's
    /// `masked_sealing_key` (authenticated by the sender key recovered from
    /// `sender_cert_chain`), recovers the security-domain masking key from
    /// `prev_sd_mk_backup`, and returns the refreshed device-local backups.
    /// Only valid on a V2 session; a V1 session returns
    /// [`HsmError::InvalidSession`].
    pub fn sd_restore_remote_backup(
        &self,
        part_policy: &[u8],
        masked_sealing_key: &[u8],
        sender_cert_chain: &[HsmCert<'_>],
        sender_evidence: &HsmSdEvidence<'_>,
        src_remote_backup: &[u8],
        prev_sd_mk_backup: &[u8],
    ) -> HsmResult<HsmSdRestoreResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_restore_remote_backup_ex(
                &inner.partition,
                inner.rev,
                inner.id,
                masked_sealing_key,
                sender_cert_chain,
                sender_evidence,
                part_policy,
                src_remote_backup,
                prev_sd_mk_backup,
                &inner.ddi_cookie,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdCreatePeerBackup` (opcode `0x0E`) on this CO session.
    ///
    /// Recovers BKS3 from `pok_local_backup` and HPKE-Auth-seals it to the
    /// destination peer in `dst_evidence` (authenticated by the sender's
    /// `masked_sealing_key`), returning the peer backup. Gated by the
    /// security domain's `allow_peer_cloning` policy flag. Only valid on a
    /// V2 session; a V1 session returns [`HsmError::InvalidSession`].
    pub fn sd_create_peer_backup(
        &self,
        part_policy: &[u8],
        masked_sealing_key: &[u8],
        dst_evidence: &HsmSdEvidence<'_>,
        pok_local_backup: &[u8],
    ) -> HsmResult<Vec<u8>> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_create_peer_backup_ex(
                &inner.partition,
                inner.rev,
                inner.id,
                masked_sealing_key,
                dst_evidence,
                part_policy,
                pok_local_backup,
                &inner.ddi_cookie,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdRestorePeerBackup` (opcode `0x0F`) on this CO
    /// session.
    ///
    /// HPKE-opens `pok_peer_backup` with the receiver's `masked_sealing_key`
    /// (authenticated by the source peer in `src_evidence`), recovers the
    /// security-domain masking key from `prev_sd_mk_backup`, and returns the
    /// refreshed device-local backups. Gated by the security domain's
    /// `allow_peer_cloning` policy flag. Only valid on a V2 session; a V1
    /// session returns [`HsmError::InvalidSession`].
    pub fn sd_restore_peer_backup(
        &self,
        part_policy: &[u8],
        masked_sealing_key: &[u8],
        src_evidence: &HsmSdEvidence<'_>,
        pok_peer_backup: &[u8],
        prev_sd_mk_backup: &[u8],
    ) -> HsmResult<HsmSdRestoreResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_restore_peer_backup_ex(
                &inner.partition,
                inner.rev,
                inner.id,
                masked_sealing_key,
                src_evidence,
                part_policy,
                pok_peer_backup,
                prev_sd_mk_backup,
                &inner.ddi_cookie,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }

    /// Issues TBOR `SdRestoreLocalBackup` (opcode `0x0D`) on this CO
    /// session.
    ///
    /// Restores the security domain from the device-local `pok_local_backup`
    /// and `sd_mk_backup` (no attestation evidence is involved), returning
    /// the refreshed device-local backups. Only valid on a V2 session; a V1
    /// session returns [`HsmError::InvalidSession`].
    pub fn sd_restore_local_backup(
        &self,
        pok_local_backup: &[u8],
        sd_mk_backup: &[u8],
    ) -> HsmResult<HsmSdRestoreResult> {
        let inner = self.inner.read();
        match &inner.kind {
            SessionKind::Ver2 { .. } => ddi::sd_restore_local_backup_ex(
                &inner.partition,
                inner.rev,
                inner.id,
                pok_local_backup,
                sd_mk_backup,
                &inner.ddi_cookie,
            ),
            SessionKind::Ver1 { .. } => Err(HsmError::InvalidSession),
        }
    }
}

/// Transport-specific session state.
///
/// The fields that differ between the V1 `open_session` path and the
/// V2 `open_session_ex` handshake live here; the shared
/// identity/rev/partition/epoch fields stay on [`HsmSessionInner`].
enum SessionKind {
    /// Version 1 session, established over the single-round-trip
    /// `OpenSession` command.
    Ver1 {
        /// 8-bit application id assigned by the device.
        app_id: u8,
        /// 48-byte random seed used for credential encryption during
        /// `open_session`. Needed by `reopen_session` after a
        /// resiliency event.
        seed: [u8; 48],
        /// Backed-up session masking key returned by the device.
        /// Updated after each successful `reopen_session` call.
        bmk_session: Vec<u8>,
    },
    /// Version 2 session, established over the two-phase
    /// `OpenSessionEx` handshake.
    Ver2 {
        /// Secret context for recovering the original session masking key.
        seed: zeroize::Zeroizing<[u8; 32]>,
        /// PSK id selecting the role (0 = CO, 1 = CU).
        psk_id: u8,
        /// Key-establishment suite of the handshake.
        suite: HsmSessionSuite,
        /// Per-session AES-256 wrap key derived from the handshake secret.
        /// Sensitive — never logged (redacted in the manual `Debug`
        /// impl, since `AesKey` is not `Debug`).
        param_key: AesKey,
        /// FW-emitted wrapped masking-key blob.
        bmk_session: Vec<u8>,
    },
}

impl fmt::Debug for SessionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionKind::Ver1 {
                app_id,
                seed,
                bmk_session,
            } => f
                .debug_struct("Ver1")
                .field("app_id", app_id)
                .field("seed", &format_args!("<redacted; {} bytes>", seed.len()))
                .field(
                    "bmk_session",
                    &format_args!("<redacted; {} bytes>", bmk_session.len()),
                )
                .finish(),
            SessionKind::Ver2 {
                psk_id,
                suite,
                bmk_session,
                ..
            } => f
                .debug_struct("Ver2")
                .field("psk_id", psk_id)
                .field("suite", suite)
                .field("param_key", &"<redacted>")
                .field(
                    "bmk_session",
                    &format_args!("<redacted; {} bytes>", bmk_session.len()),
                )
                .finish(),
        }
    }
}

/// HSM session handle.
///
/// Represents an active authenticated session with an HSM partition. Each session
/// is associated with a specific application ID and provides the context for
/// cryptographic operations within the partition.
///
/// The `last_restore_epoch` field tracks the most recent partition restore
/// epoch that this session has been reopened for, enabling per-session
/// staleness detection during key operations.
#[derive(Debug)]
struct HsmSessionInner {
    id: u16,
    rev: HsmApiRev,
    partition: HsmPartition,
    /// Opaque per-session continuity token handed back by the DDI
    /// backend (see `DdiCookie` in `ddi/interface`) and threaded into
    /// every subsequent `exec_op_tbor`/`exec_op_mbor` call for this
    /// session. Most backends ignore it, but any backend that tracks
    /// session state across calls (e.g. to recognize a session across a
    /// transport-level reset) relies on seeing the same cookie on every
    /// call for a given session id — including calls issued outside
    /// `with_dev`'s automatic `with_session_cookie` scope (see
    /// `ddi/partition_ex.rs`, `ddi/sd_restore_local_backup.rs`,
    /// `ddi/sd_create_remote_backup.rs`, `ddi/sd_reseal_remote_backup.rs`,
    /// `ddi/sd_restore_remote_backup.rs`, `ddi/sd_create_peer_backup.rs`,
    /// `ddi/sd_restore_peer_backup.rs`), which must read, pass, and write
    /// back this field explicitly instead of passing `&mut None`.
    ddi_cookie: Mutex<Option<u64>>,
    /// The partition restore epoch at which this session was last reopened.
    /// Compared against `ResiliencyState::restore_epoch` to decide whether
    /// a `reopen_session` call is needed before retrying a key operation.
    last_restore_epoch: u64,
    /// Version-specific session material (V1 vs V2).
    kind: SessionKind,
}

impl Drop for HsmSessionInner {
    /// Automatically closes the session when the handle is dropped.
    ///
    /// Ensures that HSM resources are properly released by closing the
    /// session connection when the `HsmSession` goes out of scope.
    #[instrument(skip_all, fields(session_id = self.id))]
    fn drop(&mut self) {
        let _ = match &self.kind {
            SessionKind::Ver1 { .. } => {
                self.with_dev(|dev| ddi::close_session(dev, self.id, self.rev))
            }
            SessionKind::Ver2 { .. } => {
                ddi::close_session_ex(&self.partition, self.rev, self.id, &self.ddi_cookie)
            }
        };

        // Wipe sensitive session material from process memory once the
        // session is closed: `seed` for V1 and the device-wrapped
        // `bmk_session` blob for both.
        match &mut self.kind {
            SessionKind::Ver1 {
                seed, bmk_session, ..
            } => {
                seed.zeroize();
                bmk_session.zeroize();
            }
            SessionKind::Ver2 { bmk_session, .. } => {
                bmk_session.zeroize();
            }
        }
    }
}

impl HsmSessionInner {
    /// Creates a new HSM session handle.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique session identifier
    /// * `app_id` - Application identifier for this session
    /// * `rev` - API revision used for this session
    /// * `partition` - The HSM partition this session is associated with
    ///
    /// # Returns
    ///
    /// A new `HsmSession` instance.
    #[instrument(skip_all, fields(session_id = id))]
    pub(crate) fn new(
        id: u16,
        app_id: u8,
        rev: HsmApiRev,
        partition: HsmPartition,
        ddi_cookie: Option<u64>,
        seed: [u8; 48],
        bmk_session: Vec<u8>,
    ) -> Self {
        let epoch = partition.restore_epoch();
        Self {
            id,
            rev,
            partition,
            ddi_cookie: Mutex::new(ddi_cookie),
            last_restore_epoch: epoch,
            kind: SessionKind::Ver1 {
                app_id,
                seed,
                bmk_session,
            },
        }
    }

    /// Creates a new V2 session handle from an `open_session_ex`
    /// result.
    #[instrument(skip_all, fields(session_id = result.session_id))]
    pub(crate) fn new_ex(
        rev: HsmApiRev,
        partition: HsmPartition,
        result: ddi::OpenSessionExResult,
    ) -> Self {
        let epoch = partition.restore_epoch();
        Self {
            id: result.session_id,
            rev,
            partition,
            ddi_cookie: Mutex::new(result.ddi_cookie),
            last_restore_epoch: epoch,
            kind: SessionKind::Ver2 {
                psk_id: result.psk_id,
                suite: result.suite,
                param_key: result.param_key,
                bmk_session: result.bmk_session.to_vec(),
                seed: result.seed,
            },
        }
    }

    /// Returns the session identifier.
    ///
    /// # Returns
    ///
    /// The unique 16-bit session ID assigned by the HSM.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Returns a reference to the associated partition.
    ///
    /// # Returns
    ///
    /// A reference to the `HsmPartition` handle that this session is bound to.
    pub(crate) fn partition(&self) -> &HsmPartition {
        &self.partition
    }

    /// Returns the application identifier.
    ///
    /// # Returns
    ///
    /// The 8-bit application ID associated with this session (V1
    /// only; `0` for a V2 session).
    pub(crate) fn _app_id(&self) -> u8 {
        match &self.kind {
            SessionKind::Ver1 { app_id, .. } => *app_id,
            SessionKind::Ver2 { .. } => 0,
        }
    }

    /// Returns the 48-byte V1 session seed, or `None` for a V2
    /// session (which is re-established via a fresh handshake rather
    /// than the V1 reopen path).
    pub(crate) fn seed(&self) -> Option<[u8; 48]> {
        match &self.kind {
            SessionKind::Ver1 { seed, .. } => Some(*seed),
            SessionKind::Ver2 { .. } => None,
        }
    }

    /// Returns a clone of the backed-up session masking key.
    pub(crate) fn bmk_session(&self) -> Vec<u8> {
        match &self.kind {
            SessionKind::Ver1 { bmk_session, .. } | SessionKind::Ver2 { bmk_session, .. } => {
                bmk_session.clone()
            }
        }
    }

    /// Replaces the backed-up session masking key after a successful
    /// reopen.
    pub(crate) fn set_bmk_session(&mut self, bmk_session: Vec<u8>) {
        match &mut self.kind {
            SessionKind::Ver1 { bmk_session: b, .. } | SessionKind::Ver2 { bmk_session: b, .. } => {
                *b = bmk_session;
            }
        }
    }

    /// Returns the API revision used by this session.
    ///
    /// # Returns
    ///
    /// The `HsmApiRev` that was specified when the session was opened.
    pub(crate) fn api_rev(&self) -> HsmApiRev {
        self.rev
    }

    /// Executes a closure with access to the underlying device handle.
    ///
    /// Provides thread-safe access to the HSM device through the session's
    /// associated partition. Acquires a read lock on the partition and passes
    /// the device handle to the provided closure.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that receives the device handle and returns a result
    ///
    /// # Returns
    ///
    /// Returns the result produced by the closure.
    ///
    /// # Errors
    ///
    /// Returns any error produced by the closure.
    pub(crate) fn with_dev<F, R>(&self, f: F) -> HsmResult<R>
    where
        F: FnOnce(&ddi::HsmDev) -> HsmResult<R>,
    {
        let part = self.partition().inner().read();
        let dev = part.dev();
        ddi::with_session_cookie(&self.ddi_cookie, || f(dev))
    }

    /// Executes a closure with access to the underlying device handle,
    /// without serializing on the session's cookie mutex.
    ///
    /// For cookie-free fast-path operations (e.g. the V1 AES-GCM/XTS
    /// bulk calls, which go straight to the backend without ever
    /// reading or writing `ddi_cookie`): holding the cookie mutex for
    /// their entire device call would needlessly serialize concurrent
    /// bulk operations sharing a session, removing concurrency the
    /// backend's own locking already allows. Use [`Self::with_dev`]
    /// instead for any call that may read or write the session's
    /// continuity cookie (MBOR/TBOR exchanges).
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that receives the device handle and returns a result
    ///
    /// # Returns
    ///
    /// Returns the result produced by the closure.
    ///
    /// # Errors
    ///
    /// Returns any error produced by the closure.
    pub(crate) fn with_dev_no_cookie<F, R>(&self, f: F) -> HsmResult<R>
    where
        F: FnOnce(&ddi::HsmDev) -> HsmResult<R>,
    {
        let part = self.partition().inner().read();
        let dev = part.dev();
        f(dev)
    }

    /// Returns the partition restore epoch at which this session was last
    /// reopened.
    pub(crate) fn last_restore_epoch(&self) -> u64 {
        self.last_restore_epoch
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use std::time::Instant;

    use tsra_crypto::HashAlgo;
    use tsra_crypto::Hasher;
    use x509::X509Certificate;
    use x509::X509CertificateOp;

    use super::*;

    #[test]
    fn tbor_sealing_key_rejection_completes_with_queued_session_writer() {
        let info = HsmPartitionManager::partition_info_list()
            .into_iter()
            .next()
            .expect("partition");
        let rev = info.api_rev_range.expect("API revision range").max();
        let part = HsmPartitionManager::open_partition(&info.path, rev).expect("open partition");
        let pem = part.cert_chain(0).expect("test chain");
        let certificates =
            X509Certificate::from_pem_stack(pem.as_bytes()).expect("test certificates");
        let spki = certificates
            .last()
            .expect("test root")
            .subject_public_key_info_der()
            .expect("test root SPKI");
        let root_pin: [u8; 48] = Hasher::hash_vec(&mut HashAlgo::sha384(), spki)
            .expect("test root hash")
            .try_into()
            .expect("SHA-384 length");
        let session = part
            .open_session_ex(
                rev,
                &root_pin,
                HsmSessionPsk::new(HsmPskId::CO),
                HsmSessionSuite::EcdhP384,
            )
            .expect("open EX session");
        let psk = rand::random::<[u8; PSK_LEN]>();
        session.change_psk(&psk).expect("rotate CO PSK");
        // Pause with_dev after it holds the session read lock but before its callback.
        let partition_guard = part.inner().write();
        let command_session = session.clone();
        let (completed_tx, completed_rx) = mpsc::channel();
        let command = thread::spawn(move || {
            let result = ddi::sd_sealing_key_gen(&command_session, u8::MAX);
            completed_tx.send(result).expect("report command result");
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while session
            .inner
            .try_write_for(Duration::from_millis(50))
            .is_some()
        {
            assert!(
                Instant::now() < deadline,
                "command must acquire session lock"
            );
            thread::yield_now();
        }
        let writer_session = session.clone();
        let writer = thread::spawn(move || {
            // A timeout releases the queued writer even if the old code deadlocks.
            writer_session
                .inner
                .try_write_for(Duration::from_secs(5))
                .is_some()
        });
        while session.inner.try_read().is_some() {
            assert!(Instant::now() < deadline, "session writer must be queued");
            thread::yield_now();
        }
        drop(partition_guard);
        let result = completed_rx.recv_timeout(Duration::from_secs(2));
        let writer_acquired = writer.join().expect("session writer");
        command.join().expect("key generation thread");
        assert_eq!(
            result.expect("command must finish without waiting for the queued writer to time out"),
            Err(HsmError::InvalidArgument)
        );
        assert!(
            writer_acquired,
            "writer must acquire the lock after the command"
        );
    }
}
