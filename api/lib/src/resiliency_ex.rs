// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency for TBOR (security-domain) partitions.
//!
//! A partition reset (live migration, NSSR) reverts a TBOR partition to
//! `Enabled`: the partition PSKs return to their defaults, the security
//! domain is torn down, and every open session is parked in a
//! *needs-renegotiation* state. [`HsmPartition::enable_resiliency_ex`]
//! arms the SDK to recover transparently:
//!
//! 1. Successful provisioning calls (`change_psk`, `part_init_ex`,
//!    `part_final_ex`, `sd_*_backup`) are captured — non-secret inputs and
//!    device-issued backup envelopes go to [`ResiliencyStorage`]; rotated
//!    PSKs stay in process memory only.
//! 2. When an in-session operation fails with a retryable error, the
//!    restore path replays the captured provisioning: rotate the PSKs,
//!    `PartInit`, `PartFinal` with the previous `local_mk` backup, and
//!    `SdRestoreLocalBackup`. The partition has a single CO session slot,
//!    which a reset keeps reserved for the stale CO session, so the
//!    provisioning runs on the caller's tracked CO session (reopened in
//!    place) when one is alive, else on a fresh CO session.
//! 3. Stale sessions are re-established with `SessionReopenInit` /
//!    `SessionReopenFinish`, which keeps session-scoped masked keys valid.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use parking_lot::Mutex;
use zerocopy::IntoBytes;
use zerocopy::TryFromBytes;
use zeroize::Zeroizing;

use super::*;

/// Storage key for the captured `part_init_ex` inputs.
pub(crate) const TSRA_STORAGE_EX_PART_INIT: &str = "tsra_ex_part_init";

/// Storage key for the captured PTA certificate chain (root → leaf).
pub(crate) const TSRA_STORAGE_EX_PTA_CHAIN: &str = "tsra_ex_pta_chain";

/// Storage key for the latest `local_mk` backup envelope.
pub(crate) const TSRA_STORAGE_EX_LOCAL_MK_BACKUP: &str = "tsra_ex_local_mk_backup";

/// Storage key for the latest partition-owner-key local backup.
pub(crate) const TSRA_STORAGE_EX_POK_LOCAL_BACKUP: &str = "tsra_ex_pok_local_backup";

/// Storage key for the latest security-domain masking-key backup.
pub(crate) const TSRA_STORAGE_EX_SD_MK_BACKUP: &str = "tsra_ex_sd_mk_backup";

/// Firmware partition state: enabled, not yet initialized (post reset).
const PART_STATE_ENABLED: u8 = 2;
/// Firmware partition state: `PartInit` done, `PartFinal` pending.
const PART_STATE_INITIALIZING: u8 = 4;
/// Firmware partition state: finalized.
const PART_STATE_INITIALIZED: u8 = 5;

/// Callback that endorses a freshly generated PTA key during restore.
///
/// Invoked when the restore path re-runs `PartInit` and needs a PTA
/// certificate chain for `PartFinal`. When no callback is configured the
/// chain captured from the original `part_final_ex` call is replayed —
/// valid because the PTA key is derived deterministically from the
/// device, machine seed and policy.
///
/// Invoked while internal partition locks are held: implementations must
/// not call back into the same [`HsmPartition`].
pub trait PtaEndorsementCallback: Send + Sync {
    /// Returns the PTA certificate chain (DER certificates, root first,
    /// PTA leaf last) for the given PKCS#10 CSR and COSE_Sign1 PTA report.
    fn endorse_pta(&self, pta_csr: &[u8], pta_report: &[u8]) -> HsmResult<Vec<Vec<u8>>>;
}

/// Configuration passed to [`HsmPartition::enable_resiliency_ex`].
pub struct HsmResiliencyExConfig {
    /// Persistent storage for captured provisioning state and the restore
    /// epoch.
    pub storage: Box<dyn ResiliencyStorage>,

    /// Cross-process/thread lock for restore coordination.
    pub lock: Arc<dyn ResiliencyLock>,

    /// Optional PTA endorsement callback; see [`PtaEndorsementCallback`].
    pub pta_callback: Option<Box<dyn PtaEndorsementCallback>>,
}

/// Rotated PSKs captured in process memory (never persisted).
#[derive(Default)]
struct CapturedPsks {
    co: Option<Zeroizing<[u8; PSK_LEN]>>,
    cu: Option<Zeroizing<[u8; PSK_LEN]>>,
}

/// Internal TBOR resiliency state, held in `HsmPartitionInner`.
pub(crate) struct ResiliencyExState {
    pub(crate) config: HsmResiliencyExConfig,
    psks: Mutex<CapturedPsks>,
    /// The most recently opened CO session-ex on the owning partition.
    co_session: Mutex<Option<WeakHsmSession>>,
    /// CU sessions-ex opened on the owning partition; a restore reopens
    /// one of them to rotate the CU PSK without needing a spare slot.
    cu_sessions: Mutex<Vec<WeakHsmSession>>,
    /// Set when a reset is observed and cleared once the CU PSK has been
    /// rotated back, so an interrupted restore still finishes it even
    /// though the partition no longer reports the reset.
    cu_rotation_pending: AtomicBool,
    /// Sessions reopened by a restore whose epoch is not yet published;
    /// `Some` while publication is outstanding.
    unpublished: Mutex<Option<Vec<WeakHsmSession>>>,
    restore_epoch: AtomicU64,
}

impl std::fmt::Debug for ResiliencyExState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResiliencyExState")
            .field("has_pta_callback", &self.config.pta_callback.is_some())
            .field("restore_epoch", &self.restore_epoch())
            .finish_non_exhaustive()
    }
}

/// Captured `part_init_ex` inputs.
pub(crate) struct PartInitParams {
    pub(crate) policy: PartPolicy,
    pub(crate) mach_seed: Zeroizing<Vec<u8>>,
    pub(crate) pota_thumbprint: Vec<u8>,
    pub(crate) sata_thumbprint: Vec<u8>,
    pub(crate) sapota_thumbprint: Option<Vec<u8>>,
}

impl ResiliencyExState {
    /// Creates the state, seeding the restore epoch from storage.
    pub(crate) fn new(config: HsmResiliencyExConfig) -> HsmResult<Self> {
        let restore_epoch = ResiliencyState::read_epoch(&*config.storage)?.unwrap_or(0);
        Ok(Self {
            config,
            psks: Mutex::new(CapturedPsks::default()),
            co_session: Mutex::new(None),
            cu_sessions: Mutex::new(Vec::new()),
            cu_rotation_pending: AtomicBool::new(false),
            unpublished: Mutex::new(None),
            restore_epoch: AtomicU64::new(restore_epoch),
        })
    }

    /// Returns the current restore epoch.
    pub(crate) fn restore_epoch(&self) -> u64 {
        self.restore_epoch.load(Ordering::Acquire)
    }

    /// Tracks `session` so a restore can reuse its (reset-reserved) slot:
    /// the latest CO session, or any live CU session.
    pub(crate) fn track_session(&self, psk_id: HsmPskId, session: &HsmSession) {
        match psk_id {
            HsmPskId::CO => *self.co_session.lock() = Some(session.downgrade()),
            HsmPskId::CU => {
                let mut sessions = self.cu_sessions.lock();
                sessions.retain(|s| s.upgrade().is_some());
                sessions.push(session.downgrade());
            }
        }
    }

    /// Returns the live tracked CU sessions.
    fn cu_sessions(&self) -> Vec<HsmSession> {
        self.cu_sessions
            .lock()
            .iter()
            .filter_map(WeakHsmSession::upgrade)
            .collect()
    }

    /// Whether a completed restore still has to publish its epoch.
    pub(crate) fn publish_pending(&self) -> bool {
        self.unpublished.lock().is_some()
    }

    /// Advances the restore epoch after a restore and marks the sessions
    /// it reopened as current. If persisting the epoch fails, the
    /// publication stays pending and is retried by the next restore.
    pub(crate) fn publish_restore(&self, reopened: &[HsmSession]) -> HsmResult<()> {
        let mut unpublished = self.unpublished.lock();
        unpublished
            .get_or_insert_with(Vec::new)
            .extend(reopened.iter().map(HsmSession::downgrade));
        let epoch = self.bump_epoch()?;
        for session in unpublished.take().into_iter().flatten() {
            if let Some(session) = session.upgrade() {
                session.mark_restored(epoch);
            }
        }
        Ok(())
    }

    /// Returns the tracked CO session, if it is still alive.
    fn co_session(&self) -> Option<HsmSession> {
        self.co_session
            .lock()
            .as_ref()
            .and_then(WeakHsmSession::upgrade)
    }

    /// Records the PSK currently bound to role `psk_id`.
    pub(crate) fn capture_psk(&self, psk_id: u8, psk: &[u8; PSK_LEN]) {
        let mut psks = self.psks.lock();
        let slot = if psk_id == HsmPskId::CO as u8 {
            &mut psks.co
        } else {
            &mut psks.cu
        };
        *slot = Some(Zeroizing::new(*psk));
    }

    /// Returns the captured PSK for role `psk_id`, if any.
    pub(crate) fn psk(&self, psk_id: u8) -> Option<Zeroizing<[u8; PSK_LEN]>> {
        let psks = self.psks.lock();
        if psk_id == HsmPskId::CO as u8 {
            psks.co.clone()
        } else {
            psks.cu.clone()
        }
    }

    /// Persists the `part_init_ex` inputs.
    pub(crate) fn capture_part_init(
        &self,
        policy: &PartPolicy,
        mach_seed: &[u8],
        pota_thumbprint: &[u8],
        sata_thumbprint: &[u8],
        sapota_thumbprint: Option<&[u8]>,
    ) -> HsmResult<()> {
        let has_sapota = [u8::from(sapota_thumbprint.is_some())];
        let blob = Zeroizing::new(encode_fields(&[
            policy.as_bytes(),
            mach_seed,
            pota_thumbprint,
            sata_thumbprint,
            &has_sapota,
            sapota_thumbprint.unwrap_or_default(),
        ])?);
        self.write(TSRA_STORAGE_EX_PART_INIT, &blob)
    }

    /// Loads the captured `part_init_ex` inputs.
    pub(crate) fn part_init_params(&self) -> HsmResult<Option<PartInitParams>> {
        let Some(blob) = self.read(TSRA_STORAGE_EX_PART_INIT)? else {
            return Ok(None);
        };
        let blob = Zeroizing::new(blob);
        let fields = decode_fields(&blob)?;
        let [policy, mach_seed, pota, sata, has_sapota, sapota] = fields.as_slice() else {
            return Err(HsmError::InternalError);
        };
        let policy =
            PartPolicy::try_read_from_bytes(policy).map_err(|_| HsmError::InternalError)?;
        let sapota_thumbprint = match has_sapota {
            [0] => None,
            [1] => Some(sapota.to_vec()),
            _ => return Err(HsmError::InternalError),
        };
        Ok(Some(PartInitParams {
            policy,
            mach_seed: Zeroizing::new(mach_seed.to_vec()),
            pota_thumbprint: pota.to_vec(),
            sata_thumbprint: sata.to_vec(),
            sapota_thumbprint,
        }))
    }

    /// Persists the PTA chain and resulting `local_mk` backup of a
    /// successful `part_final_ex`.
    pub(crate) fn capture_part_final(
        &self,
        pta_cert_chain: &[HsmCert<'_>],
        local_mk_backup: &[u8],
    ) -> HsmResult<()> {
        let certs: Vec<&[u8]> = pta_cert_chain.iter().map(|c| c.cert).collect();
        self.write(TSRA_STORAGE_EX_PTA_CHAIN, &encode_fields(&certs)?)?;
        self.write(TSRA_STORAGE_EX_LOCAL_MK_BACKUP, local_mk_backup)
    }

    /// Persists the device-local security-domain backups.
    pub(crate) fn capture_sd_backups(
        &self,
        pok_local_backup: &[u8],
        sd_mk_backup: &[u8],
    ) -> HsmResult<()> {
        self.write(TSRA_STORAGE_EX_POK_LOCAL_BACKUP, pok_local_backup)?;
        self.write(TSRA_STORAGE_EX_SD_MK_BACKUP, sd_mk_backup)
    }

    fn write(&self, key: &str, data: &[u8]) -> HsmResult<()> {
        self.config.storage.write(key, data)
    }

    fn read(&self, key: &str) -> HsmResult<Option<Vec<u8>>> {
        match self.config.storage.read(key) {
            Ok(v) => Ok(Some(v)),
            Err(HsmError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Adopts a newer epoch persisted by another process.
    /// Caller must hold the cross-process resiliency lock.
    pub(crate) fn sync_epoch_from_storage(&self) -> HsmResult<()> {
        let current = self.restore_epoch();
        match ResiliencyState::read_epoch(&*self.config.storage)? {
            Some(stored) if stored > current => self.restore_epoch.store(stored, Ordering::Release),
            Some(stored) if stored < current => return Err(HsmError::InternalError),
            _ => {}
        }
        Ok(())
    }

    /// Increments the epoch from the stored value and persists it.
    /// Caller must hold the cross-process resiliency lock.
    pub(crate) fn bump_epoch(&self) -> HsmResult<u64> {
        let stored = ResiliencyState::read_epoch(&*self.config.storage)?.unwrap_or(0);
        let new_epoch = stored.saturating_add(1);
        ResiliencyState::write_epoch(&*self.config.storage, new_epoch)?;
        self.restore_epoch.store(new_epoch, Ordering::Release);
        Ok(new_epoch)
    }

    /// Replays captured provisioning against a reset partition.
    ///
    /// Probes the partition on a private handle. When it was reset, or a
    /// previous restore stopped part-way, the provisioning is replayed on
    /// the tracked CO session (reopened in place) or, when none is alive,
    /// a fresh CO session on a private handle. The captured CU PSK is then
    /// restored through a tracked CU session (or a fresh one), retried
    /// until it completes even if the partition no longer reports a reset.
    ///
    /// Returns whether any device state was restored, and the tracked
    /// sessions it reopened (so the caller can mark them current).
    pub(crate) fn restore_device(
        &self,
        path: &str,
        rev: HsmApiRev,
    ) -> HsmResult<(bool, Vec<HsmSession>)> {
        // `PartInfo` is out-of-session, so probe the lifecycle state first.
        // An `Enabled` partition was reset: its PSKs are back to defaults.
        let probe = HsmPartitionManager::open_partition(path, rev)?;
        let state = ddi::part_state(&probe)?;
        let was_reset = state == PART_STATE_ENABLED;
        if was_reset {
            self.cu_rotation_pending.store(true, Ordering::Release);
        }
        let rotate_cu = self.cu_rotation_pending.load(Ordering::Acquire);
        let needs_sd = state == PART_STATE_INITIALIZED
            && !probe.sd_initialized()?
            && self.read(TSRA_STORAGE_EX_POK_LOCAL_BACKUP)?.is_some();
        if !was_reset && state != PART_STATE_INITIALIZING && !needs_sd && !rotate_cu {
            return Ok((false, Vec::new()));
        }
        // A reset parks every session in renegotiation, so the epoch must
        // advance even when there is no captured provisioning to replay.
        let mut restored = was_reset;

        let mut reopened = Vec::new();
        if was_reset || state == PART_STATE_INITIALIZING || needs_sd {
            let co_psk = self.psk(HsmPskId::CO as u8);
            let tracked = self.co_session();
            let (co, rotated) = match &tracked {
                Some(session) => {
                    drop(probe);
                    let rotated = reopen_restore_session(session, co_psk.as_deref(), was_reset)?;
                    (session.clone(), rotated)
                }
                None => {
                    open_restore_session(probe, rev, HsmPskId::CO, co_psk.as_deref(), was_reset)?
                }
            };
            restored |= rotated;

            match state {
                PART_STATE_ENABLED => {
                    if let Some(params) = self.part_init_params()? {
                        let init = co.part_init_ex(
                            &params.policy,
                            &params.mach_seed,
                            &params.pota_thumbprint,
                            &params.sata_thumbprint,
                            params.sapota_thumbprint.as_deref(),
                        )?;
                        restored = true;
                        self.finalize(&co, &params.policy, Some(&init))?;
                        self.restore_sd(&co)?;
                    }
                }
                PART_STATE_INITIALIZING => {
                    // A previous restore attempt stopped after `PartInit`.
                    if let Some(params) = self.part_init_params()? {
                        restored = true;
                        self.finalize(&co, &params.policy, None)?;
                        self.restore_sd(&co)?;
                    }
                }
                _ if needs_sd => restored |= self.restore_sd(&co)?,
                _ => {}
            }
            drop(co);
            reopened.extend(tracked);
        } else {
            drop(probe);
        }

        if rotate_cu {
            if let Some(cu_psk) = self.psk(HsmPskId::CU as u8) {
                // Rotate through an existing CU slot: after a reset every
                // pre-reset CU slot stays reserved, so a fresh open may
                // find no free slot.
                let mut rotated = None;
                for cu in self.cu_sessions() {
                    if let Ok(r) = reopen_restore_session(&cu, Some(&cu_psk), true) {
                        rotated = Some(r);
                        reopened.push(cu);
                        break;
                    }
                }
                let rotated = match rotated {
                    Some(rotated) => rotated,
                    None => {
                        let part = HsmPartitionManager::open_partition(path, rev)?;
                        open_restore_session(part, rev, HsmPskId::CU, Some(&cu_psk), true)?.1
                    }
                };
                restored |= rotated;
            }
            self.cu_rotation_pending.store(false, Ordering::Release);
        }

        Ok((restored, reopened))
    }

    /// Runs `PartFinal` with the captured (or re-endorsed) PTA chain and
    /// the previous `local_mk` backup, persisting the new backup.
    fn finalize(
        &self,
        co: &HsmSession,
        policy: &PartPolicy,
        init: Option<&HsmPartInitExResult>,
    ) -> HsmResult<()> {
        let chain = match (&self.config.pta_callback, init) {
            (Some(cb), Some(init)) => cb.endorse_pta(&init.pta_csr, &init.pta_report)?,
            _ => {
                let blob = self
                    .read(TSRA_STORAGE_EX_PTA_CHAIN)?
                    .ok_or(HsmError::InternalError)?;
                decode_fields(&blob)?
                    .into_iter()
                    .map(<[u8]>::to_vec)
                    .collect()
            }
        };
        let certs: Vec<HsmCert<'_>> = chain.iter().map(|c| HsmCert { cert: c }).collect();
        let prev = self.read(TSRA_STORAGE_EX_LOCAL_MK_BACKUP)?;
        let result = co.part_final_ex(policy, &certs, prev.as_deref())?;
        self.capture_part_final(&certs, &result.local_mk_backup)
    }

    /// Restores the security domain from the captured local backups.
    /// Returns `false` when no backups were captured.
    fn restore_sd(&self, co: &HsmSession) -> HsmResult<bool> {
        let (Some(pok), Some(sd_mk)) = (
            self.read(TSRA_STORAGE_EX_POK_LOCAL_BACKUP)?,
            self.read(TSRA_STORAGE_EX_SD_MK_BACKUP)?,
        ) else {
            return Ok(false);
        };
        let result = co.sd_restore_local_backup(&pok, &sd_mk)?;
        self.capture_sd_backups(&result.pok_local_backup, &result.sd_mk_backup)?;
        Ok(true)
    }
}

/// Session type for a role: CO sessions are authenticated, CU sessions
/// plaintext.
fn session_type_for(psk_id: HsmPskId) -> HsmSessionExType {
    match psk_id {
        HsmPskId::CO => HsmSessionExType::Authenticated,
        HsmPskId::CU => HsmSessionExType::PlainText,
    }
}

/// Opens a restore session for `psk_id` on the private handle `part`.
///
/// With a captured `psk`, the PSK most likely in effect is tried first
/// (the default after a reset, else `psk`); on failure the other is tried
/// on a fresh handle (a failed handshake may leave a pending slot on the
/// first). A session opened under the default PSK is rotated to `psk`.
///
/// Returns the session and whether a rotation was performed.
fn open_restore_session(
    part: HsmPartition,
    rev: HsmApiRev,
    psk_id: HsmPskId,
    psk: Option<&[u8; PSK_LEN]>,
    prefer_default: bool,
) -> HsmResult<(HsmSession, bool)> {
    let session_type = session_type_for(psk_id);
    let open = |part: &HsmPartition, psk: Option<&[u8; PSK_LEN]>| {
        part.open_session_ex(rev, HsmSessionPsk { psk_id, psk }, session_type)
    };
    let Some(psk) = psk else {
        return Ok((open(&part, None)?, false));
    };
    let path = part.path();
    let first = if prefer_default { None } else { Some(psk) };
    let (session, used_default) = match open(&part, first) {
        Ok(session) => (session, first.is_none()),
        Err(_) => {
            drop(part);
            let retry = HsmPartitionManager::open_partition(&path, rev)?;
            let second = if prefer_default { Some(psk) } else { None };
            (open(&retry, second)?, second.is_none())
        }
    };
    if used_default {
        session.change_psk(psk)?;
    }
    Ok((session, used_default))
}

/// Reopens the stale CO `session` in place for a restore.
///
/// Mirrors [`open_restore_session`]: the PSK most likely bound to the
/// role is tried first, then the other (a failed reopen handshake leaves
/// the slot reopenable). A session reopened under the default PSK rotates
/// it to `psk`. A session whose slot is already active (an earlier restore
/// attempt reopened it) is used as is.
///
/// Returns whether a rotation was performed.
fn reopen_restore_session(
    session: &HsmSession,
    psk: Option<&[u8; PSK_LEN]>,
    prefer_default: bool,
) -> HsmResult<bool> {
    let Some(psk) = psk else {
        return match session.force_reopen_ex(None) {
            Ok(()) | Err(HsmError::InvalidArgument) => Ok(false),
            Err(e) => Err(e),
        };
    };
    let first = if prefer_default { None } else { Some(psk) };
    let used_default = match session.force_reopen_ex(first) {
        Ok(()) => first.is_none(),
        Err(HsmError::InvalidArgument) => return Ok(false),
        Err(_) => {
            let second = if prefer_default { Some(psk) } else { None };
            session.force_reopen_ex(second)?;
            second.is_none()
        }
    };
    if used_default {
        session.change_psk(psk)?;
    }
    Ok(used_default)
}

/// Encodes byte fields as `u32 LE length ‖ bytes` records.
fn encode_fields(fields: &[&[u8]]) -> HsmResult<Vec<u8>> {
    let mut out = Vec::with_capacity(fields.iter().map(|f| f.len() + 4).sum());
    for field in fields {
        let len = u32::try_from(field.len()).map_err(|_| HsmError::InvalidArgument)?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(field);
    }
    Ok(out)
}

/// Decodes records written by [`encode_fields`].
fn decode_fields(mut data: &[u8]) -> HsmResult<Vec<&[u8]>> {
    let mut fields = Vec::new();
    while !data.is_empty() {
        let (len, rest) = data
            .split_first_chunk::<4>()
            .ok_or(HsmError::InternalError)?;
        let len = u32::from_le_bytes(*len) as usize;
        if rest.len() < len {
            return Err(HsmError::InternalError);
        }
        let (field, rest) = rest.split_at(len);
        fields.push(field);
        data = rest;
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_round_trip() {
        let encoded = encode_fields(&[b"abc", b"", b"\x01"]).expect("encode");
        let decoded = decode_fields(&encoded).expect("decode");
        assert_eq!(decoded, vec![&b"abc"[..], &b""[..], &b"\x01"[..]]);
    }

    #[test]
    fn decode_rejects_truncated_record() {
        let mut encoded = encode_fields(&[b"abcd"]).expect("encode");
        encoded.pop();
        assert_eq!(decode_fields(&encoded), Err(HsmError::InternalError));
        assert_eq!(decode_fields(&[1, 0]), Err(HsmError::InternalError));
    }
}
