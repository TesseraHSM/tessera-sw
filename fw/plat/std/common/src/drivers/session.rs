// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-partition session table with logical → physical ID remapping.
//!
//! This module implements the session slot allocator for the standard
//! PAL, mirroring the hardware session table layout.
//! reference firmware.  Each partition has its own independent
//! [`SessionTable`] with up to [`MAX_SESSIONS`] (8) concurrent sessions.
//!
//! ## Logical vs physical session IDs
//!
//! - **Logical ID** ([`HsmSessId`], 0–7): slot index returned to callers.
//! - **Physical ID** ([`HsmKeyId`]): vault key ID where the session blob
//!   (8-byte API revision + 80-byte masking key) is stored.
//!
//! The `phys_ids` array maps each logical slot to its physical vault
//! key ID.  Session-scoped vault keys reference the **physical** ID so
//! that `delete_by_session_key` can match without knowing the logical
//! slot.
//!
//! ## Allocation strategy
//!
//! Sessions are tracked with three `u8` bitmasks plus the mapping
//! array and per-slot Pending state:
//!
//! - **`alloc_mask`** — bit *N* is set when slot *N* is in use
//!   (Pending, Active, or NeedsRenegotiation).
//! - **`renego_mask`** — bit *N* is set when slot *N* requires
//!   renegotiation (e.g., after a VM live-migration event).
//! - **`pending_mask`** — bit *N* is set when slot *N* is in the
//!   Pending state (in-flight session-establishment handshake).
//! - **`phys_ids`** — `phys_ids[N]` holds the vault key ID for slot *N*
//!   once promoted to Active.  Valid iff `alloc_mask` is set AND
//!   `pending_mask` is clear.
//! - **`pending_blobs`** — opaque handshake state for Pending slots.
//!   Valid iff `pending_mask` is set.
//! - **`pending_seqs`** — monotonic counter values stamped at
//!   `create_pending` time; used as the eviction ordering key when no
//!   `Empty` slot is available in the eligible role range.
//!
//! A new Active session is allocated by finding the lowest zero bit in
//! `alloc_mask` via [`u8::trailing_ones`].  A new Pending session
//! scans only the slots in the role's eligible range (CO: slot 0; CU:
//! slots 1..=7) and prefers `Empty` slots, falling back to evicting
//! the oldest Pending in the range.
//!
//! ## Session states
//!
//! | `alloc_mask[N]` | `pending_mask[N]` | `renego_mask[N]` | State |
//! |:---:|:---:|:---:|:---|
//! | 0 | — | — | [`Invalid`](HsmSessionState::Invalid) — slot is free |
//! | 1 | 1 | — | [`Pending`](HsmSessionState::Pending) — handshake in flight |
//! | 1 | 0 | 0 | [`Active`](HsmSessionState::Active) — session is usable |
//! | 1 | 0 | 1 | [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation) |

use tsra_fw_hsm_pal_traits::*;

/// Maximum number of concurrent sessions per partition.
const MAX_SESSIONS: usize = 8;

/// Per-partition session table with logical → physical ID remapping.
///
/// Each logical session slot (0–7) maps to a physical vault key ID
/// ([`HsmKeyId`]) where the session blob is stored.
pub struct SessionTable {
    /// Allocation bitmask — bit N is set when session slot N is in
    /// use (any state).
    alloc_mask: u8,
    /// Renegotiation bitmask — bit N is set when session N needs renegotiation.
    renego_mask: u8,
    /// Pending bitmask — bit N is set when slot N is in the Pending
    /// state (in-flight session-establishment handshake; no vault
    /// entry yet).
    pending_mask: u8,
    /// Logical → physical mapping: `phys_ids[slot]` is the vault key ID
    /// for session slot `slot` once Active.  Only valid when
    /// `alloc_mask` is set AND `pending_mask` is clear.
    phys_ids: [u16; MAX_SESSIONS],
    /// Per-slot opaque handshake state for Pending sessions.  Only
    /// valid when `pending_mask` bit is set.
    pending_blobs: [PendingBlob; MAX_SESSIONS],
    /// Per-slot init-sequence stamp at Pending allocation time.  Used
    /// to choose the oldest Pending for eviction.
    pending_seqs: [u64; MAX_SESSIONS],
    /// Monotonic counter incremented for every Pending allocation;
    /// stamped into `pending_seqs` to order evictions.
    next_init_seq: u64,
    /// Per-slot next HSM→VM transport sequence number.  Restarts when a
    /// Pending slot installs fresh transport keys; carries over on
    /// promote, which keeps them.
    m2h_seqs: [u64; MAX_SESSIONS],
    recovery_bindings: [[u8; 16]; MAX_SESSIONS],
    psk_changed: u8,
}

/// Opaque per-slot handshake state for Pending sessions.
#[derive(Clone)]
struct PendingBlob {
    data: [u8; SESSION_PENDING_BLOB_MAX],
    len: usize,
}

impl Default for PendingBlob {
    fn default() -> Self {
        Self {
            data: [0u8; SESSION_PENDING_BLOB_MAX],
            len: 0,
        }
    }
}

impl PendingBlob {
    fn clear(&mut self) {
        self.data.fill(0);
        self.len = 0;
    }

    fn store(&mut self, src: &[u8]) -> HsmResult<()> {
        if src.len() > SESSION_PENDING_BLOB_MAX {
            return Err(HsmError::InvalidArg);
        }
        self.data[..src.len()].copy_from_slice(src);
        self.data[src.len()..].fill(0);
        self.len = src.len();
        Ok(())
    }

    fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionTable {
    /// Create an empty session table with no allocated sessions.
    pub fn new() -> Self {
        Self {
            alloc_mask: 0,
            renego_mask: 0,
            pending_mask: 0,
            phys_ids: [0; MAX_SESSIONS],
            pending_blobs: core::array::from_fn(|_| PendingBlob::default()),
            pending_seqs: [0u64; MAX_SESSIONS],
            next_init_seq: 0,
            m2h_seqs: [0u64; MAX_SESSIONS],
            recovery_bindings: [[0; 16]; MAX_SESSIONS],
            psk_changed: 0,
        }
    }

    /// Snapshot the set of Active session slots for a live-migration
    /// disable.
    ///
    /// Returns a bitmask of the currently-Active slots so it can be
    /// handed to [`restore`](Self::restore) after the partition's crypto
    /// state has been cleared.  In-flight Pending handshakes are excluded
    /// because they carry no reopenable credential state.  Mirrors the
    /// reference firmware's `backup`/`restore` pair.
    pub fn backup(&self) -> u8 {
        self.alloc_mask & (!self.pending_mask | self.renego_mask)
    }

    /// Re-establish session slots preserved across a partition disable,
    /// marking every survivor as [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation).
    ///
    /// `mask` is a snapshot taken by [`backup`](Self::backup) *before*
    /// the partition's vault and keys were cleared.  Every bit set in
    /// `mask` becomes an allocated slot needing renegotiation: its
    /// physical vault mapping is dropped (the key material did not
    /// survive the disable) and a subsequent `ReopenSession` re-keys it
    /// via [`recreate`](Self::recreate).  Any leftover Pending state is
    /// discarded.  Mirrors the reference firmware's `restore`.
    pub fn restore(&mut self, mask: u8) {
        self.alloc_mask = mask;
        self.renego_mask = mask;
        self.pending_mask = 0;
        self.phys_ids = [0; MAX_SESSIONS];
        for blob in &mut self.pending_blobs {
            blob.clear();
        }
        self.pending_seqs = [0u64; MAX_SESSIONS];
        self.next_init_seq = 0;
        self.m2h_seqs = [0u64; MAX_SESSIONS];
        // Each caller (disable, NSSR) also resets the PSKs, so no survivor
        // has used its change of the PSK it reauthenticates with.
        self.psk_changed = 0;
        for (slot, binding) in self.recovery_bindings.iter_mut().enumerate() {
            if mask & (1 << slot) == 0 {
                binding.fill(0);
            }
        }
    }

    /// Validate that a logical session ID refers to an allocated slot.
    /// Returns the slot index on success.
    fn active_slot(&self, id: HsmSessId) -> HsmResult<usize> {
        let slot = u16::from(id) as usize;
        if slot >= MAX_SESSIONS || (self.alloc_mask & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotFound);
        }
        Ok(slot)
    }

    /// Allocate a new session in the first available slot.
    ///
    /// Finds the lowest-numbered free slot via [`u8::trailing_ones`] on
    /// the allocation mask and stores the logical → physical mapping.
    ///
    /// # Parameters
    ///
    /// - `physical_id` — vault key ID where the session blob is stored.
    ///
    /// # Returns
    ///
    /// The logical [`HsmSessId`] (slot index 0–7).
    pub fn create(&mut self, physical_id: HsmKeyId) -> HsmResult<HsmSessId> {
        let slot = self.alloc_mask.trailing_ones() as usize;
        if slot >= MAX_SESSIONS {
            return Err(HsmError::VaultSessionLimitReached);
        }
        self.alloc_mask |= 1 << slot;
        self.phys_ids[slot] = u16::from(physical_id);
        Ok(HsmSessId::from(slot as u16))
    }

    /// Delete (close) an existing session, freeing its slot.
    ///
    /// Clears the allocation, renegotiation, and pending bits and
    /// zeroizes the Pending blob.  Returns the physical vault key ID
    /// for Active/NeedsRenegotiation slots so the caller can clean up
    /// the vault; for Pending slots there is no associated vault entry
    /// and the returned ID is `HsmKeyId::from(0)`.
    pub fn delete(&mut self, id: HsmSessId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        let mask = !(1u8 << slot);
        let was_pending = (self.pending_mask & (1 << slot)) != 0;
        let phys = if was_pending {
            HsmKeyId::from(0)
        } else {
            HsmKeyId::from(self.phys_ids[slot])
        };
        self.alloc_mask &= mask;
        self.renego_mask &= mask;
        self.pending_mask &= mask;
        self.phys_ids[slot] = 0;
        self.pending_blobs[slot].clear();
        self.pending_seqs[slot] = 0;
        self.m2h_seqs[slot] = 0;
        self.recovery_bindings[slot].fill(0);
        self.psk_changed &= mask;
        Ok(phys)
    }

    /// Look up the physical vault key ID for a logical session.
    ///
    /// Returns [`HsmError::SessionNotFound`] for slots that are free
    /// and [`HsmError::SessionNotPending`]-style not-applicable for
    /// Pending slots; callers should check
    /// [`state`](Self::state) first.
    pub fn physical_id(&self, id: HsmSessId) -> HsmResult<HsmKeyId> {
        let slot = self.active_slot(id)?;
        if (self.pending_mask & (1 << slot)) != 0 {
            return Err(HsmError::SessionNotFound);
        }
        Ok(HsmKeyId::from(self.phys_ids[slot]))
    }

    /// Validate recreation before allocating a replacement vault key.
    ///
    /// Matches the reference firmware's `recreate_session` errors without
    /// changing the slot or its key mapping.
    pub fn validate_recreation(&self, id: HsmSessId) -> HsmResult<()> {
        if u16::from(id) as usize >= MAX_SESSIONS {
            return Err(HsmError::VaultSessionLimitReached);
        }
        match self.state(id) {
            HsmSessionState::NeedsRenegotiation => Ok(()),
            HsmSessionState::Invalid => Err(HsmError::SessionNotFound),
            _ => Err(HsmError::ProcessedIoEventInInvalidState),
        }
    }

    /// Re-key an existing session with a new physical vault key ID.
    ///
    /// The session must be in [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation)
    /// state.  On success, clears the renegotiation bit and updates the
    /// physical mapping.
    pub fn recreate(&mut self, id: HsmSessId, new_physical: HsmKeyId) -> HsmResult<HsmSessId> {
        self.validate_recreation(id)?;
        let slot = u16::from(id) as usize;
        self.renego_mask &= !(1u8 << slot);
        self.phys_ids[slot] = u16::from(new_physical);
        Ok(id)
    }

    /// Roll back a [`recreate`](Self::recreate): restore the
    /// renegotiation bit and clear the physical mapping.
    ///
    /// The caller is responsible for deleting the orphaned vault entry
    /// (via [`physical_id`](Self::physical_id)) before invoking this, so
    /// the physical mapping is read while still intact.
    ///
    /// Leaves the slot as a freshly-migrated
    /// [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation) slot
    /// so the host can retry a failed `ReopenSession` (mirrors the
    /// reference firmware's `session_table().rollback_recreation(id)`).
    pub fn rollback_recreation(&mut self, id: HsmSessId) -> HsmResult<()> {
        let slot = self.active_slot(id)?;
        self.renego_mask |= 1 << slot;
        self.phys_ids[slot] = 0;
        self.pending_mask &= !(1 << slot);
        self.pending_blobs[slot].clear();
        Ok(())
    }

    /// Reserve an existing migrated slot without resetting its recovery identity.
    pub fn reopen_pending(&mut self, id: HsmSessId, blob: &[u8]) -> HsmResult<()> {
        let slot = self.active_slot(id)?;
        if self.renego_mask & (1 << slot) == 0 {
            return Err(HsmError::ProcessedIoEventInInvalidState);
        }
        self.install_pending(u16::from(id) as usize, blob)
    }

    /// Read the original masking-key fingerprint retained across migration.
    pub fn recovery_binding(&self, id: HsmSessId) -> HsmResult<&[u8]> {
        Ok(&self.recovery_bindings[self.active_slot(id)?])
    }

    /// Install a fresh session's recovery fingerprint.
    pub fn set_recovery_binding(&mut self, id: HsmSessId, binding: &[u8]) -> HsmResult<()> {
        let slot = self.active_slot(id)?;
        if binding.len() != 16 {
            return Err(HsmError::InvalidArg);
        }
        self.recovery_bindings[slot].copy_from_slice(binding);
        Ok(())
    }

    /// Read the one-successful-rotation flag.
    pub fn psk_changed(&self, id: HsmSessId) -> HsmResult<bool> {
        Ok(self.psk_changed & (1 << self.active_slot(id)?) != 0)
    }

    /// Update the one-successful-rotation flag.
    pub fn set_psk_changed(&mut self, id: HsmSessId, changed: bool) -> HsmResult<()> {
        let bit = 1 << self.active_slot(id)?;
        if changed {
            self.psk_changed |= bit;
        } else {
            self.psk_changed &= !bit;
        }
        Ok(())
    }

    /// Query the current state of a session slot.
    pub fn state(&self, id: HsmSessId) -> HsmSessionState {
        let Ok(slot) = self.active_slot(id) else {
            return HsmSessionState::Invalid;
        };
        if (self.pending_mask & (1 << slot)) != 0 {
            return HsmSessionState::Pending;
        }
        if (self.renego_mask & (1 << slot)) != 0 {
            return HsmSessionState::NeedsRenegotiation;
        }
        HsmSessionState::Active
    }

    /// Check whether all session slots are occupied.
    pub fn limit_reached(&self) -> bool {
        self.alloc_mask.count_ones() >= MAX_SESSIONS as u32
    }

    /// Set the renegotiation bit for a session (test helper).
    #[cfg(test)]
    pub fn set_needs_renego(&mut self, id: HsmSessId) {
        let slot = u16::from(id) as usize;
        if slot < MAX_SESSIONS && (self.alloc_mask & (1 << slot)) != 0 {
            self.renego_mask |= 1 << slot;
        }
    }

    /// Reserve a Pending slot for an in-flight handshake.
    ///
    /// Implements the §6 eviction algorithm: in the role's eligible
    /// slot range, prefer an `Empty` slot, else evict the oldest
    /// `Pending` slot, else return `VaultSessionLimitReached`.
    ///
    /// On eviction the caller is informed via the returned tuple's
    /// second element so it can release any associated vault state
    /// (there should be none for Pending, but the contract is
    /// uniform with the Active deletion path).
    pub fn create_pending(
        &mut self,
        role: HsmSessionRole,
        handshake_state: &[u8],
    ) -> HsmResult<HsmSessId> {
        if handshake_state.len() > SESSION_PENDING_BLOB_MAX {
            return Err(HsmError::InvalidArg);
        }
        let (range_start, range_end) = role_slot_range(role);

        // 1. Find an Empty slot in range.
        for slot in range_start..=range_end {
            if (self.alloc_mask & (1 << slot)) == 0 {
                self.install_pending(slot, handshake_state)?;
                return Ok(HsmSessId::from(slot as u16));
            }
        }

        // 2. Evict the oldest Pending slot in range.
        let mut victim: Option<usize> = None;
        let mut victim_seq = u64::MAX;
        for slot in range_start..=range_end {
            if (self.pending_mask & !self.renego_mask & (1 << slot)) != 0
                && self.pending_seqs[slot] < victim_seq
            {
                victim_seq = self.pending_seqs[slot];
                victim = Some(slot);
            }
        }
        if let Some(slot) = victim {
            // Cascade cleanup of the Pending slot (no vault entry to
            // remove, but it could acquire one in a future revision —
            // route through `delete` for uniformity).
            let _ = self.delete(HsmSessId::from(slot as u16))?;
            self.install_pending(slot, handshake_state)?;
            return Ok(HsmSessId::from(slot as u16));
        }

        // 3. All slots in range are Active or NeedsRenegotiation.  A
        //    NeedsRenegotiation slot is reserved for its own
        //    `ReopenSession`; it is never reclaimed by a fresh handshake.
        Err(HsmError::VaultSessionLimitReached)
    }

    fn install_pending(&mut self, slot: usize, handshake_state: &[u8]) -> HsmResult<()> {
        self.pending_blobs[slot].store(handshake_state)?;
        self.alloc_mask |= 1 << slot;
        self.pending_mask |= 1 << slot;
        self.next_init_seq = self.next_init_seq.wrapping_add(1);
        self.pending_seqs[slot] = self.next_init_seq;
        self.phys_ids[slot] = 0;
        self.m2h_seqs[slot] = 0;
        Ok(())
    }

    /// Reserves the next HSM→VM transport sequence number of a Pending or
    /// Active slot.
    ///
    /// # Errors
    ///
    /// - [`HsmError::SessionNotFound`] — the slot is free or awaiting
    ///   renegotiation.
    /// - [`HsmError::SessionTransportError`] — the counter is exhausted.
    pub fn next_m2h_seq(&mut self, id: HsmSessId) -> HsmResult<u64> {
        if !matches!(
            self.state(id),
            HsmSessionState::Pending | HsmSessionState::Active
        ) {
            return Err(HsmError::SessionNotFound);
        }
        let slot = u16::from(id) as usize;
        let seq = self.m2h_seqs[slot];
        self.m2h_seqs[slot] = seq.checked_add(1).ok_or(HsmError::SessionTransportError)?;
        Ok(seq)
    }

    /// Borrow the Pending blob for a slot.
    pub fn pending_state(&self, id: HsmSessId) -> HsmResult<&[u8]> {
        let slot = self.active_slot(id)?;
        if (self.pending_mask & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotPending);
        }
        Ok(self.pending_blobs[slot].as_slice())
    }

    /// Promote a Pending slot to Active and bind it to a vault key.
    ///
    /// The caller is responsible for having created the vault entry
    /// (typically holding `[api_rev ‖ session_enc_key ‖ optional
    /// masking_key]`) before invoking this method.
    pub fn promote(&mut self, id: HsmSessId, physical_id: HsmKeyId) -> HsmResult<()> {
        let slot = self.active_slot(id)?;
        if (self.pending_mask & (1 << slot)) == 0 {
            return Err(HsmError::SessionNotPending);
        }
        self.pending_mask &= !(1u8 << slot);
        self.renego_mask &= !(1u8 << slot);
        self.pending_blobs[slot].clear();
        self.pending_seqs[slot] = 0;
        self.phys_ids[slot] = u16::from(physical_id);
        Ok(())
    }
}

/// Returns the inclusive `(start, end)` slot range for a session role.
fn role_slot_range(role: HsmSessionRole) -> (usize, usize) {
    match role {
        HsmSessionRole::CryptoOfficer => (0, 0),
        HsmSessionRole::CryptoUser => (1, MAX_SESSIONS - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_identity_survives_retry_migration_and_eviction_pressure() {
        let mut table = SessionTable::new();
        let id = table
            .create_pending(HsmSessionRole::CryptoOfficer, b"fresh")
            .expect("pending");
        table.promote(id, HsmKeyId::from(1u16)).expect("promote");
        table
            .set_recovery_binding(id, &[0xA5; 16])
            .expect("fingerprint");
        table.set_psk_changed(id, true).expect("rotation");
        table.restore(table.backup());
        table.reopen_pending(id, b"recovery").expect("recovery");
        assert!(table
            .create_pending(HsmSessionRole::CryptoOfficer, b"fresh")
            .is_err());
        table.reopen_pending(id, b"replacement").expect("replace");
        table.restore(table.backup());
        assert!(matches!(
            table.state(id),
            HsmSessionState::NeedsRenegotiation
        ));
        assert_eq!(
            table.recovery_binding(id).expect("fingerprint"),
            &[0xA5; 16]
        );
        // The reset returned the PSKs to their defaults, so the change is
        // available again.
        assert!(!table.psk_changed(id).expect("allowance restored"));
        table.set_psk_changed(id, true).expect("rotation");
        table.reopen_pending(id, b"retry").expect("retry");
        table.rollback_recreation(id).expect("rollback");
        assert!(table.psk_changed(id).expect("rollback retained rotation"));
        table.delete(id).expect("close");
        let fresh = table
            .create_pending(HsmSessionRole::CryptoOfficer, b"fresh")
            .expect("fresh");
        assert!(!table.psk_changed(fresh).expect("new allowance"));
        assert_eq!(
            table.recovery_binding(fresh).expect("new fingerprint"),
            &[0; 16]
        );
    }

    #[test]
    fn create_session() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(0x0100)).unwrap();
        assert_eq!(u16::from(id), 0);
    }

    #[test]
    fn create_multiple_sessions() {
        let mut table = SessionTable::new();
        for expected in 0u16..8 {
            let phys = HsmKeyId::from(0x0100 + expected);
            let id = table.create(phys).unwrap();
            assert_eq!(u16::from(id), expected);
        }
    }

    #[test]
    fn create_beyond_limit() {
        let mut table = SessionTable::new();
        for i in 0..8u16 {
            table.create(HsmKeyId::from(i)).unwrap();
        }
        let err = table.create(HsmKeyId::from(99)).unwrap_err();
        assert_eq!(err, HsmError::VaultSessionLimitReached);
    }

    #[test]
    fn delete_and_reuse() {
        let mut table = SessionTable::new();
        let phys = HsmKeyId::from(42);
        let id = table.create(phys).unwrap();
        let returned_phys = table.delete(id).unwrap();
        assert_eq!(u16::from(returned_phys), 42);
        // Slot reused.
        let id2 = table.create(HsmKeyId::from(99)).unwrap();
        assert_eq!(u16::from(id2), 0);
    }

    #[test]
    fn session_state_active() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(0)).unwrap();
        assert!(matches!(table.state(id), HsmSessionState::Active));
    }

    #[test]
    fn session_state_invalid_never_created() {
        let table = SessionTable::new();
        let id = HsmSessId::from(0);
        assert!(matches!(table.state(id), HsmSessionState::Invalid));
    }

    #[test]
    fn session_state_invalid_after_delete() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(0)).unwrap();
        table.delete(id).unwrap();
        assert!(matches!(table.state(id), HsmSessionState::Invalid));
    }

    #[test]
    fn limit_reached_true() {
        let mut table = SessionTable::new();
        for i in 0..8u16 {
            table.create(HsmKeyId::from(i)).unwrap();
        }
        assert!(table.limit_reached());
    }

    #[test]
    fn limit_reached_false_after_delete() {
        let mut table = SessionTable::new();
        for i in 0..8u16 {
            table.create(HsmKeyId::from(i)).unwrap();
        }
        assert!(table.limit_reached());
        table.delete(HsmSessId::from(3)).unwrap();
        assert!(!table.limit_reached());
    }

    // --- New tests ---

    #[test]
    fn physical_id_lookup() {
        let mut table = SessionTable::new();
        let phys = HsmKeyId::from(0x0102);
        let id = table.create(phys).unwrap();
        assert_eq!(u16::from(table.physical_id(id).unwrap()), 0x0102);
    }

    #[test]
    fn physical_id_invalid() {
        let table = SessionTable::new();
        let err = table.physical_id(HsmSessId::from(0)).unwrap_err();
        assert_eq!(err, HsmError::SessionNotFound);
    }

    #[test]
    fn recreate_session() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(10)).unwrap();
        // Mark as needing renegotiation.
        table.set_needs_renego(id);
        assert!(matches!(
            table.state(id),
            HsmSessionState::NeedsRenegotiation
        ));
        // Recreate with new physical ID.
        let same_id = table.recreate(id, HsmKeyId::from(20)).unwrap();
        assert_eq!(u16::from(same_id), u16::from(id));
        assert!(matches!(table.state(id), HsmSessionState::Active));
        assert_eq!(u16::from(table.physical_id(id).unwrap()), 20);
    }

    #[test]
    fn recreate_not_renegotiating_fails() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(10)).unwrap();
        // Active, not NeedsRenegotiation — should fail.
        let err = table.recreate(id, HsmKeyId::from(20)).unwrap_err();
        assert_eq!(err, HsmError::ProcessedIoEventInInvalidState);
        assert!(matches!(table.state(id), HsmSessionState::Active));
        assert_eq!(u16::from(table.physical_id(id).unwrap()), 10);
    }

    #[test]
    fn recreate_rejects_missing_and_out_of_range_sessions() {
        let mut table = SessionTable::new();
        for (raw_id, expected) in [
            (0u16, HsmError::SessionNotFound),
            (7, HsmError::SessionNotFound),
            (8, HsmError::VaultSessionLimitReached),
            (9, HsmError::VaultSessionLimitReached),
            (u16::MAX, HsmError::VaultSessionLimitReached),
        ] {
            let id = HsmSessId::from(raw_id);
            assert_eq!(table.validate_recreation(id), Err(expected));
            assert_eq!(table.recreate(id, HsmKeyId::from(20)), Err(expected));
        }
        assert_eq!(table.alloc_mask, 0);
        assert_eq!(table.renego_mask, 0);
        assert_eq!(table.phys_ids, [0; MAX_SESSIONS]);
    }

    #[test]
    fn recreate_status_codes_match_reference_firmware() {
        assert_eq!(u32::from(HsmError::VaultSessionLimitReached), 0x08700001);
        assert_eq!(u32::from(HsmError::SessionNotFound), 0x08700004);
        assert_eq!(
            u32::from(HsmError::ProcessedIoEventInInvalidState),
            0x08700087
        );
    }

    #[test]
    fn delete_returns_physical_id() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(42)).unwrap();
        let phys = table.delete(id).unwrap();
        assert_eq!(u16::from(phys), 42);
    }

    // --- Pending / session-establishment protocol tests ---

    #[test]
    fn create_pending_co_lands_in_slot_zero() {
        let mut table = SessionTable::new();
        let id = table
            .create_pending(HsmSessionRole::CryptoOfficer, b"co-handshake")
            .unwrap();
        assert_eq!(u16::from(id), 0);
        assert!(matches!(table.state(id), HsmSessionState::Pending));
        assert_eq!(table.pending_state(id).unwrap(), b"co-handshake");
    }

    #[test]
    fn create_pending_cu_lands_in_one_through_seven() {
        let mut table = SessionTable::new();
        let id = table
            .create_pending(HsmSessionRole::CryptoUser, b"cu-handshake")
            .unwrap();
        assert_eq!(u16::from(id), 1);
        assert!(matches!(table.state(id), HsmSessionState::Pending));
    }

    #[test]
    fn seven_parallel_cu_inits_fill_slots_one_through_seven() {
        let mut table = SessionTable::new();
        for expected in 1u16..=7 {
            let id = table
                .create_pending(HsmSessionRole::CryptoUser, &[expected as u8])
                .unwrap();
            assert_eq!(u16::from(id), expected);
        }
    }

    #[test]
    fn eighth_cu_init_evicts_oldest_pending() {
        let mut table = SessionTable::new();
        for _ in 1u16..=7 {
            table
                .create_pending(HsmSessionRole::CryptoUser, b"x")
                .unwrap();
        }
        let oldest = HsmSessId::from(1);
        let oldest_blob_before = table.pending_state(oldest).unwrap().to_vec();
        assert_eq!(oldest_blob_before, b"x");

        // 8th request must evict the oldest (slot 1) and re-use it.
        let evicted_slot = table
            .create_pending(HsmSessionRole::CryptoUser, b"fresh")
            .unwrap();
        assert_eq!(u16::from(evicted_slot), 1);
        assert_eq!(table.pending_state(evicted_slot).unwrap(), b"fresh");
    }

    #[test]
    fn cu_init_with_all_established_returns_limit_reached() {
        let mut table = SessionTable::new();
        // Fill all 8 slots with Active sessions via the legacy path
        // (which lands them in slots 0..=7 in order).
        for i in 0u16..8 {
            table.create(HsmKeyId::from(0x100 + i)).unwrap();
        }
        let err = table
            .create_pending(HsmSessionRole::CryptoUser, b"x")
            .unwrap_err();
        assert_eq!(err, HsmError::VaultSessionLimitReached);
    }

    #[test]
    fn co_init_with_slot_zero_active_returns_limit_reached() {
        let mut table = SessionTable::new();
        // Manually fill slot 0 via the legacy create() path.
        // (slot 0 is reserved for CO; an Active CO blocks new pending.)
        table.create(HsmKeyId::from(0xCAFE)).unwrap();
        let err = table
            .create_pending(HsmSessionRole::CryptoOfficer, b"x")
            .unwrap_err();
        assert_eq!(err, HsmError::VaultSessionLimitReached);
    }

    #[test]
    fn co_init_with_slot_zero_renego_returns_limit_reached() {
        let mut table = SessionTable::new();
        // A CO session left NeedsRenegotiation by a live-migration disable
        // is reserved for its own ReopenSession — a fresh CO handshake must
        // NOT reclaim it, and reports the table full instead.
        let id = table
            .create_pending(HsmSessionRole::CryptoOfficer, b"hs")
            .unwrap();
        table.promote(id, HsmKeyId::from(0xCAFE)).unwrap();
        table.set_needs_renego(id);
        assert!(matches!(
            table.state(id),
            HsmSessionState::NeedsRenegotiation
        ));
        let err = table
            .create_pending(HsmSessionRole::CryptoOfficer, b"fresh")
            .unwrap_err();
        assert_eq!(err, HsmError::VaultSessionLimitReached);
    }

    #[test]
    fn cu_init_with_all_renego_returns_limit_reached() {
        let mut table = SessionTable::new();
        // Fill the CU range (slots 1..=7) with sessions and mark them all
        // NeedsRenegotiation (as a live-migration disable would). A fresh
        // CU handshake must NOT reclaim any of them — they are reserved for
        // their own ReopenSession — and reports the table full instead.
        for _ in 1u16..=7 {
            let id = table
                .create_pending(HsmSessionRole::CryptoUser, b"cu")
                .unwrap();
            table.promote(id, HsmKeyId::from(0x100)).unwrap();
            table.set_needs_renego(id);
        }
        let err = table
            .create_pending(HsmSessionRole::CryptoUser, b"fresh")
            .unwrap_err();
        assert_eq!(err, HsmError::VaultSessionLimitReached);
    }

    #[test]
    fn legacy_create_skips_renego_slot_and_uses_next_free() {
        let mut table = SessionTable::new();
        // An Active session in slot 0 marked NeedsRenegotiation must be
        // skipped by the legacy `create` path: a fresh session lands in the
        // next free slot rather than reclaiming the renego slot.
        let id0 = table.create(HsmKeyId::from(0x10)).unwrap();
        table.set_needs_renego(id0);
        assert!(matches!(
            table.state(id0),
            HsmSessionState::NeedsRenegotiation
        ));

        let id1 = table.create(HsmKeyId::from(0x11)).unwrap();
        assert_eq!(u16::from(id1), 1);
        // The renego slot is untouched and still reopenable.
        assert!(matches!(
            table.state(id0),
            HsmSessionState::NeedsRenegotiation
        ));
    }

    #[test]
    fn legacy_create_with_all_renego_returns_limit_reached() {
        let mut table = SessionTable::new();
        for i in 0u16..MAX_SESSIONS as u16 {
            let id = table.create(HsmKeyId::from(0x100 + i)).unwrap();
            table.set_needs_renego(id);
        }
        let err = table.create(HsmKeyId::from(0x999)).unwrap_err();
        assert_eq!(err, HsmError::VaultSessionLimitReached);
    }

    #[test]
    fn backup_snapshots_active_and_renego_but_not_pending() {
        let mut table = SessionTable::new();
        // slot 0: Active (CO); slot 1: NeedsRenegotiation (CU); slot 2:
        // Pending (CU, in-flight handshake).
        table.create(HsmKeyId::from(0xA0)).unwrap(); // slot 0 Active
        let renego = table
            .create_pending(HsmSessionRole::CryptoUser, b"r")
            .unwrap();
        table.promote(renego, HsmKeyId::from(0xA1)).unwrap();
        table.set_needs_renego(renego); // slot 1 renego
        table
            .create_pending(HsmSessionRole::CryptoUser, b"p")
            .unwrap(); // slot 2 Pending

        // Active + renego preserved; the in-flight Pending is excluded.
        assert_eq!(table.backup(), 0b0000_0011);
    }

    #[test]
    fn restore_marks_all_survivors_renego_and_drops_pending() {
        let mut table = SessionTable::new();
        // A Pending in-flight handshake must not survive the disable.
        table
            .create_pending(HsmSessionRole::CryptoUser, b"p")
            .unwrap();
        // Re-apply a snapshot of slots 0 and 3.
        table.restore(0b0000_1001);

        assert!(matches!(
            table.state(HsmSessId::from(0)),
            HsmSessionState::NeedsRenegotiation
        ));
        assert!(matches!(
            table.state(HsmSessId::from(3)),
            HsmSessionState::NeedsRenegotiation
        ));
        // The pre-restore Pending slot (2) is gone.
        assert!(matches!(
            table.state(HsmSessId::from(2)),
            HsmSessionState::Invalid
        ));
    }

    #[test]
    fn delete_frees_a_renego_slot() {
        let mut table = SessionTable::new();
        // A NeedsRenegotiation session can still be torn down (CloseSession),
        // which frees its slot for a subsequent fresh handshake.
        let id = table.create(HsmKeyId::from(0x42)).unwrap();
        table.set_needs_renego(id);
        table.delete(id).unwrap();
        assert!(matches!(table.state(id), HsmSessionState::Invalid));

        // The freed slot is now reusable.
        let reused = table.create(HsmKeyId::from(0x43)).unwrap();
        assert_eq!(u16::from(reused), u16::from(id));
    }

    #[test]
    fn promote_pending_to_active() {
        let mut table = SessionTable::new();
        let id = table
            .create_pending(HsmSessionRole::CryptoUser, b"hs")
            .unwrap();
        let phys = HsmKeyId::from(0x999);
        table.promote(id, phys).unwrap();
        assert!(matches!(table.state(id), HsmSessionState::Active));
        assert_eq!(u16::from(table.physical_id(id).unwrap()), 0x999);
        // Pending blob is cleared after promotion.
        let err = table.pending_state(id).unwrap_err();
        assert_eq!(err, HsmError::SessionNotPending);
    }

    #[test]
    fn promote_active_session_fails() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(0x123)).unwrap();
        let err = table.promote(id, HsmKeyId::from(0x456)).unwrap_err();
        assert_eq!(err, HsmError::SessionNotPending);
    }

    #[test]
    fn pending_state_blob_round_trip() {
        let mut table = SessionTable::new();
        let payload = [0xAAu8; 200];
        let id = table
            .create_pending(HsmSessionRole::CryptoUser, &payload)
            .unwrap();
        assert_eq!(table.pending_state(id).unwrap(), &payload[..]);
    }

    #[test]
    fn pending_state_rejects_oversize_blob() {
        let mut table = SessionTable::new();
        let oversized = vec![0u8; SESSION_PENDING_BLOB_MAX + 1];
        let err = table
            .create_pending(HsmSessionRole::CryptoUser, &oversized)
            .unwrap_err();
        assert_eq!(err, HsmError::InvalidArg);
    }

    #[test]
    fn delete_pending_frees_slot_without_vault_key() {
        let mut table = SessionTable::new();
        let id = table
            .create_pending(HsmSessionRole::CryptoUser, b"hs")
            .unwrap();
        // delete() returns HsmKeyId::from(0) for pending slots.
        let phys = table.delete(id).unwrap();
        assert_eq!(u16::from(phys), 0);
        assert!(matches!(table.state(id), HsmSessionState::Invalid));
    }

    #[test]
    fn pending_state_on_non_pending_slot_errors() {
        let mut table = SessionTable::new();
        let id = table.create(HsmKeyId::from(0x123)).unwrap();
        let err = table.pending_state(id).unwrap_err();
        assert_eq!(err, HsmError::SessionNotPending);
    }

    #[test]
    fn m2h_seq_carries_over_promote_and_restarts_with_new_keys() {
        let mut table = SessionTable::new();
        let id = table
            .create_pending(HsmSessionRole::CryptoUser, b"hs")
            .unwrap();
        assert_eq!(table.next_m2h_seq(id), Ok(0));
        assert_eq!(table.next_m2h_seq(id), Ok(1));
        table.promote(id, HsmKeyId::from(0x10)).unwrap();
        assert_eq!(table.next_m2h_seq(id), Ok(2));

        table.set_needs_renego(id);
        assert_eq!(table.next_m2h_seq(id), Err(HsmError::SessionNotFound));

        table.delete(id).unwrap();
        assert_eq!(table.next_m2h_seq(id), Err(HsmError::SessionNotFound));
        let id = table
            .create_pending(HsmSessionRole::CryptoUser, b"hs")
            .unwrap();
        assert_eq!(table.next_m2h_seq(id), Ok(0));
    }

    #[test]
    fn m2h_seq_fails_when_exhausted() {
        let mut table = SessionTable::new();
        let id = table
            .create_pending(HsmSessionRole::CryptoUser, b"hs")
            .unwrap();
        table.m2h_seqs[u16::from(id) as usize] = u64::MAX;
        assert_eq!(table.next_m2h_seq(id), Err(HsmError::SessionTransportError));
    }
}
