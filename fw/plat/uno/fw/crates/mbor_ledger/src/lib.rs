// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stale-ID ledger for MBOR undo.
//!
//! An MBOR command's undo log names the keys and sessions it created by
//! their reusable IDs. If another IO frees one of those IDs and it is handed
//! out again before the failed command's undo runs, the undo would delete or
//! roll back the replacement. This ledger records, per host IO slot, the IDs
//! an MBOR IO created; every free of such an ID marks the matching records
//! stale, and the undo verbs skip an ID whose own record is stale.
//!
//! Recording is best-effort: a slot keeps at most [`RECS_PER_IO`] records
//! and drops further ones. The table holds no hardware state; the Uno PAL
//! owns the instance and decides which IOs record.

#![cfg_attr(not(test), no_std)]

/// Records kept per IO slot; an MBOR command creates at most a few IDs.
pub const RECS_PER_IO: usize = 4;

/// Kind of ID a record names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A vault key ID.
    Key,
    /// A logical session ID.
    Session,
}

#[derive(Clone, Copy)]
struct Rec {
    used: bool,
    stale: bool,
    pid: u8,
    kind: Kind,
    id: u16,
    /// Session a key is bound to.
    session: Option<u16>,
}

impl Rec {
    const EMPTY: Self = Self {
        used: false,
        stale: false,
        pid: 0,
        kind: Kind::Key,
        id: 0,
        session: None,
    };

    fn names(&self, pid: u8, kind: Kind, id: u16) -> bool {
        self.used && self.pid == pid && self.kind == kind && self.id == id
    }
}

/// Per-IO-slot records of the IDs MBOR IOs created, for `SLOTS` IO slots.
pub struct Ledger<const SLOTS: usize> {
    slots: [[Rec; RECS_PER_IO]; SLOTS],
}

impl<const SLOTS: usize> Default for Ledger<SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize> Ledger<SLOTS> {
    /// An empty ledger.
    pub const fn new() -> Self {
        Self {
            slots: [[Rec::EMPTY; RECS_PER_IO]; SLOTS],
        }
    }

    /// Record that the IO in `slot` of partition `pid` created `id`.
    /// Out-of-range slots are ignored.
    pub fn record(&mut self, slot: usize, pid: u8, kind: Kind, id: u16, session: Option<u16>) {
        let Some(slot) = self.slots.get_mut(slot) else {
            return;
        };
        // Reuse a record for the same ID (re-created by this IO) so the
        // latest creation decides staleness; otherwise take a free one.
        let pos = slot
            .iter()
            .position(|r| r.names(pid, kind, id))
            .or_else(|| slot.iter().position(|r| !r.used));
        if let Some(r) = pos.and_then(|p| slot.get_mut(p)) {
            *r = Rec {
                used: true,
                stale: false,
                pid,
                kind,
                id,
                session,
            };
        }
    }

    fn mark_stale(&mut self, pred: impl Fn(&Rec) -> bool) {
        for r in self.slots.iter_mut().flatten() {
            if r.used && pred(r) {
                r.stale = true;
            }
        }
    }

    /// `id` of partition `pid` was freed.
    pub fn invalidate(&mut self, pid: u8, kind: Kind, id: u16) {
        self.mark_stale(|r| r.names(pid, kind, id));
    }

    /// Every key bound to session `session` of partition `pid` was freed.
    pub fn invalidate_session_keys(&mut self, pid: u8, session: u16) {
        self.mark_stale(|r| r.pid == pid && r.kind == Kind::Key && r.session == Some(session));
    }

    /// Every key and session of partition `pid` was freed or reset.
    pub fn invalidate_pid(&mut self, pid: u8) {
        self.mark_stale(|r| r.pid == pid);
    }

    /// Whether `id`, created by the IO in `slot` of partition `pid`, has
    /// since been freed by another path, so that IO's undo must leave the
    /// (possibly reallocated) ID alone.
    pub fn is_stale_own(&self, slot: usize, pid: u8, kind: Kind, id: u16) -> bool {
        self.slots
            .get(slot)
            .is_some_and(|s| s.iter().any(|r| r.names(pid, kind, id) && r.stale))
    }

    /// Forget `slot`'s records when its IO ends.
    pub fn clear_slot(&mut self, slot: usize) {
        if let Some(s) = self.slots.get_mut(slot) {
            *s = [Rec::EMPTY; RECS_PER_IO];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: usize = 0;
    const B: usize = 1;
    const PID: u8 = 3;

    fn ledger() -> Ledger<4> {
        Ledger::new()
    }

    #[test]
    fn unfreed_id_is_not_stale() {
        let mut l = ledger();
        l.record(A, PID, Kind::Key, 7, None);
        assert!(!l.is_stale_own(A, PID, Kind::Key, 7));
    }

    #[test]
    fn id_freed_and_reused_by_another_io_is_stale() {
        let mut l = ledger();
        l.record(A, PID, Kind::Key, 7, None);
        // Another IO deletes key 7, then creates a new key that gets ID 7.
        l.invalidate(PID, Kind::Key, 7);
        l.record(B, PID, Kind::Key, 7, None);

        assert!(l.is_stale_own(A, PID, Kind::Key, 7));
        assert!(!l.is_stale_own(B, PID, Kind::Key, 7));
    }

    #[test]
    fn invalidate_matches_pid_kind_and_id() {
        let mut l = ledger();
        l.record(A, PID, Kind::Key, 7, None);
        l.record(A, PID, Kind::Session, 7, None);
        l.record(A, PID + 1, Kind::Key, 7, None);
        l.record(A, PID, Kind::Key, 8, None);

        l.invalidate(PID, Kind::Key, 7);

        assert!(l.is_stale_own(A, PID, Kind::Key, 7));
        assert!(!l.is_stale_own(A, PID, Kind::Session, 7));
        assert!(!l.is_stale_own(A, PID + 1, Kind::Key, 7));
        assert!(!l.is_stale_own(A, PID, Kind::Key, 8));
    }

    #[test]
    fn same_io_re_creating_id_clears_stale() {
        let mut l = ledger();
        l.record(A, PID, Kind::Key, 7, None);
        l.invalidate(PID, Kind::Key, 7);
        l.record(A, PID, Kind::Key, 7, None);
        assert!(!l.is_stale_own(A, PID, Kind::Key, 7));
    }

    #[test]
    fn session_close_stales_only_its_keys() {
        let mut l = ledger();
        l.record(A, PID, Kind::Session, 2, None);
        l.record(A, PID, Kind::Key, 10, Some(2));
        l.record(A, PID, Kind::Key, 11, Some(5));
        l.record(B, PID + 1, Kind::Key, 12, Some(2));

        l.invalidate_session_keys(PID, 2);

        assert!(l.is_stale_own(A, PID, Kind::Key, 10));
        assert!(!l.is_stale_own(A, PID, Kind::Key, 11));
        assert!(!l.is_stale_own(A, PID, Kind::Session, 2));
        assert!(!l.is_stale_own(B, PID + 1, Kind::Key, 12));
    }

    #[test]
    fn partition_reset_stales_all_its_records() {
        let mut l = ledger();
        l.record(A, PID, Kind::Session, 2, None);
        l.record(B, PID, Kind::Key, 10, Some(2));
        l.record(B, PID + 1, Kind::Key, 10, None);

        l.invalidate_pid(PID);

        assert!(l.is_stale_own(A, PID, Kind::Session, 2));
        assert!(l.is_stale_own(B, PID, Kind::Key, 10));
        assert!(!l.is_stale_own(B, PID + 1, Kind::Key, 10));
    }

    #[test]
    fn clear_slot_forgets_only_that_slot() {
        let mut l = ledger();
        l.record(A, PID, Kind::Key, 7, None);
        l.record(B, PID, Kind::Key, 8, None);
        l.invalidate_pid(PID);

        l.clear_slot(A);

        assert!(!l.is_stale_own(A, PID, Kind::Key, 7));
        assert!(l.is_stale_own(B, PID, Kind::Key, 8));
        // A cleared record is gone, so a later free does not resurrect it.
        l.invalidate(PID, Kind::Key, 7);
        assert!(!l.is_stale_own(A, PID, Kind::Key, 7));
    }

    #[test]
    fn records_beyond_capacity_are_dropped() {
        let mut l = ledger();
        for id in 0..=RECS_PER_IO as u16 {
            l.record(A, PID, Kind::Key, id, None);
        }
        l.invalidate_pid(PID);

        for id in 0..RECS_PER_IO as u16 {
            assert!(l.is_stale_own(A, PID, Kind::Key, id));
        }
        assert!(!l.is_stale_own(A, PID, Kind::Key, RECS_PER_IO as u16));
    }

    #[test]
    fn re_recording_does_not_consume_capacity() {
        let mut l = ledger();
        for _ in 0..RECS_PER_IO {
            l.record(A, PID, Kind::Key, 7, None);
        }
        l.record(A, PID, Kind::Key, 8, None);
        l.invalidate_pid(PID);
        assert!(l.is_stale_own(A, PID, Kind::Key, 8));
    }

    #[test]
    fn out_of_range_slot_is_ignored() {
        let mut l = ledger();
        l.record(4, PID, Kind::Key, 7, None);
        l.invalidate_pid(PID);
        assert!(!l.is_stale_own(4, PID, Kind::Key, 7));
        l.clear_slot(4);
    }
}
