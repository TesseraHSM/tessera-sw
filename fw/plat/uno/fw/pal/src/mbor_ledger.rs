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
//! Only MBOR host IOs record, so TBOR and admin flows never find a record and
//! behave exactly as before. Recording is best-effort: a slot keeps at most
//! [`RECS_PER_IO`] records and drops further ones. Callers must not hold the
//! ledger across an `.await` (see [`SingleCell::with`]).

use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmSqe;
use tsra_fw_single_cell::SingleCell;
use tsra_fw_uno_drivers_part_store::HsmPartId;
use tsra_fw_uno_reg_soc::io_gsram::IO_SQ_COUNT;

use crate::UnoHsmIo;
use crate::alloc::IO_SLOTS;

/// Uno SQE opcode of an MBOR command (`tsra_fw_hsm_core::OP_MBOR`).
const OP_MBOR: u16 = 0;

/// Records kept per IO slot; an MBOR command creates at most a few IDs.
const RECS_PER_IO: usize = 4;

/// Kind of ID a record names.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
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

static LEDGER: SingleCell<[[Rec; RECS_PER_IO]; IO_SLOTS]> =
    SingleCell::new([[Rec::EMPTY; RECS_PER_IO]; IO_SLOTS]);

/// Record that the MBOR host IO `io` created `id`. No-op for any other IO.
pub(crate) fn record(io: &UnoHsmIo, kind: Kind, id: u16, session: Option<u16>) {
    if (io.index() as u32) >= IO_SQ_COUNT || io.sqe().opcode() != OP_MBOR {
        return;
    }
    let pid = u8::from(io.pid());
    LEDGER.with(|l| {
        let Some(slot) = l.get_mut(usize::from(io.index())) else {
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
    });
}

fn mark_stale(pred: impl Fn(&Rec) -> bool) {
    LEDGER.with(|l| {
        for r in l.iter_mut().flatten() {
            if r.used && pred(r) {
                r.stale = true;
            }
        }
    });
}

/// `id` of partition `pid` was freed.
pub(crate) fn invalidate(pid: HsmPartId, kind: Kind, id: u16) {
    let pid = u8::from(pid);
    mark_stale(|r| r.names(pid, kind, id));
}

/// Every key bound to session `session` of partition `pid` was freed.
pub(crate) fn invalidate_session_keys(pid: HsmPartId, session: u16) {
    let pid = u8::from(pid);
    mark_stale(|r| r.pid == pid && r.kind == Kind::Key && r.session == Some(session));
}

/// Every key and session of partition `pid` was freed or reset.
pub(crate) fn invalidate_pid(pid: HsmPartId) {
    let pid = u8::from(pid);
    mark_stale(|r| r.pid == pid);
}

/// Whether `id`, created by `io`, has since been freed by another path, so
/// `io`'s undo must leave the (possibly reallocated) ID alone.
pub(crate) fn is_stale_own(io: &UnoHsmIo, kind: Kind, id: u16) -> bool {
    let pid = u8::from(io.pid());
    LEDGER.with(|l| {
        l.get(usize::from(io.index()))
            .is_some_and(|slot| slot.iter().any(|r| r.names(pid, kind, id) && r.stale))
    })
}

/// Forget slot `index`'s records when its IO ends.
pub(crate) fn clear_slot(index: u16) {
    LEDGER.with(|l| {
        if let Some(slot) = l.get_mut(usize::from(index)) {
            *slot = [Rec::EMPTY; RECS_PER_IO];
        }
    });
}
