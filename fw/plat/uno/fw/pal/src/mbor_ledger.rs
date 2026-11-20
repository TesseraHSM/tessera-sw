// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno PAL instance of the MBOR stale-ID ledger
//! ([`tsra_fw_uno_mbor_ledger`]).
//!
//! Only MBOR host IOs record, so TBOR and admin flows never find a record and
//! behave exactly as before. Callers must not hold the ledger across an
//! `.await` (see [`SingleCell::with`]).

use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmSqe;
use tsra_fw_single_cell::SingleCell;
use tsra_fw_uno_drivers_part_store::HsmPartId;
pub(crate) use tsra_fw_uno_mbor_ledger::Kind;
use tsra_fw_uno_mbor_ledger::Ledger;
use tsra_fw_uno_reg_soc::io_gsram::IO_SQ_COUNT;

use crate::UnoHsmIo;
use crate::alloc::IO_SLOTS;

/// Uno SQE opcode of an MBOR command (`tsra_fw_hsm_core::OP_MBOR`).
const OP_MBOR: u16 = 0;

static LEDGER: SingleCell<Ledger<IO_SLOTS>> = SingleCell::new(Ledger::new());

/// Record that the MBOR host IO `io` created `id`. No-op for any other IO.
pub(crate) fn record(io: &UnoHsmIo, kind: Kind, id: u16, session: Option<u16>) {
    if (io.index() as u32) >= IO_SQ_COUNT || io.sqe().opcode() != OP_MBOR {
        return;
    }
    let pid = u8::from(io.pid());
    LEDGER.with(|l| l.record(usize::from(io.index()), pid, kind, id, session));
}

/// `id` of partition `pid` was freed.
pub(crate) fn invalidate(pid: HsmPartId, kind: Kind, id: u16) {
    LEDGER.with(|l| l.invalidate(u8::from(pid), kind, id));
}

/// Every key bound to session `session` of partition `pid` was freed.
pub(crate) fn invalidate_session_keys(pid: HsmPartId, session: u16) {
    LEDGER.with(|l| l.invalidate_session_keys(u8::from(pid), session));
}

/// Every key and session of partition `pid` was freed or reset.
pub(crate) fn invalidate_pid(pid: HsmPartId) {
    LEDGER.with(|l| l.invalidate_pid(u8::from(pid)));
}

/// Whether `id`, created by `io`, has since been freed by another path, so
/// `io`'s undo must leave the (possibly reallocated) ID alone.
pub(crate) fn is_stale_own(io: &UnoHsmIo, kind: Kind, id: u16) -> bool {
    let pid = u8::from(io.pid());
    LEDGER.with(|l| l.is_stale_own(usize::from(io.index()), pid, kind, id))
}

/// Forget slot `index`'s records when its IO ends.
pub(crate) fn clear_slot(index: u16) {
    LEDGER.with(|l| l.clear_slot(usize::from(index)));
}
