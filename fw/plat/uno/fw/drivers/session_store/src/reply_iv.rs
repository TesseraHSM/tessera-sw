// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deterministic IVs for the HSM→VM replies of TBOR sessions.
//!
//! NIST SP 800-38D §8.2.1: each IV is a fixed field, a salt drawn when the
//! session slot gets new transport keys, then an invocation field, a 64-bit
//! counter that never repeats under those keys:
//!
//! ```text
//! iv = salt(4, LE) ‖ counter(8, BE)
//! ```
//!
//! The state is volatile, so every slot starts each boot unarmed, and a
//! session that survives a reset seals with random IVs for the rest of its
//! life: where its counter had got to is lost with the reset.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering::Relaxed;

use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::SESSION_TRANSPORT_IV_LEN;
use tsra_fw_uno_drivers_part_store::HsmPartId;
use tsra_fw_uno_drivers_part_store::NUM_PARTITIONS;

use crate::session_store::MAX_SESSIONS;

const _: () = assert!(SESSION_TRANSPORT_IV_LEN == 12);

/// One slot's salt and the counter of its next IV; a zero counter means
/// unarmed.
struct ReplyIv {
    salt: AtomicU32,
    next_lo: AtomicU32,
    next_hi: AtomicU32,
}

impl ReplyIv {
    const fn new() -> Self {
        Self {
            salt: AtomicU32::new(0),
            next_lo: AtomicU32::new(0),
            next_hi: AtomicU32::new(0),
        }
    }

    fn set_next(&self, next: u64) {
        self.next_hi.store((next >> 32) as u32, Relaxed);
        self.next_lo.store(next as u32, Relaxed);
    }
}

/// The reply IVs of every partition's session slots.
pub struct ReplyIvs([ReplyIv; NUM_PARTITIONS * MAX_SESSIONS]);

impl Default for ReplyIvs {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplyIvs {
    /// Every slot unarmed.
    pub const fn new() -> Self {
        Self([const { ReplyIv::new() }; NUM_PARTITIONS * MAX_SESSIONS])
    }

    fn slot(&self, pid: HsmPartId, id: HsmSessId) -> Option<&ReplyIv> {
        let slot = usize::from(u16::from(id));
        if slot >= MAX_SESSIONS {
            return None;
        }
        self.0.get(usize::from(u8::from(pid)) * MAX_SESSIONS + slot)
    }

    /// Arms slot `id` of partition `pid`, which has just got new transport
    /// keys that nothing has used yet: its IVs count from 1 under `salt`.
    pub fn arm(&self, pid: HsmPartId, id: HsmSessId, salt: [u8; 4]) {
        if let Some(e) = self.slot(pid, id) {
            e.salt.store(u32::from_le_bytes(salt), Relaxed);
            e.set_next(1);
        }
    }

    /// Disarms slot `id` of partition `pid`: its replies get random IVs.
    pub fn disarm(&self, pid: HsmPartId, id: HsmSessId) {
        if let Some(e) = self.slot(pid, id) {
            e.set_next(0);
        }
    }

    /// Takes the next IV of slot `id` of partition `pid`, or `None` if the
    /// slot is unarmed (or out of range), for the caller to draw a random
    /// one. The counter wraps to zero after its last value, disarming the
    /// slot.
    pub fn next(&self, pid: HsmPartId, id: HsmSessId) -> Option<[u8; SESSION_TRANSPORT_IV_LEN]> {
        let e = self.slot(pid, id)?;
        let n = (u64::from(e.next_hi.load(Relaxed)) << 32) | u64::from(e.next_lo.load(Relaxed));
        if n == 0 {
            return None;
        }
        e.set_next(n.wrapping_add(1));
        let s = e.salt.load(Relaxed).to_le_bytes();
        let c = n.to_be_bytes();
        Some([
            s[0], s[1], s[2], s[3], c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
        ])
    }

    /// Sets the counter of slot `id` of partition `pid`'s next IV.
    #[cfg(test)]
    pub(crate) fn set_counter(&self, pid: HsmPartId, id: HsmSessId, next: u64) {
        if let Some(e) = self.slot(pid, id) {
            e.set_next(next);
        }
    }
}
