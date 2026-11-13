// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The HSM debug-log sink.
//!
//! Writes records into the GSRAM ring that the SP drains into the HSP debug
//! log, and defines the Uno log crate's debug-log hook,
//! `__hsm_log_record`. The steps and checks, and their tests, are in
//! `tsra_fw_uno_log_ring`; this module owns the sink's RAM state and the
//! ring's GSRAM pointers.

use tsra_fw_uno_log_ring::RingMemory;
use tsra_fw_uno_log_ring::SLOTS;
use tsra_fw_uno_log_ring::Sink;
use tsra_fw_uno_log_ring::Word;
use tsra_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;

/// The sink's state: readiness, the busy flag, and the drop counts, which a
/// debugger can read.
static SINK: Sink = Sink::new();

/// The ring in GSRAM.
struct GsramRing;

impl GsramRing {
    fn address(word: Word) -> *mut u32 {
        (IO_GSRAM_BASE + word.offset()) as usize as *mut u32
    }
}

impl RingMemory for GsramRing {
    const SLOTS: u32 = SLOTS;

    #[allow(unsafe_code)]
    fn read(&mut self, word: Word) -> u32 {
        // SAFETY: `word` is a word of the ring, whose slot index the log
        // ring crate checked against `SLOTS`, so the address is an aligned
        // word in GSRAM. No reference into the ring exists.
        unsafe { core::ptr::read_volatile(Self::address(word)) }
    }

    #[allow(unsafe_code)]
    fn write(&mut self, word: Word, value: u32) {
        // SAFETY: as for `read`.
        unsafe { core::ptr::write_volatile(Self::address(word), value) }
    }

    fn barrier(&mut self) {
        // Orders the record before `tail`, but cleans no data cache: the SP
        // sees the record only while CP1's D-cache is off. See "Visible to
        // the SP only while CP1's D-cache is off" on `RingMemory`.
        cortex_m::asm::dmb();
    }
}

/// The Uno debug-log sink.
pub struct UnoLog;

/// The Uno log crate's debug-log hook: writes one record into the ring,
/// or drops and counts it.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub fn __hsm_log_record(desc: u32, arg1: u32, arg2: u32) {
    UnoLog::record(desc, arg1, arg2);
}

// The definition and the Uno log crate's declaration must both have this type.
const _: fn(u32, u32, u32) = __hsm_log_record;
const _: unsafe fn(u32, u32, u32) = tsra_fw_uno_debug_log::__hsm_log_record;

impl UnoLog {
    /// Resets the ring, and then marks the sink ready. The app calls it as
    /// the first step of boot, before the first log.
    ///
    /// Images built with `semihosting` skip the reset, so their sink drops
    /// every record and never accesses the ring.
    pub fn boot_reset() {
        if cfg!(feature = "semihosting") {
            return;
        }
        SINK.boot_reset(&mut GsramRing);
    }

    /// Writes one record into the ring, or drops and counts it. Private, so
    /// that records come only through the Uno log crate's hook.
    fn record(desc: u32, value1: u32, value2: u32) {
        critical_section::with(|cs| {
            SINK.write(cs, &mut GsramRing, desc, value1, value2);
        });
    }
}
