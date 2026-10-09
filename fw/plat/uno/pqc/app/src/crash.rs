// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crash box: the fault record a core leaves behind when it stops.
//!
//! The fastpath cores have no console. A core that faults simply stops
//! answering, and the only evidence upstream is the HSM's "engine did not
//! answer" timeout -- which reads the same whether the core took a bus
//! fault, ran its stack into `.bss`, or panicked. Worse, the default fault
//! handler is an infinite loop, so the core sits there holding every clue
//! in registers nobody will ever read.
//!
//! This leaves those clues where the HSM can pick them up. The record goes
//! in the tail of this core's own mailbox: the request and response fields
//! end at word 27 and the mailbox runs to word 63. Writing there costs no PSRAM, needs no new
//! mapping, and cannot disturb a request that is not going to complete.
//!
//! The magic word is written *last*, so a reader never mistakes a
//! half-written record for a whole one.

use core::ptr::read_volatile;
use core::ptr::write_volatile;

use cortex_m_rt::exception;
use cortex_m_rt::ExceptionFrame;

/// Base of PSRAM in this core's local view; see `mailbox`.
const PSRAM_LOCAL_BASE: usize = 0x0001_0000;
const MAILBOX_OFFSET: usize = 0x0980;
const MAILBOX_STRIDE: usize = 0x100;

/// First word of the crash record, clear of the request and response
/// fields with room to spare.
const CRASH_WORD: usize = 48;

/// ASCII "FPCR".
pub const CRASH_MAGIC: u32 = 0x4650_4352;

/// Why the core stopped.
pub const KIND_HARD_FAULT: u32 = 1;
pub const KIND_PANIC: u32 = 2;

/// Configurable Fault Status Register: which fault, and why.
const CFSR: *const u32 = 0xE000_ED28 as *const u32;
/// HardFault Status Register: chiefly whether a configurable fault escalated.
const HFSR: *const u32 = 0xE000_ED2C as *const u32;
/// Faulting data address for a MemManage fault.
const MMFAR: *const u32 = 0xE000_ED34 as *const u32;
/// Faulting data address for a BusFault.
const BFAR: *const u32 = 0xE000_ED38 as *const u32;

extern "C" {
    /// End of `.bss`. The stack grows down towards this, and crossing it is
    /// the failure this module exists to make visible.
    static __ebss: u32;
}

fn slot(core_id: u8) -> *mut u32 {
    (PSRAM_LOCAL_BASE + MAILBOX_OFFSET + core_id as usize * MAILBOX_STRIDE + CRASH_WORD * 4)
        as *mut u32
}

/// Leave a record of why this core stopped.
///
/// Allocation-free and shallow on purpose: it runs on a stack that may
/// itself be the reason we are here.
pub fn record(kind: u32, pc: u32, lr: u32, sp: u32) {
    let core_id = crate::core_id();
    if core_id >= crate::FP_CORES {
        return;
    }
    let floor = core::ptr::addr_of!(__ebss) as u32;
    let p = slot(core_id);

    // SAFETY: words 48..57 of this core's own 256-byte mailbox, above every
    // field either side reads. Volatile because the HSM observes them, and
    // because this core is about to stop executing entirely.
    unsafe {
        write_volatile(p.add(1), kind);
        write_volatile(p.add(2), pc);
        write_volatile(p.add(3), lr);
        write_volatile(p.add(4), sp);
        write_volatile(p.add(5), read_volatile(CFSR));
        write_volatile(p.add(6), read_volatile(HFSR));
        write_volatile(p.add(7), read_volatile(MMFAR));
        write_volatile(p.add(8), read_volatile(BFAR));
        // Distance from the stack pointer down to the top of `.bss`. This
        // goes hugely positive -- i.e. wraps -- once the stack has crossed
        // into `.bss`, which is exactly the case worth seeing.
        write_volatile(p.add(9), sp.wrapping_sub(floor));
        write_volatile(p, CRASH_MAGIC);
    }
}

/// Current stack pointer, for the paths that are not handed an exception
/// frame.
pub fn sp() -> u32 {
    let sp: u32;
    // SAFETY: reads a core register into a local; no memory is touched.
    unsafe { core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack)) };
    sp
}

/// Catches MemManage, BusFault and UsageFault too: none of them are enabled
/// separately, so all three escalate to here.
///
/// # Safety
/// Invoked only by the CPU's exception mechanism with a valid exception
/// frame; it is never called directly. The handler diverges, so it never
/// returns to the faulting context.
#[exception]
unsafe fn HardFault(ef: &ExceptionFrame) -> ! {
    record(
        KIND_HARD_FAULT,
        ef.pc(),
        ef.lr(),
        ef as *const ExceptionFrame as u32,
    );
    crate::park()
}
