// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The UART lock that CP1 shares with CP0.
//!
//! CP0 and CP1 print to the same UART. As in the reference firmware, each
//! core holds a GSRAM word while it prints one line: it waits, without a
//! limit, until a compare-and-swap changes the word from 0 to 1, and it
//! writes 0 after the line.
//!
//! GSRAM is Non-shareable on both cores, so the compare-and-swap is atomic
//! only against this core: if both cores read 0 before either write lands,
//! both print. CP1's D-cache is off, so each access reaches GSRAM, where CP0
//! sees it.

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use tsra_fw_uno_reg_soc::io_gsram;

/// The lock word's address.
const ADDRESS: u32 = io_gsram::IO_GSRAM_BASE + io_gsram::UART_LOCK_OFFSET;

// The reference firmware's GSRAM map and the HSP firmware put the word here.
const _: () = assert!(ADDRESS == 0x6100_1000);

fn word() -> &'static AtomicU32 {
    // SAFETY: `ADDRESS` is an aligned GSRAM word, mapped for the life of the
    // firmware, that CP1 accesses only through this atomic.
    unsafe { &*(ADDRESS as *const AtomicU32) }
}

/// Holds the UART lock for one line, and releases it when dropped.
pub(crate) struct Line;

impl Line {
    /// Waits, without a limit, until it takes the lock.
    pub(crate) fn take() -> Self {
        while word()
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {}
        cortex_m::asm::dmb();
        Self
    }
}

impl Drop for Line {
    fn drop(&mut self) {
        word().store(0, Ordering::Release);
        cortex_m::asm::dmb();
    }
}
