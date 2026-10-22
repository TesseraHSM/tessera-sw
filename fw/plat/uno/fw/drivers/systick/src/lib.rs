// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Embassy time driver backed by the ARM Cortex-M SysTick timer.
//!
//! Configures SysTick as a periodic tick source at 32 Hz (31.25 ms per tick)
//! from a 450 MHz core clock. The 24-bit reload value of 14,062,499 fits
//! within the SysTick counter's maximum of 16,777,215.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │ SysTick (24-bit down-counter)            │
//! │   reload = 14,062,499                    │
//! │   clock  = 450 MHz core clock            │
//! │   ISR    = SysTick exception             │
//! └──────────┬───────────────────────────────┘
//!            │ every 31.25 ms
//!            ▼
//!    TICK_COUNT.fetch_add(1)
//!    queue.next_expiration() → wake Embassy tasks
//! ```
//!
//! # Core clock selection
//!
//! The `fp-core` feature retargets the driver at the TSRA fastpath
//! cores, which run at 750 MHz. A full 1/32 s period at that clock needs a
//! reload of 23,437,499, which does not fit in the 24-bit counter, so the
//! counter is reloaded at twice the tick rate and the ISR advances the
//! monotonic counter every second interrupt. The Embassy tick rate stays at
//! 32 Hz either way, matching `embassy-time-driver/tick-hz-32`.
//!
//! # Usage
//!
//! ```ignore
//! // Call once during PAL init:
//! tsra_fw_uno_drivers_systick::init();
//! ```

#![no_std]
#![allow(unsafe_code)]

use core::cell::RefCell;
use core::task::Waker;

use cortex_m_rt::exception;
use critical_section::Mutex;
use embassy_time_driver::Driver;
use embassy_time_queue_utils::Queue;
use portable_atomic::AtomicU32;
use portable_atomic::AtomicU64;
use portable_atomic::Ordering;

#[cfg(not(feature = "fp-core"))]
const SYSTICK_CLOCK_HZ: u32 = 450_000_000;
#[cfg(feature = "fp-core")]
const SYSTICK_CLOCK_HZ: u32 = 750_000_000;

const TICK_RATE_HZ: u32 = 32;

/// SysTick interrupts per Embassy tick.
///
/// Kept at 1 unless the reload value for a full tick would overflow the
/// 24-bit SysTick counter.
#[cfg(not(feature = "fp-core"))]
const IRQ_PER_TICK: u32 = 1;
#[cfg(feature = "fp-core")]
const IRQ_PER_TICK: u32 = 2;

// 14_062_499 at 450 MHz, 11_718_749 at 750 MHz.
const RELOAD_VALUE: u32 = SYSTICK_CLOCK_HZ / (TICK_RATE_HZ * IRQ_PER_TICK) - 1;

const _: () = assert!(
    RELOAD_VALUE <= 0x00FF_FFFF,
    "SysTick reload exceeds the 24-bit counter"
);

/// Monotonic tick counter, incremented by the SysTick exception handler.
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Interrupts seen since the last tick, when `IRQ_PER_TICK` exceeds 1.
static IRQ_DIVIDER: AtomicU32 = AtomicU32::new(0);

struct SysTickDriver {
    queue: Mutex<RefCell<Queue>>,
}

impl SysTickDriver {
    const fn new() -> Self {
        Self {
            queue: Mutex::new(RefCell::new(Queue::new())),
        }
    }

    fn set_alarm(&self, _cs: &critical_section::CriticalSection<'_>, at: u64) -> bool {
        self.now() < at
    }
}

impl Driver for SysTickDriver {
    fn now(&self) -> u64 {
        TICK_COUNT.load(Ordering::Relaxed)
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        critical_section::with(|cs| {
            let mut queue = self.queue.borrow(cs).borrow_mut();
            if queue.schedule_wake(at, waker) {
                let mut next = queue.next_expiration(self.now());
                while !self.set_alarm(&cs, next) {
                    next = queue.next_expiration(self.now());
                }
            }
        });
    }
}

embassy_time_driver::time_driver_impl!(static DRIVER: SysTickDriver = SysTickDriver::new());

/// Initialises the Cortex-M SysTick peripheral as the firmware time base.
///
/// Configures the SysTick for periodic interrupts using the processor clock.
/// Must be called exactly once during PAL init, before any Embassy timers
/// are used.
pub fn init() {
    // SAFETY: Single-core Cortex-M7, called once from PAL init before
    // any interrupts are enabled.
    let mut syst = unsafe { cortex_m::Peripherals::steal().SYST };
    syst.set_reload(RELOAD_VALUE);
    syst.clear_current();
    syst.set_clock_source(cortex_m::peripheral::syst::SystClkSource::Core);
    syst.enable_interrupt();
    syst.enable_counter();
}

#[exception]
fn SysTick() {
    if !advance_tick() {
        return;
    }

    TICK_COUNT.fetch_add(1, Ordering::Relaxed);

    critical_section::with(|cs| {
        let mut queue = DRIVER.queue.borrow(cs).borrow_mut();
        queue.next_expiration(DRIVER.now());
    });
}

/// Applies the interrupt-to-tick divider.
///
/// # Returns
/// `true` when this interrupt completes an Embassy tick.
#[inline]
fn advance_tick() -> bool {
    if IRQ_PER_TICK == 1 {
        return true;
    }

    let seen = IRQ_DIVIDER.load(Ordering::Relaxed) + 1;
    if seen < IRQ_PER_TICK {
        IRQ_DIVIDER.store(seen, Ordering::Relaxed);

        return false;
    }

    IRQ_DIVIDER.store(0, Ordering::Relaxed);

    true
}
