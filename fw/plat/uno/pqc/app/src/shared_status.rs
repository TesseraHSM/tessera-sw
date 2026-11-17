// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared status block in GSRAM, used to prove FP↔HSM shared memory works.
//!
//! FP has no console, so before any real transport is built there needs to
//! be *some* way to show that an FP core can reach the memory the HSM will
//! hand it operand pointers into.  This is that: each core publishes a
//! small block the HSM reads back and logs over UART.
//!
//! It also publishes this core's cache configuration.  Whether the FP
//! Cortex-M7s have caches at all decides whether shared memory needs
//! non-cacheable MPU attributes, and that is worth establishing from the
//! hardware rather than from belief: an MPU misconfiguration faults a core
//! that cannot report it.
//!
//! It exercises both directions:
//!
//! * **FP writes / HSM reads** — the magic, core id and a counter.  A
//!   counter rather than a constant so the HSM can tell a live core from a
//!   stale block left by a previous boot.
//! * **HSM writes / FP reads** — the HSM leaves a sentinel, and each core
//!   copies the value it sees into its own block.  A matching echo proves
//!   the read direction, and proves it is genuinely shared rather than each
//!   side talking to its own copy.
//!
//! The core id published here is also the first runtime confirmation that
//! the post-link identity stamp landed on the right core: block `n` should
//! report `core_id == n`.
//!
//! # Placement and addressing
//!
//! GSRAM spans `0x6100_0000`–`0x6120_0000` (2 MB) **in the global SoC map**,
//! which is how the HSM core sees it.  An FP core does not: it reaches
//! GSRAM through a core-local aperture at `0xE046_0000`, only `0x2_0000`
//! (128 KB) wide.  So the same word has two addresses, and each side must
//! use its own —
//!
//! ```text
//! FP-local  = 0xE046_0000 + offset
//! global    = 0x6100_0000 + offset      (offset < 0x2_0000)
//! ```
//!
//! Getting this wrong is not subtle: addressing GSRAM from FP by its global
//! address faults the core, and with no console the only symptom is a lost
//! heartbeat.  The same split applies to the other shared memories — dTCM
//! is core-local `0x2000_0000` but global `0xA300_0000 + 0x20_0000 * n`,
//! and PSRAM is core-local `0x0001_0000` but global `0xA3E0_0000`.
//!
//! In use in GSRAM today are the boot status and Admin↔HSM IPC rings at
//! offsets `0x7000`–`0x7114`, and the IO queues from `0xE440` upward.  This
//! block sits at offset `0x8000`, inside the gap between them and
//! comfortably within the 128 KB an FP core can see.
//!
//! The layout is mirrored on the HSM side in the PQC driver; the two must
//! be kept in step.

use core::ptr::read_volatile;
use core::ptr::write_volatile;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

/// Doorbells this core has answered, so the HSM can tell a fresh reply
/// from a stale descriptor value.
static DOORBELL_COUNT: AtomicU32 = AtomicU32::new(0);

/// Base of PSRAM in this core's local view.  Global address `0xA3E0_0000`.
///
/// GSRAM was tried first and faulted every core, at both its global address
/// and the `0xE046_0000` aperture the legacy memory map names.  That map
/// *defines* a GSRAM base but never uses it anywhere in the legacy
/// firmware, so it appears FP was never able to reach GSRAM.  PSRAM, by
/// contrast, the legacy fastpath used routinely.
const PSRAM_LOCAL_BASE: usize = 0x0001_0000;

/// Offset of the shared status block within PSRAM's 32 KB.
///
/// Sits just after the mailboxes and before FP0's operand slot; the tail of
/// PSRAM that this used to occupy is now covered by FP2's slot.
const PSRAM_BLOCK_OFFSET: usize = 0x0C80;

/// Base of the shared status block in this core's local view.
const BLOCK_BASE: usize = PSRAM_LOCAL_BASE + PSRAM_BLOCK_OFFSET;

/// Word the HSM writes for the cores to echo back.
const HSM_SENTINEL: *mut u32 = BLOCK_BASE as *mut u32;

/// Offset of the first per-core block, leaving the first 16 bytes for
/// HSM→FP fields.
const CORE_BLOCK_OFFSET: usize = 0x10;

/// Size of one core's block.
const CORE_BLOCK_SIZE: usize = 0x20;

/// Cache Level ID Register — which cache levels the core implements.  Zero
/// means no caches are fitted, and cacheability attributes are inert.
const CLIDR: *const u32 = 0xE000_ED78 as *const u32;

/// Configuration and Control Register — bit 16 `DC` and bit 17 `IC` report
/// whether the data and instruction caches are enabled.
const CCR: *const u32 = 0xE000_ED14 as *const u32;

/// Marks a core block as written by this firmware: ASCII "FPOK".
pub const FP_STATUS_MAGIC: u32 = 0x464F_4B50;

/// Publish this core's status, echoing whatever sentinel the HSM has left.
///
/// # Parameters
/// * `core_id` — this core's stamped identity.
/// * `counter` — increments every call, so a reader can distinguish a live
///   core from a stale block.
pub fn publish(core_id: u8, counter: u32) {
    let block = (BLOCK_BASE + CORE_BLOCK_OFFSET + (core_id as usize) * CORE_BLOCK_SIZE) as *mut u32;

    // SAFETY: `block` is a 16-byte slot in the GSRAM aperture, reserved for
    // this core by the layout above and mapped Normal / non-cacheable /
    // shareable by the MPU. It lies outside every region described to the
    // linker, so no Rust object aliases it. Volatile because the HSM core
    // observes these writes.
    unsafe {
        let sentinel = read_volatile(HSM_SENTINEL);
        write_volatile(block, FP_STATUS_MAGIC);
        write_volatile(block.add(1), core_id as u32);
        write_volatile(block.add(2), counter);
        write_volatile(block.add(3), sentinel);
        write_volatile(block.add(4), read_volatile(CLIDR));
        write_volatile(block.add(5), read_volatile(CCR));
    }
}

/// Record that a doorbell arrived from the HSM.
///
/// Written straight into the status block rather than waiting for the next
/// status refresh, so a doorbell is visible immediately after it is
/// answered.
pub fn note_doorbell(core_id: u8, pending: u32) {
    let block = (BLOCK_BASE + CORE_BLOCK_OFFSET + (core_id as usize) * CORE_BLOCK_SIZE) as *mut u32;
    let count = DOORBELL_COUNT.fetch_add(1, Ordering::Relaxed);

    // SAFETY: words 6 and 7 of this core's own 32-byte block; see `publish`.
    // Word 6 accumulates every descriptor bit ever seen, so a one-off
    // arrival is not lost between reads by the HSM.
    unsafe {
        let seen = read_volatile(block.add(6)) | pending;
        write_volatile(block.add(6), seen);
        write_volatile(block.add(7), count);
    }
}
