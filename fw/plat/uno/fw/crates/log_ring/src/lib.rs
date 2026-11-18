// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CP1's side of the HSM debug-log ring.
//!
//! The SP drains this GSRAM ring into the HSP debug log. The ring is a
//! descriptor of four words, `buffer_size`, `head`, `tail`, and `overflows`,
//! followed by [`SLOTS`] records (`HSM_LOG_*` in `io_gsram`). A record is
//! three little-endian words: the descriptor word, which holds the severity,
//! the component, the message number, and a reserved zero byte, then two
//! 32-bit values.
//!
//! CP1 writes a record into the slot at `tail`, and then publishes it by
//! moving `tail`. The SP reads the record at `head`, and then moves `head`.
//! One slot always stays empty, so that a full ring looks different from an
//! empty one: the ring holds at most `SLOTS - 1` records.
//!
//! This crate holds the steps and checks only. The platform supplies the
//! memory through [`RingMemory`], and keeps the [`Sink`] in a static:
//!
//! - [`Sink::boot_reset`] resets the ring as the first step of boot, and then
//!   marks the sink ready.
//! - [`Sink::write`] runs inside a critical section. It reads `head` and
//!   `tail` once each, checks both copies against the slot count, writes the
//!   record, orders it with [`RingMemory::barrier`], and then moves `tail`.
//!   It never waits and never repairs the ring. A full ring drops the record
//!   and counts it in `overflows`, which saturates. Every other drop counts
//!   in RAM.
//! - A busy flag keeps a nested write, such as one from a fault handler that
//!   interrupts a write, away from the ring. Only the write that sets the
//!   flag clears it.

#![cfg_attr(not(test), no_std)]

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU16;
use core::sync::atomic::Ordering;
use core::sync::atomic::compiler_fence;

use critical_section::CriticalSection;
use tsra_fw_uno_reg_soc::io_gsram;

#[cfg(test)]
mod model;
#[cfg(test)]
mod tests;

/// Number of record slots in the ring.
pub const SLOTS: u32 = io_gsram::HSM_LOG_RECORDS_COUNT;

/// Size of one record in bytes.
pub const RECORD_BYTES: u32 = io_gsram::HSM_LOG_RECORDS_STRIDE;

/// GSRAM offset of `buffer_size`, the first word of the ring.
pub const BUFFER_SIZE_OFFSET: u32 = io_gsram::HSM_LOG_BUFFER_SIZE_OFFSET;

/// GSRAM offset of `head`.
pub const HEAD_OFFSET: u32 = io_gsram::HSM_LOG_HEAD_OFFSET;

/// GSRAM offset of `tail`.
pub const TAIL_OFFSET: u32 = io_gsram::HSM_LOG_TAIL_OFFSET;

/// GSRAM offset of `overflows`.
pub const OVERFLOWS_OFFSET: u32 = io_gsram::HSM_LOG_OVERFLOWS_OFFSET;

/// GSRAM offset of the first record.
pub const RECORDS_OFFSET: u32 = io_gsram::HSM_LOG_RECORDS_OFFSET;

// The layout that the SP reads. The HSP debug log depends on every value.
const _: () = assert!(io_gsram::IO_GSRAM_BASE == 0x6100_0000);
const _: () = assert!(BUFFER_SIZE_OFFSET == 0x27F8);
const _: () = assert!(HEAD_OFFSET == 0x27FC);
const _: () = assert!(TAIL_OFFSET == 0x2800);
const _: () = assert!(OVERFLOWS_OFFSET == 0x2804);
const _: () = assert!(RECORDS_OFFSET == 0x2808);
const _: () = assert!(RECORD_BYTES == 12);
const _: () = assert!(SLOTS == 170);
const _: () = assert!(RECORDS_OFFSET + SLOTS * RECORD_BYTES == 0x3000);
const _: () =
    assert!(io_gsram::IO_GSRAM_BASE + RECORDS_OFFSET + SLOTS * RECORD_BYTES == 0x6100_3000);

/// A word of a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// The descriptor: the severity, the component, the message number, and
    /// a reserved zero byte, from the lowest byte up.
    Descriptor,
    /// The first value.
    Value1,
    /// The second value.
    Value2,
}

impl Field {
    /// Position of the word in its record.
    pub const fn index(self) -> u32 {
        match self {
            Field::Descriptor => 0,
            Field::Value1 => 1,
            Field::Value2 => 2,
        }
    }
}

/// A slot index that this crate checked against the slot count of the
/// memory it uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot(u32);

impl Slot {
    /// Checks an index read from the ring.
    const fn checked(index: u32, slots: u32) -> Option<Self> {
        if index < slots {
            Some(Self(index))
        } else {
            None
        }
    }

    /// The slot's index.
    pub const fn index(self) -> u32 {
        self.0
    }

    /// The slot after this one: 0 after the last slot.
    const fn next(self, slots: u32) -> Self {
        if self.0 + 1 == slots {
            Self(0)
        } else {
            Self(self.0 + 1)
        }
    }
}

/// One 32-bit word of the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Word {
    /// `buffer_size`: the number of slots. CP1 writes it at boot.
    BufferSize,
    /// `head`: the next record the SP reads. The SP moves it, and CP1
    /// zeroes it at boot.
    Head,
    /// `tail`: the next free slot. CP1 moves it.
    Tail,
    /// `overflows`: records dropped because the ring was full.
    Overflows,
    /// A word of the record in a slot.
    Record(Slot, Field),
}

impl Word {
    /// The word's GSRAM offset, in the ring of [`SLOTS`] slots.
    pub const fn offset(self) -> u32 {
        match self {
            Word::BufferSize => BUFFER_SIZE_OFFSET,
            Word::Head => HEAD_OFFSET,
            Word::Tail => TAIL_OFFSET,
            Word::Overflows => OVERFLOWS_OFFSET,
            Word::Record(slot, field) => {
                RECORDS_OFFSET + slot.index() * RECORD_BYTES + field.index() * 4
            }
        }
    }
}

/// The memory that holds the ring.
///
/// On target, each `read` and `write` is one volatile access to GSRAM
/// through a raw pointer, at [`Word::offset`], and nothing takes a reference
/// into the ring. `barrier` is `dmb`.
///
/// ## Visible to the SP only while CP1's D-cache is off
///
/// `dmb` orders CP1's accesses, but doesn't clean a data cache, and GSRAM,
/// at `0x6100_0000`, is in the Cortex-M7's default write-back cacheable
/// region. The SP sees each record, and then the `tail` that publishes it,
/// only because CP1 runs with the D-cache **off**: nothing in the tree
/// enables it, and the Cortex-M7 comes out of reset with it disabled, so
/// every write lands in GSRAM.
///
/// **If the D-cache is ever enabled**, give the ring a non-cacheable MPU
/// region, or clean the record's cache lines and then `tail`'s, with a
/// barrier between, before the SP reads them.
pub trait RingMemory {
    /// Number of record slots: [`SLOTS`] for the ring in GSRAM.
    const SLOTS: u32;

    /// Reads one word.
    fn read(&mut self, word: Word) -> u32;

    /// Writes one word.
    fn write(&mut self, word: Word, value: u32);

    /// Makes every earlier write visible to the SP before any later write,
    /// while CP1's D-cache is off.
    fn barrier(&mut self);
}

/// What [`Sink::write`] did with a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Written and published.
    Written,
    /// Dropped because the ring was full, and counted in `overflows`.
    Full,
    /// Dropped because `head` or `tail` was out of range, and counted in RAM.
    BadIndex,
    /// Dropped because another write was in progress, and counted in RAM.
    Busy,
    /// Dropped because the ring wasn't reset yet, and counted in RAM.
    NotReady,
}

/// Records dropped for a reason other than a full ring. Each count
/// saturates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Drops {
    /// Writes before the boot reset.
    pub not_ready: u16,
    /// Nested writes.
    pub busy: u16,
    /// Writes that found `head` or `tail` out of range.
    pub bad_index: u16,
}

/// The sink's state in RAM: readiness, the busy flag, and the drop counts.
pub struct Sink {
    ready: AtomicBool,
    busy: AtomicBool,
    not_ready_drops: AtomicU16,
    busy_drops: AtomicU16,
    bad_index_drops: AtomicU16,
}

impl Default for Sink {
    fn default() -> Self {
        Self::new()
    }
}

impl Sink {
    /// A sink that isn't ready: it drops every record until
    /// [`Sink::boot_reset`].
    pub const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            not_ready_drops: AtomicU16::new(0),
            busy_drops: AtomicU16::new(0),
            bad_index_drops: AtomicU16::new(0),
        }
    }

    /// Resets the ring, and then marks the sink ready.
    ///
    /// Call it once, as the first step of boot, before the first log. It
    /// writes `head` and `tail`, and then `buffer_size` and `overflows`, in
    /// the reference firmware's order. Records that the SP hadn't drained
    /// before a reset are lost.
    pub fn boot_reset<M: RingMemory>(&self, mem: &mut M) {
        mem.write(Word::Head, 0);
        mem.write(Word::Tail, 0);
        mem.write(Word::BufferSize, M::SLOTS);
        mem.write(Word::Overflows, 0);
        compiler_fence(Ordering::SeqCst);
        self.ready.store(true, Ordering::Relaxed);
    }

    /// Writes one record into the ring, or drops and counts it.
    ///
    /// The critical section keeps interrupts out. A fault handler can still
    /// interrupt a write; if it writes too, it finds the busy flag set, and
    /// its record is dropped.
    pub fn write<M: RingMemory>(
        &self,
        _cs: CriticalSection<'_>,
        mem: &mut M,
        desc: u32,
        value1: u32,
        value2: u32,
    ) -> Outcome {
        if self.busy.load(Ordering::Relaxed) {
            count(&self.busy_drops);
            return Outcome::Busy;
        }
        self.busy.store(true, Ordering::Relaxed);
        compiler_fence(Ordering::SeqCst);
        let outcome = if self.ready.load(Ordering::Relaxed) {
            write_record(mem, desc, value1, value2)
        } else {
            Outcome::NotReady
        };
        // Counting while the flag is set keeps a nested write away from
        // these counts.
        match outcome {
            Outcome::NotReady => count(&self.not_ready_drops),
            Outcome::BadIndex => count(&self.bad_index_drops),
            Outcome::Written | Outcome::Full | Outcome::Busy => {}
        }
        compiler_fence(Ordering::SeqCst);
        self.busy.store(false, Ordering::Relaxed);
        outcome
    }

    /// The drop counts.
    pub fn drops(&self) -> Drops {
        Drops {
            not_ready: self.not_ready_drops.load(Ordering::Relaxed),
            busy: self.busy_drops.load(Ordering::Relaxed),
            bad_index: self.bad_index_drops.load(Ordering::Relaxed),
        }
    }
}

fn count(counter: &AtomicU16) {
    counter.store(
        counter.load(Ordering::Relaxed).saturating_add(1),
        Ordering::Relaxed,
    );
}

/// The ring steps of one write. Reads `head` and `tail` once each, and uses
/// only the checked copies.
fn write_record<M: RingMemory>(mem: &mut M, desc: u32, value1: u32, value2: u32) -> Outcome {
    let head = Slot::checked(mem.read(Word::Head), M::SLOTS);
    let tail = Slot::checked(mem.read(Word::Tail), M::SLOTS);
    let (Some(head), Some(tail)) = (head, tail) else {
        return Outcome::BadIndex;
    };
    let next = tail.next(M::SLOTS);
    if next == head {
        let overflows = mem.read(Word::Overflows);
        mem.write(Word::Overflows, overflows.saturating_add(1));
        return Outcome::Full;
    }
    mem.write(Word::Record(tail, Field::Descriptor), desc);
    mem.write(Word::Record(tail, Field::Value1), value1);
    mem.write(Word::Record(tail, Field::Value2), value2);
    mem.barrier();
    mem.write(Word::Tail, next.index());
    Outcome::Written
}
