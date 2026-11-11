// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unit tests on owned memory: every index value, the order of the steps,
//! nested writes, and the bytes that the SP reads.

use super::*;

/// One access to the ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Read(Word),
    Write(Word, u32),
    Barrier,
}

/// The ring in owned memory, with a log of every access.
#[derive(Clone)]
struct Owned {
    words: Vec<u32>,
    log: Vec<Access>,
}

impl Owned {
    /// A ring whose every word holds `fill`.
    fn filled(fill: u32) -> Self {
        Self {
            words: vec![fill; 4 + 3 * SLOTS as usize],
            log: Vec::new(),
        }
    }

    fn index(word: Word) -> usize {
        ((word.offset() - BUFFER_SIZE_OFFSET) / 4) as usize
    }

    fn get(&self, word: Word) -> u32 {
        self.words[Self::index(word)]
    }

    fn set(&mut self, word: Word, value: u32) {
        self.words[Self::index(word)] = value;
    }
}

impl RingMemory for Owned {
    const SLOTS: u32 = SLOTS;

    fn read(&mut self, word: Word) -> u32 {
        self.log.push(Access::Read(word));
        self.get(word)
    }

    fn write(&mut self, word: Word, value: u32) {
        self.log.push(Access::Write(word, value));
        self.set(word, value);
    }

    fn barrier(&mut self) {
        self.log.push(Access::Barrier);
    }
}

fn slot(index: u32) -> Slot {
    Slot::checked(index, SLOTS).expect("an index below SLOTS")
}

/// Memory that ignores every access.
struct Null;

impl RingMemory for Null {
    const SLOTS: u32 = SLOTS;

    fn read(&mut self, _word: Word) -> u32 {
        0
    }

    fn write(&mut self, _word: Word, _value: u32) {}

    fn barrier(&mut self) {}
}

fn ready_sink() -> Sink {
    let sink = Sink::new();
    sink.boot_reset(&mut Null);
    sink
}

/// A ring with the given `head` and `tail`, an overflow count of 0, and
/// `0xEEEE_EEEE` in every record word.
fn ring(head: u32, tail: u32) -> Owned {
    let mut mem = Owned::filled(0xEEEE_EEEE);
    mem.set(Word::BufferSize, SLOTS);
    mem.set(Word::Head, head);
    mem.set(Word::Tail, tail);
    mem.set(Word::Overflows, 0);
    mem
}

fn write<M: RingMemory>(sink: &Sink, mem: &mut M, record: [u32; 3]) -> Outcome {
    critical_section::with(|cs| sink.write(cs, mem, record[0], record[1], record[2]))
}

const RECORD: [u32; 3] = [0x0012_3401, 0xA1A2_A3A4, 0xB1B2_B3B4];

/// The accesses of a write that finds room at `tail`.
fn written_log(tail: u32, record: [u32; 3]) -> Vec<Access> {
    let next = if tail == SLOTS - 1 { 0 } else { tail + 1 };
    vec![
        Access::Read(Word::Head),
        Access::Read(Word::Tail),
        Access::Write(Word::Record(slot(tail), Field::Descriptor), record[0]),
        Access::Write(Word::Record(slot(tail), Field::Value1), record[1]),
        Access::Write(Word::Record(slot(tail), Field::Value2), record[2]),
        Access::Barrier,
        Access::Write(Word::Tail, next),
    ]
}

#[test]
fn boot_reset_writes_the_descriptor_in_order_then_marks_ready() {
    let sink = Sink::new();
    let mut mem = Owned::filled(0xEEEE_EEEE);
    assert_eq!(write(&sink, &mut mem, RECORD), Outcome::NotReady);

    sink.boot_reset(&mut mem);

    assert_eq!(
        mem.log,
        [
            Access::Write(Word::Head, 0),
            Access::Write(Word::Tail, 0),
            Access::Write(Word::BufferSize, SLOTS),
            Access::Write(Word::Overflows, 0),
        ]
    );
    let records = &mem.words[4..];
    assert!(records.iter().all(|&word| word == 0xEEEE_EEEE));
    mem.log.clear();
    assert_eq!(write(&sink, &mut mem, RECORD), Outcome::Written);
    assert_eq!(mem.log, written_log(0, RECORD));
}

#[test]
fn writes_before_the_reset_drop_without_an_access() {
    let sink = Sink::new();
    let mut mem = ring(0, 0);
    let before = mem.words.clone();

    for _ in 0..3 {
        assert_eq!(write(&sink, &mut mem, RECORD), Outcome::NotReady);
    }

    assert!(mem.log.is_empty());
    assert_eq!(mem.words, before);
    assert_eq!(
        sink.drops(),
        Drops {
            not_ready: 3,
            ..Drops::default()
        }
    );
}

#[test]
fn a_write_reads_head_and_tail_once_and_orders_the_record_before_tail() {
    let sink = ready_sink();
    let mut mem = ring(5, 7);

    assert_eq!(write(&sink, &mut mem, RECORD), Outcome::Written);

    assert_eq!(mem.log, written_log(7, RECORD));
    assert_eq!(sink.drops(), Drops::default());
}

#[test]
fn every_valid_head_and_tail() {
    let sink = ready_sink();
    for head in 0..SLOTS {
        for tail in 0..SLOTS {
            let mut mem = ring(head, tail);
            let mut expected = mem.words.clone();
            let next = if tail == SLOTS - 1 { 0 } else { tail + 1 };

            let outcome = write(&sink, &mut mem, RECORD);

            if next == head {
                assert_eq!(outcome, Outcome::Full, "head {head} tail {tail}");
                assert_eq!(
                    mem.log,
                    [
                        Access::Read(Word::Head),
                        Access::Read(Word::Tail),
                        Access::Read(Word::Overflows),
                        Access::Write(Word::Overflows, 1),
                    ],
                    "head {head} tail {tail}"
                );
                expected[Owned::index(Word::Overflows)] = 1;
            } else {
                assert_eq!(outcome, Outcome::Written, "head {head} tail {tail}");
                assert_eq!(
                    mem.log,
                    written_log(tail, RECORD),
                    "head {head} tail {tail}"
                );
                for (field, value) in [Field::Descriptor, Field::Value1, Field::Value2]
                    .into_iter()
                    .zip(RECORD)
                {
                    expected[Owned::index(Word::Record(slot(tail), field))] = value;
                }
                expected[Owned::index(Word::Tail)] = next;
            }
            assert_eq!(mem.words, expected, "head {head} tail {tail}");
        }
    }
    assert_eq!(sink.drops(), Drops::default());
}

/// Every value from `SLOTS` to `0x2_0000`, values near each power of two up
/// to `u32::MAX`, and pseudo-random values above `0xFFFF`.
fn bad_indexes() -> Vec<u32> {
    let mut values: Vec<u32> = (SLOTS..0x2_0000).collect();
    for bit in 17..32 {
        let power = 1u32 << bit;
        values.extend((power - 256..=power + 256).filter(|&value| value >= SLOTS));
    }
    values.extend(u32::MAX - 1024..=u32::MAX);
    let mut state = 0x2545_F491_u32;
    for _ in 0..100_000 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        values.push(state | 0x0001_0000);
    }
    values
}

/// Writes once with the given `head` and `tail`, at least one of them out
/// of range, and checks that the write only read them.
fn assert_bad_index_drop(head: u32, tail: u32, template: &mut Owned) {
    let sink = ready_sink();
    template.set(Word::Head, head);
    template.set(Word::Tail, tail);
    template.log.clear();
    let before = template.words.clone();

    let outcome = write(&sink, template, RECORD);

    assert_eq!(outcome, Outcome::BadIndex, "head {head} tail {tail}");
    assert_eq!(
        template.log,
        [Access::Read(Word::Head), Access::Read(Word::Tail)],
        "head {head} tail {tail}"
    );
    assert_eq!(template.words, before, "head {head} tail {tail}");
    assert_eq!(
        sink.drops(),
        Drops {
            bad_index: 1,
            ..Drops::default()
        },
        "head {head} tail {tail}"
    );
}

#[test]
fn every_bad_head_drops_the_record_without_writing() {
    let mut mem = ring(0, 0);
    for head in bad_indexes() {
        assert_bad_index_drop(head, 3, &mut mem);
        assert_bad_index_drop(head, SLOTS - 1, &mut mem);
    }
}

#[test]
fn every_bad_tail_drops_the_record_without_writing() {
    let mut mem = ring(0, 0);
    for tail in bad_indexes() {
        assert_bad_index_drop(3, tail, &mut mem);
        assert_bad_index_drop(0, tail, &mut mem);
    }
}

#[test]
fn bad_head_and_tail_together_drop_the_record_without_writing() {
    let mut mem = ring(0, 0);
    for value in [SLOTS, SLOTS + 1, 0x100, 0xFFFF, 0x8000_0000, u32::MAX] {
        assert_bad_index_drop(value, value, &mut mem);
        assert_bad_index_drop(value, u32::MAX - value, &mut mem);
    }
}

#[test]
fn drop_counts_saturate() {
    let sink = Sink::new();
    let mut mem = ring(0, 0);
    for _ in 0..u32::from(u16::MAX) + 2 {
        write(&sink, &mut mem, RECORD);
    }
    assert_eq!(sink.drops().not_ready, u16::MAX);
}

#[test]
fn a_full_ring_counts_overflows_and_the_count_saturates() {
    let sink = ready_sink();
    let mut mem = ring(0, SLOTS - 1);
    mem.set(Word::Overflows, u32::MAX - 1);
    let mut expected = mem.words.clone();

    assert_eq!(write(&sink, &mut mem, RECORD), Outcome::Full);
    assert_eq!(write(&sink, &mut mem, RECORD), Outcome::Full);

    expected[Owned::index(Word::Overflows)] = u32::MAX;
    assert_eq!(mem.words, expected);
    assert_eq!(sink.drops(), Drops::default());
}

#[test]
fn the_ring_holds_one_record_fewer_than_its_slots() {
    let sink = ready_sink();
    let mut mem = ring(0, 0);

    for n in 0..SLOTS - 1 {
        assert_eq!(
            write(&sink, &mut mem, [n, !n, n]),
            Outcome::Written,
            "record {n}"
        );
    }
    assert_eq!(write(&sink, &mut mem, RECORD), Outcome::Full);

    assert_eq!(mem.get(Word::Tail), SLOTS - 1);
    assert_eq!(mem.get(Word::Overflows), 1);
    for n in 0..SLOTS - 1 {
        assert_eq!(mem.get(Word::Record(slot(n), Field::Descriptor)), n);
        assert_eq!(mem.get(Word::Record(slot(n), Field::Value1)), !n);
    }
    assert_eq!(
        mem.get(Word::Record(slot(SLOTS - 1), Field::Descriptor)),
        0xEEEE_EEEE
    );
}

/// Owned memory that simulates a fault handler: on access `fault_at` of a
/// write, it writes `nested` records before it performs the access.
struct Faulting<'a> {
    inner: Owned,
    sink: &'a Sink,
    cs: CriticalSection<'a>,
    accesses: usize,
    fault_at: usize,
    nested: usize,
    nested_outcomes: Vec<Outcome>,
}

impl Faulting<'_> {
    fn access(&mut self) {
        self.accesses += 1;
        if self.accesses == self.fault_at {
            for _ in 0..self.nested {
                let outcome = self.sink.write(self.cs, &mut self.inner, 1, 2, 3);
                self.nested_outcomes.push(outcome);
            }
        }
    }
}

impl RingMemory for Faulting<'_> {
    const SLOTS: u32 = SLOTS;

    fn read(&mut self, word: Word) -> u32 {
        self.access();
        self.inner.read(word)
    }

    fn write(&mut self, word: Word, value: u32) {
        self.access();
        self.inner.write(word, value);
    }

    fn barrier(&mut self) {
        self.access();
        self.inner.barrier();
    }
}

#[test]
fn nested_writes_drop_and_leave_the_busy_flag_to_the_outer_write() {
    // A write that finds room makes seven accesses; fault at each of them.
    for fault_at in 1..=7 {
        let sink = ready_sink();
        critical_section::with(|cs| {
            let mut mem = Faulting {
                inner: ring(4, 9),
                sink: &sink,
                cs,
                accesses: 0,
                fault_at,
                nested: 3,
                nested_outcomes: Vec::new(),
            };

            let outcome = sink.write(cs, &mut mem, RECORD[0], RECORD[1], RECORD[2]);

            assert_eq!(outcome, Outcome::Written, "fault at {fault_at}");
            assert_eq!(
                mem.nested_outcomes,
                [Outcome::Busy; 3],
                "fault at {fault_at}"
            );
            assert_eq!(mem.inner.log, written_log(9, RECORD), "fault at {fault_at}");
            assert_eq!(
                sink.drops(),
                Drops {
                    busy: 3,
                    ..Drops::default()
                },
                "fault at {fault_at}"
            );

            // The outer write cleared the flag: the next write goes through.
            mem.inner.log.clear();
            mem.fault_at = 0;
            let outcome = sink.write(cs, &mut mem.inner, RECORD[0], RECORD[1], RECORD[2]);
            assert_eq!(outcome, Outcome::Written, "fault at {fault_at}");
            assert_eq!(
                mem.inner.log,
                written_log(10, RECORD),
                "fault at {fault_at}"
            );
        });
    }
}

/// The ring as the SP sees it: little-endian bytes from `0x27F8` to
/// `0x3000`.
struct Bytes {
    image: Vec<u8>,
}

impl Bytes {
    const START: u32 = 0x27F8;
    const END: u32 = 0x3000;

    fn at(&self, offset: u32, len: usize) -> &[u8] {
        let start = (offset - Self::START) as usize;
        &self.image[start..start + len]
    }

    fn word(word: Word) -> std::ops::Range<usize> {
        let start = (word.offset() - Self::START) as usize;
        start..start + 4
    }
}

impl RingMemory for Bytes {
    const SLOTS: u32 = SLOTS;

    fn read(&mut self, word: Word) -> u32 {
        u32::from_le_bytes(self.image[Self::word(word)].try_into().expect("four bytes"))
    }

    fn write(&mut self, word: Word, value: u32) {
        self.image[Self::word(word)].copy_from_slice(&value.to_le_bytes());
    }

    fn barrier(&mut self) {}
}

/// A descriptor word: the severity, the component, the message number, and
/// a reserved zero byte, from the lowest byte up.
fn descriptor(severity: u8, component: u8, message: u8) -> u32 {
    u32::from_le_bytes([severity, component, message, 0])
}

#[test]
fn golden_offsets() {
    assert_eq!(Word::BufferSize.offset(), 0x27F8);
    assert_eq!(Word::Head.offset(), 0x27FC);
    assert_eq!(Word::Tail.offset(), 0x2800);
    assert_eq!(Word::Overflows.offset(), 0x2804);
    for n in 0..SLOTS {
        let start = 0x2808 + 12 * n;
        assert_eq!(Word::Record(slot(n), Field::Descriptor).offset(), start);
        assert_eq!(Word::Record(slot(n), Field::Value1).offset(), start + 4);
        assert_eq!(Word::Record(slot(n), Field::Value2).offset(), start + 8);
    }
    assert_eq!(
        Word::Record(slot(SLOTS - 1), Field::Value2).offset() + 4,
        Bytes::END
    );
    assert_eq!(
        tsra_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE + Bytes::END,
        0x6100_3000
    );
}

#[test]
fn golden_bytes() {
    let mut mem = Bytes {
        image: vec![0xEE; (Bytes::END - Bytes::START) as usize],
    };
    let sink = Sink::new();

    sink.boot_reset(&mut mem);
    assert_eq!(
        mem.at(0x27F8, 16),
        [0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );

    let desc = descriptor(1, 0xC3, 0x5A);
    assert_eq!(
        write(&sink, &mut mem, [desc, 0x0403_0201, u32::MAX]),
        Outcome::Written
    );
    assert_eq!(
        mem.at(0x2808, 12),
        [
            0x01, 0xC3, 0x5A, 0x00, 0x01, 0x02, 0x03, 0x04, 0xFF, 0xFF, 0xFF, 0xFF
        ]
    );
    assert_eq!(mem.at(0x2800, 4), [1, 0, 0, 0]);
    assert_eq!(mem.at(0x2814, 12), [0xEE; 12]);

    // The last slot ends at 0x3000, and `tail` wraps to 0 after it.
    mem.write(Word::Head, SLOTS - 1);
    mem.write(Word::Tail, SLOTS - 1);
    let desc = descriptor(2, 0x01, 0xFF);
    assert_eq!(
        write(&sink, &mut mem, [desc, 0, 0x8000_0001]),
        Outcome::Written
    );
    assert_eq!(
        mem.at(0x2FF4, 12),
        [0x02, 0x01, 0xFF, 0x00, 0, 0, 0, 0, 0x01, 0x00, 0x00, 0x80]
    );
    assert_eq!(mem.at(0x2800, 4), [0, 0, 0, 0]);
    assert_eq!(mem.at(0x27F8, 4), [0xAA, 0, 0, 0]);
}
