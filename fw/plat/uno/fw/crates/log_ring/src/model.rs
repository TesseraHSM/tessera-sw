// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Interleaving model of CP1's writes and the SP's drains.
//!
//! The model runs this crate's write and boot-reset steps against a model of
//! the shared memory and of the SP, and searches every schedule with up to
//! two preemptions: switches away from a side that could go on. An ignored
//! test repeats the searches with three. Each scheduled step is one memory
//! access:
//!
//! - CP1 runs the crate's steps. Its writes enter a store buffer and become
//!   visible later: in any order across words, and in order for one word.
//!   [`RingMemory::barrier`] waits until every earlier write is visible. CP1
//!   reads its own buffered writes.
//! - The SP drains the ring one access at a time, in program order, and its
//!   writes are visible at once. A drain checks `head`, `tail`, and
//!   `buffer_size`. Then, for each record, it loads `head`, `tail`, and
//!   `buffer_size` once each and makes the same checks, reads the record
//!   (three descriptor bytes, then the two values), and then moves `head`.
//!   A drain ends at an empty or invalid ring, with one read of
//!   `overflows`.
//! - Each side keeps using the values it loaded while the other side moves
//!   on.
//!
//! The model's rings have three slots, so full rings, wraps, and resets fit
//! the search; the steps use the slot count only in their index checks and
//! wraps. The unit tests cover every index value of the real ring.
//!
//! Two assumptions come from the SP's boot sequence:
//!
//! - A drain doesn't start while a boot-reset write is still buffered: the
//!   store buffer empties long before the SP's first periodic drain.
//! - The HSP firmware resets the device right after any drain that can run
//!   before its first periodic drain, so only such a drain can overlap a
//!   boot reset. After a drain that overlaps the boot reset, no drain starts
//!   until CP1 boots again.
//!
//! The tests that every access stays in the ring drop both assumptions.
//!
//! Mutants of both sides must fail, which shows that the search finds the
//! bugs that the properties describe.

use super::Drops;
use super::Field;
use super::Outcome;
use super::RingMemory;
use super::Sink;
use super::Slot;
use super::Word;

/// Slots in the model's rings.
const N: u32 = 3;

/// Upper limit on schedules per search, as a guard against a search that
/// doesn't end.
const MAX_SCHEDULES: u64 = 20_000_000;

// Positions of the descriptor words in the model's memory. Records follow,
// three words each.
const SIZE: usize = 0;
const HEAD: usize = 1;
const TAIL: usize = 2;
const OVERFLOWS: usize = 3;

const fn record_word(slot: u32, field: u32) -> usize {
    4 + 3 * slot as usize + field as usize
}

/// Record `n`, below 256. Its words agree with each other, so a record mixed
/// from two writes, or a slot that was never written, has no [`number`].
fn record(n: u32) -> [u32; 3] {
    let value1 = 0x5A00_0000 | n;
    [n | (n << 8) | (n << 16), value1, !value1]
}

/// The number of a whole record.
fn number(words: [u32; 3]) -> Option<u32> {
    let n = words[0] & 0xFF;
    (words == record(n)).then_some(n)
}

/// Words of a slot that holds no record.
const GARBAGE: [u32; 3] = [0xDEAD_BEEF, 0x0BAD_F00D, 0x1234_5678];

/// The ring and the work at the start of a schedule.
struct Scenario {
    head: u32,
    tail: u32,
    size: u32,
    overflows: u32,
    slots: [[u32; 3]; N as usize],
    /// CP1 boots first: it resets the ring, and only then is the sink
    /// ready. Otherwise the sink is ready from the start, and the SP has
    /// already reported `overflows`.
    boot: bool,
    /// After a drain that overlaps the boot reset, the device resets, and
    /// CP1 boots again before the next drain.
    reboot: bool,
    /// Records CP1 writes, numbered from 1.
    records: u32,
    /// Drains the SP may start while CP1 runs. One more drain empties the
    /// ring at the end.
    drains: u32,
}

impl Scenario {
    /// The records in the ring before CP1 starts, in the order the SP reads
    /// them.
    fn old_records(&self) -> Vec<u32> {
        let mut old = Vec::new();
        let mut slot = self.head;
        while slot != self.tail {
            old.push(number(self.slots[slot as usize]).expect("an old record"));
            slot = (slot + 1) % N;
        }
        old
    }

    fn power_on(&self) -> bool {
        self.size == 0
    }
}

/// An empty ring at its last slot, so CP1's writes wrap and fill it.
fn room() -> Scenario {
    Scenario {
        head: 2,
        tail: 2,
        size: N,
        overflows: 0,
        slots: [GARBAGE; N as usize],
        boot: false,
        reboot: false,
        records: 3,
        drains: 2,
    }
}

/// A full ring: two records that the SP hasn't read.
fn full() -> Scenario {
    Scenario {
        head: 1,
        tail: 0,
        size: N,
        overflows: 7,
        slots: [GARBAGE, record(101), record(102)],
        boot: false,
        reboot: false,
        records: 2,
        drains: 2,
    }
}

/// A warm boot: the ring keeps two records from before the reset, and a
/// write that CP1 hadn't published.
fn warm_boot() -> Scenario {
    Scenario {
        head: 2,
        tail: 1,
        size: N,
        overflows: 9,
        slots: [record(102), GARBAGE, record(101)],
        boot: true,
        reboot: true,
        records: 2,
        drains: 2,
    }
}

/// A warm boot with no device reset after a drain that overlaps it.
fn warm_boot_without_reboot() -> Scenario {
    Scenario {
        reboot: false,
        ..warm_boot()
    }
}

/// The smallest warm boot that shows the spill without the device reset:
/// one drain overlaps the boot reset, and a second one reads the stale
/// slots before CP1 publishes a record.
fn spill() -> Scenario {
    Scenario {
        records: 1,
        ..warm_boot_without_reboot()
    }
}

/// A power-on boot: GSRAM starts cleared.
fn power_on() -> Scenario {
    Scenario {
        head: 0,
        tail: 0,
        size: 0,
        overflows: 0,
        slots: [[0; 3]; N as usize],
        boot: true,
        reboot: false,
        records: 2,
        drains: 2,
    }
}

/// A boot with GSRAM that holds old values: `head` and `tail` are past the
/// ring, but below the stale `buffer_size`.
fn uncleared() -> Scenario {
    Scenario {
        head: 5,
        tail: 9,
        size: 16,
        overflows: 0x1234,
        slots: [GARBAGE; N as usize],
        boot: true,
        reboot: false,
        records: 1,
        drains: 2,
    }
}

/// CP1's steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Producer {
    /// [`Sink::write`].
    Crate,
    /// Mutant: moves `tail`, and only then writes the record.
    TailFirst,
    /// Mutant: no barrier between the record and `tail`.
    NoBarrier,
    /// Mutant: never finds the ring full, so it fills the last empty slot.
    NoFullCheck,
}

/// The SP's steps for each record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Consumer {
    /// Load `head`, `tail`, and `buffer_size`; check; read; move `head`.
    Drain,
    /// Mutant: reads the record before it loads `tail`.
    RecordBeforeTail,
    /// Moves `head` before it reads the record.
    HeadFirst,
    /// Mutant: doesn't check that `buffer_size` is the ring's size.
    NoSizeCheck,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    LoadHead,
    LoadTail,
    LoadSize,
    /// Ends the loop when the copies are invalid or the ring is empty.
    Check,
    /// Ends the loop when the `head` copy is out of range.
    CheckHead,
    /// Reads byte `0..3` of the descriptor, or value 1 (3) or 2 (4).
    Read(u8),
    StoreHead,
    Deliver,
}

impl Consumer {
    fn steps(self) -> &'static [Op] {
        use Op::*;
        match self {
            Consumer::Drain | Consumer::NoSizeCheck => &[
                LoadHead,
                LoadTail,
                LoadSize,
                Check,
                Read(0),
                Read(1),
                Read(2),
                Read(3),
                Read(4),
                StoreHead,
                Deliver,
            ],
            Consumer::RecordBeforeTail => &[
                LoadHead,
                CheckHead,
                Read(0),
                Read(1),
                Read(2),
                Read(3),
                Read(4),
                LoadTail,
                LoadSize,
                Check,
                StoreHead,
                Deliver,
            ],
            Consumer::HeadFirst => &[
                LoadHead,
                LoadTail,
                LoadSize,
                Check,
                StoreHead,
                Read(0),
                Read(1),
                Read(2),
                Read(3),
                Read(4),
                Deliver,
            ],
        }
    }
}

/// When a drain ran, relative to CP1's boot reset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// It ended before the boot reset began.
    BeforeBoot,
    /// It was running when the boot reset began.
    Overlap,
    /// It started after every boot-reset write was visible, or there was no
    /// boot reset.
    Clean,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpState {
    Idle,
    Check(u8),
    Loop(usize),
    Overflows,
}

struct Sp {
    state: SpState,
    class: Class,
    started: u32,
    head: u32,
    tail: u32,
    size: u32,
    got: [u32; 5],
    reported_baseline: u32,
    reported: Option<u32>,
}

impl Sp {
    fn valid(&self, consumer: Consumer) -> bool {
        self.head < self.size
            && self.tail < self.size
            && (consumer == Consumer::NoSizeCheck || self.size == N)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Actor {
    Cp1,
    Buffer,
    Sp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    /// CP1 goes on to its next load.
    Cp1,
    /// The buffered write at this position becomes visible.
    Commit(usize),
    /// The SP makes one access.
    Sp,
}

impl Event {
    fn actor(self) -> Actor {
        match self {
            Event::Cp1 => Actor::Cp1,
            Event::Commit(_) => Actor::Buffer,
            Event::Sp => Actor::Sp,
        }
    }
}

/// A point with more than one possible next event.
struct Decision {
    options: Vec<Event>,
    chosen: usize,
    current: Actor,
    current_enabled: bool,
    preemptions: u32,
}

impl Decision {
    fn cost(&self, option: usize) -> u32 {
        u32::from(self.current_enabled && self.options[option].actor() != self.current)
    }
}

/// Replays a prefix of choices, then takes the first option at each new
/// point: the side that ran last, when it can go on.
struct Sched {
    prefix: Vec<usize>,
    decisions: Vec<Decision>,
    current: Actor,
    preemptions: u32,
}

impl Sched {
    fn choose(&mut self, mut options: Vec<Event>) -> Event {
        let current = self.current;
        options.sort_by_key(|event| event.actor() != current);
        let current_enabled = options[0].actor() == current;
        let chosen = if options.len() == 1 {
            0
        } else {
            let chosen = self.prefix.get(self.decisions.len()).copied().unwrap_or(0);
            self.decisions.push(Decision {
                options: options.clone(),
                chosen,
                current,
                current_enabled,
                preemptions: self.preemptions,
            });
            chosen
        };
        let event = options[chosen];
        if current_enabled && event.actor() != current {
            self.preemptions += 1;
        }
        self.current = event.actor();
        event
    }
}

/// The next prefix to replay with at most `bound` preemptions, or `None` when
/// the search is done.
fn next_prefix(decisions: &[Decision], bound: u32) -> Option<Vec<usize>> {
    for (at, decision) in decisions.iter().enumerate().rev() {
        for option in decision.chosen + 1..decision.options.len() {
            if decision.preemptions + decision.cost(option) <= bound {
                let mut prefix: Vec<usize> = decisions[..at].iter().map(|d| d.chosen).collect();
                prefix.push(option);
                return Some(prefix);
            }
        }
    }
    None
}

struct Buffered {
    index: usize,
    value: u32,
    boot: bool,
    /// Issue order.
    seq: u64,
}

struct World<'a> {
    scn: &'a Scenario,
    consumer: Consumer,
    sched: Sched,
    mem: Vec<u32>,
    buffer: Vec<Buffered>,
    issued: u64,
    /// The last write committed in the current run of commits.
    last_commit: Option<u64>,
    sp: Sp,
    deliveries: Vec<(Class, [u32; 3])>,
    booting: bool,
    boot_started: bool,
    overlapped: bool,
    /// A drain that overlapped the boot reset ended, and the device is
    /// resetting: no drain starts until CP1 boots again.
    resetting: bool,
    rebooted: bool,
    /// Most SP accesses while a boot-reset write is buffered; `None`: no limit.
    reset_window: Option<u32>,
    reset_window_used: u32,
    /// A drain doesn't start while a boot-reset write is buffered.
    wait_for_reset: bool,
    error: Option<String>,
}

impl<'a> World<'a> {
    fn new(scn: &'a Scenario, consumer: Consumer, prefix: Vec<usize>) -> Self {
        let mut mem = vec![0; record_word(N, 0)];
        mem[SIZE] = scn.size;
        mem[HEAD] = scn.head;
        mem[TAIL] = scn.tail;
        mem[OVERFLOWS] = scn.overflows;
        for (slot, words) in (0..).zip(scn.slots) {
            for (field, word) in (0..).zip(words) {
                mem[record_word(slot, field)] = word;
            }
        }
        Self {
            scn,
            consumer,
            sched: Sched {
                prefix,
                decisions: Vec::new(),
                current: Actor::Cp1,
                preemptions: 0,
            },
            mem,
            buffer: Vec::new(),
            issued: 0,
            last_commit: None,
            sp: Sp {
                state: SpState::Idle,
                class: Class::Clean,
                started: 0,
                head: 0,
                tail: 0,
                size: 0,
                got: [0; 5],
                reported_baseline: if scn.boot { 0 } else { scn.overflows },
                reported: None,
            },
            deliveries: Vec::new(),
            booting: false,
            boot_started: false,
            overlapped: false,
            resetting: false,
            rebooted: false,
            reset_window: None,
            reset_window_used: 0,
            wait_for_reset: true,
            error: None,
        }
    }

    fn fail(&mut self, error: String) {
        self.error.get_or_insert(error);
    }

    fn sp_can_step(&self, finishing: bool) -> bool {
        let boot_buffered = self.buffer.iter().any(|b| b.boot);
        if boot_buffered
            && self
                .reset_window
                .is_some_and(|window| self.reset_window_used >= window)
        {
            return false;
        }
        if self.sp.state != SpState::Idle {
            return true;
        }
        self.sp.started < self.scn.drains
            && !self.resetting
            && !(self.wait_for_reset && boot_buffered)
            && !(finishing && self.buffer.is_empty())
    }

    fn options(&self, cp1: bool, finishing: bool) -> Vec<Event> {
        let mut options = Vec::new();
        if cp1 {
            options.push(Event::Cp1);
        }
        // Commits of different words commute, so a run of commits with
        // nothing between them takes them in issue order; it can still
        // skip any of them. When nothing else can run, no one can see the
        // order, except that a buffered boot-reset write can keep drains
        // from starting: so the oldest write, or the oldest boot-reset
        // write, commits next.
        let after = match self.sched.current {
            Actor::Buffer => self.last_commit,
            _ => None,
        };
        let eligible: Vec<(usize, u64)> = (0..self.buffer.len())
            .filter(|&at| {
                // Writes to one word become visible in order.
                let index = self.buffer[at].index;
                !self.buffer[..at].iter().any(|b| b.index == index)
            })
            .map(|at| (at, self.buffer[at].seq))
            .collect();
        let sp = self.sp_can_step(finishing);
        let commits: Vec<(usize, u64)> = if cp1 || sp {
            eligible
                .iter()
                .copied()
                .filter(|&(_, seq)| after.is_none_or(|last| seq > last))
                .collect()
        } else {
            // CP1 issues boot-reset writes before any other write, and a
            // reboot commits every older write first.
            let first_other = self.buffer.iter().position(|b| !b.boot);
            assert!(
                first_other.is_none_or(|first| self.buffer[first..].iter().all(|b| !b.boot)),
                "a boot-reset write follows another buffered write"
            );
            let oldest = eligible.first().copied();
            let oldest_boot = eligible
                .iter()
                .copied()
                .find(|&(at, _)| self.buffer[at].boot);
            let mut commits: Vec<(usize, u64)> = oldest.into_iter().collect();
            if oldest_boot != oldest {
                commits.extend(oldest_boot);
            }
            commits
        };
        options.extend(commits.into_iter().map(|(at, _)| Event::Commit(at)));
        if sp {
            options.push(Event::Sp);
        }
        options
    }

    fn perform(&mut self, event: Event) {
        match event {
            Event::Cp1 => unreachable!("CP1 runs in its own steps"),
            Event::Commit(at) => {
                let buffered = self.buffer.remove(at);
                self.mem[buffered.index] = buffered.value;
                self.last_commit = Some(buffered.seq);
            }
            Event::Sp => {
                if self.buffer.iter().any(|b| b.boot) {
                    self.reset_window_used += 1;
                }
                self.sp_step();
            }
        }
    }

    /// CP1 is about to load: the other sides may run first.
    fn cp1_yield(&mut self) {
        loop {
            let options = self.options(true, false);
            match self.sched.choose(options) {
                Event::Cp1 => return,
                event => self.perform(event),
            }
        }
    }

    fn cp1_load(&self, index: usize) -> u32 {
        self.buffer
            .iter()
            .rev()
            .find(|b| b.index == index)
            .map_or(self.mem[index], |b| b.value)
    }

    fn cp1_store(&mut self, index: usize, value: u32) {
        if self.booting && !self.boot_started {
            self.boot_started = true;
            if self.sp.state != SpState::Idle {
                self.sp.class = Class::Overlap;
                self.overlapped = true;
            }
        }
        self.issued += 1;
        self.buffer.push(Buffered {
            index,
            value,
            boot: self.booting,
            seq: self.issued,
        });
    }

    fn cp1_barrier(&mut self) {
        while !self.buffer.is_empty() {
            let options = self.options(false, false);
            let event = self.sched.choose(options);
            self.perform(event);
        }
    }

    /// CP1 is done: the other sides run until the buffer is empty and the
    /// SP is idle.
    fn finish(&mut self) {
        loop {
            let options = self.options(false, true);
            if options.is_empty() {
                return;
            }
            let event = self.sched.choose(options);
            self.perform(event);
        }
    }

    /// The device resets: CP1's buffered writes complete, and CP1 boots
    /// again.
    fn reboot(&mut self) {
        for buffered in std::mem::take(&mut self.buffer) {
            self.mem[buffered.index] = buffered.value;
        }
        self.resetting = false;
        self.rebooted = true;
    }

    fn end_drain(&mut self) {
        self.sp.state = SpState::Idle;
        if self.scn.reboot && self.sp.class == Class::Overlap {
            self.resetting = true;
        }
    }

    /// One more drain, alone, which empties the ring.
    fn final_drain(&mut self) {
        self.sp.class = Class::Clean;
        self.sp.state = SpState::Check(0);
        while self.sp.state != SpState::Idle {
            self.sp_step();
        }
    }

    fn sp_step(&mut self) {
        loop {
            match self.sp.state {
                SpState::Idle => {
                    self.sp.started += 1;
                    self.sp.class = if self.scn.boot && !self.boot_started {
                        Class::BeforeBoot
                    } else {
                        Class::Clean
                    };
                    self.sp.state = SpState::Check(0);
                }
                SpState::Check(0) => {
                    self.sp.head = self.mem[HEAD];
                    self.sp.state = SpState::Check(1);
                    return;
                }
                SpState::Check(1) => {
                    self.sp.tail = self.mem[TAIL];
                    self.sp.state = SpState::Check(2);
                    return;
                }
                SpState::Check(_) => {
                    self.sp.size = self.mem[SIZE];
                    if self.sp.valid(self.consumer) {
                        self.sp.state = SpState::Loop(0);
                    } else {
                        self.end_drain();
                    }
                    return;
                }
                SpState::Loop(at) => {
                    let steps = self.consumer.steps();
                    self.sp.state = SpState::Loop((at + 1) % steps.len());
                    match steps[at] {
                        Op::LoadHead => {
                            self.sp.head = self.mem[HEAD];
                            return;
                        }
                        Op::LoadTail => {
                            self.sp.tail = self.mem[TAIL];
                            return;
                        }
                        Op::LoadSize => {
                            self.sp.size = self.mem[SIZE];
                            return;
                        }
                        Op::Check => {
                            if !self.sp.valid(self.consumer) || self.sp.head == self.sp.tail {
                                self.sp.state = SpState::Overflows;
                            }
                        }
                        Op::CheckHead => {
                            if self.sp.head >= N {
                                self.sp.state = SpState::Overflows;
                            }
                        }
                        Op::Read(k) => {
                            if self.sp.head >= N {
                                self.fail(format!("the SP read slot {}", self.sp.head));
                                self.end_drain();
                                return;
                            }
                            let slot = self.sp.head;
                            self.sp.got[usize::from(k)] = match k {
                                0..=2 => (self.mem[record_word(slot, 0)] >> (8 * k)) & 0xFF,
                                3 => self.mem[record_word(slot, 1)],
                                _ => self.mem[record_word(slot, 2)],
                            };
                            return;
                        }
                        Op::StoreHead => {
                            self.mem[HEAD] = if self.sp.head + 1 == self.sp.size {
                                0
                            } else {
                                self.sp.head + 1
                            };
                            return;
                        }
                        Op::Deliver => {
                            let got = self.sp.got;
                            let desc = got[0] | (got[1] << 8) | (got[2] << 16);
                            self.deliveries
                                .push((self.sp.class, [desc, got[3], got[4]]));
                        }
                    }
                }
                SpState::Overflows => {
                    let overflows = self.mem[OVERFLOWS];
                    if overflows > self.sp.reported_baseline {
                        self.sp.reported_baseline = overflows;
                        self.sp.reported = Some(overflows);
                    }
                    self.end_drain();
                    return;
                }
            }
        }
    }
}

/// CP1's view of the model's memory.
struct Cp1<'w, 'a> {
    world: &'w mut World<'a>,
}

impl Cp1<'_, '_> {
    fn index(&mut self, word: Word) -> usize {
        match word {
            Word::BufferSize => SIZE,
            Word::Head => HEAD,
            Word::Tail => TAIL,
            Word::Overflows => OVERFLOWS,
            Word::Record(slot, field) => {
                if slot.index() >= N {
                    self.world
                        .fail(format!("CP1 accessed slot {}", slot.index()));
                }
                record_word(slot.index() % N, field.index())
            }
        }
    }
}

impl RingMemory for Cp1<'_, '_> {
    const SLOTS: u32 = N;

    fn read(&mut self, word: Word) -> u32 {
        let index = self.index(word);
        self.world.cp1_yield();
        self.world.cp1_load(index)
    }

    fn write(&mut self, word: Word, value: u32) {
        let index = self.index(word);
        self.world.cp1_store(index, value);
    }

    fn barrier(&mut self) {
        self.world.cp1_barrier();
    }
}

/// Memory that ignores every access; it makes a sink ready without a ring.
struct Null;

impl RingMemory for Null {
    const SLOTS: u32 = N;

    fn read(&mut self, _word: Word) -> u32 {
        0
    }

    fn write(&mut self, _word: Word, _value: u32) {}

    fn barrier(&mut self) {}
}

/// A mutant of the crate's write steps.
fn mutant_write<M: RingMemory>(producer: Producer, mem: &mut M, record: [u32; 3]) -> Outcome {
    let head = Slot::checked(mem.read(Word::Head), M::SLOTS);
    let tail = Slot::checked(mem.read(Word::Tail), M::SLOTS);
    let (Some(head), Some(tail)) = (head, tail) else {
        return Outcome::BadIndex;
    };
    let next = tail.next(M::SLOTS);
    if next == head && producer != Producer::NoFullCheck {
        let overflows = mem.read(Word::Overflows);
        mem.write(Word::Overflows, overflows.saturating_add(1));
        return Outcome::Full;
    }
    if producer == Producer::TailFirst {
        mem.write(Word::Tail, next.index());
        mem.barrier();
    }
    mem.write(Word::Record(tail, Field::Descriptor), record[0]);
    mem.write(Word::Record(tail, Field::Value1), record[1]);
    mem.write(Word::Record(tail, Field::Value2), record[2]);
    match producer {
        Producer::TailFirst => {}
        Producer::NoBarrier => mem.write(Word::Tail, next.index()),
        Producer::Crate | Producer::NoFullCheck => {
            mem.barrier();
            mem.write(Word::Tail, next.index());
        }
    }
    Outcome::Written
}

/// What one schedule did.
struct Run {
    /// Each record's outcome, and whether CP1 wrote it after a reboot.
    outcomes: Vec<(bool, Outcome)>,
    deliveries: Vec<(Class, [u32; 3])>,
    overflows: u32,
    reported: Option<u32>,
    drops: Drops,
    overlapped: bool,
    rebooted: bool,
    error: Option<String>,
}

/// The properties a search checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Properties {
    All,
    /// Only that every access stays in the ring.
    InBounds,
}

/// What a search runs.
#[derive(Clone, Copy, Debug)]
struct Config {
    producer: Producer,
    consumer: Consumer,
    properties: Properties,
    reset_window: Option<u32>,
    /// A drain doesn't start while a boot-reset write is buffered.
    wait_for_reset: bool,
    /// Preemptions per schedule.
    preemptions: u32,
}

impl Config {
    const CRATE: Config = Config {
        producer: Producer::Crate,
        consumer: Consumer::Drain,
        properties: Properties::All,
        reset_window: None,
        wait_for_reset: true,
        preemptions: 2,
    };

    /// Only the in-bounds property, with no timing condition: drains start
    /// while boot-reset writes are buffered, and run with no limit.
    const IN_BOUNDS: Config = Config {
        properties: Properties::InBounds,
        wait_for_reset: false,
        ..Config::CRATE
    };
}

fn boot(sink: &Sink, world: &mut World<'_>) {
    world.booting = true;
    sink.boot_reset(&mut Cp1 { world });
    world.booting = false;
}

fn run_once(scn: &Scenario, cfg: &Config, prefix: Vec<usize>) -> (Run, Vec<Decision>) {
    let mut world = World::new(scn, cfg.consumer, prefix);
    world.reset_window = cfg.reset_window;
    world.wait_for_reset = cfg.wait_for_reset;
    let mut sink = Sink::new();
    if !scn.boot {
        sink.boot_reset(&mut Null);
    }
    let mut outcomes = Vec::new();
    critical_section::with(|cs| {
        if scn.boot {
            world.cp1_yield();
            boot(&sink, &mut world);
        }
        for n in 1..=scn.records {
            if world.resetting {
                world.reboot();
                sink = Sink::new();
                boot(&sink, &mut world);
            }
            let [desc, value1, value2] = record(n);
            let rebooted = world.rebooted;
            let mut mem = Cp1 { world: &mut world };
            let outcome = match cfg.producer {
                Producer::Crate => sink.write(cs, &mut mem, desc, value1, value2),
                mutant => mutant_write(mutant, &mut mem, [desc, value1, value2]),
            };
            outcomes.push((rebooted, outcome));
        }
    });
    world.finish();
    if world.resetting {
        world.reboot();
        sink = Sink::new();
        boot(&sink, &mut world);
        world.finish();
    }
    world.final_drain();
    let run = Run {
        outcomes,
        deliveries: world.deliveries,
        overflows: world.mem[OVERFLOWS],
        reported: world.sp.reported,
        drops: sink.drops(),
        overlapped: world.overlapped,
        rebooted: world.rebooted,
        error: world.error,
    };
    (run, world.sched.decisions)
}
/// Checks one schedule against the properties.
fn check(scn: &Scenario, run: &Run, properties: Properties) -> Result<(), String> {
    if let Some(error) = &run.error {
        return Err(error.clone());
    }
    if properties == Properties::InBounds {
        return Ok(());
    }
    if run.drops != Drops::default() {
        return Err(format!("RAM drops {:?}", run.drops));
    }
    // After a reboot, only the records written since then count.
    let mut published = Vec::new();
    let mut full = 0;
    for (n, &(rebooted, outcome)) in (1..).zip(&run.outcomes) {
        if rebooted != run.rebooted {
            continue;
        }
        match outcome {
            Outcome::Written => published.push(n),
            Outcome::Full => full += 1,
            other => return Err(format!("record {n}: {other:?}")),
        }
    }
    let first_overflows = if scn.boot { 0 } else { scn.overflows };
    if run.overflows != first_overflows + full {
        return Err(format!(
            "overflows is {}, but {full} records found the ring full",
            run.overflows
        ));
    }
    let delivered = |class: Option<Class>| -> Vec<Option<u32>> {
        run.deliveries
            .iter()
            .filter(|(c, _)| class.is_none_or(|class| *c == class))
            .map(|(_, words)| number(*words))
            .collect()
    };

    if !scn.boot {
        // Old records, then the published ones: each once, in order, whole.
        let expected: Vec<Option<u32>> = scn
            .old_records()
            .into_iter()
            .chain(published.iter().copied())
            .map(Some)
            .collect();
        let got = delivered(None);
        if got != expected {
            return Err(format!("delivered {got:?}, expected {expected:?}"));
        }
        let report = (full > 0).then_some(first_overflows + full);
        if run.reported != report {
            return Err(format!(
                "the SP reported overflows {:?}, expected {report:?}",
                run.reported
            ));
        }
        return Ok(());
    }

    // A drain that ended before the boot reset reads only old records.
    let before = delivered(Some(Class::BeforeBoot));
    let old: Vec<Option<u32>> = scn.old_records().into_iter().map(Some).collect();
    if !old.starts_with(&before) {
        return Err(format!(
            "before the boot: delivered {before:?}, old {old:?}"
        ));
    }
    // A drain that overlaps the boot reset may read stale or partial
    // records. Every later drain reads whole published records, each once,
    // in order: after a reboot, all of them; otherwise, the last of them at
    // least, and all of them if no drain overlapped the boot reset.
    let clean = delivered(Some(Class::Clean));
    let Some(clean) = clean.into_iter().collect::<Option<Vec<u32>>>() else {
        return Err(format!(
            "a drain after the boot read a partial or stale record: {:?}",
            delivered(Some(Class::Clean))
        ));
    };
    let all_arrive = run.rebooted || !run.overlapped;
    if !published.ends_with(&clean) || (all_arrive && clean != published) {
        return Err(format!(
            "after the boot: delivered {clean:?}, published {published:?}"
        ));
    }
    if scn.power_on() {
        // A cleared ring holds nothing stale: every drain reads only the
        // published records.
        let all = delivered(None);
        let expected: Vec<Option<u32>> = published.iter().copied().map(Some).collect();
        if all != expected {
            return Err(format!(
                "after power-on: delivered {all:?}, published {expected:?}"
            ));
        }
    }
    Ok(())
}

/// Searches every schedule with up to `cfg.preemptions` preemptions. Returns
/// the number of schedules, or the first property that failed and its
/// schedule.
fn explore(scn: &Scenario, cfg: &Config) -> Result<u64, String> {
    let mut prefix = Vec::new();
    let mut schedules = 0;
    loop {
        schedules += 1;
        assert!(schedules <= MAX_SCHEDULES, "the search didn't end");
        let (run, decisions) = run_once(scn, cfg, prefix);
        if let Err(error) = check(scn, &run, cfg.properties) {
            let schedule: Vec<Event> = decisions.iter().map(|d| d.options[d.chosen]).collect();
            return Err(format!(
                "{error}; after {schedules} schedules; schedule {schedule:?}"
            ));
        }
        match next_prefix(&decisions, cfg.preemptions) {
            Some(next) => prefix = next,
            None => return Ok(schedules),
        }
    }
}

fn holds(scn: &Scenario, cfg: &Config) {
    match explore(scn, cfg) {
        Ok(schedules) => println!("held: {schedules} schedules"),
        Err(error) => panic!("{error}"),
    }
}

fn fails(scn: &Scenario, cfg: &Config) {
    match explore(scn, cfg) {
        Ok(schedules) => panic!("passed {schedules} schedules, but must fail"),
        Err(error) => println!("caught: {error}"),
    }
}

fn with_producer(producer: Producer) -> Config {
    Config {
        producer,
        ..Config::CRATE
    }
}

fn with_consumer(consumer: Consumer) -> Config {
    Config {
        consumer,
        ..Config::CRATE
    }
}

#[test]
fn writes_into_a_ring_with_room() {
    holds(&room(), &Config::CRATE);
}

#[test]
fn writes_into_a_full_ring() {
    holds(&full(), &Config::CRATE);
}

#[test]
fn writes_after_a_warm_boot() {
    holds(&warm_boot(), &Config::CRATE);
}

#[test]
fn writes_after_a_power_on_boot() {
    holds(&power_on(), &Config::CRATE);
}

/// Without the device reset that follows a drain that overlaps the boot
/// reset, a later drain can read stale records. The overlapping drain loads
/// the reset's `head` and the old `tail`, stores a stale `head`, reloads the
/// old `tail`, and ends; then the reset's `tail` write lands, and the ring
/// looks like it holds old slots. The margin: if every boot-reset write
/// becomes visible within two SP accesses, no drain spills; with three, one
/// can (`spill_needs_three_sp_accesses`).
#[test]
fn without_the_device_reset_a_later_drain_reads_stale_records() {
    fails(&spill(), &Config::CRATE);
}

/// The index checks keep every access in the ring with no timing condition:
/// without the device reset, and with drains that start while boot-reset
/// writes are still buffered. This is the warm boot that shows the
/// stale-record spill.
#[test]
fn every_access_stays_in_the_ring_after_a_warm_boot() {
    holds(&spill(), &Config::IN_BOUNDS);
}

#[test]
fn every_access_stays_in_the_ring_after_an_uncleared_boot() {
    holds(&uncleared(), &Config::IN_BOUNDS);
}

/// The margin of the stale-record spill: if every boot-reset write becomes
/// visible within two SP accesses, no drain spills; with three, one can.
#[test]
fn spill_needs_three_sp_accesses() {
    let window = |reset_window| Config {
        reset_window: Some(reset_window),
        ..Config::CRATE
    };
    holds(&warm_boot_without_reboot(), &window(2));
    fails(&warm_boot_without_reboot(), &window(3));
}

#[test]
fn mutant_that_moves_tail_first_fails() {
    fails(&room(), &with_producer(Producer::TailFirst));
}

#[test]
fn mutant_without_a_barrier_fails() {
    fails(&room(), &with_producer(Producer::NoBarrier));
}

#[test]
fn mutant_without_the_full_check_fails() {
    fails(&full(), &with_producer(Producer::NoFullCheck));
}

#[test]
fn mutant_that_reads_the_record_before_tail_fails() {
    fails(&room(), &with_consumer(Consumer::RecordBeforeTail));
}

#[test]
fn mutant_without_the_size_check_fails() {
    let cfg = Config {
        consumer: Consumer::NoSizeCheck,
        ..Config::IN_BOUNDS
    };
    fails(&uncleared(), &cfg);
}

/// Moving `head` before reading the record is safe in this ring. While the
/// SP reads slot `h` with `head` already at `h + 1`, slot `h` is the empty
/// slot, which CP1 never writes: writing it would need `next(h) != head`.
#[test]
fn moving_head_before_the_read_is_safe() {
    holds(&room(), &with_consumer(Consumer::HeadFirst));
    holds(&full(), &with_consumer(Consumer::HeadFirst));
}

/// The searches that must hold, with three preemptions instead of two.
#[test]
#[ignore = "takes about two minutes"]
fn every_property_holds_with_three_preemptions() {
    let deeper = |cfg: Config| Config {
        preemptions: 3,
        ..cfg
    };
    let crate_steps = deeper(Config::CRATE);
    holds(&room(), &crate_steps);
    holds(&full(), &crate_steps);
    holds(&warm_boot(), &crate_steps);
    holds(&power_on(), &crate_steps);
    let window = Config {
        reset_window: Some(2),
        ..crate_steps
    };
    holds(&warm_boot_without_reboot(), &window);
    let head_first = deeper(with_consumer(Consumer::HeadFirst));
    holds(&room(), &head_first);
    holds(&full(), &head_first);
}

/// The in-bounds searches, with three preemptions instead of two.
#[test]
#[ignore = "takes about two and a half minutes"]
fn every_access_stays_in_the_ring_with_three_preemptions() {
    let cfg = Config {
        preemptions: 3,
        ..Config::IN_BOUNDS
    };
    holds(&spill(), &cfg);
    holds(&uncleared(), &cfg);
}
