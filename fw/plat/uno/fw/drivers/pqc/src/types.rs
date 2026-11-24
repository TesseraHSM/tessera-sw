// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core types for the PQC engine pool.

/// Number of fastpath cores serving PQC requests (FP0, FP1, FP2).
pub const CORES: usize = 3;

/// Number of PQC engines: two request lanes per fastpath core.
///
/// Each lane is a mailbox and operand slot of its own, and a core serves
/// its two in the order they were posted. So while it works on one lane's
/// request the HSM can stage and post the next on the other, and the core
/// moves straight on to it instead of idling while the HSM notices the
/// answer, reads it back and stages another -- 7-11% of its time under a
/// stream of ML-DSA signatures.
///
/// Engine `n` is lane `n / CORES` of core `n % CORES`: engines 0-2 are the
/// lanes in PSRAM, 3-5 the ones in the cores' shares of the GSRAM window
/// the SP fences to them (see `mailbox`).
pub const ENGINES: usize = 2 * CORES;

/// Depth of the FIFO queue of tasks waiting for a free engine.
///
/// Must be a power of two, and must be at least as large as the number of
/// host IO slots: CP1 spawns a `handle_io` task per inbound command from a
/// 33-slot pool (32 host + 1 admin), so up to 32 tasks can be waiting on an
/// engine at once. Anything smaller and a busy host gets `QUEUE_FULL`
/// rejections rather than backpressure.
///
/// This was 4, on the assumption that four was "comfortably above the
/// number of IO slots that can be mid-PQC-operation at once". It is not:
/// with 3 engines that capped concurrency at 7, and a 32-stream client saw
/// 25 of its requests rejected outright.
///
/// Each slot is a waker plus a state word, so the whole queue is a few
/// hundred bytes on a core that has memory to spare — unlike FP.
pub const QUEUE_DEPTH: usize = 32;

/// `QUEUE_DEPTH` must be a power of two (the ring arithmetic depends on it)
/// and must cover every host IO slot that could be waiting at once.
const _: () = assert!(QUEUE_DEPTH.is_power_of_two());
const _: () = assert!(
    QUEUE_DEPTH as u32 >= tsra_fw_uno_reg_soc::io_gsram::IO_SQ_COUNT,
    "PQC waiter queue is smaller than the host IO slot count; a busy host \
     would see QUEUE_FULL instead of backpressure"
);

/// Identifies one PQC engine, i.e. one request lane of an FP core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineId(u8);

impl EngineId {
    /// Wrap a raw engine index.
    ///
    /// # Panics
    /// Panics if `id` is not a valid engine index.  Callers that cannot
    /// guarantee that should use [`EngineId::try_new`].
    pub const fn new(id: u8) -> Self {
        assert!((id as usize) < ENGINES, "engine id out of range");
        Self(id)
    }

    /// Wrap a raw engine index, returning `None` if out of range.
    pub const fn try_new(id: u8) -> Option<Self> {
        if (id as usize) < ENGINES {
            Some(Self(id))
        } else {
            None
        }
    }

    /// The raw engine index.
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// The FP core this engine is a lane of.
    pub const fn core(self) -> u8 {
        self.0 % CORES as u8
    }

    /// The IPC pair index carrying this engine's core's traffic.
    ///
    /// Pairs 0 and 1 are the Admin↔HSM message and event channels, so the
    /// three HSM↔FP pairs follow them.
    pub const fn ipc_pair(self) -> u8 {
        FIRST_FP_IPC_PAIR + self.core()
    }

    /// Descriptor the HSM rings to notify this engine's FP core.
    pub const fn outbound_desc(self) -> u8 {
        FIRST_FP_DESC + self.core() * 2
    }

    /// Descriptor this engine's FP core rings to notify the HSM.
    pub const fn inbound_desc(self) -> u8 {
        FIRST_FP_DESC + self.core() * 2 + 1
    }
}

/// IPC pair index of the HSM↔FP0 pair.  Pairs 0 and 1 belong to the
/// Admin↔HSM message and event channels.
pub const FIRST_FP_IPC_PAIR: u8 = 2;

/// First IPC descriptor reserved for HSM↔FP traffic.
///
/// Descriptors 2–7 are free and carry the three pairs, two descriptors
/// each: FP0 uses 2/3, FP1 uses 4/5, FP2 uses 6/7.  (Admin↔HSM uses the
/// high descriptors 28–31.)
pub const FIRST_FP_DESC: u8 = 2;

/// Lifecycle state of one engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    /// Not assigned to any task.
    Idle,

    /// Assigned to a task, which may or may not have work in flight.
    Busy,

    /// Released while request `seq` may still be running on the core: a
    /// timeout or a cancelled future let go of it before the answer
    /// arrived. Withheld from the pool until the core answers, so a new
    /// request cannot overwrite operands it is still reading or receive its
    /// late output, then scrubbed before reuse.
    Draining(u32),
}

/// Lifecycle state of one queue slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueSlotState {
    /// Unused.
    Free,

    /// A task is waiting for any engine.
    Pending,

    /// An engine has been handed to the waiting task, which has not yet
    /// woken to collect it.
    Assigned(EngineId),
}
