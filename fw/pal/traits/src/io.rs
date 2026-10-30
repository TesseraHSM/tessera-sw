// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! I/O controller and per-IO traits for the HSM platform abstraction
//! layer.
//!
//! Defines the shared IO type and the traits the core uses to receive
//! and complete host commands:
//!
//! - [`HsmIoTypes`] — the platform's IO type, shared by PAL capabilities
//!   without requiring controller operations.
//! - [`HsmIoController`] — the platform's I/O fabric.  Drives the
//!   submission/completion queue lifecycle and produces individual
//!   [`HsmIo`] handles.
//! - [`HsmIo`] — a single in-flight command: borrows of its SQE/CQE.
//!   Partition binding, queue routing, and resource-slot management stay
//!   private to each platform.
//!
//! ## SQE / CQE layout
//!
//! Submission and completion queue entries are dword slices with
//! platform-defined lengths and contents. This crate exposes only
//! the raw views ([`HsmSqe`], [`HsmCqe`]); supported sizes and field
//! layouts belong to the protocol codec (`tsra_fw_hsm_io`).
//!
//! ## Pipeline
//!
//! ```text
//! poll_io().await        — receive next request
//!   ↓
//! io.sqe() / io.cqe()    — decode SQE, populate CQE
//! PAL operations         — resolve partition from private IO context
//!   ↓
//! complete_io(io).await  — emit CQE; or
//! drop_io(io).await      — silently discard (e.g. disabled partition)
//! ```

use super::*;

/// A submission queue entry as a raw dword slice.
///
/// Length and layout are platform-defined and validated by the protocol codec.
pub type HsmSqe = [u32];

/// A completion queue entry as a raw dword slice.
///
/// Length and layout are platform-defined and validated by the protocol codec.
pub type HsmCqe = [u32];

/// Handle to a single in-flight I/O.
///
/// Represents a submission/completion pair: the caller reads the
/// submission queue entry via [`sqe`](Self::sqe) to determine the
/// requested operation and writes the result into the completion
/// queue entry via [`cqe`](Self::cqe). Partition binding, queue routing,
/// and per-IO allocator slots are private platform state.
///
/// `HsmIo` is `Send` (via [`HsmIoTypes::Io`]) so an IO can be
/// moved between Embassy executor tasks during processing.  It is
/// **not** `Sync`: each IO is owned by exactly one task at a time.
///
/// The handle is consumed by exactly one of
/// [`HsmIoController::complete_io`] or
/// [`HsmIoController::drop_io`]; failing to do so leaks the
/// underlying queue slot.
pub trait HsmIo {
    /// Borrows the submission queue entry.
    ///
    /// The SQE is read-only from the firmware's perspective: the
    /// host populated it before raising the doorbell that triggered
    /// [`HsmIoController::poll_io`].
    ///
    /// # Returns
    ///
    /// An immutable reference to the [`HsmSqe`] dword slice. Borrow
    /// lives for the duration of the `&self` borrow.
    fn sqe(&self) -> &HsmSqe;

    /// Borrows the completion queue entry for in-place population.
    ///
    /// The firmware writes the status word, response length, and any
    /// session-control fields here before calling
    /// [`HsmIoController::complete_io`].  Contents prior to that
    /// call are unspecified; callers must overwrite, not read.
    ///
    /// # Returns
    ///
    /// A mutable reference to the [`HsmCqe`] dword slice. Borrow
    /// lives for the duration of the `&mut self` borrow.
    fn cqe(&mut self) -> &mut HsmCqe;
}

/// Shared IO type for platform capabilities.
///
/// Each platform declares its IO type once. Allocator, crypto, and state
/// traits use this type without requiring queue lifecycle operations;
/// only [`HsmPal`] combines them with [`HsmIoController`].
///
/// Capability bounds alone do not provide controller operations:
///
/// ```compile_fail,E0599
/// use tsra_fw_hsm_pal_traits::{HsmAlloc, HsmHash, HsmIoController};
///
/// async fn poll_from_capabilities<P: HsmAlloc + HsmHash>(pal: &P) {
///     let _ = pal.poll_io().await;
/// }
/// ```
pub trait HsmIoTypes {
    /// Platform-specific IO type.
    ///
    /// Bound to be `Send` so that the core can move IOs across
    /// Embassy executor tasks during async processing.
    type Io: HsmIo + Send;
}

/// Asynchronous I/O controller that produces and completes IOs.
///
/// Implementations own the platform's submission/completion queue
/// pair (or pairs): IPC mailboxes on Uno, in-process channels for
/// the std PAL emulator.  The controller is consumed by the core's
/// main loop, which calls [`poll_io`](Self::poll_io) in an
/// `async` fashion and dispatches each returned [`HsmIo`] to the
/// command pipeline.
///
/// Lifecycle invariant: every IO returned by
/// [`poll_io`](Self::poll_io) must eventually be passed to either
/// [`complete_io`](Self::complete_io) or
/// [`drop_io`](Self::drop_io) — dropping the IO without either call
/// leaks the underlying queue slot.
pub trait HsmIoController: HsmIoTypes {
    /// Awaits the next IO from any submission queue.
    ///
    /// Yields until at least one queue has a pending entry, then
    /// returns the corresponding [`Self::Io`](HsmIoTypes::Io) handle.
    ///
    /// # Returns
    ///
    /// - `Ok(io)` — a fresh in-flight IO ready for processing.
    /// - `Err(HsmError)` — fatal queue error (controller is no
    ///   longer usable; the main loop should treat this as
    ///   unrecoverable).
    async fn poll_io(&self) -> HsmResult<Self::Io>;

    /// Posts the completion entry (CQE) for `io` to the host.
    ///
    /// Borrows `io` by `&mut` and leaves its queue slot **allocated**, so
    /// the caller can run post-completion work — e.g. an undo/commit walk
    /// that DMAs through `io` — before releasing the slot with
    /// [`drop_io`](Self::drop_io).  Callers must have written the desired
    /// CQE contents via [`HsmIo::cqe`] before invoking this method.
    /// The platform fills transport-specific fields, such as the source
    /// queue identifier, before posting the completion to the host.
    ///
    /// # Parameters
    ///
    /// - `io` — handle previously returned by
    ///   [`poll_io`](Self::poll_io).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — completion was successfully posted.
    /// - `Err(HsmError)` — failed to enqueue the CQE; the host will not
    ///   see this completion.  The slot is still owned and must be freed
    ///   via [`drop_io`](Self::drop_io).
    async fn complete_io(&self, io: &mut Self::Io) -> HsmResult<()>;

    /// Frees the queue slot, releasing `io`.
    ///
    /// Posts no CQE of its own.  Called either to silently discard an IO
    /// — for example one that arrived for a
    /// non-[`HsmPartState::Enabled`](crate::HsmPartState::Enabled) partition and
    /// core wants to drop without surfacing anything to the host — or to
    /// release the slot after [`complete_io`](Self::complete_io) has
    /// already posted the completion.
    ///
    /// # Parameters
    ///
    /// - `io` — handle previously returned by
    ///   [`poll_io`](Self::poll_io).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — slot was freed.
    /// - `Err(HsmError)` — slot release failed (logged by core; the
    ///   IO is no longer accessible regardless).
    async fn drop_io(&self, io: Self::Io) -> HsmResult<()>;
}
