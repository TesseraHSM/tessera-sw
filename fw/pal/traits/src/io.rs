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
//! Submission and completion queue entry layouts are platform-defined.
//! The core sees them only through [`HsmSqe`] (opcode and session fields)
//! and [`HsmCqe`] (the outcome); request and response transfers go
//! through [`HsmIoController`].
//!
//! ## Pipeline
//!
//! ```text
//! poll_io().await        — receive next request
//!   ↓
//! recv_request(io)       — validate SQE, fetch request
//! PAL operations         — resolve partition from private IO context
//! io.cqe().set_ok_ex(..) — record outcome
//! send_response(io, ..)  — return response
//!   ↓
//! complete_io(io).await  — emit CQE; or
//! drop_io(io).await      — silently discard (e.g. disabled partition)
//! ```

use super::*;

/// Session-control kind of a command, as its SQE declares it and its CQE
/// reports it back.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HsmSessCtrl {
    /// The IO protocol does not declare session control in its SQE.
    Unspecified,

    /// No session is involved.
    #[default]
    NoSession,

    /// Opens a new session.
    Open,

    /// Runs within an existing session.
    InSession,

    /// Closes an existing session.
    Close,
}

/// Session fields of a successful completion
/// ([`HsmCqe::set_ok_ex`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HsmCqeSession {
    /// Session control of the completed command.
    pub ctrl: HsmSessCtrl,

    /// Session the command opened or closed.
    pub id: Option<u16>,

    /// Application vault of an opened session.
    pub vault_id: Option<u8>,

    /// Whether the command closed the session.
    pub closed: bool,
}

/// A submission queue entry.
///
/// Layout is platform-defined; the core reads only the fields below.
pub trait HsmSqe {
    /// Returns the raw command opcode.
    fn opcode(&self) -> u16;

    /// Returns the session the SQE names, if any.
    fn session_id(&self) -> Option<u16>;

    /// Returns the session control the SQE declares;
    /// [`Unspecified`](HsmSessCtrl::Unspecified) if the IO protocol has none.
    fn session_ctrl(&self) -> HsmSessCtrl;
}

/// A completion queue entry.
///
/// Layout is platform-defined. The platform fills identity and routing
/// fields (command id, queue id); the core writes only the outcome.
pub trait HsmCqe {
    /// Records a success with a `dst_len`-byte response.
    fn set_ok(&mut self, dst_len: u32);

    /// Records a success with a `dst_len`-byte response and its session
    /// fields. Protocols without CQE session fields ignore `sess`.
    fn set_ok_ex(&mut self, dst_len: u32, sess: HsmCqeSession);

    /// Records a failure; the entry maps `err` to its wire status.
    fn set_err(&mut self, err: HsmError);
}

/// A request received by [`HsmIoController::recv_request`].
pub struct HsmRequest<'a> {
    /// Exchange storage holding the request in its first
    /// [`len`](Self::len) bytes; growable with
    /// [`HsmAlloc::dma_grow`](crate::HsmAlloc::dma_grow).
    pub buf: HsmDmaAllocation<'a>,

    /// Request length in bytes.
    pub len: usize,

    /// Largest response the host accepts, in bytes.
    pub resp_capacity: usize,
}

/// Queue kind of an [`HsmIo`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HsmIoKind {
    /// Command (DDI) IO with request / response buffers.
    Cmd,

    /// Bulk (fast-path) AES-GCM / AES-XTS IO.
    Bulk,
}

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
    /// Submission queue entry type.
    type Sqe: HsmSqe + ?Sized;

    /// Completion queue entry type.
    type Cqe: HsmCqe + ?Sized;

    /// Borrows the submission queue entry.
    ///
    /// The SQE is read-only from the firmware's perspective: the
    /// host populated it before raising the doorbell that triggered
    /// [`HsmIoController::poll_io`].
    fn sqe(&self) -> &Self::Sqe;

    /// Borrows the completion queue entry.
    ///
    /// The platform fills its identity fields when the IO is received; the
    /// core records the outcome before
    /// [`HsmIoController::complete_io`].
    fn cqe(&mut self) -> &mut Self::Cqe;

    /// Returns which queue kind this IO came from.
    ///
    /// A [`Bulk`](HsmIoKind::Bulk) IO is run through
    /// [`HsmBulkCrypto::bulk_crypt`] instead of command dispatch; its
    /// [`sqe`](Self::sqe) is the 32-dword bulk submission entry and its
    /// [`cqe`](Self::cqe) the 16-dword bulk completion entry.
    ///
    /// # Returns
    ///
    /// The IO kind; [`Cmd`](HsmIoKind::Cmd) by default.
    fn kind(&self) -> HsmIoKind {
        HsmIoKind::Cmd
    }
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

    /// Receives `io`'s request from the host.
    ///
    /// Validates the SQE's transfer fields, allocates exchange storage and
    /// transfers the request into it, decrypting it if the IO protocol
    /// protects it.
    ///
    /// # Errors
    ///
    /// Errors are canonical; the CQE maps each to its wire status:
    ///
    /// - `SqeInvalidPsdt`, `IoChannelInvalid{Src,Dst,Oob}{Len,Alignment}` —
    ///   a malformed transfer field.
    /// - `InvalidArg` — another malformed SQE field.
    /// - `NotEnoughSpace` — the exchange storage cannot be allocated.
    /// - `FailedToStartDmaTransaction` — the host transfer failed.
    /// - `SessionTransportError` — a protected request failed authentication
    ///   or its session has no transport keys.
    async fn recv_request(&self, io: &Self::Io) -> HsmResult<HsmRequest<'_>>;

    /// Sends the response `resp` to the host for `io`.
    ///
    /// The core records the success in the CQE first
    /// ([`HsmCqe::set_ok_ex`]); a platform that builds its own success CQE
    /// (for example with transport protection fields) overwrites it.
    ///
    /// # Errors
    ///
    /// Canonical, as for [`recv_request`](Self::recv_request): `InvalidArg`
    /// if `resp` exceeds the host's capacity, `FailedToStartDmaTransaction`,
    /// `NotEnoughSpace`, or `SessionTransportError`. The core then records
    /// the error in the CQE.
    async fn send_response(&self, io: &mut Self::Io, resp: &HsmDmaBuf) -> HsmResult<()>;

    /// Copies out-of-band item `index` of `io` from the host into `dst`;
    /// the item's length must equal `dst.len()`.
    ///
    /// # Errors
    ///
    /// - `InvalidArg` — `io` has no such item, or its length differs.
    /// - `FailedToStartDmaTransaction` — the host transfer failed.
    async fn recv_oob(&self, io: &Self::Io, index: usize, dst: &mut HsmDmaBuf) -> HsmResult<()>;

    /// Copies `src` to out-of-band item `index` of `io` in host memory; the
    /// item's length must equal `src.len()`.
    ///
    /// # Errors
    ///
    /// As for [`recv_oob`](Self::recv_oob).
    async fn send_oob(&self, io: &Self::Io, index: usize, src: &HsmDmaBuf) -> HsmResult<()>;

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

    /// Finishes `io` without the caller: sends `resp` (as
    /// [`send_response`](Self::send_response)), then posts its completion
    /// (as [`complete_io`](Self::complete_io)) and drops it (as
    /// [`drop_io`](Self::drop_io)).
    ///
    /// For an IO with nothing left to do once its completion is posted, so
    /// that its task can move on at once. The CQE must already record the
    /// success; if the transfer fails, the platform records that instead.
    ///
    /// # Errors
    ///
    /// Returns `io`, having started nothing, if the platform cannot take it
    /// over now; the caller then sends, completes and drops it itself.
    /// Platforms without a detached transfer engine always return `Err(io)`.
    fn finish_io(&self, io: Self::Io, resp: &HsmDmaBuf) -> Result<(), Self::Io>;
}
