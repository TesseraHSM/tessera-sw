// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM platform abstraction layer trait.
//!
//! Defines the [`HsmPal`] aggregate trait — the single bound that the
//! HSM core uses to talk to a platform implementation.  Concrete
//! platforms (`UnoHsmPal` for STM32, `StdHsmPal` for the host-side
//! emulator) implement [`HsmPal`] by composing all of the smaller PAL
//! sub-traits in this crate.
//!
//! ## Lifecycle
//!
//! ```text
//! HsmPal::default()        — construct (zero-init)
//!   ↓
//! HsmPal::init(&self)      — one-time hardware bring-up (sync)
//!   ↓
//! HsmPal::run(&self).await — main event loop, returns on fatal error
//!   ↓
//! HsmPal::deinit(&self)    — release resources (sync)
//! ```
//!
//! The trait is `&self` throughout: PAL implementations rely on
//! interior mutability (no atomics; the firmware is single-core and
//! cooperatively scheduled).

use super::*;

/// Aggregate platform trait implemented by every HSM PAL.
///
/// `HsmPal` is the single entry point the HSM core depends on.  All
/// hardware- and platform-specific behavior is reached through one of
/// the supertraits listed below; this trait itself only adds the
/// platform-wide lifecycle hooks ([`init`](Self::init),
/// [`run`](Self::run), [`deinit`](Self::deinit)) and the [`Default`]
/// constructibility constraint.
///
/// ## Supertraits
///
/// | Trait | Purpose |
/// |-------|---------|
/// | [`HsmAlloc`] | Per-IO bump-allocator scopes (DTCM and DMA SRAM) |
/// | [`HsmIoController`] | I/O submission and completion |
/// | [`HsmGdmaController`] | Host↔device memory copies (GDMA) |
/// | [`HsmPartitionManager`] | Partition lifecycle and identity queries |
/// | [`HsmPartitionLock`] | Per-partition async mutex for DDI handlers |
/// | [`HsmCertStore`] | Per-partition certificate chain storage |
/// | [`HsmSessionManager`] | Session allocation (vault-backed) |
/// | [`HsmVault`] | Key storage with firmware capacity emulation |
/// | [`HsmCrypto`] | Cryptographic operations (hash, hmac, kdf, …) |
///
/// ## Construction
///
/// `HsmPal: Default` lets the core build the platform from a constant
/// context.  Implementations should make `default()` cheap (no
/// hardware access, no allocations, no panics); real bring-up belongs
/// in [`init`](Self::init).
pub trait HsmPal:
    HsmAlloc
    + HsmIoController
    + HsmGdmaController
    + HsmCustomDispatch
    + HsmPartitionManager
    + HsmPartitionLock
    + HsmCertStore
    + HsmSeedStore
    + HsmSessionManager
    + HsmVault
    + HsmCrypto
    + Default
{
    fn init(&self);

    /// Drives the platform's main event loop.
    ///
    /// This future runs for the lifetime of the firmware: it polls
    /// the IO controller for incoming SQEs, dispatches them through
    /// the core's IO pipeline, and yields back to the executor while
    /// hardware operations are in flight.  It returns only on a
    /// fatal, unrecoverable error.
    ///
    /// # Parameters
    ///
    /// - `&self` — initialised platform.  Must have had
    ///   [`init`](Self::init) called previously.
    ///
    /// # Returns
    ///
    /// `()` once the loop has terminated.  Errors are surfaced
    /// internally (logged, mapped to CQE statuses, etc.) and do not
    /// propagate from this method.
    async fn run(&self);

    /// Copies a response to the host, then posts `io`'s completion:
    /// [`copy_mem_to_host`](HsmGdmaController::copy_mem_to_host) followed
    /// by [`complete_io`](HsmIoController::complete_io), as one step so a
    /// platform can post the completion as soon as the copy lands rather
    /// than when the IO's task next runs.
    ///
    /// The CQE must already hold the completion of a successful copy.
    ///
    /// # Errors
    ///
    /// - [`ReplyError::Copy`] — the copy failed and nothing was posted;
    ///   the caller still owes the host a completion.
    /// - [`ReplyError::Complete`] — the copy landed but the completion
    ///   could not be posted.
    async fn reply_io(
        &self,
        io: &mut Self::Io,
        resp: &DmaBuf,
        dst: HsmDmaAddr,
        dst2: HsmDmaAddr,
        prp: bool,
    ) -> Result<(), ReplyError> {
        self.copy_mem_to_host(io, resp, dst, dst2, prp)
            .await
            .map_err(ReplyError::Copy)?;
        self.complete_io(io).await.map_err(ReplyError::Complete)
    }

    /// Releases platform resources.
    ///
    /// Called after [`run`](Self::run) returns.  Powers down
    /// peripherals, flushes any pending logs, and clears
    /// vault/session state.  Idempotent — safe to call from drop or
    /// panic paths.
    ///
    /// # Parameters
    ///
    /// - `&self` — platform instance to tear down.
    ///
    /// # Returns
    ///
    /// Nothing.
    fn deinit(&self);
}
