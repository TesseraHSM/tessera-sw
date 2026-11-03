// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public API for the PQC driver.

use core::future::poll_fn;
use core::task::Poll;

use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_single_cell::SingleCell;

use crate::engine::PqcEngine;
use crate::error::PqcError;
use crate::mailbox;
use crate::pool::PqcState;
use crate::shared_status;
use crate::types::EngineId;
use crate::types::ENGINES;

/// Async driver for PQC offload to the fastpath cores.
///
/// Manages the three FP cores as a pool of interchangeable engines, in
/// the same shape as the UPKA driver manages its sixteen PKA engines.
pub struct PqcDriver {
    pub(crate) state: SingleCell<PqcState>,
}

impl PqcDriver {
    /// Create the driver with every engine idle.
    pub const fn new() -> Self {
        Self {
            state: SingleCell::new(PqcState::new()),
        }
    }

    /// Acquire any free engine, waiting if all three are busy.
    ///
    /// Waiters are served FIFO: a task that queues is handed the next
    /// engine to be released, rather than racing tasks that arrive later.
    ///
    /// Draining engines (see [`EngineState`](crate::EngineState))
    /// rejoin the pool, scrubbed, once their core answers; nothing signals
    /// that, so a waiter keeps polling while any engine is draining.
    ///
    /// # Errors
    /// * [`PqcError::QUEUE_FULL`] — every waiter slot is taken.
    /// * [`PqcError::FP_NOT_READY`] — every engine is draining, so none
    ///   will be released until a core answers a request it has already
    ///   missed its deadline for.
    pub async fn acquire_any(&self) -> HsmResult<PqcEngine<'_>> {
        // Withdraws from the queue if this future is dropped while waiting,
        // so an engine handed to it is passed on rather than stranded.
        let mut wait = WaitGuard {
            driver: self,
            idx: None,
        };

        let result = poll_fn(|cx| {
            self.state.with(|s| {
                s.reclaim_drained(mailbox::has_answered, mailbox::scrub);

                // Already queued: take the engine if one has been handed over.
                if let Some(idx) = wait.idx {
                    if let Some(id) = s.poll_queue_slot(idx, cx) {
                        wait.idx = None;
                        return Poll::Ready(Ok(id));
                    }
                    if s.all_draining() {
                        s.cancel_wait(idx);
                        wait.idx = None;
                        return Poll::Ready(Err(PqcError::FP_NOT_READY));
                    }
                    if s.has_draining() {
                        cx.waker().wake_by_ref();
                    }
                    return Poll::Pending;
                }

                // Fast path, but only when nobody is waiting — otherwise a
                // task arriving now would jump the queue.
                if !s.has_waiters() {
                    if let Some(id) = s.claim_free_engine() {
                        return Poll::Ready(Ok(id));
                    }
                }
                if s.all_draining() {
                    return Poll::Ready(Err(PqcError::FP_NOT_READY));
                }

                let Some(idx) = s.reserve_queue_slot() else {
                    return Poll::Ready(Err(PqcError::QUEUE_FULL));
                };
                wait.idx = Some(idx);
                s.poll_queue_slot(idx, cx);
                if s.has_draining() {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            })
        })
        .await;

        match result {
            Ok(id) => Ok(PqcEngine {
                driver: self,
                id,
                released: false,
                in_flight: None,
            }),
            // Errors are returned before a slot is reserved, or after the
            // waiter has withdrawn, so there is never a slot to give back.
            Err(e) => Err(e),
        }
    }

    /// Acquire an engine, run `f` on it, and release it however `f` ends.
    ///
    pub async fn with_engine<F, R>(&self, f: F) -> HsmResult<R>
    where
        F: for<'a> AsyncFnOnce(&'a mut PqcEngine<'_>) -> HsmResult<R>,
    {
        let mut engine = self.acquire_any().await?;

        let result = f(&mut engine).await;

        engine.release();
        result
    }

    /// Generate an ML-DSA keypair on whichever FP core is free.
    ///
    /// Convenience wrapper over [`acquire_any`](Self::acquire_any) +
    /// [`PqcEngine::mldsa_gen_key`] + release.
    pub async fn mldsa_gen_key(
        &self,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        self.with_engine(async |engine| engine.mldsa_gen_key(kind, seed, pub_key, sec_key).await)
            .await
    }

    /// Leave a fresh sentinel for the FP cores and read what each has
    /// published.
    ///
    /// Debugging aid, deliberately **not** called on the request path: it
    /// touches PSRAM four times per call and its output is only visible
    /// with a trace backend compiled in. Call it from `submit_raw`, and
    /// add an `error!` for the values, when you need to see whether the
    /// cores are alive and which one answered. The sentinel changes every
    /// call so a stale echo is distinguishable from a live one.
    ///
    /// See [`shared_status`] for what the fields mean.
    #[allow(dead_code)]
    pub(crate) fn probe_fp_shared_memory(&self) {
        let sentinel = self.state.with(|s| {
            s.probe_seq = s.probe_seq.wrapping_add(1);
            0x5AA5_0000 | s.probe_seq
        });
        shared_status::write_sentinel(sentinel);

        for idx in 0..ENGINES {
            // Underscore-prefixed: the trace macros compile to nothing
            // without a trace backend, and this is read only by them.
            let _st = shared_status::read_status(idx);
        }
    }

    /// Sign a message on whichever FP core is free.
    pub async fn mldsa_sign(
        &self,
        kind: HsmVaultKeyKind,
        sec_key: &[u8],
        rnd: &[u8; crate::MLDSA_SEED_LEN],
        msg: &[u8],
        ctx: &[u8],
        sig: &mut [u8],
    ) -> HsmResult<()> {
        self.with_engine(async |engine| engine.mldsa_sign(kind, sec_key, rnd, msg, ctx, sig).await)
            .await
    }

    /// Generate an ML-KEM key pair on whichever FP core is free.
    pub async fn mlkem_gen_key(
        &self,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        self.with_engine(async |engine| engine.mlkem_gen_key(kind, seed, pub_key, sec_key).await)
            .await
    }

    /// Encapsulate to a public key on whichever FP core is free.
    pub async fn mlkem_encaps(
        &self,
        kind: HsmVaultKeyKind,
        pub_key: &[u8],
        m: &[u8; crate::MLDSA_SEED_LEN],
        ciphertext: &mut [u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()> {
        self.with_engine(async |engine| {
            engine
                .mlkem_encaps(kind, pub_key, m, ciphertext, shared_secret)
                .await
        })
        .await
    }

    /// Decapsulate a ciphertext on whichever FP core is free.
    pub async fn mlkem_decaps(
        &self,
        kind: HsmVaultKeyKind,
        sec_key: &[u8],
        ciphertext: &[u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()> {
        self.with_engine(async |engine| {
            engine
                .mlkem_decaps(kind, sec_key, ciphertext, shared_secret)
                .await
        })
        .await
    }

    /// Verify a signature on whichever FP core is free.
    pub async fn mldsa_verify(
        &self,
        kind: HsmVaultKeyKind,
        pub_key: &[u8],
        msg: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> HsmResult<bool> {
        self.with_engine(async |engine| engine.mldsa_verify(kind, pub_key, msg, ctx, sig).await)
            .await
    }

    /// Hash `msg` with SHAKE on whichever FP core is free, writing the
    /// output length `algo` carries into the front of `out`.
    /// See [`PqcEngine::shake`].
    pub async fn shake(&self, algo: HsmHashAlgo, msg: &[u8], out: &mut [u8]) -> HsmResult<()> {
        self.with_engine(async |engine| engine.shake(algo, msg, out).await)
            .await
    }

    /// Next request sequence number.
    ///
    /// Monotonic across all engines, so a response can never be mistaken
    /// for one to an earlier request on the same core.
    pub(crate) fn next_request_seq(&self) -> u32 {
        self.state.with(|s| {
            s.request_seq = s.request_seq.wrapping_add(1);
            s.request_seq
        })
    }

    /// Return an engine to the pool.
    pub(crate) fn release_engine(&self, id: EngineId) {
        self.state.with(|s| s.release_engine(id));
    }

    /// Withhold an engine whose request `seq` may still be running.
    pub(crate) fn quarantine_engine(&self, id: EngineId, seq: u32) {
        self.state.with(|s| s.quarantine_engine(id, seq));
    }

    /// Number of engines currently idle.  Diagnostics only.
    pub fn free_engines(&self) -> u32 {
        self.state.with(|s| s.free_mask.count_ones())
    }
}

impl Default for PqcDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// A waiter's queue slot, withdrawn if [`PqcDriver::acquire_any`] is
/// dropped before it collects an engine.
struct WaitGuard<'a> {
    driver: &'a PqcDriver,
    idx: Option<u8>,
}

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        if let Some(idx) = self.idx.take() {
            self.driver.state.with(|s| s.cancel_wait(idx));
        }
    }
}

impl core::fmt::Debug for PqcDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PqcDriver")
            .field("free_engines", &self.free_engines())
            .finish()
    }
}
