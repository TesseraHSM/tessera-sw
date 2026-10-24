// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public API for the PQC driver.

use core::future::poll_fn;
use core::task::Poll;

use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_single_cell::SingleCell;

use crate::engine::PqcEngine;
use crate::error::PqcError;
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
    /// # Errors
    /// * [`PqcError::QUEUE_FULL`] — every waiter slot is taken.
    pub async fn acquire_any(&self) -> HsmResult<PqcEngine<'_>> {
        let mut queue_idx: Option<u8> = None;

        let result = poll_fn(|cx| {
            self.state.with(|s| {
                // Already queued: take the engine if one has been handed over.
                if let Some(idx) = queue_idx {
                    return match s.poll_queue_slot(idx, cx) {
                        Some(id) => Poll::Ready(Ok(id)),
                        None => Poll::Pending,
                    };
                }

                // Fast path, but only when nobody is waiting — otherwise a
                // task arriving now would jump the queue.
                if !s.has_waiters() {
                    if let Some(id) = s.claim_free_engine() {
                        return Poll::Ready(Ok(id));
                    }
                }

                let Some(idx) = s.reserve_queue_slot() else {
                    return Poll::Ready(Err(PqcError::QUEUE_FULL));
                };
                queue_idx = Some(idx);
                s.poll_queue_slot(idx, cx);
                Poll::Pending
            })
        })
        .await;

        match result {
            Ok(id) => Ok(PqcEngine {
                driver: self,
                id,
                released: false,
            }),
            // The closure's only error is `QUEUE_FULL`, returned before a
            // slot is reserved, so there is never a slot to give back here.
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

    /// Wakes each task whose engine has posted the response it awaits.
    ///
    /// The cores raise no interrupt CP1 can claim for itself (their pending
    /// bits belong to the IPC driver), so the PAL calls this from its poll
    /// loop, as it does the BCP's. With no response awaited it touches only
    /// this driver's state.
    pub fn wake(&self) {
        self.state.with(|s| {
            let mut awaiting = s.awaiting;
            while awaiting != 0 {
                let i = awaiting.trailing_zeros() as usize;
                awaiting &= awaiting - 1;
                if crate::mailbox::response_seq(EngineId::new(i as u8)) == s.awaiting_seq[i] {
                    s.awaiting &= !(1 << i);
                    s.resp_wakers[i].wake();
                }
            }
        });
    }

    /// Return an engine to the pool.
    pub(crate) fn release_engine(&self, id: EngineId) {
        self.state.with(|s| s.release_engine(id));
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

impl core::fmt::Debug for PqcDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PqcDriver")
            .field("free_engines", &self.free_engines())
            .finish()
    }
}
