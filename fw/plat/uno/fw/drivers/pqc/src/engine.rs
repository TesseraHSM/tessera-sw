// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A claimed PQC engine, i.e. exclusive use of one FP core.

use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_uno_trace::tracing::*;

use crate::api::PqcDriver;
use crate::error::PqcError;
use crate::mailbox;
use crate::pool::Staged;
use crate::request::PqcOp;
use crate::types::EngineId;

/// Core status meaning "the crypto rejected the request"; for verify this
/// is an invalid signature rather than a fault.  Mirrors the FP side.
const STATUS_CRYPTO_FAILED: u32 = 4;

/// How long to await a core's response before giving up on it.
///
/// Must cover the slowest operation, with margin: ML-DSA-87 signing runs to
/// ~175 ms because FIPS 204 rejection sampling retries until a candidate
/// passes the norm checks. The response is picked up as soon as it lands
/// (see [`PqcDriver::wake`]); this only bounds a dead core.
const SUBMIT_TIMEOUT: embassy_time::Duration = embassy_time::Duration::from_millis(600);

/// Length of the compact ML-DSA private seed (`xi`).  Identical for every
/// parameter set, which is why the key kind has to travel with it.
pub const MLDSA_SEED_LEN: usize = 32;

/// Largest message the wire carries (`MLDSA_MESSAGE_MAX_LEN`).
pub const MLDSA_MSG_MAX: usize = 586;

/// Largest context string the wire carries (`MLDSA_CTX_MAX_LEN`).
pub const MLDSA_CTX_MAX: usize = 255;

/// Length of the ML-KEM seed pair `(d ‖ z)`.
///
/// Twice the ML-DSA seed, and carried in the mailbox's two 32-byte seed
/// fields rather than a wider one.
pub const MLKEM_SEED_LEN: usize = 64;

/// Encapsulation-key length per ML-KEM parameter set (FIPS 203 Table 3).
pub fn mlkem_pub_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlKem512Seed => Ok(800),
        HsmVaultKeyKind::MlKem768Seed => Ok(1184),
        HsmVaultKeyKind::MlKem1024Seed => Ok(1568),
        _ => Err(PqcError::INVALID_KEY_KIND),
    }
}

/// Ciphertext length per ML-KEM parameter set (FIPS 203 Table 3).
pub fn mlkem_ct_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlKem512Seed => Ok(768),
        HsmVaultKeyKind::MlKem768Seed => Ok(1088),
        HsmVaultKeyKind::MlKem1024Seed => Ok(1568),
        _ => Err(PqcError::INVALID_KEY_KIND),
    }
}

/// Signature length per ML-DSA parameter set (FIPS 204 Table 2).
pub fn mldsa_sig_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(2420),
        HsmVaultKeyKind::MlDsa65Seed => Ok(3309),
        HsmVaultKeyKind::MlDsa87Seed => Ok(4627),
        _ => Err(PqcError::INVALID_KEY_KIND),
    }
}

/// Public key length per ML-DSA parameter set (FIPS 204 Table 2).
///
/// These are all distinct, so a public key's length identifies its
/// parameter set — the property the TBOR wire relies on.
pub fn mldsa_pub_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(1312),
        HsmVaultKeyKind::MlDsa65Seed => Ok(1952),
        HsmVaultKeyKind::MlDsa87Seed => Ok(2592),
        _ => Err(PqcError::INVALID_KEY_KIND),
    }
}

/// Expanded ML-DSA secret-key length for a parameter set (FIPS 204).
///
/// The masked key carries this alongside the seed, so signing never has to
/// re-derive it.
pub fn mldsa_sec_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlDsa44Seed => Ok(2560),
        HsmVaultKeyKind::MlDsa65Seed => Ok(4032),
        HsmVaultKeyKind::MlDsa87Seed => Ok(4896),
        _ => Err(PqcError::INVALID_KEY_KIND),
    }
}

/// ML-KEM decapsulation-key length for a parameter set (FIPS 203).
///
/// Carried in the masked key beside the `(d, z)` seed pair, so
/// decapsulation never has to re-derive it.
pub fn mlkem_sec_key_len(kind: HsmVaultKeyKind) -> HsmResult<usize> {
    match kind {
        HsmVaultKeyKind::MlKem512Seed => Ok(1632),
        HsmVaultKeyKind::MlKem768Seed => Ok(2400),
        HsmVaultKeyKind::MlKem1024Seed => Ok(3168),
        _ => Err(PqcError::INVALID_KEY_KIND),
    }
}

/// Check a key generation's buffers against parameter set `kind` and build
/// its request.
///
/// `seed` is the private seed from the HSM's TRNG -- `xi` for ML-DSA, the
/// pair `(d ‖ z)` for ML-KEM -- which the request carries in its two seed
/// fields; an FP core has no entropy source of its own. The keys come back
/// in the core's operand slot.
pub(crate) fn gen_key_request(
    op: PqcOp,
    kind: HsmVaultKeyKind,
    seed: &[u8],
    pub_key: &[u8],
    sec_key: &[u8],
) -> HsmResult<Staged> {
    let (seed_len, expected_pub, expected_sec) = match op {
        PqcOp::MlDsaGenerateKey => (
            MLDSA_SEED_LEN,
            mldsa_pub_key_len(kind)?,
            mldsa_sec_key_len(kind)?,
        ),
        _ => (
            MLKEM_SEED_LEN,
            mlkem_pub_key_len(kind)?,
            mlkem_sec_key_len(kind)?,
        ),
    };
    if seed.len() != seed_len || pub_key.len() != expected_pub || sec_key.len() != expected_sec {
        return Err(PqcError::INVALID_BUFFER_SIZE);
    }

    let mut staged = Staged {
        op: op as u32,
        key_kind: kind.0 as u32,
        xi: [0; MLDSA_SEED_LEN],
        rnd: [0; MLDSA_SEED_LEN],
    };
    let (xi, rnd) = seed.split_at(MLDSA_SEED_LEN);
    staged.xi.copy_from_slice(xi);
    if !rnd.is_empty() {
        staged.rnd.copy_from_slice(rnd);
    }
    Ok(staged)
}

/// Exclusive claim on one FP core.
///
/// Returned by [`PqcDriver::acquire_any`].  The engine is returned to the
/// pool by [`release`](Self::release); `Drop` cannot do it because
/// releasing may hand the engine straight to a waiting task, which needs
/// access to driver state.
pub struct PqcEngine<'a> {
    pub(crate) driver: &'a PqcDriver,
    pub(crate) id: EngineId,
    pub(crate) released: bool,
}

impl PqcEngine<'_> {
    /// Which FP core this engine is.
    pub fn id(&self) -> EngineId {
        self.id
    }

    /// Generate an ML-DSA keypair on this engine.
    ///
    /// # Parameters
    /// * `kind` — ML-DSA seed kind selecting the parameter set.
    /// * `seed` — **in/out**: supplied filled with entropy from the HSM's
    ///   TRNG, and left unchanged. It is the ML-DSA seed `xi`, which is the
    ///   private key; an FP core has no entropy source of its own.
    /// * `pub_key` — output, exactly the parameter set's public key length.
    ///
    /// # Returns
    /// * `Err(PqcError::FP_NOT_READY)` — always, for now.  See the module
    ///   docs on [`crate`]: the FP firmware has no PQC responder, so the
    ///   request is built and validated but never submitted.
    pub async fn mldsa_gen_key(
        &mut self,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        let mut staged = gen_key_request(PqcOp::MlDsaGenerateKey, kind, seed, pub_key, sec_key)?;
        self.gen_key(&mut staged, pub_key, sec_key).await
    }

    /// Sign a message on this engine.
    ///
    /// # Parameters
    /// * `kind` — ML-DSA seed kind selecting the parameter set.
    /// * `sec_key` — the expanded secret key recovered from the caller's
    ///   masked key. Supplying it rather than the seed is what keeps a key
    ///   generation out of every signature.
    /// * `rnd` — per-signature randomness from the device TRNG.
    /// * `msg`, `ctx` — staged into the operand slot.
    /// * `sig` — output, exactly the parameter set's signature length.
    pub async fn mldsa_sign(
        &mut self,
        kind: HsmVaultKeyKind,
        sec_key: &[u8],
        rnd: &[u8; MLDSA_SEED_LEN],
        msg: &[u8],
        ctx: &[u8],
        sig: &mut [u8],
    ) -> HsmResult<()> {
        let expected_sig = mldsa_sig_len(kind)?;
        if sig.len() != expected_sig
            || sec_key.len() != mldsa_sec_key_len(kind)?
            || msg.len() > MLDSA_MSG_MAX
            || ctx.len() > MLDSA_CTX_MAX
        {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        // Stage the bulk inputs before posting: the core reads them only
        // after seeing the request sequence number, which is written last.
        if !mailbox::write_slot(self.id, mailbox::SLOT_MSG_OFFSET, msg)
            || !mailbox::write_slot(self.id, mailbox::SLOT_CTX_OFFSET, ctx)
            || !mailbox::write_slot(self.id, mailbox::SLOT_KEY_IN_OFFSET, sec_key)
        {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        let resp = self
            .submit(&mailbox::RequestParams {
                op: PqcOp::MlDsaSign as u32,
                key_kind: kind.0 as u32,
                xi: &[0u8; MLDSA_SEED_LEN],
                rnd,
                msg_len: msg.len() as u32,
                ctx_len: ctx.len() as u32,
                sig_len: 0,
                pub_key_len: 0,
            })
            .await?;

        if resp.out_len as usize != expected_sig {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }
        if !mailbox::read_slot_at(self.id, mailbox::SLOT_SIG_OFFSET, sig) {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        Ok(())
    }

    /// Generate an ML-KEM key pair on this engine.
    ///
    /// # Parameters
    /// * `kind` — ML-KEM seed kind selecting the parameter set.
    /// * `seed` — **in/out**: supplied filled with 64 bytes of entropy from
    ///   the HSM's TRNG and left unchanged. It is the `(d ‖ z)` seed pair,
    ///   which is the private key.
    /// * `pub_key` — output; the encapsulation key.
    pub async fn mlkem_gen_key(
        &mut self,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        let mut staged = gen_key_request(PqcOp::MlKemGenerateKey, kind, seed, pub_key, sec_key)?;
        self.gen_key(&mut staged, pub_key, sec_key).await
    }

    /// Encapsulate to a public key on this engine.
    ///
    /// # Parameters
    /// * `kind` — ML-KEM seed kind selecting the parameter set.
    /// * `pub_key` — the encapsulation key to encapsulate to.
    /// * `m` — 32 bytes of randomness from the device TRNG.
    /// * `ciphertext` — output, exactly the parameter set's ciphertext length.
    /// * `shared_secret` — output, 32 bytes.
    pub async fn mlkem_encaps(
        &mut self,
        kind: HsmVaultKeyKind,
        pub_key: &[u8],
        m: &[u8; MLDSA_SEED_LEN],
        ciphertext: &mut [u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()> {
        let expected_pub = mlkem_pub_key_len(kind)?;
        let expected_ct = mlkem_ct_len(kind)?;
        if pub_key.len() != expected_pub
            || ciphertext.len() != expected_ct
            || shared_secret.len() != mailbox::SHARED_SECRET_LEN
        {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        if !mailbox::write_slot(self.id, mailbox::SLOT_PK_OFFSET, pub_key) {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        let resp = self
            .submit(&mailbox::RequestParams {
                op: PqcOp::MlKemEncapsulate as u32,
                key_kind: kind.0 as u32,
                xi: m,
                rnd: &[0u8; MLDSA_SEED_LEN],
                msg_len: 0,
                ctx_len: 0,
                sig_len: 0,
                pub_key_len: pub_key.len() as u32,
            })
            .await?;

        if resp.out_len as usize != expected_ct {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }
        if !mailbox::read_slot_at(self.id, mailbox::SLOT_CT_OFFSET, ciphertext)
            || !mailbox::read_slot_at(self.id, mailbox::SLOT_SS_OFFSET, shared_secret)
        {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        Ok(())
    }

    /// Decapsulate a ciphertext on this engine.
    ///
    /// # Parameters
    /// * `kind` — ML-KEM seed kind selecting the parameter set.
    /// * `sec_key` — the expanded decapsulation key recovered from the
    ///   caller's masked key. Supplying it rather than the seed pair is
    ///   what keeps a key generation out of every decapsulation.
    /// * `ciphertext` — the ciphertext to decapsulate.
    /// * `shared_secret` — output, 32 bytes.
    pub async fn mlkem_decaps(
        &mut self,
        kind: HsmVaultKeyKind,
        sec_key: &[u8],
        ciphertext: &[u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()> {
        let expected_ct = mlkem_ct_len(kind)?;
        if sec_key.len() != mlkem_sec_key_len(kind)?
            || ciphertext.len() != expected_ct
            || shared_secret.len() != mailbox::SHARED_SECRET_LEN
        {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        // The decapsulation key occupies the region the ciphertext used to
        // use, so the ciphertext moves to the public-key region — which
        // decapsulation does not otherwise touch.
        if !mailbox::write_slot(self.id, mailbox::SLOT_KEY_IN_OFFSET, sec_key)
            || !mailbox::write_slot(self.id, mailbox::SLOT_CT_IN_OFFSET, ciphertext)
        {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        let resp = self
            .submit(&mailbox::RequestParams {
                op: PqcOp::MlKemDecapsulate as u32,
                key_kind: kind.0 as u32,
                xi: &[0u8; MLDSA_SEED_LEN],
                rnd: &[0u8; MLDSA_SEED_LEN],
                msg_len: 0,
                ctx_len: 0,
                // The ciphertext length rides in the signature-length
                // field, as it did when the ciphertext shared that region.
                sig_len: ciphertext.len() as u32,
                pub_key_len: 0,
            })
            .await;

        let resp = resp?;

        if resp.out_len as usize != mailbox::SHARED_SECRET_LEN {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }
        if !mailbox::read_slot_at(self.id, mailbox::SLOT_SS_OFFSET, shared_secret) {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        Ok(())
    }

    /// Verify a signature on this engine.
    ///
    /// Returns `Ok(true)` for a good signature and `Ok(false)` for a bad
    /// one; `Err` is reserved for transport and argument faults, so a
    /// caller cannot mistake a failed verification for a broken link.
    pub async fn mldsa_verify(
        &mut self,
        kind: HsmVaultKeyKind,
        pub_key: &[u8],
        msg: &[u8],
        ctx: &[u8],
        sig: &[u8],
    ) -> HsmResult<bool> {
        if pub_key.len() != mldsa_pub_key_len(kind)?
            || sig.len() != mldsa_sig_len(kind)?
            || msg.len() > MLDSA_MSG_MAX
            || ctx.len() > MLDSA_CTX_MAX
        {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        if !mailbox::write_slot(self.id, mailbox::SLOT_MSG_OFFSET, msg)
            || !mailbox::write_slot(self.id, mailbox::SLOT_CTX_OFFSET, ctx)
            || !mailbox::write_slot(self.id, mailbox::SLOT_SIG_OFFSET, sig)
            || !mailbox::write_slot(self.id, mailbox::SLOT_PK_OFFSET, pub_key)
        {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        // A bad signature comes back as a status, so use the status-tolerant
        // submit rather than letting every non-zero status become an error.
        let resp = self
            .submit_raw(&mailbox::RequestParams {
                op: PqcOp::MlDsaVerify as u32,
                key_kind: kind.0 as u32,
                xi: &[0u8; MLDSA_SEED_LEN],
                rnd: &[0u8; MLDSA_SEED_LEN],
                msg_len: msg.len() as u32,
                ctx_len: ctx.len() as u32,
                sig_len: sig.len() as u32,
                pub_key_len: pub_key.len() as u32,
            })
            .await?;

        match resp.status {
            0 => Ok(true),
            s if s == STATUS_CRYPTO_FAILED => Ok(false),
            _ => Err(PqcError::FP_ERROR),
        }
    }

    /// Run key generation request `staged` here, wiping it once posted.
    async fn gen_key(
        &mut self,
        staged: &mut Staged,
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        let id = self.id;
        let seq = self
            .driver
            .state
            .with(|s| s.responses.post(id, &staged.params()));
        staged.wipe();
        self.finish_gen_key(seq, pub_key, sec_key).await
    }

    /// Collect the keys key generation request `seq` left in this core's
    /// operand slot.
    pub(crate) async fn finish_gen_key(
        &mut self,
        seq: u32,
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        let resp = self.await_response(seq).await?;
        if resp.status != 0 {
            return Err(PqcError::FP_ERROR);
        }
        if resp.out_len as usize != pub_key.len() {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        // Both keys are too large for the mailbox, so they travel in this
        // core's operand slot. Read only after the response sequence number
        // matched, which the core writes last.
        if !mailbox::read_slot_at(self.id, mailbox::SLOT_PK_OFFSET, pub_key)
            || !mailbox::read_slot_at(self.id, mailbox::SLOT_KEY_OUT_OFFSET, sec_key)
        {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        Ok(())
    }

    /// Send a request to this engine's FP core and wait for its answer.
    ///
    /// The request travels in the core's PSRAM mailbox; the doorbell only
    /// wakes it.  Completion is detected by polling the mailbox sequence
    /// number rather than an interrupt pending bit, because block 1's
    /// pending bits belong to the IPC driver, whose `wake()` clears every
    /// bit it processes and would race the reply away.
    async fn submit(
        &mut self,
        params: &mailbox::RequestParams<'_>,
    ) -> HsmResult<mailbox::Response> {
        let resp = self.submit_raw(params).await?;
        if resp.status != 0 {
            return Err(PqcError::FP_ERROR);
        }
        Ok(resp)
    }

    /// As [`submit`](Self::submit), but returns the core's status untouched.
    ///
    /// Verify needs this: a bad signature is a legitimate outcome carried in
    /// the status, not a transport fault.
    async fn submit_raw(
        &mut self,
        params: &mailbox::RequestParams<'_>,
    ) -> HsmResult<mailbox::Response> {
        // NOTE: `probe_fp_shared_memory()` used to run here. It writes a
        // sentinel and reads all three FP status blocks out of PSRAM, and
        // its only consumer was a trace call -- so with tracing out of the
        // hot path it was pure cost on every request. Call it from a
        // debugging build if you need to see what the cores are
        // publishing.

        let id = self.id;
        let seq = self.driver.state.with(|s| s.responses.post(id, params));
        self.await_response(seq).await
    }

    /// Await the response to request `seq`, already posted to this engine.
    pub(crate) async fn await_response(&mut self, seq: u32) -> HsmResult<mailbox::Response> {
        // Woken by `PqcDriver::wake` (from the PAL's poll loop) once the
        // core posts the response, rather than re-polling the mailbox from
        // this task on every executor pass: three tasks doing that, each
        // pass re-queueing itself and reading the clock, took most of CP1's
        // time while every core worked, and lengthened every pass, so a
        // task handed a freed core started it later.
        let engine = usize::from(self.id.raw());
        let deadline = embassy_time::Instant::now() + SUBMIT_TIMEOUT;
        let response = embassy_futures::select::select(
            core::future::poll_fn(|cx| {
                if let Some(resp) = mailbox::take_response(self.id, seq) {
                    return core::task::Poll::Ready(resp);
                }
                self.driver
                    .state
                    .with(|s| s.responses.wakers[engine].register(cx.waker()));
                core::task::Poll::Pending
            }),
            embassy_time::Timer::at(deadline),
        )
        .await;
        self.driver
            .state
            .with(|s| s.responses.awaiting &= !(1 << engine));
        if let embassy_futures::select::Either::First(resp) = response {
            return Ok(resp);
        }

        error!(
            "pqc",
            PqcError::FP_NOT_READY,
            "engine {} (FP{}) did not answer seq={} within the deadline",
            self.id.raw(),
            self.id.raw(),
            seq
        );
        // A core that faulted or panicked leaves a record on its way down.
        // Without this the timeout above is all anyone ever sees, and a
        // stack overflow is indistinguishable from a core that is merely
        // busy.
        // Bound with a leading underscore because the only reader is the
        // `error!` below, which compiles to nothing unless a trace backend
        // is enabled; without this the fields look unused in default builds.
        if let Some(_c) = mailbox::crash_record(self.id) {
            error!(
                "pqc",
                PqcError::FP_NOT_READY,
                "FP{} crashed: kind={} pc={:#010x} lr={:#010x} sp={:#010x} cfsr={:#010x} hfsr={:#010x} mmfar={:#010x} bfar={:#010x} stack_free={}",
                self.id.raw(),
                _c.kind,
                _c.pc,
                _c.lr,
                _c.sp,
                _c.cfsr,
                _c.hfsr,
                _c.mmfar,
                _c.bfar,
                _c.stack_free as i32
            );
        }
        Err(PqcError::FP_NOT_READY)
    }

    /// Return this engine to the pool.
    ///
    /// Deliberately synchronous and infallible, unlike
    /// `UpkaEngine::release`, which is `async` and fallible because it
    /// issues a memory-wipe command to scrub the PKA register bank on
    /// every release.
    ///
    /// The equivalent CSPs here — the ML-DSA seed and expanded private
    /// key — live in the FP core's DTCM, and the contract is that **FP
    /// zeroizes its own working memory after sending its response**.  So
    /// there is nothing for the HSM side to scrub and no round trip to
    /// wait on.
    ///
    /// If that contract ever needs to be enforced from this side (for
    /// FIPS 140-3 Level 3 assurance, say, where a self-zeroization claim
    /// resting on FP firmware may not satisfy the evaluator), this is the
    /// place: `release` would become `async fn release(self) ->
    /// HsmResult<()>`, send a wipe request, and `Drop` would need the
    /// same synchronous fallback UPKA uses.
    pub fn release(mut self) {
        if !self.released {
            self.released = true;
            self.driver.release_engine(self.id);
        }
    }
}

impl Drop for PqcEngine<'_> {
    /// Safety net for an engine dropped without [`release`](Self::release)
    /// — an early `?` on an error path, say.  Without this the engine would
    /// be leaked from the pool and, after three such leaks, PQC would wedge
    /// permanently.
    fn drop(&mut self) {
        if !self.released {
            self.released = true;
            self.driver.release_engine(self.id);
        }
    }
}
