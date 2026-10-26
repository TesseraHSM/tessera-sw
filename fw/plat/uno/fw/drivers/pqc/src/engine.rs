// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A claimed PQC engine, i.e. exclusive use of one FP core.

use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_uno_trace::tracing::*;

use crate::api::PqcDriver;
use crate::error::PqcError;
use crate::mailbox;
use crate::pool::Operand;
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

    let mut staged = Staged::new(op as u32, kind.0 as u32);
    staged.outputs = [
        (mailbox::SLOT_PK_OFFSET, expected_pub),
        (mailbox::SLOT_KEY_OUT_OFFSET, expected_sec),
    ];
    let (xi, rnd) = seed.split_at(MLDSA_SEED_LEN);
    staged.xi.copy_from_slice(xi);
    if !rnd.is_empty() {
        staged.rnd.copy_from_slice(rnd);
    }
    Ok(staged)
}

/// Check a signing request's buffers against parameter set `kind` and
/// build it; `sig` is only sized here.
pub(crate) fn sign_request(
    kind: HsmVaultKeyKind,
    sec_key: &[u8],
    rnd: &[u8; MLDSA_SEED_LEN],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> HsmResult<Staged> {
    if sig.len() != mldsa_sig_len(kind)?
        || sec_key.len() != mldsa_sec_key_len(kind)?
        || msg.len() > MLDSA_MSG_MAX
        || ctx.len() > MLDSA_CTX_MAX
    {
        return Err(PqcError::INVALID_BUFFER_SIZE);
    }
    let mut staged = Staged::new(PqcOp::MlDsaSign as u32, kind.0 as u32);
    staged.rnd = *rnd;
    staged.msg_len = msg.len() as u32;
    staged.ctx_len = ctx.len() as u32;
    staged.operands[0] = Operand::new(msg, mailbox::SLOT_MSG_OFFSET);
    staged.operands[1] = Operand::new(ctx, mailbox::SLOT_MSG_OFFSET + msg.len());
    // The key's t0 -- k rows of 416 bytes at its end -- is not read until an
    // attempt passes, so it may follow the rest (see `Staged::deferred`):
    // without it the key fits beside the last signature, and the core can
    // start while that is read.
    let key_at = mailbox::sign_key_offset(msg.len(), ctx.len());
    let t0_at = sec_key.len() - (mldsa_pub_key_len(kind)? - 32) / 320 * 416;
    let (head, t0) = sec_key.split_at(t0_at);
    staged.operands[2] = Operand::new(head, key_at);
    staged.deferred = Operand::new(t0, key_at + t0_at);
    staged.outputs[0] = (mailbox::sign_sig_offset(sig.len()), sig.len());
    Ok(staged)
}

/// Check a verification request's buffers against parameter set `kind` and
/// build it.
pub(crate) fn verify_request(
    kind: HsmVaultKeyKind,
    pub_key: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
) -> HsmResult<Staged> {
    if pub_key.len() != mldsa_pub_key_len(kind)?
        || sig.len() != mldsa_sig_len(kind)?
        || msg.len() > MLDSA_MSG_MAX
        || ctx.len() > MLDSA_CTX_MAX
    {
        return Err(PqcError::INVALID_BUFFER_SIZE);
    }
    let mut staged = Staged::new(PqcOp::MlDsaVerify as u32, kind.0 as u32);
    staged.msg_len = msg.len() as u32;
    staged.ctx_len = ctx.len() as u32;
    staged.sig_len = sig.len() as u32;
    staged.pub_key_len = pub_key.len() as u32;
    staged.operands = [
        Operand::new(msg, mailbox::SLOT_MSG_OFFSET),
        Operand::new(ctx, mailbox::SLOT_CTX_OFFSET),
        Operand::new(sig, mailbox::SLOT_SIG_OFFSET),
        Operand::new(pub_key, mailbox::SLOT_PK_OFFSET),
    ];
    Ok(staged)
}

/// Check an encapsulation request's buffers against parameter set `kind`
/// and build it; `ciphertext` and `shared_secret` are only sized here.
pub(crate) fn encaps_request(
    kind: HsmVaultKeyKind,
    pub_key: &[u8],
    m: &[u8; MLDSA_SEED_LEN],
    ciphertext: &[u8],
    shared_secret: &[u8],
) -> HsmResult<Staged> {
    if pub_key.len() != mlkem_pub_key_len(kind)?
        || ciphertext.len() != mlkem_ct_len(kind)?
        || shared_secret.len() != mailbox::SHARED_SECRET_LEN
    {
        return Err(PqcError::INVALID_BUFFER_SIZE);
    }
    let mut staged = Staged::new(PqcOp::MlKemEncapsulate as u32, kind.0 as u32);
    staged.xi = *m;
    staged.pub_key_len = pub_key.len() as u32;
    staged.operands[0] = Operand::new(pub_key, mailbox::SLOT_PK_OFFSET);
    staged.outputs = [
        (mailbox::SLOT_CT_OFFSET, ciphertext.len()),
        (mailbox::SLOT_SS_OFFSET, shared_secret.len()),
    ];
    Ok(staged)
}

/// Check a decapsulation request's buffers against parameter set `kind` and
/// build it; `shared_secret` is only sized here.
pub(crate) fn decaps_request(
    kind: HsmVaultKeyKind,
    sec_key: &[u8],
    ciphertext: &[u8],
    shared_secret: &[u8],
) -> HsmResult<Staged> {
    if sec_key.len() != mlkem_sec_key_len(kind)?
        || ciphertext.len() != mlkem_ct_len(kind)?
        || shared_secret.len() != mailbox::SHARED_SECRET_LEN
    {
        return Err(PqcError::INVALID_BUFFER_SIZE);
    }
    let mut staged = Staged::new(PqcOp::MlKemDecapsulate as u32, kind.0 as u32);
    // The ciphertext length rides in the signature-length field, as it did
    // when the ciphertext shared that region.
    staged.sig_len = ciphertext.len() as u32;
    // The decapsulation key occupies the region the ciphertext used to use,
    // so the ciphertext moves to the public-key region -- which
    // decapsulation does not otherwise touch.
    staged.operands[0] = Operand::new(sec_key, mailbox::SLOT_KEY_IN_OFFSET);
    staged.operands[1] = Operand::new(ciphertext, mailbox::SLOT_CT_IN_OFFSET);
    staged.outputs[0] = (mailbox::SLOT_SS_OFFSET, shared_secret.len());
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
    /// The request last posted here, zero for none: the core holds the
    /// next request's outputs back until it is marked collected.
    pub(crate) seq: u32,
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
        let mut staged = sign_request(kind, sec_key, rnd, msg, ctx, sig)?;
        let seq = self.post(&mut staged);
        self.finish_sign(seq, sig, false).await
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
        let mut staged = encaps_request(kind, pub_key, m, ciphertext, shared_secret)?;
        let seq = self.post(&mut staged);
        self.finish_encaps(seq, ciphertext, shared_secret, false).await
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
        let mut staged = decaps_request(kind, sec_key, ciphertext, shared_secret)?;
        let seq = self.post(&mut staged);
        self.finish_decaps(seq, shared_secret, false).await
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
        let mut staged = verify_request(kind, pub_key, msg, ctx, sig)?;
        let seq = self.post(&mut staged);
        self.finish_verify(seq).await
    }

    /// Post `staged` to this engine, wiping it once posted.
    ///
    /// The core reads the bulk inputs only after seeing the request's
    /// sequence number, which is written last.
    fn post(&mut self, staged: &mut Staged) -> u32 {
        let id = self.id;
        let seq = self.driver.state.with(|s| s.post(id, staged, false));
        staged.wipe();
        self.seq = seq;
        seq
    }

    /// With `hand_on`, give this engine to the next waiting request now,
    /// before the outputs of the one just finished -- the `(offset, len)`
    /// slot regions `outputs` -- are read, if that request's inputs land
    /// clear of them: the core starts on it while they are read, and holds
    /// its own outputs back until [`collected`](Self::collected).
    ///
    /// Only for a caller that releases the engine once these outputs are
    /// read, as the driver's one-shot operations do.
    fn hand_on(&mut self, hand_on: bool, outputs: &[(usize, usize)]) {
        let id = self.id;
        if hand_on && self.driver.state.with(|s| s.release_engine_early(id, outputs)) {
            self.released = true;
        }
    }

    /// Tell the core the last request's outputs have been read, and write
    /// any input the request handed on ahead of that held back.
    fn collected(&self) {
        if self.seq != 0 {
            mailbox::mark_collected(self.id, self.seq);
        }
        let id = self.id;
        self.driver.state.with(|s| s.flush_deferred(id));
    }

    /// Collect the signature signing request `seq` left in this core's
    /// operand slot.
    pub(crate) async fn finish_sign(
        &mut self,
        seq: u32,
        sig: &mut [u8],
        hand_on: bool,
    ) -> HsmResult<()> {
        let resp = self.await_ok(seq).await?;
        if resp.out_len as usize != sig.len() {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }
        let at = mailbox::sign_sig_offset(sig.len());
        self.hand_on(hand_on, &[(at, sig.len())]);
        let read = mailbox::read_slot_at(self.id, at, sig);
        self.collected();
        if !read {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }
        Ok(())
    }

    /// Collect the outcome of verification request `seq`.
    pub(crate) async fn finish_verify(&mut self, seq: u32) -> HsmResult<bool> {
        // A bad signature comes back as a status, so take the status as is
        // rather than letting every non-zero status become an error.
        let resp = self.await_response(seq).await?;
        match resp.status {
            0 => Ok(true),
            s if s == STATUS_CRYPTO_FAILED => Ok(false),
            _ => Err(PqcError::FP_ERROR),
        }
    }

    /// Collect the ciphertext and shared secret encapsulation request `seq`
    /// left in this core's operand slot.
    pub(crate) async fn finish_encaps(
        &mut self,
        seq: u32,
        ciphertext: &mut [u8],
        shared_secret: &mut [u8],
        hand_on: bool,
    ) -> HsmResult<()> {
        let resp = self.await_ok(seq).await?;
        if resp.out_len as usize != ciphertext.len() {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }
        self.hand_on(
            hand_on,
            &[
                (mailbox::SLOT_CT_OFFSET, ciphertext.len()),
                (mailbox::SLOT_SS_OFFSET, shared_secret.len()),
            ],
        );
        let read = mailbox::read_slot_at(self.id, mailbox::SLOT_CT_OFFSET, ciphertext)
            && mailbox::read_slot_at(self.id, mailbox::SLOT_SS_OFFSET, shared_secret);
        self.collected();
        if !read {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }
        Ok(())
    }

    /// Collect the shared secret decapsulation request `seq` left in this
    /// core's operand slot.
    pub(crate) async fn finish_decaps(
        &mut self,
        seq: u32,
        shared_secret: &mut [u8],
        hand_on: bool,
    ) -> HsmResult<()> {
        let resp = self.await_ok(seq).await?;
        if resp.out_len as usize != mailbox::SHARED_SECRET_LEN {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }
        self.hand_on(hand_on, &[(mailbox::SLOT_SS_OFFSET, shared_secret.len())]);
        let read = mailbox::read_slot_at(self.id, mailbox::SLOT_SS_OFFSET, shared_secret);
        self.collected();
        if !read {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }
        Ok(())
    }

    /// Run key generation request `staged` here, wiping it once posted.
    async fn gen_key(
        &mut self,
        staged: &mut Staged,
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()> {
        let seq = self.post(staged);
        self.finish_gen_key(seq, pub_key, sec_key, false).await
    }

    /// Collect the keys key generation request `seq` left in this core's
    /// operand slot.
    pub(crate) async fn finish_gen_key(
        &mut self,
        seq: u32,
        pub_key: &mut [u8],
        sec_key: &mut [u8],
        hand_on: bool,
    ) -> HsmResult<()> {
        let resp = self.await_ok(seq).await?;
        if resp.out_len as usize != pub_key.len() {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        // Both keys are too large for the mailbox, so they travel in this
        // core's operand slot. Read only after the response sequence number
        // matched, which the core writes last.
        self.hand_on(
            hand_on,
            &[
                (mailbox::SLOT_PK_OFFSET, pub_key.len()),
                (mailbox::SLOT_KEY_OUT_OFFSET, sec_key.len()),
            ],
        );
        let read = mailbox::read_slot_at(self.id, mailbox::SLOT_PK_OFFSET, pub_key)
            && mailbox::read_slot_at(self.id, mailbox::SLOT_KEY_OUT_OFFSET, sec_key);
        self.collected();
        if !read {
            return Err(PqcError::INVALID_BUFFER_SIZE);
        }

        Ok(())
    }

    /// As [`await_response`](Self::await_response), but a non-zero status
    /// is an error.
    async fn await_ok(&mut self, seq: u32) -> HsmResult<mailbox::Response> {
        let resp = self.await_response(seq).await?;
        if resp.status != 0 {
            return Err(PqcError::FP_ERROR);
        }
        Ok(resp)
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
            self.collected();
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
            self.collected();
            self.driver.release_engine(self.id);
        }
    }
}
