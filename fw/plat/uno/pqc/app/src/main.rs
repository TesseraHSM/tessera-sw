// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TSRA fastpath (FP) firmware.
//!
//! Bring-up skeleton: one image is built and loaded into all three FP
//! cores, where it starts an Embassy executor on the SysTick time base and
//! services the SP core-liveliness heartbeat. There is no FP workload yet.
//!
//! # Per-core identity
//!
//! The three cores need to differ at runtime -- each will own its own IPC
//! descriptor pair and INTC block -- but they run one compiled image.
//!
//! Identity is therefore *patched into the image after linking*: the build
//! produces one binary, then `make_fp.sh` stamps a core number into a copy
//! of it per core.  See [`FP_IDENTITY`].
//!
//! The alternative, self-identification at runtime, is possible in
//! principle -- a core could write a sentinel to its dTCM and look for it
//! through the global aliases at `0xA300_0000 + 0x20_0000 * n` -- but it
//! relies on a core being able to read its own dTCM back through the SoC
//! interconnect, which is not established.  With no console on FP, a wrong
//! guess there fails silently.

#![no_std]
#![no_main]

mod crash;
mod ipc;
mod mailbox;
mod shared_status;

use core::ptr::addr_of;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

use tsra_fw_uno_drivers_systick as systick;
use embassy_executor::Spawner;
use embassy_time::Duration;
use embassy_time::Timer;

/// Number of fastpath cores.
const FP_CORES: u8 = 3;

/// Marker `make_fp.sh` searches for to locate [`FP_IDENTITY`] in the linked
/// binary.  Must appear exactly once in the image; the build fails if it
/// does not.
const FP_IDENTITY_MAGIC: [u8; 8] = *b"FPIDENT0";

/// Value the core id holds before patching.  A core that still sees this
/// has been loaded from an unpatched image and must not run: it would
/// otherwise collide with another core on the IPC descriptors it picks.
const FP_ID_UNPATCHED: u8 = 0xFF;

/// Per-core identity, stamped into the image after linking.
///
/// `make_fp.sh` finds [`FP_IDENTITY_MAGIC`] in the linked binary and writes
/// the core number into the byte that follows it, producing one image per
/// core from a single compilation.
#[repr(C)]
struct FpIdentity {
    /// Locates this block in the binary.
    magic: [u8; 8],

    /// 0, 1 or 2 once patched; [`FP_ID_UNPATCHED`] before.
    core_id: u8,

    /// Pads the block to 16 bytes, leaving room to stamp more per-core
    /// configuration later without moving `core_id`.
    _reserved: [u8; 7],
}

/// The identity block itself.
///
/// `#[used]` and `#[no_mangle]` keep it in the binary: nothing references
/// it at link time, so it would otherwise be dropped, and the patch step
/// would find no magic.
#[used]
#[no_mangle]
static FP_IDENTITY: FpIdentity = FpIdentity {
    magic: FP_IDENTITY_MAGIC,
    core_id: FP_ID_UNPATCHED,
    _reserved: [0; 7],
};

/// This core's id, cached once at boot.
static CORE_ID: AtomicU8 = AtomicU8::new(FP_ID_UNPATCHED);

/// Read the patched core id, or `None` if the image was never patched or
/// carries a nonsensical value.
fn read_core_id() -> Option<u8> {
    // Volatile: `FP_IDENTITY` is an immutable static, so a plain read would
    // be constant-folded to the pre-patch value and the patch ignored.
    let id = unsafe { core::ptr::read_volatile(addr_of!(FP_IDENTITY.core_id)) };
    (id < FP_CORES).then_some(id)
}

/// This core's id.  Valid once [`main`] has run.
pub fn core_id() -> u8 {
    CORE_ID.load(Ordering::Relaxed)
}

/// SP-polled core liveliness slot, in the DTCM window this core shares with
/// its ring neighbour.
///
/// The SP's SoC crash monitor reads this word about once a second and
/// zeroes it after each read; a core that leaves it at zero for a full poll
/// period is reported as hung. The address is the same in all three cores'
/// local views: the SP reaches it at `0xA302_3DDC` (FP0), `0xA322_3DDC`
/// (FP1) and `0xA342_3DDC` (FP2).
const CORE_RUN_STATUS: *mut u32 = 0x2002_3DDC as *mut u32;

/// Value the SP treats as "this core made forward progress".
const CORE_ALIVE: u32 = 1;

/// Heartbeat refresh period, comfortably faster than the SP's 1 s poll.
const HEARTBEAT_PERIOD: Duration = Duration::from_millis(250);

/// How often to look for an HSM doorbell.  Fast enough not to dominate a
/// PQC operation, slow enough to stay free.
const DOORBELL_POLL_PERIOD: Duration = Duration::from_millis(2);

/// How long to yield-poll the doorbell after servicing a request, before
/// dropping back to [`DOORBELL_POLL_PERIOD`].
///
/// `Timer::after` cannot sleep for less than one embassy tick and this core
/// runs `tick-hz-32`, so the 2 ms above is really 31.25 ms. A request could
/// therefore sit unnoticed for a full tick before the core even started
/// work — on operations that take 3–9 ms.
///
/// Yielding re-checks on every executor pass, so a request arriving while
/// this window is open is picked up almost immediately. The window is
/// bounded rather than infinite so an idle core eventually returns to the
/// timer instead of spinning forever: the heartbeat keeps running either
/// way, but a permanently spinning core burns power for nothing.
///
/// Expressed as a deadline rather than an iteration count so it does not
/// depend on how long one trip through the executor takes.
const DOORBELL_YIELD_WINDOW: Duration = Duration::from_millis(50);

/// Refreshes the SP-polled liveliness slot for the life of the firmware.
///
/// Runs as its own task so the heartbeat tracks executor forward progress
/// rather than any single workload.
#[embassy_executor::task]
async fn heartbeat() -> ! {
    loop {
        // SAFETY: `CORE_RUN_STATUS` is a 32-bit slot reserved for this
        // purpose by the SoC memory map. It lies outside every region
        // described to the linker, so no Rust object aliases it.
        unsafe { CORE_RUN_STATUS.write_volatile(CORE_ALIVE) };

        Timer::after(HEARTBEAT_PERIOD).await;
    }
}

/// Service PQC requests from the HSM.
///
/// The doorbell only wakes this task; the request itself is read from
/// this core's PSRAM mailbox, and the response written back there. The
/// doorbell is still answered so the HSM can distinguish a core that is
/// running from one that is wedged.
///
/// Polled rather than interrupt-driven; see [`ipc`].
#[embassy_executor::task]
async fn doorbell(core_id: u8) -> ! {
    // Publish a marker immediately so a task that never starts is
    // distinguishable from one that starts but sees nothing.
    shared_status::note_doorbell(core_id, 0);

    // End of the current fast window, reset on every serviced request so a
    // stream of work stays on the fast path.
    let mut yield_until = embassy_time::Instant::now();

    loop {
        if let Some(ring) = ipc::take_request(core_id) {
            shared_status::note_doorbell(core_id, ring);

            if let Some(req) = mailbox::take_request(core_id) {
                service(core_id, &req);
            }

            ipc::ring_response(core_id, ring.wrapping_add(1));
            yield_until = embassy_time::Instant::now() + DOORBELL_YIELD_WINDOW;
            continue;
        }

        if embassy_time::Instant::now() < yield_until {
            embassy_futures::yield_now().await;
        } else {
            Timer::after(DOORBELL_POLL_PERIOD).await;
        }
    }
}

/// Produce a response for `req`.
///
/// Runs real ML-DSA key generation from the seed the HSM supplied, writing
/// the public key straight into this core's operand slot.
///
fn service(core_id: u8, req: &mailbox::Request) {
    // ML-KEM carries its own key kinds, so route on the operation first.
    if matches!(
        req.op,
        mailbox::OP_MLKEM_GENERATE_KEY
            | mailbox::OP_MLKEM_ENCAPSULATE
            | mailbox::OP_MLKEM_DECAPSULATE
    ) {
        let Some(variant) = mlkem_variant(req.key_kind) else {
            mailbox::respond(core_id, req, mailbox::STATUS_UNSUPPORTED_KIND, 0);
            return;
        };
        match req.op {
            mailbox::OP_MLKEM_GENERATE_KEY => service_mlkem_keygen(core_id, req, variant),
            mailbox::OP_MLKEM_ENCAPSULATE => service_mlkem_encaps(core_id, req, variant),
            _ => service_mlkem_decaps(core_id, req, variant),
        }
        return;
    }

    let Some(variant) = mldsa_variant(req.key_kind) else {
        mailbox::respond(core_id, req, mailbox::STATUS_UNSUPPORTED_KIND, 0);
        return;
    };

    match req.op {
        mailbox::OP_MLDSA_GENERATE_KEY => service_keygen(core_id, req, variant),
        mailbox::OP_MLDSA_SIGN => service_sign(core_id, req, variant),
        mailbox::OP_MLDSA_VERIFY => service_verify(core_id, req, variant),
        _ => mailbox::respond(core_id, req, mailbox::STATUS_UNSUPPORTED_OP, 0),
    }
}

/// Derive an ML-KEM key pair from the supplied `(d, z)` seed pair,
/// publishing both the encapsulation and decapsulation keys.
///
/// The two 32-byte seed fields carry `d` and `z`. The decapsulation key
/// travels back to the HSM, which masks it alongside the seeds so
/// decapsulation never has to re-derive it.
#[inline(never)]
fn service_mlkem_keygen(core_id: u8, req: &mailbox::Request, variant: pqc_ml::MlKemVariant) {
    let ek_len = variant.pk_size();
    let dk_len = variant.sk_size();

    let mut scratch = [0u8; KEM_DK_LEN];
    if dk_len > scratch.len() {
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    }

    // Generate the decapsulation key into dTCM and copy it out in one go,
    // rather than letting the packing write PSRAM directly.
    //
    // Unlike ML-DSA, `dk = (dk_pke || ek || H(ek) || z)` is assembled from
    // several small pieces, and PSRAM is slow enough per access that those
    // scattered writes cost more than one bulk copy: writing it in place
    // measured 4-6% *worse* across all three parameter sets.
    {
        let Some(ek) = mailbox::slot_range_mut(core_id, mailbox::SLOT_PK_OFFSET, ek_len) else {
            mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
            return;
        };
        pqc_ml::ml_kem_keygen(variant, &req.xi, &req.rnd, ek, &mut scratch[..dk_len]);
    }

    let Some(dk_out) = mailbox::slot_range_mut(core_id, mailbox::SLOT_KEY_OUT_OFFSET, dk_len)
    else {
        scratch[..dk_len].fill(0);
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    };
    dk_out.copy_from_slice(&scratch[..dk_len]);

    // Do not leave key material in dTCM for the next request to find.
    scratch[..dk_len].fill(0);

    mailbox::respond(core_id, req, mailbox::STATUS_OK, ek_len as u32);
}

/// Encapsulate to the public key staged in the operand slot.
///
/// Produces a ciphertext and a shared secret; both are outputs, and the
/// only input besides the public key is the 32 bytes of randomness the HSM
/// supplied in the first seed field.
#[inline(never)]
fn service_mlkem_encaps(core_id: u8, req: &mailbox::Request, variant: pqc_ml::MlKemVariant) {
    let ek_len = variant.pk_size();
    let ct_len = variant.ct_size();

    if req.pub_key_len != ek_len {
        mailbox::respond(core_id, req, mailbox::STATUS_UNSUPPORTED_KIND, 0);
        return;
    }

    // Copy the public key out of the slot before writing outputs back into
    // it: the regions are disjoint, but holding a shared and a mutable
    // borrow of the same slot at once would not be.
    let mut ek = Align4([0u8; MAX_MLKEM_PK_LEN]);
    let ek = &mut ek.0;
    let Some(src) = mailbox::slot_range(core_id, mailbox::SLOT_PK_OFFSET, ek_len) else {
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    };
    mailbox::stage(&mut ek[..ek_len], src);

    let mut ss = [0u8; mailbox::SHARED_SECRET_LEN];
    {
        let Some(ct) = mailbox::slot_range_mut(core_id, mailbox::SLOT_CT_OFFSET, ct_len) else {
            mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
            return;
        };
        pqc_ml::ml_kem_encaps(variant, &mut ss, ct, &ek[..ek_len], &req.xi);
    }

    let Some(out) =
        mailbox::slot_range_mut(core_id, mailbox::SLOT_SS_OFFSET, mailbox::SHARED_SECRET_LEN)
    else {
        ss.fill(0);
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    };
    out.copy_from_slice(&ss);

    // The shared secret is key material; the copy in the slot is the one
    // the HSM reads, so do not leave a second on the stack.
    ss.fill(0);

    mailbox::respond(core_id, req, mailbox::STATUS_OK, ct_len as u32);
}

/// Decapsulate the ciphertext staged in the operand slot.
///
/// The caller supplies the **expanded decapsulation key**, staged in the
/// slot, so no key derivation happens here. Deriving it from the seed pair
/// instead used to dominate this operation: a full ML-KEM key generation
/// per decapsulation, roughly 3.6 ms of ML-KEM-1024's 5.3 ms.
#[inline(never)]
fn service_mlkem_decaps(core_id: u8, req: &mailbox::Request, variant: pqc_ml::MlKemVariant) {
    let dk_len = variant.sk_size();
    let ct_len = variant.ct_size();

    if req.sig_len != ct_len {
        mailbox::respond(core_id, req, mailbox::STATUS_UNSUPPORTED_KIND, 0);
        return;
    }

    // Stage both inputs into dTCM rather than reading them out of the slot
    // in place. Decapsulation re-derives the whole key pair and unpacks the
    // key into polynomials, so neither input is read only once, and PSRAM
    // is slow enough per access that one bulk copy beats repeated reads.
    //
    // The same effect showed up the other way round in ML-KEM key
    // generation, where letting the packing write PSRAM directly measured
    // 4-6% worse than staging.
    //
    let mut scratch = Align4([0u8; KEM_CT_PLUS_DK_LEN]);
    let scratch = &mut scratch.0;

    let Some(staged_len) = ct_len.checked_add(dk_len).filter(|n| *n <= scratch.len()) else {
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    };

    {
        let (Some(ct_src), Some(dk_src)) = (
            mailbox::slot_range(core_id, mailbox::SLOT_CT_IN_OFFSET, ct_len),
            mailbox::slot_range(core_id, mailbox::SLOT_KEY_IN_OFFSET, dk_len),
        ) else {
            mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
            return;
        };

        mailbox::stage(&mut scratch[..ct_len], ct_src);
        mailbox::stage(&mut scratch[ct_len..staged_len], dk_src);
    }

    let (ct, dk) = scratch[..staged_len].split_at(ct_len);

    let mut ss = [0u8; mailbox::SHARED_SECRET_LEN];
    pqc_ml::ml_kem_decaps(variant, &mut ss, ct, dk);

    // Do not leave key material in dTCM for the next request to find.
    scratch[..staged_len].fill(0);

    let Some(out) =
        mailbox::slot_range_mut(core_id, mailbox::SLOT_SS_OFFSET, mailbox::SHARED_SECRET_LEN)
    else {
        ss.fill(0);
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    };
    out.copy_from_slice(&ss);
    ss.fill(0);

    mailbox::respond(
        core_id,
        req,
        mailbox::STATUS_OK,
        mailbox::SHARED_SECRET_LEN as u32,
    );
}

/// Largest ML-KEM encapsulation key (ML-KEM-1024).
const MAX_MLKEM_PK_LEN: usize = 1568;

/// Word-aligned byte buffer.
///
/// The staging buffers are `[u8; N]`, whose alignment is 1, and
/// [`mailbox::stage`] can only burst when both sides are word aligned.
/// Wrapping them makes the fast path reachable instead of silently
/// falling back to a byte-wise copy.
#[repr(align(4))]
struct Align4<const N: usize>([u8; N]);

/// Zero `n` bytes at `p`, eight words per store.
///
/// `compiler_builtins`' `memset` runs `stmia rd!, {r4}` behind a compare
/// and two branches -- four instructions per word -- and every fastpath
/// request clears tens of kilobytes of scratch before any crypto runs: a
/// signature spends about 20 K cycles on its 25 KB workspace, which is
/// 0.4% of the operation. LTO internalises that symbol, so a strong
/// definition cannot replace it and the buffers are cleared through here
/// instead.
///
/// r6/r7 are left out of the register list because the compiler reserves
/// them. The tail is volatile so LLVM cannot turn it back into a `memset`
/// call into itself.
///
/// # Safety
/// `p` must be valid for `n` writes and word aligned.
unsafe fn fast_zero(p: *mut u8, n: usize) {
    let mut q = p;
    let mut left = n;

    #[cfg(target_arch = "arm")]
    {
        let bursts = left / 32;
        if bursts != 0 {
            core::arch::asm!(
                "2:",
                "stmia {d}!, {{r0, r1, r2, r3, r4, r5, r8, r9}}",
                "subs  {n}, {n}, #1",
                "bne   2b",
                d = inout(reg) q,
                n = inout(reg) bursts => _,
                in("r0") 0, in("r1") 0, in("r2") 0, in("r3") 0,
                in("r4") 0, in("r5") 0, in("r8") 0, in("r9") 0,
                options(nostack),
            );
            left -= bursts * 32;
        }
    }

    while left != 0 {
        core::ptr::write_volatile(q, 0);
        q = q.add(1);
        left -= 1;
    }
}

/// Map a `HsmVaultKeyKind` discriminant onto an ML-KEM parameter set.
fn mlkem_variant(key_kind: u32) -> Option<pqc_ml::MlKemVariant> {
    // These are `HsmVaultKeyKind` discriminants, arriving as a raw u32 over
    // the mailbox. The FP app is a standalone binary and does not link the
    // PAL traits crate, so the values are mirrored here by hand: keep them
    // in step with `HsmVaultKeyKind` in fw/pal/traits/src/vault.rs.
    match key_kind {
        55 => Some(pqc_ml::MlKemVariant::MlKem512),
        56 => Some(pqc_ml::MlKemVariant::MlKem768),
        57 => Some(pqc_ml::MlKemVariant::MlKem1024),
        _ => None,
    }
}

/// Derive a key pair from the supplied seed, publishing the public key.
#[inline(never)]
fn service_keygen(core_id: u8, req: &mailbox::Request, variant: pqc_ml::MlDsaVariant) {
    let params = variant.params();
    let pk_len = params.pk_bytes();
    let sk_len = params.sk_bytes();

    // SAFETY: written in full by `fast_zero` before any read.
    let mut work = core::mem::MaybeUninit::<[[i32; 256]; pqc_ml::DSA_WORK_POLYS_SHORT]>::uninit();
    let work = unsafe {
        fast_zero(
            work.as_mut_ptr().cast(),
            core::mem::size_of::<[[i32; 256]; pqc_ml::DSA_WORK_POLYS_SHORT]>(),
        );
        &mut work.assume_init_mut()[..]
    };

    // Both keys are written straight into their slot regions. Taking the
    // two borrows together is what makes that possible; staging the secret
    // key through dTCM would cost a copy back plus a wipe of the staging
    // buffer, and would leave key material in dTCM in between.
    //
    // The expanded secret key travels back to the HSM, which masks it
    // alongside the seed so signing never has to re-derive it.
    let Some((pk, sk_out)) = mailbox::slot_pair_mut(
        core_id,
        mailbox::SLOT_PK_OFFSET,
        pk_len,
        mailbox::SLOT_KEY_OUT_OFFSET,
        sk_len,
    ) else {
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    };

    pqc_ml::ml_dsa_keygen(variant, &req.xi, pk, sk_out, work);

    mailbox::respond(core_id, req, mailbox::STATUS_OK, pk_len as u32);
}

/// Sign the message staged in the operand slot.
///
/// The caller supplies the **expanded secret key**, staged in the slot, so
/// no key derivation happens here. Deriving it from the seed instead used
/// to cost a full key generation per signature — 8.51 ms of ML-DSA-87's
/// 24.5 ms floor.
///
/// The key overlaps the region the signature goes back into, so one of the
/// two has to be staged in dTCM. It is the signature: at up to 4627 bytes
/// it is the smaller of the pair, and staging it costs nothing extra
/// because signing already needs a buffer of exactly that shape to hold the
/// mask stream between the commitment and z passes. The key is then read
/// where it lies, and this core never takes a copy of it to wipe.
#[inline(never)]
fn service_sign(core_id: u8, req: &mailbox::Request, variant: pqc_ml::MlDsaVariant) {
    let params = variant.params();
    let sk_len = params.sk_bytes();
    let sig_len = params.sig_bytes();

    // Cleared through `fast_zero` rather than the array initialiser: the
    // compiler's `memset` costs about 20 K cycles on these 25 KB, ahead of
    // any crypto.
    //
    // SAFETY: both are written in full by `fast_zero` before any read.
    let mut work = core::mem::MaybeUninit::<pqc_ml::DsaWorkBuf>::uninit();
    let mut sig_buf = core::mem::MaybeUninit::<Align4<DSA_SIG_LEN>>::uninit();
    let (work, sig_buf) = unsafe {
        fast_zero(
            work.as_mut_ptr().cast(),
            core::mem::size_of::<pqc_ml::DsaWorkBuf>(),
        );
        fast_zero(
            sig_buf.as_mut_ptr().cast(),
            core::mem::size_of::<Align4<DSA_SIG_LEN>>(),
        );
        (work.assume_init_mut(), &mut sig_buf.assume_init_mut().0)
    };

    let ok = {
        let (Some(sk), Some(msg), Some(ctx)) = (
            mailbox::slot_range(core_id, mailbox::SLOT_KEY_IN_OFFSET, sk_len),
            mailbox::slot_range(core_id, mailbox::SLOT_MSG_OFFSET, req.msg_len),
            mailbox::slot_range(core_id, mailbox::SLOT_CTX_OFFSET, req.ctx_len),
        ) else {
            mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
            return;
        };

        pqc_ml::ml_dsa_sign(
            variant,
            &mut sig_buf[..sig_len],
            msg,
            ctx,
            sk,
            &req.rnd,
            work,
        )
    };

    if !ok {
        mailbox::respond(core_id, req, mailbox::STATUS_CRYPTO_FAILED, 0);
        return;
    }

    // Only now, with the key no longer being read, does the slot region it
    // shares with the signature get written.
    let Some(sig) = mailbox::slot_range_mut(core_id, mailbox::SLOT_SIG_OFFSET, sig_len) else {
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    };
    sig.copy_from_slice(&sig_buf[..sig_len]);

    mailbox::respond(core_id, req, mailbox::STATUS_OK, sig_len as u32);
}

/// Verify a signature under the supplied public key.
///
/// Every operand is an input, so all four are borrowed straight out of the
/// slot with no copying -- unlike sign, where the output aliases the same
/// slot and the inputs have to be staged first.
///
/// A bad signature is reported as `STATUS_CRYPTO_FAILED`, which the HSM
/// turns into `MlDsaVerifyFailed`. It is an ordinary outcome, not a fault:
/// the distinction matters because a caller who ignored the result must not
/// be able to treat an invalid signature as valid.
#[inline(never)]
fn service_verify(core_id: u8, req: &mailbox::Request, variant: pqc_ml::MlDsaVariant) {
    let params = variant.params();
    if req.pub_key_len != params.pk_bytes() || req.sig_len != params.sig_bytes() {
        mailbox::respond(core_id, req, mailbox::STATUS_UNSUPPORTED_KIND, 0);
        return;
    }

    let (Some(msg), Some(ctx), Some(sig_src), Some(pk_src)) = (
        mailbox::slot_range(core_id, mailbox::SLOT_MSG_OFFSET, req.msg_len),
        mailbox::slot_range(core_id, mailbox::SLOT_CTX_OFFSET, req.ctx_len),
        mailbox::slot_range(core_id, mailbox::SLOT_SIG_OFFSET, req.sig_len),
        mailbox::slot_range(core_id, mailbox::SLOT_PK_OFFSET, req.pub_key_len),
    ) else {
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    };

    // Stage the signature and public key into dTCM. Both are unpacked into
    // polynomials and read repeatedly, and PSRAM costs enough per access
    // that one bulk copy wins -- the same trade that made decapsulation
    // ~4.5% faster. The message and context are read once and stay in
    // place. Neither staging buffer is otherwise in use during a verify.
    //
    // Word aligned so `mailbox::stage` can burst rather than fall back.
    //
    // SAFETY: as elsewhere, one operation in flight per core.
    // SAFETY: all three are written in full by `fast_zero` before any read;
    // see it for why the array initialiser is not used.
    let mut pk_buf = core::mem::MaybeUninit::<Align4<DSA_PK_LEN>>::uninit();
    let mut sig_buf = core::mem::MaybeUninit::<Align4<DSA_SIG_LEN>>::uninit();
    let (sig_buf, pk_buf) = unsafe {
        fast_zero(
            sig_buf.as_mut_ptr().cast(),
            core::mem::size_of::<Align4<DSA_SIG_LEN>>(),
        );
        fast_zero(
            pk_buf.as_mut_ptr().cast(),
            core::mem::size_of::<Align4<DSA_PK_LEN>>(),
        );
        (
            &mut sig_buf.assume_init_mut().0,
            &mut pk_buf.assume_init_mut().0,
        )
    };

    if sig_src.len() > sig_buf.len() || pk_src.len() > pk_buf.len() {
        mailbox::respond(core_id, req, mailbox::STATUS_SLOT_TOO_SMALL, 0);
        return;
    }

    let sig = &mut sig_buf[..sig_src.len()];
    let pk = &mut pk_buf[..pk_src.len()];
    mailbox::stage(sig, sig_src);
    mailbox::stage(pk, pk_src);

    // SAFETY: see `service_keygen` -- one operation in flight per core, so
    // the scratch cannot be aliased.
    // SAFETY: written in full by `fast_zero` before any read.
    let mut work = core::mem::MaybeUninit::<[[i32; 256]; pqc_ml::DSA_WORK_POLYS_SHORT]>::uninit();
    let work = unsafe {
        fast_zero(
            work.as_mut_ptr().cast(),
            core::mem::size_of::<[[i32; 256]; pqc_ml::DSA_WORK_POLYS_SHORT]>(),
        );
        &mut work.assume_init_mut()[..]
    };

    let verified = pqc_ml::ml_dsa_verify(variant, msg, sig, ctx, pk, work);

    if verified {
        mailbox::respond(core_id, req, mailbox::STATUS_OK, 0);
    } else {
        mailbox::respond(core_id, req, mailbox::STATUS_CRYPTO_FAILED, 0);
    }
}

// Operand and work buffers live on the **stack**, not in `.bss`.
//
// They are all short-lived: each is used within one `service_*` call and
// never across calls. As statics they were reserved permanently and
// simultaneously, so `.bss` paid the *sum* of every buffer (16,691 B)
// even though no two operations ever run at once on a core. On the stack
// each frame is reclaimed on return, so the cost is the *maximum* any one
// operation needs — 14,387 B, for verify.
//
// dTCM is 32 KB and the stack is whatever `.bss` leaves, so this is not a
// wash: it moved `.bss` from 19,160 B to about 2.5 KB and roughly doubled
// the stack. That headroom is what lets the ML-DSA signing path, whose
// stack requirement grew from 7 KiB to 14 KiB when it started caching `w`
// across rejection attempts, fit at all.
//
// **There is no stack guard**: overflow corrupts `.bss` silently rather
// than faulting. Keep the largest claim below in view when adding to it.
//
// | Operation | Live buffers | Bytes |
// |---|---|---|
// | ML-DSA keygen | work | 7,168 |
// | ML-DSA sign | work + secret key | 12,064 |
// | ML-DSA verify | work + signature + public key | 14,387 |
// | ML-KEM decapsulate | ciphertext + decapsulation key | 4,736 |

/// ML-DSA signature (ML-DSA-87), the largest of the three parameter sets.
const DSA_SIG_LEN: usize = 4627;

/// ML-DSA public key (ML-DSA-87).
const DSA_PK_LEN: usize = 2592;

/// ML-KEM decapsulation key (ML-KEM-1024).
const KEM_DK_LEN: usize = 3168;

/// ML-KEM ciphertext (ML-KEM-1024).
const KEM_CT_LEN: usize = 1568;

/// Decapsulation stages ciphertext and key together in one buffer.
const KEM_CT_PLUS_DK_LEN: usize = KEM_CT_LEN + KEM_DK_LEN;

/// Map a `HsmVaultKeyKind` discriminant onto an ML-DSA parameter set.
fn mldsa_variant(key_kind: u32) -> Option<pqc_ml::MlDsaVariant> {
    // `HsmVaultKeyKind` discriminants mirrored by hand -- see the note on
    // `mlkem_variant` above.
    match key_kind {
        46 => Some(pqc_ml::MlDsaVariant::MlDsa44),
        47 => Some(pqc_ml::MlDsaVariant::MlDsa65),
        48 => Some(pqc_ml::MlDsaVariant::MlDsa87),
        _ => None,
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Establish identity before anything else. A core that cannot -- an
    // unpatched or corrupt image -- parks instead of running, so it stops
    // heartbeating and the SP reports it. That turns the SP's existing
    // liveliness check into the verification for the patch step, which is
    // the only signal available: FP has no console.
    let Some(id) = read_core_id() else {
        park();
    };
    CORE_ID.store(id, Ordering::Relaxed);

    // The signer spills the part of the ML-DSA matrix that will not fit in
    // dTCM to GSRAM. The SP fences 0x611D0000 for the fastpath initiators
    // and each core takes its own third of it; nothing is shared between
    // cores, so no locking is involved.
    //
    // This address is duplicated rather than imported: the register crate
    // that carries it (`tsra_fw_uno_reg_soc::fp_dsa_cache_t`) lives in
    // the `fw` workspace, and depending on it from `fp` drags that
    // workspace's dependency tree into a build with a different target.
    // Three places therefore have to agree, and nothing checks them:
    //
    //   * here,
    //   * `FP_DSA_CACHE` in fw/plat/uno/rdl/soc/gsram_map.rdl (0x1D0000),
    //   * `rsvd_fp_dsa_cache` in cp/hsm/mem-map/src/gsram.rs, which also
    //     pins it with a const_assert,
    //
    // Moving the window means moving all three. The key vault sits directly
    // below and is sized to end before it; letting the vault grow back over
    // this region is what the RDL declaration is there to prevent.
    //
    // SAFETY: called once, before any request can be serviced, with a
    // region this core alone owns.
    unsafe {
        const FP_SPILL_BASE: usize = 0x611D_0000;
        // Exactly what one core needs: ML-DSA-87 spills 44 of its 56 matrix
        // elements, packed three bytes to a coefficient, plus 23 key-derived
        // transforms held unpacked. No parameter set needs more. The stride
        // used to be 0x1B000, of which 41 KB per core was never addressable.
        const FP_SPILL_PER_CORE: usize = 0xE000;
        const FP_SPILL_WORDS: usize = FP_SPILL_PER_CORE / 4;
        pqc_ml::spill::init(
            (FP_SPILL_BASE + id as usize * FP_SPILL_PER_CORE) as *mut i32,
            FP_SPILL_WORDS,
        );
    }

    systick::init();

    mailbox::cyc_init();

    if let Ok(token) = heartbeat() {
        spawner.spawn(token);
    }

    if let Ok(token) = shared_status::status_task(id, HEARTBEAT_PERIOD) {
        spawner.spawn(token);
    }

    ipc::init(id);
    if let Ok(token) = doorbell(id) {
        spawner.spawn(token);
    }

    loop {
        Timer::after(Duration::from_secs(1)).await;
    }
}

/// Stop this core permanently, leaving the heartbeat slot untouched so the
/// SP notices.
pub(crate) fn park() -> ! {
    loop {
        cortex_m::asm::wfi();
    }
}

/// A panic leaves the same record a fault does.
///
/// The panic site is deliberately *not* recorded: reading
/// `PanicInfo::location` forces every panic site's file-name string to be
/// retained, which costs 3.7 KB of a 32 KB iTCM. Knowing that a core
/// panicked rather than faulted, and how much stack was left when it did,
/// is worth far more here than knowing which line it was.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    crash::record(crash::KIND_PANIC, 0, 0, crash::sp());
    park()
}
