// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#![no_std]
#![allow(clippy::needless_range_loop)]

// Shared modules
pub mod keccak;
pub mod spill;

/// Zero `n` bytes at `p`, eight words per store.
///
/// The `memset` an array initialiser compiles to stores a word or two at a
/// time behind a compare and a branch. Signing creates about sixty-eight
/// sponge states per signature and each one clears 200 bytes, which is why
/// this is worth having rather than leaning on the array initialiser. The
/// app clears its request workspaces through it too.
///
/// # Safety
/// `p` must be valid for `n` writes and word aligned.
pub unsafe fn fast_zero(p: *mut u8, n: usize) {
    let mut q = p;
    let mut left = n;

    #[cfg(target_arch = "arm")]
    {
        let bursts = left / 32;
        if bursts != 0 {
            // r6/r7 are left out because the compiler reserves them.
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

// ML-DSA (FIPS 204)
pub mod dsa;

// ML-KEM (FIPS 203)
pub mod kem;

use dsa::params::MlDsaParams;
use dsa::params::N as DSA_N;
use keccak::shake256;
use keccak::shake256_init;

/// ML-DSA parameter set selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsaVariant {
    pub fn params(self) -> &'static MlDsaParams {
        match self {
            MlDsaVariant::MlDsa44 => &dsa::params::ML_DSA_44,
            MlDsaVariant::MlDsa65 => &dsa::params::ML_DSA_65,
            MlDsaVariant::MlDsa87 => &dsa::params::ML_DSA_87,
        }
    }

    pub fn pk_size(self) -> usize {
        self.params().pk_bytes()
    }
    pub fn sk_size(self) -> usize {
        self.params().sk_bytes()
    }
    pub fn sig_size(self) -> usize {
        self.params().sig_bytes()
    }
}

/// Number of polynomials in the ML-DSA work buffer.
///
/// Polynomials signing needs: `k` accumulators for `w = A*y`, plus room to
/// park the leading elements of `A` so they survive across attempts. Eight
/// covers the accumulators at every parameter set; the rest is cache, and
/// there is as much of it as the fastpath core's 32 KB of dTCM will carry
/// once signing's other working set is accounted for.
pub const DSA_WORK_POLYS: usize = 21;

/// Polynomials key generation and verification need: `l`, which is at most
/// seven. Neither caches the matrix -- they walk it once -- so neither pays
/// for signing's larger workspace.
pub const DSA_WORK_POLYS_SHORT: usize = 7;

/// DSA work buffer type: 21 polynomials × 256 coefficients × i32.
/// Allocate this in `.bss` (static) for constrained stacks, or on the stack
/// if you have ≥21 KiB available.
pub type DsaWorkBuf = [[i32; DSA_N]; DSA_WORK_POLYS];

// ================================================================
// Key Generation
// ================================================================

/// Generate an ML-DSA key pair.
/// `work` is a 7 KiB scratch buffer — pass a `&mut DsaWorkBuf`.
pub fn ml_dsa_keygen(
    variant: MlDsaVariant,
    xi: &[u8; 32],
    pk: &mut [u8],
    sk: &mut [u8],
    work: &mut [[i32; DSA_N]],
) {
    ml_dsa_keygen_guarded(variant, xi, pk, sk, work, || {});
}

/// As [`ml_dsa_keygen`], but writing nothing to `sk` before `before_sk`
/// returns, which is called once, after the first row of the matrix
/// product: a caller whose `sk` may still hold the previous key, being read
/// out, waits in it.
pub fn ml_dsa_keygen_guarded(
    variant: MlDsaVariant,
    xi: &[u8; 32],
    pk: &mut [u8],
    sk: &mut [u8],
    work: &mut [[i32; DSA_N]],
    before_sk: impl FnOnce(),
) {
    dsa::keygen::keygen_internal(variant.params(), xi, pk, sk, work, before_sk);
    let mut tr = [0u8; 64];
    shake256(&pk[..variant.params().pk_bytes()], &mut tr);
    sk[64..128].copy_from_slice(&tr);
}

// ================================================================
// External interface — pure ML-DSA (FIPS 204 Algorithm 2/3)
// ================================================================

/// Sign a message (external interface, pure mode).
pub fn ml_dsa_sign(
    variant: MlDsaVariant,
    sig: &mut [u8],
    msg: &[u8],
    ctx: &[u8],
    sk: &[u8],
    rnd: &[u8; 32],
    work: &mut DsaWorkBuf,
) -> bool {
    ml_dsa_sign_guarded(variant, sig, msg, ctx, sk, rnd, work, || {})
}

/// As [`ml_dsa_sign`], but reading nothing of `t0` -- the part of `sk`
/// after s2 -- before `before_t0` returns, which is called once, by the
/// first attempt to pass the norm checks: a caller whose `t0` may still be
/// arriving waits in it.
#[allow(clippy::too_many_arguments)]
pub fn ml_dsa_sign_guarded(
    variant: MlDsaVariant,
    sig: &mut [u8],
    msg: &[u8],
    ctx: &[u8],
    sk: &[u8],
    rnd: &[u8; 32],
    work: &mut DsaWorkBuf,
    before_t0: impl FnOnce(),
) -> bool {
    let p = variant.params();
    let tr = &sk[64..128];
    let mut mu = [0u8; 64];
    compute_mu_pure(&mut mu, tr, ctx, msg);
    dsa::sign::sign_internal(p, sig, &mu, sk, rnd, work, before_t0)
}

/// Verify a signature (external interface, pure mode).
pub fn ml_dsa_verify(
    variant: MlDsaVariant,
    msg: &[u8],
    sig: &[u8],
    ctx: &[u8],
    pk: &[u8],
    work: &mut [[i32; DSA_N]],
) -> bool {
    let p = variant.params();
    let mut tr = [0u8; 64];
    shake256(&pk[..p.pk_bytes()], &mut tr);
    let mut mu = [0u8; 64];
    compute_mu_pure(&mut mu, &tr, ctx, msg);
    dsa::verify::verify_internal(p, &mu, sig, pk, work)
}

// ================================================================
// Internal interface — caller provides mu directly
// ================================================================

/// Sign with pre-computed mu (internal interface, externalMu=true).
pub fn ml_dsa_sign_internal(
    variant: MlDsaVariant,
    sig: &mut [u8],
    mu: &[u8; 64],
    sk: &[u8],
    rnd: &[u8; 32],
    work: &mut DsaWorkBuf,
) -> bool {
    dsa::sign::sign_internal(variant.params(), sig, mu, sk, rnd, work, || {})
}

/// Verify with pre-computed mu (internal interface, externalMu=true).
pub fn ml_dsa_verify_internal(
    variant: MlDsaVariant,
    mu: &[u8; 64],
    sig: &[u8],
    pk: &[u8],
    work: &mut [[i32; DSA_N]],
) -> bool {
    dsa::verify::verify_internal(variant.params(), mu, sig, pk, work)
}

/// Sign with internal interface, externalMu=false.
pub fn ml_dsa_sign_internal_msg(
    variant: MlDsaVariant,
    sig: &mut [u8],
    msg: &[u8],
    sk: &[u8],
    rnd: &[u8; 32],
    work: &mut DsaWorkBuf,
) -> bool {
    let tr = &sk[64..128];
    let mut mu = [0u8; 64];
    compute_mu_internal(&mut mu, tr, msg);
    dsa::sign::sign_internal(variant.params(), sig, &mu, sk, rnd, work, || {})
}

/// Verify with internal interface, externalMu=false.
pub fn ml_dsa_verify_internal_msg(
    variant: MlDsaVariant,
    msg: &[u8],
    sig: &[u8],
    pk: &[u8],
    work: &mut [[i32; DSA_N]],
) -> bool {
    let p = variant.params();
    let mut tr = [0u8; 64];
    shake256(&pk[..p.pk_bytes()], &mut tr);
    let mut mu = [0u8; 64];
    compute_mu_internal(&mut mu, &tr, msg);
    dsa::verify::verify_internal(p, &mu, sig, pk, work)
}

// ================================================================
// mu computation helpers
// ================================================================

/// Pure ML-DSA's message representative: the public-key hash
/// `tr = H(pk)` of `pk`, then `mu = H(tr || 0 || |ctx| || ctx || msg)`.
pub fn ml_dsa_mu(variant: MlDsaVariant, pk: &[u8], ctx: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut tr = [0u8; 64];
    shake256(&pk[..variant.params().pk_bytes()], &mut tr);
    let mut mu = [0u8; 64];
    compute_mu_pure(&mut mu, &tr, ctx, msg);
    mu
}

/// Pure mode: mu = SHAKE256(tr || 0x00 || len(ctx) || ctx || msg)
fn compute_mu_pure(mu: &mut [u8; 64], tr: &[u8], ctx: &[u8], msg: &[u8]) {
    let mut hctx = shake256_init();
    hctx.absorb(tr);
    let prefix = [0x00, ctx.len() as u8];
    hctx.absorb(&prefix);
    hctx.absorb(ctx);
    hctx.absorb(msg);
    hctx.finalize();
    hctx.squeeze(mu);
}

/// Internal mode (externalMu=false): mu = SHAKE256(tr || msg)
fn compute_mu_internal(mu: &mut [u8; 64], tr: &[u8], msg: &[u8]) {
    let mut hctx = shake256_init();
    hctx.absorb(tr);
    hctx.absorb(msg);
    hctx.finalize();
    hctx.squeeze(mu);
}

// ================================================================
// ML-KEM (FIPS 203)
// ================================================================

/// ML-KEM parameter set selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl MlKemVariant {
    pub fn params(self) -> &'static kem::params::MlKemParams {
        match self {
            MlKemVariant::MlKem512 => &kem::params::ML_KEM_512,
            MlKemVariant::MlKem768 => &kem::params::ML_KEM_768,
            MlKemVariant::MlKem1024 => &kem::params::ML_KEM_1024,
        }
    }
    pub fn pk_size(self) -> usize {
        self.params().pk_bytes()
    }
    pub fn sk_size(self) -> usize {
        self.params().sk_bytes()
    }
    pub fn ct_size(self) -> usize {
        self.params().ct_bytes()
    }
}

/// ML-KEM key generation.
/// `d` and `z` are 32 bytes of randomness each.
pub fn ml_kem_keygen(
    variant: MlKemVariant,
    d: &[u8; 32],
    z: &[u8; 32],
    ek: &mut [u8],
    dk: &mut [u8],
) {
    kem::mlkem::mlkem_keygen(variant.params(), d, z, ek, dk);
}

/// ML-KEM encapsulation.
/// `m` is 32 bytes of randomness.
/// Returns shared secret in `ss` and ciphertext in `ct`.
pub fn ml_kem_encaps(
    variant: MlKemVariant,
    ss: &mut [u8; 32],
    ct: &mut [u8],
    ek: &[u8],
    m: &[u8; 32],
) {
    kem::mlkem::mlkem_encaps(variant.params(), ss, ct, ek, m);
}

/// ML-KEM decapsulation.
/// Returns shared secret in `ss`.
pub fn ml_kem_decaps(variant: MlKemVariant, ss: &mut [u8; 32], ct: &[u8], dk: &[u8]) {
    kem::mlkem::mlkem_decaps(variant.params(), ss, ct, dk);
}
