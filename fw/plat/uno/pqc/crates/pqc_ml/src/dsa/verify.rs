// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::ntt;
use super::packing;
/// ML-DSA Verification (FIPS 204 Algorithm 3 / Internal Algorithm 8).
///
/// Stack-optimized: z_hat lives in caller-provided workspace; hints unpacked per-poly.
use super::params::MlDsaParams;
/// ML-DSA Verification (FIPS 204 Algorithm 3 / Internal Algorithm 8).
///
/// Stack-optimized: z_hat lives in caller-provided workspace; hints unpacked per-poly.
use super::params::N;
use super::poly::Poly;
use super::poly::{self};
use super::rounding;
use super::sampling;
use crate::keccak::shake256_init;

/// -2^d * 2^32 mod q: c_hat's Montgomery product with it is c_hat * -2^d.
const NEG_2D_MONT: i64 = 4165636;

pub fn verify_internal(
    params: &MlDsaParams,
    mu: &[u8; 64],
    sig: &[u8],
    pk: &[u8],
    work: &mut [[i32; N]],
) -> bool {
    let k = params.k as usize;
    let l = params.l as usize;
    let ctilde_len = params.ctilde_bytes as usize;

    if sig.len() < params.sig_bytes() {
        return false;
    }

    let rho = &pk[0..32];
    let ctilde = &sig[0..ctilde_len];

    // z_hat lives in caller-provided workspace
    let z_hat = work;
    let mut sig_offset = ctilde_len;
    for j in 0..l {
        packing::unpack_z(&mut z_hat[j], &sig[sig_offset..], params.gamma1);
        sig_offset += params.z_pack_bytes();

        if !poly::poly_chknorm(&z_hat[j], params.gamma1 - params.beta) {
            return false;
        }
        // NTT in-place: now z_hat[j] is ready for pointwise multiply
        ntt::ntt(&mut z_hat[j]);
    }

    // Validate hint encoding (without unpacking all k polys)
    let hint_sig = &sig[sig_offset..sig_offset + params.omega as usize + k];
    if !validate_hints(hint_sig, k, params.omega) {
        return false;
    }

    // Reconstruct challenge, scaled by -2^d: then each row's c * t1 * 2^d
    // comes off as one multiply-accumulate on t1's own transform, with no
    // shift, product or subtraction pass of its own.
    let mut c_hat: Poly = [0i32; N];
    sampling::poly_challenge(&mut c_hat, ctilde, params.tau);
    ntt::ntt(&mut c_hat);
    for x in c_hat.iter_mut() {
        *x = ntt::montgomery_reduce(*x as i64 * NEG_2D_MONT);
    }

    // Compute w'_i = A*z_hat - c*t1*2^d for each i, apply UseHint, hash
    let mut commit_ctx = shake256_init();
    commit_ctx.absorb(mu);

    let mut a_ij: Poly = [0i32; N];
    let mut w_prime: Poly = [0i32; N];
    let mut t1_poly: Poly = [0i32; N];
    let mut tmp: Poly = [0i32; N];
    let mut w1_packed_buf = [0u8; 192];

    for i in 0..k {
        for j in 0..l {
            sampling::poly_uniform(&mut a_ij, rho, i as u8, j as u8);
            if j == 0 {
                ntt::poly_pointwise_montgomery(&mut w_prime, &a_ij, &z_hat[0]);
            } else {
                ntt::poly_pointwise_acc_montgomery(&mut w_prime, &a_ij, &z_hat[j]);
            }
        }

        packing::unpack_t1(&mut t1_poly, &pk[32 + i * 320..]);
        ntt::ntt(&mut t1_poly);
        ntt::poly_pointwise_acc_montgomery(&mut w_prime, &c_hat, &t1_poly);
        ntt::invntt(&mut w_prime);

        // HighBits straight off the transform, as signing does: w1 into
        // tmp and w0 into t1_poly, which is done with until the next row.
        // UseHint then needs only the parts at the hinted positions rather
        // than a fresh decomposition of each.
        rounding::poly_decompose_reduced(&mut tmp, &mut t1_poly, &w_prime, params.gamma2);
        let hint_start = if i == 0 {
            0
        } else {
            hint_sig[params.omega as usize + i - 1] as usize
        };
        let hint_end = hint_sig[params.omega as usize + i] as usize;
        for j in hint_start..hint_end {
            let idx = hint_sig[j] as usize;
            tmp[idx] = rounding::use_hint_parts(tmp[idx], t1_poly[idx], params.gamma2);
        }

        let w1_bytes = params.w1_pack_bytes();
        packing::pack_w1(&mut w1_packed_buf[..w1_bytes], &tmp, params.gamma2);
        commit_ctx.absorb(&w1_packed_buf[..w1_bytes]);
    }

    // Recompute c_tilde' and compare
    commit_ctx.finalize();
    let mut ctilde_prime = [0u8; 64];
    commit_ctx.squeeze(&mut ctilde_prime[..ctilde_len]);

    let mut diff = 0u8;
    for i in 0..ctilde_len {
        diff |= ctilde[i] ^ ctilde_prime[i];
    }
    diff == 0
}

/// Validate the hint encoding without allocating k polynomials.
fn validate_hints(buf: &[u8], k: usize, omega: u8) -> bool {
    let mut prev = 0u8;
    for i in 0..k {
        let limit = buf[omega as usize + i];
        if limit < prev || limit > omega {
            return false;
        }
        // Check indices are strictly increasing within each polynomial
        for j in prev..limit {
            if buf[j as usize] as usize >= N {
                return false;
            }
            if j > prev && buf[j as usize] <= buf[(j - 1) as usize] {
                return false;
            }
        }
        prev = limit;
    }
    // Check remaining bytes are zero
    for i in prev as usize..omega as usize {
        if buf[i] != 0 {
            return false;
        }
    }
    true
}
