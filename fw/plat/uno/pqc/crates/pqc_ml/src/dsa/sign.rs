// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::ntt;
use super::packing;
/// ML-DSA Signing (FIPS 204 Algorithm 2 / Internal Algorithm 7).
///
/// Stack-optimized: multi-poly buffer provided by caller.
/// z is packed directly into sig; hints are built incrementally.
use super::params::MlDsaParams;
/// ML-DSA Signing (FIPS 204 Algorithm 2 / Internal Algorithm 7).
///
/// Stack-optimized: multi-poly buffer provided by caller.
/// z is packed directly into sig; hints are built incrementally.
use super::params::N;
use super::poly::Poly;
use super::poly::{self};
use super::rounding;
use super::sampling;
use crate::keccak::shake256_init;
use crate::spill::PACKED_WORDS;
use crate::DsaWorkBuf;

pub fn sign_internal(
    params: &MlDsaParams,
    sig: &mut [u8],
    mu: &[u8; 64],
    sk: &[u8],
    rnd: &[u8; 32],
    work: &mut DsaWorkBuf,
) -> bool {
    let k = params.k as usize;
    let l = params.l as usize;

    // The expanded key is read in place from the operand slot, which is
    // shared memory an order of magnitude slower than dTCM. rho is absorbed
    // once per matrix element, so it earns a local copy; the rest is read a
    // handful of times per attempt and is left where it is.
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk[0..32]);
    let rho = &rho;
    let key = &sk[32..64];

    // rho'' = H(key || rnd || mu)
    let mut rhoprime = [0u8; 64];
    {
        let mut hctx = shake256_init();
        hctx.absorb(key);
        hctx.absorb(rnd);
        hctx.absorb(mu);
        hctx.finalize();
        hctx.squeeze(&mut rhoprime);
    }

    // w = A*y lives in the caller-provided workspace and survives from the
    // commitment pass into the hint pass. Keeping it is what lets the
    // matrix be expanded once per attempt instead of twice: ExpandA is by
    // far the most expensive part of signing, and the hint pass used to
    // regenerate every element of A just to recompute a value it had
    // already seen.
    // The accumulators need k slots; whatever the parameter set leaves over
    // holds the leading elements of A across attempts. Re-expanding the
    // matrix is by far the largest cost of a signature, so those spare
    // slots buy back one expansion each per retry, and they cost nothing.
    let (w, a_cache) = work.split_at_mut(k);
    // They are kept packed, three bytes to a coefficient as the spill holds
    // them: a third more of the matrix fits in the same dTCM, and the
    // multiply-accumulate unpacks as it reads.
    let a_cache = a_cache.as_flattened_mut();
    let cache_slots = a_cache.len() / PACKED_WORDS;
    let mut a_cached = false;

    // s1, s2 and t0 are transformed once per attempt but depend only on the
    // key, so their transforms are held alongside the spilled matrix and
    // reused. They live in their own region above the matrix, so their
    // indices do not depend on how much this parameter set spilled.
    //
    // Both passes walk their rows from zero and can stop early, so a count
    // of how many slots have been filled is enough -- an attempt that got
    // as far as row n leaves rows 0..n valid for the next one.
    let mut s1_done = 0usize;
    let mut hint_done = 0usize;

    // Stack temporaries: single polynomials only
    let mut w1_i: Poly = [0i32; N];
    let mut w0_i: Poly = [0i32; N];
    let mut tmp: Poly = [0i32; N];
    // The commitment pass wants a scratch polynomial for the matrix
    // elements it does not have cached; the challenge is not sampled until
    // that pass is over, and is dead again by the time the next one starts.
    // They share a buffer.
    let mut c_hat: Poly = [0i32; N];
    let mut w1_packed = [0u8; 192]; // per-row buffer (max: gamma2=(q-1)/88 → 192 B)

    // ExpandMask output for the whole attempt, staged in the z region of the
    // signature buffer -- y and z pack to the same width, so the z pass can
    // read y back and overwrite it in place. Re-running the XOF instead cost
    // five Keccak permutations per column.
    let ybytes = params.z_pack_bytes();

    let mut kappa: u16 = 0;
    let max_attempts = 1000u16;
    let ctilde_len = params.ctilde_bytes as usize;
    let sk_s1_offset = 128usize;
    let sk_s2_offset = 128 + l * params.eta_pack_bytes();
    let sk_t0_offset = sk_s2_offset + k * params.eta_pack_bytes();

    while kappa < max_attempts {
        // Compute w = A · y one *column* at a time: each y_j is sampled
        // once and consumed by every row before it is discarded, so the k
        // accumulators are all live but only one y_hat ever is. That is
        // what makes room for w to be kept.
        // The commitment pass has finished with `tmp` before the z pass
        // wants it, so the transform of y borrows that buffer rather than
        // claiming a seventh polynomial of its own.
        let y_hat = &mut tmp;
        let mut t = 0usize;
        for j in 0..l {
            let yb = &mut sig[ctilde_len + j * ybytes..ctilde_len + (j + 1) * ybytes];
            sampling::expand_mask_bytes(yb, &rhoprime, kappa + j as u16);
            sampling::unpack_gamma1(y_hat, yb, params.gamma1);
            ntt::ntt(y_hat);
            for i in 0..k {
                let spill = if t < cache_slots {
                    None
                } else {
                    crate::spill::matrix_slot(t - cache_slots)
                };
                if !a_cached || (t >= cache_slots && spill.is_none()) {
                    // The first attempt, or an element with nowhere to be
                    // kept: derive it.
                    sampling::poly_uniform(&mut c_hat, rho, i as u8, j as u8);
                    if j == 0 {
                        ntt::poly_pointwise_montgomery(&mut w[i], &c_hat, y_hat);
                    } else {
                        ntt::poly_pointwise_acc_montgomery(&mut w[i], &c_hat, y_hat);
                    }
                    if !a_cached {
                        if t < cache_slots {
                            crate::spill::pack(&mut a_cache[t * PACKED_WORDS..], &c_hat);
                        } else if let Some(p) = spill {
                            // SAFETY: `p` is this core's own slot, sized for
                            // one packed element by `spill::init`.
                            unsafe { crate::spill::store_packed(p, &c_hat) };
                        }
                    }
                } else {
                    let packed: &[i32] = match spill {
                        // Off-core, but a burst read still costs a fifth of
                        // what deriving the element again would.
                        Some(p) => {
                            // SAFETY: as above; the first attempt wrote it.
                            unsafe { crate::spill::load_packed_words(&mut c_hat, p) };
                            &c_hat
                        }
                        None => &a_cache[t * PACKED_WORDS..],
                    };
                    if j == 0 {
                        // SAFETY: one whole word-aligned polynomial.
                        unsafe {
                            crate::fast_zero(
                                w[i].as_mut_ptr().cast(),
                                core::mem::size_of_val(&w[i]),
                            )
                        };
                    }
                    ntt::poly_pointwise_acc_montgomery_packed(&mut w[i], packed, y_hat);
                }
                t += 1;
            }
        }
        a_cached = true;

        // Decompose, hash w1 → ctilde
        let mut commit_ctx = shake256_init();
        commit_ctx.absorb(mu);

        for i in 0..k {
            ntt::invntt(&mut w[i]);
            rounding::poly_decompose_reduced(&mut w1_i, &mut w0_i, &w[i], params.gamma2);
            let w1_bytes = params.w1_pack_bytes();
            packing::pack_w1(&mut w1_packed[..w1_bytes], &w1_i, params.gamma2);
            commit_ctx.absorb(&w1_packed[..w1_bytes]);
        }

        let mut ctilde = [0u8; 64];
        commit_ctx.finalize();
        commit_ctx.squeeze(&mut ctilde[..ctilde_len]);

        // Challenge
        sampling::poly_challenge(&mut c_hat, &ctilde[..ctilde_len], params.tau);
        ntt::ntt(&mut c_hat);

        // ---- z pass: compute z_j, check norm, pack directly into sig ----
        sig[..ctilde_len].copy_from_slice(&ctilde[..ctilde_len]);
        let mut z_reject = false;
        let mut sig_z_offset = ctilde_len;

        for j in 0..l {
            // y_j comes back from the packed stream this attempt already
            // produced; compute z_j = y_j + c*s1_j
            sampling::unpack_gamma1(
                &mut tmp,
                &sig[ctilde_len + j * ybytes..ctilde_len + (j + 1) * ybytes],
                params.gamma1,
            );

            // c * s1_j — reuse w0_i/w1_i (unused in z-pass)
            match crate::spill::key_slot(j) {
                // SAFETY: a slot of this core's own region, and `s1_done`
                // says whether this one has been written yet.
                Some(p) if j < s1_done => unsafe { crate::spill::load(&mut w0_i, p) },
                slot => {
                    packing::unpack_eta(
                        &mut w0_i,
                        &sk[sk_s1_offset + j * params.eta_pack_bytes()..],
                        params.eta,
                    );
                    ntt::ntt(&mut w0_i);
                    if let Some(p) = slot {
                        // SAFETY: as above.
                        unsafe { crate::spill::store(p, &w0_i) };
                        s1_done = j + 1;
                    }
                }
            }
            ntt::poly_pointwise_montgomery_inplace(&mut w0_i, &c_hat);
            ntt::invntt(&mut w0_i);

            // z_j = y_j + c*s1_j
            if !poly::poly_add_reduce_chknorm(&mut tmp, &w0_i, params.gamma1 - params.beta) {
                z_reject = true;
                break;
            }

            // Pack z_j directly into signature
            packing::pack_z(&mut sig[sig_z_offset..], &tmp, params.gamma1);
            sig_z_offset += params.z_pack_bytes();
        }

        if z_reject {
            kappa += l as u16;
            continue;
        }

        // ---- hint pass: check w0-cs2, ct0, build hints incrementally ----
        let hint_offset = ctilde_len + l * params.z_pack_bytes();
        let hint_buf = &mut sig[hint_offset..hint_offset + params.omega as usize + k];
        // Zero the hint buffer
        for b in hint_buf.iter_mut() {
            *b = 0;
        }
        let mut hint_idx = 0usize; // write position in first omega bytes
        let mut hint_count = 0u32;
        let mut w0_reject = false;

        for i in 0..k {
            // w_i is still in the workspace from the commitment pass.
            rounding::poly_decompose_reduced(&mut w1_i, &mut w0_i, &w[i], params.gamma2);

            // c * s2_i, folded in place so no fifth polynomial is needed
            match crate::spill::key_slot(l + 2 * i) {
                // SAFETY: as in the z-pass.
                Some(p) if 2 * i < hint_done => unsafe { crate::spill::load(&mut tmp, p) },
                slot => {
                    packing::unpack_eta(
                        &mut tmp,
                        &sk[sk_s2_offset + i * params.eta_pack_bytes()..],
                        params.eta,
                    );
                    ntt::ntt(&mut tmp);
                    if let Some(p) = slot {
                        // SAFETY: as above.
                        unsafe { crate::spill::store(p, &tmp) };
                        hint_done = 2 * i + 1;
                    }
                }
            }
            ntt::poly_pointwise_montgomery_inplace(&mut tmp, &c_hat);
            ntt::invntt(&mut tmp);

            if !poly::poly_sub_reduce_chknorm(&mut w0_i, &tmp, params.gamma2 - params.beta) {
                w0_reject = true;
                break;
            }

            // c * t0_i, likewise in place
            match crate::spill::key_slot(l + 2 * i + 1) {
                // SAFETY: as in the z-pass.
                Some(p) if 2 * i + 1 < hint_done => unsafe { crate::spill::load(&mut tmp, p) },
                slot => {
                    packing::unpack_t0(&mut tmp, &sk[sk_t0_offset + i * 416..]);
                    ntt::ntt(&mut tmp);
                    if let Some(p) = slot {
                        // SAFETY: as above.
                        unsafe { crate::spill::store(p, &tmp) };
                        hint_done = 2 * i + 2;
                    }
                }
            }
            ntt::poly_pointwise_montgomery_inplace(&mut tmp, &c_hat);
            ntt::invntt(&mut tmp);
            if !poly::poly_reduce_chknorm(&mut tmp, params.gamma2) {
                w0_reject = true;
                break;
            }

            // MakeHint and pack incrementally into hint_buf
            // w0_i + ct0 is read once and w0_i is rebuilt on the next row,
            // so the sum is formed here rather than in a pass that writes
            // back a polynomial nothing reads again.
            for coeff in 0..N {
                let h = rounding::make_hint(w0_i[coeff] + tmp[coeff], w1_i[coeff], params.gamma2);
                if h != 0 {
                    if hint_count >= params.omega as u32 {
                        w0_reject = true;
                        break;
                    }
                    hint_buf[hint_idx] = coeff as u8;
                    hint_idx += 1;
                    hint_count += 1;
                }
            }
            if w0_reject {
                break;
            }
            // Write cumulative count for polynomial i
            hint_buf[params.omega as usize + i] = hint_count as u8;
        }

        if w0_reject {
            kappa += l as u16;
            continue;
        }

        // Zero-fill remaining hint index slots
        while hint_idx < params.omega as usize {
            hint_buf[hint_idx] = 0;
            hint_idx += 1;
        }

        return true;
    }

    false
}
