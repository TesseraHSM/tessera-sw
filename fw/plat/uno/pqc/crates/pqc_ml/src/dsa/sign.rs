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
use crate::keccak::XofPrefix;
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
    // shared memory an order of magnitude slower than dTCM; it is read a
    // handful of times per attempt. rho, which seeds every matrix element,
    // is taken once into the XOF prefix they all start from.
    let rho = &XofPrefix::new(&sk[0..32]);
    let key = &sk[32..64];

    // rho'' = H(key || rnd || mu), likewise the prefix of every ExpandMask.
    let rhoprime = {
        let mut rhoprime = [0u8; 64];
        let mut hctx = shake256_init();
        hctx.absorb(key);
        hctx.absorb(rnd);
        hctx.absorb(mu);
        hctx.finalize();
        hctx.squeeze(&mut rhoprime);
        XofPrefix::new(&rhoprime)
    };

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
    let (w, a_polys) = work.split_at_mut(k);
    // The elements after those go to the platform's near regions, if it
    // gave any -- the first region filled before the second -- packed,
    // three bytes to a coefficient as the spill holds them, and only the
    // rest to the spill.
    //
    // SAFETY: signing is the near regions' only user, and this the only
    // borrow of them.
    let [near1, near2] = unsafe { crate::spill::near() };
    let near_slots = near1.len() / PACKED_WORDS + near2.len() / PACKED_WORDS;
    // The work slots keep their elements whole, a word to a coefficient, if
    // the whole matrix still fits without the spill that way: a cached
    // product is then the plain multiply-accumulate. Otherwise they pack
    // them too, fitting a third more, and the multiply-accumulate unpacks
    // as it reads.
    let whole = a_polys.len() + near_slots >= k * l;
    let cache_slots = if whole {
        a_polys.len()
    } else {
        a_polys.len() * N / PACKED_WORDS
    };
    let want = (k * l).saturating_sub(cache_slots);
    let near_a1 = want.min(near1.len() / PACKED_WORDS);
    let near_a2 = (want - near_a1).min(near2.len() / PACKED_WORDS);
    let held = cache_slots + near_a1 + near_a2;
    let mut a_cached = false;

    // s1 and s2 coefficients are packed eta - f in d-bit fields.
    let eta_d = if params.eta == 2 { 3 } else { 4 };
    let eta_bias = params.eta as i32;

    // Stack temporaries: single polynomials only
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
                let spill = if t < held {
                    None
                } else {
                    crate::spill::matrix_slot(t - held)
                };
                // Kept whole: derived straight into its slot the first
                // time, and used from there.
                let kept_whole = whole && t < cache_slots;
                if kept_whole || !a_cached || (t >= held && spill.is_none()) {
                    // Otherwise the first attempt, or an element with
                    // nowhere to be kept: derive it.
                    let a = if kept_whole { &mut a_polys[t] } else { &mut c_hat };
                    if !(kept_whole && a_cached) {
                        sampling::poly_uniform(a, rho, i as u8, j as u8);
                    }
                    if j == 0 {
                        ntt::poly_pointwise_montgomery(&mut w[i], a, y_hat);
                    } else {
                        ntt::poly_pointwise_acc_montgomery(&mut w[i], a, y_hat);
                    }
                    if !a_cached && !kept_whole {
                        if t < cache_slots {
                            crate::spill::pack(
                                &mut a_polys.as_flattened_mut()[t * PACKED_WORDS..],
                                &c_hat,
                            );
                        } else if t < held {
                            crate::spill::pack(
                                near_elem(near1, near2, t - cache_slots),
                                &c_hat,
                            );
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
                        None if t < cache_slots => &a_polys.as_flattened()[t * PACKED_WORDS..],
                        None => near_elem(near1, near2, t - cache_slots),
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
            // w1 packed for the hash; w_i keeps (w0 << 6) | w1 for the r0
            // check and the hints.
            let w1_bytes = params.w1_pack_bytes();
            rounding::poly_decompose_pack(&mut w1_packed[..w1_bytes], &mut w[i], params.gamma2);
            commit_ctx.absorb(&w1_packed[..w1_bytes]);
        }

        let mut ctilde = [0u8; 64];
        commit_ctx.finalize();
        commit_ctx.squeeze(&mut ctilde[..ctilde_len]);

        // Challenge, and its nonzero coefficients -- each one's position,
        // with 0x100 set where it is -1 -- for the norm checks.
        sampling::poly_challenge(&mut c_hat, &ctilde[..ctilde_len], params.tau);
        let mut c_sparse = [0u16; 64];
        let mut c_n = 0;
        for (p, &v) in c_hat.iter().enumerate() {
            if v != 0 {
                c_sparse[c_n] = p as u16 | (u16::from(v < 0) << 8);
                c_n += 1;
            }
        }
        let c_sparse = &c_sparse[..c_n];

        // ---- the norm checks, exactly, without the products ----
        // An attempt must keep every coefficient of w0 - c*s2 inside
        // gamma2 - beta and of y + c*s1 inside gamma1 - beta, and most
        // attempts fail one or the other. But |c*s| <= tau*eta = beta, so a
        // coefficient of w0 or y more than 2*beta inside its bound stays
        // inside whatever c*s is: only the few closer than that -- a
        // fraction of one a polynomial -- need c*s, and only at that
        // coefficient, a sum of tau coefficients of s. The checks decide
        // each attempt as the full products would, so the attempts and the
        // signature are the same; the products themselves, a forward and an
        // inverse transform each, are left for the one attempt that passes.
        // The low bits fail most often, so they go first.
        let r0_bound = (params.gamma2 - params.beta) as i32;
        let z_bound = (params.gamma1 - params.beta) as i32;
        let beta = params.beta as i32;
        let mut ok = true;
        for i in 0..k {
            // w_i holds (w0 << 6) | w1.
            let near = r0_bound - beta;
            ok = close_ok(
                &w[i],
                [64 * (near - 1), 64 * (2 * near - 1)],
                -1,
                c_sparse,
                &mut tmp,
                &sk[sk_s2_offset + i * params.eta_pack_bytes()..],
                [eta_d, eta_bias as u32],
                r0_bound,
            );
            if !ok {
                break;
            }
        }
        for j in 0..l {
            if !ok {
                break;
            }
            // y_j comes back from the packed stream this attempt produced.
            sampling::unpack_gamma1(
                &mut tmp,
                &sig[ctilde_len + j * ybytes..ctilde_len + (j + 1) * ybytes],
                params.gamma1,
            );
            let near = z_bound - beta;
            ok = close_ok(
                &tmp,
                [near - 1, 2 * near - 1],
                1,
                c_sparse,
                &mut w0_i,
                &sk[sk_s1_offset + j * params.eta_pack_bytes()..],
                [eta_d, eta_bias as u32],
                z_bound,
            );
        }
        if !ok {
            kappa += l as u16;
            continue;
        }
        // Only the products below want c transformed, so only an attempt
        // that passes the checks above pays for it.
        ntt::ntt(&mut c_hat);

        // ---- hint pass: r0 and c*t0 row by row, hints incrementally ----
        let hint_offset = ctilde_len + l * params.z_pack_bytes();
        let hint_buf = &mut sig[hint_offset..hint_offset + params.omega as usize + k];
        // Zero the hint buffer
        for b in hint_buf.iter_mut() {
            *b = 0;
        }
        let mut hint_idx = 0usize; // write position in first omega bytes
        let mut hint_count = 0u32;
        let mut reject = false;

        // The hints want w0 - c*s2 + c*t0, and c*t0 inside gamma2. For
        // ML-DSA-65 and -87 |c*t0| <= tau * 2^12 is below gamma2 anyway, so
        // that check cannot fail and one product a row does: w0 + c*(t0 -
        // s2). ML-DSA-44's c*t0 can exceed gamma2, so it forms r0 = w0 -
        // c*s2 in w_i and checks c*t0 on its own.
        let ct0_checked = params.tau as u32 * (1 << 12) >= params.gamma2;
        for i in 0..k {
            let s2 = &sk[sk_s2_offset + i * params.eta_pack_bytes()..];
            let t0 = &sk[sk_t0_offset + i * 416..];
            if ct0_checked {
                c_times_key(&mut tmp, &c_hat, s2, [eta_d, eta_bias as u32], None);
                poly::poly_r0_check(&mut w[i], &tmp, params.gamma2 - params.beta);
                c_times_key(&mut tmp, &c_hat, t0, [13, 1 << 12], None);
                if !poly::poly_reduce_chknorm(&mut tmp, params.gamma2) {
                    reject = true;
                    break;
                }
            } else {
                let minus = (&mut w0_i, s2, [eta_d, eta_bias as u32]);
                c_times_key(&mut tmp, &c_hat, t0, [13, 1 << 12], Some(minus));
                // Only to centre it: the bound is out of reach.
                poly::poly_reduce_chknorm(&mut tmp, 1 << 22);
            }

            // MakeHint and pack incrementally into hint_buf, from w_i's low
            // part -- r0, or w0 with c*s2 folded into tmp -- and w1.
            for coeff in 0..N {
                let v = w[i][coeff];
                let h = rounding::make_hint((v >> 6) + tmp[coeff], v & 63, params.gamma2);
                if h != 0 {
                    if hint_count >= params.omega as u32 {
                        reject = true;
                        break;
                    }
                    hint_buf[hint_idx] = coeff as u8;
                    hint_idx += 1;
                    hint_count += 1;
                }
            }
            if reject {
                break;
            }
            // Write cumulative count for polynomial i
            hint_buf[params.omega as usize + i] = hint_count as u8;
        }

        if reject {
            kappa += l as u16;
            continue;
        }

        // Zero-fill remaining hint index slots
        while hint_idx < params.omega as usize {
            hint_buf[hint_idx] = 0;
            hint_idx += 1;
        }

        // ---- z pass: z_j = y_j + c*s1_j, packed over y_j ----
        // The check above already found every z_j inside its bound.
        sig[..ctilde_len].copy_from_slice(&ctilde[..ctilde_len]);
        for j in 0..l {
            let zj = &mut sig[ctilde_len + j * ybytes..ctilde_len + (j + 1) * ybytes];
            sampling::unpack_gamma1(&mut tmp, zj, params.gamma1);
            c_times_key(
                &mut w0_i,
                &c_hat,
                &sk[sk_s1_offset + j * params.eta_pack_bytes()..],
                [eta_d, eta_bias as u32],
                None,
            );
            poly::poly_add_reduce_chknorm(&mut tmp, &w0_i, params.gamma1 - params.beta);
            packing::pack_z(zj, &tmp, params.gamma1);
        }

        return true;
    }

    false
}

/// `dst = c * p`, for `p` a polynomial of s1, s2 or t0 packed in `src` as
/// `bias - f` in `d`-bit fields, `fmt` = [d, bias] -- less, if `minus` names
/// one, a second such polynomial, unpacked into the scratch it carries.
///
/// Each is needed once a signature, by the attempt that passes, so the
/// transform is not kept.
#[inline(never)]
#[allow(clippy::type_complexity)]
fn c_times_key(
    dst: &mut Poly,
    c_hat: &Poly,
    src: &[u8],
    fmt: [u32; 2],
    minus: Option<(&mut Poly, &[u8], [u32; 2])>,
) {
    packing::unpack_centered(dst, src, fmt[0], fmt[1] as i32);
    if let Some((scratch, src, fmt)) = minus {
        packing::unpack_centered(scratch, src, fmt[0], fmt[1] as i32);
        for (x, &y) in dst.iter_mut().zip(scratch.iter()) {
            *x -= y;
        }
    }
    ntt::ntt(dst);
    ntt::poly_pointwise_montgomery_inplace(dst, c_hat);
    ntt::invntt(dst);
}

/// Whether every `|x + sign * (c*s)[n]|` is below `bound`, for x the
/// coefficients of `a` (shifted down 6 where `a` holds `(w0 << 6) | w1`),
/// `c` the challenge's nonzero coefficients and `s` the key polynomial
/// packed in `src` as `fmt` = [d, bias].
///
/// `close` = [k, m] picks out the coefficients that need looking at --
/// those with `(x + k) as u32 >= m`, the ones within 2*beta of the bound.
/// Everywhere else `|c*s| <= beta` keeps the sum inside. `s` is unpacked
/// into `scratch` only if some coefficient does.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn close_ok(
    a: &Poly,
    close: [i32; 2],
    sign: i32,
    c: &[u16],
    scratch: &mut Poly,
    src: &[u8],
    fmt: [u32; 2],
    bound: i32,
) -> bool {
    let shift = if sign < 0 { 6 } else { 0 };
    let mut have_s = false;
    let mut n = find_close(a, 0, close);
    while n < N {
        if !have_s {
            packing::unpack_centered(scratch, src, fmt[0], fmt[1] as i32);
            have_s = true;
        }
        // Coefficient n of the negacyclic product c * s.
        let mut cs = 0i32;
        for &e in c {
            let p = (e & 0xff) as usize;
            let v = if n >= p { scratch[n - p] } else { -scratch[n + N - p] };
            cs += if e & 0x100 != 0 { -v } else { v };
        }
        if ((a[n] >> shift) + sign * cs).abs() >= bound {
            return false;
        }
        n = find_close(a, n + 1, close);
    }
    true
}

/// The first index from `n` whose coefficient `x` has `(x + k) as u32 >=
/// m`, or N.
fn find_close(a: &Poly, n: usize, [k, m]: [i32; 2]) -> usize {
    #[cfg(target_arch = "arm")]
    {
        extern "C" {
            fn pqc_ml_dsa_find_close(a: *const i32, n: u32, k: i32, m: u32) -> u32;
        }
        // SAFETY: `a` is 256 word-aligned coefficients and n <= 256.
        unsafe { pqc_ml_dsa_find_close(a.as_ptr(), n as u32, k, m as u32) as usize }
    }

    #[cfg(not(target_arch = "arm"))]
    {
        (n..N)
            .find(|&i| a[i].wrapping_add(k) as u32 >= m as u32)
            .unwrap_or(N)
    }
}

/// Near-region matrix element `u`: the first region's elements, then the
/// second's.
#[inline(always)]
fn near_elem<'a>(near1: &'a mut [i32], near2: &'a mut [i32], u: usize) -> &'a mut [i32] {
    let first = near1.len() / PACKED_WORDS;
    if u < first {
        &mut near1[u * PACKED_WORDS..]
    } else {
        &mut near2[(u - first) * PACKED_WORDS..]
    }
}
