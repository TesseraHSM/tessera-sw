// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::ntt;
use super::packing;
/// ML-DSA Key Generation (FIPS 204 Algorithm 1 / Internal Algorithm 6).
use super::params::MlDsaParams;
/// ML-DSA Key Generation (FIPS 204 Algorithm 1 / Internal Algorithm 6).
use super::params::N;
use super::poly::Poly;
use super::poly::{self};
use super::rounding;
use super::sampling;
use crate::keccak::shake256;
use crate::keccak::XofPrefix;

/// Bytes of `s1` packed: at most seven polynomials of 96 bytes (eta = 2)
/// or five of 128 (eta = 4).
const S1_PACKED_MAX: usize = 7 * 96;

/// Internal keygen from a 32-byte seed xi.
/// `work` is a caller-provided 7×256 i32 scratch buffer.
///
/// Nothing is written to `sk` until `before_sk` has returned, which is not
/// before the first row of the matrix product: a caller whose `sk` may
/// still hold the previous key, being read out, waits in `before_sk`.
pub fn keygen_internal(
    params: &MlDsaParams,
    xi: &[u8; 32],
    pk: &mut [u8],
    sk: &mut [u8],
    work: &mut [[i32; N]],
    before_sk: impl FnOnce(),
) {
    let k = params.k as usize;
    let l = params.l as usize;

    // H(xi || k || l) -> rho(32) || rho'(64) || K(32)
    let mut seed_buf = [0u8; 34];
    seed_buf[..32].copy_from_slice(xi);
    seed_buf[32] = params.k;
    seed_buf[33] = params.l;

    let mut expanded = [0u8; 128];
    shake256(&seed_buf, &mut expanded);

    let rho = &expanded[0..32];
    let rhoprime = &expanded[32..96];
    let key = &expanded[96..128];
    let a_xof = XofPrefix::new(rho);
    let eta_xof = XofPrefix::new(rhoprime);

    // s1_hat lives in caller-provided workspace
    let s1_hat = work;

    // Sample and NTT s1, packing it here until `sk` may be written.
    let s1_len = l * params.eta_pack_bytes();
    let mut s1_packed = [0u8; S1_PACKED_MAX];
    for j in 0..l {
        sampling::poly_sample_eta(&mut s1_hat[j], &eta_xof, j as u16, params.eta);
        packing::pack_eta(&mut s1_packed[j * params.eta_pack_bytes()..], &s1_hat[j], params.eta);
        ntt::ntt(&mut s1_hat[j]);
    }

    pk[..32].copy_from_slice(rho);
    let mut before_sk = Some(before_sk);

    let sk_s2_offset = 128 + l * params.eta_pack_bytes();
    let sk_t0_offset = sk_s2_offset + k * params.eta_pack_bytes();

    let mut t_poly: Poly = [0i32; N];
    let mut a_ij: Poly = [0i32; N];
    let mut s2_poly: Poly = [0i32; N];
    let mut t1: Poly = [0i32; N];
    let mut t0: Poly = [0i32; N];

    for i in 0..k {
        poly::poly_zero(&mut t_poly);
        for j in 0..l {
            sampling::poly_uniform(&mut a_ij, &a_xof, i as u8, j as u8);
            ntt::poly_pointwise_acc_montgomery(&mut t_poly, &a_ij, &s1_hat[j]);
        }
        ntt::invntt(&mut t_poly);

        if let Some(f) = before_sk.take() {
            f();
            sk[..32].copy_from_slice(rho);
            sk[32..64].copy_from_slice(key);
            sk[128..128 + s1_len].copy_from_slice(&s1_packed[..s1_len]);
        }

        sampling::poly_sample_eta(&mut s2_poly, &eta_xof, (l + i) as u16, params.eta);
        packing::pack_eta(
            &mut sk[sk_s2_offset + i * params.eta_pack_bytes()..],
            &s2_poly,
            params.eta,
        );
        poly::poly_add_inplace(&mut t_poly, &s2_poly);

        poly::poly_reduce_caddq(&mut t_poly);

        rounding::poly_power2round(&mut t1, &mut t0, &t_poly);
        packing::pack_t1(&mut pk[32 + i * 320..], &t1);
        packing::pack_t0(&mut sk[sk_t0_offset + i * 416..], &t0);
    }
}
