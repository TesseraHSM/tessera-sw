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

/// Internal keygen from a 32-byte seed xi.
/// `work` is a caller-provided 7×256 i32 scratch buffer.
pub fn keygen_internal(
    params: &MlDsaParams,
    xi: &[u8; 32],
    pk: &mut [u8],
    sk: &mut [u8],
    work: &mut [[i32; N]],
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

    // s1_hat lives in caller-provided workspace
    let s1_hat = work;

    // Sample and NTT s1
    for j in 0..l {
        sampling::poly_sample_eta(&mut s1_hat[j], rhoprime, j as u16, params.eta);
        let sk_s1_offset = 128 + j * params.eta_pack_bytes();
        packing::pack_eta(&mut sk[sk_s1_offset..], &s1_hat[j], params.eta);
        ntt::ntt(&mut s1_hat[j]);
    }

    pk[..32].copy_from_slice(rho);
    sk[..32].copy_from_slice(rho);
    sk[32..64].copy_from_slice(key);

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
            sampling::poly_uniform(&mut a_ij, rho, i as u8, j as u8);
            ntt::poly_pointwise_acc_montgomery(&mut t_poly, &a_ij, &s1_hat[j]);
        }
        ntt::invntt(&mut t_poly);

        sampling::poly_sample_eta(&mut s2_poly, rhoprime, (l + i) as u16, params.eta);
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

    let pk_len = params.pk_bytes();
    let mut tr = [0u8; 64];
    shake256(&pk[..pk_len], &mut tr);
    sk[64..128].copy_from_slice(&tr);
}
