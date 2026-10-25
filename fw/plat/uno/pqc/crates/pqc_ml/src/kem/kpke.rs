// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::ntt;
use super::packing;
/// K-PKE: Internal lattice-based public-key encryption for ML-KEM.
/// FIPS 203 Algorithms 13 (KeyGen), 14 (Encrypt), 15 (Decrypt).
use super::params::MlKemParams;
/// K-PKE: Internal lattice-based public-key encryption for ML-KEM.
/// FIPS 203 Algorithms 13 (KeyGen), 14 (Encrypt), 15 (Decrypt).
use super::params::N;
/// K-PKE: Internal lattice-based public-key encryption for ML-KEM.
/// FIPS 203 Algorithms 13 (KeyGen), 14 (Encrypt), 15 (Decrypt).
use super::poly::Poly;
use super::poly::{self};
use super::sampling;
use crate::keccak::sha3_512;

/// Largest `k` across the parameter sets (ML-KEM-1024).
const MAX_K: usize = 4;

/// K-PKE.KeyGen(d): generate encryption key pair from 32-byte seed.
/// ek = ByteEncode12(t_hat[0..k]) || rho     (rho at end!)
/// dk = ByteEncode12(s_hat[0..k])
pub fn kpke_keygen(params: &MlKemParams, d: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
    let k = params.k as usize;

    // (rho, sigma) = G(d || k)
    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = params.k;
    let mut g_out = [0u8; 64];
    sha3_512(&g_input, &mut g_out);
    let rho = &g_out[0..32];
    let sigma = &g_out[32..64];

    // Sample s, NTT(s), store in dk
    let mut nonce: u8 = 0;
    let mut s_hat = Poly::ZERO;
    for i in 0..k {
        sampling::poly_cbd(&mut s_hat, sigma, nonce, params.eta1);
        nonce += 1;
        ntt::ntt(&mut s_hat);
        poly::poly_reduce(&mut s_hat);
        packing::byte_encode_12(&mut dk[384 * i..], &s_hat);
    }

    // Compute t_hat = A_hat * s_hat + e_hat, accumulating every row at
    // once so each column of s is decoded from dk a single time; the
    // row-major loop decoded all k of them for every row.
    let mut a_ij = Poly::ZERO;
    let mut e_hat = Poly::ZERO;
    let mut s_hat_j = Poly::ZERO;
    let mut t = [Poly::ZERO; MAX_K];

    for t_i in t[..k].iter_mut() {
        poly::poly_zero(t_i);
    }

    for j in 0..k {
        packing::byte_decode_12(&mut s_hat_j, &dk[384 * j..]);
        for i in 0..k {
            sampling::poly_uniform(&mut a_ij, rho, i as u8, j as u8);
            ntt::poly_basemul_acc(&mut t[i], &a_ij, &s_hat_j);
        }
    }

    for i in 0..k {
        ntt::poly_tomont(&mut t[i]); // cancel R^{-1} from basemul

        // Sample and NTT e_i
        sampling::poly_cbd(&mut e_hat, sigma, nonce, params.eta1);
        nonce += 1;
        ntt::ntt(&mut e_hat);

        poly::poly_add_inplace(&mut t[i], &e_hat);
        poly::poly_reduce(&mut t[i]);

        // ek = ByteEncode12(t_hat[0]) || ... || ByteEncode12(t_hat[k-1]) || rho
        packing::byte_encode_12(&mut ek[384 * i..], &t[i]);
    }
    // Append rho at the end of ek
    ek[384 * k..384 * k + 32].copy_from_slice(rho);
}

/// K-PKE.Encrypt(ek, m, r): encrypt 32-byte message m.
/// ct = Compress_du(u) || Compress_dv(v)
pub fn kpke_encrypt(params: &MlKemParams, ct: &mut [u8], ek: &[u8], m: &[u8; 32], r: &[u8]) {
    let k = params.k as usize;
    let du = params.du;
    let dv = params.dv;

    // ek = ByteEncode12(t_hat) || rho
    let rho = &ek[384 * k..384 * k + 32];

    let u_poly_bytes = N * du as usize / 8;
    let mut a_ij = Poly::ZERO;
    let mut r_hat_j = Poly::ZERO;
    let mut t_hat_j = Poly::ZERO;
    let mut u = [Poly::ZERO; MAX_K];
    let mut v = Poly::ZERO;

    // One pass over r. Accumulating every row of u at once means each
    // r_hat[j] is sampled and transformed once instead of once per row --
    // the row-major loop paid k CBD extractions and k NTTs for every one it
    // needed.
    for u_i in u[..k].iter_mut() {
        poly::poly_zero(u_i);
    }
    poly::poly_zero(&mut v);

    for j in 0..k {
        sampling::poly_cbd(&mut r_hat_j, r, j as u8, params.eta1);
        ntt::ntt(&mut r_hat_j);

        for i in 0..k {
            // A^T[i][j] = A[j][i]
            sampling::poly_uniform(&mut a_ij, rho, j as u8, i as u8);
            ntt::poly_basemul_acc(&mut u[i], &a_ij, &r_hat_j);
        }

        packing::byte_decode_12(&mut t_hat_j, &ek[384 * j..]);
        ntt::poly_basemul_acc(&mut v, &t_hat_j, &r_hat_j);
    }

    // u[i] = INTT(A^T[i] * r_hat) + e1[i], compressed into the ciphertext
    let mut e1 = Poly::ZERO;
    for i in 0..k {
        ntt::invntt(&mut u[i]);
        sampling::poly_cbd(&mut e1, r, (k + i) as u8, params.eta2);
        poly::poly_add_inplace(&mut u[i], &e1);
        poly::poly_compress(&mut ct[u_poly_bytes * i..], &u[i], du);
    }

    // v = INTT(t^T * r_hat) + e2 + Decompress_1(m)
    ntt::invntt(&mut v);
    let mut e2 = Poly::ZERO;
    sampling::poly_cbd(&mut e2, r, (2 * k) as u8, params.eta2);
    poly::poly_add_inplace(&mut v, &e2);

    let mut msg_poly = Poly::ZERO;
    packing::byte_decode_1(&mut msg_poly, m);
    for i in 0..N {
        msg_poly[i] = poly::decompress(msg_poly[i] as u16, 1) as i16;
    }
    poly::poly_add_inplace(&mut v, &msg_poly);
    poly::poly_compress(&mut ct[k * u_poly_bytes..], &v, dv);
}

/// K-PKE.Decrypt(dk, ct): decrypt ciphertext, return 32-byte message.
pub fn kpke_decrypt(params: &MlKemParams, m: &mut [u8; 32], dk: &[u8], ct: &[u8]) {
    let k = params.k as usize;
    let du = params.du;
    let dv = params.dv;
    let u_poly_bytes = N * du as usize / 8;

    // v = Decompress_dv(ct_v)
    let mut v = Poly::ZERO;
    poly::poly_decompress(&mut v, &ct[k * u_poly_bytes..], dv);

    // s^T * NTT(u)
    let mut su = Poly::ZERO;
    poly::poly_zero(&mut su);
    let mut u_i = Poly::ZERO;
    let mut s_hat_i = Poly::ZERO;

    for i in 0..k {
        poly::poly_decompress(&mut u_i, &ct[u_poly_bytes * i..], du);
        ntt::ntt(&mut u_i);
        packing::byte_decode_12(&mut s_hat_i, &dk[384 * i..]);
        ntt::poly_basemul_acc(&mut su, &s_hat_i, &u_i);
    }
    ntt::invntt(&mut su);

    // w = v - s^T * u
    let mut w = Poly::ZERO;
    poly::poly_sub(&mut w, &v, &su);

    // Compress_1(w) -> message: ByteEncode_1 of Compress_1, which is the
    // general packing at d = 1. w is within -1664..4992, inside its range.
    poly::poly_compress(m, &w, 1);
}
