// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::kpke;
/// ML-KEM: Fujisaki-Okamoto KEM built on K-PKE.
/// FIPS 203 Algorithms 16 (KeyGen), 17 (Encaps), 18 (Decaps).
use super::params::MlKemParams;
use crate::keccak::sha3_256;
use crate::keccak::sha3_512;
use crate::keccak::shake256_init;

/// ML-KEM.KeyGen_internal(d, z).
pub fn mlkem_keygen(
    params: &MlKemParams,
    d: &[u8; 32],
    z: &[u8; 32],
    ek: &mut [u8],
    dk: &mut [u8],
) {
    let k = params.k as usize;
    let ek_len = params.pk_bytes();
    let dk_pke_len = k * 384;

    kpke::kpke_keygen(params, d, ek, &mut dk[..dk_pke_len]);

    // dk = dk_pke || ek || H(ek) || z
    dk[dk_pke_len..dk_pke_len + ek_len].copy_from_slice(&ek[..ek_len]);
    let mut h_ek = [0u8; 32];
    sha3_256(&ek[..ek_len], &mut h_ek);
    dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32].copy_from_slice(&h_ek);
    dk[dk_pke_len + ek_len + 32..dk_pke_len + ek_len + 64].copy_from_slice(z);
}

/// ML-KEM.Encaps_internal(ek, m).
/// FIPS 203 Algorithm 17: K is returned directly from G, not re-hashed.
pub fn mlkem_encaps(
    params: &MlKemParams,
    ss: &mut [u8; 32],
    ct: &mut [u8],
    ek: &[u8],
    m: &[u8; 32],
) {
    let ek_len = params.pk_bytes();

    // (K, r) = G(m || H(ek))
    let mut h_ek = [0u8; 32];
    sha3_256(&ek[..ek_len], &mut h_ek);

    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..64].copy_from_slice(&h_ek);
    let mut g_out = [0u8; 64];
    sha3_512(&g_input, &mut g_out);

    // K = g_out[0:32], r = g_out[32:64]
    ss.copy_from_slice(&g_out[0..32]);
    let r = &g_out[32..64];

    // ct = K-PKE.Encrypt(ek, m, r)
    kpke::kpke_encrypt(params, ct, ek, m, r);
}

/// ML-KEM.Decaps_internal(dk, c).
/// FIPS 203 Algorithm 18: implicit rejection via J(z || c).
pub fn mlkem_decaps(params: &MlKemParams, ss: &mut [u8; 32], ct: &[u8], dk: &[u8]) {
    let k = params.k as usize;
    let dk_pke_len = k * 384;
    let ek_len = params.pk_bytes();
    let ct_len = params.ct_bytes();

    let dk_pke = &dk[..dk_pke_len];
    let ek = &dk[dk_pke_len..dk_pke_len + ek_len];
    let h_ek = &dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32];
    let z = &dk[dk_pke_len + ek_len + 32..dk_pke_len + ek_len + 64];

    // m' = K-PKE.Decrypt(dk_pke, ct)
    let mut m_prime = [0u8; 32];
    kpke::kpke_decrypt(params, &mut m_prime, dk_pke, ct);

    // (K', r') = G(m' || H(ek))
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..64].copy_from_slice(h_ek);
    let mut g_out = [0u8; 64];
    sha3_512(&g_input, &mut g_out);
    let k_prime = &g_out[0..32];
    let r_prime = &g_out[32..64];

    // Re-encrypt: ct' = K-PKE.Encrypt(ek, m', r')
    let mut ct_prime = [0u8; 1568]; // max ct size
    kpke::kpke_encrypt(params, &mut ct_prime[..ct_len], ek, &m_prime, r_prime);

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..ct_len {
        diff |= ct[i] ^ ct_prime[i];
    }

    // Implicit rejection: K_bar = J(z || ct) = SHAKE-256(z || ct), 32 bytes
    let mut k_rej = [0u8; 32];
    {
        let mut jctx = shake256_init();
        jctx.absorb(z);
        jctx.absorb(&ct[..ct_len]);
        jctx.finalize();
        jctx.squeeze(&mut k_rej);
    }

    // Select: if ct matches, use K'; otherwise use K_rej
    // Constant-time select
    let mask = if diff == 0 { 0u8 } else { 0xFFu8 };
    for i in 0..32 {
        ss[i] = (k_prime[i] & !mask) | (k_rej[i] & mask);
    }
}
