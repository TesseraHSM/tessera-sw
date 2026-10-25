// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// NTT zetas for ML-KEM (q=3329, ζ=17, R=2^16).
/// 128 entries in Montgomery domain: ζ^{brv7(i)} × R mod q.
const ZETAS_MONT: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

pub static ZETAS: [i16; 128] = ZETAS_MONT;

/// The same twiddles for the Plantard multiply in `asm/kem_ntt.S`, which
/// computes `a * b * -2^-32 mod q`: entry i is the centered b that makes
/// that `a * zeta^{brv7(i + 1)}`, which is `-ZETAS[i + 1] * 2^16 mod q`.
/// The forward transform reads them up from the start and the inverse down
/// from the end, as with `ZETAS`.
#[cfg(target_arch = "arm")]
pub static PLANT: [i16; 127] = {
    let mut t = [0i16; 127];
    let mut i = 0;
    while i < 127 {
        let b = (-(ZETAS_MONT[i + 1] as i32) * 65536).rem_euclid(3329);
        t[i] = (if b > 3329 / 2 { b - 3329 } else { b }) as i16;
        i += 1;
    }
    t
};

/// `ZETAS[64..]`, the ones [`poly_basemul_acc`](super::ntt::poly_basemul_acc)
/// reads. On ARM the transforms take [`PLANT`], so this half is all the
/// image needs of `ZETAS`.
#[cfg(target_arch = "arm")]
pub static BASEMUL_ZETAS: [i16; 64] = {
    let mut t = [0i16; 64];
    let mut i = 0;
    while i < 64 {
        t[i] = ZETAS_MONT[64 + i];
        i += 1;
    }
    t
};
