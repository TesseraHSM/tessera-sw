// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/// ML-DSA parameter set. All three variants share this struct layout.
pub struct MlDsaParams {
    pub k: u8,
    pub l: u8,
    pub eta: u8,
    pub tau: u8,
    pub beta: u32,
    pub gamma1: u32,
    pub gamma2: u32,
    pub omega: u8,
    pub d: u8,
    pub ctilde_bytes: u8,
}

/// q = 8380417
pub const Q: u32 = 8380417;
/// n = 256 (polynomial degree)
pub const N: usize = 256;
/// d = 13 (dropping bits in t)
pub const D: u32 = 13;

impl MlDsaParams {
    /// Bytes per polynomial when packing eta-bounded coefficients.
    pub const fn eta_pack_bytes(&self) -> usize {
        match self.eta {
            2 => 96,  // 3 bits per coeff: 256*3/8 = 96
            4 => 128, // 4 bits per coeff: 256*4/8 = 128
            _ => 0,
        }
    }

    /// Bytes per polynomial when packing z (gamma1-bounded).
    pub const fn z_pack_bytes(&self) -> usize {
        match self.gamma1 {
            131072 => 576, // 2^17: 18 bits, 256*18/8 = 576
            524288 => 640, // 2^19: 20 bits, 256*20/8 = 640
            _ => 0,
        }
    }

    /// Bits per coefficient in w1 packing.
    pub const fn w1_bits(&self) -> usize {
        match self.gamma2 {
            95232 => 6,  // (q-1)/88 → w1 range 0..43, 6 bits
            261888 => 4, // (q-1)/32 → w1 range 0..15, 4 bits
            _ => 0,
        }
    }

    /// Bytes per polynomial when packing w1.
    pub const fn w1_pack_bytes(&self) -> usize {
        N * self.w1_bits() / 8
    }

    /// Public key size.
    pub const fn pk_bytes(&self) -> usize {
        32 + self.k as usize * 320
    }

    /// Secret key size.
    pub const fn sk_bytes(&self) -> usize {
        32 + 32
            + 64
            + self.l as usize * self.eta_pack_bytes()
            + self.k as usize * self.eta_pack_bytes()
            + self.k as usize * 416
    }

    /// Signature size.
    pub const fn sig_bytes(&self) -> usize {
        self.ctilde_bytes as usize
            + self.l as usize * self.z_pack_bytes()
            + self.omega as usize
            + self.k as usize
    }

    /// Gamma1 bit-length (log2(gamma1)).
    pub const fn gamma1_bits(&self) -> u32 {
        match self.gamma1 {
            131072 => 17,
            524288 => 19,
            _ => 0,
        }
    }
}

pub static ML_DSA_44: MlDsaParams = MlDsaParams {
    k: 4,
    l: 4,
    eta: 2,
    tau: 39,
    beta: 78,
    gamma1: 1 << 17, // 131072
    gamma2: 95232,   // (q-1)/88
    omega: 80,
    d: 13,
    ctilde_bytes: 32,
};

pub static ML_DSA_65: MlDsaParams = MlDsaParams {
    k: 6,
    l: 5,
    eta: 4,
    tau: 49,
    beta: 196,
    gamma1: 1 << 19, // 524288
    gamma2: 261888,  // (q-1)/32
    omega: 55,
    d: 13,
    ctilde_bytes: 48,
};

pub static ML_DSA_87: MlDsaParams = MlDsaParams {
    k: 8,
    l: 7,
    eta: 2,
    tau: 60,
    beta: 120,
    gamma1: 1 << 19, // 524288
    gamma2: 261888,  // (q-1)/32
    omega: 75,
    d: 13,
    ctilde_bytes: 64,
};
