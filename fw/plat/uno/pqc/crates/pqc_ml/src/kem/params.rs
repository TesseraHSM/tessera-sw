// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! ML-KEM parameter sets (FIPS 203).

pub const Q: u16 = 3329;
pub const N: usize = 256;

pub struct MlKemParams {
    pub k: u8,
    pub eta1: u8,
    pub eta2: u8,
    pub du: u8,
    pub dv: u8,
}

impl MlKemParams {
    pub const fn pk_bytes(&self) -> usize {
        32 + self.k as usize * 384
    }
    pub const fn sk_bytes(&self) -> usize {
        // dk = sk_pke || pk || H(pk) || z
        self.k as usize * 384 + self.pk_bytes() + 32 + 32
    }
    pub const fn ct_bytes(&self) -> usize {
        self.k as usize * (N * self.du as usize / 8) + (N * self.dv as usize / 8)
    }
}

pub static ML_KEM_512: MlKemParams = MlKemParams {
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};
pub static ML_KEM_768: MlKemParams = MlKemParams {
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};
pub static ML_KEM_1024: MlKemParams = MlKemParams {
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};
