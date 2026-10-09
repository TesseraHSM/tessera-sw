// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]

//! Tests for ML-DSA (FIPS 204) signature operations.
mod kat;
mod mldsa_keys;
mod mldsa_sign;

use super::*;

/// Every parameter set, so each test covers all three rather than picking one.
pub(crate) const VARIANTS: [MlDsaVariant; 3] = [
    MlDsaVariant::MlDsa44,
    MlDsaVariant::MlDsa65,
    MlDsaVariant::MlDsa87,
];

/// Maps a known-answer vector's `param_set` field onto the variant.
pub(crate) fn variant_of(param_set: u16) -> MlDsaVariant {
    match param_set {
        44 => MlDsaVariant::MlDsa44,
        65 => MlDsaVariant::MlDsa65,
        87 => MlDsaVariant::MlDsa87,
        other => panic!("unknown ML-DSA parameter set {other}"),
    }
}

/// A distinct, reproducible byte pattern per `tag`.
pub(crate) fn filler(tag: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| tag.wrapping_mul(31).wrapping_add(i as u8).wrapping_mul(7))
        .collect()
}

/// A reproducible signing-randomness block, sized for the pinning constructor.
pub(crate) fn rnd(tag: u8) -> [u8; MLDSA_RND_LEN] {
    filler(tag, MLDSA_RND_LEN)
        .try_into()
        .expect("filler returns the requested length")
}
