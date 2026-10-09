// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]

//! Tests for ML-KEM (FIPS 203) key encapsulation operations.
mod kat;
mod mlkem_kem;
mod mlkem_keys;

use super::*;

/// Every parameter set, so each test covers all three rather than picking one.
pub(crate) const VARIANTS: [MlKemVariant; 3] = [
    MlKemVariant::MlKem512,
    MlKemVariant::MlKem768,
    MlKemVariant::MlKem1024,
];

/// Maps a known-answer vector's `param_set` field onto the variant.
pub(crate) fn variant_of(param_set: u16) -> MlKemVariant {
    match param_set {
        512 => MlKemVariant::MlKem512,
        768 => MlKemVariant::MlKem768,
        1024 => MlKemVariant::MlKem1024,
        other => panic!("unknown ML-KEM parameter set {other}"),
    }
}

/// A distinct, reproducible byte pattern per `tag`.
pub(crate) fn filler(tag: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| tag.wrapping_mul(31).wrapping_add(i as u8).wrapping_mul(7))
        .collect()
}

/// A reproducible encapsulation message, sized for the pinning constructor.
pub(crate) fn msg(tag: u8) -> [u8; MLKEM_M_LEN] {
    filler(tag, MLKEM_M_LEN)
        .try_into()
        .expect("filler returns the requested length")
}
