// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parameter-set tables for the ML-DSA / ML-KEM command tests.
//!
//! Every PQC smoke test sweeps all three parameter sets of its
//! algorithm, so the sizes live here once rather than being restated as
//! a private `const` in each command module.
//!
//! The lengths are the FIPS values, written out literally rather than
//! derived from the schema crate: a test that recomputed them the same
//! way the implementation does would not be able to catch the
//! implementation getting them wrong.
//!
//! Sweeping matters more here than it looks. The FP operand slot has
//! fixed offsets sized for the *largest* parameter set, and the FP
//! scratch statics are shared across algorithms, so the small parameter
//! sets exercise none of the sizing that constrains the design --
//! ML-DSA-87 and ML-KEM-1024 are the cases that can actually overflow
//! something.

/// One ML-DSA parameter set (FIPS 204 Table 2).
pub struct MlDsaParams {
    /// Human-readable name, used in assertion messages.
    pub name: &'static str,
    /// TBOR `key_kind` discriminant for the seed form.
    pub key_kind: u8,
    /// Verification key length in bytes.
    pub pub_key_len: usize,
    /// Signature length in bytes.
    pub sig_len: usize,
    /// Masked private-key length: seed + expanded secret key + the
    /// 228-byte AEAD envelope.
    ///
    /// Parameter-set dependent, because the blob carries the expanded key
    /// so that signing does not have to re-derive it.
    pub masked_key_len: usize,
}

/// One ML-KEM parameter set (FIPS 203 Table 3).
pub struct MlKemParams {
    /// Human-readable name, used in assertion messages.
    pub name: &'static str,
    /// TBOR `key_kind` discriminant for the seed form.
    pub key_kind: u8,
    /// Encapsulation key length in bytes.
    pub pub_key_len: usize,
    /// Ciphertext length in bytes.
    pub ciphertext_len: usize,
    /// Masked private-key length: `(d ‖ z)` seed pair + expanded
    /// decapsulation key + the 228-byte AEAD envelope.
    pub masked_key_len: usize,
}

pub const ML_DSA_44: MlDsaParams = MlDsaParams {
    name: "ML-DSA-44",
    key_kind: tsra_ddi_tbor_types::MLDSA_KEY_KIND_44_SEED,
    pub_key_len: 1312,
    sig_len: 2420,
    masked_key_len: 228 + 32 + 2560, // AEAD envelope + seed + expanded key
};

pub const ML_DSA_65: MlDsaParams = MlDsaParams {
    name: "ML-DSA-65",
    key_kind: tsra_ddi_tbor_types::MLDSA_KEY_KIND_65_SEED,
    pub_key_len: 1952,
    sig_len: 3309,
    masked_key_len: 228 + 32 + 4032, // AEAD envelope + seed + expanded key
};

pub const ML_DSA_87: MlDsaParams = MlDsaParams {
    name: "ML-DSA-87",
    key_kind: tsra_ddi_tbor_types::MLDSA_KEY_KIND_87_SEED,
    pub_key_len: 2592,
    sig_len: 4627,
    masked_key_len: 228 + 32 + 4896, // AEAD envelope + seed + expanded key
};

pub const ML_KEM_512: MlKemParams = MlKemParams {
    name: "ML-KEM-512",
    key_kind: tsra_ddi_tbor_types::MLKEM_KEY_KIND_512_SEED,
    pub_key_len: 800,
    ciphertext_len: 768,
    masked_key_len: 228 + 64 + 1632, // AEAD envelope + seed + expanded key
};

pub const ML_KEM_768: MlKemParams = MlKemParams {
    name: "ML-KEM-768",
    key_kind: tsra_ddi_tbor_types::MLKEM_KEY_KIND_768_SEED,
    pub_key_len: 1184,
    ciphertext_len: 1088,
    masked_key_len: 228 + 64 + 2400, // AEAD envelope + seed + expanded key
};

pub const ML_KEM_1024: MlKemParams = MlKemParams {
    name: "ML-KEM-1024",
    key_kind: tsra_ddi_tbor_types::MLKEM_KEY_KIND_1024_SEED,
    pub_key_len: 1568,
    ciphertext_len: 1568,
    masked_key_len: 228 + 64 + 3168, // AEAD envelope + seed + expanded key
};

/// Host-DMA page size. A response is carried to the host as a PRP pair of
/// 4 KiB pages.
const HOST_PAGE: usize = 4096;

/// Fail if a response field that crosses the 4 KiB host-DMA page boundary
/// is all zeroes past it.
///
/// This guards a specific, nasty failure mode that ordinary assertions
/// cannot see. When firmware programs only the first PRP page, the response
/// is truncated at the page boundary and zero-filled after it. The CBOR
/// length prefix is still correct, so the response decodes cleanly and the
/// field is exactly its expected length — both a length check and an
/// "is not entirely zero" check pass on a buffer whose tail is garbage.
///
/// That is not hypothetical: every ML-DSA-87 signature produced before the
/// second PRP page was plumbed was invalid past byte 4096, and the test
/// suite reported it as passing.
///
/// Real key and signature material is indistinguishable from random, so a
/// run of zeroes this long has no legitimate explanation.
///
/// Today only an ML-DSA-87 signature (4627 B) exceeds the boundary, but
/// masked *expanded* private keys would too if those key forms are ever
/// added — a masked ML-DSA-87 private key is 5028 B.
pub fn assert_not_truncated_at_page(field: &[u8], what: &str) {
    if field.len() <= HOST_PAGE {
        return;
    }
    assert!(
        field[HOST_PAGE..].iter().any(|&b| b != 0),
        "{what}: all {} bytes past the 4 KiB page boundary are zero \
         (field is {} B) — this is the signature of a host DMA transfer \
         truncated at the first PRP page",
        field.len() - HOST_PAGE,
        field.len(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_field_that_does_not_reach_the_boundary() {
        assert_not_truncated_at_page(&vec![0u8; HOST_PAGE], "short");
    }

    #[test]
    fn accepts_a_field_with_content_past_the_boundary() {
        let mut buf = vec![0xABu8; HOST_PAGE + 500];
        buf[..HOST_PAGE].fill(0);
        assert_not_truncated_at_page(&buf, "populated tail");
    }

    /// The guard is only worth having if it actually fires, so prove it
    /// does on a buffer shaped exactly like a truncated response.
    #[test]
    #[should_panic(expected = "truncated at the first PRP page")]
    fn rejects_a_zero_filled_tail() {
        let mut buf = vec![0xABu8; 4627];
        buf[HOST_PAGE..].fill(0);
        assert_not_truncated_at_page(&buf, "truncated signature");
    }
}
