// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hardware round-trip for TBOR `EccSign`: generate on device, sign on
//! device, verify on the host.
//!
//! The existing `ecc_sign` round-trip lives behind
//! `#![cfg(feature = "emu")]`, and that build does not currently compile,
//! so `EccSign` has had **no** coverage on silicon. That gap is why the
//! P-521 masking failure (known-issue 2.4) went unnoticed, and it means
//! a green 341/341 says nothing about this command.
//!
//! This is deliberately backend-agnostic and ungated, so it runs wherever
//! the rest of the suite runs. It verifies the signature against the
//! device's own public key with a host reference implementation, which is
//! the only check that actually proves the private key reached the engine
//! intact -- a handler that signs with the wrong operand still returns a
//! well-formed, completely invalid signature.

use tsra_crypto::EccAlgo;
use tsra_crypto::EccPublicKey;
use tsra_crypto::Verifier;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborEccGenerateKeyReq;
use tsra_ddi_tbor_types::TborEccSignReq;
use tsra_ddi_tbor_types::ECC_CURVE_P256;
use tsra_ddi_tbor_types::ECC_CURVE_P384;
use tsra_ddi_tbor_types::KEY_USAGE_SIGN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// `KeyScope::Local` discriminant.
const SCOPE_LOCAL: u8 = 0b011;

/// Per-curve wire sizes keyed by public-key length:
/// `(wire_coord_len, raw_coord_len)`.
fn coord_sizes(pub_len: usize) -> (usize, usize) {
    match pub_len {
        64 => (32, 32),
        96 => (48, 48),
        136 => (68, 66),
        other => panic!("unexpected public key length {other}"),
    }
}

/// Reverse the low `len` bytes of `src` into a fresh big-endian vec.
fn rev(src: &[u8], len: usize) -> Vec<u8> {
    src[..len].iter().rev().copied().collect()
}

/// Verify a wire-LE ECDSA signature on the host.
fn verify_wire_ecdsa(pub_le: &[u8], sig_le: &[u8], digest_le: &[u8]) -> bool {
    let (wire_coord, raw_coord) = coord_sizes(pub_le.len());
    assert_eq!(sig_le.len(), wire_coord * 2, "signature length mismatch");

    let (x_le, y_le) = pub_le.split_at(wire_coord);
    let mut pub_be = rev(x_le, wire_coord);
    pub_be.extend(rev(y_le, wire_coord));
    let pubkey = EccPublicKey::from_hsm_bytes(&pub_be).expect("import public key");

    let (r_le, s_le) = sig_le.split_at(wire_coord);
    let mut sig_be = rev(r_le, raw_coord);
    sig_be.extend(rev(s_le, raw_coord));

    let digest_be = rev(digest_le, digest_le.len());

    Verifier::verify(&mut EccAlgo::default(), &pubkey, &digest_be, &sig_be)
        .expect("host ECDSA verify")
}

/// Sign on the device and verify against the device's own public key.
///
/// Covers both operand paths: P-256 and P-384 hand the request digest
/// straight to the engine because it already fills the operand width,
/// while a short digest is staged into a zeroed operand-width buffer. A
/// mistake in either yields a signature that will not verify.
#[test]
fn ecc_sign_roundtrip_verifies_on_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // P-521 is omitted: EccGenerateKey cannot mask a 66-byte scalar on
    // this hardware (known-issue 2.4, AES CTR block alignment).
    for (curve, digest_len) in [(ECC_CURVE_P256, 32usize), (ECC_CURVE_P384, 48usize)] {
        let key = ctx
            .tbor(&TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: SCOPE_LOCAL,
                curve,
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            })
            .expect("EccGenerateKey");

        // Exercise the full-width operand path and, for P-384, a short
        // digest that must be zero-extended.
        for len in [digest_len, 32usize] {
            let digest: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(7).wrapping_add(0x11))
                .collect();

            let resp = ctx
                .tbor(&TborEccSignReq {
                    session_id: session.session_id,
                    masked_key: key.masked_key.clone(),
                    digest: digest.clone(),
                })
                .expect("EccSign");

            assert!(
                verify_wire_ecdsa(&key.pub_key, &resp.signature, &digest),
                "curve {curve} digest {len} B: device signature failed host verification"
            );
        }
    }
}
