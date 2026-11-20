// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::EccCurve;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::dev_rev;
use tsra_ddi_tbor_test_harness::device_is_little_endian;
use tsra_ddi_tbor_types::*;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn selector(self) -> u8 {
        match self {
            Self::Sha256 => HASH_ALGO_SHA256,
            Self::Sha384 => HASH_ALGO_SHA384,
            Self::Sha512 => HASH_ALGO_SHA512,
        }
    }

    fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Mutation {
    Valid,
    R,
    S,
    Digest,
    Hash,
    Length,
    Padding,
    Envelope,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    curve: EccCurve,
    hash: Hash,
    mutation: Mutation,
    index: u8,
    value: u8,
}

fn packed_input(curve: EccCurve, digest: &[u8], signature: &[u8]) -> Vec<u8> {
    let sign_coord_len = curve.wire_coord_len();
    let verify_coord_len = if matches!(curve, EccCurve::P521) && !device_is_little_endian() {
        72
    } else {
        sign_coord_len
    };
    let mut input = vec![0; verify_coord_len * 2];
    for (index, component) in signature.chunks_exact(sign_coord_len).enumerate() {
        let start = index * verify_coord_len;
        input[start..start + sign_coord_len].copy_from_slice(component);
    }

    let pad = if device_is_little_endian() { 4 } else { 8 };
    let digest_lane_len = digest.len().next_multiple_of(pad).max(verify_coord_len);
    input.extend_from_slice(digest);
    input.resize(verify_coord_len * 2 + digest_lane_len, 0);
    input
}

fn verify_coord_len(curve: EccCurve) -> usize {
    if matches!(curve, EccCurve::P521) && !device_is_little_endian() {
        72
    } else {
        curve.wire_coord_len()
    }
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
        let generated = ctx
            .tbor(&TborEccGenerateKeyReq {
                session_id: session.session_id,
                scope: common::KEY_SCOPE_SESSION,
                curve: input.curve.to_tbor(),
                key_usage: KEY_USAGE_SIGN,
                key_label: Vec::new(),
            })
            .expect("seed key generation");

        let digest: Vec<u8> = (0..input.hash.digest_len())
            .map(|index| (index as u8).wrapping_mul(19).wrapping_add(input.value))
            .collect();
        let digest_wire = dev_rev(&digest);
        let signature = ctx
            .tbor(&TborEccSignReq {
                session_id: session.session_id,
                masked_key: generated.masked_key.clone(),
                hash_algo: input.hash.selector(),
                input: ecc_sign_input(
                    input.curve.wire_coord_len(),
                    if device_is_little_endian() { 4 } else { 8 },
                    &digest_wire,
                )
                .expect("bounded ECC sign input"),
            })
            .expect("seed signature")
            .signature;
        let mut masked_key = generated.masked_key.clone();
        let mut packed = packed_input(input.curve, &digest_wire, &signature);
        let mut hash_algo = input.hash.selector();

        match input.mutation {
            Mutation::Valid => {}
            Mutation::R => {
                packed[usize::from(input.index) % input.curve.coord_len()] ^= input.value | 1;
            }
            Mutation::S => {
                let at = verify_coord_len(input.curve)
                    + usize::from(input.index) % input.curve.coord_len();
                packed[at] ^= input.value | 1;
            }
            Mutation::Digest => {
                let digest_len = input.hash.digest_len();
                let retained_len = digest_len.min(input.curve.coord_len());
                let retained_start = if device_is_little_endian() {
                    digest_len - retained_len
                } else {
                    0
                };
                let at = verify_coord_len(input.curve) * 2
                    + retained_start
                    + usize::from(input.index) % retained_len;
                packed[at] ^= input.value | 1;
            }
            Mutation::Hash => hash_algo = HASH_ALGO_SHA1,
            Mutation::Length => {
                if packed.len() < ECC_VERIFY_INPUT_MAX_LEN {
                    packed.push(0);
                } else {
                    packed.pop();
                }
            }
            Mutation::Padding => {
                let raw_coord = input.curve.coord_len();
                let coord = verify_coord_len(input.curve);
                let signature_padding = raw_coord < coord;
                let at = if signature_padding {
                    raw_coord
                } else {
                    coord * 2 + input.hash.digest_len()
                };
                if at < packed.len() {
                    packed[at] = 1;
                } else {
                    packed.push(0);
                }
            }
            Mutation::Envelope => {
                let at = usize::from(input.index) % masked_key.len();
                masked_key[at] ^= 1;
            }
        }

        let req = TborEccVerifyReq {
            session_id: session.session_id,
            hash_algo,
            masked_key,
            input: packed,
        };
        let result = ctx.tbor(&req);
        match (result, input.mutation) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(_), Mutation::Valid) => {}
            (
                Err(DdiError::TborStatus(TborStatus::EccVerifyFailed)),
                Mutation::R | Mutation::S | Mutation::Digest,
            ) => {}
            (
                Err(DdiError::TborStatus(TborStatus::InvalidArg)),
                Mutation::Hash | Mutation::Length | Mutation::Padding,
            ) => {}
            (Err(_), Mutation::Envelope) => {}
            (Ok(_), mutation) => panic!("invalid EccVerify request succeeded: {mutation:?}"),
            (Err(err), mutation) => {
                panic!("unexpected EccVerify rejection for {mutation:?}: {err}")
            }
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
