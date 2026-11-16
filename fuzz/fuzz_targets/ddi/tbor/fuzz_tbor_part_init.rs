// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_crypto::aead_envelope::AeadAlg;
use tsra_crypto::aead_envelope::HEADER_LEN;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::encrypt_mach_seed_envelope;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::TborPartInitReq;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// 32-byte `mach_seed` plaintext sealed under the active session's
    /// `param_key`; guarantees the wire envelope authenticates so the
    /// FW handler advances past AEAD into the policy/seed pipeline.
    mach_seed: [u8; MACH_SEED_LEN],
    /// Optional post-seal mutation for reject-path coverage.
    envelope_mutation: common::EnvelopeMutation,
    /// Fuzzed CBOR partition policy (known-good, structured or raw).
    policy: common::FuzzPolicy,
}

fuzz_target!(|input: FuzzInput| {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        // Fresh-slate CO session under a rotated (non-default) PSK — the
        // gate `PartInit` needs cleared before the fuzzed opcode can fire.
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

        // `PartInit` records the policy as a claim but never walks the
        // PTA cert chain, so thumbprints need not name real keys.
        let part_policy = input.policy.to_bytes();
        let policy_is_valid = common::is_valid_part_policy(&part_policy);

        // Seal the fuzzed 32-byte mach_seed under the freshly negotiated
        // param_key so the envelope authenticates; then optionally apply
        // a fuzzed mutation to cover AEAD-reject / length-reject paths.
        let mut mach_seed_envelope = encrypt_mach_seed_envelope(&session, &input.mach_seed)
            .expect("sealing mach_seed under session param_key should succeed");
        // Opening ignores the stored IV suffix: only its first 12 bytes
        // form the GCM nonce. Flips in that suffix still authenticate.
        let envelope_is_valid = input.envelope_mutation.is_noop(&mach_seed_envelope)
            || match &input.envelope_mutation {
                common::EnvelopeMutation::FlipByte { offset, .. } => (HEADER_LEN + 12
                    ..HEADER_LEN + AeadAlg::AesGcm256.iv_len())
                    .contains(&(usize::from(*offset) % mach_seed_envelope.len())),
                _ => false,
            };
        input.envelope_mutation.apply(&mut mach_seed_envelope);

        let part_init_req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope,
            part_policy,
        };

        // Classify the fuzzed inputs by deterministic outcome so we can
        // catch bugs where a valid input is rejected or an invalid input
        // is accepted (silent regressions the `let _` discard would hide).
        //
        // * expect_success: envelope is unchanged except possibly in
        //   the ignored IV suffix AND the policy is a canonical,
        //   schema-valid CBOR document. The AEAD open authenticates and
        //   the handler runs the provisioning pipeline through Commit.
        // * expect_failure: any other non-noop envelope mutation changes
        //   the required length, invalidates the header, or tampers with
        //   the nonce/AAD/ciphertext/tag; or the policy is malformed,
        //   non-canonical or oversized. Encoding, firmware decoding,
        //   or AEAD authentication rejects it with `TborEncodeError`
        //   or a firmware `TborStatus`, never a response-decoding failure.
        let result = ctx.tbor(&part_init_req);

        if envelope_is_valid && policy_is_valid {
            result.expect(
                "PartInit should succeed with an authentic envelope and a wire-valid request",
            );
        } else {
            assert!(
                matches!(
                    &result,
                    Err(DdiError::TborStatus(_) | DdiError::TborEncodeError)
                ),
                "PartInit should reject an invalid envelope or policy with a firmware \
                 status or request-encoding error, got {result:?}"
            );
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
});
