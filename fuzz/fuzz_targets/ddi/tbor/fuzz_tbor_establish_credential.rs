// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_test_harness::ROTATED_CO_PSK;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_co;
use tsra_ddi_tbor_test_harness::encrypt_mach_seed_envelope;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::TborPartInitReq;

/// Fuzzed base request parameters for the TBOR `PartInit` operation.
#[derive(Arbitrary, Debug)]
pub struct PartInitCmdReqData {
    /// Raw `mach_seed` plaintext. Always sealed into a wire-correct
    /// AEAD-GCM envelope (canonical session-bound AAD), which is then
    /// optionally corrupted by [`FuzzInput::envelope_mutation`].
    pub mach_seed: [u8; MACH_SEED_LEN],
    /// Fuzzed CBOR `part_policy` document (known-good, structured or raw).
    pub part_policy: common::FuzzPolicy,
}

/// Fuzz input for the TBOR `PartInit` DDI op (the TBOR equivalent of
/// the MBOR `EstablishCredential` op: both bootstrap a partition's
/// initial trust material from inside a freshly-authenticated
/// Crypto-Officer session).
#[derive(Arbitrary, Debug)]
pub struct FuzzInput {
    /// Post-seal mutation applied to the wire-valid 100-byte
    /// `mach_seed` envelope. Mutating a valid envelope (rather than
    /// shipping raw bytes) keeps the length gate satisfied for
    /// `FlipByte`, so malformed headers, AAD, ciphertext, and tags reach
    /// the device-side envelope parser.
    pub envelope_mutation: common::EnvelopeMutation,
    /// A fuzzed `PartInitCmdReqData` structure that provides the base
    /// for request parameters for the `PartInit` operation.
    pub cmdreq_data: PartInitCmdReqData,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_tbor_establish_credential(input);
});

pub fn fuzz_tbor_establish_credential(input: FuzzInput) {
    common::common_fuzz_test(&|ctx: &TestCtx, _path: &str| {
        // `PartInit` is a CO-session command; bootstrap and
        // authenticate a CO session the same way the `PartInit`
        // integration suite does (rotating off the public default PSK
        // so the request clears the default-PSK reject arm).
        let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

        let mut mach_seed_envelope =
            encrypt_mach_seed_envelope(&session, &input.cmdreq_data.mach_seed)
                .expect("mach_seed envelope should seal");
        // Snapshot no-op-ness against the pre-mutation envelope.
        let envelope_is_valid = input.envelope_mutation.is_noop(&mach_seed_envelope);
        input.envelope_mutation.apply(&mut mach_seed_envelope);

        let part_policy = input.cmdreq_data.part_policy.to_bytes();

        // `PartInit` succeeds only with an unmutated (authentic) `mach_seed`
        // envelope and a canonical, schema-valid policy document; the
        // policy thumbprints are opaque claims at this stage.
        let expect_success = envelope_is_valid && common::is_valid_part_policy(&part_policy);

        let req = TborPartInitReq {
            session_id: session.session_id,
            mach_seed_envelope,
            part_policy,
        };

        let resp = ctx.tbor(&req);

        match (&resp, expect_success) {
            (Err(err @ DdiError::DriverError(_)), _) => panic!("Crash Detected: {err}"),
            (Ok(resp), true) => {
                assert!(!resp.pta_csr.is_empty(), "PartInit must return a PTA CSR");
                assert!(
                    !resp.pta_report.is_empty(),
                    "PartInit must return a PTA report"
                );
            }
            (Ok(_), false) => {
                panic!("invalid PartInit request unexpectedly succeeded")
            }
            (Err(err), true) => panic!("valid PartInit request failed: {err}"),
            (Err(_), false) => {}
        }

        ctx.session_close(session.session_id)
            .expect("session close should succeed");
    });
}
