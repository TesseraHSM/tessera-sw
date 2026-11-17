// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi::Ddi;
use tsra_ddi::DdiAesGcmParams;
use tsra_ddi::DdiAesXtsParams;
use tsra_ddi::DdiDev;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_types::DdiAesOp;

/// A small enum to differentiate between dispatching an AES-GCM request and an
/// AES-XTS request.
#[derive(Debug, Arbitrary, Clone)]
enum FuzzAesType {
    AesGcm,
    AesXts,
}

#[derive(Debug, Arbitrary, Clone)]
enum FuzzAesMode {
    Encrypt,
    Decrypt,
}

// Keep the legacy simulator field order for existing fuzz corpora.
#[derive(Debug, Arbitrary, Clone)]
struct FuzzAesGcmRequest {
    key_id: u32,
    iv: [u8; 12],
    tag: Option<[u8; 16]>,
    session_id: u16,
    short_app_id: u8,
    aad: Option<Vec<u8>>,
}

#[derive(Debug, Arbitrary, Clone)]
struct FuzzAesXtsRequest {
    data_unit_len: usize,
    key_id1: u32,
    key_id2: u32,
    tweak: [u8; 16],
    session_id: u16,
    short_app_id: u8,
}

/// A struct containing several fields to adjust the manner in which this fuzz
/// target executes.
#[derive(Debug, Arbitrary, Clone)]
struct FuzzInput {
    /// Tells the test which type of AES fast-path operation to dispatch (GCM or
    /// XTS).
    aes_type: FuzzAesType,

    /// Tells the test which AES mode to submit for the GCM/XTS request.
    /// (Encrypt or decrypt)
    aes_mode: FuzzAesMode,

    /// Randomized AES-GCM request data.
    gcm_request: FuzzAesGcmRequest,

    /// Randomized AES-XTS request data.
    xts_request: FuzzAesXtsRequest,

    /// Source buffers concatenated for the DDI fast-path slice operation.
    source_buffers: Vec<Vec<u8>>,

    /// Destination buffers concatenated for the DDI fast-path slice operation.
    destination_buffers: Vec<Vec<u8>>,
}

fuzz_target!(|input: FuzzInput| {
    let ddi = common::DdiTest::default();
    let dev_infos = ddi.dev_info_list();
    let path = std::env::var("FUZZ_DEVICE")
        .unwrap_or_else(|_| dev_infos.first().expect("No devices found").path.clone());
    let dev = ddi.open_dev(&path).expect("Failed to open device");
    let source: Vec<u8> = input.source_buffers.into_iter().flatten().collect();
    let mut destination: Vec<u8> = input.destination_buffers.into_iter().flatten().collect();
    let mode = match input.aes_mode {
        FuzzAesMode::Encrypt => DdiAesOp::Encrypt,
        FuzzAesMode::Decrypt => DdiAesOp::Decrypt,
    };
    let mut fips_approved = false;

    let result = match input.aes_type {
        FuzzAesType::AesGcm => {
            let request = input.gcm_request;
            let mut tag = None;
            let mut iv = None;
            dev.exec_op_fp_gcm_slice(
                mode,
                DdiAesGcmParams {
                    key_id: request.key_id,
                    iv: request.iv,
                    aad: request.aad,
                    tag: request.tag,
                    session_id: request.session_id,
                    short_app_id: request.short_app_id,
                },
                &source,
                &mut destination,
                &mut tag,
                &mut iv,
                &mut fips_approved,
            )
        }
        FuzzAesType::AesXts => {
            let request = input.xts_request;
            dev.exec_op_fp_xts_slice(
                mode,
                DdiAesXtsParams {
                    data_unit_len: request.data_unit_len,
                    key_id1: request.key_id1,
                    key_id2: request.key_id2,
                    tweak: request.tweak,
                    session_id: request.session_id,
                    short_app_id: request.short_app_id,
                },
                &source,
                &mut destination,
                &mut fips_approved,
            )
        }
    };
    if let Err(err @ DdiError::DriverError(_)) = result {
        panic!("Crash Detected: {err}");
    }
});
