// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device crypto byte order for test-side operand conversion.
//!
//! Crypto operands (big integers, curve coordinates, digests) travel in the
//! device's byte order: little-endian on Uno, big-endian on Duo. Host
//! crypto is big-endian, so tests convert through [`dev_rev`]. A test
//! process targets a single device, whose model the first [`TestDev`]
//! records here.
//!
//! [`TestDev`]: crate::fixture::TestDev

use std::sync::OnceLock;

use tsra_ddi_interface::DdiDeviceModel;

static DEVICE_MODEL: OnceLock<DdiDeviceModel> = OnceLock::new();

/// Record the model of the device this test process targets.
pub(crate) fn record_model(model: DdiDeviceModel) {
    let recorded = *DEVICE_MODEL.get_or_init(|| model);
    assert_eq!(
        recorded, model,
        "a test process must target one device model"
    );
}

/// Whether the device's crypto operands are little-endian (Uno) rather
/// than big-endian (Duo).
///
/// # Panics
///
/// Panics if no test device has been opened yet.
pub fn device_is_little_endian() -> bool {
    let model = DEVICE_MODEL
        .get()
        .expect("open a TestCtx before converting crypto operands");
    *model != DdiDeviceModel::Duo
}

/// Convert `bytes` between device byte order and big-endian: reversed on a
/// little-endian device, copied unchanged on a big-endian one.
pub fn dev_rev(bytes: &[u8]) -> Vec<u8> {
    if device_is_little_endian() {
        bytes.iter().rev().copied().collect()
    } else {
        bytes.to_vec()
    }
}

/// Convert `bytes` in place between device byte order and big-endian.
pub fn dev_rev_in_place(bytes: &mut [u8]) {
    if device_is_little_endian() {
        bytes.reverse();
    }
}

/// On-wire length of a curve coordinate of `raw_len` bytes. A
/// little-endian device pads P-521's 66-byte coordinates to 68 (4-byte
/// aligned); a big-endian one sends them unpadded.
pub fn wire_coord_len(raw_len: usize) -> usize {
    if raw_len == 66 && device_is_little_endian() {
        68
    } else {
        raw_len
    }
}

/// Converts one device-order ECC coordinate to the big-endian, 4-byte
/// aligned form `EccPublicKey::from_hsm_bytes` expects (P-521: 68 bytes).
pub fn dev_coord_to_host_be(coord: &[u8]) -> Vec<u8> {
    let be = dev_rev(coord);
    let aligned = be.len().next_multiple_of(4);
    let mut out = vec![0u8; aligned - be.len()];
    out.extend(be);
    out
}
