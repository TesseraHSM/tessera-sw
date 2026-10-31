// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Pass: #[tbor] on a struct with no fields. The body wire-encodes as a
// single synthetic `None` TOC placeholder, and the generated decoder
// validates that placeholder is present.
#![allow(unsafe_code)]
use tsra_fw_ddi_tbor_api::tbor;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;

fn brand(b: &[u8]) -> &HsmDmaBuf {
    unsafe { HsmDmaBuf::from_raw(b) }
}

#[tbor(opcode = 0x01)]
pub struct EmptyReq {}

fn main() {
    let mut buf = [0u8; 16];
    let frame = EmptyReq::encode(&mut buf).expect("encode").finish();
    let bytes = frame.as_bytes();
    // 8-byte header + 1 TOC entry (4 bytes) = 12 bytes total.
    assert_eq!(bytes.len(), 12);
    EmptyReq::decode(brand(bytes)).expect("decode");
}
