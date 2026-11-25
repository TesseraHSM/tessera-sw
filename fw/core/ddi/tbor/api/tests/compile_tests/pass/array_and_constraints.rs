// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Valid: fixed-size array and length constraints.
#![allow(unsafe_code)]
use tsra_fw_ddi_tbor_api::tbor;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;

fn brand(b: &[u8]) -> &HsmDmaBuf {
    unsafe { HsmDmaBuf::from_raw(b) }
}

#[tbor(opcode = 0x03)]
pub struct ArrayReq<'a> {
    nonce: [u8; 16],
    #[tbor(min_len = 1, max_len = 64)]
    tag: &'a [u8],
    #[tbor(align = 4, max_len = 256)]
    payload: &'a [u8],
}

fn main() {
    let nonce = [0u8; 16];
    let mut buf = [0u8; 256];
    let frame = ArrayReq::encode(&mut buf, (1, 1))
        .expect("array request encoding should succeed")
        .nonce(&nonce)
        .expect("nonce field should be available")
        .tag(b"hello")
        .expect("tag field should be available")
        .payload(b"data")
        .expect("payload field should be available")
        .finish();

    let view = ArrayReq::decode(brand(frame.as_bytes())).expect("array request decoding should succeed");
    let _n: &HsmDmaBuf = view.nonce(); // accessor returns &HsmDmaBuf uniformly
}
