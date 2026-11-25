// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: calling a field twice should not compile.
use tsra_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x06)]
pub struct DupReq {
    a: u8,
    b: u16,
}

fn main() {
    let mut buf = [0u8; 64];
    let _ = DupReq::encode(&mut buf, (1, 1)).expect("dup request encoding should succeed")
        .a(1).expect("a field should be available")
        .a(2).expect("a field should be available") // ERROR: `a` not available on State1
        .b(3).expect("b field should be available")
        .finish();
}
