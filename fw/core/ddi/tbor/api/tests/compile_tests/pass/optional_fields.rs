// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Valid: optional fields with early finish and skip-ahead.
use tsra_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x02)]
pub struct OptReq {
    required: u8,
    opt_a: Option<u16>,
    opt_b: Option<u8>,
}

fn main() {
    let mut buf = [0u8; 64];

    // Set all fields.
    let _ = OptReq::encode(&mut buf, (1, 1)).expect("optional request encoding should succeed")
        .required(1).expect("required value lookup should succeed")
        .opt_a(Some(2)).expect("optional a field should be available")
        .opt_b(Some(3)).expect("optional b field should be available")
        .finish();

    // Early finish — skip trailing optionals.
    let _ = OptReq::encode(&mut buf, (1, 1)).expect("optional request encoding should succeed")
        .required(1).expect("required value lookup should succeed")
        .finish();

    // Skip intermediate optional, jump to opt_b.
    let _ = OptReq::encode(&mut buf, (1, 1)).expect("optional request encoding should succeed")
        .required(1).expect("required value lookup should succeed")
        .opt_b(Some(3)).expect("optional b field should be available")
        .finish();

    // Set opt_a with None explicitly.
    let _ = OptReq::encode(&mut buf, (1, 1)).expect("optional request encoding should succeed")
        .required(1).expect("required value lookup should succeed")
        .opt_a(None).expect("optional a field should be available")
        .opt_b(Some(3)).expect("optional b field should be available")
        .finish();
}
