// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Valid: response with optional and FIPS flag.
use tsra_fw_ddi_tbor_api::tbor;

#[tbor(response)]
pub struct MyResp<'a> {
    #[tbor(max_len = 256)]
    data: &'a [u8],
    #[tbor(max_len = 256)]
    opt_tag: Option<&'a [u8]>,
}

fn main() {
    let mut buf = [0u8; 256];

    // With tag.
    let _ = MyResp::encode(&mut buf, (1, 1), 0, true).expect("my response encoding should succeed")
        .data(b"ciphertext").expect("data field should be available")
        .opt_tag(Some(b"tag")).expect("optional tag field should be available")
        .finish();

    // Without tag — early finish.
    let _ = MyResp::encode(&mut buf, (1, 1), 0, false).expect("my response encoding should succeed")
        .data(b"ciphertext").expect("data field should be available")
        .finish();
}
