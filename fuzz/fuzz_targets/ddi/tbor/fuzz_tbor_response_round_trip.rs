// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::EncoderTOCBuilders;
use common::FUZZ_RESP_BUF_SIZE;
use common::run_encoder;
use common::validate_toc_entry;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tsra_ddi_tbor_codec::ResponseEncoder;
use tsra_ddi_tbor_codec::ResponseView;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    buf_size: usize,
    api_rev: (u16, u16),
    status: u32,
    fips_approved: bool,
    ops: Vec<EncoderTOCBuilders>,
}

fuzz_target!(|input: FuzzInput| {
    let mut backing = [0u8; FUZZ_RESP_BUF_SIZE];
    let len = input.buf_size % (FUZZ_RESP_BUF_SIZE + 1); // clamp into range
    let buf = &mut backing[..len];
    let encoder = ResponseEncoder::new(buf, input.api_rev, input.status, input.fips_approved);
    if let Some(encoded) = run_encoder(encoder, &input.ops) {
        let view = ResponseView::parse(encoded)
            .expect("bytes from a successful ResponseEncoder::finish must parse");
        assert_eq!(view.api_rev(), input.api_rev);
        assert_eq!(view.status(), input.status);
        assert_eq!(view.fips_approved(), input.fips_approved);
        assert_eq!(view.flags(), u8::from(input.fips_approved));
        assert_eq!(view.toc_count(), input.ops.len());
        let _ = view.data_start();
        let _ = view.data_size();
        let _ = view.len();
        let _ = view.is_empty();
        let _ = view.as_bytes();
        let _ = view.data_section();

        for (i, (entry, op)) in view.toc_iter().zip(input.ops).enumerate() {
            assert_eq!(view.toc_entry(i), entry);
            let _ = view.toc_entry_type(i);

            validate_toc_entry(&op, entry);
        }
    }
});
