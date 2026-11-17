// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Constructor coverage for the public `Request` / `Response` header types.

use tsra_ddi_tbor_codec::Header;
use tsra_ddi_tbor_codec::Request;
use tsra_ddi_tbor_codec::Response;

#[test]
fn request_header_encodes_full_width_revision_and_opcode() {
    let hdr = Request::new((0x1234, 0x5678), 0x42);
    let mut bytes = [0xA5; 12];
    Request::write_header(&mut bytes, &hdr, 2);
    assert_eq!(bytes, [0x34, 0x12, 0x78, 0x56, 1, 0x42, 0, 0, 0, 0, 0, 0]);
    assert_eq!(hdr.opcode, 0x42);
}

#[test]
fn response_new_without_fips_clears_flags() {
    let hdr = Response::new((2, 0), 0x1234_5678, false);
    assert_eq!(hdr.api_rev, (2, 0));
    assert_eq!(hdr.status, 0x1234_5678);
    assert_eq!(hdr.flags, 0);
}

#[test]
fn response_new_with_fips_sets_flag_bit() {
    let hdr = Response::new((0x1234, 0x5678), 0xDEAD_BEEF, true);
    let mut bytes = [0xA5; 12];
    Response::write_header(&mut bytes, &hdr, 1);
    assert_eq!(
        bytes,
        [0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0xEF, 0xBE, 0xAD, 0xDE]
    );
    assert_eq!(
        hdr.flags & Response::FIPS_APPROVED_FLAG,
        Response::FIPS_APPROVED_FLAG
    );
}
