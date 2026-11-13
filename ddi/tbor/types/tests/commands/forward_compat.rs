// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the forward/backward-compatibility contract of derived
//! [`TborResp::decode_response`] implementations.
//!
//! The host derive emits a `toc_count() < expected_toc` gate so that:
//!
//! * **Fewer** entries than the schema knows ⇒
//!   [`codec::DecodeError::MessageTruncated`].
//! * **Exactly** the expected number of entries ⇒ the response decodes
//!   normally.
//! * **More** entries than the schema knows ⇒ trailing entries are
//!   ignored and the known prefix decodes successfully.
//!
//! Coverage includes representative response layouts:
//!
//! * Inline scalar fields in `TborApiRevResp`.
//! * Typed inline fields (`SessionId` and `KeyId`).
//! * Single variable-length buffers in `TborEccSignResp` and
//!   `TborKeyReportResp`.
//! * Variable-length buffer plus fixed-size array in
//!   `TborAesEncryptDecryptResp`.
//! * Two variable-length buffers in `TborEccGenerateKeyResp`.
//! * Scalar plus two variable-length buffers in `TborUnwrapKeyResp`.
//! * Mixed-width integer and fixed-size buffer fields in
//!   `TborPartInfoResp`.
//! * Session-id plus multiple fixed-size buffer fields in
//!   `TborSessionOpenInitResp`.

use tsra_ddi_tbor_codec::EncodeError;
use tsra_ddi_tbor_codec::MAX_TOC_ENTRIES;
use tsra_ddi_tbor_types::codec::DecodeError;
use tsra_ddi_tbor_types::codec::ResponseEncoder;
use tsra_ddi_tbor_types::codec::PROTOCOL_VERSION;
use tsra_ddi_tbor_types::tbor;
use tsra_ddi_tbor_types::tbor_int::U32;
use tsra_ddi_tbor_types::tbor_int::U64;
use tsra_ddi_tbor_types::TborAesEncryptDecryptResp;
use tsra_ddi_tbor_types::TborApiRevResp;
use tsra_ddi_tbor_types::TborEccGenerateKeyResp;
use tsra_ddi_tbor_types::TborEccSignResp;
use tsra_ddi_tbor_types::TborKeyReportResp;
use tsra_ddi_tbor_types::TborPartInfoResp;
use tsra_ddi_tbor_types::TborResp;
use tsra_ddi_tbor_types::TborSessionOpenInitResp;
use tsra_ddi_tbor_types::TborUnwrapKeyResp;

#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyIdForwardCompatResp {
    #[tbor(key_id)]
    key_id: u16,
    value: u8,
}

/// Number of known TOC entries in `TborApiRevResp`.
const API_REV_FIELDS: usize = 4;

const TRAILING_COUNT: usize = MAX_TOC_ENTRIES - API_REV_FIELDS;

/// `TborApiRevResp` field values in wire order:
/// `[min_major, min_minor, max_major, max_minor]`.
type Rev = [u16; API_REV_FIELDS];

/// Returns the decoded `TborApiRevResp` fields in wire order.
fn fields(resp: &TborApiRevResp) -> Rev {
    [
        resp.min_major.get(),
        resp.min_minor.get(),
        resp.max_major.get(),
        resp.max_minor.get(),
    ]
}

/// Encode the leading `known` API revision fields followed by the
/// supplied future fields.
fn encode_api_rev_fields<'a>(buf: &'a mut [u8], known: &[u16], trailing: &[u8]) -> &'a [u8] {
    let mut encoder = ResponseEncoder::new(buf, PROTOCOL_VERSION, 0, false);
    for (index, value) in known.iter().copied().enumerate() {
        encoder = encoder
            .uint16(value)
            .unwrap_or_else(|err| panic!("encode known field {index}: {err:?}"));
    }
    for value in trailing.iter().copied() {
        encoder = encoder.uint8(value).unwrap_or_else(|err| {
            panic!("encode trailing future field with value {value:#04x}: {err:?}")
        });
    }
    encoder.finish().expect("finish response")
}

/// Encode all four API revision fields followed by the supplied future
/// fields.
fn encode_api_rev_with_trailing<'a>(buf: &'a mut [u8], rev: Rev, trailing: &[u8]) -> &'a [u8] {
    encode_api_rev_fields(buf, &rev, trailing)
}

/// Decode a normal four-field `TborApiRevResp`.
fn decode_api_rev(rev: Rev) -> TborApiRevResp {
    let mut buf = [0u8; 64];
    let bytes = encode_api_rev_with_trailing(&mut buf, rev, &[]);
    TborApiRevResp::decode_response(bytes).expect("decode API revision response")
}

/// Decode `rev` followed by `trailing` future fields, asserting the known
/// fields survive.
fn assert_known_fields_survive(rev: Rev, trailing: &[u8]) {
    let mut buf = [0u8; 512];
    let bytes = encode_api_rev_with_trailing(&mut buf, rev, trailing);
    let resp = TborApiRevResp::decode_response(bytes).unwrap_or_else(|err| {
        panic!(
            "{rev:?} with {} trailing entries must decode: {err:?}",
            trailing.len()
        )
    });
    assert_eq!(
        fields(&resp),
        rev,
        "known fields changed with {} trailing entries",
        trailing.len()
    );
}

/// Verifies that a response with exactly the expected TOC count decodes successfully.
#[test]
fn exact_toc_count_decodes_successfully() {
    assert_eq!(fields(&decode_api_rev([1, 0, 1, 1])), [1, 0, 1, 1]);
}

/// Verifies that exact-count decoding preserves zero-valued known fields.
#[test]
fn exact_toc_count_preserves_zero_values() {
    assert_eq!(fields(&decode_api_rev([0; 4])), [0; 4]);
}

/// Verifies that exact-count decoding preserves the full `u16` boundary range.
#[test]
fn exact_toc_count_preserves_uint16_boundary_values() {
    for rev in [
        [u16::MIN, u16::MAX, u16::MIN, u16::MAX],
        [u16::MAX, u16::MIN, u16::MAX, u16::MIN],
        [u16::MAX; 4],
    ] {
        assert_eq!(fields(&decode_api_rev(rev)), rev);
    }
}

/// Verifies that exact-count decoding preserves representative known-field sets.
#[test]
fn exact_toc_count_preserves_representative_value_sets() {
    let cases: [Rev; 8] = [
        [0, 0, 0, 0],
        [1, 0, 1, 1],
        [2, 0, 2, 0],
        [1, 0, 2, 0],
        [0x00FF, 0xFF00, 0x0100, 0x00FE],
        [0x7FFF, 0x8000, 0x8001, 0x7FFE],
        [0x5555, 0xAAAA, 0xAAAA, 0x5555],
        [0x1234, 0x5678, 0x9ABC, 0xDEF0],
    ];

    for rev in cases {
        assert_eq!(
            fields(&decode_api_rev(rev)),
            rev,
            "fields changed for {rev:?}"
        );
    }
}

/// Verifies that one appended future TOC entry is ignored.
#[test]
fn one_extra_trailing_toc_entry_is_ignored() {
    // TborApiRevResp expects four Uint16 TOC entries. Encode five:
    // the four known fields plus one future-field placeholder.
    assert_known_fields_survive([1, 0, 1, 1], &[0xFF]);
}

/// Verifies that every possible `u8` value is ignored when appended as a future field.
#[test]
fn every_uint8_value_is_ignored_as_one_trailing_entry() {
    // The compatibility behavior must not depend on the encoded value
    // of the appended field.
    for trailing_value in u8::MIN..=u8::MAX {
        assert_known_fields_survive([0x12, 0x34, 0x56, 0x78], &[trailing_value]);
    }
}

/// Verifies that multiple appended future TOC entries are ignored.
#[test]
fn multiple_extra_trailing_toc_entries_are_ignored() {
    // Verify that compatibility is not limited to exactly one appended
    // field. A newer firmware may append several fields over time.
    assert_known_fields_survive([0x11, 0x22, 0x33, 0x44], &[0x55, 0x66, 0x77]);
}

/// Verifies that trailing future entries cannot overwrite known decoded fields.
#[test]
fn trailing_entries_do_not_overwrite_known_fields() {
    // Use deliberately different values for every entry to ensure the
    // decoder reads the known prefix rather than accidentally reading
    // the final entries.
    let mut buf = [0u8; 64];
    let bytes = encode_api_rev_with_trailing(&mut buf, [0x01, 0x02, 0x03, 0x04], &[0xA1, 0xA2]);

    let resp = TborApiRevResp::decode_response(bytes)
        .expect("trailing fields must not change known decoded fields");

    assert_eq!(fields(&resp), [0x01, 0x02, 0x03, 0x04]);
    assert!(fields(&resp)
        .iter()
        .all(|&field| field != 0xA1 && field != 0xA2));
}

/// Verifies that repeatedly decoding the same extended response produces identical results.
#[test]
fn repeated_decode_of_forward_compatible_message_is_deterministic() {
    let trailing = [0x10, 0x20, 0x30, 0x40, 0x50];
    let mut buf = [0u8; 128];

    let bytes = encode_api_rev_with_trailing(&mut buf, [0x09, 0x0A, 0x0B, 0x0C], &trailing);

    let first = TborApiRevResp::decode_response(bytes).expect("first decode with trailing entries");
    let second =
        TborApiRevResp::decode_response(bytes).expect("second decode with trailing entries");

    assert_eq!(fields(&first), [0x09, 0x0A, 0x0B, 0x0C]);
    assert_eq!(second, first);
}

/// Verifies that a response missing any required TOC entry is truncated.
#[test]
fn missing_known_toc_entries_are_message_truncated() {
    let rev: Rev = [1, 0, 1, 1];
    for present in 1..API_REV_FIELDS {
        let mut buf = [0u8; 64];
        let bytes = encode_api_rev_fields(&mut buf, &rev[..present], &[]);

        let err = TborApiRevResp::decode_response(bytes)
            .expect_err("a response missing a known field must produce MessageTruncated");

        assert_eq!(
            err,
            DecodeError::MessageTruncated,
            "unexpected result with {present} of {API_REV_FIELDS} fields",
        );
    }
}

/// Verifies that the response encoder rejects an empty TOC.
#[test]
fn zero_toc_entries_cannot_be_encoded() {
    // ResponseEncoder requires at least one TOC entry, so an empty
    // response cannot reach TborApiRevResp::decode_response.
    let mut buf = [0u8; 64];

    let err = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .finish()
        .expect_err("an empty response must be rejected by the encoder");

    assert_eq!(err, EncodeError::MissingTocEntries);
}

/// Verifies that truncation depends on TOC count rather than the present field values.
#[test]
fn truncated_result_is_independent_of_present_field_values() {
    // The TOC count, rather than the values of the existing entries,
    // determines whether the message is truncated.
    for value in [u16::MIN, 0x0001, 0x7FFF, u16::MAX] {
        let mut buf = [0u8; 64];
        let bytes = encode_api_rev_fields(&mut buf, &[value; API_REV_FIELDS - 1], &[]);

        let err = TborApiRevResp::decode_response(bytes).expect_err(
            "a three-entry response must be truncated regardless \
                 of field values",
        );

        assert_eq!(
            err,
            DecodeError::MessageTruncated,
            "unexpected result for value={value:#06x}",
        );
    }
}

/// Verifies for every `u16` value that a lone first field is truncated.
#[test]
fn every_uint16_first_field_value_is_truncated_when_others_are_missing() {
    // Exhaustively verify that no possible first-field value can alter
    // the schema-length check.
    for min_major in u16::MIN..=u16::MAX {
        let mut buf = [0u8; 64];
        let bytes = encode_api_rev_fields(&mut buf, &[min_major], &[]);

        let err = TborApiRevResp::decode_response(bytes)
            .expect_err("missing fields must produce MessageTruncated");

        assert_eq!(
            err,
            DecodeError::MessageTruncated,
            "unexpected result for min_major={min_major:#06x}",
        );
    }
}

/// Verifies that forward-compatible decoding preserves boundary-valued known fields.
#[test]
fn forward_compatibility_preserves_boundary_values() {
    // Exercise the compatibility behavior while the known fields
    // contain their minimum and maximum representable values.
    assert_known_fields_survive([u16::MIN, u16::MAX, u16::MIN, u16::MAX], &[0x55]);
}

/// Verifies that forward-compatible decoding preserves representative known-field values.
#[test]
fn forward_compatibility_preserves_representative_known_values() {
    let cases: [Rev; 7] = [
        [0, 0, 0, 0],
        [1, 0, 1, 1],
        [2, 0, 2, 0],
        [u16::MAX; 4],
        [0x0001, 0xFFFE, 0xFFFE, 0x0001],
        [0x7FFF, 0x8000, 0x8000, 0x7FFF],
        [0x5555, 0xAAAA, 0x5555, 0xAAAA],
    ];

    for rev in cases {
        assert_known_fields_survive(rev, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }
}

/// Verifies that the maximum supported TOC count still decodes the known prefix.
#[test]
fn maximum_supported_toc_count_decodes_known_prefix() {
    // TborApiRevResp uses four known TOC entries; fill the remaining
    // encoder capacity with trailing future entries.
    let trailing: [u8; TRAILING_COUNT] = core::array::from_fn(|index| index as u8);
    assert_known_fields_survive([u16::MIN, u16::MAX, u16::MIN, u16::MAX], &trailing);
}

/// Verifies that the encoder rejects a TOC entry beyond its supported limit.
#[test]
fn toc_entry_beyond_encoder_limit_is_rejected() {
    // Fill the remaining TOC capacity after the four known fields.
    // One additional entry beyond MAX_TOC_ENTRIES must fail with
    // TooManyTocEntries.
    let mut buf = [0u8; 512];

    let mut encoder = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false);
    for value in [1, 0, 1, 1] {
        encoder = encoder.uint16(value).expect("encode known field");
    }

    for index in 0..TRAILING_COUNT {
        encoder = encoder.uint8(index as u8).unwrap_or_else(|err| {
            panic!(
                "trailing field {index} must fit within the \
             MAX_TOC_ENTRIES limit: {err:?}"
            )
        });
    }

    let err = encoder
        .uint8(0xFF)
        .expect_err("one TOC entry beyond MAX_TOC_ENTRIES must be rejected");

    assert_eq!(err, EncodeError::TooManyTocEntries);
}

/// Verifies that the maximum supported number of trailing future entries is ignored.
#[test]
fn many_extra_trailing_toc_entries_are_ignored() {
    // Exercise the maximum number of future fields supported by the
    // encoder after the four known fields.
    let trailing: [u8; TRAILING_COUNT] = core::array::from_fn(|index| index as u8);
    assert_known_fields_survive([0x21, 0x43, 0x65, 0x87], &trailing);
}

/// Verifies that varying supported trailing-entry counts preserve the same known fields.
#[test]
fn different_trailing_counts_preserve_the_same_known_fields() {
    // Include values immediately below and at the encoder's maximum
    // supported trailing-entry count.
    for trailing_count in [0usize, 1, 2, 3, 8, 16, TRAILING_COUNT - 1, TRAILING_COUNT] {
        let trailing: Vec<u8> = (0..trailing_count).map(|index| index as u8).collect();
        assert_known_fields_survive([0x6A, 0xB5, 0x6B, 0xB6], &trailing);
    }
}

/// Verifies exact-count decoding across representative `u16` values.
#[test]
fn exact_toc_count_preserves_representative_uint16_sets() {
    let values = [u16::MIN, 0x0001, 0x7FFF, 0x8000, 0xFFFE, u16::MAX];

    for major in values {
        for minor in values {
            let rev = [major, minor, minor, major];
            assert_eq!(
                fields(&decode_api_rev(rev)),
                rev,
                "fields changed for {rev:?}"
            );
        }
    }
}

/// Verifies that decoding preserves field values without imposing semantic revision ordering.
#[test]
fn exact_toc_count_does_not_require_min_rev_to_be_at_most_max_rev() {
    assert_eq!(fields(&decode_api_rev([2, 5, 1, 0])), [2, 5, 1, 0]);
}

/// Verifies that equal known-field values are preserved with appended future fields.
#[test]
fn forward_compatibility_preserves_equal_known_values() {
    assert_known_fields_survive([2, 0, 2, 0], &[0x10, 0x20, 0x30, 0x40]);
}

/// Verifies that maximum-count trailing entries filled with zero are ignored.
#[test]
fn maximum_supported_trailing_zero_values_are_ignored() {
    assert_known_fields_survive([0x12, 0x34, 0x56, 0x78], &[u8::MIN; TRAILING_COUNT]);
}

/// Verifies that maximum-count trailing entries filled with `u8::MAX` are ignored.
#[test]
fn maximum_supported_trailing_max_values_are_ignored() {
    assert_known_fields_survive([0x56, 0x78, 0x9A, 0xBC], &[u8::MAX; TRAILING_COUNT]);
}

/// Verifies that alternating boundary-valued future fields are ignored at the TOC limit.
#[test]
fn maximum_supported_alternating_trailing_values_are_ignored() {
    let trailing: [u8; TRAILING_COUNT] =
        core::array::from_fn(|index| if index % 2 == 0 { u8::MIN } else { u8::MAX });
    assert_known_fields_survive([0xA5, 0x5A, 0xA5, 0x5A], &trailing);
}

/// Verifies forward compatibility immediately below and at the maximum TOC count.
#[test]
fn forward_compatibility_preserves_known_fields_at_toc_limit_boundary() {
    for trailing_count in [TRAILING_COUNT - 1, TRAILING_COUNT] {
        let trailing: Vec<u8> = (0..trailing_count)
            .map(|index| 0xF0u8.wrapping_add(index as u8))
            .collect();
        assert_known_fields_survive([0x2A, 0xD5, 0x2B, 0xD6], &trailing);
    }
}

/// Encode one known buffer field followed by the supplied future fields.
fn encode_buffer_with_trailing<'a>(buf: &'a mut [u8], value: &[u8], trailing: &[u8]) -> &'a [u8] {
    let mut encoder = ResponseEncoder::new(buf, PROTOCOL_VERSION, 0, false)
        .buffer(value)
        .expect("encode known buffer");

    for value in trailing.iter().copied() {
        encoder = encoder.uint8(value).unwrap_or_else(|err| {
            panic!(
                "encode trailing future field \
                 with value {value:#04x}: {err:?}"
            )
        });
    }

    encoder.finish().expect("finish response")
}
/// Verifies exact-count decoding of a variable-length ECDSA signature.
#[test]
fn ecc_sign_exact_toc_count_decodes_signature() {
    let signature: Vec<u8> = (0..96).map(|index| index as u8).collect();
    let mut buf = [0u8; 512];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .buffer(&signature)
        .expect("encode signature")
        .finish()
        .expect("finish response");

    let resp = TborEccSignResp::decode_response(bytes).expect("decode ECC sign response");

    assert_eq!(resp.signature, signature);
}

/// Verifies that an appended field is ignored for a variable-length ECDSA signature.
#[test]
fn ecc_sign_extra_trailing_toc_entry_is_ignored() {
    let signature: Vec<u8> = (0..96).map(|index| index as u8).collect();
    let mut buf = [0u8; 512];

    let bytes = encode_buffer_with_trailing(&mut buf, &signature, &[0xFF]);

    let resp = TborEccSignResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb signature");

    assert_eq!(resp.signature, signature);
}

/// Verifies that multiple appended fields are ignored for an ECDSA signature.
#[test]
fn ecc_sign_multiple_trailing_toc_entries_are_ignored() {
    let signature: Vec<u8> = (0..96).map(|index| index as u8).collect();
    let trailing = [0x11, 0x22, 0x33, 0x44];
    let mut buf = [0u8; 512];

    let bytes = encode_buffer_with_trailing(&mut buf, &signature, &trailing);

    let resp = TborEccSignResp::decode_response(bytes)
        .expect("forward compatibility: trailing entries must not disturb signature");

    assert_eq!(resp.signature, signature);
}

/// Verifies forward-compatible decoding of the maximum-size ECDSA signature buffer.
#[test]
fn ecc_sign_maximum_signature_with_trailing_entry_is_preserved() {
    let signature: Vec<u8> = (0..136).map(|index| index as u8).collect();

    let mut buf = [0u8; 512];
    let bytes = encode_buffer_with_trailing(&mut buf, &signature, &[0xA5]);

    let resp = TborEccSignResp::decode_response(bytes)
        .expect("maximum-size signature with trailing entry must decode");

    assert_eq!(resp.signature, signature);
}
/// Verifies exact-count decoding of a variable-length key report.
#[test]
fn key_report_exact_toc_count_decodes_report() {
    let report: Vec<u8> = (0..512).map(|index| (index & 0xFF) as u8).collect();

    let mut buf = [0u8; 2048];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .buffer(&report)
        .expect("encode report")
        .finish()
        .expect("finish response");

    let resp = TborKeyReportResp::decode_response(bytes).expect("decode key report response");

    assert_eq!(resp.report, report);
}

/// Verifies that an appended field is ignored for a variable-length key report.
#[test]
fn key_report_extra_trailing_toc_entry_is_ignored() {
    let report: Vec<u8> = (0..512).map(|index| (index & 0xFF) as u8).collect();

    let mut buf = [0u8; 2048];

    let bytes = encode_buffer_with_trailing(&mut buf, &report, &[0xFF]);

    let resp = TborKeyReportResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb report");

    assert_eq!(resp.report, report);
}

/// Verifies that multiple appended fields are ignored for a variable-length key report.
#[test]
fn key_report_multiple_trailing_toc_entries_are_ignored() {
    let report: Vec<u8> = (0..512).map(|index| (index & 0xFF) as u8).collect();

    let trailing = [0x10, 0x20, 0x30, 0x40];
    let mut buf = [0u8; 2048];

    let bytes = encode_buffer_with_trailing(&mut buf, &report, &trailing);

    let resp = TborKeyReportResp::decode_response(bytes)
        .expect("forward compatibility: trailing entries must not disturb report");

    assert_eq!(resp.report, report);
}

/// Verifies forward-compatible decoding of the maximum-size key report buffer.
#[test]
fn key_report_maximum_report_with_trailing_entry_is_preserved() {
    let report: Vec<u8> = (0..1024).map(|index| (index & 0xFF) as u8).collect();

    let mut buf = [0u8; 2048];

    let bytes = encode_buffer_with_trailing(&mut buf, &report, &[0xA5]);

    let resp = TborKeyReportResp::decode_response(bytes)
        .expect("maximum-size report with trailing entry must decode");

    assert_eq!(resp.report, report);
}

/// Verifies that an appended field is ignored for a variable-length
/// message followed by a variable-length IV.
#[test]
fn aes_encrypt_decrypt_extra_trailing_toc_entry_is_ignored() {
    let msg: Vec<u8> = (0..64).map(|index| index as u8).collect();
    let iv = [0xA5u8; 16];

    let mut buf = [0u8; 512];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .buffer(&msg)
        .expect("encode transformed message")
        .buffer(&iv)
        .expect("encode IV")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborAesEncryptDecryptResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb AES response");

    assert_eq!(resp.msg, msg);
    assert_eq!(resp.iv, iv);
}

/// Rejects a response whose masked key is off its alignment boundary.
#[test]
fn ecc_generate_key_misaligned_masked_key_is_rejected() {
    let mut buf = [0u8; 1024];

    // The data section starts at 8 + 3 * 4 = 20, so 2 bytes of padding put
    // the masked key at offset 22.
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .padding(2)
        .expect("encode misaligning padding")
        .buffer(&[0x11; 180])
        .expect("encode masked key")
        .buffer(&[0x22; 96])
        .expect("encode public key")
        .finish()
        .expect("finish response");

    assert_eq!(
        TborEccGenerateKeyResp::decode_response(bytes).err(),
        Some(DecodeError::MisalignedField)
    );
}

/// Verifies that an appended field is ignored for a response containing
/// two variable-length buffers.
#[test]
fn ecc_generate_key_extra_trailing_toc_entry_is_ignored() {
    let masked_key: Vec<u8> = (0..180).map(|index| index as u8).collect();
    let pub_key: Vec<u8> = (0..96)
        .map(|index| 0xFFu8.wrapping_sub(index as u8))
        .collect();

    let mut buf = [0u8; 1024];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .padding(0)
        .expect("encode masked key alignment padding")
        .buffer(&masked_key)
        .expect("encode masked key")
        .buffer(&pub_key)
        .expect("encode public key")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborEccGenerateKeyResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb generated key response");

    assert_eq!(resp.masked_key, masked_key);
    assert_eq!(resp.pub_key, pub_key);
}

/// Verifies that an appended field is ignored for a mixed scalar and
/// multi-buffer response.
#[test]
fn unwrap_key_extra_trailing_toc_entry_is_ignored() {
    let key_kind = 0x03;

    let masked_key: Vec<u8> = (0..256).map(|index| (index & 0xFF) as u8).collect();

    let pub_key: Vec<u8> = (0..136)
        .map(|index| 0xFFu8.wrapping_sub(index as u8))
        .collect();

    let mut buf = [0u8; 1024];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(key_kind)
        .expect("encode key kind")
        .padding(0)
        .expect("encode masked key alignment padding")
        .buffer(&masked_key)
        .expect("encode masked key")
        .buffer(&pub_key)
        .expect("encode public key")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborUnwrapKeyResp::decode_response(bytes)
        .expect("forward compatibility: trailing entry must not disturb unwrap response");

    assert_eq!(resp.key_kind, key_kind);
    assert_eq!(resp.masked_key, masked_key);
    assert_eq!(resp.pub_key, pub_key);
}

/// Verifies that multiple appended fields are ignored for a mixed scalar
/// and multi-buffer response.
#[test]
fn unwrap_key_multiple_trailing_toc_entries_are_ignored() {
    let key_kind = 0x03;
    let masked_key = vec![0x11; 256];
    let pub_key = vec![0x22; 136];

    let mut buf = [0u8; 1024];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(key_kind)
        .expect("encode key kind")
        .padding(0)
        .expect("encode masked key alignment padding")
        .buffer(&masked_key)
        .expect("encode masked key")
        .buffer(&pub_key)
        .expect("encode public key")
        .uint8(0xA1)
        .expect("encode future field 1")
        .uint8(0xA2)
        .expect("encode future field 2")
        .uint8(0xA3)
        .expect("encode future field 3")
        .finish()
        .expect("finish response");

    let resp = TborUnwrapKeyResp::decode_response(bytes)
        .expect("forward compatibility: trailing entries must not disturb unwrap response");

    assert_eq!(resp.key_kind, key_kind);
    assert_eq!(resp.masked_key, masked_key);
    assert_eq!(resp.pub_key, pub_key);
}

/// Verifies that a mixed response missing its final required field is truncated.
#[test]
fn unwrap_key_missing_required_field_is_message_truncated() {
    let key_kind = 0x03;
    let masked_key = vec![0x11; 256];

    let mut buf = [0u8; 1024];

    // TborUnwrapKeyResp expects:
    //   key_kind, masked_key alignment padding, masked_key, pub_key.
    // Encode all but pub_key.
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(key_kind)
        .expect("encode key kind")
        .padding(0)
        .expect("encode masked key alignment padding")
        .buffer(&masked_key)
        .expect("encode masked key")
        .finish()
        .expect("finish response");

    let err = TborUnwrapKeyResp::decode_response(bytes)
        .expect_err("missing pub_key must produce MessageTruncated");

    assert_eq!(err, DecodeError::MessageTruncated);
}

/// Verifies that an AES response missing its IV is reported as truncated.
#[test]
fn aes_encrypt_decrypt_missing_iv_is_message_truncated() {
    let msg = vec![0x22; 64];
    let mut buf = [0u8; 512];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .buffer(&msg)
        .expect("encode transformed message")
        .finish()
        .expect("finish response");

    let err = TborAesEncryptDecryptResp::decode_response(bytes)
        .expect_err("missing IV must produce MessageTruncated");

    assert_eq!(err, DecodeError::MessageTruncated);
}

/// Verifies forward compatibility for mixed-width integers and
/// fixed-size buffer fields.
#[test]
fn part_info_extra_trailing_toc_entry_is_ignored() {
    let pid = [0xA5u8; 16];
    let pid_pub_key = [0x5Au8; 96];

    let mut buf = [0u8; 512];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .uint8(0x02)
        .expect("encode device kind")
        .uint8(0x03)
        .expect("encode partition state")
        .uint32(0x1122_3344)
        .expect("encode generation")
        .uint64(0x1122_3344_5566_7788)
        .expect("encode owner SVN")
        .uint64(0x8877_6655_4433_2211)
        .expect("encode manufacturer SVN")
        .buffer(&pid)
        .expect("encode PID")
        .buffer(&pid_pub_key)
        .expect("encode PID public key")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborPartInfoResp::decode_response(bytes)
        .expect("trailing entry must not disturb PartInfo response");

    assert_eq!(resp.device_kind, 0x02);
    assert_eq!(resp.part_state, 0x03);
    assert_eq!(resp.generation, U32::from(0x1122_3344));
    assert_eq!(resp.owner_svn, U64::from(0x1122_3344_5566_7788));
    assert_eq!(resp.mfgr_svn, U64::from(0x8877_6655_4433_2211));
    assert_eq!(resp.pid, pid);
    assert_eq!(resp.pid_pub_key, pid_pub_key);
}

/// Verifies forward compatibility for a session-id scalar followed by
/// multiple fixed-size array fields.
#[test]
fn session_open_init_extra_trailing_toc_entry_is_ignored() {
    let session_id = 0x1234;
    let enc = [0x11u8; 97];
    let sig = [0x22u8; 96];

    let mut buf = [0u8; 512];

    // session_id, enc's alignment padding, enc, sig, trailing field.
    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .with_toc_slots(5)
        .expect("reserve TOC")
        .session_id(session_id)
        .expect("encode session id")
        .align_to(4)
        .expect("align response encapsulation")
        .buffer(&enc)
        .expect("encode response encapsulation")
        .buffer(&sig)
        .expect("encode response signature")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = TborSessionOpenInitResp::decode_response(bytes)
        .expect("trailing entry must not disturb session-open response");

    assert_eq!(resp.session_id, session_id);
    assert_eq!(resp.enc, enc);
    assert_eq!(resp.sig, sig);
}

/// Verifies forward compatibility for the typed `KeyId` TOC entry.
#[test]
fn key_id_extra_trailing_toc_entry_is_ignored() {
    let key_id = 0x1234;

    let mut buf = [0u8; 128];

    let bytes = ResponseEncoder::new(&mut buf, PROTOCOL_VERSION, 0, false)
        .key_id(key_id)
        .expect("encode key id")
        .uint8(0x56)
        .expect("encode known value")
        .uint8(0xFF)
        .expect("encode trailing future field")
        .finish()
        .expect("finish response");

    let resp = KeyIdForwardCompatResp::decode_response(bytes)
        .expect("trailing entry must not disturb key-id response");

    assert_eq!(resp.key_id, key_id);
    assert_eq!(resp.value, 0x56);
}
