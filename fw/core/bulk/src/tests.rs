// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

fn data_block(addr: u64, len: u32) -> [u8; 16] {
    let mut desc = [0; 16];
    desc[..8].copy_from_slice(&addr.to_le_bytes());
    desc[8..12].copy_from_slice(&len.to_le_bytes());
    desc
}

fn validate_sgl_length(root: [u8; 16], len: u32, entries: &[(u64, [u8; 16])]) -> HsmResult<()> {
    let mut cursor = SglRangeCursor::new_exact(root, len)?;
    let mut fetched = None;
    loop {
        match cursor.step(fetched.take())? {
            SglRangeStep::Descriptor(addr) => {
                fetched = Some(
                    entries
                        .iter()
                        .find(|(entry_addr, _)| *entry_addr == addr)
                        .ok_or(HsmError::InvalidArg)?
                        .1,
                );
            }
            SglRangeStep::Data(_) => {}
            SglRangeStep::Done => return Ok(()),
        }
    }
}

#[test]
fn sgl_exact_length_accepts_matching_payloads() {
    assert_eq!(validate_sgl_length(data_block(0, 0), 0, &[]), Ok(()));
    assert_eq!(
        validate_sgl_length(data_block(0x1000, MAX_DATA_LEN), MAX_DATA_LEN, &[]),
        Ok(())
    );
    let mut root = data_block(0x2000, 2 * SGL_DESC_LEN);
    root[15] = SGL_LAST_SEGMENT << 4;
    let entries = [
        (0x2000, data_block(0x3000, 32)),
        (0x2010, data_block(0x4000, 29)),
    ];
    assert_eq!(validate_sgl_length(root, 61, &entries), Ok(()));
}

#[test]
fn sgl_exact_length_rejects_mismatches() {
    let expected = 2 * BLOCK_LEN;
    let mut root = data_block(0x2000, SGL_DESC_LEN);
    root[15] = SGL_LAST_SEGMENT << 4;
    for len in [expected - 1, expected + 1] {
        assert_eq!(
            validate_sgl_length(data_block(0x3000, len), expected, &[]),
            Err(HsmError::InvalidArg)
        );
        assert_eq!(
            validate_sgl_length(root, expected, &[(0x2000, data_block(0x3000, len))]),
            Err(HsmError::InvalidArg)
        );
    }
    assert_eq!(
        validate_sgl_length(root, expected, &[(0x2000, data_block(0x3000, expected))]),
        Ok(())
    );
}

#[test]
fn sgl_exact_length_rejects_trailing_payload() {
    let mut root = data_block(0x2000, 2 * SGL_DESC_LEN);
    root[15] = SGL_LAST_SEGMENT << 4;
    let entries = [
        (0x2000, data_block(0x3000, BLOCK_LEN)),
        (0x2010, data_block(0x4000, 1)),
    ];
    assert_eq!(
        validate_sgl_length(root, BLOCK_LEN, &entries),
        Err(HsmError::InvalidArg)
    );
}

#[test]
fn sgl_exact_length_validates_chained_payloads() {
    let mut root = data_block(0x2000, 2 * SGL_DESC_LEN);
    root[15] = SGL_SEGMENT << 4;
    let mut last = data_block(0x5000, SGL_DESC_LEN);
    last[15] = SGL_LAST_SEGMENT << 4;
    let entries = [
        (0x2000, data_block(0x3000, BLOCK_LEN)),
        (0x2010, last),
        (0x5000, data_block(0x6000, BLOCK_LEN)),
    ];
    assert_eq!(validate_sgl_length(root, 2 * BLOCK_LEN, &entries), Ok(()));
    assert_eq!(
        validate_sgl_length(root, 2 * BLOCK_LEN - 1, &entries),
        Err(HsmError::InvalidArg)
    );
    assert_eq!(
        validate_sgl_length(root, 2 * BLOCK_LEN + 1, &entries),
        Err(HsmError::InvalidArg)
    );
}

#[test]
fn sgl_exact_length_rejects_malformed_and_cyclic_lists() {
    let mut root = data_block(0x2000, SGL_DESC_LEN);
    root[15] = SGL_LAST_SEGMENT << 4;
    let mut invalid = data_block(0x3000, BLOCK_LEN);
    invalid[15] = 1;
    for desc in [
        invalid,
        data_block(0, BLOCK_LEN),
        data_block(u64::MAX - 7, BLOCK_LEN),
        data_block(0, 0),
        root,
    ] {
        assert_eq!(
            validate_sgl_length(root, BLOCK_LEN, &[(0x2000, desc)]),
            Err(HsmError::InvalidArg)
        );
    }
    root[15] = SGL_SEGMENT << 4;
    root[8..12].copy_from_slice(&(2 * SGL_DESC_LEN).to_le_bytes());
    let entries = [(0x2000, data_block(0x3000, 1)), (0x2010, root)];
    assert_eq!(
        validate_sgl_length(root, MAX_DATA_LEN, &entries),
        Err(HsmError::InvalidArg)
    );
}

#[test]
fn sgl_prefix_and_tail() {
    let desc = data_block(0x1000, 61);
    assert_eq!(sgl_prefix(&desc, 61, 48), Ok(data_block(0x1000, 48)));
    assert_eq!(
        sgl_data_block_range(&desc, 48, 13),
        Ok(data_block(0x1030, 13))
    );
    assert_eq!(
        sgl_prefix(
            &data_block(0x1000, MAX_DATA_LEN),
            MAX_DATA_LEN,
            MAX_DATA_LEN
        ),
        Ok(data_block(0x1000, MAX_DATA_LEN))
    );
    assert_eq!(sgl_prefix(&data_block(0, 0), 0, 0), Ok(data_block(0, 0)));
}

#[test]
fn sgl_rejects_bad_ranges() {
    let desc = data_block(0x1000, 61);
    for (len, prefix) in [(60, 48), (61, 64), (61, 47), (MAX_DATA_LEN + 1, 0)] {
        assert_eq!(sgl_prefix(&desc, len, prefix), Err(HsmError::InvalidArg));
    }
    for (offset, len) in [(61, 1), (48, 14), (u32::MAX, 1)] {
        assert_eq!(
            sgl_data_block_range(&desc, offset, len),
            Err(HsmError::InvalidArg)
        );
    }
    for invalid in [data_block(0, 16), data_block(u64::MAX - 7, 16)] {
        assert_eq!(sgl_prefix(&invalid, 16, 16), Err(HsmError::InvalidArg));
    }
}

#[test]
fn sgl_segment_prefix_preserves_list() {
    for kind in [SGL_SEGMENT, SGL_LAST_SEGMENT] {
        let mut desc = data_block(0x2000, 2 * SGL_DESC_LEN);
        desc[15] = kind << 4;
        assert_eq!(sgl_prefix(&desc, MAX_DATA_LEN, 48), Ok(desc));
        assert_eq!(sgl_data_block_range(&desc, 0, 1), Err(HsmError::InvalidArg));
        for len in [0, 1, SGL_MAX_SEGMENT_LEN + SGL_DESC_LEN] {
            desc[8..12].copy_from_slice(&len.to_le_bytes());
            assert_eq!(sgl_prefix(&desc, 61, 48), Err(HsmError::InvalidArg));
        }
    }
}

#[test]
fn sgl_tail_crosses_data_blocks() {
    let mut root = data_block(0x2000, 2 * SGL_DESC_LEN);
    root[15] = SGL_LAST_SEGMENT << 4;
    let mut cursor = SglRangeCursor::new(root, 48, 13).expect("range");
    assert_eq!(cursor.step(None), Ok(SglRangeStep::Descriptor(0x2000)));
    assert_eq!(
        cursor.step(Some(data_block(0x3000, 52))),
        Ok(SglRangeStep::Data(data_block(0x3030, 4)))
    );
    assert_eq!(cursor.step(None), Ok(SglRangeStep::Descriptor(0x2010)));
    assert_eq!(
        cursor.step(Some(data_block(0x4000, 9))),
        Ok(SglRangeStep::Data(data_block(0x4000, 9)))
    );
    assert_eq!(cursor.step(None), Ok(SglRangeStep::Done));
}

#[test]
fn sgl_tail_follows_segment_chain() {
    let mut root = data_block(0x2000, 2 * SGL_DESC_LEN);
    root[15] = SGL_SEGMENT << 4;
    let mut last = data_block(0x5000, SGL_DESC_LEN);
    last[15] = SGL_LAST_SEGMENT << 4;
    let mut cursor = SglRangeCursor::new(root, 32, 13).expect("range");
    assert_eq!(cursor.step(None), Ok(SglRangeStep::Descriptor(0x2000)));
    assert_eq!(
        cursor.step(Some(data_block(0x3000, 32))),
        Ok(SglRangeStep::Descriptor(0x2010))
    );
    assert_eq!(
        cursor.step(Some(last)),
        Ok(SglRangeStep::Descriptor(0x5000))
    );
    assert_eq!(
        cursor.step(Some(data_block(0x6000, 13))),
        Ok(SglRangeStep::Data(data_block(0x6000, 13)))
    );
    assert_eq!(cursor.step(None), Ok(SglRangeStep::Done));
}

#[test]
fn sgl_tail_rejects_bad_lists() {
    let mut root = data_block(0x2000, SGL_DESC_LEN);
    root[15] = SGL_LAST_SEGMENT << 4;
    let mut cursor = SglRangeCursor::new(root, 0, 13).expect("range");
    assert_eq!(cursor.step(None), Ok(SglRangeStep::Descriptor(0x2000)));
    assert_eq!(
        cursor.step(Some(data_block(0x3000, 12))),
        Ok(SglRangeStep::Data(data_block(0x3000, 12)))
    );
    assert_eq!(cursor.step(None), Err(HsmError::InvalidArg));
    let mut cursor = SglRangeCursor::new(root, 0, 1).expect("range");
    assert_eq!(cursor.step(None), Ok(SglRangeStep::Descriptor(0x2000)));
    assert_eq!(cursor.step(Some(root)), Err(HsmError::InvalidArg));
}

#[test]
fn sgl_tail_bounds_cyclic_chains() {
    let mut root = data_block(0x2000, 2 * SGL_DESC_LEN);
    root[15] = SGL_SEGMENT << 4;
    let mut cursor = SglRangeCursor::new(root, MAX_DATA_LEN - 1, 1).expect("range");
    let mut fetched = None;
    let mut rejected = false;
    for _ in 0..=SGL_MAX_SEGMENT_LEN / SGL_DESC_LEN {
        match cursor.step(fetched) {
            Ok(SglRangeStep::Descriptor(addr)) => {
                fetched = Some(if addr == 0x2000 {
                    data_block(0x3000, 1)
                } else {
                    root
                });
            }
            Err(HsmError::InvalidArg) => {
                rejected = true;
                break;
            }
            _ => panic!("cyclic chain must not complete"),
        }
    }
    assert!(rejected, "descriptor traversal must have a fixed bound");
}

fn gcm_sqe() -> BulkSqe {
    BulkSqe {
        dir: BulkDir::Decrypt,
        cid: 0x1234,
        session_id: 0x0102,
        short_app_id: 7,
        src_len: 64 + 256,
        src_addr: 0x1000_0000,
        dst_len: 64 + 256,
        dst_addr: 0x2000_0000,
        params: BulkParams::Gcm(GcmParams {
            key_id: 0x0105,
            aad_len: 40,
            aligned_aad_len: 64,
            tag: [0xAA; GCM_TAG_LEN],
            iv: [0xBB; GCM_IV_LEN],
            tail: Some(GcmTail {
                len: 5,
                src: 0x3000,
                dst: 0x3000,
            }),
        }),
    }
}

fn xts_sqe() -> BulkSqe {
    BulkSqe {
        dir: BulkDir::Encrypt,
        cid: 9,
        session_id: 3,
        short_app_id: 1,
        src_len: 4096,
        src_addr: 0x1000,
        dst_len: 4096,
        dst_addr: 0x2000,
        params: BulkParams::Xts(XtsParams {
            dul: XtsDul::B512,
            key_id1: 0x0201,
            key_id2: 0,
            tweak: [0xCC; XTS_TWEAK_LEN],
        }),
    }
}

fn bytes(e: &RawBulkSqe) -> [u8; BULK_SQE_DWORDS * 4] {
    core::array::from_fn(|i| rd_u8(e, i))
}

fn set_byte(e: &mut RawBulkSqe, off: usize, f: impl FnOnce(u8) -> u8) {
    let b = f(rd_u8(e, off));
    wr(e, off, &[b]);
}

fn gcm_of(sqe: &mut BulkSqe) -> &mut GcmParams {
    match &mut sqe.params {
        BulkParams::Gcm(gcm) => gcm,
        BulkParams::Xts(_) => unreachable!(),
    }
}

#[test]
fn sqe_round_trips() {
    for sqe in [gcm_sqe(), xts_sqe()] {
        assert_eq!(BulkSqe::parse(&sqe.encode()), Ok(sqe));
    }
}

#[test]
fn sqe_encode_matches_driver_layout() {
    let e = bytes(&gcm_sqe().encode());
    // attr: decrypt | SGL | cmd type 5; cid
    assert_eq!(&e[4..8], &[0x2D, 0x00, 0x34, 0x12]);
    assert_eq!(e[64], FRAME_TYPE_AES);
    // single data-block descriptor covering the full source buffer
    assert_eq!(&e[36..40], &320u32.to_le_bytes());
    assert_eq!(e[43], 0);
    assert_eq!(&e[108..110], &[5, 5]);

    let e = bytes(&xts_sqe().encode());
    assert_eq!(u16::from_le_bytes([e[4], e[5]]), 0x412C);
}

#[test]
fn gcm_text_len_includes_tail() {
    let mut sqe = gcm_sqe();
    assert_eq!(gcm_of(&mut sqe).text_len(320), 256 + 5);
}

#[test]
fn sqe_rejects_bad_command() {
    let mut e = gcm_sqe().encode();
    set_byte(&mut e, 4, |b| b & !(1 << 2)); // PRP
    assert_eq!(BulkSqe::parse(&e), Err(HsmError::UnsupportedCmd));

    let mut e = gcm_sqe().encode();
    set_byte(&mut e, 4, |b| b & !(0x7 << 3)); // command type 0
    assert_eq!(BulkSqe::parse(&e), Err(HsmError::UnsupportedCmd));

    let mut e = gcm_sqe().encode();
    set_byte(&mut e, 64, |_| 0);
    assert_eq!(BulkSqe::parse(&e), Err(HsmError::UnsupportedCmd));

    let e = gcm_sqe().encode();
    assert_eq!(
        BulkSqe::parse(&e[..BULK_SQE_DWORDS - 1]),
        Err(HsmError::UnsupportedCmd)
    );
}

#[test]
fn sqe_rejects_bad_lengths() {
    let cases: [fn(&mut BulkSqe); 4] = [
        |s| s.dst_len += 16,
        |s| s.src_len += 8,
        |s| {
            s.src_len = MAX_DATA_LEN + BLOCK_LEN;
            s.dst_len = s.src_len;
        },
        |s| {
            s.params = xts_sqe().params;
            s.src_len = MAX_DATA_LEN + BLOCK_LEN;
            s.dst_len = s.src_len;
        },
    ];
    for (i, case) in cases.iter().enumerate() {
        let mut sqe = gcm_sqe();
        case(&mut sqe);
        assert!(BulkSqe::parse(&sqe.encode()).is_err(), "case {i}");
    }
}

#[test]
fn gcm_rejects_bad_aad_and_tail() {
    let cases: [fn(&mut GcmParams); 6] = [
        |g| g.aligned_aad_len = 48,
        |g| g.aad_len = 65,
        |g| g.aligned_aad_len = 352,
        |g| g.tail = g.tail.map(|t| GcmTail { len: 16, ..t }),
        |g| g.tail = g.tail.map(|t| GcmTail { src: 0, ..t }),
        |g| g.tail = g.tail.map(|t| GcmTail { dst: 0, ..t }),
    ];
    for (i, case) in cases.iter().enumerate() {
        let mut sqe = gcm_sqe();
        case(gcm_of(&mut sqe));
        assert_eq!(
            BulkSqe::parse(&sqe.encode()),
            Err(HsmError::AesGcmInvalidBufferSize),
            "case {i}"
        );
    }

    let mut e = gcm_sqe().encode();
    set_byte(&mut e, 109, |_| 4); // tail dst len differs from src len
    assert_eq!(BulkSqe::parse(&e), Err(HsmError::AesGcmInvalidBufferSize));
}

#[test]
fn gcm_accepts_empty_and_aad_only() {
    let mut sqe = gcm_sqe();
    sqe.src_len = 0;
    sqe.dst_len = 0;
    let gcm = gcm_of(&mut sqe);
    gcm.aad_len = 0;
    gcm.aligned_aad_len = 0;
    gcm.tail = None;
    assert_eq!(BulkSqe::parse(&sqe.encode()), Ok(sqe));

    let mut sqe = gcm_sqe();
    sqe.src_len = 64;
    sqe.dst_len = 64;
    gcm_of(&mut sqe).tail = None;
    assert_eq!(BulkSqe::parse(&sqe.encode()), Ok(sqe));
}

#[test]
fn xts_rejects_bad_lengths() {
    let mut sqe = xts_sqe();
    sqe.src_len = 0;
    sqe.dst_len = 0;
    assert_eq!(
        BulkSqe::parse(&sqe.encode()),
        Err(HsmError::AesXtsInvalidBufferSize)
    );

    let mut sqe = xts_sqe();
    sqe.src_len = 4096 + 16;
    sqe.dst_len = sqe.src_len;
    assert_eq!(
        BulkSqe::parse(&sqe.encode()),
        Err(HsmError::AesXtsInvalidDul)
    );
}

#[test]
fn cqe_round_trips() {
    let mut cqe = BulkCqe::success(&gcm_sqe(), 0x22);
    cqe.tag = [1; GCM_TAG_LEN];
    cqe.iv = [2; GCM_IV_LEN];
    cqe.fips_approved = true;
    assert_eq!(cqe.tail_len, 5);
    assert_eq!(cqe.data_len, 320);
    assert_eq!(BulkCqe::decode(&cqe.encode()), cqe);

    let mut raw = [0xFFFF_FFFFu32; BULK_CQE_DWORDS];
    assert_eq!(cqe.write(&mut raw), Ok(()));
    assert_eq!(BulkCqe::decode(&raw), cqe);

    let mut short = [0u32; BULK_CQE_DWORDS - 1];
    assert_eq!(cqe.write(&mut short), Err(HsmError::InternalError));
}

#[test]
fn error_cqe_echoes_sqe_dw1() {
    let cqe = BulkCqe::error(&xts_sqe().encode(), 4, HsmError::KeyNotFound);
    assert_eq!(cqe.attr, xts_sqe().attr());
    assert_eq!(cqe.cid, 9);
    assert_eq!(cqe.sq_id, 4);
    assert_eq!(
        cqe.status,
        BulkStatus {
            sts: sts::INVALID_FIELD_XTS,
            err: xts_err::INVALID_KEY1,
        }
    );

    let cqe = BulkCqe::error(
        &gcm_sqe().encode(),
        4,
        HsmError::AesGcmDecryptTagDoesNotMatch,
    );
    assert_eq!(
        cqe.status,
        BulkStatus {
            sts: sts::CRYPTO_ENGINE_ERROR,
            err: engine_err::TAG_MISMATCH,
        }
    );

    let cqe = BulkCqe::error(&[], 4, HsmError::UnsupportedCmd);
    assert_eq!((cqe.attr, cqe.cid), (0, 0));
}

#[test]
fn error_status_is_never_success() {
    for err in [
        HsmError::InvalidArg,
        HsmError::UnsupportedCmd,
        HsmError::InternalError,
        HsmError::KeyNotFound,
        HsmError::DmaCompletedWithError,
        HsmError(0),
    ] {
        for cipher in [BulkCipher::Gcm, BulkCipher::Xts] {
            assert!(!BulkStatus::from_error(cipher, err).is_success());
        }
    }
}

#[test]
fn xts_length_errors_name_the_length_problem() {
    let cases = [
        (MAX_DATA_LEN + BLOCK_LEN, xts_err::DATA_LENGTH_EXCEEDED),
        (4100, xts_err::LENGTH_UNALIGNED_16B),
        (0, xts_err::UNDEFINED),
    ];
    for (len, want) in cases {
        let mut sqe = xts_sqe();
        sqe.src_len = len;
        sqe.dst_len = len;
        let raw = sqe.encode();
        let err = HsmError::AesXtsInvalidBufferSize;
        assert_eq!(BulkSqe::parse(&raw), Err(err), "len {len}");
        assert_eq!(
            BulkCqe::error(&raw, 0, err).status,
            BulkStatus {
                sts: sts::INVALID_FIELD_XTS,
                err: want,
            },
            "len {len}"
        );
    }

    // GCM length errors keep the generic code: `gcm_err` has no length one.
    let mut sqe = gcm_sqe();
    sqe.src_len = MAX_DATA_LEN + BLOCK_LEN;
    sqe.dst_len = sqe.src_len;
    let raw = sqe.encode();
    let err = HsmError::AesGcmInvalidBufferSize;
    assert_eq!(BulkSqe::parse(&raw), Err(err));
    assert_eq!(
        BulkCqe::error(&raw, 0, err).status,
        BulkStatus {
            sts: sts::INVALID_FIELD_GCM,
            err: gcm_err::UNDEFINED,
        }
    );
}

#[test]
fn xts_same_keys_maps_to_same_keys_passed() {
    assert_eq!(
        BulkStatus::from_error(BulkCipher::Xts, HsmError::KeyStructuralValidationFailed),
        BulkStatus {
            sts: sts::INVALID_FIELD_XTS,
            err: xts_err::SAME_KEYS_PASSED,
        }
    );
}

#[test]
fn set_sq_id_patches_only_sq_id() {
    let cqe = BulkCqe::success(&gcm_sqe(), 1);
    let mut raw = cqe.encode();
    BulkCqe::set_sq_id(&mut raw, 0x1234);
    assert_eq!(
        BulkCqe::decode(&raw),
        BulkCqe {
            sq_id: 0x1234,
            ..cqe
        }
    );
}
