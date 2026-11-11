// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

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
