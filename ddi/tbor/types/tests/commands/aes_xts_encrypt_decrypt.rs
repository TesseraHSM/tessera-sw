// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `AesXtsEncryptDecrypt` command.
//!
//! The command processes `data_len / dul` consecutive XTS data units out
//! of band: the device reads the in SGL Data Block and writes the out
//! block, with the 8-byte little-endian tweak naming the first data unit
//! and incrementing per unit.
//!
//! XTS keys cannot be imported, so correctness is checked through
//! properties of generated keys rather than known answers:
//! * Encrypt / decrypt round trips across data-unit lengths and up to
//!   [`XTS_DATA_MAX_LEN`] bytes (multiple data units per submission).
//! * A multi-unit submission equals per-unit submissions with
//!   incrementing tweaks.
//! * The tweak and the key both change the ciphertext.
//! * Bad data-unit / data lengths, tweak overflow, oversize data, missing
//!   OOB, a non-XTS key, a tampered key and an invalid session are
//!   rejected.

// The sock backend gains out-of-band output support in a later change.
#![cfg(not(feature = "sock"))]

use tsra_crypto::Rng;
use tsra_ddi_interface::TborOobItem;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborAesXtsEncryptDecryptReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::AES_OP_DECRYPT;
use tsra_ddi_tbor_types::AES_OP_ENCRYPT;
use tsra_ddi_tbor_types::KEY_CLASS_AES_XTS512;
use tsra_ddi_tbor_types::KEY_CLASS_HMAC_SHA512;
use tsra_ddi_tbor_types::XTS_DATA_MAX_LEN;

use crate::commands::aes_generate_key::SCOPE_LOCAL;
use crate::commands::aes_generate_key::SCOPE_SESSION;
use crate::commands::aes_xts_generate_key::generate_xts_key;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;

/// Builds a request over `data_len` bytes in `dul`-byte data units.
fn req(
    session_id: u16,
    op: u8,
    key: &[u8],
    tweak: u64,
    data_len: usize,
    dul: usize,
) -> TborAesXtsEncryptDecryptReq {
    TborAesXtsEncryptDecryptReq {
        session_id,
        op,
        data_len: data_len as u16,
        dul: dul as u16,
        in_index: 0,
        out_index: 1,
        tweak: tweak.to_le_bytes().to_vec(),
        masked_key: key.to_vec(),
    }
}

/// Runs one XTS submission over `data` and returns the out block.
fn crypt(
    ctx: &TestCtx,
    sid: u16,
    op: u8,
    key: &[u8],
    tweak: u64,
    dul: usize,
    data: &[u8],
) -> Vec<u8> {
    let r = req(sid, op, key, tweak, data.len(), dul);
    let mut out = vec![0u8; data.len()];
    ctx.tbor_oob_io(&r, &mut [TborOobItem::In(data), TborOobItem::Out(&mut out)])
        .expect("AesXtsEncryptDecrypt");
    out
}

/// Asserts that `r` over a zeroed `data_len`-byte block is rejected.
#[track_caller]
fn expect_reject(
    ctx: &TestCtx,
    r: &TborAesXtsEncryptDecryptReq,
    data_len: usize,
    status: TborStatus,
) {
    let input = vec![0u8; data_len];
    let mut out = vec![0u8; data_len];
    ctx.expect_fw_reject_oob_io(
        r,
        &mut [TborOobItem::In(&input), TborOobItem::Out(&mut out)],
        status,
    );
}

/// Random bytes of `len`.
fn random(len: usize) -> Vec<u8> {
    Rng::rand_vec(len).expect("rng")
}

/// Random tweak that leaves room to advance across many data units.
fn random_tweak() -> u64 {
    let mut b = [0u8; 4];
    Rng::rand_bytes(&mut b).expect("rng");
    u32::from_le_bytes(b) as u64
}

/// Round trips across data-unit lengths, single and multiple units per
/// submission up to [`XTS_DATA_MAX_LEN`], with Session and Local keys.
#[test]
fn aes_xts_roundtrip_data_unit_lengths() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;

    for scope in [SCOPE_SESSION, SCOPE_LOCAL] {
        let key = generate_xts_key(&ctx, sid, scope);
        for (dul, units) in [
            (16, 1),
            (32, 3),
            (512, 1),
            (512, 8),
            (512, 32),
            (4096, 1),
            (4096, 4),
            (XTS_DATA_MAX_LEN, 1),
        ] {
            let pt = random(dul * units);
            let tweak = random_tweak();
            let ct = crypt(&ctx, sid, AES_OP_ENCRYPT, &key, tweak, dul, &pt);
            assert_ne!(ct, pt, "dul {dul} units {units}");
            let back = crypt(&ctx, sid, AES_OP_DECRYPT, &key, tweak, dul, &ct);
            assert_eq!(back, pt, "dul {dul} units {units}");
        }
    }
}

/// A multi-unit submission equals per-unit submissions with the tweak
/// incremented per data unit, in both directions.
#[test]
fn aes_xts_multi_unit_matches_per_unit() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_xts_key(&ctx, sid, SCOPE_LOCAL);

    for dul in [512, 4096] {
        let pt = random(XTS_DATA_MAX_LEN);
        let tweak = 0x0123_4567_89ab_cdef_u64;
        let whole = crypt(&ctx, sid, AES_OP_ENCRYPT, &key, tweak, dul, &pt);
        for (i, (unit_pt, unit_ct)) in pt.chunks(dul).zip(whole.chunks(dul)).enumerate() {
            let t = tweak + i as u64;
            assert_eq!(
                crypt(&ctx, sid, AES_OP_ENCRYPT, &key, t, dul, unit_pt),
                unit_ct,
                "dul {dul} unit {i}"
            );
            assert_eq!(
                crypt(&ctx, sid, AES_OP_DECRYPT, &key, t, dul, unit_ct),
                unit_pt,
                "dul {dul} unit {i}"
            );
        }
    }
}

/// Different tweaks, and different keys, produce different ciphertexts;
/// decrypting under the wrong tweak does not recover the plaintext.
#[test]
fn aes_xts_tweak_and_key_change_ciphertext() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_xts_key(&ctx, sid, SCOPE_LOCAL);
    let other = generate_xts_key(&ctx, sid, SCOPE_LOCAL);
    let pt = random(512);

    let ct = crypt(&ctx, sid, AES_OP_ENCRYPT, &key, 7, 512, &pt);
    assert_ne!(crypt(&ctx, sid, AES_OP_ENCRYPT, &key, 8, 512, &pt), ct);
    assert_ne!(crypt(&ctx, sid, AES_OP_ENCRYPT, &other, 7, 512, &pt), ct);
    assert_ne!(crypt(&ctx, sid, AES_OP_DECRYPT, &key, 8, 512, &ct), pt);
    assert_eq!(crypt(&ctx, sid, AES_OP_DECRYPT, &key, 7, 512, &ct), pt);

    // Deterministic for the same key and tweak.
    assert_eq!(crypt(&ctx, sid, AES_OP_ENCRYPT, &key, 7, 512, &pt), ct);
}

/// The tweak after the last data unit must fit in 64 bits: a run ending
/// just below `u64::MAX` works, one reaching it is rejected.
#[test]
fn aes_xts_tweak_overflow() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_xts_key(&ctx, sid, SCOPE_LOCAL);

    let pt = random(32);
    let ct = crypt(&ctx, sid, AES_OP_ENCRYPT, &key, u64::MAX - 2, 16, &pt);
    assert_eq!(
        crypt(&ctx, sid, AES_OP_DECRYPT, &key, u64::MAX - 2, 16, &ct),
        pt
    );

    for (tweak, len) in [(u64::MAX, 16), (u64::MAX - 1, 32), (u64::MAX - 2, 48)] {
        let r = req(sid, AES_OP_ENCRYPT, &key, tweak, len, 16);
        expect_reject(&ctx, &r, len, TborStatus::AesXtsInvalidBufferSize);
    }
}

/// Invalid data-unit / data lengths are rejected.
#[test]
fn aes_xts_rejects_invalid_unit_lengths() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_xts_key(&ctx, sid, SCOPE_LOCAL);

    for (data_len, dul) in [
        // dul zero / below 16 / not a multiple of 16.
        (32, 0),
        (32, 8),
        (48, 24),
        // data_len not a multiple of dul (including dul > data_len).
        (48, 32),
        (512, 1024),
    ] {
        let r = req(sid, AES_OP_ENCRYPT, &key, 0, data_len, dul);
        expect_reject(&ctx, &r, data_len, TborStatus::AesXtsInvalidBufferSize);
    }
}

/// Oversize data and missing OOB blocks are rejected.
#[test]
fn aes_xts_rejects_oversize_and_missing_oob() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_xts_key(&ctx, sid, SCOPE_LOCAL);

    let n = XTS_DATA_MAX_LEN + 512;
    let r = req(sid, AES_OP_ENCRYPT, &key, 0, n, 512);
    expect_reject(&ctx, &r, n, TborStatus::InvalidArg);

    let r = req(sid, AES_OP_ENCRYPT, &key, 0, 512, 512);
    ctx.expect_fw_reject_oob_io(&r, &mut [], TborStatus::InvalidArg);
}

/// A same-sized masked key that is not AES-XTS is rejected.
#[test]
fn aes_xts_rejects_non_xts_key() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = unwrap(&ctx, sid, KEY_CLASS_HMAC_SHA512, &[0x5a; 64]).masked_key;
    let r = req(sid, AES_OP_ENCRYPT, &key, 0, 512, 512);
    expect_reject(&ctx, &r, 512, TborStatus::InvalidKeyType);
}

/// A masked key whose authentication tag was altered is rejected.
#[test]
fn aes_xts_rejects_tampered_key() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let mut key = generate_xts_key(&ctx, sid, SCOPE_LOCAL);
    *key.last_mut().expect("non-empty masked key") ^= 1;
    let r = req(sid, AES_OP_ENCRYPT, &key, 0, 512, 512);
    expect_reject(&ctx, &r, 512, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

/// A request bound to an unknown session id is rejected.
#[test]
fn aes_xts_rejects_invalid_session() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_xts_key(&ctx, sid, SCOPE_LOCAL);
    let r = req(u16::MAX, AES_OP_ENCRYPT, &key, 0, 512, 512);
    expect_reject(&ctx, &r, 512, TborStatus::FileHandleSessionIdDoesNotMatch);
}

/// A key imported through `UnwrapKey` (`K1 ‖ K2`) encrypts exactly like the
/// host reference AES-XTS with the same key and tweak, and decrypts back.
#[test]
fn aes_xts_unwrapped_key_matches_host() {
    use tsra_crypto::AesXtsAlgo;
    use tsra_crypto::AesXtsKey;
    use tsra_crypto::EncryptOp;
    use tsra_crypto::ImportableKey;

    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;

    let key_bytes = random(64);
    let key = unwrap(&ctx, sid, KEY_CLASS_AES_XTS512, &key_bytes).masked_key;

    let (dul, units) = (512, 4);
    let pt = random(dul * units);
    let tweak = random_tweak();
    let ct = crypt(&ctx, sid, AES_OP_ENCRYPT, &key, tweak, dul, &pt);

    let host_key = AesXtsKey::from_bytes(&key_bytes).expect("host XTS key");
    let mut expected = Vec::with_capacity(pt.len());
    for (i, unit) in pt.chunks(dul).enumerate() {
        let unit_tweak = (tweak + i as u64).to_le_bytes();
        let mut algo = AesXtsAlgo::new(&unit_tweak, dul).expect("host XTS algo");
        let mut out = vec![0u8; dul];
        algo.encrypt(&host_key, unit, Some(&mut out))
            .expect("host XTS encrypt");
        expected.extend_from_slice(&out);
    }
    assert_eq!(ct, expected, "device ciphertext must match host AES-XTS");

    let back = crypt(&ctx, sid, AES_OP_DECRYPT, &key, tweak, dul, &ct);
    assert_eq!(back, pt);
}
