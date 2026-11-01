// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `AesGcmEncryptDecrypt` command.
//!
//! The command carries its data out of band: the in SGL Data Block holds
//! `[padded AAD | text]` and the device writes the same layout to the out
//! block (the text region is the result). The padded AAD region is 0 for
//! no AAD, otherwise a multiple of 32 bytes with the AAD at offset 16 when
//! `aad_len % 32` is in `1..=16` and at offset 0 otherwise.
//!
//! Coverage:
//! * McGrew–Viega AES-256 known answers (empty message without OOB,
//!   plaintext only, and plaintext + AAD).
//! * Encrypt / decrypt round trips across AAD and text lengths, including
//!   the maximum data length.
//! * Device-generated IV on encrypt; rejected on decrypt.
//! * Tampered tag / AAD / ciphertext / masked key fail authentication.
//! * Non-AES-256 key, oversize data, inconsistent lengths, missing OOB
//!   and an invalid session are rejected.

use tsra_crypto::Rng;
use tsra_ddi_interface::TborOobItem;
use tsra_ddi_tbor_test_harness::assertions::assert_session_rejects;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborAesGcmEncryptDecryptReq;
use tsra_ddi_tbor_types::TborAesGcmEncryptDecryptResp;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::AES_KEY_SIZE_256;
use tsra_ddi_tbor_types::AES_OP_DECRYPT;
use tsra_ddi_tbor_types::AES_OP_ENCRYPT;
use tsra_ddi_tbor_types::GCM_DATA_MAX_LEN;
use tsra_ddi_tbor_types::GCM_IV_LEN;
use tsra_ddi_tbor_types::GCM_IV_SOURCE_DEVICE;
use tsra_ddi_tbor_types::GCM_IV_SOURCE_HOST;
use tsra_ddi_tbor_types::GCM_TAG_LEN;
use tsra_ddi_tbor_types::KEY_CLASS_AES;
use tsra_ddi_tbor_types::KEY_CLASS_HMAC_SHA256;

use crate::commands::aes_generate_key::generate_key;
use crate::commands::aes_generate_key::SCOPE_LOCAL;
use crate::commands::aes_generate_key::SCOPE_SESSION;
use crate::commands::sd_sealing_key_gen::finalized_co_session;
use crate::commands::unwrap_key::unwrap;

/// Padded AAD region length of the `[padded AAD | text]` OOB layout.
fn padded_aad_len(aad_len: usize) -> usize {
    aad_len.next_multiple_of(32)
}

/// Builds the in SGL Data Block `[padded AAD | text]`.
fn in_block(aad: &[u8], text: &[u8]) -> Vec<u8> {
    let padded = padded_aad_len(aad.len());
    let off = if (1..=16).contains(&(aad.len() % 32)) {
        16
    } else {
        0
    };
    let mut buf = vec![0u8; padded + text.len()];
    buf[off..off + aad.len()].copy_from_slice(aad);
    buf[padded..].copy_from_slice(text);
    buf
}

/// Builds a host-IV request for `aad` + `text_len` bytes of text.
fn req(
    session_id: u16,
    op: u8,
    masked_key: &[u8],
    iv: &[u8],
    tag: &[u8],
    aad_len: usize,
    text_len: usize,
) -> TborAesGcmEncryptDecryptReq {
    TborAesGcmEncryptDecryptReq {
        session_id,
        op,
        iv_source: GCM_IV_SOURCE_HOST,
        aad_len: aad_len as u16,
        data_len: (padded_aad_len(aad_len) + text_len) as u16,
        in_index: 0,
        out_index: 1,
        iv: iv.to_vec(),
        tag: tag.to_vec(),
        masked_key: masked_key.to_vec(),
    }
}

/// Executes `req` over in / out OOB blocks and returns the response plus
/// the text region of the out block.
fn exec(
    ctx: &TestCtx,
    req: &TborAesGcmEncryptDecryptReq,
    aad: &[u8],
    text: &[u8],
) -> (TborAesGcmEncryptDecryptResp, Vec<u8>) {
    let input = in_block(aad, text);
    let mut out = vec![0u8; input.len()];
    let resp = if input.is_empty() {
        ctx.tbor_oob_io(req, &mut [])
    } else {
        ctx.tbor_oob_io(
            req,
            &mut [TborOobItem::In(&input), TborOobItem::Out(&mut out)],
        )
    }
    .expect("AesGcmEncryptDecrypt");
    (resp, out[padded_aad_len(aad.len())..].to_vec())
}

/// Encrypts `pt` with a host IV, returning `(ciphertext, tag)`.
fn encrypt(
    ctx: &TestCtx,
    sid: u16,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let r = req(
        sid,
        AES_OP_ENCRYPT,
        key,
        iv,
        &[0; GCM_TAG_LEN],
        aad.len(),
        pt.len(),
    );
    let (resp, ct) = exec(ctx, &r, aad, pt);
    assert_eq!(resp.iv, iv, "host IV must be echoed");
    assert_eq!(resp.tag.len(), GCM_TAG_LEN);
    (ct, resp.tag)
}

/// Decrypts `ct` and verifies `tag`, returning the plaintext.
fn decrypt(
    ctx: &TestCtx,
    sid: u16,
    key: &[u8],
    iv: &[u8],
    tag: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Vec<u8> {
    let r = req(sid, AES_OP_DECRYPT, key, iv, tag, aad.len(), ct.len());
    let (resp, pt) = exec(ctx, &r, aad, ct);
    assert_eq!(resp.tag, tag, "verified tag must be echoed");
    pt
}

/// Asserts that decrypting `ct` under `tag` fails authentication.
#[track_caller]
fn expect_tag_mismatch(
    ctx: &TestCtx,
    sid: u16,
    key: &[u8],
    iv: &[u8],
    tag: &[u8],
    aad: &[u8],
    ct: &[u8],
) {
    let r = req(sid, AES_OP_DECRYPT, key, iv, tag, aad.len(), ct.len());
    let input = in_block(aad, ct);
    let mut out = vec![0u8; input.len()];
    let mut items = [TborOobItem::In(&input), TborOobItem::Out(&mut out)];
    let items: &mut [TborOobItem<'_>] = if input.is_empty() {
        &mut []
    } else {
        &mut items
    };
    ctx.expect_fw_reject_oob_io(&r, items, TborStatus::AesGcmDecryptTagDoesNotMatch);
}

/// Decodes a hex string into bytes.
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// Imports a known AES-256 key and returns its masked form.
fn import_aes256(ctx: &TestCtx, sid: u16, key: &[u8]) -> Vec<u8> {
    unwrap(ctx, sid, KEY_CLASS_AES, key).masked_key
}

/// Random bytes of `len`.
fn random(len: usize) -> Vec<u8> {
    Rng::rand_vec(len).expect("rng")
}

/// McGrew–Viega test cases 13 (empty), 14 (one zero block) and 16
/// (60-byte plaintext + 20-byte AAD) with AES-256.
#[test]
fn aes_gcm_known_answers() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;

    let zero_key = import_aes256(&ctx, sid, &[0u8; 32]);
    let zero_iv = [0u8; GCM_IV_LEN];

    // TC13: empty message, no AAD — tag only, no OOB blocks.
    let (ct, tag) = encrypt(&ctx, sid, &zero_key, &zero_iv, &[], &[]);
    assert!(ct.is_empty());
    assert_eq!(tag, hex("530f8afbc74536b9a963b4f1c4cb738b"));
    assert!(decrypt(&ctx, sid, &zero_key, &zero_iv, &tag, &[], &[]).is_empty());

    // TC14: one zero block.
    let (ct, tag) = encrypt(&ctx, sid, &zero_key, &zero_iv, &[], &[0u8; 16]);
    assert_eq!(ct, hex("cea7403d4d606b6e074ec5d3baf39d18"));
    assert_eq!(tag, hex("d0d1c8a799996bf0265b98b5d48ab919"));

    // TC16: 20-byte AAD (at offset 0, padded to 32) + 60-byte plaintext.
    let key = import_aes256(
        &ctx,
        sid,
        &hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
    );
    let iv = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = hex(concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    ));
    let (ct, tag) = encrypt(&ctx, sid, &key, &iv, &aad, &pt);
    assert_eq!(
        ct,
        hex(concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        ))
    );
    assert_eq!(tag, hex("76fc6ece0f4e1768cddf8853bb2d551b"));
    assert_eq!(decrypt(&ctx, sid, &key, &iv, &tag, &aad, &ct), pt);
}

/// Round trips across AAD lengths covering every padding branch and
/// several text lengths, with Session and Local scoped keys.
#[test]
fn aes_gcm_roundtrip_aad_and_text_lengths() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;

    for scope in [SCOPE_SESSION, SCOPE_LOCAL] {
        let key = generate_key(&ctx, sid, scope, AES_KEY_SIZE_256);
        for aad_len in [0, 1, 16, 17, 31, 32, 33, 48, 64] {
            for text_len in [0, 1, 15, 16, 17, 100, 1024] {
                let iv = random(GCM_IV_LEN);
                let aad = random(aad_len);
                let pt = random(text_len);
                let (ct, tag) = encrypt(&ctx, sid, &key, &iv, &aad, &pt);
                if text_len >= 16 {
                    assert_ne!(ct, pt, "aad {aad_len} text {text_len}");
                }
                assert_eq!(
                    decrypt(&ctx, sid, &key, &iv, &tag, &aad, &ct),
                    pt,
                    "aad {aad_len} text {text_len}"
                );
            }
        }
    }
}

/// `data_len` at [`GCM_DATA_MAX_LEN`] round trips (text only and with
/// AAD).
#[test]
fn aes_gcm_roundtrip_max_data_len() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_key(&ctx, sid, SCOPE_LOCAL, AES_KEY_SIZE_256);

    for aad_len in [0, 32] {
        let iv = random(GCM_IV_LEN);
        let aad = random(aad_len);
        let pt = random(GCM_DATA_MAX_LEN - padded_aad_len(aad_len));
        let (ct, tag) = encrypt(&ctx, sid, &key, &iv, &aad, &pt);
        assert_eq!(decrypt(&ctx, sid, &key, &iv, &tag, &aad, &ct), pt);
    }
}

/// A device-generated IV is returned on encrypt and decrypts with a host
/// IV; two encryptions draw distinct IVs.
#[test]
fn aes_gcm_device_iv_roundtrip() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_key(&ctx, sid, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let aad = b"device iv aad";
    let pt = b"device generated iv plaintext";

    let mut ivs = Vec::new();
    for _ in 0..2 {
        let r = TborAesGcmEncryptDecryptReq {
            iv_source: GCM_IV_SOURCE_DEVICE,
            ..req(
                sid,
                AES_OP_ENCRYPT,
                &key,
                &[0; GCM_IV_LEN],
                &[0; GCM_TAG_LEN],
                aad.len(),
                pt.len(),
            )
        };
        let (resp, ct) = exec(&ctx, &r, aad, pt);
        assert_eq!(resp.iv.len(), GCM_IV_LEN);
        assert_ne!(resp.iv, [0u8; GCM_IV_LEN], "device IV must be generated");
        assert_eq!(decrypt(&ctx, sid, &key, &resp.iv, &resp.tag, aad, &ct), pt);
        ivs.push(resp.iv);
    }
    assert_ne!(ivs[0], ivs[1], "device IVs must be fresh");
}

/// A device-generated IV is rejected on decrypt.
#[test]
fn aes_gcm_rejects_device_iv_on_decrypt() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_key(&ctx, sid, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let ct = [0u8; 32];
    let r = TborAesGcmEncryptDecryptReq {
        iv_source: GCM_IV_SOURCE_DEVICE,
        ..req(
            sid,
            AES_OP_DECRYPT,
            &key,
            &[0; GCM_IV_LEN],
            &[0; GCM_TAG_LEN],
            0,
            ct.len(),
        )
    };
    let mut out = [0u8; 32];
    ctx.expect_fw_reject_oob_io(
        &r,
        &mut [TborOobItem::In(&ct), TborOobItem::Out(&mut out)],
        TborStatus::InvalidArg,
    );
}

/// Tampering with the tag, AAD, ciphertext or IV fails authentication.
#[test]
fn aes_gcm_rejects_tampered_inputs() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_key(&ctx, sid, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let iv = random(GCM_IV_LEN);
    let aad = random(20);
    let pt = random(64);
    let (ct, tag) = encrypt(&ctx, sid, &key, &iv, &aad, &pt);

    let mut bad_tag = tag.clone();
    bad_tag[0] ^= 1;
    expect_tag_mismatch(&ctx, sid, &key, &iv, &bad_tag, &aad, &ct);

    let mut bad_aad = aad.clone();
    bad_aad[19] ^= 1;
    expect_tag_mismatch(&ctx, sid, &key, &iv, &tag, &bad_aad, &ct);

    let mut bad_ct = ct.clone();
    bad_ct[63] ^= 1;
    expect_tag_mismatch(&ctx, sid, &key, &iv, &tag, &aad, &bad_ct);

    let mut bad_iv = iv.clone();
    bad_iv[11] ^= 1;
    expect_tag_mismatch(&ctx, sid, &key, &bad_iv, &tag, &aad, &ct);

    // Empty message: only the tag authenticates.
    let (_, empty_tag) = encrypt(&ctx, sid, &key, &iv, &[], &[]);
    let mut bad_empty_tag = empty_tag;
    bad_empty_tag[15] ^= 1;
    expect_tag_mismatch(&ctx, sid, &key, &iv, &bad_empty_tag, &[], &[]);
}

/// A masked key whose authentication tag was altered is rejected.
#[test]
fn aes_gcm_rejects_tampered_key() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let mut key = generate_key(&ctx, sid, SCOPE_LOCAL, AES_KEY_SIZE_256);
    *key.last_mut().expect("non-empty masked key") ^= 1;
    let pt = [0u8; 16];
    let r = req(
        sid,
        AES_OP_ENCRYPT,
        &key,
        &[0; GCM_IV_LEN],
        &[0; GCM_TAG_LEN],
        0,
        pt.len(),
    );
    let mut out = [0u8; 16];
    ctx.expect_fw_reject_oob_io(
        &r,
        &mut [TborOobItem::In(&pt), TborOobItem::Out(&mut out)],
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// A same-sized masked key that is not AES-256 is rejected.
#[test]
fn aes_gcm_rejects_non_aes256_key() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = unwrap(&ctx, sid, KEY_CLASS_HMAC_SHA256, &[0x5a; 32]).masked_key;
    let pt = [0u8; 16];
    let r = req(
        sid,
        AES_OP_ENCRYPT,
        &key,
        &[0; GCM_IV_LEN],
        &[0; GCM_TAG_LEN],
        0,
        pt.len(),
    );
    let mut out = [0u8; 16];
    ctx.expect_fw_reject_oob_io(
        &r,
        &mut [TborOobItem::In(&pt), TborOobItem::Out(&mut out)],
        TborStatus::InvalidKeyType,
    );
}

/// Inconsistent or oversize lengths and missing OOB blocks are rejected.
#[test]
fn aes_gcm_rejects_invalid_lengths_and_missing_oob() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_key(&ctx, sid, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let base = req(
        sid,
        AES_OP_ENCRYPT,
        &key,
        &[0; GCM_IV_LEN],
        &[0; GCM_TAG_LEN],
        0,
        32,
    );

    // Data present but no OOB blocks.
    ctx.expect_fw_reject_oob_io(&base, &mut [], TborStatus::InvalidArg);

    let buf = vec![0u8; GCM_DATA_MAX_LEN + 32];
    let mut out = vec![0u8; buf.len()];
    let cases = [
        // Oversize data.
        TborAesGcmEncryptDecryptReq {
            data_len: (GCM_DATA_MAX_LEN + 16) as u16,
            ..base.clone()
        },
        // Padded AAD exceeds data_len.
        TborAesGcmEncryptDecryptReq {
            aad_len: 17,
            data_len: 16,
            ..base.clone()
        },
        // AAD without any data.
        TborAesGcmEncryptDecryptReq {
            aad_len: 1,
            data_len: 0,
            ..base.clone()
        },
    ];
    for r in &cases {
        let n = r.data_len as usize;
        let mut items = [TborOobItem::In(&buf[..n]), TborOobItem::Out(&mut out[..n])];
        let items: &mut [TborOobItem<'_>] = if n == 0 { &mut [] } else { &mut items };
        ctx.expect_fw_reject_oob_io(r, items, TborStatus::InvalidArg);
    }
}

/// A request bound to an unknown session id is rejected.
#[test]
fn aes_gcm_rejects_invalid_session() {
    let ctx = TestCtx::new();
    let sid = finalized_co_session(&ctx).session_id;
    let key = generate_key(&ctx, sid, SCOPE_LOCAL, AES_KEY_SIZE_256);
    let r = req(
        u16::MAX,
        AES_OP_ENCRYPT,
        &key,
        &[0; GCM_IV_LEN],
        &[0; GCM_TAG_LEN],
        0,
        0,
    );
    let err = ctx
        .tbor_oob_io(&r, &mut [])
        .expect_err("session command must be rejected");
    assert_session_rejects(&err, TborStatus::FileHandleSessionIdDoesNotMatch);
}
