// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the test-only TBOR `TestAesGcm` command.
//!
//! `TestAesGcm` runs AES-256-GCM under a raw host key through the
//! device's GCM (the PAL `HsmAes::gcm_*_in_place` methods that key masking
//! uses: the BCP on Uno, software AES on std/emu). The firmware must be
//! built with `tbor-test-cmds`; the std/emu build and the Uno bring-up
//! image are.
//!
//! Every result is checked against an independent reference: the NIST
//! CAVP AES-256 GCM vectors, the GCM spec (McGrew & Viega) AES-256 test
//! cases 13-16, and the host OpenSSL implementation in `tsra_crypto` for
//! randomized inputs. Each randomized request uses a fresh key, IV, AAD and
//! text, so nothing can be cached or specialized across calls.
//!
//! Text lengths are split into block-aligned and unaligned sets. The BCP
//! only processes whole blocks, so on Uno the aligned set runs entirely on
//! the engine, while the unaligned set (and every AAD length that is not a
//! multiple of 32) also exercises the PAL's tag correction, and an empty
//! text its software GMAC path. The firmware moves its working buffer by
//! the IV, so the random IVs also cover every buffer alignment.
//!
//! Coverage:
//! * NIST CAVP AES-256 vectors with a 96-bit IV and 128-bit tag
//!   (`gcmEncryptExtIV256.rsp` / `gcmDecrypt256.rsp`): 375 encrypt, and
//!   375 decrypt of which 191 must fail authentication.
//! * GCM spec test cases 13-16, encrypt and decrypt.
//! * Block-aligned and unaligned text lengths (0..=2048) with assorted
//!   AAD lengths (0..=256) covering every `[padded_AAD | text]` layout,
//!   cross-checked against the host reference.
//! * The request `tag` is ignored on encrypt.
//! * Decrypt rejects a tampered tag, ciphertext or AAD, a wrong key and
//!   a wrong IV.
//! * Invalid `op` values and over-maximum AAD / text are rejected.
//!
//! Ungated: runs on emu and on hardware.

use rand::RngExt;
use tsra_crypto::testvectors::aes::AesGcmTestVector;
use tsra_crypto::testvectors::aes::AES_GCM_256_NIST_TEST_VECTORS;
use tsra_crypto::AesGcmAlgo;
use tsra_crypto::AesKey;
use tsra_crypto::EncryptOp;
use tsra_crypto::ImportableKey;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::TborTestAesGcmReq;
use tsra_ddi_tbor_types::TborTestAesGcmResp;
use tsra_ddi_tbor_types::AES_OP_DECRYPT;
use tsra_ddi_tbor_types::AES_OP_ENCRYPT;
use tsra_ddi_tbor_types::TEST_AES_GCM_AAD_MAX_LEN;
use tsra_ddi_tbor_types::TEST_AES_GCM_DATA_MAX_LEN;
use tsra_ddi_tbor_types::TEST_AES_GCM_IV_LEN;
use tsra_ddi_tbor_types::TEST_AES_GCM_KEY_LEN;
use tsra_ddi_tbor_types::TEST_AES_GCM_TAG_LEN;

type Key = [u8; TEST_AES_GCM_KEY_LEN];
type Iv = [u8; TEST_AES_GCM_IV_LEN];
type Tag = [u8; TEST_AES_GCM_TAG_LEN];

/// AAD lengths covering every `[padded_AAD | text]` layout: none,
/// `% 32` in `1..=16` (zero prefix), `% 32` in `17..=31` (zero suffix),
/// whole 32-byte multiples, and the maximum.
const AAD_LENS: [usize; 9] = [0, 1, 16, 17, 31, 32, 33, 255, TEST_AES_GCM_AAD_MAX_LEN];

/// Block-aligned text lengths, up to the maximum.
const ALIGNED_DATA_LENS: [usize; 8] = [0, 16, 32, 48, 256, 1024, 2032, TEST_AES_GCM_DATA_MAX_LEN];

/// Text lengths with a partial final block.
const UNALIGNED_DATA_LENS: [usize; 8] =
    [1, 15, 17, 31, 60, 255, 1000, TEST_AES_GCM_DATA_MAX_LEN - 1];

/// Random-length round trips run on top of the unaligned table.
const RANDOM_ROUNDS: usize = 16;

/// One GCM spec test case (all AES-256 with a 96-bit IV).
struct SpecCase {
    name: &'static str,
    key: &'static str,
    iv: &'static str,
    aad: &'static str,
    pt: &'static str,
    ct: &'static str,
    tag: &'static str,
}

const SPEC_KEY_15: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
const SPEC_IV_15: &str = "cafebabefacedbaddecaf888";

/// GCM spec test cases 13-15: block-aligned text, no AAD.
const SPEC_ALIGNED: [SpecCase; 3] = [
    SpecCase {
        name: "TC13",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        aad: "",
        pt: "",
        ct: "",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
    },
    SpecCase {
        name: "TC14",
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        iv: "000000000000000000000000",
        aad: "",
        pt: "00000000000000000000000000000000",
        ct: "cea7403d4d606b6e074ec5d3baf39d18",
        tag: "d0d1c8a799996bf0265b98b5d48ab919",
    },
    SpecCase {
        name: "TC15",
        key: SPEC_KEY_15,
        iv: SPEC_IV_15,
        aad: "",
        pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        tag: "b094dac5d93471bdec1a502270e3cc6c",
    },
];

/// GCM spec test case 16: 60-byte text and 20-byte AAD.
const SPEC_UNALIGNED: SpecCase = SpecCase {
    name: "TC16",
    key: SPEC_KEY_15,
    iv: SPEC_IV_15,
    aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    pt: "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    ct: "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
    tag: "76fc6ece0f4e1768cddf8853bb2d551b",
};

/// Decodes a hex string.
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

/// Returns `len` random bytes.
fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill(&mut buf[..]);
    buf
}

/// Builds a `TestAesGcm` request.
fn req(op: u8, key: &Key, iv: &Iv, aad: &[u8], data: &[u8], tag: &Tag) -> TborTestAesGcmReq {
    TborTestAesGcmReq {
        op,
        key: *key,
        iv: *iv,
        aad: aad.to_vec(),
        data: data.to_vec(),
        tag: *tag,
    }
}

/// Encrypts on the device.
fn device_seal(ctx: &TestCtx, key: &Key, iv: &Iv, aad: &[u8], pt: &[u8]) -> TborTestAesGcmResp {
    ctx.tbor(&req(
        AES_OP_ENCRYPT,
        key,
        iv,
        aad,
        pt,
        &[0; TEST_AES_GCM_TAG_LEN],
    ))
    .unwrap_or_else(|e| {
        panic!(
            "TestAesGcm encrypt (aad {}, data {}): {e:?}",
            aad.len(),
            pt.len()
        )
    })
}

/// Decrypts on the device, expecting success.
fn device_open(
    ctx: &TestCtx,
    key: &Key,
    iv: &Iv,
    aad: &[u8],
    ct: &[u8],
    tag: &Tag,
) -> TborTestAesGcmResp {
    ctx.tbor(&req(AES_OP_DECRYPT, key, iv, aad, ct, tag))
        .unwrap_or_else(|e| {
            panic!(
                "TestAesGcm decrypt (aad {}, data {}): {e:?}",
                aad.len(),
                ct.len()
            )
        })
}

/// Encrypts on the host with the OpenSSL-backed reference.
fn host_seal(key: &Key, iv: &Iv, aad: &[u8], pt: &[u8]) -> (Vec<u8>, Tag) {
    let key = AesKey::from_bytes(key).expect("host AES key");
    let aad = (!aad.is_empty()).then_some(aad);
    let mut algo = AesGcmAlgo::for_encrypt(iv, aad).expect("host GCM init");
    let mut ct = vec![0u8; pt.len()];
    let n = algo
        .encrypt(&key, pt, Some(&mut ct))
        .expect("host GCM encrypt");
    assert_eq!(n, pt.len(), "host GCM output length");
    let tag = algo.tag().try_into().expect("16-byte host tag");
    (ct, tag)
}

/// Runs a spec case through device encrypt and decrypt.
fn check_spec_case(ctx: &TestCtx, case: &SpecCase) {
    let key: Key = hex(case.key).try_into().expect("32-byte key");
    let iv: Iv = hex(case.iv).try_into().expect("12-byte IV");
    let aad = hex(case.aad);
    let pt = hex(case.pt);
    let ct = hex(case.ct);
    let tag: Tag = hex(case.tag).try_into().expect("16-byte tag");

    let enc = device_seal(ctx, &key, &iv, &aad, &pt);
    assert_eq!(enc.data, ct, "{}: ciphertext", case.name);
    assert_eq!(enc.tag, tag, "{}: tag", case.name);

    let dec = device_open(ctx, &key, &iv, &aad, &ct, &tag);
    assert_eq!(dec.data, pt, "{}: plaintext", case.name);
    assert_eq!(
        dec.tag, tag,
        "{}: decrypt echoes the verified tag",
        case.name
    );
}

/// Encrypts fresh random inputs on the device, checks them against the
/// host reference, and decrypts them back on the device.
fn check_round_trip(ctx: &TestCtx, aad_len: usize, data_len: usize) {
    let mut rng = rand::rng();
    let key: Key = rng.random();
    let iv: Iv = rng.random();
    let aad = random_bytes(aad_len);
    let pt = random_bytes(data_len);

    let (want_ct, want_tag) = host_seal(&key, &iv, &aad, &pt);

    let enc = device_seal(ctx, &key, &iv, &aad, &pt);
    assert_eq!(
        enc.data, want_ct,
        "ciphertext mismatch (aad {aad_len}, data {data_len})"
    );
    assert_eq!(
        enc.tag, want_tag,
        "tag mismatch (aad {aad_len}, data {data_len})"
    );

    let dec = device_open(ctx, &key, &iv, &aad, &enc.data, &enc.tag);
    assert_eq!(
        dec.data, pt,
        "decrypt mismatch (aad {aad_len}, data {data_len})"
    );
}

/// Runs one NIST CAVP vector through the device.
fn check_cavp(ctx: &TestCtx, v: &AesGcmTestVector) {
    let id = v.test_count_id;
    let key: Key = v.key.try_into().expect("32-byte key");
    let iv: Iv = v.iv.try_into().expect("96-bit IV");
    let tag: Tag = v.tag.try_into().expect("128-bit tag");

    if v.encrypt {
        let enc = device_seal(ctx, &key, &iv, v.aad, v.plaintext);
        assert_eq!(enc.data, v.ciphertext, "CAVP {id}: ciphertext");
        assert_eq!(enc.tag, tag, "CAVP {id}: tag");
    } else if v.valid {
        let dec = device_open(ctx, &key, &iv, v.aad, v.ciphertext, &tag);
        assert_eq!(dec.data, v.plaintext, "CAVP {id}: plaintext");
    } else {
        ctx.expect_fw_reject(
            &req(AES_OP_DECRYPT, &key, &iv, v.aad, v.ciphertext, &tag),
            TborStatus::AesGcmDecryptTagDoesNotMatch,
        );
    }
}

/// Seals a fixed-shape aligned message for the negative tests.
fn sealed_sample(ctx: &TestCtx) -> (Key, Iv, Vec<u8>, Vec<u8>, Tag) {
    let mut rng = rand::rng();
    let key: Key = rng.random();
    let iv: Iv = rng.random();
    let aad = random_bytes(32);
    let pt = random_bytes(64);
    let enc = device_seal(ctx, &key, &iv, &aad, &pt);
    (key, iv, aad, enc.data, enc.tag)
}

/// NIST CAVP AES-256 encrypt vectors reproduce the published ciphertext
/// and tag.
#[test]
fn nist_cavp_encrypt_vectors() {
    let ctx = TestCtx::new();
    let mut n = 0;
    for v in AES_GCM_256_NIST_TEST_VECTORS.iter().filter(|v| v.encrypt) {
        check_cavp(&ctx, v);
        n += 1;
    }
    assert_eq!(n, 375, "CAVP encrypt vector count");
}

/// NIST CAVP AES-256 decrypt vectors recover the published plaintext, or
/// fail authentication where CAVP marks them FAIL.
#[test]
fn nist_cavp_decrypt_vectors() {
    let ctx = TestCtx::new();
    let mut n = 0;
    for v in AES_GCM_256_NIST_TEST_VECTORS.iter().filter(|v| !v.encrypt) {
        check_cavp(&ctx, v);
        n += 1;
    }
    assert_eq!(n, 375, "CAVP decrypt vector count");
}

/// GCM spec test cases 13-15 (block-aligned text) encrypt and decrypt
/// to the published values.
#[test]
fn spec_vectors_block_aligned() {
    let ctx = TestCtx::new();
    for case in &SPEC_ALIGNED {
        check_spec_case(&ctx, case);
    }
}

/// GCM spec test case 16 (60-byte text, 20-byte AAD) encrypts and
/// decrypts to the published values.
#[test]
fn spec_vector_unaligned() {
    let ctx = TestCtx::new();
    check_spec_case(&ctx, &SPEC_UNALIGNED);
}

/// Block-aligned text lengths match the host reference for every AAD
/// layout.
#[test]
fn block_aligned_lengths_match_host() {
    let ctx = TestCtx::new();
    for (i, &data_len) in ALIGNED_DATA_LENS.iter().enumerate() {
        for aad_len in AAD_LENS.iter().cycle().skip(i).take(3) {
            check_round_trip(&ctx, *aad_len, data_len);
        }
    }
}

/// Text lengths with a partial final block match the host reference,
/// as do random lengths.
#[test]
fn unaligned_lengths_match_host() {
    let ctx = TestCtx::new();
    for (i, &data_len) in UNALIGNED_DATA_LENS.iter().enumerate() {
        for aad_len in AAD_LENS.iter().cycle().skip(i).take(3) {
            check_round_trip(&ctx, *aad_len, data_len);
        }
    }

    let mut rng = rand::rng();
    for _ in 0..RANDOM_ROUNDS {
        let aad_len = rng.random_range(0..=TEST_AES_GCM_AAD_MAX_LEN);
        let data_len = rng.random_range(0..=TEST_AES_GCM_DATA_MAX_LEN);
        check_round_trip(&ctx, aad_len, data_len);
    }
}

/// The request `tag` field does not influence encryption.
#[test]
fn encrypt_ignores_request_tag() {
    let ctx = TestCtx::new();
    let mut rng = rand::rng();
    let key: Key = rng.random();
    let iv: Iv = rng.random();
    let aad = random_bytes(32);
    let pt = random_bytes(64);

    let zero = device_seal(&ctx, &key, &iv, &aad, &pt);
    let junk = ctx
        .tbor(&req(AES_OP_ENCRYPT, &key, &iv, &aad, &pt, &rng.random()))
        .expect("TestAesGcm encrypt with a junk request tag");
    assert_eq!(zero, junk);
}

/// Decrypt rejects a tag with any single bit flipped.
#[test]
fn decrypt_rejects_tampered_tag() {
    let ctx = TestCtx::new();
    let (key, iv, aad, ct, tag) = sealed_sample(&ctx);

    for (byte, bit) in [(0, 0), (7, 3), (TEST_AES_GCM_TAG_LEN - 1, 7)] {
        let mut bad = tag;
        bad[byte] ^= 1 << bit;
        ctx.expect_fw_reject(
            &req(AES_OP_DECRYPT, &key, &iv, &aad, &ct, &bad),
            TborStatus::AesGcmDecryptTagDoesNotMatch,
        );
    }
}

/// Decrypt rejects tampered ciphertext and tampered AAD.
#[test]
fn decrypt_rejects_tampered_ciphertext_and_aad() {
    let ctx = TestCtx::new();
    let (key, iv, aad, ct, tag) = sealed_sample(&ctx);

    let mut bad_ct = ct.clone();
    bad_ct[ct.len() / 2] ^= 0x01;
    ctx.expect_fw_reject(
        &req(AES_OP_DECRYPT, &key, &iv, &aad, &bad_ct, &tag),
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );

    let mut bad_aad = aad.clone();
    bad_aad[0] ^= 0x80;
    ctx.expect_fw_reject(
        &req(AES_OP_DECRYPT, &key, &iv, &bad_aad, &ct, &tag),
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// Decrypt under the wrong key or IV fails authentication.
#[test]
fn decrypt_rejects_wrong_key_and_iv() {
    let ctx = TestCtx::new();
    let (key, iv, aad, ct, tag) = sealed_sample(&ctx);

    let mut bad_key = key;
    bad_key[TEST_AES_GCM_KEY_LEN - 1] ^= 0x01;
    ctx.expect_fw_reject(
        &req(AES_OP_DECRYPT, &bad_key, &iv, &aad, &ct, &tag),
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );

    let mut bad_iv = iv;
    bad_iv[0] ^= 0x01;
    ctx.expect_fw_reject(
        &req(AES_OP_DECRYPT, &key, &bad_iv, &aad, &ct, &tag),
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

/// `op` values other than encrypt / decrypt are rejected.
#[test]
fn rejects_invalid_op() {
    let ctx = TestCtx::new();
    let key: Key = rand::rng().random();
    for op in [0u8, 3, 0xFF] {
        ctx.expect_fw_reject(
            &req(op, &key, &[0; TEST_AES_GCM_IV_LEN], &[], &[0; 16], &[0; 16]),
            TborStatus::InvalidArg,
        );
    }
}

/// AAD or text one byte beyond the maximum is rejected.
///
/// Asserted at the request boundary: the host encoder or the firmware
/// decoder may catch it, depending on where the length is enforced.
#[test]
fn rejects_over_max_lengths() {
    let ctx = TestCtx::new();
    let key: Key = rand::rng().random();
    let iv = [0u8; TEST_AES_GCM_IV_LEN];
    let tag = [0u8; TEST_AES_GCM_TAG_LEN];

    let long_aad = vec![0u8; TEST_AES_GCM_AAD_MAX_LEN + 1];
    assert!(
        ctx.tbor(&req(AES_OP_ENCRYPT, &key, &iv, &long_aad, &[], &tag))
            .is_err(),
        "AAD of {} bytes must be rejected",
        long_aad.len(),
    );

    let long_data = vec![0u8; TEST_AES_GCM_DATA_MAX_LEN + 1];
    assert!(
        ctx.tbor(&req(AES_OP_ENCRYPT, &key, &iv, &[], &long_data, &tag))
            .is_err(),
        "text of {} bytes must be rejected",
        long_data.len(),
    );
}
