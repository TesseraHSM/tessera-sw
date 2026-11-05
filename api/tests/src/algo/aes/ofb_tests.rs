// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-OFB tests.
//!
//! OFB is only supported on extended sessions; on other sessions every
//! operation must fail with `HsmError::UnsupportedAlgorithm`.

use tsra_api::HsmAesOfbAlgo;

use super::modes_common::*;
use super::*;

fn new_algo(iv: &[u8]) -> HsmAesOfbAlgo {
    HsmAesOfbAlgo::new(iv.to_vec()).expect("Failed to create AES-OFB algo")
}

fn iv_a() -> Vec<u8> {
    (0u8..16).collect()
}

#[cfg(not(feature = "session-ex-tests"))]
#[session_test]
fn test_ofb_unsupported_without_ex_session(session: HsmSession) {
    let key = mode_key_all(&session, 128);
    let data = mode_data(32);

    let result = one_shot_encrypt(&mut new_algo(&iv_a()), &key, &data);
    assert!(matches!(result, Err(HsmError::UnsupportedAlgorithm)));
    let result = one_shot_decrypt(&mut new_algo(&iv_a()), &key, &data);
    assert!(matches!(result, Err(HsmError::UnsupportedAlgorithm)));
    let result = stream_encrypt(new_algo(&iv_a()), &key, &data, &[16]);
    assert!(matches!(result, Err(HsmError::UnsupportedAlgorithm)));
    let result = stream_decrypt(new_algo(&iv_a()), &key, &data, &[16]);
    assert!(matches!(result, Err(HsmError::UnsupportedAlgorithm)));
}

/// IVs that are not exactly 16 bytes are rejected.
#[test]
fn test_ofb_invalid_iv_len() {
    for len in [0, 1, 15, 17, 32] {
        let result = HsmAesOfbAlgo::new(vec![0u8; len]);
        assert!(
            matches!(result, Err(HsmError::InvalidArgument)),
            "len {len}"
        );
    }
}

#[cfg(feature = "session-ex-tests")]
mod ex {
    use super::*;

    const LENGTHS: [usize; 9] = [1, 15, 16, 17, 31, 32, 33, 100, 255];

    fn run_known_answer(session: &HsmSession, bits: u32) {
        let key = mode_key_all(session, bits);
        for len in LENGTHS {
            let pt = mode_data(len);
            let (expected, expected_iv) = reference_encrypt(RefMode::Ofb, &key, &iv_a(), &pt);

            let mut algo = new_algo(&iv_a());
            let ct = one_shot_encrypt(&mut algo, &key, &pt).expect("encrypt");
            assert_eq!(ct, expected, "ciphertext len {len}");
            assert_eq!(algo.iv(), expected_iv, "IV-out len {len}");

            let mut algo = new_algo(&iv_a());
            let back = one_shot_decrypt(&mut algo, &key, &ct).expect("decrypt");
            assert_eq!(back, pt, "plaintext len {len}");
            assert_eq!(algo.iv(), expected_iv, "decrypt IV-out len {len}");
        }
    }

    /// Output matches the SP 800-38A definition built from the HSM's ECB.
    #[session_test]
    fn test_ofb_known_answer_128(session: HsmSession) {
        run_known_answer(&session, 128);
    }

    /// Output matches the SP 800-38A definition built from the HSM's ECB.
    #[session_test]
    fn test_ofb_known_answer_192(session: HsmSession) {
        run_known_answer(&session, 192);
    }

    /// Output matches the SP 800-38A definition built from the HSM's ECB.
    #[session_test]
    fn test_ofb_known_answer_256(session: HsmSession) {
        run_known_answer(&session, 256);
    }

    /// Input larger than one device request is chunked with correct chaining.
    #[session_test]
    fn test_ofb_known_answer_multi_request(session: HsmSession) {
        let key = mode_key_all(&session, 256);
        let pt = mode_data(2 * 1024 + 37);
        let (expected, expected_iv) = reference_encrypt(RefMode::Ofb, &key, &iv_a(), &pt);

        let mut algo = new_algo(&iv_a());
        let ct = one_shot_encrypt(&mut algo, &key, &pt).expect("encrypt");
        assert_eq!(ct, expected);
        assert_eq!(algo.iv(), expected_iv);

        let back = one_shot_decrypt(&mut new_algo(&iv_a()), &key, &ct).expect("decrypt");
        assert_eq!(back, pt);
    }

    /// Streaming with irregular chunk sizes matches single-shot output.
    #[session_test]
    fn test_ofb_streaming_matches_single_shot(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let pt = mode_data(1100);
        let mut algo = new_algo(&iv_a());
        let ct = one_shot_encrypt(&mut algo, &key, &pt).expect("encrypt");

        for sizes in [&[1usize][..], &[7], &[16], &[5, 33, 2], &[1024, 3], &[2000]] {
            let (sct, salgo) =
                stream_encrypt(new_algo(&iv_a()), &key, &pt, sizes).expect("stream encrypt");
            assert_eq!(sct, ct, "encrypt chunks {sizes:?}");
            assert_eq!(salgo.iv(), algo.iv(), "encrypt IV-out chunks {sizes:?}");

            let (spt, salgo) =
                stream_decrypt(new_algo(&iv_a()), &key, &ct, sizes).expect("stream decrypt");
            assert_eq!(spt, pt, "decrypt chunks {sizes:?}");
            assert_eq!(salgo.iv(), algo.iv(), "decrypt IV-out chunks {sizes:?}");
        }
    }

    /// Block-aligned calls can be continued from the chained IV.
    #[session_test]
    fn test_ofb_chained_calls_match_single_shot(session: HsmSession) {
        let key = mode_key_all(&session, 192);
        let pt = mode_data(77);
        let ct = one_shot_encrypt(&mut new_algo(&iv_a()), &key, &pt).expect("encrypt");

        let mut algo = new_algo(&iv_a());
        let mut chained = one_shot_encrypt(&mut algo, &key, &pt[..32]).expect("encrypt first");
        chained.extend(one_shot_encrypt(&mut algo, &key, &pt[32..48]).expect("encrypt second"));
        chained.extend(one_shot_encrypt(&mut algo, &key, &pt[48..]).expect("encrypt last"));
        assert_eq!(chained, ct);
    }

    /// Different IVs produce different ciphertext.
    #[session_test]
    fn test_ofb_iv_changes_ciphertext(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let pt = mode_data(48);
        let mut iv_b = iv_a();
        iv_b[0] ^= 1;
        let a = one_shot_encrypt(&mut new_algo(&iv_a()), &key, &pt).expect("encrypt a");
        let b = one_shot_encrypt(&mut new_algo(&iv_b), &key, &pt).expect("encrypt b");
        assert_ne!(a, b);
    }

    /// Empty input produces empty output and leaves the IV unchanged.
    #[session_test]
    fn test_ofb_empty_input(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let mut algo = new_algo(&iv_a());
        assert!(
            one_shot_encrypt(&mut algo, &key, &[])
                .expect("encrypt")
                .is_empty()
        );
        assert!(
            one_shot_decrypt(&mut algo, &key, &[])
                .expect("decrypt")
                .is_empty()
        );
        assert_eq!(algo.iv(), iv_a());

        let (out, algo) = stream_encrypt(new_algo(&iv_a()), &key, &[], &[16]).expect("stream");
        assert!(out.is_empty());
        assert_eq!(algo.iv(), iv_a());
    }

    /// Size queries report the input length.
    #[session_test]
    fn test_ofb_size_query(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let pt = mode_data(37);
        let mut algo = new_algo(&iv_a());
        assert_eq!(algo.encrypt(&key, &pt, None).expect("encrypt len"), 37);
        assert_eq!(algo.decrypt(&key, &pt, None).expect("decrypt len"), 37);
        assert_eq!(algo.iv(), iv_a());

        let mut ctx = new_algo(&iv_a()).encrypt_init(key.clone()).expect("init");
        assert_eq!(ctx.update(&pt, None).expect("update len"), 32);
        let mut out = vec![0u8; 32];
        assert_eq!(ctx.update(&pt, Some(&mut out)).expect("update"), 32);
        assert_eq!(ctx.finish(None).expect("finish len"), 5);
    }

    /// Output buffers smaller than the input are rejected.
    #[session_test]
    fn test_ofb_buffer_too_small(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let pt = mode_data(33);
        let mut out = vec![0u8; 32];
        let mut algo = new_algo(&iv_a());
        let result = algo.encrypt(&key, &pt, Some(&mut out));
        assert!(matches!(result, Err(HsmError::BufferTooSmall)));
        let result = algo.decrypt(&key, &pt, Some(&mut out));
        assert!(matches!(result, Err(HsmError::BufferTooSmall)));

        let mut ctx = new_algo(&iv_a()).decrypt_init(key.clone()).expect("init");
        let result = ctx.update(&pt, Some(&mut out[..16]));
        assert!(matches!(result, Err(HsmError::BufferTooSmall)));
        ctx.update(&pt, Some(&mut out)).expect("update");
        let result = ctx.finish(Some(&mut []));
        assert!(matches!(result, Err(HsmError::BufferTooSmall)));
    }

    /// Keys without the matching usage are rejected.
    #[session_test]
    fn test_ofb_key_permissions(session: HsmSession) {
        let pt = mode_data(16);
        match mode_key(&session, 128, false, true) {
            Ok(key) => {
                let result = one_shot_encrypt(&mut new_algo(&iv_a()), &key, &pt);
                assert!(matches!(result, Err(HsmError::InvalidKey)));
                let result = new_algo(&iv_a()).encrypt_init(key);
                assert!(matches!(result, Err(HsmError::InvalidKey)));
            }
            Err(HsmError::InvalidKeyProps) => {}
            Err(e) => panic!("unexpected keygen error: {e:?}"),
        }
        match mode_key(&session, 128, true, false) {
            Ok(key) => {
                let result = one_shot_decrypt(&mut new_algo(&iv_a()), &key, &pt);
                assert!(matches!(result, Err(HsmError::InvalidKey)));
                let result = new_algo(&iv_a()).decrypt_init(key);
                assert!(matches!(result, Err(HsmError::InvalidKey)));
            }
            Err(HsmError::InvalidKeyProps) => {}
            Err(e) => panic!("unexpected keygen error: {e:?}"),
        }
    }

    /// A finished context rejects further use.
    #[session_test]
    fn test_ofb_context_unusable_after_finish(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let pt = mode_data(20);
        let mut out = vec![0u8; 32];

        let mut ctx = new_algo(&iv_a()).encrypt_init(key.clone()).expect("init");
        ctx.update(&pt, Some(&mut out)).expect("update");
        ctx.finish(Some(&mut out)).expect("finish");
        let result = ctx.update(&pt, Some(&mut out));
        assert!(matches!(result, Err(HsmError::InvalidContextState)));
        let result = ctx.finish(Some(&mut out));
        assert!(matches!(result, Err(HsmError::InvalidContextState)));

        let mut ctx = new_algo(&iv_a()).decrypt_init(key).expect("init");
        ctx.finish(Some(&mut out)).expect("finish");
        let result = ctx.update(&pt, Some(&mut out));
        assert!(matches!(result, Err(HsmError::InvalidContextState)));
    }
}
