// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-ECB tests.
//!
//! ECB is only supported on extended sessions; on other sessions every
//! operation must fail with `HsmError::UnsupportedAlgorithm`.

use tsra_api::HsmAesEcbAlgo;

use super::modes_common::*;
use super::*;

#[cfg(not(feature = "session-ex-tests"))]
#[session_test]
fn test_ecb_unsupported_without_ex_session(session: HsmSession) {
    let key = mode_key_all(&session, 128);
    let data = mode_data(32);

    let result = one_shot_encrypt(&mut HsmAesEcbAlgo, &key, &data);
    assert!(matches!(result, Err(HsmError::UnsupportedAlgorithm)));
    let result = one_shot_decrypt(&mut HsmAesEcbAlgo, &key, &data);
    assert!(matches!(result, Err(HsmError::UnsupportedAlgorithm)));
    let result = stream_encrypt(HsmAesEcbAlgo, &key, &data, &[16]);
    assert!(matches!(result, Err(HsmError::UnsupportedAlgorithm)));
    let result = stream_decrypt(HsmAesEcbAlgo, &key, &data, &[16]);
    assert!(matches!(result, Err(HsmError::UnsupportedAlgorithm)));
}

#[cfg(feature = "session-ex-tests")]
mod ex {
    use super::common::cbc_encrypt;
    use super::*;

    fn run_known_answer(session: &HsmSession, bits: u32) {
        let key = mode_key_all(session, bits);
        for len in [16, 32, 160, 2 * 1024 + 48] {
            let pt = mode_data(len);
            // CBC with a zero IV over a single block is the AES forward cipher.
            let expected: Vec<u8> = pt
                .chunks(AES_BLOCK)
                .flat_map(|b| cbc_encrypt(&key, false, &[0u8; AES_BLOCK], b).expect("cbc"))
                .collect();

            let ct = one_shot_encrypt(&mut HsmAesEcbAlgo, &key, &pt).expect("encrypt");
            assert_eq!(ct, expected, "ciphertext len {len}");
            let back = one_shot_decrypt(&mut HsmAesEcbAlgo, &key, &ct).expect("decrypt");
            assert_eq!(back, pt, "plaintext len {len}");
        }
    }

    /// Each block matches the AES forward cipher (via zero-IV CBC).
    #[session_test]
    fn test_ecb_known_answer_128(session: HsmSession) {
        run_known_answer(&session, 128);
    }

    /// Each block matches the AES forward cipher (via zero-IV CBC).
    #[session_test]
    fn test_ecb_known_answer_192(session: HsmSession) {
        run_known_answer(&session, 192);
    }

    /// Each block matches the AES forward cipher (via zero-IV CBC).
    #[session_test]
    fn test_ecb_known_answer_256(session: HsmSession) {
        run_known_answer(&session, 256);
    }

    /// Identical plaintext blocks encrypt to identical ciphertext blocks.
    #[session_test]
    fn test_ecb_identical_blocks(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let pt = [0x5Au8; 48];
        let ct = one_shot_encrypt(&mut HsmAesEcbAlgo, &key, &pt).expect("encrypt");
        assert_eq!(ct[..16], ct[16..32]);
        assert_eq!(ct[..16], ct[32..]);
    }

    /// Empty and non-block-aligned input is rejected.
    #[session_test]
    fn test_ecb_invalid_length(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        for len in [0, 1, 15, 17, 33] {
            let data = mode_data(len);
            let result = one_shot_encrypt(&mut HsmAesEcbAlgo, &key, &data);
            assert!(
                matches!(result, Err(HsmError::InvalidArgument)),
                "len {len}"
            );
            let result = one_shot_decrypt(&mut HsmAesEcbAlgo, &key, &data);
            assert!(
                matches!(result, Err(HsmError::InvalidArgument)),
                "len {len}"
            );
        }
    }

    /// Streaming with irregular chunk sizes matches single-shot output.
    #[session_test]
    fn test_ecb_streaming_matches_single_shot(session: HsmSession) {
        let key = mode_key_all(&session, 256);
        let pt = mode_data(1104);
        let ct = one_shot_encrypt(&mut HsmAesEcbAlgo, &key, &pt).expect("encrypt");

        for sizes in [&[1usize][..], &[7], &[16], &[5, 33, 2], &[1024, 3], &[2000]] {
            let (sct, _) = stream_encrypt(HsmAesEcbAlgo, &key, &pt, sizes).expect("stream encrypt");
            assert_eq!(sct, ct, "encrypt chunks {sizes:?}");
            let (spt, _) = stream_decrypt(HsmAesEcbAlgo, &key, &ct, sizes).expect("stream decrypt");
            assert_eq!(spt, pt, "decrypt chunks {sizes:?}");
        }
    }

    /// Streaming finish fails if the total input was not block-aligned.
    #[session_test]
    fn test_ecb_streaming_partial_block_rejected(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let result = stream_encrypt(HsmAesEcbAlgo, &key, &mode_data(20), &[7]);
        assert!(matches!(result, Err(HsmError::InvalidArgument)));
        let result = stream_decrypt(HsmAesEcbAlgo, &key, &mode_data(31), &[16]);
        assert!(matches!(result, Err(HsmError::InvalidArgument)));
    }

    /// Output buffers smaller than the input are rejected.
    #[session_test]
    fn test_ecb_buffer_too_small(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let pt = mode_data(32);
        let mut out = vec![0u8; 16];
        let result = HsmAesEcbAlgo.encrypt(&key, &pt, Some(&mut out));
        assert!(matches!(result, Err(HsmError::BufferTooSmall)));
        let result = HsmAesEcbAlgo.decrypt(&key, &pt, Some(&mut out));
        assert!(matches!(result, Err(HsmError::BufferTooSmall)));

        let mut ctx = HsmAesEcbAlgo.encrypt_init(key).expect("init");
        let result = ctx.update(&pt, Some(&mut out));
        assert!(matches!(result, Err(HsmError::BufferTooSmall)));
    }

    /// Keys without the matching usage are rejected.
    #[session_test]
    fn test_ecb_key_permissions(session: HsmSession) {
        let pt = mode_data(16);
        match mode_key(&session, 128, false, true) {
            Ok(key) => {
                let result = one_shot_encrypt(&mut HsmAesEcbAlgo, &key, &pt);
                assert!(matches!(result, Err(HsmError::InvalidKey)));
                let result = HsmAesEcbAlgo.encrypt_init(key);
                assert!(matches!(result, Err(HsmError::InvalidKey)));
            }
            Err(HsmError::InvalidKeyProps) => {}
            Err(e) => panic!("unexpected keygen error: {e:?}"),
        }
        match mode_key(&session, 128, true, false) {
            Ok(key) => {
                let result = one_shot_decrypt(&mut HsmAesEcbAlgo, &key, &pt);
                assert!(matches!(result, Err(HsmError::InvalidKey)));
                let result = HsmAesEcbAlgo.decrypt_init(key);
                assert!(matches!(result, Err(HsmError::InvalidKey)));
            }
            Err(HsmError::InvalidKeyProps) => {}
            Err(e) => panic!("unexpected keygen error: {e:?}"),
        }
    }

    /// A finished context rejects further use.
    #[session_test]
    fn test_ecb_context_unusable_after_finish(session: HsmSession) {
        let key = mode_key_all(&session, 128);
        let pt = mode_data(16);
        let mut out = vec![0u8; 16];

        let mut ctx = HsmAesEcbAlgo.encrypt_init(key).expect("init");
        ctx.update(&pt, Some(&mut out)).expect("update");
        ctx.finish(Some(&mut out)).expect("finish");
        let result = ctx.update(&pt, Some(&mut out));
        assert!(matches!(result, Err(HsmError::InvalidContextState)));
        let result = ctx.finish(Some(&mut out));
        assert!(matches!(result, Err(HsmError::InvalidContextState)));
    }
}
