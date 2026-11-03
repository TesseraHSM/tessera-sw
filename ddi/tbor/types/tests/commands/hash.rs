// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `Hash` command.
//!
//! `Hash` computes a SHA-1 / 256 / 384 / 512 digest, or SHAKE128 / SHAKE256
//! output of a requested length, of a host-supplied message.  These tests
//! hash several messages on-device and verify the result byte-for-byte
//! against the output computed on the host with `tsra_crypto` (natural
//! big-endian output), for every algorithm.

use std::num::NonZeroUsize;

use tsra_crypto::HashAlgo as CryptoHashAlgo;
use tsra_crypto::Hasher;
use tsra_ddi_tbor_test_harness::bootstrap_rotated_cu;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::CU_PSK_ID;
use tsra_ddi_tbor_test_harness::ROTATED_CU_PSK;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::TborHashReq;
use tsra_ddi_tbor_types::TborStatus;
use tsra_ddi_tbor_types::HASH_ALGO_SHA1;
use tsra_ddi_tbor_types::HASH_ALGO_SHA256;
use tsra_ddi_tbor_types::HASH_ALGO_SHA384;
use tsra_ddi_tbor_types::HASH_ALGO_SHA512;
use tsra_ddi_tbor_types::HASH_ALGO_SHAKE128;
use tsra_ddi_tbor_types::HASH_ALGO_SHAKE256;
use tsra_ddi_tbor_types::HASH_DIGEST_MAX_LEN;

use crate::commands::sd_sealing_key_gen::finalized_co_session;

/// All supported TBOR Hash algorithms.
const HASH_ALGOS: [u8; 4] = [
    HASH_ALGO_SHA1,
    HASH_ALGO_SHA256,
    HASH_ALGO_SHA384,
    HASH_ALGO_SHA512,
];

/// Clear the CU default-PSK gate without keeping a session slot occupied.
fn rotate_cu_psk_and_close(ctx: &TestCtx) {
    let bootstrap = ctx
        .open_session(CU_PSK_ID, SessionType::PlainText)
        .expect("open bootstrap CU session");
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU session");
}

/// Hash `msg` on-device with `algo`, returning the digest.
fn device_digest(ctx: &TestCtx, session_id: u16, algo: u8, msg: Vec<u8>) -> Vec<u8> {
    ctx.tbor(&TborHashReq {
        session_id,
        algo,
        out_len: None,
        msg,
    })
    .expect("Hash")
    .digest
}

/// Compute the expected digest on the host with `tsra_crypto`.
fn host_digest(algo: u8, msg: &[u8]) -> Vec<u8> {
    let mut crypto_algo = match algo {
        HASH_ALGO_SHA1 => CryptoHashAlgo::sha1(),
        HASH_ALGO_SHA256 => CryptoHashAlgo::sha256(),
        HASH_ALGO_SHA384 => CryptoHashAlgo::sha384(),
        HASH_ALGO_SHA512 => CryptoHashAlgo::sha512(),
        _ => unreachable!("unknown hash algo"),
    };
    Hasher::hash_vec(&mut crypto_algo, msg).expect("host hash")
}

/// Expected digest length for a mode.
fn digest_len(algo: u8) -> usize {
    match algo {
        HASH_ALGO_SHA1 => 20,
        HASH_ALGO_SHA256 => 32,
        HASH_ALGO_SHA384 => 48,
        HASH_ALGO_SHA512 => 64,
        _ => unreachable!(),
    }
}

/// Verifies SHA-1, SHA-256, SHA-384, and SHA-512 digests match the host for varied inputs.
#[test]
fn hash_matches_host_all_algos() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // A few messages: short, empty, and a longer non-trivial buffer.
    let short = b"abc".to_vec();
    let empty: Vec<u8> = Vec::new();
    let long: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();

    for msg in [short, empty, long] {
        for mode in HASH_ALGOS {
            let dev = device_digest(&ctx, session.session_id, mode, msg.clone());
            assert_eq!(
                dev.len(),
                digest_len(mode),
                "digest length must match the algorithm (mode {mode}, msg {} B)",
                msg.len(),
            );
            assert_eq!(
                dev,
                host_digest(mode, &msg),
                "device digest must match host SHA (mode {mode}, msg {} B)",
                msg.len(),
            );
        }
    }
}

/// Rejects an unsupported hash algorithm.
#[test]
fn hash_unknown_algo_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborHashReq {
            session_id: session.session_id,
            algo: u8::MAX,
            out_len: None,
            msg: b"abc".to_vec(),
        },
        TborStatus::InvalidArg,
    );
}

/// Rejects a Hash request that references a nonexistent session.
#[test]
fn hash_invalid_session_id_rejected() {
    let ctx = TestCtx::new();

    // u16::MAX selects the CU role; clear its default-PSK gate first.
    rotate_cu_psk_and_close(&ctx);

    ctx.expect_session_reject(
        &TborHashReq {
            session_id: u16::MAX,
            algo: HASH_ALGO_SHA256,
            out_len: None,
            msg: b"abc".to_vec(),
        },
        TborStatus::SessionNotFound,
    );
}

/// Rejects multiple invalid hash algorithm discriminants.
#[test]
fn hash_invalid_algos_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // Valid algorithms are:
    //   0 = SHA-1
    //   1 = SHA-256
    //   2 = SHA-384
    //   3 = SHA-512
    //   7 = SHAKE128, 8 = SHAKE256 (4-6 are reserved for SHA-3)
    for algo in [HASH_ALGO_SHA512.wrapping_add(1), 5, 6, 9, 0x7f, u8::MAX] {
        ctx.expect_fw_reject(
            &TborHashReq {
                session_id: session.session_id,
                algo,
                out_len: None,
                msg: b"abc".to_vec(),
            },
            TborStatus::InvalidArg,
        );
    }
}

/// Verifies binary input containing arbitrary byte values hashes correctly.
#[test]
fn hash_binary_message_matches_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let msg = vec![
        0x00, 0xff, 0x80, 0x7f, 0x00, 0x01, 0xfe, 0xaa, 0x55, 0x00, 0xff,
    ];

    for algo in HASH_ALGOS {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(dev, host_digest(algo, &msg));
    }
}

/// Verifies different messages produce different digests for every supported algorithm.
#[test]
fn hash_different_messages_produce_different_digests() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for algo in HASH_ALGOS {
        let digest_a = device_digest(&ctx, session.session_id, algo, b"abc".to_vec());
        let digest_b = device_digest(&ctx, session.session_id, algo, b"abd".to_vec());

        assert_ne!(
            digest_a, digest_b,
            "different messages should produce different hashes for algo {algo}",
        );
    }
}

/// Verifies hashing across SHA padding and compression-block boundaries.
#[test]
fn hash_block_boundary_lengths_match_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    // SHA-1/SHA-256 block = 64 bytes.
    // SHA-384/SHA-512 block = 128 bytes.
    for len in [1usize, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129] {
        let msg: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

        for algo in HASH_ALGOS {
            let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

            assert_eq!(
                dev,
                host_digest(algo, &msg),
                "hash mismatch for algo {algo}, message length {len}",
            );
        }
    }
}

/// Rejects a Hash request made with a previously closed session.
#[test]
fn hash_closed_session_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let session_id = session.session_id;

    ctx.session_close(session_id).expect("close CO session");

    ctx.expect_session_reject(
        &TborHashReq {
            session_id,
            algo: HASH_ALGO_SHA256,
            out_len: None,
            msg: b"abc".to_vec(),
        },
        TborStatus::SessionNotFound,
    );
}

/// Verifies the same message hashes correctly with every supported algorithm.
#[test]
fn hash_same_message_different_algos() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = b"same message".to_vec();

    for algo in HASH_ALGOS {
        let digest = device_digest(&ctx, session.session_id, algo, msg.clone());
        assert_eq!(
            digest.len(),
            digest_len(algo),
            "digest length for algo {algo}"
        );
        assert_eq!(digest, host_digest(algo, &msg), "digest for algo {algo}");
    }
}

/// Verifies a one-bit input change produces a different digest.
#[test]
fn hash_one_bit_message_change_changes_digest() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let msg_a = vec![0x00; 64];
    let mut msg_b = msg_a.clone();
    msg_b[31] ^= 0x01;

    for algo in HASH_ALGOS {
        let digest_a = device_digest(&ctx, session.session_id, algo, msg_a.clone());
        let digest_b = device_digest(&ctx, session.session_id, algo, msg_b.clone());

        assert_ne!(
            digest_a, digest_b,
            "one-bit input change must change digest for algo {algo}",
        );

        assert_eq!(digest_a, host_digest(algo, &msg_a));
        assert_eq!(digest_b, host_digest(algo, &msg_b));
    }
}

/// Verifies a rotated Crypto-User session can hash with every supported algorithm.
#[test]
fn hash_crypto_user_session_matches_host() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    let msg = b"crypto-user hash".to_vec();

    for algo in HASH_ALGOS {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "CU hash must match host for algo {algo}",
        );
    }
}

/// Verifies SHA-1, SHA-256, SHA-384, and SHA-512 against known-answer vectors.
#[test]
fn hash_known_answer_vectors() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = b"abc".to_vec();

    let sha1_expected = [
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2,
        0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    ];

    assert_eq!(
        device_digest(&ctx, session.session_id, HASH_ALGO_SHA1, msg.clone()),
        sha1_expected,
    );

    let sha256_expected = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    let sha384_expected = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50,
        0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff,
        0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34,
        0xc8, 0x25, 0xa7,
    ];

    let sha512_expected = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];

    assert_eq!(
        device_digest(&ctx, session.session_id, HASH_ALGO_SHA256, msg.clone()),
        sha256_expected,
    );

    assert_eq!(
        device_digest(&ctx, session.session_id, HASH_ALGO_SHA384, msg.clone()),
        sha384_expected,
    );

    assert_eq!(
        device_digest(&ctx, session.session_id, HASH_ALGO_SHA512, msg),
        sha512_expected,
    );
}

/// Rejects hashing from a Crypto-User session that still uses the default PSK.
#[test]
fn hash_default_psk_cu_rejected() {
    let ctx = TestCtx::new();

    let session = ctx
        .open_session(CU_PSK_ID, SessionType::PlainText)
        .expect("open default-PSK CU session");

    ctx.expect_fw_reject(
        &TborHashReq {
            session_id: session.session_id(),
            algo: HASH_ALGO_SHA256,
            out_len: None,
            msg: b"abc".to_vec(),
        },
        TborStatus::DefaultPskMustRotate,
    );
}

/// Verifies repeated identical Hash requests return the same digest.
#[test]
fn hash_same_request_is_deterministic() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = b"deterministic hash input".to_vec();

    for algo in HASH_ALGOS {
        let first = device_digest(&ctx, session.session_id, algo, msg.clone());

        let second = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            first, second,
            "same input must produce same digest for algo {algo}",
        );
    }
}

/// Hashing the full range of byte values must match the host implementation.
#[test]
fn hash_all_byte_values_matches_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let msg: Vec<u8> = (0u8..=u8::MAX).collect();

    for algo in HASH_ALGOS {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "all-byte-values hash mismatch for algo {algo}",
        );
    }
}

/// A rejected Hash request must not invalidate or poison the session.
#[test]
fn hash_session_usable_after_invalid_algo() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    ctx.expect_fw_reject(
        &TborHashReq {
            session_id: session.session_id,
            algo: u8::MAX,
            out_len: None,
            msg: b"invalid request".to_vec(),
        },
        TborStatus::InvalidArg,
    );

    let msg = b"valid request after rejection".to_vec();

    for algo in HASH_ALGOS {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "session must remain usable after rejected request for algo {algo}",
        );
    }
}

/// Verifies consecutive requests of different lengths do not retain hash state.
#[test]
fn hash_consecutive_different_length_messages_match_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let messages = [
        vec![0x5a],
        vec![0xa5; 1000],
        Vec::new(),
        vec![0x3c; 17],
        vec![0xc3; 513],
    ];

    for algo in HASH_ALGOS {
        for msg in &messages {
            let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

            assert_eq!(
                dev,
                host_digest(algo, msg),
                "hash mismatch for algo {algo}, message length {}",
                msg.len(),
            );
        }
    }
}

/// Verifies switching hash algorithms on the same session does not leak state
/// between requests.
#[test]
fn hash_alternating_algorithms_match_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);
    let msg = b"alternate hash algorithms on one session".to_vec();

    let sequence = [
        HASH_ALGO_SHA1,
        HASH_ALGO_SHA256,
        HASH_ALGO_SHA512,
        HASH_ALGO_SHA384,
        HASH_ALGO_SHA1,
        HASH_ALGO_SHA256,
        HASH_ALGO_SHA384,
        HASH_ALGO_SHA512,
    ];

    for algo in sequence {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "algorithm switch must not retain state from a previous Hash request (algo {algo})",
        );
    }
}

/// Verifies leading, embedded, and trailing zero bytes are treated as message
/// data rather than terminators.
#[test]
fn hash_zero_byte_positions_match_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let messages = [
        vec![0x00],
        vec![0x00, 0x61, 0x62, 0x63],
        vec![0x61, 0x00, 0x62, 0x00, 0x63],
        vec![0x61, 0x62, 0x63, 0x00],
        vec![0x00; 128],
    ];

    for msg in &messages {
        for algo in HASH_ALGOS {
            let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

            assert_eq!(
                dev,
                host_digest(algo, msg),
                "zero-containing input mismatch for algo {algo}, message length {}",
                msg.len(),
            );
        }
    }
}

/// Verifies CO and rotated-CU sessions produce the same digest for the same
/// request. Sessions are exercised sequentially because authenticated CO and
/// CU setup may consume the same limited session resource in the test fixture.
#[test]
fn hash_matches_across_co_and_cu_sessions() {
    let ctx = TestCtx::new();
    let msg = b"same hash request across sessions".to_vec();

    let co_session = finalized_co_session(&ctx);

    let co_digests: Vec<(u8, Vec<u8>)> = HASH_ALGOS
        .into_iter()
        .map(|algo| {
            let digest = device_digest(&ctx, co_session.session_id, algo, msg.clone());

            assert_eq!(
                digest,
                host_digest(algo, &msg),
                "CO digest must match host for algo {algo}",
            );

            (algo, digest)
        })
        .collect();

    ctx.session_close(co_session.session_id)
        .expect("close CO session");

    let cu_session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);

    for (algo, co_digest) in co_digests {
        let cu_digest = device_digest(&ctx, cu_session.session_id, algo, msg.clone());

        assert_eq!(
            cu_digest,
            host_digest(algo, &msg),
            "CU digest must match host for algo {algo}",
        );

        assert_eq!(
            cu_digest, co_digest,
            "CO and CU sessions must produce the same digest for algo {algo}",
        );
    }
}

/// Verifies a request using an invalid session ID does not affect a separate
/// valid session.
#[test]
fn hash_valid_session_usable_after_invalid_session_request() {
    let ctx = TestCtx::new();
    // Rotate and close CU before opening CO to avoid competing for a slot.
    rotate_cu_psk_and_close(&ctx);
    let session = finalized_co_session(&ctx);

    ctx.expect_session_reject(
        &TborHashReq {
            session_id: u16::MAX,
            algo: HASH_ALGO_SHA512,
            out_len: None,
            msg: b"request with invalid session".to_vec(),
        },
        TborStatus::FileHandleSessionIdDoesNotMatch,
    );

    let msg = b"valid session still works".to_vec();

    for algo in HASH_ALGOS {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "valid session must remain usable after an invalid-session request (algo {algo})",
        );
    }
}

/// Verifies closing one session releases its slot and a subsequently opened CU
/// session can execute Hash normally.
#[test]
fn hash_new_session_works_after_previous_session_closed() {
    let ctx = TestCtx::new();

    let co_session = finalized_co_session(&ctx);
    let closed_session_id = co_session.session_id;

    let first_msg = b"hash before closing CO session".to_vec();
    let digest = device_digest(&ctx, closed_session_id, HASH_ALGO_SHA256, first_msg.clone());

    assert_eq!(
        digest,
        host_digest(HASH_ALGO_SHA256, &first_msg),
        "CO Hash must work before the session is closed",
    );

    ctx.session_close(closed_session_id)
        .expect("close CO session");

    ctx.expect_session_reject(
        &TborHashReq {
            session_id: closed_session_id,
            algo: HASH_ALGO_SHA256,
            out_len: None,
            msg: b"closed session".to_vec(),
        },
        TborStatus::SessionNotFound,
    );

    let cu_session = bootstrap_rotated_cu(&ctx, &ROTATED_CU_PSK);
    let msg = b"new session after previous session closed".to_vec();

    for algo in HASH_ALGOS {
        let dev = device_digest(&ctx, cu_session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "new CU session must hash correctly after CO session was closed for algo {algo}",
        );
    }
}

/// Verifies the protocol maximum Hash message length succeeds and matches the
/// host implementation for every supported algorithm.
#[test]
fn hash_max_message_length_matches_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let msg: Vec<u8> = (0..2048usize).map(|i| (i % 251) as u8).collect();

    for algo in HASH_ALGOS {
        let dev = device_digest(&ctx, session.session_id, algo, msg.clone());

        assert_eq!(
            dev,
            host_digest(algo, &msg),
            "maximum-length Hash request must match host for algo {algo}",
        );
    }
}

/// Verifies a Hash message one byte beyond the protocol maximum is rejected.
///
/// Keep this assertion at the request boundary rather than pinning a firmware
/// status: depending on where length validation occurs, the request may be
/// rejected by TBOR encoding/decoding before the Hash handler executes.
#[test]
fn hash_over_max_message_length_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for algo in HASH_ALGOS {
        let result = ctx.tbor(&TborHashReq {
            session_id: session.session_id,
            algo,
            out_len: None,
            msg: vec![0x5a; 2049],
        });
        assert!(
            result.is_err(),
            "2049-byte Hash message must be rejected for algo {algo}",
        );
    }
}

/// The SHAKE XOFs, whose output length the request chooses.
const SHAKE_ALGOS: [u8; 2] = [HASH_ALGO_SHAKE128, HASH_ALGO_SHAKE256];

/// Hash `msg` on-device with a SHAKE XOF, returning `out_len` bytes.
fn device_shake(ctx: &TestCtx, session_id: u16, algo: u8, out_len: u16, msg: Vec<u8>) -> Vec<u8> {
    ctx.tbor(&TborHashReq {
        session_id,
        algo,
        out_len: Some(out_len),
        msg,
    })
    .expect("Hash (SHAKE)")
    .digest
}

/// Compute the expected SHAKE output on the host with `tsra_crypto`.
fn host_shake(algo: u8, out_len: u16, msg: &[u8]) -> Vec<u8> {
    let len = NonZeroUsize::new(usize::from(out_len)).expect("non-zero out_len");
    let mut crypto_algo = match algo {
        HASH_ALGO_SHAKE128 => CryptoHashAlgo::shake128(len),
        HASH_ALGO_SHAKE256 => CryptoHashAlgo::shake256(len),
        _ => unreachable!("not a SHAKE algo"),
    };
    Hasher::hash_vec(&mut crypto_algo, msg).expect("host SHAKE")
}

/// Verifies SHAKE128 and SHAKE256 match the host at output lengths from 1 to
/// the 256-byte maximum (across the 136- and 168-byte sponge rates) for empty,
/// short, long and maximum-length messages.
#[test]
fn hash_shake_matches_host() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let long: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    let max: Vec<u8> = (0..2048usize).map(|i| (i % 251) as u8).collect();

    for msg in [Vec::new(), b"abc".to_vec(), long, max] {
        for algo in SHAKE_ALGOS {
            for out_len in [1u16, 16, 32, 64, 136, 168, 169, 255, 256] {
                let dev = device_shake(&ctx, session.session_id, algo, out_len, msg.clone());
                assert_eq!(
                    dev,
                    host_shake(algo, out_len, &msg),
                    "device SHAKE must match host (algo {algo}, out_len {out_len}, msg {} B)",
                    msg.len(),
                );
            }
        }
    }
}

/// Verifies the FIPS 202 "abc" known answers: 32 bytes of SHAKE128 and 64
/// bytes of SHAKE256.
#[test]
fn hash_shake_known_answer_vectors() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let shake128_expected = [
        0x58, 0x81, 0x09, 0x2d, 0xd8, 0x18, 0xbf, 0x5c, 0xf8, 0xa3, 0xdd, 0xb7, 0x93, 0xfb, 0xcb,
        0xa7, 0x40, 0x97, 0xd5, 0xc5, 0x26, 0xa6, 0xd3, 0x5f, 0x97, 0xb8, 0x33, 0x51, 0x94, 0x0f,
        0x2c, 0xc8,
    ];
    let shake256_expected = [
        0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77, 0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11,
        0x4d, 0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee, 0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b,
        0x57, 0x39, 0xd5, 0xa1, 0x5b, 0xef, 0x18, 0x6a, 0x53, 0x86, 0xc7, 0x57, 0x44, 0xc0, 0x52,
        0x7e, 0x1f, 0xaa, 0x9f, 0x87, 0x26, 0xe4, 0x62, 0xa1, 0x2a, 0x4f, 0xeb, 0x06, 0xbd, 0x88,
        0x01, 0xe7, 0x51, 0xe4,
    ];

    assert_eq!(
        device_shake(
            &ctx,
            session.session_id,
            HASH_ALGO_SHAKE128,
            32,
            b"abc".to_vec()
        ),
        shake128_expected,
    );
    assert_eq!(
        device_shake(
            &ctx,
            session.session_id,
            HASH_ALGO_SHAKE256,
            64,
            b"abc".to_vec()
        ),
        shake256_expected,
    );
}

/// Rejects a SHAKE request without `out_len`, or with an `out_len` of 0 or
/// above the maximum.
#[test]
fn hash_shake_invalid_out_len_rejected() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    let over_max = u16::try_from(HASH_DIGEST_MAX_LEN + 1).expect("out_len bound fits in u16");
    for algo in SHAKE_ALGOS {
        for out_len in [None, Some(0), Some(over_max), Some(u16::MAX)] {
            ctx.expect_fw_reject(
                &TborHashReq {
                    session_id: session.session_id,
                    algo,
                    out_len,
                    msg: b"abc".to_vec(),
                },
                TborStatus::InvalidArg,
            );
        }
    }
}

/// Rejects `out_len` on the fixed-length digests, even when it equals the
/// digest length.
#[test]
fn hash_fixed_length_algos_reject_out_len() {
    let ctx = TestCtx::new();
    let session = finalized_co_session(&ctx);

    for algo in HASH_ALGOS {
        let digest_len = u16::try_from(digest_len(algo)).expect("digest length fits in u16");
        for out_len in [1, digest_len] {
            ctx.expect_fw_reject(
                &TborHashReq {
                    session_id: session.session_id,
                    algo,
                    out_len: Some(out_len),
                    msg: b"abc".to_vec(),
                },
                TborStatus::InvalidArg,
            );
        }
    }
}
