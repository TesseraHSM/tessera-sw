// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SHAKE128/256 (FIPS 202): known-answer tests, output-length behavior, the
//! NIST CAVP SHA3VS byte-oriented ShortMsg, LongMsg, VariableOut and Monte
//! Carlo vectors (each run one-shot and streaming), and rejection by every
//! API that needs a fixed-length hash.

use std::num::NonZeroUsize;

use super::*;
use crate::testvectors::hash::SHAKE128_LONG_MSG_TEST_VECTORS;
use crate::testvectors::hash::SHAKE128_MONTE_TEST_VECTORS;
use crate::testvectors::hash::SHAKE128_SHORT_MSG_TEST_VECTORS;
use crate::testvectors::hash::SHAKE128_VARIABLE_OUT_TEST_VECTORS;
use crate::testvectors::hash::SHAKE256_LONG_MSG_TEST_VECTORS;
use crate::testvectors::hash::SHAKE256_MONTE_TEST_VECTORS;
use crate::testvectors::hash::SHAKE256_SHORT_MSG_TEST_VECTORS;
use crate::testvectors::hash::SHAKE256_VARIABLE_OUT_TEST_VECTORS;
use crate::testvectors::hash::ShaTestVector;
use crate::testvectors::hash::ShakeMonteTestVector;

/// `HashAlgo::shake128` or `HashAlgo::shake256`.
type Shake = fn(NonZeroUsize) -> HashAlgo;

const SHAKES: [(&str, Shake); 2] = [
    ("SHAKE128", HashAlgo::shake128),
    ("SHAKE256", HashAlgo::shake256),
];

fn len(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).expect("non-zero output length")
}

/// 1024 bytes of 0x11223344 words in big- or little-endian byte order, as the
/// SHA-2 and SHA-3 tests use.
fn words(big_endian: bool) -> Vec<u8> {
    let word = if big_endian {
        0x11223344u32.to_be_bytes()
    } else {
        0x11223344u32.to_le_bytes()
    };
    word.repeat(1024 / 4)
}

/// Hash `data` one-shot and streaming (split at byte 700) into
/// `expected_hex.len() / 2` bytes and compare both to `expected_hex`.
fn shake_kat(shake: Shake, data: &[u8], expected_hex: &str) {
    let expected = hex::decode(expected_hex).expect("expected output hex");
    let out_len = len(expected.len());

    let mut actual = vec![0u8; expected.len()];
    let written =
        Hasher::hash(&mut shake(out_len), data, Some(&mut actual)).expect("one-shot hash");
    assert_eq!(written, expected.len());
    assert_eq!(actual, expected, "one-shot");

    let mut ctx = Hasher::hash_init(shake(out_len)).expect("hash init");
    ctx.update(&data[..700]).expect("update part 1");
    ctx.update(&data[700..]).expect("update part 2");
    actual.fill(0);
    let written = ctx.finish(Some(&mut actual)).expect("finish");
    assert_eq!(written, expected.len());
    assert_eq!(actual, expected, "streaming");
}

fn shake_vector_one_shot(name: &str, shake: Shake, vector: &ShaTestVector) {
    let out_len = vector.md_len_bytes as usize;
    let mut algo = shake(len(out_len));
    let required_len = Hasher::hash(&mut algo, vector.msg, None).expect("size query");
    assert_eq!(required_len, out_len);

    let mut actual = vec![0u8; out_len];
    let written = Hasher::hash(&mut algo, vector.msg, Some(&mut actual)).expect("one-shot hash");
    assert_eq!(written, out_len);

    if vector.md != actual.as_slice() {
        panic!(
            "{name} NIST (one-shot) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

fn shake_vector_streaming(name: &str, shake: Shake, vector: &ShaTestVector) {
    let out_len = vector.md_len_bytes as usize;
    let mut ctx = Hasher::hash_init(shake(len(out_len))).expect("hash init");

    // Odd chunk sizes so updates straddle the 136- and 168-byte sponge rates.
    let chunk_sizes = [1usize, 7, 5, 12, 2, 19, 60, 132];
    let mut cursor = 0usize;
    let mut chunk_index = 0usize;
    while cursor < vector.msg.len() {
        let chunk_len = chunk_sizes[chunk_index % chunk_sizes.len()];
        chunk_index += 1;
        let end = (cursor + chunk_len).min(vector.msg.len());
        ctx.update(&vector.msg[cursor..end]).expect("update");
        cursor = end;
    }

    let mut actual = vec![0u8; out_len];
    let written = ctx.finish(Some(&mut actual)).expect("finish");
    assert_eq!(written, out_len);

    if vector.md != actual.as_slice() {
        panic!(
            "{name} NIST (streaming) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

/// NIST SHA3VS SHAKE Monte Carlo test (SHA3VS section 6.3.3), byte-oriented.
/// Each message is the previous output's leftmost 16 bytes, and each output's
/// rightmost 16 bits pick the next output length:
///
/// ```text
/// Output = Msg; Len = MaxLen
/// for j in 0..100 {
///     for i in 1..=1000 {
///         Output = SHAKE(leftmost 16 bytes of Output, zero-padded; Len)
///         Len = MinLen + (rightmost 16 bits of Output) mod (MaxLen - MinLen + 1)
///     }
///     OUTPUT: Output == checkpoint j
/// }
/// ```
///
/// With `streaming`, each hash feeds the message in two updates.
fn shake_monte(name: &str, shake: Shake, vector: &ShakeMonteTestVector, streaming: bool) {
    let min = vector.min_output_len_bytes;
    let range = vector.max_output_len_bytes - min + 1;
    let mut output = vector.msg.to_vec();
    let mut out_len = vector.max_output_len_bytes;

    for (j, expected_output) in vector.expected_outputs.iter().enumerate() {
        for _ in 0..1000 {
            let mut msg = [0u8; 16];
            let n = output.len().min(msg.len());
            msg[..n].copy_from_slice(&output[..n]);

            output = vec![0u8; out_len];
            let written = if streaming {
                let mut ctx = Hasher::hash_init(shake(len(out_len))).expect("hash init");
                ctx.update(&msg[..5]).expect("update part 1");
                ctx.update(&msg[5..]).expect("update part 2");
                ctx.finish(Some(&mut output)).expect("finish")
            } else {
                Hasher::hash(&mut shake(len(out_len)), &msg, Some(&mut output))
                    .expect("one-shot hash")
            };
            assert_eq!(written, out_len);

            let rightmost = u16::from_be_bytes([output[out_len - 2], output[out_len - 1]]);
            out_len = min + usize::from(rightmost) % range;
        }

        if output.as_slice() != *expected_output {
            panic!(
                "{name} NIST Monte Carlo ({}) failed!\nOuterIter(j): {}\nExpected: {:02x?}\nActual:   {:02x?}",
                if streaming { "streaming" } else { "one-shot" },
                j,
                expected_output,
                output
            );
        }
    }
}

#[test]
fn test_shake128_hash() {
    shake_kat(
        HashAlgo::shake128,
        &[1u8; 1024],
        "b85a7ddf325131ef4b5c60f197b4c2d821d91fd771b558f64bac42c0e75781d4",
    );
}

#[test]
fn test_shake128_hash_big_endian_data() {
    shake_kat(
        HashAlgo::shake128,
        &words(true),
        "675e283523d424969b0309802f7d968715b3230aba703a2e0fa1d63962e3bad1",
    );
}

#[test]
fn test_shake128_hash_little_endian_data() {
    shake_kat(
        HashAlgo::shake128,
        &words(false),
        "a8cefde38023e0bac2ee4c02068021015696b6e73ee1e844e1e9be24df7ac598",
    );
}

#[test]
fn test_shake256_hash() {
    shake_kat(
        HashAlgo::shake256,
        &[1u8; 1024],
        "bd1f8d748e7969bd280158fac013aaf10231766614bc5b2916c5211b409f641ae8d0a8260d7a55daa86b3866cf30d0bd955e4afa75027ef425c3617d4e704ece",
    );
}

#[test]
fn test_shake256_hash_big_endian_data() {
    shake_kat(
        HashAlgo::shake256,
        &words(true),
        "d568dc4127f4d08971d5a616454f9b095813e1dcdf495a13e3ff5f670f86c038f7f76be821d6102894dcd83d284b9f671dfbb1cd9da940c7a6787d68c0254163",
    );
}

#[test]
fn test_shake256_hash_little_endian_data() {
    shake_kat(
        HashAlgo::shake256,
        &words(false),
        "0be825c7680018342d0294db222215fb0abd98e7a9dbf9d8f40152b0276cca8254ed0abd8594ef57eed50bc29a7898c8d25d02a4e547f45904da8ce0fb969b5e",
    );
}

/// 500 bytes spans several squeezes of both sponges (rates 168 and 136
/// bytes), which the NIST SHAKE128 vectors (at most 140 bytes) never reach.
/// The expected values are SHA-256 digests of the 500-byte outputs.
#[test]
fn test_shake_output_longer_than_rate() {
    let cases = [
        (
            HashAlgo::shake128 as Shake,
            "a76b5f08a7eaa3689496e96d5a97bd0092c8798268f027c1a2c4b1946dff3599",
        ),
        (
            HashAlgo::shake256,
            "62fde18c7de7fcd9aaa7508b82d6c032bc76ba189f636bf1336738e6620c94a7",
        ),
    ];
    for (shake, expected_hex) in cases {
        let mut output = vec![0u8; 500];
        Hasher::hash(&mut shake(len(500)), &[1u8; 1024], Some(&mut output)).expect("one-shot hash");
        let digest = Hasher::hash_vec(&mut HashAlgo::sha256(), &output).expect("sha256");
        assert_eq!(hex::encode(digest), expected_hex, "one-shot");

        let mut ctx = Hasher::hash_init(shake(len(500))).expect("hash init");
        ctx.update(&[1u8; 1024]).expect("update");
        output.fill(0);
        ctx.finish(Some(&mut output)).expect("finish");
        let digest = Hasher::hash_vec(&mut HashAlgo::sha256(), &output).expect("sha256");
        assert_eq!(hex::encode(digest), expected_hex, "streaming");
    }
}

#[test]
fn test_shake_size_is_requested_length() {
    for (name, shake) in SHAKES {
        for n in [1usize, 32, 64, 137, 169, 500] {
            let mut algo = shake(len(n));
            assert_eq!(algo.size(), n, "{name} size()");
            let required = Hasher::hash(&mut algo, b"abc", None).expect("size query");
            assert_eq!(required, n, "{name} one-shot size query");

            let mut ctx = Hasher::hash_init(shake(len(n))).expect("hash init");
            assert_eq!(
                ctx.finish(None).expect("size query"),
                n,
                "{name} finish size query"
            );
        }
    }
}

/// An XOF's output does not depend on the requested length: shorter outputs
/// are prefixes of longer ones.
#[test]
fn test_shake_shorter_output_is_prefix_of_longer() {
    for (name, shake) in SHAKES {
        let mut long = vec![0u8; 500];
        Hasher::hash(&mut shake(len(500)), b"abc", Some(&mut long)).expect("hash");
        for n in [1usize, 31, 136, 168, 499] {
            let mut short = vec![0u8; n];
            Hasher::hash(&mut shake(len(n)), b"abc", Some(&mut short)).expect("hash");
            assert_eq!(short, long[..n], "{name} {n}-byte output");
        }
    }
}

#[test]
fn test_shake_rejects_short_buffer() {
    for (name, shake) in SHAKES {
        let mut out = [0u8; 31];
        assert_eq!(
            Hasher::hash(&mut shake(len(32)), b"abc", Some(&mut out)),
            Err(CryptoError::HashBufferTooSmall),
            "{name} one-shot"
        );

        let mut ctx = Hasher::hash_init(shake(len(32))).expect("hash init");
        ctx.update(b"abc").expect("update");
        assert_eq!(
            ctx.finish(Some(&mut out)),
            Err(CryptoError::HashBufferTooSmall),
            "{name} streaming"
        );
    }
}

/// A larger buffer receives exactly the requested length; the rest is left
/// untouched.
#[test]
fn test_shake_writes_only_requested_length() {
    for (name, shake) in SHAKES {
        let mut expected = [0u8; 32];
        Hasher::hash(&mut shake(len(32)), b"abc", Some(&mut expected)).expect("hash");

        let mut out = [0xa5u8; 48];
        let written =
            Hasher::hash(&mut shake(len(32)), b"abc", Some(&mut out)).expect("one-shot hash");
        assert_eq!(written, 32, "{name} one-shot");
        assert_eq!(out[..32], expected, "{name} one-shot");
        assert!(out[32..].iter().all(|&b| b == 0xa5), "{name} one-shot tail");

        let mut out = [0xa5u8; 48];
        let mut ctx = Hasher::hash_init(shake(len(32))).expect("hash init");
        ctx.update(b"abc").expect("update");
        let written = ctx.finish(Some(&mut out)).expect("finish");
        assert_eq!(written, 32, "{name} streaming");
        assert_eq!(out[..32], expected, "{name} streaming");
        assert!(
            out[32..].iter().all(|&b| b == 0xa5),
            "{name} streaming tail"
        );
    }
}

#[test]
fn test_shake128_nist_short_msg_vectors_one_shot() {
    for vector in SHAKE128_SHORT_MSG_TEST_VECTORS {
        shake_vector_one_shot("SHAKE128", HashAlgo::shake128, vector);
    }
}

#[test]
fn test_shake128_nist_short_msg_vectors_streaming() {
    for vector in SHAKE128_SHORT_MSG_TEST_VECTORS {
        shake_vector_streaming("SHAKE128", HashAlgo::shake128, vector);
    }
}

#[test]
fn test_shake128_nist_long_msg_vectors_one_shot() {
    for vector in SHAKE128_LONG_MSG_TEST_VECTORS {
        shake_vector_one_shot("SHAKE128", HashAlgo::shake128, vector);
    }
}

#[test]
fn test_shake128_nist_long_msg_vectors_streaming() {
    for vector in SHAKE128_LONG_MSG_TEST_VECTORS {
        shake_vector_streaming("SHAKE128", HashAlgo::shake128, vector);
    }
}

#[test]
fn test_shake128_nist_variable_out_vectors_one_shot() {
    for vector in SHAKE128_VARIABLE_OUT_TEST_VECTORS {
        shake_vector_one_shot("SHAKE128", HashAlgo::shake128, vector);
    }
}

#[test]
fn test_shake128_nist_variable_out_vectors_streaming() {
    for vector in SHAKE128_VARIABLE_OUT_TEST_VECTORS {
        shake_vector_streaming("SHAKE128", HashAlgo::shake128, vector);
    }
}

#[test]
fn test_shake128_nist_monte_vectors_one_shot() {
    for vector in SHAKE128_MONTE_TEST_VECTORS {
        shake_monte("SHAKE128", HashAlgo::shake128, vector, false);
    }
}

#[test]
fn test_shake128_nist_monte_vectors_streaming() {
    for vector in SHAKE128_MONTE_TEST_VECTORS {
        shake_monte("SHAKE128", HashAlgo::shake128, vector, true);
    }
}

#[test]
fn test_shake256_nist_short_msg_vectors_one_shot() {
    for vector in SHAKE256_SHORT_MSG_TEST_VECTORS {
        shake_vector_one_shot("SHAKE256", HashAlgo::shake256, vector);
    }
}

#[test]
fn test_shake256_nist_short_msg_vectors_streaming() {
    for vector in SHAKE256_SHORT_MSG_TEST_VECTORS {
        shake_vector_streaming("SHAKE256", HashAlgo::shake256, vector);
    }
}

#[test]
fn test_shake256_nist_long_msg_vectors_one_shot() {
    for vector in SHAKE256_LONG_MSG_TEST_VECTORS {
        shake_vector_one_shot("SHAKE256", HashAlgo::shake256, vector);
    }
}

#[test]
fn test_shake256_nist_long_msg_vectors_streaming() {
    for vector in SHAKE256_LONG_MSG_TEST_VECTORS {
        shake_vector_streaming("SHAKE256", HashAlgo::shake256, vector);
    }
}

#[test]
fn test_shake256_nist_variable_out_vectors_one_shot() {
    for vector in SHAKE256_VARIABLE_OUT_TEST_VECTORS {
        shake_vector_one_shot("SHAKE256", HashAlgo::shake256, vector);
    }
}

#[test]
fn test_shake256_nist_variable_out_vectors_streaming() {
    for vector in SHAKE256_VARIABLE_OUT_TEST_VECTORS {
        shake_vector_streaming("SHAKE256", HashAlgo::shake256, vector);
    }
}

#[test]
fn test_shake256_nist_monte_vectors_one_shot() {
    for vector in SHAKE256_MONTE_TEST_VECTORS {
        shake_monte("SHAKE256", HashAlgo::shake256, vector, false);
    }
}

#[test]
fn test_shake256_nist_monte_vectors_streaming() {
    for vector in SHAKE256_MONTE_TEST_VECTORS {
        shake_monte("SHAKE256", HashAlgo::shake256, vector, true);
    }
}

// SHAKE is supported for hashing only: every API that needs a fixed-length
// hash rejects it, even at the 32/64-byte lengths FIPS 186-5 pairs with
// SHAKE128/256.

const UNSUPPORTED: Option<CryptoError> = Some(CryptoError::HashUnsupportedAlgorithm);

fn fips_length_shakes() -> [HashAlgo; 2] {
    [HashAlgo::shake128(len(32)), HashAlgo::shake256(len(64))]
}

#[test]
fn test_shake_rejected_by_hmac() {
    let key = HmacKey::from_bytes(&[0x0b; 32]).expect("hmac key");
    let mac = [0u8; 64];
    for shake in fips_length_shakes() {
        let mut out = [0u8; 64];
        let mut hmac = HmacAlgo::new(shake.clone());
        assert_eq!(
            Signer::sign(&mut hmac, &key, b"abc", None).err(),
            UNSUPPORTED
        );
        assert_eq!(
            Signer::sign(&mut hmac, &key, b"abc", Some(&mut out)).err(),
            UNSUPPORTED
        );
        assert_eq!(
            Verifier::verify(&mut hmac, &key, b"abc", &mac).err(),
            UNSUPPORTED
        );
        assert_eq!(
            Signer::sign_init(HmacAlgo::new(shake.clone()), key.clone()).err(),
            UNSUPPORTED
        );
        assert_eq!(
            Verifier::verify_init(HmacAlgo::new(shake), key.clone()).err(),
            UNSUPPORTED
        );
    }
}

#[test]
fn test_shake_rejected_by_kdfs() {
    let key = GenericSecretKey::from_bytes(&[0x0b; 32]).expect("key");
    for shake in fips_length_shakes() {
        for mode in [
            HkdfMode::Extract,
            HkdfMode::Expand,
            HkdfMode::ExtractAndExpand,
        ] {
            let hkdf = HkdfAlgo::new(mode, &shake, Some(b"salt"), Some(b"info"));
            assert_eq!(hkdf.derive(&key, shake.size()).err(), UNSUPPORTED);
        }

        let kbkdf = KbkdfAlgo::with_len(shake.clone(), Some(b"label".to_vec()), None);
        assert_eq!(kbkdf.derive(&key, 32).err(), UNSUPPORTED);
        let kbkdf = KbkdfAlgo::without_len(shake.clone(), None, Some(b"context".to_vec()));
        assert_eq!(kbkdf.derive(&key, 32).err(), UNSUPPORTED);

        for mode in [ConcatKdfMode::X963, ConcatKdfMode::Sp800_56a] {
            let concat = ConcatKdfAlgo::new(shake.clone(), mode, Some(b"info".to_vec()));
            assert_eq!(concat.derive(&key, 32).err(), UNSUPPORTED);
        }
    }
}

#[test]
fn test_shake_rejected_by_rsa_encryption() {
    let private_key = RsaPrivateKey::generate(2048 / 8).expect("rsa key");
    let public_key = private_key.public_key().expect("rsa public key");
    let block = [0u8; 2048 / 8];
    for shake in fips_length_shakes() {
        let mut oaep = RsaEncryptAlgo::with_oaep_padding(shake.clone(), None);
        assert_eq!(
            Encrypter::encrypt(&mut oaep, &public_key, b"abc", None).err(),
            UNSUPPORTED
        );
        assert_eq!(
            Decrypter::decrypt(&mut oaep, &private_key, &block, None).err(),
            UNSUPPORTED
        );

        let mut encoder = RsaPadOaepAlgo::with_mgf1(block.len(), shake.clone(), None, b"abc");
        assert_eq!(Encoder::encode_vec(&mut encoder).err(), UNSUPPORTED);
        let params = RsaPadOaepAlgoParams::new(block.len(), shake, None);
        assert_eq!(
            Decoder::decode::<RsaPadOaepAlgo>(&block, params).err(),
            UNSUPPORTED
        );
    }
}

#[test]
fn test_shake_rejected_by_rsa_signing() {
    let private_key = RsaPrivateKey::generate(2048 / 8).expect("rsa key");
    let public_key = private_key.public_key().expect("rsa public key");
    let signature = [0u8; 2048 / 8];
    for shake in fips_length_shakes() {
        let digest = vec![0u8; shake.size()];

        for mut algo in [
            RsaSignAlgo::with_pss_padding(shake.clone(), 32),
            RsaSignAlgo::with_pkcs1_padding(shake.clone()),
        ] {
            assert_eq!(
                Signer::sign(&mut algo, &private_key, &digest, None).err(),
                UNSUPPORTED
            );
            assert_eq!(
                Verifier::verify(&mut algo, &public_key, &digest, &signature).err(),
                UNSUPPORTED
            );
        }

        let pss = || RsaHashSignAlgo::with_pss_padding(shake.clone(), 32);
        let pkcs1 = || RsaHashSignAlgo::with_pkcs1_padding(shake.clone());
        for algo in [pss(), pkcs1()] {
            assert_eq!(
                Signer::sign_init(algo, private_key.clone()).err(),
                UNSUPPORTED
            );
        }
        for algo in [pss(), pkcs1()] {
            assert_eq!(
                Verifier::verify_init(algo, public_key.clone()).err(),
                UNSUPPORTED
            );
        }
        for mut algo in [pss(), pkcs1()] {
            assert_eq!(
                Signer::sign(&mut algo, &private_key, b"abc", None).err(),
                UNSUPPORTED
            );
            assert_eq!(
                Verifier::verify(&mut algo, &public_key, b"abc", &signature).err(),
                UNSUPPORTED
            );
        }

        let mut encoder = RsaPadPssAlgo::with_mgf1(signature.len(), shake.clone(), &digest, 32);
        assert_eq!(Encoder::encode_vec(&mut encoder).err(), UNSUPPORTED);
        let params = RsaPadPssAlgoParams::new(signature.len(), shake, &digest);
        assert_eq!(
            Decoder::decode::<RsaPadPssAlgo>(&signature, params).err(),
            UNSUPPORTED
        );
    }
}

#[test]
fn test_shake_rejected_by_ecdsa() {
    let private_key = EccPrivateKey::from_curve(EccCurve::P256).expect("ecc key");
    let public_key = private_key.public_key().expect("ecc public key");
    let signature = [0u8; 64];
    for shake in fips_length_shakes() {
        assert_eq!(
            Signer::sign(
                &mut EcdsaAlgo::new(shake.clone()),
                &private_key,
                b"abc",
                None
            )
            .err(),
            UNSUPPORTED
        );
        assert_eq!(
            Verifier::verify(
                &mut EcdsaAlgo::new(shake.clone()),
                &public_key,
                b"abc",
                &signature
            )
            .err(),
            UNSUPPORTED
        );
        assert_eq!(
            Signer::sign_init(EcdsaAlgo::new(shake.clone()), private_key.clone()).err(),
            UNSUPPORTED
        );
        assert_eq!(
            Verifier::verify_init(EcdsaAlgo::new(shake), public_key.clone()).err(),
            UNSUPPORTED
        );
    }
}
