// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SHA3-256/384/512 (FIPS 202): known-answer tests over 1 KiB inputs and the
//! NIST CAVP SHA3VS byte-oriented ShortMsg, LongMsg and Monte Carlo vectors,
//! each run one-shot and streaming, and rejection by HMAC and RSA signing.

use super::*;
use crate::testvectors::hash::SHA3_256_LONG_MSG_TEST_VECTORS;
use crate::testvectors::hash::SHA3_256_MONTE_TEST_VECTORS;
use crate::testvectors::hash::SHA3_256_SHORT_MSG_TEST_VECTORS;
use crate::testvectors::hash::SHA3_384_LONG_MSG_TEST_VECTORS;
use crate::testvectors::hash::SHA3_384_MONTE_TEST_VECTORS;
use crate::testvectors::hash::SHA3_384_SHORT_MSG_TEST_VECTORS;
use crate::testvectors::hash::SHA3_512_LONG_MSG_TEST_VECTORS;
use crate::testvectors::hash::SHA3_512_MONTE_TEST_VECTORS;
use crate::testvectors::hash::SHA3_512_SHORT_MSG_TEST_VECTORS;
use crate::testvectors::hash::ShaMonteTestVector;
use crate::testvectors::hash::ShaTestVector;

/// 1024 bytes of 0x11223344 words in big- or little-endian byte order, as the
/// SHA-2 tests use.
fn words(big_endian: bool) -> Vec<u8> {
    let word = if big_endian {
        0x11223344u32.to_be_bytes()
    } else {
        0x11223344u32.to_le_bytes()
    };
    word.repeat(1024 / 4)
}

/// Hash `data` one-shot and streaming (split at byte 700) and compare both to
/// `expected_hex`.
fn sha3_kat(algo: fn() -> HashAlgo, data: &[u8], expected_hex: &str) {
    let expected = hex::decode(expected_hex).expect("expected digest hex");

    let mut actual = vec![0u8; expected.len()];
    let written = Hasher::hash(&mut algo(), data, Some(&mut actual)).expect("one-shot hash");
    assert_eq!(written, expected.len());
    assert_eq!(actual, expected, "one-shot");

    let mut ctx = Hasher::hash_init(algo()).expect("hash init");
    ctx.update(&data[..700]).expect("update part 1");
    ctx.update(&data[700..]).expect("update part 2");
    actual.fill(0);
    let written = ctx.finish(Some(&mut actual)).expect("finish");
    assert_eq!(written, expected.len());
    assert_eq!(actual, expected, "streaming");
}

fn sha3_vector_one_shot(name: &str, algo: fn() -> HashAlgo, vector: &ShaTestVector) {
    let mut algo = algo();
    let required_len = Hasher::hash(&mut algo, vector.msg, None).expect("size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let mut actual = vec![0u8; required_len];
    let written = Hasher::hash(&mut algo, vector.msg, Some(&mut actual)).expect("one-shot hash");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "{name} NIST (one-shot) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

fn sha3_vector_streaming(name: &str, algo: fn() -> HashAlgo, vector: &ShaTestVector) {
    let required_len = Hasher::hash(&mut algo(), vector.msg, None).expect("size query");
    assert_eq!(required_len, vector.md_len_bytes as usize);

    let mut ctx = Hasher::hash_init(algo()).expect("hash init");

    // Odd chunk sizes so updates straddle the 72-168 byte sponge rates.
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

    let mut actual = vec![0u8; required_len];
    let written = ctx.finish(Some(&mut actual)).expect("finish");
    assert_eq!(written, required_len);

    if vector.md != actual.as_slice() {
        panic!(
            "{name} NIST (streaming) failed!\nMsgLenBytes: {}\nMsg: {:02x?}\nExpected: {:02x?}\nActual: {:02x?}",
            vector.msg_len_bytes, vector.msg, vector.md, actual
        );
    }
}

/// NIST SHA3VS Monte Carlo test (SHA3VS section 6.2.3). Unlike SHA-2's, each
/// message is just the previous digest:
///
/// ```text
/// MD = Seed
/// for j in 0..100 {
///     for i in 1..=1000 { MD = SHA3(MD) }
///     OUTPUT: MD == checkpoint j
/// }
/// ```
///
/// With `streaming`, each hash feeds the digest in two updates.
fn sha3_monte(name: &str, algo: fn() -> HashAlgo, vector: &ShaMonteTestVector, streaming: bool) {
    let digest_len = Hasher::hash(&mut algo(), &[], None).expect("size query");
    assert_eq!(digest_len, vector.expected_digest_len_bytes);
    assert_eq!(vector.seed.len(), digest_len);

    let mut md = vector.seed.to_vec();
    let mut next = vec![0u8; digest_len];
    for (j, expected_digest) in vector.expected_digests.iter().enumerate() {
        assert_eq!(expected_digest.len(), digest_len);
        for _ in 0..1000 {
            let written = if streaming {
                let mut ctx = Hasher::hash_init(algo()).expect("hash init");
                ctx.update(&md[..13]).expect("update part 1");
                ctx.update(&md[13..]).expect("update part 2");
                ctx.finish(Some(&mut next)).expect("finish")
            } else {
                Hasher::hash(&mut algo(), &md, Some(&mut next)).expect("one-shot hash")
            };
            assert_eq!(written, digest_len);
            std::mem::swap(&mut md, &mut next);
        }

        if md.as_slice() != *expected_digest {
            panic!(
                "{name} NIST Monte Carlo ({}) failed!\nOuterIter(j): {}\nExpected: {:02x?}\nActual:   {:02x?}",
                if streaming { "streaming" } else { "one-shot" },
                j,
                expected_digest,
                md
            );
        }
    }
}

#[test]
fn test_sha3_256_hash() {
    sha3_kat(
        HashAlgo::sha3_256,
        &[1u8; 1024],
        "fda1cceb7c89acd0e11874c278ce914f6287f313d427056bbcc40d6ae3a9e0e9",
    );
}

#[test]
fn test_sha3_256_hash_big_endian_data() {
    sha3_kat(
        HashAlgo::sha3_256,
        &words(true),
        "b15493450a58af6f5648e2f95cbae1d483d0d9fb932a31344281fe5ee74587de",
    );
}

#[test]
fn test_sha3_256_hash_little_endian_data() {
    sha3_kat(
        HashAlgo::sha3_256,
        &words(false),
        "c87522083778c620b491337dfabf5fe74bbde3466d879fb1c133f126f083bb4a",
    );
}

#[test]
fn test_sha3_384_hash() {
    sha3_kat(
        HashAlgo::sha3_384,
        &[1u8; 1024],
        "488b5c8070f07ee406de4f59132bb672772008493f8e2110105850b200bd5e037c45055b7be441ee6a8237a7fd067715",
    );
}

#[test]
fn test_sha3_384_hash_big_endian_data() {
    sha3_kat(
        HashAlgo::sha3_384,
        &words(true),
        "eb54fe6d27353d015f933a41a0e08b057f8b7559f9fbae2c6d7dbe8397aef669d4cee1a14d8956d3bc4b8bee3b11f44f",
    );
}

#[test]
fn test_sha3_384_hash_little_endian_data() {
    sha3_kat(
        HashAlgo::sha3_384,
        &words(false),
        "bc53ca4e53b1fb3f2bd6298776fb66ea3a90896b620ffea03b65223ef79ce907bd530b7a183c5e54b538763b2122e260",
    );
}

#[test]
fn test_sha3_512_hash() {
    sha3_kat(
        HashAlgo::sha3_512,
        &[1u8; 1024],
        "0c61ca029c4c4218a1ec87f7a5e7894531e44aa70c66d26a22a35922160be9cc298cb2fd7d478ff2239773bfb7f2f418e43d6084d872b7c22be0614f0f028d9e",
    );
}

#[test]
fn test_sha3_512_hash_big_endian_data() {
    sha3_kat(
        HashAlgo::sha3_512,
        &words(true),
        "a263efa429290983c2fdae62759d5e15d07dc54fa4b628c232f858d27d195be8e23e6571981c3085f7c129ed0cf0cf1b86efbeeb63a8f6c0223b680d7a49c15e",
    );
}

#[test]
fn test_sha3_512_hash_little_endian_data() {
    sha3_kat(
        HashAlgo::sha3_512,
        &words(false),
        "02e9c1c058cbf8f8c27c804c397f91e4bc7f57a7c9cf4e1f5e34422c35f8e6de92af9f2fbf05eda9f4df77108b154e94439ed27c65d30dcd2014669a62823814",
    );
}

#[test]
fn test_sha3_256_nist_short_msg_vectors_one_shot() {
    for vector in SHA3_256_SHORT_MSG_TEST_VECTORS {
        sha3_vector_one_shot("SHA3-256", HashAlgo::sha3_256, vector);
    }
}

#[test]
fn test_sha3_256_nist_short_msg_vectors_streaming() {
    for vector in SHA3_256_SHORT_MSG_TEST_VECTORS {
        sha3_vector_streaming("SHA3-256", HashAlgo::sha3_256, vector);
    }
}

#[test]
fn test_sha3_256_nist_long_msg_vectors_one_shot() {
    for vector in SHA3_256_LONG_MSG_TEST_VECTORS {
        sha3_vector_one_shot("SHA3-256", HashAlgo::sha3_256, vector);
    }
}

#[test]
fn test_sha3_256_nist_long_msg_vectors_streaming() {
    for vector in SHA3_256_LONG_MSG_TEST_VECTORS {
        sha3_vector_streaming("SHA3-256", HashAlgo::sha3_256, vector);
    }
}

#[test]
fn test_sha3_256_nist_monte_vectors_one_shot() {
    for vector in SHA3_256_MONTE_TEST_VECTORS {
        sha3_monte("SHA3-256", HashAlgo::sha3_256, vector, false);
    }
}

#[test]
fn test_sha3_256_nist_monte_vectors_streaming() {
    for vector in SHA3_256_MONTE_TEST_VECTORS {
        sha3_monte("SHA3-256", HashAlgo::sha3_256, vector, true);
    }
}

#[test]
fn test_sha3_384_nist_short_msg_vectors_one_shot() {
    for vector in SHA3_384_SHORT_MSG_TEST_VECTORS {
        sha3_vector_one_shot("SHA3-384", HashAlgo::sha3_384, vector);
    }
}

#[test]
fn test_sha3_384_nist_short_msg_vectors_streaming() {
    for vector in SHA3_384_SHORT_MSG_TEST_VECTORS {
        sha3_vector_streaming("SHA3-384", HashAlgo::sha3_384, vector);
    }
}

#[test]
fn test_sha3_384_nist_long_msg_vectors_one_shot() {
    for vector in SHA3_384_LONG_MSG_TEST_VECTORS {
        sha3_vector_one_shot("SHA3-384", HashAlgo::sha3_384, vector);
    }
}

#[test]
fn test_sha3_384_nist_long_msg_vectors_streaming() {
    for vector in SHA3_384_LONG_MSG_TEST_VECTORS {
        sha3_vector_streaming("SHA3-384", HashAlgo::sha3_384, vector);
    }
}

#[test]
fn test_sha3_384_nist_monte_vectors_one_shot() {
    for vector in SHA3_384_MONTE_TEST_VECTORS {
        sha3_monte("SHA3-384", HashAlgo::sha3_384, vector, false);
    }
}

#[test]
fn test_sha3_384_nist_monte_vectors_streaming() {
    for vector in SHA3_384_MONTE_TEST_VECTORS {
        sha3_monte("SHA3-384", HashAlgo::sha3_384, vector, true);
    }
}

#[test]
fn test_sha3_512_nist_short_msg_vectors_one_shot() {
    for vector in SHA3_512_SHORT_MSG_TEST_VECTORS {
        sha3_vector_one_shot("SHA3-512", HashAlgo::sha3_512, vector);
    }
}

#[test]
fn test_sha3_512_nist_short_msg_vectors_streaming() {
    for vector in SHA3_512_SHORT_MSG_TEST_VECTORS {
        sha3_vector_streaming("SHA3-512", HashAlgo::sha3_512, vector);
    }
}

#[test]
fn test_sha3_512_nist_long_msg_vectors_one_shot() {
    for vector in SHA3_512_LONG_MSG_TEST_VECTORS {
        sha3_vector_one_shot("SHA3-512", HashAlgo::sha3_512, vector);
    }
}

#[test]
fn test_sha3_512_nist_long_msg_vectors_streaming() {
    for vector in SHA3_512_LONG_MSG_TEST_VECTORS {
        sha3_vector_streaming("SHA3-512", HashAlgo::sha3_512, vector);
    }
}

#[test]
fn test_sha3_512_nist_monte_vectors_one_shot() {
    for vector in SHA3_512_MONTE_TEST_VECTORS {
        sha3_monte("SHA3-512", HashAlgo::sha3_512, vector, false);
    }
}

#[test]
fn test_sha3_512_nist_monte_vectors_streaming() {
    for vector in SHA3_512_MONTE_TEST_VECTORS {
        sha3_monte("SHA3-512", HashAlgo::sha3_512, vector, true);
    }
}

// PKCS #11 defines HMAC and RSA signing over SHA-1 and SHA-2 only, so both
// reject SHA-3 (KBKDF, which runs over HMAC, does too).

const UNSUPPORTED: Option<CryptoError> = Some(CryptoError::HashUnsupportedAlgorithm);

fn sha3s() -> [HashAlgo; 3] {
    [
        HashAlgo::sha3_256(),
        HashAlgo::sha3_384(),
        HashAlgo::sha3_512(),
    ]
}

#[test]
fn test_sha3_rejected_by_hmac() {
    let key = HmacKey::from_bytes(&[0x0b; 32]).expect("hmac key");
    let mac = [0u8; 64];
    for sha3 in sha3s() {
        let mut out = [0u8; 64];
        let mut hmac = HmacAlgo::new(sha3.clone());
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
            Signer::sign_init(HmacAlgo::new(sha3.clone()), key.clone()).err(),
            UNSUPPORTED
        );
        assert_eq!(
            Verifier::verify_init(HmacAlgo::new(sha3), key.clone()).err(),
            UNSUPPORTED
        );
    }
}

#[test]
fn test_sha3_rejected_by_kbkdf() {
    let key = GenericSecretKey::from_bytes(&[0x0b; 32]).expect("key");
    for sha3 in sha3s() {
        let kbkdf = KbkdfAlgo::with_len(sha3, Some(b"label".to_vec()), None);
        assert_eq!(kbkdf.derive(&key, 32).err(), UNSUPPORTED);
    }
}

#[test]
fn test_sha3_rejected_by_rsa_signing() {
    let private_key = RsaPrivateKey::generate(2048 / 8).expect("rsa key");
    let public_key = private_key.public_key().expect("rsa public key");
    let signature = [0u8; 2048 / 8];
    for sha3 in sha3s() {
        let digest = vec![0u8; sha3.size()];

        for mut algo in [
            RsaSignAlgo::with_pss_padding(sha3.clone(), 32),
            RsaSignAlgo::with_pkcs1_padding(sha3.clone()),
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

        let pss = || RsaHashSignAlgo::with_pss_padding(sha3.clone(), 32);
        let pkcs1 = || RsaHashSignAlgo::with_pkcs1_padding(sha3.clone());
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

        let mut encoder = RsaPadPkcs1SignAlgo::new(signature.len(), sha3.clone(), &digest);
        assert_eq!(Encoder::encode(&mut encoder, None).err(), UNSUPPORTED);
        let mut encoder = RsaPadPssAlgo::with_mgf1(signature.len(), sha3.clone(), &digest, 32);
        assert_eq!(Encoder::encode_vec(&mut encoder).err(), UNSUPPORTED);
        let params = RsaPadPssAlgoParams::new(signature.len(), sha3, &digest);
        assert_eq!(
            Decoder::decode::<RsaPadPssAlgo>(&signature, params).err(),
            UNSUPPORTED
        );
    }
}
