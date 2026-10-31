// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-CTR tests using NIST SP 800-38A F.5 test vectors plus
//! counter-update, chaining and error-path checks.

use super::*;

const STREAMING_CHUNK_LENS: [usize; 6] = [1, 3, 7, 11, 2, 19];

const SP800_38A_PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                            30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const SP800_38A_CTR: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

/// (key, ciphertext) from SP 800-38A F.5.1/F.5.3/F.5.5.
const SP800_38A_CTR_VECTORS: [(&str, &str); 3] = [
    (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff\
         5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee",
    ),
    (
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        "1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e94\
         1e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050",
    ),
    (
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5\
         2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6",
    ),
];

fn ctr_one_shot(
    key: &AesKey,
    iv: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut algo = AesCtrAlgo::new(iv);
    let output = if encrypt {
        Encrypter::encrypt_vec(&mut algo, key, input)?
    } else {
        Decrypter::decrypt_vec(&mut algo, key, input)?
    };
    Ok((output, algo.iv().to_vec()))
}

fn ctr_streaming(
    key: &AesKey,
    iv: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut output = vec![0u8; input.len()];
    let mut offset = 0usize;
    let mut cursor = 0usize;
    let mut chunks = STREAMING_CHUNK_LENS.iter().copied().cycle();
    let algo = AesCtrAlgo::new(iv);
    let algo = if encrypt {
        let mut ctx = Encrypter::encrypt_init(algo, key.clone())?;
        while cursor < input.len() {
            let end = (cursor + chunks.next().unwrap()).min(input.len());
            offset += ctx.update(&input[cursor..end], Some(&mut output[offset..]))?;
            cursor = end;
        }
        offset += ctx.finish(Some(&mut output[offset..]))?;
        ctx.into_algo()
    } else {
        let mut ctx = Decrypter::decrypt_init(algo, key.clone())?;
        while cursor < input.len() {
            let end = (cursor + chunks.next().unwrap()).min(input.len());
            offset += ctx.update(&input[cursor..end], Some(&mut output[offset..]))?;
            cursor = end;
        }
        offset += ctx.finish(Some(&mut output[offset..]))?;
        ctx.into_algo()
    };
    output.truncate(offset);
    Ok((output, algo.iv().to_vec()))
}

fn ecb_block(key: &AesKey, block: &[u8]) -> Vec<u8> {
    let mut ecb = AesEcbAlgo::default();
    Encrypter::encrypt_vec(&mut ecb, key, block).unwrap()
}

#[test]
fn test_aes_ctr_sp800_38a_one_shot() {
    let pt = hex::decode(SP800_38A_PT).unwrap();
    let iv = hex::decode(SP800_38A_CTR).unwrap();
    let iv_out = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03").unwrap();
    for (key, ct) in SP800_38A_CTR_VECTORS {
        let key = AesKey::from_bytes(&hex::decode(key).unwrap()).unwrap();
        let ct = hex::decode(ct).unwrap();

        let (out, next_iv) = ctr_one_shot(&key, &iv, &pt, true).unwrap();
        assert_eq!(out, ct);
        assert_eq!(next_iv, iv_out);

        let (out, next_iv) = ctr_one_shot(&key, &iv, &ct, false).unwrap();
        assert_eq!(out, pt);
        assert_eq!(next_iv, iv_out);
    }
}

#[test]
fn test_aes_ctr_sp800_38a_streaming() {
    let pt = hex::decode(SP800_38A_PT).unwrap();
    let iv = hex::decode(SP800_38A_CTR).unwrap();
    let iv_out = hex::decode("f0f1f2f3f4f5f6f7f8f9fafbfcfdff03").unwrap();
    for (key, ct) in SP800_38A_CTR_VECTORS {
        let key = AesKey::from_bytes(&hex::decode(key).unwrap()).unwrap();
        let ct = hex::decode(ct).unwrap();

        let (out, next_iv) = ctr_streaming(&key, &iv, &pt, true).unwrap();
        assert_eq!(out, ct);
        assert_eq!(next_iv, iv_out);

        let (out, next_iv) = ctr_streaming(&key, &iv, &ct, false).unwrap();
        assert_eq!(out, pt);
        assert_eq!(next_iv, iv_out);
    }
}

#[test]
fn test_aes_ctr_partial_block_counter_rounds_up() {
    let pt = hex::decode(SP800_38A_PT).unwrap();
    let iv = hex::decode(SP800_38A_CTR).unwrap();
    let (key, ct) = SP800_38A_CTR_VECTORS[0];
    let key = AesKey::from_bytes(&hex::decode(key).unwrap()).unwrap();
    let ct = hex::decode(ct).unwrap();

    for (len, iv_out) in [
        (0, "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        (1, "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00"),
        (16, "f0f1f2f3f4f5f6f7f8f9fafbfcfdff00"),
        (20, "f0f1f2f3f4f5f6f7f8f9fafbfcfdff01"),
        (63, "f0f1f2f3f4f5f6f7f8f9fafbfcfdff03"),
    ] {
        let iv_out = hex::decode(iv_out).unwrap();
        let (out, next_iv) = ctr_one_shot(&key, &iv, &pt[..len], true).unwrap();
        assert_eq!(out, &ct[..len], "len={len}");
        assert_eq!(next_iv, iv_out, "len={len}");

        let (out, next_iv) = ctr_streaming(&key, &iv, &pt[..len], true).unwrap();
        assert_eq!(out, &ct[..len], "streaming len={len}");
        assert_eq!(next_iv, iv_out, "streaming len={len}");
    }
}

#[test]
fn test_aes_ctr_chaining_across_calls() {
    let pt = hex::decode(SP800_38A_PT).unwrap();
    let iv = hex::decode(SP800_38A_CTR).unwrap();
    let (key, ct) = SP800_38A_CTR_VECTORS[1];
    let key = AesKey::from_bytes(&hex::decode(key).unwrap()).unwrap();
    let ct = hex::decode(ct).unwrap();

    let (first, next_iv) = ctr_one_shot(&key, &iv, &pt[..32], true).unwrap();
    let (second, _) = ctr_one_shot(&key, &next_iv, &pt[32..], true).unwrap();
    assert_eq!([first, second].concat(), ct);
}

#[test]
fn test_aes_ctr_counter_wraps_128_bits() {
    let key = AesKey::from_bytes(&hex::decode(SP800_38A_CTR_VECTORS[2].0).unwrap()).unwrap();
    let iv = [0xffu8; 16];
    let pt = [0x5au8; 40];

    let keystream = [
        ecb_block(&key, &[0xff; 16]),
        ecb_block(&key, &[0x00; 16]),
        ecb_block(&key, &{
            let mut b = [0u8; 16];
            b[15] = 1;
            b
        }),
    ]
    .concat();
    let expected: Vec<u8> = pt.iter().zip(&keystream).map(|(p, k)| p ^ k).collect();

    let mut iv_out = [0u8; 16];
    iv_out[15] = 2;

    let (out, next_iv) = ctr_one_shot(&key, &iv, &pt, true).unwrap();
    assert_eq!(out, expected);
    assert_eq!(next_iv, iv_out);

    let (out, next_iv) = ctr_streaming(&key, &iv, &pt, true).unwrap();
    assert_eq!(out, expected);
    assert_eq!(next_iv, iv_out);
}

#[test]
fn test_aes_ctr_invalid_iv_size() {
    let key = AesKey::from_bytes(&hex::decode(SP800_38A_CTR_VECTORS[0].0).unwrap()).unwrap();
    for iv_len in [0usize, 12, 15, 17] {
        let iv = vec![0u8; iv_len];
        let err = ctr_one_shot(&key, &iv, &[0u8; 16], true).unwrap_err();
        assert!(
            matches!(err, CryptoError::AesInvalidIVSize),
            "iv_len={iv_len}"
        );
        assert!(Encrypter::encrypt_init(AesCtrAlgo::new(&iv), key.clone()).is_err());
    }
}

#[test]
fn test_aes_ctr_output_too_small() {
    let key = AesKey::from_bytes(&hex::decode(SP800_38A_CTR_VECTORS[0].0).unwrap()).unwrap();
    let iv = hex::decode(SP800_38A_CTR).unwrap();
    let mut algo = AesCtrAlgo::new(&iv);
    let mut out = [0u8; 15];
    let err = Encrypter::encrypt(&mut algo, &key, &[0u8; 16], Some(&mut out)).unwrap_err();
    assert!(matches!(err, CryptoError::AesBufferTooSmall));

    let mut ctx = Encrypter::encrypt_init(AesCtrAlgo::new(&iv), key).unwrap();
    let err = ctx.update(&[0u8; 16], Some(&mut out)).unwrap_err();
    assert!(matches!(err, CryptoError::AesBufferTooSmall));
}
