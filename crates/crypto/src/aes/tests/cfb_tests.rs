// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-CFB128 partial-length, IV-out, chaining and error-path tests using the
//! NIST SP 800-38A F.3.13 AES-128 vector.

use super::*;

const STREAMING_CHUNK_LENS: [usize; 6] = [1, 3, 7, 11, 2, 19];

const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const IV: &str = "000102030405060708090a0b0c0d0e0f";
const PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                  30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const CT: &str = "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b\
                  26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6";

const LENS: [usize; 8] = [0, 1, 15, 16, 17, 20, 32, 63];

fn cfb_one_shot(
    key: &AesKey,
    iv: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut algo = AesCfbAlgo::new(iv);
    let output = if encrypt {
        Encrypter::encrypt_vec(&mut algo, key, input)?
    } else {
        Decrypter::decrypt_vec(&mut algo, key, input)?
    };
    Ok((output, algo.iv().to_vec()))
}

fn cfb_streaming(
    key: &AesKey,
    iv: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut output = vec![0u8; input.len()];
    let mut offset = 0usize;
    let mut cursor = 0usize;
    let mut chunks = STREAMING_CHUNK_LENS.iter().copied().cycle();
    let algo = AesCfbAlgo::new(iv);
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

/// CFB IV-out is the last complete ciphertext block, or the input IV if none.
fn expected_iv_out(iv: &[u8], _pt: &[u8], ct: &[u8], len: usize) -> Vec<u8> {
    let blocks = len / 16;
    if blocks == 0 {
        iv.to_vec()
    } else {
        ct[(blocks - 1) * 16..blocks * 16].to_vec()
    }
}

fn check_lengths(run: fn(&AesKey, &[u8], &[u8], bool) -> Result<(Vec<u8>, Vec<u8>), CryptoError>) {
    let key = AesKey::from_bytes(&hex::decode(KEY).unwrap()).unwrap();
    let iv = hex::decode(IV).unwrap();
    let pt = hex::decode(PT).unwrap();
    let ct = hex::decode(CT).unwrap();

    for len in LENS {
        let expected_iv = expected_iv_out(&iv, &pt, &ct, len);

        let (out, next_iv) = run(&key, &iv, &pt[..len], true).unwrap();
        assert_eq!(out, &ct[..len], "encrypt len={len}");
        assert_eq!(next_iv, expected_iv, "encrypt iv len={len}");

        let (out, next_iv) = run(&key, &iv, &ct[..len], false).unwrap();
        assert_eq!(out, &pt[..len], "decrypt len={len}");
        assert_eq!(next_iv, expected_iv, "decrypt iv len={len}");
    }
}

#[test]
fn test_aes_cfb_partial_lengths_and_iv_out_one_shot() {
    check_lengths(cfb_one_shot);
}

#[test]
fn test_aes_cfb_partial_lengths_and_iv_out_streaming() {
    check_lengths(cfb_streaming);
}

#[test]
fn test_aes_cfb_chaining_across_calls() {
    let key = AesKey::from_bytes(&hex::decode(KEY).unwrap()).unwrap();
    let iv = hex::decode(IV).unwrap();
    let pt = hex::decode(PT).unwrap();
    let ct = hex::decode(CT).unwrap();

    let (first, next_iv) = cfb_one_shot(&key, &iv, &pt[..32], true).unwrap();
    let (second, _) = cfb_streaming(&key, &next_iv, &pt[32..], true).unwrap();
    assert_eq!([first, second].concat(), ct);

    let (first, next_iv) = cfb_streaming(&key, &iv, &ct[..16], false).unwrap();
    let (second, _) = cfb_one_shot(&key, &next_iv, &ct[16..], false).unwrap();
    assert_eq!([first, second].concat(), pt);
}

#[test]
fn test_aes_cfb_invalid_iv_size() {
    let key = AesKey::from_bytes(&hex::decode(KEY).unwrap()).unwrap();
    for iv_len in [0usize, 12, 15, 17] {
        let iv = vec![0u8; iv_len];
        let err = cfb_one_shot(&key, &iv, &[0u8; 16], true).unwrap_err();
        assert!(
            matches!(err, CryptoError::AesInvalidIVSize),
            "iv_len={iv_len}"
        );
        let err = cfb_one_shot(&key, &iv, &[0u8; 16], false).unwrap_err();
        assert!(
            matches!(err, CryptoError::AesInvalidIVSize),
            "iv_len={iv_len}"
        );
        assert!(Encrypter::encrypt_init(AesCfbAlgo::new(&iv), key.clone()).is_err());
        assert!(Decrypter::decrypt_init(AesCfbAlgo::new(&iv), key.clone()).is_err());
    }
}

#[test]
fn test_aes_cfb_output_too_small() {
    let key = AesKey::from_bytes(&hex::decode(KEY).unwrap()).unwrap();
    let iv = hex::decode(IV).unwrap();
    let mut out = [0u8; 15];

    let mut algo = AesCfbAlgo::new(&iv);
    let err = Encrypter::encrypt(&mut algo, &key, &[0u8; 16], Some(&mut out)).unwrap_err();
    assert!(matches!(err, CryptoError::AesBufferTooSmall));

    let mut ctx = Decrypter::decrypt_init(AesCfbAlgo::new(&iv), key).unwrap();
    let err = ctx.update(&[0u8; 16], Some(&mut out)).unwrap_err();
    assert!(matches!(err, CryptoError::AesBufferTooSmall));
}
