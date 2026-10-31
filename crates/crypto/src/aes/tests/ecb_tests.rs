// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn test_aes128_ecb_encrypt_decrypt() {
    let key = hex::decode("80000000000000000000000000000000").unwrap();
    let pt = hex::decode("00000000000000000000000000000000").unwrap();
    let ct = hex::decode("0EDD33D3C621E546455BD8BA1418BEC8").unwrap();

    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut aes_ecb = AesEcbAlgo::default();

    // Encrypt
    let actual_ct =
        Encrypter::encrypt_vec(&mut aes_ecb, &aes_key, &pt).expect("AES ECB encryption failed");
    assert_eq!(actual_ct, ct);

    // Decrypt
    let actual_pt =
        Decrypter::decrypt_vec(&mut aes_ecb, &aes_key, &ct).expect("AES ECB decryption failed");
    assert_eq!(actual_pt, pt);
}

#[test]
fn test_aes192_ecb_encrypt_decrypt() {
    let key = hex::decode("800000000000000000000000000000000000000000000000").unwrap();
    let pt = hex::decode("00000000000000000000000000000000").unwrap();
    let ct = hex::decode("de885dc87f5a92594082d02cc1e1b42c").unwrap();

    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut aes_ecb = AesEcbAlgo::default();

    // Encrypt
    let actual_ct =
        Encrypter::encrypt_vec(&mut aes_ecb, &aes_key, &pt).expect("AES ECB encryption failed");
    assert_eq!(actual_ct, ct);

    // Decrypt
    let actual_pt =
        Decrypter::decrypt_vec(&mut aes_ecb, &aes_key, &ct).expect("AES ECB decryption failed");
    assert_eq!(actual_pt, pt);
}

#[test]
fn test_aes256_ecb_encrypt_decrypt() {
    let key =
        hex::decode("8000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let pt = hex::decode("00000000000000000000000000000000").unwrap();
    let ct = hex::decode("e35a6dcb19b201a01ebcfa8aa22b5759").unwrap();

    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut aes_ecb = AesEcbAlgo::default();

    // Encrypt
    let actual_ct =
        Encrypter::encrypt_vec(&mut aes_ecb, &aes_key, &pt).expect("AES ECB encryption failed");
    assert_eq!(actual_ct, ct);

    // Decrypt
    let actual_pt =
        Decrypter::decrypt_vec(&mut aes_ecb, &aes_key, &ct).expect("AES ECB decryption failed");
    assert_eq!(actual_pt, pt);
}

const SP800_38A_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const SP800_38A_PT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                            30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
const SP800_38A_ECB_CT: &str = "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf\
                                43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4";

/// Streams `input` in the given chunk sizes into an output buffer of exactly
/// `input.len()` bytes.
fn ecb_streaming(
    key: &AesKey,
    input: &[u8],
    chunk_lens: &[usize],
    encrypt: bool,
) -> Result<Vec<u8>, CryptoError> {
    let mut output = vec![0u8; input.len()];
    let mut offset = 0usize;
    let mut cursor = 0usize;
    let mut chunks = chunk_lens.iter().copied().cycle();
    if encrypt {
        let mut ctx = Encrypter::encrypt_init(AesEcbAlgo::default(), key.clone())?;
        while cursor < input.len() {
            let end = (cursor + chunks.next().unwrap()).min(input.len());
            offset += ctx.update(&input[cursor..end], Some(&mut output[offset..]))?;
            cursor = end;
        }
        offset += ctx.finish(Some(&mut output[offset..]))?;
    } else {
        let mut ctx = Decrypter::decrypt_init(AesEcbAlgo::default(), key.clone())?;
        while cursor < input.len() {
            let end = (cursor + chunks.next().unwrap()).min(input.len());
            offset += ctx.update(&input[cursor..end], Some(&mut output[offset..]))?;
            cursor = end;
        }
        offset += ctx.finish(Some(&mut output[offset..]))?;
    }
    output.truncate(offset);
    Ok(output)
}

#[test]
fn test_aes_ecb_streaming_sp800_38a() {
    let key = AesKey::from_bytes(&hex::decode(SP800_38A_KEY).unwrap()).unwrap();
    let pt = hex::decode(SP800_38A_PT).unwrap();
    let ct = hex::decode(SP800_38A_ECB_CT).unwrap();

    for chunk_lens in [
        &[1usize, 3, 7, 11, 2, 19][..],
        &[16],
        &[32],
        &[64],
        &[5, 27],
    ] {
        assert_eq!(
            ecb_streaming(&key, &pt, chunk_lens, true).unwrap(),
            ct,
            "chunks={chunk_lens:?}"
        );
        assert_eq!(
            ecb_streaming(&key, &ct, chunk_lens, false).unwrap(),
            pt,
            "chunks={chunk_lens:?}"
        );
    }
}

#[test]
fn test_aes_ecb_streaming_empty_input() {
    let key = AesKey::from_bytes(&hex::decode(SP800_38A_KEY).unwrap()).unwrap();
    assert!(ecb_streaming(&key, &[], &[1], true).unwrap().is_empty());
    assert!(ecb_streaming(&key, &[], &[1], false).unwrap().is_empty());
}

#[test]
fn test_aes_ecb_streaming_unaligned_input() {
    let key = AesKey::from_bytes(&hex::decode(SP800_38A_KEY).unwrap()).unwrap();
    let pt = hex::decode(SP800_38A_PT).unwrap();
    for len in [1usize, 15, 17, 63] {
        for encrypt in [true, false] {
            let err = ecb_streaming(&key, &pt[..len], &[7], encrypt).unwrap_err();
            assert!(
                matches!(err, CryptoError::AesInvalidInputSize),
                "len={len} encrypt={encrypt} err={err:?}"
            );
        }
    }
}

#[test]
fn test_aes_ecb_streaming_output_too_small() {
    let key = AesKey::from_bytes(&hex::decode(SP800_38A_KEY).unwrap()).unwrap();
    let pt = hex::decode(SP800_38A_PT).unwrap();
    let mut out = [0u8; 15];

    let mut ctx = Encrypter::encrypt_init(AesEcbAlgo::default(), key.clone()).unwrap();
    let err = ctx.update(&pt[..32], Some(&mut out)).unwrap_err();
    assert!(matches!(err, CryptoError::AesBufferTooSmall));

    let mut ctx = Decrypter::decrypt_init(AesEcbAlgo::default(), key).unwrap();
    assert_eq!(ctx.update(&pt[..16], Some(&mut out)).unwrap(), 0);
    let err = ctx.finish(Some(&mut out)).unwrap_err();
    assert!(matches!(err, CryptoError::AesBufferTooSmall));
}
