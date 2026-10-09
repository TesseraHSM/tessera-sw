// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for ML-DSA key types: generation, import, export and metadata.

use super::*;

/// Generation is a pure function of the seed and parameter set.
#[test]
fn keygen_is_deterministic() {
    for variant in VARIANTS {
        let seed = filler(1, MLDSA_SEED_LEN);
        let a = MlDsaPrivateKey::from_seed(variant, &seed).unwrap();
        let b = MlDsaPrivateKey::from_seed(variant, &seed).unwrap();
        assert_eq!(a.to_vec().unwrap(), b.to_vec().unwrap());
    }
}

/// Different seeds must give different keys; otherwise the seed is not reaching
/// the expansion at all.
#[test]
fn distinct_seeds_give_distinct_keys() {
    for variant in VARIANTS {
        let a = MlDsaPrivateKey::from_seed(variant, &filler(1, MLDSA_SEED_LEN)).unwrap();
        let b = MlDsaPrivateKey::from_seed(variant, &filler(2, MLDSA_SEED_LEN)).unwrap();
        assert_ne!(a.to_vec().unwrap(), b.to_vec().unwrap());
    }
}

/// A seed of the wrong length is rejected rather than padded or truncated.
#[test]
fn keygen_rejects_a_wrong_length_seed() {
    for variant in VARIANTS {
        for len in [0, MLDSA_SEED_LEN - 1, MLDSA_SEED_LEN + 1] {
            assert!(MlDsaPrivateKey::from_seed(variant, &filler(1, len)).is_err());
        }
    }
}

/// Encoded lengths must match FIPS 204 for every parameter set, since the wire
/// format and the masked key blob are sized from them.
#[test]
fn encoded_lengths_match_the_standard() {
    for (variant, pub_len, sec_len, sig_len) in [
        (MlDsaVariant::MlDsa44, 1312, 2560, 2420),
        (MlDsaVariant::MlDsa65, 1952, 4032, 3309),
        (MlDsaVariant::MlDsa87, 2592, 4896, 4627),
    ] {
        assert_eq!(variant.pub_key_len(), pub_len);
        assert_eq!(variant.sec_key_len(), sec_len);
        assert_eq!(variant.sig_len(), sig_len);

        let sk = MlDsaPrivateKey::from_seed(variant, &filler(3, MLDSA_SEED_LEN)).unwrap();
        assert_eq!(sk.size(), sec_len);
        assert_eq!(sk.bits(), sec_len * 8);
        assert_eq!(sk.public_key().unwrap().size(), pub_len);
    }
}

/// Export and re-import must round-trip, and must recover the parameter set
/// from the length alone.
#[test]
fn keys_roundtrip_through_bytes() {
    for variant in VARIANTS {
        let sk = MlDsaPrivateKey::from_seed(variant, &filler(4, MLDSA_SEED_LEN)).unwrap();
        let pk = sk.public_key().unwrap();

        let sk2 = MlDsaPrivateKey::from_bytes(&sk.to_vec().unwrap()).unwrap();
        assert_eq!(sk2.variant(), variant);
        assert_eq!(sk2.to_vec().unwrap(), sk.to_vec().unwrap());

        let pk2 = MlDsaPublicKey::from_bytes(&pk.to_vec().unwrap()).unwrap();
        assert_eq!(pk2.variant(), variant);
        assert_eq!(pk2.to_vec().unwrap(), pk.to_vec().unwrap());
    }
}

/// Deriving the public key from the expanded private key must agree with
/// deriving it during generation.
#[test]
fn public_key_is_recoverable_from_an_imported_private_key() {
    for variant in VARIANTS {
        let sk = MlDsaPrivateKey::from_seed(variant, &filler(5, MLDSA_SEED_LEN)).unwrap();
        let expected = sk.public_key().unwrap().to_vec().unwrap();

        let imported = MlDsaPrivateKey::from_bytes(&sk.to_vec().unwrap()).unwrap();
        assert_eq!(imported.public_key().unwrap().to_vec().unwrap(), expected);
    }
}

/// Import is length-checked, so a truncated or padded key cannot be mistaken
/// for a valid one of another parameter set.
#[test]
fn import_rejects_wrong_lengths() {
    for variant in VARIANTS {
        for delta in [-1i32, 1] {
            let sec_len = (variant.sec_key_len() as i32 + delta) as usize;
            assert!(MlDsaPrivateKey::from_bytes(&filler(6, sec_len)).is_err());
            let pub_len = (variant.pub_key_len() as i32 + delta) as usize;
            assert!(MlDsaPublicKey::from_bytes(&filler(6, pub_len)).is_err());
        }
    }
    assert!(MlDsaPrivateKey::from_bytes(&[]).is_err());
    assert!(MlDsaPublicKey::from_bytes(&[]).is_err());
}

/// `None` queries the required size without writing, per the crate's buffer
/// contract.
#[test]
fn export_reports_the_required_size() {
    for variant in VARIANTS {
        let sk = MlDsaPrivateKey::from_seed(variant, &filler(7, MLDSA_SEED_LEN)).unwrap();
        assert_eq!(sk.to_bytes(None).unwrap(), variant.sec_key_len());

        let mut buf = vec![0u8; variant.sec_key_len()];
        assert_eq!(sk.to_bytes(Some(&mut buf)).unwrap(), variant.sec_key_len());
        assert_eq!(buf, sk.to_vec().unwrap());

        let pk = sk.public_key().unwrap();
        assert_eq!(pk.to_bytes(None).unwrap(), variant.pub_key_len());
    }
}

/// A short export buffer is an error, not a truncated key.
#[test]
fn export_rejects_a_short_buffer() {
    for variant in VARIANTS {
        let sk = MlDsaPrivateKey::from_seed(variant, &filler(8, MLDSA_SEED_LEN)).unwrap();
        let mut buf = vec![0u8; variant.sec_key_len() - 1];
        assert!(matches!(
            sk.to_bytes(Some(&mut buf)),
            Err(CryptoError::MlDsaBufferTooSmall)
        ));
    }
}

/// Length-based variant recovery must be exact, and must reject any length that
/// belongs to no parameter set.
#[test]
fn variant_recovery_is_unambiguous() {
    for variant in VARIANTS {
        assert_eq!(
            MlDsaVariant::from_pub_key_len(variant.pub_key_len()),
            Some(variant)
        );
        assert_eq!(
            MlDsaVariant::from_sec_key_len(variant.sec_key_len()),
            Some(variant)
        );
    }
    assert_eq!(MlDsaVariant::from_pub_key_len(0), None);
    assert_eq!(MlDsaVariant::from_sec_key_len(1), None);

    // The two length families must not overlap, or an expanded key could be
    // imported as a public key.
    for variant in VARIANTS {
        assert_eq!(MlDsaVariant::from_pub_key_len(variant.sec_key_len()), None);
        assert_eq!(MlDsaVariant::from_sec_key_len(variant.pub_key_len()), None);
    }
}
