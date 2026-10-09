// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for ML-KEM key types: generation, import, export and metadata.

use super::*;

/// Generation is a pure function of the seed and parameter set.
#[test]
fn keygen_is_deterministic() {
    for variant in VARIANTS {
        let seed = filler(1, MLKEM_SEED_LEN);
        let a = MlKemPrivateKey::from_seed(variant, &seed).unwrap();
        let b = MlKemPrivateKey::from_seed(variant, &seed).unwrap();
        assert_eq!(a.to_vec().unwrap(), b.to_vec().unwrap());
    }
}

/// Different seeds must give different keys; otherwise the seed is not reaching
/// the expansion at all.
#[test]
fn distinct_seeds_give_distinct_keys() {
    for variant in VARIANTS {
        let a = MlKemPrivateKey::from_seed(variant, &filler(1, MLKEM_SEED_LEN)).unwrap();
        let b = MlKemPrivateKey::from_seed(variant, &filler(2, MLKEM_SEED_LEN)).unwrap();
        assert_ne!(a.to_vec().unwrap(), b.to_vec().unwrap());
    }
}

/// A seed of the wrong length is rejected rather than padded or truncated.
#[test]
fn keygen_rejects_a_wrong_length_seed() {
    for variant in VARIANTS {
        for len in [0, MLKEM_SEED_LEN - 1, MLKEM_SEED_LEN + 1] {
            assert!(MlKemPrivateKey::from_seed(variant, &filler(1, len)).is_err());
        }
    }
}

/// Encoded lengths must match FIPS 203 for every parameter set, since the wire
/// format and the masked key blob are sized from them.
#[test]
fn encoded_lengths_match_the_standard() {
    for (variant, pub_len, sec_len, ct_len) in [
        (MlKemVariant::MlKem512, 800, 1632, 768),
        (MlKemVariant::MlKem768, 1184, 2400, 1088),
        (MlKemVariant::MlKem1024, 1568, 3168, 1568),
    ] {
        assert_eq!(variant.pub_key_len(), pub_len);
        assert_eq!(variant.sec_key_len(), sec_len);
        assert_eq!(variant.ciphertext_len(), ct_len);

        let dk = MlKemPrivateKey::from_seed(variant, &filler(3, MLKEM_SEED_LEN)).unwrap();
        assert_eq!(dk.size(), sec_len);
        assert_eq!(dk.bits(), sec_len * 8);
        assert_eq!(dk.public_key().unwrap().size(), pub_len);
    }
}

/// Export and re-import must round-trip, and must recover the parameter set
/// from the length alone.
#[test]
fn keys_roundtrip_through_bytes() {
    for variant in VARIANTS {
        let dk = MlKemPrivateKey::from_seed(variant, &filler(4, MLKEM_SEED_LEN)).unwrap();
        let ek = dk.public_key().unwrap();

        let dk2 = MlKemPrivateKey::from_bytes(&dk.to_vec().unwrap()).unwrap();
        assert_eq!(dk2.variant(), variant);
        assert_eq!(dk2.to_vec().unwrap(), dk.to_vec().unwrap());

        let ek2 = MlKemPublicKey::from_bytes(&ek.to_vec().unwrap()).unwrap();
        assert_eq!(ek2.variant(), variant);
        assert_eq!(ek2.to_vec().unwrap(), ek.to_vec().unwrap());
    }
}

/// Deriving the encapsulation key from the expanded private key must agree with
/// deriving it during generation.
#[test]
fn public_key_is_recoverable_from_an_imported_private_key() {
    for variant in VARIANTS {
        let dk = MlKemPrivateKey::from_seed(variant, &filler(5, MLKEM_SEED_LEN)).unwrap();
        let expected = dk.public_key().unwrap().to_vec().unwrap();

        let imported = MlKemPrivateKey::from_bytes(&dk.to_vec().unwrap()).unwrap();
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
            assert!(MlKemPrivateKey::from_bytes(&filler(6, sec_len)).is_err());
            let pub_len = (variant.pub_key_len() as i32 + delta) as usize;
            assert!(MlKemPublicKey::from_bytes(&filler(6, pub_len)).is_err());
        }
    }
    assert!(MlKemPrivateKey::from_bytes(&[]).is_err());
    assert!(MlKemPublicKey::from_bytes(&[]).is_err());
}

/// `None` queries the required size without writing, per the crate's buffer
/// contract.
#[test]
fn export_reports_the_required_size() {
    for variant in VARIANTS {
        let dk = MlKemPrivateKey::from_seed(variant, &filler(7, MLKEM_SEED_LEN)).unwrap();
        assert_eq!(dk.to_bytes(None).unwrap(), variant.sec_key_len());

        let mut buf = vec![0u8; variant.sec_key_len()];
        assert_eq!(dk.to_bytes(Some(&mut buf)).unwrap(), variant.sec_key_len());
        assert_eq!(buf, dk.to_vec().unwrap());

        let ek = dk.public_key().unwrap();
        assert_eq!(ek.to_bytes(None).unwrap(), variant.pub_key_len());
    }
}

/// A short export buffer is an error, not a truncated key.
#[test]
fn export_rejects_a_short_buffer() {
    for variant in VARIANTS {
        let dk = MlKemPrivateKey::from_seed(variant, &filler(8, MLKEM_SEED_LEN)).unwrap();
        let mut buf = vec![0u8; variant.sec_key_len() - 1];
        assert!(matches!(
            dk.to_bytes(Some(&mut buf)),
            Err(CryptoError::MlKemBufferTooSmall)
        ));
    }
}

/// Length-based variant recovery must be exact, and must reject any length that
/// belongs to no parameter set.
#[test]
fn variant_recovery_is_unambiguous() {
    for variant in VARIANTS {
        assert_eq!(
            MlKemVariant::from_pub_key_len(variant.pub_key_len()),
            Some(variant)
        );
        assert_eq!(
            MlKemVariant::from_sec_key_len(variant.sec_key_len()),
            Some(variant)
        );
    }
    assert_eq!(MlKemVariant::from_pub_key_len(0), None);
    assert_eq!(MlKemVariant::from_sec_key_len(1), None);

    // The two length families must not overlap, or an expanded key could be
    // imported as an encapsulation key.
    for variant in VARIANTS {
        assert_eq!(MlKemVariant::from_pub_key_len(variant.sec_key_len()), None);
        assert_eq!(MlKemVariant::from_sec_key_len(variant.pub_key_len()), None);
    }
}
