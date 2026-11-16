// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL ML-KEM key expansion and validation.

use zeroize::Zeroizing;

use super::*;
#[cfg(ossl350)]
use crate::pqc_ossl::OsslPqcKey;

pub(super) fn expand_key(
    variant: MlKemVariant,
    seed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    #[cfg(ossl350)]
    {
        OsslPqcKey::import(variant.name(), c"seed", seed)
            .and_then(|key| key.export(c"priv", variant.sec_key_len()))
            .map_err(|_| CryptoError::MlKemKeyGenError)
    }
    #[cfg(not(ossl350))]
    {
        let _ = (variant, seed);
        Err(CryptoError::PqcUnavailable)
    }
}

pub(super) fn public_key(variant: MlKemVariant, sk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    #[cfg(ossl350)]
    {
        OsslPqcKey::import(variant.name(), c"priv", sk)
            .and_then(|key| {
                key.check(true)?;
                key.export(c"pub", variant.pub_key_len())
            })
            .map(|bytes| bytes.to_vec())
            .map_err(|_| CryptoError::MlKemKeyGenError)
    }
    #[cfg(not(ossl350))]
    {
        let _ = (variant, sk);
        Err(CryptoError::PqcUnavailable)
    }
}

pub(super) fn validate_public_key(variant: MlKemVariant, pk: &[u8]) -> Result<(), CryptoError> {
    #[cfg(ossl350)]
    {
        OsslPqcKey::import(variant.name(), c"pub", pk)
            .and_then(|key| key.check(false))
            .map_err(|_| CryptoError::MlKemKeyImportError)
    }

    #[cfg(not(ossl350))]
    {
        let _ = (variant, pk);
        Err(CryptoError::PqcUnavailable)
    }
}

#[cfg(all(test, not(ossl350)))]
mod tests {
    use super::*;

    #[test]
    fn legacy_openssl_reports_pqc_unavailable() {
        assert!(matches!(
            MlKemPrivateKey::from_seed(MlKemVariant::MlKem512, &[0; MLKEM_SEED_LEN]),
            Err(CryptoError::PqcUnavailable),
        ));
        assert!(matches!(
            MlKemPublicKey::from_bytes(&[0; 800]),
            Err(CryptoError::PqcUnavailable),
        ));
        let sk = MlKemPrivateKey::from_bytes(&[0; 1632]).expect("length-valid key");
        let mut ss = [0xA5; MLKEM_SHARED_SECRET_LEN];
        assert_eq!(
            MlKemAlgo::new().decapsulate(&sk, &[0; 768], Some(&mut ss)),
            Err(CryptoError::PqcUnavailable),
        );
        assert_eq!(ss, [0xA5; MLKEM_SHARED_SECRET_LEN]);
    }
}
