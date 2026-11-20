// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL ML-DSA key expansion and validation.

use zeroize::Zeroizing;

use super::*;
#[cfg(ossl350)]
use crate::pqc_ossl::OsslPqcKey;

pub(super) fn expand_key(
    variant: MlDsaVariant,
    seed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    #[cfg(ossl350)]
    {
        OsslPqcKey::import(variant.name(), c"seed", seed)
            .and_then(|key| key.export(c"priv", variant.sec_key_len()))
            .map_err(|_| CryptoError::MlDsaKeyGenError)
    }
    #[cfg(not(ossl350))]
    {
        let _ = (variant, seed);
        Err(CryptoError::PqcUnavailable)
    }
}

pub(super) fn public_key(variant: MlDsaVariant, sk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    #[cfg(ossl350)]
    {
        OsslPqcKey::import(variant.name(), c"priv", sk)
            .and_then(|key| {
                key.check(true)?;
                key.export(c"pub", variant.pub_key_len())
            })
            .map(|bytes| bytes.to_vec())
            .map_err(|_| CryptoError::MlDsaKeyGenError)
    }
    #[cfg(not(ossl350))]
    {
        let _ = (variant, sk);
        Err(CryptoError::PqcUnavailable)
    }
}

pub(super) fn validate_public_key(variant: MlDsaVariant, pk: &[u8]) -> Result<(), CryptoError> {
    #[cfg(ossl350)]
    {
        OsslPqcKey::import(variant.name(), c"pub", pk)
            .and_then(|key| key.check(false))
            .map_err(|_| CryptoError::MlDsaKeyImportError)
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
            MlDsaPrivateKey::from_seed(MlDsaVariant::MlDsa44, &[0; MLDSA_SEED_LEN]),
            Err(CryptoError::PqcUnavailable),
        ));
        assert!(matches!(
            MlDsaPublicKey::from_bytes(&[0; 1312]),
            Err(CryptoError::PqcUnavailable),
        ));
        let sk = MlDsaPrivateKey::from_bytes(&[0; 2560]).expect("length-valid key");
        let mut algo = MlDsaAlgo::new(b"").expect("context");
        let mut sig = [0xA5; 2420];
        assert_eq!(
            algo.sign(&sk, b"message", Some(&mut sig)),
            Err(CryptoError::PqcUnavailable)
        );
        assert_eq!(sig, [0xA5; 2420]);
    }
}
