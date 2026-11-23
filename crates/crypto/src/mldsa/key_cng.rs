// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG ML-DSA seed and expanded-key operations.

use zeroize::Zeroizing;

use super::*;
use crate::pqc_cng::CngPqcKey;
use crate::pqc_cng::PqcBlob;

pub(super) fn expand_key(
    variant: MlDsaVariant,
    seed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    CngPqcKey::import(variant.parameter_name(), PqcBlob::DsaSeed, seed)
        .and_then(|key| key.export(PqcBlob::DsaPrivate, variant.sec_key_len()))
        .map_err(|_| CryptoError::MlDsaKeyGenError)
}

pub(super) fn public_key(variant: MlDsaVariant, sk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    CngPqcKey::import(variant.parameter_name(), PqcBlob::DsaPrivate, sk)
        .and_then(|key| key.export(PqcBlob::DsaPublic, variant.pub_key_len()))
        .map(|bytes| bytes.to_vec())
        .map_err(|_| CryptoError::MlDsaKeyGenError)
}

pub(super) fn validate_public_key(variant: MlDsaVariant, pk: &[u8]) -> Result<(), CryptoError> {
    CngPqcKey::import(variant.parameter_name(), PqcBlob::DsaPublic, pk)
        .map(|_| ())
        .map_err(|_| CryptoError::MlDsaKeyImportError)
}
