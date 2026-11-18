// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG ML-KEM seed and expanded-key operations.

use zeroize::Zeroizing;

use super::*;
use crate::pqc_cng::CngPqcKey;
use crate::pqc_cng::PqcBlob;

pub(super) fn expand_key(
    variant: MlKemVariant,
    seed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    CngPqcKey::import(variant.parameter_name(), PqcBlob::KemSeed, seed)
        .and_then(|key| key.export(PqcBlob::KemPrivate, variant.sec_key_len()))
        .map_err(|_| CryptoError::MlKemKeyGenError)
}

pub(super) fn public_key(variant: MlKemVariant, sk: &[u8]) -> Result<Vec<u8>, CryptoError> {
    CngPqcKey::import(variant.parameter_name(), PqcBlob::KemPrivate, sk)
        .and_then(|key| key.export(PqcBlob::KemPublic, variant.pub_key_len()))
        .map(|bytes| bytes.to_vec())
        .map_err(|_| CryptoError::MlKemKeyGenError)
}

pub(super) fn validate_public_key(variant: MlKemVariant, pk: &[u8]) -> Result<(), CryptoError> {
    CngPqcKey::import(variant.parameter_name(), PqcBlob::KemPublic, pk)
        .map(|_| ())
        .map_err(|_| CryptoError::MlKemKeyImportError)
}
