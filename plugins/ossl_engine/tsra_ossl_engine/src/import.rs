// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key import shared by RSA and EC: the external key source (`tsra.input_key`
//! or `tsra.wrapped_key`) and the RSA-AES wrap against the HSM's unwrapping
//! key.

use std::path::Path;

use openssl::pkey::PKey;
use tsra_api::HsmEncrypter;
use tsra_api::HsmHashAlgo;
use tsra_api::HsmRsaAesWrapAlgo;
use tsra_api::HsmRsaPublicKey;
use tsra_ossl_engine_core::error::EngineError;
use tsra_ossl_engine_core::error::EngineResult;
use zeroize::Zeroizing;

/// RSA-AES wrap parameters, matching the 3.x provider so a `wrapped_key` blob
/// produced against the exported unwrapping key interoperates: SHA-256
/// OAEP/MGF1 and a 256-bit (32-byte) AES KEK.
pub(crate) const WRAP_HASH: HsmHashAlgo = HsmHashAlgo::Sha256;
pub(crate) const WRAP_KEK_BYTES: usize = 32;

/// The external key material to import.
pub(crate) enum ImportSource {
    /// A plaintext DER private key (`tsra.input_key`); the engine wraps it.
    /// Held zeroizing — it is external private-key material.
    PlaintextDer(Zeroizing<Vec<u8>>),
    /// A pre-wrapped blob (`tsra.wrapped_key`); unwrapped directly.
    WrappedBlob(Zeroizing<Vec<u8>>),
}

impl ImportSource {
    /// Read the file `input_key` or `wrapped_key` names; `None` when neither
    /// is set, an error when both are.
    pub(crate) fn read(
        input_key: Option<&Path>,
        wrapped_key: Option<&Path>,
    ) -> EngineResult<Option<Self>> {
        match (input_key, wrapped_key) {
            (Some(_), Some(_)) => Err(EngineError::Other(
                "tsra.input_key and tsra.wrapped_key are mutually exclusive".into(),
            )),
            (Some(p), None) => Ok(Some(Self::PlaintextDer(crate::keyload::read_masked_key(
                p,
            )?))),
            (None, Some(p)) => Ok(Some(Self::WrappedBlob(crate::keyload::read_masked_key(p)?))),
            (None, None) => Ok(None),
        }
    }

    /// The blob to unwrap. A plaintext key is wrapped against `unwrap_pub`,
    /// exactly as an external party would for `wrapped_key`; the HSM unwrap
    /// parser expects unencrypted PKCS#8, so PKCS#1/SEC1 input is normalized
    /// first, as the provider does.
    pub(crate) fn wrapped(&self, unwrap_pub: &HsmRsaPublicKey) -> EngineResult<Zeroizing<Vec<u8>>> {
        match self {
            Self::PlaintextDer(der) => {
                let pkcs8 = to_pkcs8_der(der)?;
                let mut wrap = HsmRsaAesWrapAlgo::new(WRAP_HASH, WRAP_KEK_BYTES);
                HsmEncrypter::encrypt_vec(&mut wrap, unwrap_pub, &pkcs8)
                    .map(Zeroizing::new)
                    .map_err(|e| EngineError::wrap("RSA-AES wrap input key", e))
            }
            Self::WrappedBlob(blob) => Ok(blob.clone()),
        }
    }
}

/// Normalize a plaintext private-key DER (traditional PKCS#1/SEC1 or already
/// PKCS#8) to unencrypted PKCS#8 — the form the HSM unwrap parser expects and
/// the provider produces before RSA-AES wrapping.
fn to_pkcs8_der(der: &[u8]) -> EngineResult<Zeroizing<Vec<u8>>> {
    let pkey =
        PKey::private_key_from_der(der).map_err(|e| EngineError::wrap("parse input key DER", e))?;
    pkey.private_key_to_pkcs8()
        .map(Zeroizing::new)
        .map_err(|e| EngineError::wrap("re-encode input key as PKCS#8", e))
}
