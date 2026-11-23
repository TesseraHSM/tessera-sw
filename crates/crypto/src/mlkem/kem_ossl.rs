// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL ML-KEM encapsulation and implicit-rejection decapsulation.

#[cfg(ossl350)]
use openssl_sys as ffi;

use super::*;
#[cfg(ossl350)]
use crate::libctx::OSSL_SUCCESS;
#[cfg(ossl350)]
use crate::pqc_ossl::OsslPqcKey;

impl EncapsulateOp for MlKemAlgo {
    type Key = MlKemPublicKey;

    #[allow(unsafe_code)]
    fn encapsulate(
        &mut self,
        key: &Self::Key,
        ciphertext: Option<&mut [u8]>,
        shared_secret: Option<&mut [u8]>,
    ) -> Result<(usize, usize), CryptoError> {
        let lens = (key.variant().ciphertext_len(), MLKEM_SHARED_SECRET_LEN);
        let (Some(ciphertext), Some(shared_secret)) = (ciphertext, shared_secret) else {
            return Ok(lens);
        };
        let ciphertext = ciphertext
            .get_mut(..lens.0)
            .ok_or(CryptoError::MlKemBufferTooSmall)?;
        let shared_secret = shared_secret
            .get_mut(..lens.1)
            .ok_or(CryptoError::MlKemBufferTooSmall)?;
        #[cfg(ossl350)]
        {
            let native = OsslPqcKey::import(key.variant().name(), c"pub", key.as_bytes())
                .map_err(|_| CryptoError::MlKemEncapsError)?;
            let ctx = native
                .context()
                .map_err(|_| CryptoError::MlKemEncapsError)?;
            // SAFETY: params are copied by init, and output buffers are writable
            // for the exact FIPS 203 lengths supplied to encapsulate.
            unsafe {
                let params = [
                    ffi::OSSL_PARAM_construct_end(),
                    ffi::OSSL_PARAM_construct_end(),
                ];
                #[cfg(test)]
                let params = if let Some(m) = &self.pinned_m {
                    [
                        ffi::OSSL_PARAM_construct_octet_string(
                            c"ikme".as_ptr(),
                            m.as_ptr().cast_mut().cast(),
                            m.len(),
                        ),
                        ffi::OSSL_PARAM_construct_end(),
                    ]
                } else {
                    params
                };
                if ffi::EVP_PKEY_encapsulate_init(ctx.as_ptr(), params.as_ptr()) != OSSL_SUCCESS {
                    return Err(CryptoError::MlKemEncapsError);
                }
                let (mut ct_len, mut ss_len) = lens;
                if ffi::EVP_PKEY_encapsulate(
                    ctx.as_ptr(),
                    ciphertext.as_mut_ptr(),
                    &mut ct_len,
                    shared_secret.as_mut_ptr(),
                    &mut ss_len,
                ) != OSSL_SUCCESS
                    || (ct_len, ss_len) != lens
                {
                    return Err(CryptoError::MlKemEncapsError);
                }
            }
            Ok(lens)
        }
        #[cfg(not(ossl350))]
        {
            let _ = (ciphertext, shared_secret);
            Err(CryptoError::PqcUnavailable)
        }
    }
}

impl DecapsulateOp for MlKemAlgo {
    type Key = MlKemPrivateKey;

    #[allow(unsafe_code)]
    fn decapsulate(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        shared_secret: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let Some(shared_secret) = shared_secret else {
            return Ok(MLKEM_SHARED_SECRET_LEN);
        };
        if ciphertext.len() != key.variant().ciphertext_len() {
            return Err(CryptoError::MlKemDecapsError);
        }
        let shared_secret = shared_secret
            .get_mut(..MLKEM_SHARED_SECRET_LEN)
            .ok_or(CryptoError::MlKemBufferTooSmall)?;
        #[cfg(ossl350)]
        {
            let native = OsslPqcKey::import(key.variant().name(), c"priv", key.as_bytes())
                .map_err(|_| CryptoError::MlKemDecapsError)?;
            native
                .check(true)
                .map_err(|_| CryptoError::MlKemDecapsError)?;
            let ctx = native
                .context()
                .map_err(|_| CryptoError::MlKemDecapsError)?;
            let mut len = shared_secret.len();
            // SAFETY: the live key/context and the exact-sized buffers are valid.
            unsafe {
                if ffi::EVP_PKEY_decapsulate_init(ctx.as_ptr(), std::ptr::null()) != OSSL_SUCCESS
                    || ffi::EVP_PKEY_decapsulate(
                        ctx.as_ptr(),
                        shared_secret.as_mut_ptr(),
                        &mut len,
                        ciphertext.as_ptr(),
                        ciphertext.len(),
                    ) != OSSL_SUCCESS
                    || len != MLKEM_SHARED_SECRET_LEN
                {
                    return Err(CryptoError::MlKemDecapsError);
                }
            }
            Ok(len)
        }
        #[cfg(not(ossl350))]
        {
            let _ = shared_secret;
            Err(CryptoError::PqcUnavailable)
        }
    }
}
