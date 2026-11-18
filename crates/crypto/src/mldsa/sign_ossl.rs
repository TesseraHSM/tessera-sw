// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL ML-DSA pure and external-μ signing and verification.

#[cfg(ossl350)]
use openssl::error::ErrorStack;
#[cfg(ossl350)]
use openssl_sys as ffi;

use super::*;
#[cfg(ossl350)]
use crate::libctx::OSSL_SUCCESS;
#[cfg(ossl350)]
use crate::libctx::PkeyCtx;
#[cfg(ossl350)]
use crate::libctx::crypto_libctx_ptr;
#[cfg(ossl350)]
use crate::pqc_ossl::OsslPqcKey;

#[cfg(ossl350)]
struct SignatureAlgorithm(*mut ffi::EVP_SIGNATURE);

#[cfg(ossl350)]
impl Drop for SignatureAlgorithm {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: this owns the non-null fetched signature algorithm.
        unsafe { ffi::EVP_SIGNATURE_free(self.0) };
    }
}

#[cfg(ossl350)]
#[allow(unsafe_code)]
fn context(
    algo: &MlDsaAlgo,
    key: &OsslPqcKey,
    variant: MlDsaVariant,
    signing: bool,
) -> Result<(PkeyCtx, SignatureAlgorithm), ErrorStack> {
    let ctx = key.context()?;
    let mut external_mu = u32::from(algo.external_mu);
    let mut deterministic = u32::from(algo.deterministic);
    // SAFETY: parameter inputs remain alive until init returns, which copies
    // them. Key and fetched algorithm outlive the returned operation context.
    unsafe {
        let signature = ffi::EVP_SIGNATURE_fetch(
            crypto_libctx_ptr(),
            variant.name().as_ptr(),
            std::ptr::null(),
        );
        if signature.is_null() {
            return Err(ErrorStack::get());
        }
        let signature = SignatureAlgorithm(signature);
        let mut params = vec![
            ffi::OSSL_PARAM_construct_octet_string(
                c"context-string".as_ptr(),
                algo.ctx.as_ptr().cast_mut().cast(),
                algo.ctx.len(),
            ),
            ffi::OSSL_PARAM_construct_uint(c"mu".as_ptr(), &mut external_mu),
        ];
        if signing {
            params.push(ffi::OSSL_PARAM_construct_uint(
                c"deterministic".as_ptr(),
                &mut deterministic,
            ));
            #[cfg(test)]
            if !algo.deterministic
                && let Some(rnd) = &algo.pinned_rnd
            {
                params.push(ffi::OSSL_PARAM_construct_octet_string(
                    c"test-entropy".as_ptr(),
                    rnd.as_ptr().cast_mut().cast(),
                    rnd.len(),
                ));
            }
        }
        params.push(ffi::OSSL_PARAM_construct_end());
        let ok = if signing {
            ffi::EVP_PKEY_sign_message_init(ctx.as_ptr(), signature.0, params.as_ptr())
        } else {
            ffi::EVP_PKEY_verify_message_init(ctx.as_ptr(), signature.0, params.as_ptr())
        };
        if ok != OSSL_SUCCESS {
            return Err(ErrorStack::get());
        }
        Ok((ctx, signature))
    }
}

impl SignOp for MlDsaAlgo {
    type Key = MlDsaPrivateKey;

    #[allow(unsafe_code)]
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let len = key.variant().sig_len();
        let Some(signature) = signature else {
            return Ok(len);
        };
        self.check_input(data)?;
        let signature = signature
            .get_mut(..len)
            .ok_or(CryptoError::MlDsaBufferTooSmall)?;
        #[cfg(ossl350)]
        {
            let native = OsslPqcKey::import(key.variant().name(), c"priv", key.as_bytes())
                .map_err(|_| CryptoError::MlDsaSignError)?;
            let (ctx, _algorithm) = context(self, &native, key.variant(), true)
                .map_err(|_| CryptoError::MlDsaSignError)?;
            let mut written = signature.len();
            // SAFETY: ctx is initialized for signing; input and output are valid.
            let ok = unsafe {
                ffi::EVP_PKEY_sign(
                    ctx.as_ptr(),
                    signature.as_mut_ptr(),
                    &mut written,
                    data.as_ptr(),
                    data.len(),
                )
            };
            if ok != OSSL_SUCCESS || written != len {
                return Err(CryptoError::MlDsaSignError);
            }
            Ok(written)
        }
        #[cfg(not(ossl350))]
        {
            let _ = signature;
            Err(CryptoError::PqcUnavailable)
        }
    }
}

impl VerifyOp for MlDsaAlgo {
    type Key = MlDsaPublicKey;

    #[allow(unsafe_code)]
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        self.check_input(data)?;
        #[cfg(ossl350)]
        {
            if signature.len() != key.variant().sig_len() {
                return Ok(false);
            }
            let native = OsslPqcKey::import(key.variant().name(), c"pub", key.as_bytes())
                .map_err(|_| CryptoError::MlDsaVerifyError)?;
            let (ctx, _algorithm) = context(self, &native, key.variant(), false)
                .map_err(|_| CryptoError::MlDsaVerifyError)?;
            // SAFETY: ctx is initialized for verification and buffers are valid.
            let result = unsafe {
                ffi::EVP_PKEY_verify(
                    ctx.as_ptr(),
                    signature.as_ptr(),
                    signature.len(),
                    data.as_ptr(),
                    data.len(),
                )
            };
            match result {
                OSSL_SUCCESS => Ok(true),
                0 => {
                    // Invalid signatures can leave provider errors on the queue.
                    let _ = ErrorStack::get();
                    Ok(false)
                }
                _ => Err(CryptoError::MlDsaVerifyError),
            }
        }
        #[cfg(not(ossl350))]
        {
            let _ = (key, signature);
            Err(CryptoError::PqcUnavailable)
        }
    }
}
