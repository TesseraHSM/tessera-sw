// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared OpenSSL PQC key import/export in the isolated default-provider libctx.

use std::ffi::CStr;
use std::ptr;

use openssl::error::ErrorStack;
use openssl_sys as ffi;
use zeroize::Zeroizing;

use crate::libctx::OSSL_SUCCESS;
use crate::libctx::PkeyCtx;

#[allow(unsafe_code)]
unsafe extern "C" {
    fn EVP_PKEY_private_check(ctx: *mut ffi::EVP_PKEY_CTX) -> std::ffi::c_int;
}

pub(crate) struct OsslPqcKey(*mut ffi::EVP_PKEY);

impl OsslPqcKey {
    #[allow(unsafe_code)]
    pub(crate) fn import(name: &CStr, field: &CStr, bytes: &[u8]) -> Result<Self, ErrorStack> {
        let ctx = PkeyCtx::from_name(name).ok_or_else(ErrorStack::get)?;
        let selection = if field == c"pub" {
            ffi::EVP_PKEY_PUBLIC_KEY
        } else {
            ffi::EVP_PKEY_KEYPAIR
        };
        // SAFETY: fromdata reads the input buffer; all parameters remain alive
        // until it returns. The returned key is owned and freed on every path.
        unsafe {
            let mut params = [
                ffi::OSSL_PARAM_construct_octet_string(
                    field.as_ptr(),
                    bytes.as_ptr().cast_mut().cast(),
                    bytes.len(),
                ),
                ffi::OSSL_PARAM_construct_end(),
            ];
            if ffi::EVP_PKEY_fromdata_init(ctx.as_ptr()) != OSSL_SUCCESS {
                return Err(ErrorStack::get());
            }
            let mut key = ptr::null_mut();
            let ok = ffi::EVP_PKEY_fromdata(ctx.as_ptr(), &mut key, selection, params.as_mut_ptr());
            if ok != OSSL_SUCCESS || key.is_null() {
                ffi::EVP_PKEY_free(key);
                return Err(ErrorStack::get());
            }
            Ok(Self(key))
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn context(&self) -> Result<PkeyCtx, ErrorStack> {
        // SAFETY: callers keep this key alive until the returned context drops.
        unsafe { PkeyCtx::from_pkey(self.0) }.ok_or_else(ErrorStack::get)
    }

    #[allow(unsafe_code)]
    pub(crate) fn check(&self, private: bool) -> Result<(), ErrorStack> {
        let ctx = self.context()?;
        // SAFETY: ctx owns a valid operation context bound to this live key.
        let ok = unsafe {
            if private {
                EVP_PKEY_private_check(ctx.as_ptr())
            } else {
                ffi::EVP_PKEY_public_check(ctx.as_ptr())
            }
        };
        if ok == OSSL_SUCCESS {
            Ok(())
        } else {
            Err(ErrorStack::get())
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn export(
        &self,
        field: &CStr,
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ErrorStack> {
        let mut bytes = Zeroizing::new(vec![0u8; len]);
        let mut written = 0;
        // SAFETY: the key and field are valid; the output has len writable bytes.
        let ok = unsafe {
            ffi::EVP_PKEY_get_octet_string_param(
                self.0,
                field.as_ptr(),
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut written,
            )
        };
        if ok != OSSL_SUCCESS || written != len {
            return Err(ErrorStack::get());
        }
        Ok(bytes)
    }
}

impl Drop for OsslPqcKey {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: this is the sole owner of the non-null EVP_PKEY.
        unsafe { ffi::EVP_PKEY_free(self.0) };
    }
}
