// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG ML-DSA pure and external-μ signing and verification.

use std::ffi::c_void;

use windows::Win32::Foundation::STATUS_INVALID_SIGNATURE;
use windows::Win32::Security::Cryptography::*;

use super::*;
use crate::pqc_cng::CngPqcKey;
use crate::pqc_cng::PqcBlob;

// These public SDK declarations are not yet in windows 0.62's metadata.
const BCRYPT_PAD_PQDSA: BCRYPT_FLAGS = BCRYPT_FLAGS(0x20);
const BCRYPT_MLDSA_EXTERNAL_MU: BCRYPT_FLAGS = BCRYPT_FLAGS(0x40);

#[repr(C)]
struct PqDsaPaddingInfo {
    context: *const u8,
    context_len: u32,
    prehash_algorithm: *const u16,
}

impl MlDsaAlgo {
    fn padding_info(&self) -> PqDsaPaddingInfo {
        PqDsaPaddingInfo {
            context: self.ctx.as_ptr(),
            context_len: self.ctx.len() as u32,
            prehash_algorithm: std::ptr::null(),
        }
    }

    fn padding(&self, info: &PqDsaPaddingInfo) -> (Option<*const c_void>, BCRYPT_FLAGS) {
        if self.external_mu {
            (None, BCRYPT_MLDSA_EXTERNAL_MU)
        } else {
            (Some(std::ptr::from_ref(info).cast()), BCRYPT_PAD_PQDSA)
        }
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
        if self.deterministic {
            return Err(CryptoError::MlDsaDeterministicUnsupported);
        }
        if u32::try_from(data.len()).is_err() {
            return Err(CryptoError::MlDsaSignError);
        }
        let native = CngPqcKey::import(
            key.variant().parameter_name(),
            PqcBlob::DsaPrivate,
            key.as_bytes(),
        )
        .map_err(|_| CryptoError::MlDsaSignError)?;
        let info = self.padding_info();
        let (padding, flags) = self.padding(&info);
        let mut written = 0;
        // SAFETY: padding and context remain live; all buffers have checked sizes.
        unsafe {
            BCryptSignHash(
                native.handle,
                padding,
                data,
                Some(signature),
                &mut written,
                flags,
            )
            .ok()
            .map_err(|_| CryptoError::MlDsaSignError)?;
        }
        if written as usize != len {
            return Err(CryptoError::MlDsaSignError);
        }
        Ok(len)
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
        if signature.len() != key.variant().sig_len() {
            return Ok(false);
        }
        if u32::try_from(data.len()).is_err() {
            return Err(CryptoError::MlDsaVerifyError);
        }
        let native = CngPqcKey::import(
            key.variant().parameter_name(),
            PqcBlob::DsaPublic,
            key.as_bytes(),
        )
        .map_err(|_| CryptoError::MlDsaVerifyError)?;
        let info = self.padding_info();
        let (padding, flags) = self.padding(&info);
        // SAFETY: padding/context and the checked input buffers remain alive.
        let status =
            unsafe { BCryptVerifySignature(native.handle, padding, data, signature, flags) };
        if status == STATUS_INVALID_SIGNATURE {
            return Ok(false);
        }
        status.ok().map_err(|_| CryptoError::MlDsaVerifyError)?;
        Ok(true)
    }
}
