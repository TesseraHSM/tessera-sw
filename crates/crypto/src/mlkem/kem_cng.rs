// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG ML-KEM encapsulation and implicit-rejection decapsulation.

use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Security::Cryptography::BCRYPT_KEY_HANDLE;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::LibraryLoader::GetProcAddress;
use windows::core::s;
use windows::core::w;

use super::*;
use crate::pqc_cng::CngPqcKey;
use crate::pqc_cng::PqcBlob;

// Resolve the new APIs at runtime: old CNG versions must still load the
// classical backend, and windows 0.62's bindings do not include these exports.
type Encapsulate = unsafe extern "system" fn(
    BCRYPT_KEY_HANDLE,
    *mut u8,
    u32,
    *mut u32,
    *mut u8,
    u32,
    *mut u32,
    u32,
) -> NTSTATUS;
type Decapsulate = unsafe extern "system" fn(
    BCRYPT_KEY_HANDLE,
    *const u8,
    u32,
    *mut u8,
    u32,
    *mut u32,
    u32,
) -> NTSTATUS;

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
        let native = CngPqcKey::import(
            key.variant().parameter_name(),
            PqcBlob::KemPublic,
            key.as_bytes(),
        )
        .map_err(|_| CryptoError::MlKemEncapsError)?;
        // SAFETY: bcrypt.dll is linked by the CNG backend and remains loaded.
        // The SDK function signature matches the named export; checked buffers
        // remain live until the synchronous operation completes.
        unsafe {
            let module =
                GetModuleHandleW(w!("bcrypt.dll")).map_err(|_| CryptoError::PqcUnavailable)?;
            let address = GetProcAddress(module, s!("BCryptEncapsulate"))
                .ok_or(CryptoError::PqcUnavailable)?;
            let encapsulate: Encapsulate = std::mem::transmute(address);
            let (mut ss_len, mut ct_len) = (0, 0);
            encapsulate(
                native.handle,
                shared_secret.as_mut_ptr(),
                lens.1 as u32,
                &mut ss_len,
                ciphertext.as_mut_ptr(),
                lens.0 as u32,
                &mut ct_len,
                0,
            )
            .ok()
            .map_err(|_| CryptoError::MlKemEncapsError)?;
            if (ct_len as usize, ss_len as usize) != lens {
                return Err(CryptoError::MlKemEncapsError);
            }
        }
        Ok(lens)
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
        let native = CngPqcKey::import(
            key.variant().parameter_name(),
            PqcBlob::KemPrivate,
            key.as_bytes(),
        )
        .map_err(|_| CryptoError::MlKemDecapsError)?;
        // SAFETY: the linked module remains loaded, the SDK signature matches,
        // and both buffers have the exact FIPS 203 lengths for this parameter set.
        unsafe {
            let module =
                GetModuleHandleW(w!("bcrypt.dll")).map_err(|_| CryptoError::PqcUnavailable)?;
            let address = GetProcAddress(module, s!("BCryptDecapsulate"))
                .ok_or(CryptoError::PqcUnavailable)?;
            let decapsulate: Decapsulate = std::mem::transmute(address);
            let mut len = 0;
            decapsulate(
                native.handle,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                shared_secret.as_mut_ptr(),
                MLKEM_SHARED_SECRET_LEN as u32,
                &mut len,
                0,
            )
            .ok()
            .map_err(|_| CryptoError::MlKemDecapsError)?;
            if len as usize != MLKEM_SHARED_SECRET_LEN {
                return Err(CryptoError::MlKemDecapsError);
            }
        }
        Ok(MLKEM_SHARED_SECRET_LEN)
    }
}
