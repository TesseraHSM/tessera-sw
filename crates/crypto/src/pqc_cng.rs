// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared Windows CNG PQC key blob import/export.

use windows::Win32::Foundation::E_INVALIDARG;
use windows::Win32::Security::Cryptography::*;
use windows::core::Error;
use windows::core::PCWSTR;
use windows::core::w;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(crate) enum PqcBlob {
    DsaSeed,
    DsaPrivate,
    DsaPublic,
    KemSeed,
    KemPrivate,
    KemPublic,
}

impl PqcBlob {
    fn name(self) -> PCWSTR {
        match self {
            Self::DsaSeed => w!("PQDSAPRIVATESEEDBLOB"),
            Self::DsaPrivate => w!("PQDSAPRIVATEBLOB"),
            Self::DsaPublic => w!("PQDSAPUBLICBLOB"),
            Self::KemSeed => w!("MLKEMPRIVATESEEDBLOB"),
            Self::KemPrivate => w!("MLKEMPRIVATEBLOB"),
            Self::KemPublic => w!("MLKEMPUBLICBLOB"),
        }
    }

    fn magic(self) -> u32 {
        match self {
            Self::DsaSeed => 0x53535344,
            Self::DsaPrivate => 0x4B535344,
            Self::DsaPublic => 0x4B505344,
            Self::KemSeed => 0x534B4C4D,
            Self::KemPrivate => 0x524B4C4D,
            Self::KemPublic => 0x504B4C4D,
        }
    }

    fn algorithm(self) -> PCWSTR {
        match self {
            Self::DsaSeed | Self::DsaPrivate | Self::DsaPublic => w!("ML-DSA"),
            Self::KemSeed | Self::KemPrivate | Self::KemPublic => w!("ML-KEM"),
        }
    }
}

struct Algorithm(BCRYPT_ALG_HANDLE);

impl Drop for Algorithm {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: this is the sole owner of an open algorithm provider.
        let _ = unsafe { BCryptCloseAlgorithmProvider(self.0, 0) };
    }
}

pub(crate) struct CngPqcKey {
    pub(crate) handle: BCRYPT_KEY_HANDLE,
    _algorithm: Algorithm,
    parameter: Vec<u8>,
}

impl CngPqcKey {
    #[allow(unsafe_code)]
    pub(crate) fn import(parameter: &str, format: PqcBlob, bytes: &[u8]) -> Result<Self, Error> {
        let parameter: Vec<u8> = parameter
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        let parameter_len =
            u32::try_from(parameter.len()).map_err(|_| Error::from_hresult(E_INVALIDARG))?;
        let key_len = u32::try_from(bytes.len()).map_err(|_| Error::from_hresult(E_INVALIDARG))?;
        let mut blob = Zeroizing::new(Vec::with_capacity(12 + parameter.len() + bytes.len()));
        blob.extend_from_slice(&format.magic().to_le_bytes());
        blob.extend_from_slice(&parameter_len.to_le_bytes());
        blob.extend_from_slice(&key_len.to_le_bytes());
        blob.extend_from_slice(&parameter);
        blob.extend_from_slice(bytes);
        let mut algorithm = BCRYPT_ALG_HANDLE::default();
        // SAFETY: constant names are NUL-terminated; the input blob remains live
        // until CNG copies it. RAII closes the provider on import failure.
        unsafe {
            let status = BCryptOpenAlgorithmProvider(
                &mut algorithm,
                format.algorithm(),
                MS_PRIMITIVE_PROVIDER,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            );
            status.ok()?;
            let algorithm = Algorithm(algorithm);
            let mut handle = BCRYPT_KEY_HANDLE::default();
            let status =
                BCryptImportKeyPair(algorithm.0, None, format.name(), &mut handle, &blob, 0);
            status.ok()?;
            Ok(Self {
                handle,
                _algorithm: algorithm,
                parameter,
            })
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn export(&self, format: PqcBlob, len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
        let expected = 12 + self.parameter.len() + len;
        let mut blob = Zeroizing::new(vec![0u8; expected]);
        let mut written = 0;
        // SAFETY: the live key exports into a buffer of the known blob size.
        unsafe {
            let status = BCryptExportKey(
                self.handle,
                None,
                format.name(),
                Some(&mut blob),
                &mut written,
                0,
            );
            status.ok()?;
        }
        if written as usize != expected
            || blob[..4] != format.magic().to_le_bytes()
            || blob[4..8] != (self.parameter.len() as u32).to_le_bytes()
            || blob[8..12] != (len as u32).to_le_bytes()
            || blob[12..12 + self.parameter.len()] != self.parameter
        {
            return Err(Error::from_hresult(E_INVALIDARG));
        }
        Ok(Zeroizing::new(blob[12 + self.parameter.len()..].to_vec()))
    }
}

impl Drop for CngPqcKey {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: this owns the key; its algorithm provider drops afterwards.
        let _ = unsafe { BCryptDestroyKey(self.handle) };
    }
}
