// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_api::*;

use super::*;
use crate::HANDLE_TABLE;
use crate::TsraHandle;
use crate::TsraStatus;
use crate::handle_table::HandleType;

impl TryFrom<&TsraAlgo> for tsra_api::HsmAesKeyGenAlgo {
    type Error = TsraStatus;

    /// Converts a C FFI algorithm specification to HsmAesKeyGenAlgo.
    fn try_from(_algo: &TsraAlgo) -> Result<Self, Self::Error> {
        Ok(HsmAesKeyGenAlgo::default())
    }
}

impl TryFrom<&TsraAlgo> for tsra_api::HsmAesGcmKeyGenAlgo {
    type Error = TsraStatus;

    /// Converts a C FFI algorithm specification to HsmAesGcmKeyGenAlgo.
    fn try_from(_algo: &TsraAlgo) -> Result<Self, Self::Error> {
        Ok(HsmAesGcmKeyGenAlgo::default())
    }
}

impl TryFrom<&TsraAlgo> for tsra_api::HsmAesXtsKeyGenAlgo {
    type Error = TsraStatus;

    /// Converts a C FFI algorithm specification to HsmAesXtsKeyGenAlgo.
    fn try_from(_algo: &TsraAlgo) -> Result<Self, Self::Error> {
        Ok(HsmAesXtsKeyGenAlgo::default())
    }
}

/// Generates a new AES key
///
/// Creates a new AES symmetric key with the specified properties.
///
/// # Arguments
/// * `session` - HSM session for key generation
/// * `algo` - AES key generation algorithm parameters (key size)
/// * `key_props` - Properties for the generated key (extractable, persistent, etc.)
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the generated AES key
/// * `Err(TsraStatus)` - On failure (e.g., unsupported key size)
pub(crate) fn aes_generate_key(
    session: &HsmSession,
    algo: &TsraAlgo,
    key_props: HsmKeyProps,
) -> Result<TsraHandle, TsraStatus> {
    let handle = match key_props.kind() {
        HsmKeyKind::Aes => {
            let mut aes_algo = HsmAesKeyGenAlgo::try_from(algo)?;
            let key = HsmKeyManager::generate_key(session, &mut aes_algo, key_props)?;
            HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(key))
        }
        HsmKeyKind::AesGcm => {
            let mut aes_algo = HsmAesGcmKeyGenAlgo::try_from(algo)?;
            let key = HsmKeyManager::generate_key(session, &mut aes_algo, key_props)?;
            HANDLE_TABLE.alloc_handle(HandleType::AesGcmKey, Box::new(key))
        }
        HsmKeyKind::AesXts => {
            let mut aes_algo = HsmAesXtsKeyGenAlgo::try_from(algo)?;
            let key = HsmKeyManager::generate_key(session, &mut aes_algo, key_props)?;
            HANDLE_TABLE.alloc_handle(HandleType::AesXtsKey, Box::new(key))
        }
        _ => Err(TsraStatus::UnsupportedKeyKind)?,
    };

    Ok(handle)
}

/// Unmasks a masked AES key and returns a handle to it
///
/// Takes a masked AES key (typically received from external storage or transmission)
/// and unmasks it within the HSM session, creating a usable key handle.
///
/// # Arguments
/// * `session` - Reference to the HSM session where the key will be unmasked
/// * `masked_key` - Byte slice containing the masked key material
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the unmasked AES key for subsequent cryptographic operations
/// * `Err(TsraStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn aes_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<TsraHandle, TsraStatus> {
    let aes_key: HsmAesKey =
        HsmKeyManager::unmask_key(session, &mut HsmAesKeyUnmaskAlgo::default(), masked_key)?;
    let handle = HANDLE_TABLE.alloc_handle(HandleType::AesKey, Box::new(aes_key));

    Ok(handle)
}

/// Unmasks a masked AES-GCM key and returns a handle to it
///
/// Takes a masked AES-GCM key (typically received from external storage or transmission)
/// and unmasks it within the HSM session, creating a usable key handle.
///
/// # Arguments
/// * `session` - Reference to the HSM session where the key will be unmasked
/// * `masked_key` - Byte slice containing the masked key material
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the unmasked AES-GCM key for subsequent cryptographic operations
/// * `Err(TsraStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn aes_gcm_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<TsraHandle, TsraStatus> {
    let gcm_key: HsmAesGcmKey =
        HsmKeyManager::unmask_key(session, &mut HsmAesGcmKeyUnmaskAlgo::default(), masked_key)?;
    let handle = HANDLE_TABLE.alloc_handle(HandleType::AesGcmKey, Box::new(gcm_key));

    Ok(handle)
}

/// Unmasks a masked AES-XTS key and returns a handle to it
///
/// Takes a masked AES-XTS key pair (typically received from external storage or transmission)
/// and unmasks it within the HSM session, creating a usable key handle. The masked key
/// contains both the tweak key and data encryption key in the XTS key pair format.
///
/// # Arguments
/// * `session` - Reference to the HSM session where the key will be unmasked
/// * `masked_key` - Byte slice containing the masked XTS key pair material
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the unmasked AES-XTS key for subsequent cryptographic operations
/// * `Err(TsraStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn aes_xts_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<TsraHandle, TsraStatus> {
    let mut unmask_algo = HsmAesXtsKeyUnmaskAlgo::default();

    // Unmask AES-XTS key
    let key: HsmAesXtsKey = HsmKeyManager::unmask_key(session, &mut unmask_algo, masked_key)?;

    let handle = HANDLE_TABLE.alloc_handle(HandleType::AesXtsKey, Box::new(key));

    Ok(handle)
}
