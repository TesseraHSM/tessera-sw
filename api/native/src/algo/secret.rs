// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_api::*;

use crate::HANDLE_TABLE;
use crate::TsraHandle;
use crate::TsraStatus;
use crate::handle_table::HandleType;

/// Unmasks a generic secret key
///
/// Imports a previously masked (encrypted/protected) generic secret key back into the HSM.
/// The masked key contains the key material and properties, so no external properties
/// are needed.
///
/// # Arguments
/// * `session` - HSM session for the unmask operation
/// * `masked_key` - Byte slice containing the masked key material
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the unmasked generic secret key for subsequent operations
/// * `Err(TsraStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn secret_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<TsraHandle, TsraStatus> {
    let mut unmask_algo = HsmGenericSecretKeyUnmaskAlgo::default();

    // Unmask generic secret key
    let key: HsmGenericSecretKey =
        HsmKeyManager::unmask_key(session, &mut unmask_algo, masked_key)?;

    let handle = HANDLE_TABLE.alloc_handle(HandleType::GenericSecretKey, Box::new(key));

    Ok(handle)
}
