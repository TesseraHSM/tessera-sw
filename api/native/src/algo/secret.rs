// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use tsra_api::*;

use crate::HANDLE_TABLE;
use crate::TsraHandle;
use crate::TsraStatus;
use crate::handle_table::HandleType;

/// Unmasks a shared secret key
///
/// Imports a previously masked (encrypted/protected) shared secret key back into the HSM.
/// The masked key contains the key material and properties, so no external properties
/// are needed.
///
/// # Arguments
/// * `session` - HSM session for the unmask operation
/// * `masked_key` - Byte slice containing the masked key material
///
/// # Returns
/// * `Ok(TsraHandle)` - Handle to the unmasked shared secret key for subsequent operations
/// * `Err(TsraStatus)` - On failure (e.g., invalid masked key format, session error)
pub(crate) fn shared_secret_unmask_key(
    session: &HsmSession,
    masked_key: &[u8],
) -> Result<TsraHandle, TsraStatus> {
    let mut unmask_algo = HsmSharedSecretKeyUnmaskAlgo::default();

    // Unmask shared secret key
    let key: HsmSharedSecretKey = HsmKeyManager::unmask_key(session, &mut unmask_algo, masked_key)?;

    let handle = HANDLE_TABLE.alloc_handle(HandleType::SharedSecretKey, Box::new(key));

    Ok(handle)
}
