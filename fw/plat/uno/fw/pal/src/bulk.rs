// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmBulkCrypto`] implementation for the Uno PAL.
//!
//! - **default build** — a bulk key is a vault entry holding its AES-256
//!   material, and its host-visible bulk key id is its vault key id. Bulk
//!   IOs will run on the BCP; they are not serviced yet.
//! - **`bulk_crypto`** — the fast-path firmware hosts the bulk engine: the
//!   key is registered with it over IPC, the vault keeps the 2-byte engine
//!   handle, and that handle is the bulk key id. Bulk IOs never reach the
//!   HSM core.
//!
//! Deletion goes through the [`HsmVault`](tsra_fw_hsm_pal_traits::HsmVault)
//! delete paths in [`crate::vault`], which release any engine state.

use tsra_fw_hsm_pal_traits::HsmBulkCrypto;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVault;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use crate::UnoHsmIo;
use crate::UnoHsmPal;
use crate::vault::FP_BULK_KEY_LEN;
use crate::vault::is_bulk_kind;

impl HsmBulkCrypto for UnoHsmPal {
    async fn bulk_key_create(
        &self,
        io: &UnoHsmIo,
        key: &HsmDmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<(HsmKeyId, u16)> {
        if !is_bulk_kind(kind) {
            return Err(HsmError::InvalidKeyType);
        }
        if key.len() != FP_BULK_KEY_LEN {
            return Err(HsmError::InvalidArg);
        }

        #[cfg(feature = "bulk_crypto")]
        let key_id = crate::vault::fp_bulk_create(self, io, key, kind, session_id, attrs).await?;
        #[cfg(not(feature = "bulk_crypto"))]
        let key_id = {
            // Serialized with session teardown, as in `fp_bulk_create`. The
            // guard drops before the cleanup below, which takes it again.
            let _guard = self.fp_bulk_lock.lock().await;
            crate::vault::check_bulk_session(self, io, session_id)?;
            let app_id = u8::from(io.pid());
            let session = session_id.map(u16::from);
            crate::vault::vault(io)
                .create(self, io, app_id, key, kind, session, attrs)
                .await?
        };

        match self.bulk_key_id(io, key_id) {
            Ok(bulk_key_id) => Ok((key_id, bulk_key_id)),
            Err(e) => {
                // Don't leave a key (or engine registration) the host has
                // no handle for.
                let _ = self.vault_key_delete(io, key_id).await;
                Err(e)
            }
        }
    }

    fn bulk_key_id(&self, io: &UnoHsmIo, key_id: HsmKeyId) -> HsmResult<u16> {
        if !is_bulk_kind(self.vault_key_kind(io, key_id)?) {
            return Err(HsmError::UnsupportedKeyType);
        }
        #[cfg(feature = "bulk_crypto")]
        {
            // The vault entry holds the 2-byte engine handle.
            let bytes: &[u8] = self.vault_key(io, key_id)?;
            let handle: [u8; 2] = bytes.try_into().map_err(|_| HsmError::InternalError)?;
            Ok(u16::from_le_bytes(handle))
        }
        #[cfg(not(feature = "bulk_crypto"))]
        Ok(u16::from(key_id))
    }

    async fn bulk_crypt(&self, _io: &mut UnoHsmIo) -> HsmResult<()> {
        Err(HsmError::UnsupportedCmd)
    }
}
