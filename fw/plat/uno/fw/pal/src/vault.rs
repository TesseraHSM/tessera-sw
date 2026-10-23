// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmVault`] implementation for the Uno PAL.
//!
//! Key material lives in the GSRAM key-vault region. The platform-agnostic
//! allocator and key logic live in the [`KeyVault`] crate; the GSRAM table
//! layout and access live in the
//! [`VaultStorage`](tsra_fw_uno_drivers_vault::VaultStorage) driver. This
//! module just wires the async [`HsmVault`] trait methods to a per-call
//! [`KeyVault`] over that storage, using the PAL's own GDMA controller for
//! large-key copy/zeroize.
//!
//! All state is in GSRAM, so a [`KeyVault`] is constructed per call over a
//! lightweight [`VaultStorage`](tsra_fw_uno_drivers_vault::VaultStorage)
//! handle that carries only the calling partition's resource mask — there
//! is no PAL-resident vault state.
//!
//! Following the reference firmware, the SDK `meta` (key label) is not
//! stored (see the [`KeyVault`] crate docs).

#![allow(unsafe_code)]

use tsra_fw_hsm_io::Sqe;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVault;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_uno_drivers_part_store::PartStore;
use tsra_fw_uno_drivers_vault::VaultStorage;
use tsra_fw_uno_key_vault::KeyVault;

use crate::UnoHsmPal;

#[inline]
pub(crate) fn vault(io: &impl HsmIo) -> KeyVault<VaultStorage> {
    // Out-of-range partitions own no tables (empty mask → no storage).
    let res_mask = PartStore::partition(io.pid()).map_or(0, |p| p.res_mask());
    KeyVault::new(VaultStorage::new(res_mask))
}

impl UnoHsmPal {
    /// Reject cross-session access to a `Session`-scoped key with
    /// [`HsmError::KeyNotFound`]; partition-scoped keys are unaffected.
    fn enforce_session_key_isolation(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        Self::check_key_session(io, vault(io).key_session(key_id)?)
    }

    /// The isolation check of
    /// [`enforce_session_key_isolation`](Self::enforce_session_key_isolation)
    /// for a key bound to session `bound` (`None` if partition-scoped).
    fn check_key_session(io: &impl HsmIo, bound: Option<u16>) -> HsmResult<()> {
        let Some(bound) = bound else {
            return Ok(());
        };
        let sqe = Sqe::from(io.sqe());
        let current = sqe.session_flags().id_valid().then(|| sqe.session_id());
        if current == Some(bound) {
            Ok(())
        } else {
            Err(HsmError::KeyNotFound)
        }
    }
}

impl HsmVault for UnoHsmPal {
    async fn vault_key_create(
        &self,
        io: &impl HsmIo,
        key: &DmaBuf,
        kind: HsmVaultKeyKind,
        session_id: Option<HsmSessId>,
        attrs: HsmVaultKeyAttrs,
    ) -> HsmResult<HsmKeyId> {
        let app_id = u8::from(io.pid());
        let session = session_id.map(u16::from);
        let mut v = vault(io);
        v.create(self, io, app_id, key, kind, session, attrs).await
    }

    async fn vault_key_delete(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let mut v = vault(io);
        v.delete(self, io, key_id).await
    }

    fn vault_key_disable(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let mut v = vault(io);
        v.disable(key_id)
    }

    fn vault_key_enable(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
        let mut v = vault(io);
        v.enable(key_id)
    }

    async fn vault_key_delete_by_session(
        &self,
        io: &impl HsmIo,
        session_id: HsmSessId,
    ) -> HsmResult<()> {
        let mut v = vault(io);
        v.delete_by_session(self, io, u16::from(session_id)).await
    }

    async fn vault_clear(&self, io: &impl HsmIo) -> HsmResult<()> {
        let mut v = vault(io);
        v.clear(self, io).await
    }

    fn vault_key(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<&DmaBuf> {
        let ((table, off, len), session) = vault(io).key_location_and_session(key_id)?;
        Self::check_key_session(io, session)?;
        let addr = VaultStorage::blob_addr(table) + off;
        // SAFETY: `key_location` validated the key is live; `addr..addr+len`
        // lies within that table's 'static GSRAM blob region.
        Ok(unsafe { DmaBuf::from_raw(core::slice::from_raw_parts(addr as *const u8, len)) })
    }

    fn vault_key_len(&self, _io: &impl HsmIo, kind: HsmVaultKeyKind) -> HsmResult<u16> {
        KeyVault::<VaultStorage>::key_len(kind)
    }

    fn vault_key_kind(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyKind> {
        self.enforce_session_key_isolation(io, key_id)?;
        vault(io).key_kind(key_id)
    }

    fn vault_key_attrs(&self, io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<HsmVaultKeyAttrs> {
        self.enforce_session_key_isolation(io, key_id)?;
        vault(io).key_attrs(key_id)
    }
}

impl UnoHsmPal {
    #[cfg(feature = "fips_validation_hooks")]
    pub(crate) fn vault_key_session_binding(
        &self,
        io: &impl HsmIo,
        key_id: HsmKeyId,
    ) -> HsmResult<Option<u16>> {
        vault(io).key_session_binding(key_id)
    }
}
