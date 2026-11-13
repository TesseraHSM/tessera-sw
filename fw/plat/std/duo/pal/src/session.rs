// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmSessionManager`] implementation for the standard PAL.
//!
//! Sessions are stored as vault keys.  `session_create` builds an
//! 88-byte blob (`[api_rev(8) || masking_key(80)]`), stores it in the
//! partition's [`KeyVault`] as `HsmVaultKeyKind::Session`, then
//! allocates a logical session slot in the [`SessionTable`] that maps
//! to the vault key's physical [`HsmKeyId`].
//!
//! `session_destroy` cascades cleanup: removes session-scoped vault
//! keys, deletes the session vault key itself, and frees the logical
//! slot.
//!
//! `session_create` commits the session immediately and returns its
//! [`HsmSessId`]; rollback of a half-completed handshake is left to a
//! future undo log.
//!
//! [`KeyVault`]: crate::drivers::vault::KeyVault
//! [`SessionTable`]: crate::drivers::session::SessionTable

use zeroize::Zeroizing;

use super::*;
use crate::StdHsmPal;

/// Size of the API revision portion of the session blob (bytes).
const SESSION_API_REV_SIZE: usize = 8;

/// Size of the masking key portion of the session blob (bytes).
/// AES-CBC-256 key (32) + HMAC-SHA-384 key (48) = 80.
const SESSION_MASKING_KEY_SIZE: usize = 80;

/// Legacy `Session`-kind blob size used by [`session_create`] for the
/// MBOR masking-key flow: `[api_rev(8) || masking_key(80)]` = 88 B.
const SESSION_BLOB_SIZE: usize = SESSION_API_REV_SIZE + SESSION_MASKING_KEY_SIZE;

/// `SessionEx`-kind blob size for **PlainText (CU)** sessions:
/// `api_rev(8) || param_key(32) || masking_key(32) || auth_binding(68)` = 140 B.  The
/// SessionEx masking key is the 32 B AES-256-GCM `key_masking::aead`
/// key ([`SESSION_MASKING_KEY_LEN`]), not the legacy 80 B cbc key.
pub(crate) const SESSION_CU_BLOB_SIZE: usize = SESSION_API_REV_SIZE
    + SESSION_PARAM_KEY_LEN
    + SESSION_MASKING_KEY_LEN
    + SESSION_AUTH_BINDING_LEN;

/// `SessionEx`-kind blob size for **Authenticated (CO)** sessions:
/// PlainText blob ‖ `mac_tx(48) ‖ mac_rx(48)` = 236 B.
pub(crate) const SESSION_CU_AUTH_BLOB_SIZE: usize =
    SESSION_CU_BLOB_SIZE + 2 * SESSION_MAC_DIR_KEY_LEN;

/// `SessionEx`-kind blob size for **secure-transport** sessions:
/// PlainText blob ‖ `h2m(32) ‖ m2h(32)` AES-256-GCM transport keys = 204 B.
pub(crate) const SESSION_SECURE_BLOB_SIZE: usize =
    SESSION_CU_BLOB_SIZE + 2 * SESSION_TRANSPORT_KEY_LEN;

/// Whether `len` is a `SessionEx` (TBOR handshake) blob length.
pub(crate) fn is_session_ex_len(len: usize) -> bool {
    if len == SESSION_SECURE_BLOB_SIZE {
        return true;
    }
    matches!(len, SESSION_CU_BLOB_SIZE | SESSION_CU_AUTH_BLOB_SIZE)
}

impl HsmSessionManager for StdHsmPal {
    /// Check whether the partition's session table is full.
    fn session_limit_reached(&self, io: &StdHsmIo) -> bool {
        let Ok(entry) = self.active_part(io.pid()) else {
            return true;
        };
        entry.session_table.limit_reached()
    }

    /// Create (or re-key) a session.
    ///
    /// 1. Builds 88-byte blob: `[api_rev || masking_key]`.
    /// 2. Stores blob in vault as `HsmVaultKeyKind::Session`.
    /// 3. Allocates (or re-maps) a logical session slot.
    ///
    /// The session is committed immediately.
    async fn session_create(
        &self,
        io: &StdHsmIo,
        api_rev: &[u8],
        masking_key: &HsmDmaBuf,
        id: Option<HsmSessId>,
    ) -> HsmResult<HsmSessId> {
        if api_rev.len() != SESSION_API_REV_SIZE || masking_key.len() != SESSION_MASKING_KEY_SIZE {
            return Err(HsmError::InvalidArg);
        }

        let pid = io.pid();
        let entry = self.active_part_mut(pid)?;

        // On re-key, only a slot awaiting renegotiation after a
        // live-migration disable may be recreated: its vault key material
        // was already cleared, so `recreate` below simply installs the
        // fresh mapping (mirroring the reference firmware's
        // `recreate_session`).  Reject every other state before touching
        // the vault — tearing down a live session's keys and then failing
        // in `recreate` would leave the slot pointing at a deleted key,
        // so it could never be closed.
        if let Some(reopen_id) = id {
            entry.session_table.validate_recreation(reopen_id)?;
        }

        // Build 88-byte session blob: [api_rev(8) || masking_key(80)].
        let mut blob = [0u8; SESSION_BLOB_SIZE];
        blob[..SESSION_API_REV_SIZE].copy_from_slice(api_rev);
        blob[SESSION_API_REV_SIZE..].copy_from_slice(masking_key);

        // Store in vault as internal session key.
        let attrs = HsmVaultKeyAttrs::new().with_internal(true);
        let physical_id = entry
            .vault
            .create(&blob, HsmVaultKeyKind::Session, None, attrs)?;

        // Allocate or re-map logical session slot.
        let result = match id {
            None => entry.session_table.create(physical_id),
            Some(reopen_id) => entry.session_table.recreate(reopen_id, physical_id),
        };

        // If session-table allocation fails, remove the just-stored vault
        // key so the slot does not leak.
        match result {
            Ok(sess_id) => Ok(sess_id),
            Err(e) => {
                let _ = entry.vault.delete(physical_id);
                Err(e)
            }
        }
    }

    /// Destroy (close) a session with cascading vault cleanup.
    ///
    /// 1. Looks up physical vault key ID from logical session ID.
    /// 2. Deletes all session-scoped vault keys bound to that physical ID.
    /// 3. Deletes the session vault key itself.
    /// 4. Frees the logical session slot.
    ///
    /// For [`Pending`](HsmSessionState::Pending) slots no vault entry
    /// exists yet, so steps 1–3 are skipped and only step 4 runs.
    /// [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation) slots
    /// have no backing vault key after partition disable and likewise
    /// only require freeing the logical slot.
    async fn session_destroy(&self, io: &StdHsmIo, id: HsmSessId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;

        if matches!(
            entry.session_table.state(id),
            HsmSessionState::Pending | HsmSessionState::NeedsRenegotiation
        ) {
            entry.session_table.delete(id)?;
            return Ok(());
        }

        // Look up physical session key ID.
        let physical_id = entry.session_table.physical_id(id)?;

        // Delete all session-scoped keys bound to this physical ID.
        entry.vault.delete_by_session_key(physical_id)?;

        // Delete the session key itself.
        entry.vault.delete(physical_id)?;

        // Free the logical session slot.
        entry.session_table.delete(id)?;
        Ok(())
    }

    /// Roll back a failed post-migration re-key (`ReopenSession`).
    ///
    /// Restores the slot to [`NeedsRenegotiation`](HsmSessionState::NeedsRenegotiation)
    /// and deletes the fresh masking-key vault entry that
    /// [`session_create`](Self::session_create) installed, so neither the
    /// slot state nor the vault leaks and the host can retry the reopen.
    async fn session_rollback_reopen(&self, io: &StdHsmIo, id: HsmSessId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;

        // Delete the fresh masking-key vault entry while the physical mapping
        // is still intact, then restore the slot (clearing the mapping).
        let physical_id = entry.session_table.physical_id(id)?;
        entry.vault.delete(physical_id)?;
        entry.session_table.rollback_recreation(id)?;
        Ok(())
    }

    /// Query the lifecycle state of a session.
    fn session_state(&self, io: &StdHsmIo, id: HsmSessId) -> HsmSessionState {
        let Ok(entry) = self.active_part(io.pid()) else {
            return HsmSessionState::Invalid;
        };
        entry.session_table.state(id)
    }

    async fn session_create_pending(
        &self,
        io: &StdHsmIo,
        role: HsmSessionRole,
        handshake_state: &HsmDmaBuf,
    ) -> HsmResult<HsmSessId> {
        let entry = self.active_part_mut(io.pid())?;
        entry.session_table.create_pending(role, handshake_state)
    }

    fn session_pending_state(
        &self,
        io: &StdHsmIo,
        id: HsmSessId,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let entry = self.active_part(io.pid())?;
        let blob = entry.session_table.pending_state(id)?;
        match out {
            None => Ok(blob.len()),
            Some(buf) => {
                if buf.len() < blob.len() {
                    return Err(HsmError::InvalidArg);
                }
                buf[..blob.len()].copy_from_slice(blob);
                Ok(blob.len())
            }
        }
    }

    async fn session_promote(
        &self,
        io: &StdHsmIo,
        id: HsmSessId,
        api_rev: &[u8],
        param_key: &HsmDmaBuf,
        masking_key: &HsmDmaBuf,
        auth_binding: &HsmDmaBuf,
        mac_tx_key: Option<&HsmDmaBuf>,
        mac_rx_key: Option<&HsmDmaBuf>,
    ) -> HsmResult<()> {
        if api_rev.len() != SESSION_API_REV_SIZE
            || param_key.len() != SESSION_PARAM_KEY_LEN
            || masking_key.len() != SESSION_MASKING_KEY_LEN
            || auth_binding.len() != SESSION_AUTH_BINDING_LEN
        {
            return Err(HsmError::InvalidArg);
        }

        // Both MAC keys must be present together (Authenticated) or both
        // absent (PlainText) — mixed presence is a caller bug.
        let mac_pair = match (mac_tx_key, mac_rx_key) {
            (None, None) => None,
            (Some(tx), Some(rx)) => {
                if tx.len() != rx.len() || !is_dir_key_len(tx.len()) {
                    return Err(HsmError::InvalidArg);
                }
                Some((tx, rx))
            }
            _ => return Err(HsmError::InvalidArg),
        };

        let pid = io.pid();
        let entry = self.active_part_mut(pid)?;

        // Confirm the slot is Pending before doing any work.
        if !matches!(entry.session_table.state(id), HsmSessionState::Pending) {
            return Err(HsmError::SessionNotPending);
        }

        let attrs = HsmVaultKeyAttrs::new().with_internal(true);

        // Length-discriminated blob:
        // - PlainText: api_rev(8) + param_key(32) + masking_key(32) + auth_binding(68) = 140 B
        // - Authenticated: above ‖ mac_tx(48) ‖ mac_rx(48)                       = 236 B
        // - Secure transport: above PlainText ‖ h2m(32) ‖ m2h(32)              = 204 B
        let mut blob = Zeroizing::new([0u8; SESSION_CU_AUTH_BLOB_SIZE]);
        blob[..SESSION_API_REV_SIZE].copy_from_slice(api_rev);
        blob[SESSION_API_REV_SIZE..SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN]
            .copy_from_slice(param_key);
        blob[SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN
            ..SESSION_CU_BLOB_SIZE - SESSION_AUTH_BINDING_LEN]
            .copy_from_slice(masking_key);
        blob[SESSION_CU_BLOB_SIZE - SESSION_AUTH_BINDING_LEN..SESSION_CU_BLOB_SIZE]
            .copy_from_slice(auth_binding);

        let blob_len = match mac_pair {
            None => SESSION_CU_BLOB_SIZE,
            Some((tx, rx)) => {
                let key_len = tx.len();
                blob[SESSION_CU_BLOB_SIZE..SESSION_CU_BLOB_SIZE + key_len].copy_from_slice(tx);
                blob[SESSION_CU_BLOB_SIZE + key_len..SESSION_CU_BLOB_SIZE + 2 * key_len]
                    .copy_from_slice(rx);
                SESSION_CU_BLOB_SIZE + 2 * key_len
            }
        };

        let physical_id =
            entry
                .vault
                .create(&blob[..blob_len], HsmVaultKeyKind::SessionEx, None, attrs)?;

        // Promote the slot to Active and bind to the new vault entry.
        if let Err(e) = entry.session_table.promote(id, physical_id) {
            let _ = entry.vault.delete(physical_id);
            return Err(e);
        }
        Ok(())
    }

    fn session_param_key(&self, io: &StdHsmIo, id: HsmSessId) -> HsmResult<&HsmDmaBuf> {
        let entry = self.active_part(io.pid())?;
        let kid = entry.session_table.physical_id(id)?;
        let blob = entry.vault.key(kid)?;
        if !is_session_ex_len(blob.len()) {
            return Err(HsmError::InvalidPermissions);
        }
        let key_bytes = &blob[SESSION_API_REV_SIZE..SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN];
        // SAFETY: same justification as `vault_key` — on the host,
        // any heap byte is reachable; branding the sub-slice as
        // `HsmDmaBuf` only satisfies the type system.
        Ok(unsafe { HsmDmaBuf::from_raw(key_bytes) })
    }

    fn session_masking_key(&self, io: &StdHsmIo, id: HsmSessId) -> HsmResult<&HsmDmaBuf> {
        let entry = self.active_part(io.pid())?;
        let kid = entry.session_table.physical_id(id)?;
        let blob = entry.vault.key(kid)?;
        // The masking key follows `api_rev` in a legacy MBOR `Session`
        // blob (80 B `aes32 ‖ hmac48` cbc key), or `api_rev ‖ param_key`
        // in a `SessionEx` (CU/CO) blob (32 B AES-256-GCM aead key); pick
        // the offset *and length* from the blob length so both schedules
        // work.
        let (offset, size) = match blob.len() {
            SESSION_BLOB_SIZE => (SESSION_API_REV_SIZE, SESSION_MASKING_KEY_SIZE),
            len if is_session_ex_len(len) => (
                SESSION_API_REV_SIZE + SESSION_PARAM_KEY_LEN,
                SESSION_MASKING_KEY_LEN,
            ),
            _ => return Err(HsmError::InternalError),
        };
        let key_bytes = &blob[offset..offset + size];
        // SAFETY: same justification as `session_param_key` — on the
        // host, any heap byte is reachable; branding the sub-slice as
        // `HsmDmaBuf` only satisfies the type system.
        Ok(unsafe { HsmDmaBuf::from_raw(key_bytes) })
    }

    fn session_auth_binding(&self, io: &StdHsmIo, id: HsmSessId) -> HsmResult<&HsmDmaBuf> {
        let entry = self.active_part(io.pid())?;
        let kid = entry.session_table.physical_id(id)?;
        let blob = entry.vault.key(kid)?;
        if !is_session_ex_len(blob.len()) {
            return Err(HsmError::InvalidPermissions);
        }
        let binding = &blob[SESSION_CU_BLOB_SIZE - SESSION_AUTH_BINDING_LEN..SESSION_CU_BLOB_SIZE];
        // SAFETY: this is a sub-view of the vault's DMA-reachable key storage.
        Ok(unsafe { HsmDmaBuf::from_raw(binding) })
    }

    fn session_try_consume_psk_change(&self, io: &StdHsmIo, id: HsmSessId) -> HsmResult<()> {
        let entry = self.active_part_mut(io.pid())?;
        entry.session_table.try_consume_psk_change(id)
    }
}

/// Whether `len` is a valid directional key length for `session_promote`.
fn is_dir_key_len(len: usize) -> bool {
    if len == SESSION_TRANSPORT_KEY_LEN {
        return true;
    }
    len == SESSION_MAC_DIR_KEY_LEN
}

/// Direction of a session transport key.
#[derive(Clone, Copy)]
pub(crate) enum TransportDir {
    /// VM→HSM (requests).
    H2m,
    /// HSM→VM (responses).
    M2h,
}

impl StdHsmPal {
    /// Borrows a directional transport key: from a Pending slot's
    /// handshake blob tail, or an Active session's secure-transport blob.
    pub(crate) fn session_transport_key(
        &self,
        io: &StdHsmIo,
        id: HsmSessId,
        dir: TransportDir,
    ) -> HsmResult<&[u8; SESSION_TRANSPORT_KEY_LEN]> {
        let entry = self.active_part(io.pid())?;
        let (blob, keys_off) = match entry.session_table.state(id) {
            HsmSessionState::Pending => {
                let blob = entry.session_table.pending_state(id)?;
                let off = blob
                    .len()
                    .checked_sub(2 * SESSION_TRANSPORT_KEY_LEN)
                    .ok_or(HsmError::InvalidPermissions)?;
                (blob, off)
            }
            HsmSessionState::Active => {
                let kid = entry.session_table.physical_id(id)?;
                let blob = entry.vault.key(kid)?;
                if blob.len() != SESSION_SECURE_BLOB_SIZE {
                    return Err(HsmError::InvalidPermissions);
                }
                (blob, SESSION_CU_BLOB_SIZE)
            }
            _ => return Err(HsmError::SessionNotFound),
        };
        let offset = match dir {
            TransportDir::H2m => keys_off,
            TransportDir::M2h => keys_off + SESSION_TRANSPORT_KEY_LEN,
        };
        blob[offset..offset + SESSION_TRANSPORT_KEY_LEN]
            .try_into()
            .map_err(|_| HsmError::InternalError)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod session_reopen_tests {
    use super::*;
    use crate::drivers::vault::KeyVault;

    fn dma(bytes: &[u8]) -> &HsmDmaBuf {
        // SAFETY: host test memory is DMA-reachable and retains the input borrow.
        unsafe { HsmDmaBuf::from_raw(bytes) }
    }

    fn test_pal() -> (StdHsmPal, StdHsmIo) {
        let (_tx, rx) = async_channel::bounded(1);
        let mut pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let entry = &mut pal.part_table.get_mut().entries[0];
        entry.state = HsmPartState::Enabled;
        entry.vault = KeyVault::new(1);
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        (pal, io)
    }

    #[tokio::test]
    async fn session_reopen_errors_preserve_existing_slots_and_vault_keys() {
        let (pal, io) = test_pal();
        let api_rev = [1u8; SESSION_API_REV_SIZE];
        let masking_key = dma(&[2u8; SESSION_MASKING_KEY_SIZE]);
        let active = pal
            .session_create(&io, &api_rev, masking_key, None)
            .await
            .unwrap();
        let pending = pal
            .active_part_mut(io.pid())
            .unwrap()
            .session_table
            .create_pending(HsmSessionRole::CryptoUser, &[])
            .unwrap();
        let physical_id = pal
            .active_part(io.pid())
            .unwrap()
            .session_table
            .physical_id(active)
            .unwrap();
        let original_key = pal
            .active_part(io.pid())
            .unwrap()
            .vault
            .key(physical_id)
            .unwrap()
            .to_vec();

        for (id, expected) in [
            (active, HsmError::ProcessedIoEventInInvalidState),
            (pending, HsmError::ProcessedIoEventInInvalidState),
            (HsmSessId::from(7u16), HsmError::SessionNotFound),
            (HsmSessId::from(8u16), HsmError::VaultSessionLimitReached),
            (
                HsmSessId::from(u16::MAX),
                HsmError::VaultSessionLimitReached,
            ),
        ] {
            assert_eq!(
                pal.session_create(&io, &api_rev, masking_key, Some(id))
                    .await,
                Err(expected)
            );
            let entry = pal.active_part(io.pid()).unwrap();
            assert_eq!(
                entry.session_table.physical_id(active).unwrap(),
                physical_id
            );
            assert_eq!(entry.vault.key(physical_id).unwrap(), original_key);
            assert!(matches!(
                entry.session_table.state(active),
                HsmSessionState::Active
            ));
            assert!(matches!(
                entry.session_table.state(pending),
                HsmSessionState::Pending
            ));
        }

        let next = pal
            .session_create(&io, &api_rev, masking_key, None)
            .await
            .unwrap();
        assert_eq!(u16::from(next), 2);
        assert_eq!(
            u16::from(
                pal.active_part(io.pid())
                    .unwrap()
                    .session_table
                    .physical_id(next)
                    .unwrap()
            ),
            1
        );
        pal.session_destroy(&io, active).await.unwrap();
    }

    #[tokio::test]
    async fn session_reopen_succeeds_when_all_slots_need_renegotiation() {
        let (pal, io) = test_pal();
        let api_rev = [1u8; SESSION_API_REV_SIZE];
        let masking_key = dma(&[2u8; SESSION_MASKING_KEY_SIZE]);
        for _ in 0..8 {
            pal.session_create(&io, &api_rev, masking_key, None)
                .await
                .unwrap();
        }
        let entry = pal.active_part_mut(io.pid()).unwrap();
        let retained = entry.session_table.backup();
        entry.vault.clear();
        entry.session_table.restore(retained);
        assert!(pal.session_limit_reached(&io));

        for raw_id in 0..8u16 {
            let id = HsmSessId::from(raw_id);
            assert_eq!(
                pal.session_create(&io, &api_rev, masking_key, Some(id))
                    .await,
                Ok(id)
            );
            assert!(matches!(
                pal.session_state(&io, id),
                HsmSessionState::Active
            ));
        }
        assert!(pal.session_limit_reached(&io));
    }

    #[tokio::test]
    async fn session_reopen_invalid_lengths_still_return_invalid_arg() {
        let (pal, io) = test_pal();
        let api_rev = [1u8; SESSION_API_REV_SIZE];
        let masking_key = dma(&[2u8; SESSION_MASKING_KEY_SIZE]);
        for id in [
            None,
            Some(HsmSessId::from(0u16)),
            Some(HsmSessId::from(8u16)),
        ] {
            assert_eq!(
                pal.session_create(&io, &api_rev[..7], masking_key, id)
                    .await,
                Err(HsmError::InvalidArg)
            );
            assert_eq!(
                pal.session_create(&io, &api_rev, &masking_key[..79], id)
                    .await,
                Err(HsmError::InvalidArg)
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod session_type_tests {
    use tsra_fw_hsm_pal_traits::HsmError;
    use tsra_fw_hsm_pal_traits::HsmSessionRole;
    use tsra_fw_hsm_pal_traits::HsmSessionType;

    use super::*;

    #[tokio::test]
    async fn legacy_mbor_cu_slot_has_no_tbor_credential_or_param_key() {
        let (tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        pal.part_alloc_internal(0, 1).await.unwrap();
        pal.part_enable_internal(0).await.unwrap();
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        tx.send(HsmIoRequest::cmd(
            HsmPartId::from(0u8),
            0,
            0,
            [0; tsra_fw_hsm_io::duo::DUO_SQE_DWORDS],
            reply_tx,
        ))
        .await
        .unwrap();
        let io = pal.poll_io().await.unwrap();
        let masking_key = pal.dma_alloc(&io, SESSION_MASKING_KEY_SIZE).unwrap();
        masking_key.fill(0x42);
        let co_slot = pal
            .session_create(&io, &[0u8; 8], masking_key, None)
            .await
            .unwrap();
        let cu_slot = pal
            .session_create(&io, &[0u8; 8], masking_key, None)
            .await
            .unwrap();
        assert_eq!(co_slot.role(), HsmSessionRole::CryptoOfficer);
        assert_eq!(cu_slot.role(), HsmSessionRole::CryptoUser);
        assert!(matches!(
            pal.session_state(&io, cu_slot),
            HsmSessionState::Active
        ));
        assert!(matches!(
            pal.session_auth_binding(&io, cu_slot),
            Err(HsmError::InvalidPermissions)
        ));
        assert!(matches!(
            pal.session_param_key(&io, cu_slot),
            Err(HsmError::InvalidPermissions)
        ));
        pal.session_destroy(&io, cu_slot).await.unwrap();
        pal.session_destroy(&io, co_slot).await.unwrap();
    }

    #[test]
    fn to_u8_matches_discriminant() {
        assert_eq!(HsmSessionType::PlainText.to_u8(), 0);
        assert_eq!(HsmSessionType::Authenticated.to_u8(), 1);
    }

    #[test]
    fn from_u8_round_trip() {
        assert_eq!(
            HsmSessionType::from_u8(0).unwrap(),
            HsmSessionType::PlainText
        );
        assert_eq!(
            HsmSessionType::from_u8(1).unwrap(),
            HsmSessionType::Authenticated
        );
    }

    #[test]
    fn from_u8_rejects_unknown_values() {
        for v in [2u8, 3, 0x7f, 0x80, 0xff] {
            assert!(
                matches!(
                    HsmSessionType::from_u8(v),
                    Err(HsmError::InvalidSessionType)
                ),
                "expected InvalidSessionType for v={v}"
            );
        }
    }

    #[test]
    fn validate_for_role_co_requires_authenticated() {
        assert!(HsmSessionType::Authenticated
            .validate_for_role(HsmSessionRole::CryptoOfficer)
            .is_ok());
        assert!(matches!(
            HsmSessionType::PlainText.validate_for_role(HsmSessionRole::CryptoOfficer),
            Err(HsmError::InvalidSessionType)
        ));
    }

    #[test]
    fn validate_for_role_cu_requires_plaintext() {
        assert!(HsmSessionType::PlainText
            .validate_for_role(HsmSessionRole::CryptoUser)
            .is_ok());
        assert!(matches!(
            HsmSessionType::Authenticated.validate_for_role(HsmSessionRole::CryptoUser),
            Err(HsmError::InvalidSessionType)
        ));
    }

    #[test]
    fn is_authenticated_flag() {
        assert!(HsmSessionType::Authenticated.is_authenticated());
        assert!(!HsmSessionType::PlainText.is_authenticated());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod secure_session_tests {
    use tsra_fw_hsm_io::duo::DuoCmdDword;
    use tsra_fw_hsm_io::duo::DuoOp;
    use tsra_fw_hsm_io::duo::DuoSqeBuilder;
    use tsra_fw_hsm_io::duo::DuoSqeEntry;

    use super::*;
    use crate::drivers::vault::KeyVault;

    const H2M: [u8; SESSION_TRANSPORT_KEY_LEN] = [0x11; SESSION_TRANSPORT_KEY_LEN];
    const M2H: [u8; SESSION_TRANSPORT_KEY_LEN] = [0x22; SESSION_TRANSPORT_KEY_LEN];
    const MSG: &[u8] = b"secure session transport";

    fn dma(bytes: &[u8]) -> &HsmDmaBuf {
        // SAFETY: host test memory is DMA-reachable and retains the input borrow.
        unsafe { HsmDmaBuf::from_raw(bytes) }
    }

    fn dma_mut(bytes: &mut [u8]) -> &mut HsmDmaBuf {
        // SAFETY: as for `dma`.
        unsafe { HsmDmaBuf::from_raw_mut(bytes) }
    }

    fn test_pal() -> (StdHsmPal, StdHsmIo) {
        let (_tx, rx) = async_channel::bounded(1);
        let mut pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        let entry = &mut pal.part_table.get_mut().entries[0];
        entry.state = HsmPartState::Enabled;
        entry.vault = KeyVault::new(1);
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        (pal, io)
    }

    /// A Pending slot whose handshake blob ends with `H2M ‖ M2H`.
    async fn pending(pal: &StdHsmPal, io: &StdHsmIo) -> HsmSessId {
        let mut blob = vec![0u8; 8];
        blob.extend_from_slice(&H2M);
        blob.extend_from_slice(&M2H);
        pal.session_create_pending(io, HsmSessionRole::CryptoUser, dma(&blob))
            .await
            .unwrap()
    }

    /// A secure-op SQE pointing at host buffers `src` and `dst`.
    fn secure_sqe(
        id: HsmSessId,
        tag: &[u8; SESSION_TRANSPORT_TAG_LEN],
        src: &[u8],
        dst: &mut [u8],
    ) -> DuoSqeBuilder {
        DuoSqeBuilder::new()
            .cmd(DuoCmdDword::new().with_op(DuoOp::TborSecure as u8))
            .session_id(u16::from(id))
            .buf_lens(src.len() as u32, dst.len() as u32)
            .src_prp1(src.as_ptr() as u64)
            .dst_prp1(dst.as_mut_ptr() as u64)
            .gcm_tag(tag)
            .iv(&IV)
    }

    fn secure_io(sqe: DuoSqeBuilder) -> (StdHsmIo, DuoSqeEntry) {
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let raw = sqe.build();
        let io = StdHsmIo::new(
            crate::io::HsmIoRequest::cmd(HsmPartId::from(0u8), 0, 0, raw, reply_tx),
            0,
        );
        (io, DuoSqeEntry(raw))
    }

    /// The CQE protection fields `(iv, tag)` the PAL filled.
    fn cqe_protection(
        io: &mut StdHsmIo,
    ) -> (
        [u8; SESSION_TRANSPORT_IV_LEN],
        [u8; SESSION_TRANSPORT_TAG_LEN],
    ) {
        let crate::io::StdCqe::Cmd(cqe) = &mut io.cqe else {
            unreachable!("command IO")
        };
        let cqe = cqe.view();
        (cqe.iv(), cqe.tag())
    }

    /// `MSG` sealed under `H2M`, as the host sends it.
    async fn seal_request(pal: &StdHsmPal) -> (Vec<u8>, [u8; SESSION_TRANSPORT_TAG_LEN]) {
        let mut tag = [0u8; SESSION_TRANSPORT_TAG_LEN];
        let mut ct = vec![0u8; MSG.len()];
        pal.aes
            .gcm_encrypt(&H2M, &IV, None, MSG, &mut ct, &mut tag)
            .await
            .unwrap();
        (ct, tag)
    }

    const IV: [u8; SESSION_TRANSPORT_IV_LEN] = [7; SESSION_TRANSPORT_IV_LEN];

    /// The PAL fetches and opens a request sealed under `H2M`, then seals
    /// the response under `M2H` into host memory with its IV and tag in
    /// the CQE.
    async fn assert_round_trip(pal: &StdHsmPal, id: HsmSessId) {
        let (ct, tag) = seal_request(pal).await;
        let mut dst = vec![0u8; 64];
        let (mut io, sqe) = secure_io(secure_sqe(id, &tag, &ct, &mut dst));

        let req = pal.transport_recv_payload(&io, &sqe).await.unwrap();
        assert_eq!(req.len, MSG.len());
        let mut allocation = req.buf;
        assert_eq!(&allocation.buffer_mut()[..MSG.len()], MSG);

        let resp = &allocation.into_buffer()[..MSG.len()];
        pal.transport_send(&mut io, sqe, resp).await.unwrap();
        let (resp_iv, resp_tag) = cqe_protection(&mut io);
        assert_ne!(&dst[..MSG.len()], MSG);
        let mut plain = vec![0u8; MSG.len()];
        pal.aes
            .gcm_decrypt(
                &M2H,
                &resp_iv,
                None,
                &resp_tag,
                &dst[..MSG.len()],
                &mut plain,
            )
            .await
            .unwrap();
        assert_eq!(plain, MSG);
    }

    #[tokio::test]
    async fn pending_and_active_sessions_use_their_transport_keys() {
        let (pal, io) = test_pal();
        let id = pending(&pal, &io).await;
        assert_round_trip(&pal, id).await;

        pal.session_promote(
            &io,
            id,
            &[1u8; SESSION_API_REV_SIZE],
            dma(&[2u8; SESSION_PARAM_KEY_LEN]),
            dma(&[3u8; SESSION_MASKING_KEY_LEN]),
            dma(&[4u8; SESSION_AUTH_BINDING_LEN]),
            Some(dma(&H2M)),
            Some(dma(&M2H)),
        )
        .await
        .unwrap();
        assert_round_trip(&pal, id).await;
    }

    #[tokio::test]
    async fn tampered_request_fails_authentication() {
        let (pal, io) = test_pal();
        let id = pending(&pal, &io).await;
        let (ct, mut tag) = seal_request(&pal).await;
        tag[0] ^= 1;
        let (io, sqe) = secure_io(secure_sqe(id, &tag, &ct, &mut []));
        assert!(matches!(
            pal.transport_recv_payload(&io, &sqe).await,
            Err(HsmError::SessionTransportError)
        ));
    }

    #[tokio::test]
    async fn requests_with_aad_are_rejected() {
        let (pal, io) = test_pal();
        let id = pending(&pal, &io).await;
        let (ct, tag) = seal_request(&pal).await;
        let (io, sqe) = secure_io(secure_sqe(id, &tag, &ct, &mut []).aad_len(16));
        assert!(matches!(
            pal.transport_recv_payload(&io, &sqe).await,
            Err(HsmError::InvalidArg)
        ));
    }

    #[tokio::test]
    async fn sessions_without_transport_keys_are_rejected() {
        let (pal, io) = test_pal();
        let plain = pal
            .session_create(
                &io,
                &[1u8; SESSION_API_REV_SIZE],
                dma(&[2u8; SESSION_MASKING_KEY_SIZE]),
                None,
            )
            .await
            .unwrap();
        let buf = MSG.to_vec();
        let mut dst = vec![0u8; MSG.len()];
        for id in [plain, HsmSessId::from(7u16)] {
            let (mut io, sqe) = secure_io(secure_sqe(
                id,
                &[0; SESSION_TRANSPORT_TAG_LEN],
                MSG,
                &mut dst,
            ));
            assert!(matches!(
                pal.transport_recv_payload(&io, &sqe).await,
                Err(HsmError::SessionTransportError)
            ));
            assert_eq!(
                pal.transport_send(&mut io, sqe, dma(&buf)).await,
                Err(HsmError::SessionTransportError)
            );
        }
        assert_eq!(dst, vec![0u8; MSG.len()], "nothing reaches the host");
    }

    /// Duo defers `SessionClose` to the commit walk so the response can
    /// still be sealed under the session's transport key.
    #[tokio::test]
    async fn session_close_destroys_only_on_commit() {
        use tsra_fw_hsm_pal_traits::HsmSessionState;
        use tsra_fw_hsm_undo::UndoLog;

        let (pal, io) = test_pal();
        let id = pending(&pal, &io).await;
        pal.session_promote(
            &io,
            id,
            &[1u8; SESSION_API_REV_SIZE],
            dma(&[2u8; SESSION_PARAM_KEY_LEN]),
            dma(&[3u8; SESSION_MASKING_KEY_LEN]),
            dma(&[4u8; SESSION_AUTH_BINDING_LEN]),
            Some(dma(&H2M)),
            Some(dma(&M2H)),
        )
        .await
        .unwrap();
        for commit in [false, true] {
            let mut storage = [0u8; 128];
            let mut undo = UndoLog::new(dma_mut(&mut storage));
            undo.push_session_close(id).unwrap();
            assert!(matches!(
                pal.session_state(&io, id),
                HsmSessionState::Active
            ));
            let _ = if commit {
                undo.apply_commit(&pal, &io).await
            } else {
                undo.apply_undo(&pal, &io).await
            };
            let expected_live = !commit;
            assert_eq!(
                matches!(pal.session_state(&io, id), HsmSessionState::Active),
                expected_live
            );
        }
    }
}
