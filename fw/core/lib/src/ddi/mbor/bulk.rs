// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for committing freshly produced keys to storage and
//! rolling them back on a later failure.
//!
//! Bulk keys (AES-GCM / XTS) are owned by the platform bulk-crypto path:
//! they are created through
//! [`bulk_key_create`](tsra_fw_hsm_pal_traits::HsmBulkCrypto::bulk_key_create),
//! which also returns the host-visible `bulk_key_id`, and are deleted
//! through the ordinary vault delete paths.  Every op that can produce a
//! bulk key — AES generate, HKDF / KBKDF derive, unmask, RSA unwrap —
//! commits it through [`commit_key`].

use super::*;

/// True for the AES bulk vault kinds (GCM / XTS) whose material lives in
/// the platform bulk-crypto backend rather than the vault.
pub(crate) fn is_bulk(kind: HsmVaultKeyKind) -> bool {
    matches!(
        kind,
        HsmVaultKeyKind::AesGcmBulk256
            | HsmVaultKeyKind::AesGcmBulk256Unapproved
            | HsmVaultKeyKind::AesXtsBulk256
    )
}

/// Commit freshly produced key `material` and return its handle plus, for
/// bulk kinds, the host-visible `bulk_key_id`.
///
/// Bulk kinds are created through
/// [`bulk_key_create`](HsmBulkCrypto::bulk_key_create); all other kinds
/// through [`vault_key_create`](HsmVault::vault_key_create) with no bulk id.
pub(crate) async fn commit_key<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    material: &HsmDmaBuf,
    kind: HsmVaultKeyKind,
    sess_id: HsmSessId,
    attrs: HsmVaultKeyAttrs,
) -> HsmResult<(HsmKeyId, Option<u16>)> {
    let session_id = attrs.session().then_some(sess_id);
    if is_bulk(kind) {
        let (handle, bulk_key_id) = pal
            .bulk_key_create(io, material, kind, session_id, attrs)
            .await?;
        Ok((handle, Some(bulk_key_id)))
    } else {
        let handle = pal
            .vault_key_create(io, material, kind, session_id, attrs)
            .await?;
        Ok((handle, None))
    }
}

/// Return `result` unchanged, first deleting the key committed earlier in
/// the op (best effort) if it is an error, so a failure after the commit
/// leaves no vault entry (or backend registration) the host has no handle
/// for.
pub(crate) async fn rollback_on_err<P: HsmPal, T>(
    pal: &P,
    io: &P::Io,
    handle: HsmKeyId,
    result: HsmResult<T>,
) -> HsmResult<T> {
    if result.is_err() {
        let _ = pal.vault_key_delete(io, handle).await;
    }
    result
}
