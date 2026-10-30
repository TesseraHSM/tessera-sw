// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for committing freshly produced keys to storage and
//! rolling them back on a later failure.
//!
//! Bulk keys (AES-GCM / XTS) are not stored in the HSM vault as key
//! material: the bulk crypto runs on a dedicated platform backend, so the
//! vault records only a small opaque handle and the host addresses the key
//! by a backend-assigned `bulk_key_id`.  The core stays unaware of that
//! backend — each PAL folds any bulk registration into its
//! [`vault_key_create`](tsra_fw_hsm_pal_traits::HsmVault::vault_key_create)
//! override and exposes the id through
//! [`bulk_key_id`](tsra_fw_hsm_pal_traits::HsmVault::bulk_key_id).  Every
//! op that can produce a bulk key — AES generate, HKDF / KBKDF derive,
//! unmask, RSA unwrap — commits it through [`commit_key`].

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

/// Commit freshly produced key `material` to the vault and return its
/// handle plus, for bulk kinds, the backend-assigned `bulk_key_id`.
///
/// All keys are created through [`vault_key_create`](HsmVault::vault_key_create).
/// Only bulk kinds query [`bulk_key_id`](HsmVault::bulk_key_id); ordinary
/// keys return `None` for the bulk id. A failed bulk-id lookup rolls back
/// the vault entry and propagates the error.
pub(crate) async fn commit_key<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    material: &HsmDmaBuf,
    kind: HsmVaultKeyKind,
    sess_id: HsmSessId,
    attrs: HsmVaultKeyAttrs,
) -> HsmResult<(HsmKeyId, Option<u16>)> {
    let handle = pal
        .vault_key_create(
            io,
            material,
            kind,
            attrs.session().then_some(sess_id),
            attrs,
        )
        .await?;
    let bulk_key_id = if is_bulk(kind) {
        match pal.bulk_key_id(io, handle) {
            Ok(id) => Some(id),
            // Roll back the just-created key so a lookup failure can't leave the
            // vault entry (and any backend registration) behind with no handle.
            Err(e) => {
                let _ = pal.vault_key_delete(io, handle).await;
                return Err(e);
            }
        }
    } else {
        None
    };
    Ok((handle, bulk_key_id))
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
