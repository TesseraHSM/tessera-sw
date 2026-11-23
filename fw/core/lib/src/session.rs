// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session-scoped helpers shared across DDI handlers.
//!
//! Currently this exposes [`session_app_id`], which projects the
//! public [`APP_ID_LEN`]-byte AppId out of the partition PSK bound
//! to a given session.  See [`tsra_fw_hsm_pal_traits::PSK_LEN`]
//! for the `app_id ‖ app_pin` PSK layout.

use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionRole;
use tsra_fw_hsm_pal_traits::HsmSqe;
use tsra_fw_hsm_pal_traits::APP_ID_LEN;
use tsra_fw_hsm_pal_traits::DEFAULT_PSK_CU;
use tsra_fw_hsm_pal_traits::PSK_LEN;
use tsra_fw_hsm_pal_traits::SESSION_AUTH_BINDING_LEN;

/// Snapshot vault-backed session identity before any asynchronous work.
pub(crate) fn copy_auth_binding<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    id: HsmSessId,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let source = pal.session_auth_binding(io, id)?;
    if source.len() != SESSION_AUTH_BINDING_LEN {
        return Err(HsmError::InvalidPermissions);
    }
    let binding = alloc.dma_alloc(SESSION_AUTH_BINDING_LEN)?;
    binding.copy_from_slice(source);
    Ok(binding)
}

/// Capture the credential actually used by the HPKE handshake.
pub(crate) async fn capture_auth_binding<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    role: HsmSessionRole,
    psk: &HsmDmaBuf,
) -> HsmResult<&'a mut HsmDmaBuf> {
    if psk.len() != PSK_LEN {
        return Err(HsmError::InvalidArg);
    }
    let binding = alloc.dma_alloc(SESSION_AUTH_BINDING_LEN)?;
    binding[..4].copy_from_slice(&u32::from(role == HsmSessionRole::CryptoUser).to_le_bytes());
    binding[4..4 + APP_ID_LEN].copy_from_slice(&psk[..APP_ID_LEN]);
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        psk,
        HsmDigestForm::Standard,
        Some(&mut binding[4 + APP_ID_LEN..]),
    )
    .await?;
    Ok(binding)
}

/// Reject a role mismatch or a session authenticated with an obsolete PSK.
pub(crate) async fn validate_auth_binding<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    id: HsmSessId,
    binding: &[u8],
) -> HsmResult<()> {
    let role = id.role();
    let expected_role = u32::from(role == HsmSessionRole::CryptoUser).to_le_bytes();
    if binding.len() != SESSION_AUTH_BINDING_LEN || binding[..4] != expected_role {
        return Err(HsmError::InvalidPermissions);
    }
    let psk_id = u8::from(role == HsmSessionRole::CryptoUser);
    let psk = alloc.dma_alloc(PSK_LEN)?;
    psk.copy_from_slice(crate::part_state::part_psk(pal, io, psk_id)?);
    let digest = alloc.dma_alloc(48)?;
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        psk,
        HsmDigestForm::Standard,
        Some(digest),
    )
    .await?;
    if digest[..] != binding[4 + APP_ID_LEN..] {
        if role == HsmSessionRole::CryptoUser {
            psk.copy_from_slice(&DEFAULT_PSK_CU);
            pal.hash(
                io,
                HsmHashAlgo::Sha384,
                psk,
                HsmDigestForm::Standard,
                Some(digest),
            )
            .await?;
            if digest[..] == binding[4 + APP_ID_LEN..] {
                return Err(HsmError::DefaultPskChanged);
            }
        }
        return Err(HsmError::SessionAuthFailure);
    }
    Ok(())
}

/// Apply CU credential policy to the bulk path, which bypasses TBOR dispatch.
///
/// The binding is copied to the stack rather than the IO's DMA heap: it is
/// only compared, and a platform may give a bulk IO a small heap (Uno uses
/// the IO's 128-byte bulk scratch), which then needs to hold only the PSK
/// and its digest.
pub(crate) async fn validate_bulk_session<P: HsmPal>(pal: &P, io: &P::Io) -> HsmResult<()> {
    let id = HsmSessId::from(io.sqe().session_id().ok_or(HsmError::SessionNotFound)?);
    if id.role() != HsmSessionRole::CryptoUser {
        return Ok(());
    }
    let mut binding = [0u8; SESSION_AUTH_BINDING_LEN];
    match pal.session_auth_binding(io, id) {
        Ok(source) if source.len() == SESSION_AUTH_BINDING_LEN => binding.copy_from_slice(source),
        Ok(_) => return Err(HsmError::InvalidPermissions),
        // Legacy MBOR sessions have no SessionEx binding and retain
        // their existing bulk authorization and key-binding rules.
        Err(HsmError::InvalidPermissions) => return Ok(()),
        Err(err) => return Err(err),
    }
    pal.alloc_scoped_async(io, async |alloc| {
        validate_auth_binding(pal, io, alloc, id, &binding).await?;
        if crate::part_state::part_psk_is_default(pal, io, 1)? {
            return Err(HsmError::DefaultPskMustRotate);
        }
        Ok(())
    })
    .await
}

/// Returns the public AppId bound to `sess_id`'s partition PSK slot.
///
/// The PSK is structured as `app_id (16) ‖ app_pin (16)` (see
/// [`PSK_LEN`]); this helper loads the PSK by the slot implied by
/// the session role (CO → slot 0, CU → slot 1) and copies its first
/// [`APP_ID_LEN`] bytes into the returned array.  The PIN portion
/// is zeroized from the temporary buffer before return; the AppId
/// itself is public by design (it is surfaced in attestation
/// reports such as PTAReport).
///
/// Callers must validate the session's authentication binding under the
/// partition credential lock before using the current credential's AppId.
///
/// # Parameters
///
/// - `pal` — PAL implementation.
/// - `io` — caller's I/O context (partition scope).
/// - `sess_id` — Active session slot.
///
/// # Returns
///
/// - `Ok(app_id)` on success.
/// - Any error propagated from
///   [`HsmPartitionManager::part_psk`](tsra_fw_hsm_pal_traits::HsmPartitionManager::part_psk),
///   notably `PartitionNotEnabled` / `InvalidArg` if the partition
///   is no longer active.
pub fn session_app_id<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    sess_id: HsmSessId,
) -> HsmResult<[u8; APP_ID_LEN]> {
    let psk_id = u8::from(sess_id.role() == tsra_fw_hsm_pal_traits::HsmSessionRole::CryptoUser);

    let mut app_id = [0u8; APP_ID_LEN];
    let res = crate::part_state::part_psk(pal, io, psk_id);
    if let Ok(psk_buf) = res.as_ref() {
        app_id.copy_from_slice(&psk_buf[..APP_ID_LEN]);
    }
    res.map(|_| app_id)
}
