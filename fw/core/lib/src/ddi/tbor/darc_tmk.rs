// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared DARC Transfer Masking Key (TMK) masking helpers.
//!
//! A TMK is a 32-byte security-domain secret.  Whether it is *created*
//! on-device ([`DarcTmkGen`](super::darc_tmk_gen)) or *imported*
//! from an off-device seal ([`DarcTmkImport`](super::darc_tmk_import)),
//! it must be masked into a **byte-identical envelope** — same key kind,
//! attributes, and key label — so the two are interchangeable downstream
//! (e.g. `DarcTmkExport`).  Both handlers therefore mask through this one
//! definition rather than duplicating the metadata.

use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

/// Envelope key-label recorded in a masked TMK's `MaskedKeyMetadata`.
pub(super) const DARC_TMK_KEY_LABEL: &[u8] = b"DarcTmk";

/// Attributes recorded in a masked TMK's metadata (restored on
/// re-import): a security-domain-scoped derive key that never leaves the
/// device in the clear.
pub(super) fn tmk_key_attrs() -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_private(true)
        .with_never_extractable(true)
        .with_derive(true)
        .with_scope(HsmKeyScope::SecurityDomain)
}

/// Mask a 32-byte `tmk` (AEAD-GCM-256) under the security-domain masking
/// key `sdmk` into `out`, tagged with the canonical `DarcTmk` kind,
/// attributes, and key label.
///
/// The resulting envelope is fully deterministic in shape
/// (`header(8) ‖ iv(12) ‖ aad(96) ‖ ct(32) ‖ tag(16)` = 164 B) and
/// matches the one produced by `DarcTmkImport`, so a created TMK and an
/// imported TMK are interchangeable.
#[allow(clippy::too_many_arguments)]
pub(super) async fn mask_tmk<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    sdmk: &HsmDmaBuf,
    svn: u64,
    owner: u16,
    tmk: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let key_label = alloc.dma_alloc(DARC_TMK_KEY_LABEL.len())?;
    key_label.copy_from_slice(DARC_TMK_KEY_LABEL);
    let params = MaskParams {
        key_kind: HsmVaultKeyKind::DarcTmk,
        key_attrs: tmk_key_attrs(),
        svn,
        owner_seed_id: owner,
        key_label,
    };
    mask(
        pal,
        io,
        alloc,
        AeadAlg::AesGcm256,
        sdmk,
        &params,
        tmk,
        Some(out),
    )
    .await?;
    Ok(())
}
