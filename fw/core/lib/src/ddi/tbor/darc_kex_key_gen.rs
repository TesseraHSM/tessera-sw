// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcKexKeyGen` handler.
//!
//! Generates a fresh DARC key-exchange key — a P-384 ECC keypair for
//! ECDH key agreement — under the active session's partition, and
//! returns the **masked** private key plus the public key.
//!
//! The private key is **not** stored on the device.  Instead it is
//! masked (AEAD-GCM-256) under the masking key associated with the
//! requested [`scope`](HsmKeyScope) and the masked blob is returned to
//! the caller, which re-imports it (unmask-on-use) when the key is later
//! needed.  Because nothing is persisted, the command records no
//! rollback on the undo log.
//!
//! Scope → masking key:
//!
//! * [`Ephemeral`](HsmKeyScope::Ephemeral) → the partition
//!   [`PartitionEphemeralMaskingKey`](HsmVaultKeyKind::PartitionEphemeralMaskingKey).
//! * [`Local`](HsmKeyScope::Local) → the partition
//!   [`PartitionLocalMaskingKey`](HsmVaultKeyKind::PartitionLocalMaskingKey).
//!
//! Both masking keys are provisioned by `PartFinal`, so this command
//! requires a partition in the [`Initialized`](HsmPartState::Initialized)
//! lifecycle state.  The [`Session`](HsmKeyScope::Session) and
//! [`SecurityDomain`](HsmKeyScope::SecurityDomain) scopes (and any other)
//! are rejected with [`HsmError::UnsupportedKeyScope`] until their
//! masking keys exist.
//!
//! This command is **Crypto-Officer-only**: a Crypto-User session is
//! rejected with [`HsmError::InvalidPermissions`].

use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::TborDarcKexKeyGenReq;
use tsra_fw_ddi_tbor_types::TborDarcKexKeyGenResp;
use tsra_fw_ddi_tbor_types::MASKED_KEX_KEY_LEN;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmEccPct;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmPartState;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::masking_key_id_for_scope;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// NIST curve for DARC key-exchange keys.  Fixed at P-384 to match the
/// SD sealing / session / establish-cred key material elsewhere in the
/// firmware.
const DARC_KEX_CURVE: HsmEccCurve = HsmEccCurve::P384;

/// Envelope key-label recorded in the masked blob's `MaskedKeyMetadata`.
const DARC_KEX_KEY_LABEL: &[u8] = b"DarcKexKey";

/// Attributes recorded in the masked blob's metadata (restored on
/// re-import).  Per the key-exchange-key contract the only usage
/// attribute is `derive`; `local`/`private`/`never_extractable` are
/// HSM-internal flags, and `scope` records the lifecycle / visibility
/// domain.
fn kex_key_attrs(scope: HsmKeyScope) -> HsmVaultKeyAttrs {
    HsmVaultKeyAttrs::new()
        .with_local(true)
        .with_private(true)
        .with_never_extractable(true)
        .with_derive(true)
        .with_scope(scope)
}

async fn generate_kex_keypair<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
) -> HsmResult<(&'p mut HsmDmaBuf, &'p mut HsmDmaBuf)> {
    // Generate the P-384 keypair for ECDH.  The buffers must outlive the
    // scoped keygen-scratch allocator, so allocate them between the two
    // query/use calls rather than inside one scope.
    let (priv_key_size, pub_key_size) = pal
        .alloc_scoped_async(io, async |a| {
            pal.ecc_gen_keypair(io, a, DARC_KEX_CURVE, None, HsmEccPct::KeyAgreement)
                .await
        })
        .await?;
    let priv_key = pal.dma_alloc(io, priv_key_size)?;
    let pub_key = pal.dma_alloc(io, pub_key_size)?;
    let (priv_key_len, pub_key_len) = pal
        .alloc_scoped_async(io, async |a| -> HsmResult<_> {
            pal.ecc_gen_keypair(
                io,
                a,
                DARC_KEX_CURVE,
                Some((&mut *priv_key, &mut *pub_key)),
                HsmEccPct::KeyAgreement,
            )
            .await
        })
        .await?;

    Ok((&mut priv_key[..priv_key_len], &mut pub_key[..pub_key_len]))
}

async fn mask_kex_private_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    mk_key_id: HsmKeyId,
    attrs: HsmVaultKeyAttrs,
    svn: u64,
    owner: u16,
    priv_key: &HsmDmaBuf,
) -> HsmResult<&'p mut HsmDmaBuf> {
    let masked_key = pal.dma_alloc(io, MASKED_KEX_KEY_LEN)?;

    // The masked blob lives in an IO-scoped buffer allocated before the
    // masking scope so it survives the scratch allocator's reset.
    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        let masking_key = pal.vault_key(io, mk_key_id)?;
        let key_label = alloc.dma_alloc(DARC_KEX_KEY_LABEL.len())?;
        key_label.copy_from_slice(DARC_KEX_KEY_LABEL);
        let params = MaskParams {
            key_kind: HsmVaultKeyKind::DarcKex,
            key_attrs: attrs,
            svn,
            owner_seed_id: owner,
            key_label,
        };
        mask(
            pal,
            io,
            alloc,
            AeadAlg::AesGcm256Iv16,
            masking_key,
            &params,
            priv_key,
            Some(masked_key),
        )
        .await?;
        Ok(())
    })
    .await?;

    Ok(masked_key)
}

fn encode_kex_response(
    cmd_buf: &mut HsmCmdBuf<'_>,
    masked_key: &HsmDmaBuf,
    pub_key: &HsmDmaBuf,
) -> HsmResult<usize> {
    let resp = cmd_buf.encode_response(|buf| {
        let frame = TborDarcKexKeyGenResp::encode(buf, 0, false)?
            .masked_key(masked_key)?
            .pub_key(pub_key)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}

/// Handle a TBOR `DarcKexKeyGen` request.
///
/// No partition lock or undo log is required: the command **persists
/// nothing** — it reads partition state and returns a freshly generated,
/// masked keypair.  It makes no observable state change, so a
/// concurrently-dispatched command (IOs run in a task pool and interleave
/// at await points) can neither observe it half-done nor require its
/// rollback on failure.  The raw private scalar is wiped from the per-IO
/// DMA pool during IO teardown.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let req = TborDarcKexKeyGenReq::decode(cmd_buf.request())?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));

    // Losslessly map the wire `KeyScope` onto the PAL `HsmKeyScope`
    // (byte-identical 3-bit discriminants; unknown values round-trip).
    let scope = HsmKeyScope(req.scope().0);
    validate_crypto_officer_active_session(pal, io, sess_id)?;

    // The scope's masking key is provisioned by `PartFinal`, so the
    // partition must be finalized (`Initialized`).
    if part_state::part_state(pal, io)? != HsmPartState::Initialized {
        return Err(HsmError::InvalidArg);
    }

    // Resolve (and validate) the masking key before generating anything,
    // so an unsupported scope fails cheaply.
    let mk_key_id = masking_key_id_for_scope(pal, io, scope)?;

    // Platform identity that binds the masked blob (anti-rollback on
    // re-import): SVN (BKS1 lineage) and owner-seed id (BKS2 lineage).
    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    let attrs = kex_key_attrs(scope);
    let (priv_key, pub_key) = generate_kex_keypair(pal, io).await?;
    let masked_key =
        mask_kex_private_key(pal, io, mk_key_id, attrs, svn, owner, &priv_key[..]).await?;

    // Encode the response: the masked private key plus the public key.
    // The PAL already emitted the public key in wire format (little-endian),
    // so copy it through unchanged.
    encode_kex_response(cmd_buf, masked_key, pub_key)
}
