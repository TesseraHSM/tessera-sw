// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcTmkExport` handler.
//!
//! Seals a locally-masked DARC Transfer Masking Key (TMK) to a remote
//! **target** so the target can import it with
//! [`DarcTmkImport`](super::darc_tmk_import).  It is the source-side
//! mirror of `DarcTmkImport`: where import opens a `sealed_tmk` and
//! re-masks it under the SDMK, export unmasks a local `masked_tmk` and
//! HPKE-Auth-seals it to the target.
//!
//! It is `SdCreateRemoteBackup`'s **seal front-end** narrowed to a single
//! DATA-anchored certificate chain (the export-side mirror of the
//! `POTAPubKey`-anchored sender chain `DarcTmkImport` verifies).
//!
//! Flow:
//!
//! 1. Decode; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition whose security domain is initialized.
//! 2. Bind the caller-supplied [`PartPolicy`] to the partition's fixed
//!    `policy_hash`, then validate `target_cert_chain` anchored to the
//!    policy `DATAPubKey`, recovering the terminal certificate's public
//!    key as `RcvrPub`.
//! 3. Unmask `masked_sender_key` → `SndrPriv` (must be a
//!    [`DarcKex`](HsmVaultKeyKind::DarcKex) key) and derive `SndrPub`.
//! 4. Unmask `masked_tmk` → the 32-byte **TMK** (must be a
//!    [`DarcTmk`](HsmVaultKeyKind::DarcTmk) key).
//! 5. HPKE-Auth-seal the TMK to `RcvrPub` (sender-auth `SndrPriv`) →
//!    the 145-byte `sealed_tmk`, byte-compatible with `DarcTmkImport`.
//!
//! The command **persists nothing** (no vault write, no lifecycle
//! advance), so it records no rollback on the undo log.  This command is
//! **Crypto-Officer-only**.  Every recovered secret (`SndrPriv`, the TMK)
//! is scrubbed on EVERY exit path — scope rewind does not clear DMA
//! memory, and `unmask` decrypts in place.
//!
//! [`PartPolicy`]: super::policy

use tsra_fw_core_crypto_hpke::seal;
use tsra_fw_core_crypto_hpke::AuthParams;
use tsra_fw_core_crypto_hpke::HpkeSealConfig;
use tsra_fw_core_crypto_hpke::HpkeSuite;
use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_x509_chain::validate_chain;
use tsra_fw_ddi_tbor_types::evidence::MAX_CERTS;
use tsra_fw_ddi_tbor_types::policy::PolicyKeyKind;
use tsra_fw_ddi_tbor_types::policy::POLICY_MAX_KEY_LEN;
use tsra_fw_ddi_tbor_types::TborDarcTmkExportReq;
use tsra_fw_ddi_tbor_types::TborDarcTmkExportResp;
use tsra_fw_ddi_tbor_types::MASKED_KEX_KEY_LEN;
use tsra_fw_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_fw_ddi_tbor_types::SEALED_TMK_LEN;
use tsra_fw_ddi_tbor_types::TMK_LEN;
use tsra_fw_hsm_oob::copy_oob;
use tsra_fw_hsm_oob::OobPtr;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// NIST curve for the DARC key-exchange key and the HPKE seal.
const DARC_CURVE: HsmEccCurve = HsmEccCurve::P384;

/// HPKE ciphersuite for the sealed TMK.
const HPKE_SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

/// SEC1 uncompressed point tag (`0x04 ‖ X ‖ Y`).
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Validate `target_cert_chain` and recover the terminal (leaf)
/// certificate's public key as the HPKE receiver key `RcvrPub`.
///
/// The chain travels out of band; it must carry `1..=MAX_CERTS`
/// certificates and be cryptographically anchored to the policy
/// `DATAPubKey`.  On success `rcvr_pub` is the SEC1-uncompressed
/// (`0x04 ‖ X ‖ Y`) receiver public key.
async fn recover_target_pub<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    oob: &OobPtr,
    req_buf: &DmaBuf,
    rcvr_pub: &mut DmaBuf,
) -> HsmResult<()> {
    // The re-supplied policy must match the one bound at `PartInit`; only
    // then is its `DATAPubKey` a trustworthy anchor.
    let req = TborDarcTmkExportReq::decode(req_buf)?;
    let policy = req.policy();
    verify_policy_hash(pal, io, alloc, policy).await?;

    let part_policy = super::policy::from_bytes(policy)?;
    let data = &part_policy.data_pub_key;
    if data.kind() != PolicyKeyKind::Ecc384 || data.len() != POLICY_MAX_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    let anchor = &data.data[..POLICY_MAX_KEY_LEN];

    let cert_descriptors = req.target_cert_chain();
    if cert_descriptors.is_empty() || cert_descriptors.len() > MAX_CERTS {
        return Err(HsmError::InvalidArg);
    }

    // `validate_chain` fills `leaf_out` with the leaf public key (raw
    // big-endian `X ‖ Y`); recover it into the SEC1 buffer's coordinate
    // region and prepend the uncompressed tag.
    validate_chain(
        pal,
        io,
        alloc,
        cert_descriptors,
        Some(anchor),
        &mut rcvr_pub[1..1 + POLICY_MAX_KEY_LEN],
        async |index, buf| copy_oob(pal, io, oob, index, buf).await,
    )
    .await?;
    rcvr_pub[0] = SEC1_UNCOMPRESSED;

    Ok(())
}

/// Handle a TBOR `DarcTmkExport` request.
///
/// **Stateless**: recovers the local TMK and returns it HPKE-Auth-sealed
/// to the target without writing the vault or advancing any lifecycle, so
/// it records no rollback on the `undo` log.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
    oob: Option<OobPtr>,
) -> HsmResult<&'p DmaBuf> {
    // Session/state gating + masking-key routing use only the shared
    // `decode` view.  Both ids are `Copy`, so they outlive the view.
    let (sender_mk_id, tmk_mk_id): (HsmKeyId, HsmKeyId) = {
        let req = TborDarcTmkExportReq::decode(req_buf)?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_crypto_officer_active_session(pal, io, sess_id)?;

        // The SDMK the input TMK is masked under is provisioned by SD
        // setup, which requires a finalized partition.
        if !part_state::part_state(pal, io)?.is_finalized() {
            return Err(HsmError::InvalidArg);
        }
        if !part_state::part_is_sd_initialized(pal, io)? {
            return Err(HsmError::InvalidArg);
        }

        // Route each masked input to its masking key via the cleartext,
        // tag-bound metadata (before unmasking).
        let sender_scope = peek_metadata(req.masked_sender_key())?
            .usage_flags()
            .scope();
        let sender_mk_id = masking_key_id_for_scope(pal, io, sender_scope)?;
        let tmk_scope = peek_metadata(req.masked_tmk())?.usage_flags().scope();
        let tmk_mk_id = masking_key_id_for_scope(pal, io, tmk_scope)?;
        (sender_mk_id, tmk_mk_id)
    };

    // The target certificate chain is mandatory side-band data carried in
    // the out-of-band SGL page.
    let oob = oob.ok_or(HsmError::InvalidArg)?;

    // Allocate the fixed-size output seal in the IO scope so it survives
    // the crypto scratch allocator's reset.
    let sealed_tmk_out = pal.dma_alloc(io, SEALED_TMK_LEN)?;

    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        let coord = DARC_CURVE.priv_key_len();

        // ── Phase 1: policy binding + DATA-anchored target chain ──
        let pk_r = alloc.dma_alloc(1 + 2 * coord)?;
        recover_target_pub(pal, io, alloc, &oob, req_buf, pk_r).await?;

        // ── Phase 2: recover SndrPriv + TMK, then HPKE-Auth seal the TMK
        // to RcvrPub.  The masked inputs are copied into crypto scratch so
        // the request-buffer borrow is confined; `unmask` decrypts in
        // place, so each scratch blob holds plaintext secret after and is
        // scrubbed immediately.  Every recovered secret is scrubbed on
        // EVERY exit path (scope rewind does not clear DMA).
        let sender_blob = alloc.dma_alloc(MASKED_KEX_KEY_LEN)?;
        let tmk_blob = alloc.dma_alloc(MASKED_TMK_LEN)?;
        {
            let req = TborDarcTmkExportReq::decode(req_buf)?;
            sender_blob.copy_from_slice(req.masked_sender_key());
            tmk_blob.copy_from_slice(req.masked_tmk());
        }

        // Unmask the sender key into `sender_blob`, copy the recovered
        // private key out into its own scratch, then scrub `sender_blob`.
        let sender_masking_key = pal.vault_key(io, sender_mk_id)?;
        let unmask_sender = async {
            let view = unmask(pal, io, sender_masking_key, sender_blob).await?;
            if !matches!(view.key_kind, HsmVaultKeyKind::DarcKex) {
                return Err(HsmError::UnsupportedKeyType);
            }
            let sndr_priv = alloc.dma_alloc(view.target_key.len())?;
            sndr_priv.copy_from_slice(view.target_key);
            Ok::<_, HsmError>(sndr_priv)
        }
        .await;
        sender_blob.zeroize();
        let sndr_priv = unmask_sender?;

        // From here `sndr_priv` holds a private key and MUST be scrubbed on
        // every path.  Its scrub lives *outside* `crypto_res`, so every
        // allocation that could fail after `sndr_priv` is recovered — the
        // TMK buffer included — must stay *inside* `crypto_res`; otherwise
        // an early `?` would rewind the scope (which does not clear DMA)
        // before the unconditional scrub below.
        let crypto_res = async {
            // The recovered TMK likewise MUST be scrubbed on every path
            // once populated, so it is scrubbed here (inside `crypto_res`)
            // after the `inner` block, whatever its outcome.
            let tmk = alloc.dma_alloc(TMK_LEN)?;
            let inner = async {
                // Unmask the masked TMK into `tmk_blob`, copy the 32-byte
                // TMK out, then scrub `tmk_blob`.
                let tmk_masking_key = pal.vault_key(io, tmk_mk_id)?;
                let unmask_tmk = async {
                    let view = unmask(pal, io, tmk_masking_key, tmk_blob).await?;
                    if !matches!(view.key_kind, HsmVaultKeyKind::DarcTmk) {
                        return Err(HsmError::UnsupportedKeyType);
                    }
                    if view.target_key.len() != TMK_LEN {
                        return Err(HsmError::InvalidArg);
                    }
                    tmk.copy_from_slice(view.target_key);
                    Ok::<_, HsmError>(())
                }
                .await;
                tmk_blob.zeroize();
                unmask_tmk?;

                // Sender public key (`SndrPub`) in SEC1 BE, derived
                // on-device from the recovered private key.  The PAL emits
                // wire-LE `X ‖ Y`; reversing each coordinate in place yields
                // SEC1 `0x04 ‖ X_be ‖ Y_be`.
                let pk_s = alloc.dma_alloc(1 + 2 * coord)?;
                pal.ecc_pub_from_priv(io, DARC_CURVE, sndr_priv, &mut pk_s[1..1 + 2 * coord])
                    .await?;
                pk_s[0] = SEC1_UNCOMPRESSED;
                pk_s[1..1 + coord].reverse();
                pk_s[1 + coord..1 + 2 * coord].reverse();

                // ── HPKE-Auth seal the TMK to RcvrPub ────────────────
                let cfg = HpkeSealConfig::auth(
                    HPKE_SUITE,
                    pk_r,
                    &[],
                    &[],
                    AuthParams {
                        sk_s: sndr_priv,
                        pk_s,
                    },
                );

                // Size query, then split the response buffer into the `enc`
                // and `ct` regions the seal writes.
                let sizes = seal(pal, io, &cfg, tmk, None, None, alloc).await?;
                if sizes.enc_len + sizes.ct_len != SEALED_TMK_LEN {
                    return Err(HsmError::InternalError);
                }
                let (enc, ct) = sealed_tmk_out.split_at_mut(sizes.enc_len);
                seal(pal, io, &cfg, tmk, Some(enc), Some(ct), alloc).await?;
                Ok::<_, HsmError>(())
            }
            .await;
            tmk.zeroize();
            inner
        }
        .await;

        // Scrub the recovered sender private key on every path.
        sndr_priv.zeroize();
        crypto_res
    })
    .await?;

    encode_response(pal, io, sealed_tmk_out)
}

/// Encode the `DarcTmkExport` response around the sealed TMK.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    sealed_tmk: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborDarcTmkExportResp::encode(buf, 0, false)?
            .sealed_tmk(sealed_tmk)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
