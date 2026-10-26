// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcTmkImport` handler.
//!
//! Imports a DARC Transfer Masking Key (TMK) that was HPKE-sealed
//! off-device to a DARC key-exchange key (see
//! [`DarcKexKeyGen`](super::darc_kex_key_gen)) and re-masks it locally
//! under the partition security-domain masking key (SDMK) so the caller
//! can persist and later re-import it.
//!
//! It is `SdRestoreRemoteBackup`'s **open front-end** narrowed to a
//! single POTA-anchored certificate chain: it recovers the 32-byte TMK by
//! HPKE-Auth-opening `sealed_tmk` with the receiver's masked DARC
//! key-exchange private key, authenticated by the sender public key
//! recovered from the chain's terminal certificate.
//!
//! Flow:
//!
//! 1. Decode; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition whose security domain is initialized (the
//!    SDMK the output is masked under is provisioned by SD setup).
//! 2. Bind the caller-supplied [`PartPolicy`] to the partition's fixed
//!    `policy_hash`, then validate `remote_cert_chain` anchored to the
//!    policy `POTAPubKey`, recovering the terminal certificate's public
//!    key as `SndrPub`.
//! 3. Unmask `masked_kex_key` → `RcvrPriv` (must be a
//!    [`DarcKex`](HsmVaultKeyKind::DarcKex) key) and derive `RcvrPub`.
//! 4. HPKE-Auth-open `sealed_tmk` (`sk_r = RcvrPriv`, sender-auth
//!    `SndrPub`) → the 32-byte **TMK**.
//! 5. Re-mask the TMK under the SDMK and return the masked envelope.
//!    `RcvrPriv` and the TMK are zeroized before returning.
//!
//! The command **persists nothing** (no vault write, no lifecycle
//! advance), so it records no rollback on the undo log.  This command is
//! **Crypto-Officer-only**.
//!
//! [`PartPolicy`]: super::policy

use tsra_fw_core_crypto_hpke::open;
use tsra_fw_core_crypto_hpke::HpkeOpenConfig;
use tsra_fw_core_crypto_hpke::HpkeSuite;
use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_x509_chain::validate_chain;
use tsra_fw_ddi_tbor_types::evidence::MAX_CERTS;
use tsra_fw_ddi_tbor_types::policy::PolicyKeyKind;
use tsra_fw_ddi_tbor_types::policy::POLICY_MAX_KEY_LEN;
use tsra_fw_ddi_tbor_types::TborDarcTmkImportReq;
use tsra_fw_ddi_tbor_types::TborDarcTmkImportResp;
use tsra_fw_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_fw_ddi_tbor_types::TMK_LEN;
use tsra_fw_hsm_oob::copy_oob;
use tsra_fw_hsm_oob::OobPtr;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::masking_key_id_for_scope;
use super::part_final::verify_policy_hash;
use super::sd_backup;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// NIST curve for the DARC key-exchange key and the HPKE seal.
const DARC_CURVE: HsmEccCurve = HsmEccCurve::P384;

/// HPKE ciphersuite for the sealed TMK.
const HPKE_SUITE: HpkeSuite = HpkeSuite::DHKemP384Sha384AesGcm256;

/// SEC1 uncompressed point tag (`0x04 ‖ X ‖ Y`).
const SEC1_UNCOMPRESSED: u8 = 0x04;

/// Length of the HPKE encapsulated key `enc` (P-384 SEC1 uncompressed).
const DARC_ENC_LEN: usize = 1 + 2 * 48;

// The sealed TMK is `enc(97) ‖ ct(TMK 32 + GCM tag 16 = 48)` = 145 B.
const _: () = assert!(DARC_ENC_LEN + (TMK_LEN + 16) == tsra_fw_ddi_tbor_types::SEALED_TMK_LEN);

/// Validate `remote_cert_chain` and recover the terminal (leaf)
/// certificate's public key as the HPKE sender key `SndrPub`.
///
/// The chain travels out of band; it must carry `1..=MAX_CERTS`
/// certificates and be cryptographically anchored to the policy
/// `POTAPubKey`.  On success `sndr_pub` is the SEC1-uncompressed
/// (`0x04 ‖ X ‖ Y`) sender public key.
async fn recover_sender_pub<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    alloc: &impl HsmScopedAlloc,
    oob: &OobPtr,
    req_buf: &DmaBuf,
    sndr_pub: &mut DmaBuf,
) -> HsmResult<()> {
    // The re-supplied policy must match the one bound at `PartInit`; only
    // then is its `POTAPubKey` a trustworthy anchor.
    let req = TborDarcTmkImportReq::decode(req_buf)?;
    let policy = req.policy();
    verify_policy_hash(pal, io, alloc, policy).await?;

    let part_policy = super::policy::from_bytes(policy)?;
    let pota = &part_policy.pota_pub_key;
    if pota.kind() != PolicyKeyKind::Ecc384 || pota.len() != POLICY_MAX_KEY_LEN {
        return Err(HsmError::InvalidArg);
    }
    let anchor = &pota.data[..POLICY_MAX_KEY_LEN];

    let cert_descriptors = req.remote_cert_chain();
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
        &mut sndr_pub[1..1 + POLICY_MAX_KEY_LEN],
        async |index, buf| copy_oob(pal, io, oob, index, buf).await,
    )
    .await?;
    sndr_pub[0] = SEC1_UNCOMPRESSED;

    Ok(())
}

/// Handle a TBOR `DarcTmkImport` request.
///
/// **Stateless**: recovers the sealed TMK and returns it re-masked under
/// the SDMK without writing the vault or advancing any lifecycle, so it
/// records no rollback on the `undo` log.  Every recovered secret
/// (`RcvrPriv`, the TMK) is scrubbed on EVERY exit path — scope rewind
/// does not clear DMA memory.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
    oob: Option<OobPtr>,
) -> HsmResult<&'p DmaBuf> {
    // Session/state gating + masking-key routing use only the shared
    // `decode` view.  Both ids are `Copy`, so they outlive the view.
    let (kex_mk_id, sdmk_id): (HsmKeyId, HsmKeyId) = {
        let req = TborDarcTmkImportReq::decode(req_buf)?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_crypto_officer_active_session(pal, io, sess_id)?;

        // The SDMK the output is masked under is provisioned by SD setup,
        // which requires a finalized partition.
        if !part_state::part_state(pal, io)?.is_finalized() {
            return Err(HsmError::InvalidArg);
        }
        if !part_state::part_is_sd_initialized(pal, io)? {
            return Err(HsmError::InvalidArg);
        }

        // Route the masked receiver key to its masking key via the
        // cleartext, tag-bound metadata (before unmasking).
        let kex_scope = peek_metadata(req.masked_kex_key())?.usage_flags().scope();
        let kex_mk_id = masking_key_id_for_scope(pal, io, kex_scope)?;
        let sdmk_id = masking_key_id_for_scope(pal, io, HsmKeyScope::SecurityDomain)?;
        (kex_mk_id, sdmk_id)
    };

    // The sender certificate chain is mandatory side-band data carried in
    // the out-of-band SGL page.
    let oob = oob.ok_or(HsmError::InvalidArg)?;

    // Allocate the fixed-size output envelope in the IO scope so it
    // survives the crypto scratch allocator's reset.
    let masked_tmk_out = pal.dma_alloc(io, MASKED_TMK_LEN)?;

    pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
        let coord = DARC_CURVE.priv_key_len();
        let (svn, owner) = sd_backup::platform_svn_owner(pal)?;

        // ── Phase 1: policy binding + POTA-anchored sender chain ──
        let sndr_pub = alloc.dma_alloc(1 + 2 * coord)?;
        recover_sender_pub(pal, io, alloc, &oob, req_buf, sndr_pub).await?;

        // ── Phase 2: recover RcvrPriv, HPKE-open the sealed TMK, and
        // re-mask it under the SDMK.  The masked receiver key and sealed
        // TMK are copied into crypto scratch so the request-buffer borrow
        // is confined; every recovered secret is scrubbed on EVERY exit
        // path (scope rewind does not clear DMA).
        let kex_masking_key = pal.vault_key(io, kex_mk_id)?;

        let blob = alloc.dma_alloc(tsra_fw_ddi_tbor_types::MASKED_KEX_KEY_LEN)?;
        let sealed = alloc.dma_alloc(tsra_fw_ddi_tbor_types::SEALED_TMK_LEN)?;
        {
            let req = TborDarcTmkImportReq::decode(req_buf)?;
            blob.copy_from_slice(req.masked_kex_key());
            sealed.copy_from_slice(req.sealed_tmk());
        }

        // Unmask into `blob`, copy the recovered private key out into its
        // own scratch, then scrub `blob` immediately.
        let unmask_res = async {
            let view = unmask(pal, io, kex_masking_key, blob).await?;
            let rcvr_priv = alloc.dma_alloc(view.target_key.len())?;
            rcvr_priv.copy_from_slice(view.target_key);
            Ok::<_, HsmError>((view.key_kind, rcvr_priv))
        }
        .await;
        blob.zeroize();
        let (key_kind, rcvr_priv) = unmask_res?;

        let crypto_res = async {
            if !matches!(key_kind, HsmVaultKeyKind::DarcKex) {
                return Err(HsmError::UnsupportedKeyType);
            }

            // Receiver public key (`RcvrPub`) in SEC1 BE, derived on-device
            // from the recovered private key.
            let pk_r = alloc.dma_alloc(1 + 2 * coord)?;
            pal.ecc_pub_from_priv(io, DARC_CURVE, rcvr_priv, &mut pk_r[1..1 + 2 * coord])
                .await?;
            pk_r[0] = SEC1_UNCOMPRESSED;
            pk_r[1..1 + coord].reverse();
            pk_r[1 + coord..1 + 2 * coord].reverse();

            // HPKE `open` needs a plaintext buffer at least the ciphertext
            // length (`ct` = TMK + GCM tag = 48 B); the recovered TMK
            // occupies its first `TMK_LEN` bytes.
            let pt_buf = alloc.dma_alloc(tsra_fw_ddi_tbor_types::SEALED_TMK_LEN - DARC_ENC_LEN)?;
            let tmk = alloc.dma_alloc(TMK_LEN)?;
            let inner = async {
                // ── Open the sealed TMK with RcvrPriv, authenticated by
                // the sender key (`SndrPub`).
                let (enc, ct) = sealed.split_at(DARC_ENC_LEN);
                let open_cfg =
                    HpkeOpenConfig::auth(HPKE_SUITE, rcvr_priv, pk_r, &[], &[], sndr_pub);
                let pt_len =
                    open(pal, io, &open_cfg, enc, ct, Some(&mut pt_buf[..]), alloc).await?;
                if pt_len != TMK_LEN {
                    return Err(HsmError::InvalidArg);
                }
                tmk.copy_from_slice(&pt_buf[..TMK_LEN]);

                // ── Re-mask the TMK under the SDMK (shared envelope with
                // `DarcTmkGen` so created / imported TMKs match).
                let sdmk = pal.vault_key(io, sdmk_id)?;
                super::darc_tmk::mask_tmk(pal, io, alloc, sdmk, svn, owner, tmk, masked_tmk_out)
                    .await?;
                Ok(())
            }
            .await;

            tmk.zeroize();
            pt_buf.zeroize();
            inner
        }
        .await;

        // Scrub the recovered receiver private key on every path.
        rcvr_priv.zeroize();
        crypto_res?;

        Ok(())
    })
    .await?;

    encode_response(pal, io, masked_tmk_out)
}

/// Encode the `DarcTmkImport` response around the masked TMK.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    masked_tmk: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborDarcTmkImportResp::encode(buf, 0, false)?
            .masked_tmk(masked_tmk)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
