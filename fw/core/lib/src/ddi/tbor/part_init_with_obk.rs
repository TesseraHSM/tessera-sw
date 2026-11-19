// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartInitWithObk` handler — owner-backup-key (OBK) partition
//! provisioning inside a v2 session.
//!
//! `PartInitWithObk` is a CO-session command that provisions an `Enabled`
//! partition from the masked owner backup key (MOBK) that UEFI sealed with
//! the TPM.  It fuses the roles of [`PartInit`](super::part_init) and
//! [`PartFinal`](super::part_final) for the OBK trust model, which has no
//! CSR / certificate round trip: the host opens a session first, then
//! provisions — the v1 `EstablishCredential` provisioning step, reachable
//! from a v2 session.
//!
//! Flow:
//!
//! 1. **Parse + gate** — CO-only `Active` session whose credential is still
//!    current; the partition must be `Enabled` and untouched by the v1
//!    (`EstablishCredential`) or v2 (`PartInit` / `PartFinal`) flows.
//! 2. **Open the MOBK** — AEAD-open the `mobk_envelope` under the session's
//!    `param_key` and check its AAD binds this command and session.
//! 3. **Trust gate** — verify the POTA endorsement of the partition identity
//!    (`SHA-384(0x04 ‖ PID public key)`), then unmask BK3 from the MOBK
//!    under the partition's `BK_BOOT`.
//! 4. **Masking keys** — derive `PartLocalBMK` from BK3 (bound to the POTA
//!    public key); generate a fresh `PartLocalMK` or restore it from
//!    `prev_local_mk_backup`; provision the random `EphemeralMK`.
//! 5. **Commit** — vault the new keys (recording their ids) and advance the
//!    lifecycle to [`HsmPartState::Initialized`].
//! 6. **Respond** — return the current `local_mk_backup`.
//!
//! BK3 and `PartLocalBMK` live only in scoped scratch that IO teardown
//! scrubs; nothing derived from BK3 is persisted except the masked
//! `local_mk_backup` the host stores.
//!
//! The key-handling helpers deliberately mirror those of `PartFinal`, rooted
//! in BK3 instead of UPS, so this command shares no code with — and cannot
//! change the behaviour of — the existing provisioning commands.

use tsra_fw_core_crypto_aead_envelope::open as aead_open;
use tsra_fw_core_crypto_key_derive::derive_masking_key;
use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_core_crypto_key_masking::cbc;
use tsra_fw_ddi_tbor_types::build_part_init_with_obk_aad;
use tsra_fw_ddi_tbor_types::TborPartInitWithObkReq;
use tsra_fw_ddi_tbor_types::TborPartInitWithObkResp;
use tsra_fw_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use tsra_fw_ddi_tbor_types::PART_INIT_OBK_AAD_LEN;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmPartPropId;
use tsra_fw_hsm_pal_traits::HsmPartState;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_hsm_pal_traits::HsmVaultPct;
use tsra_fw_hsm_pal_traits::BK_BOOT_LEN;
use tsra_fw_hsm_pal_traits::SESSION_PARAM_KEY_LEN;
use tsra_fw_hsm_undo::UndoLog;

use super::validate_crypto_officer_active_session;
use crate::part_state;

/// BK3 plaintext length in bytes (the 48-byte owner backup key).
const BK3_LEN: usize = 48;

/// Length of a raw P-384 public key (`x ‖ y`, two 48-byte coordinates).
const P384_PUB_RAW_LEN: usize = 2 * 48;

/// AES-256-GCM masking-key length (the v2 AEAD envelope key).
const MASKING_KEY_LEN: usize = 32;

/// `PartLocalMK` length (the masked plaintext / `local_mk`).
const PART_LOCAL_MK_LEN: usize = 32;

/// `EphemeralMK` length (random masking key).
const EPHEMERAL_MK_LEN: usize = 32;

/// BK3 → `PartLocalBMK` masking-key derivation label (KBKDF), following the
/// `TSRA-<Command>-<Purpose>-v<N>` naming.  The POTA public key is the extra
/// context, so a backup only restores under the same POTA.
const PART_LOCAL_BMK_LABEL: &[u8] = b"TSRA-PartInitWithObk-PartLocalBMK-v1";

/// Opaque envelope label stamped into the `local_mk_backup`
/// `MaskedKeyMetadata`; identical to `PartFinal`'s so both provisioning
/// paths mint the same backup shape.
const PART_LOCAL_MK_ENVELOPE_LABEL: &[u8] = b"PartLocalMK";

/// Vault attributes for `PartLocalMK` and `EphemeralMK` — on-device,
/// internal, never extractable (identical to `PartFinal`).
const MK_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Inputs rooting the `PartLocalBMK` derivation.
struct BmkRoot<'a> {
    /// The 48-byte owner backup key.
    bk3: &'a HsmDmaBuf,
    /// POTA public key (device byte order), bound in as KBKDF context.
    pota_pub_key: &'a [u8],
}

/// Handle a TBOR `PartInitWithObk` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        // `decode_mut` hands back a destructured view: `mobk_envelope` and
        // `prev_local_mk_backup` as `&mut HsmDmaBuf` so they can be opened in
        // place, the fixed-length POTA fields as shared `&HsmDmaBuf`.
        let req = TborPartInitWithObkReq::decode_mut(cmd_buf.request_mut())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id));

        validate_crypto_officer_active_session(pal, io, sess_id)?;

        // The optional `prev_local_mk_backup` is variable (empty = absent);
        // when present it must be exactly the backup-envelope length.
        let prev = req.prev_local_mk_backup;
        let prev_local_mk_backup = match prev.len() {
            0 => None,
            n if n == LOCAL_MK_BACKUP_LEN => Some(prev),
            _ => return Err(HsmError::InvalidArg),
        };

        // Lifecycle gate, ahead of any crypto: only an untouched `Enabled`
        // partition can be provisioned from the OBK.
        ensure_unprovisioned(pal, io)?;

        // Copy the session-bound secrets before the first yield (session
        // close does not take the credential guard), then require the
        // session to have been opened with the CO credential that is current.
        let auth_binding = crate::session::copy_auth_binding(pal, io, alloc, sess_id)?;
        let param_key = alloc.dma_alloc(SESSION_PARAM_KEY_LEN)?;
        param_key.copy_from_slice(pal.session_param_key(io, sess_id)?);
        crate::session::validate_auth_binding(pal, io, alloc, sess_id, auth_binding).await?;

        // AEAD-open the MOBK envelope **in place** on the inbound request
        // buffer.  The tag authenticates the AAD, so the comparison below is
        // not a timing oracle on a secret; a wrong length is a client
        // encoding bug (`InvalidArg`), a wrong AAD an authentication failure.
        let aead_view = aead_open(pal, io, param_key, req.mobk_envelope)
            .await
            .map_err(|_| HsmError::AeadEnvelopeAuthFailed)?;
        if aead_view.aad.len() != PART_INIT_OBK_AAD_LEN {
            return Err(HsmError::InvalidArg);
        }
        let expected_aad = build_part_init_with_obk_aad(u16::from(sess_id));
        let aad_bytes: &[u8] = aead_view.aad;
        if aad_bytes != expected_aad.as_slice() {
            return Err(HsmError::AeadEnvelopeAuthFailed);
        }
        if aead_view.payload.is_empty() {
            return Err(HsmError::InvalidArg);
        }

        // The MOBK is unmasked in place by `unmask_bk3`; stage it in its own
        // buffer so the opened envelope is left as received.
        let masked_bk3 = alloc.dma_alloc(aead_view.payload.len())?;
        masked_bk3.copy_from_slice(aead_view.payload);

        // Trust gate: the POTA must endorse this partition's identity.  The
        // PKA reads its operands by DMA, but where the key and signature sit
        // in the frame depends on the MOBK envelope length, so verify
        // word-aligned scratch copies.  The nested scope also reclaims the
        // verification scratch before the key derivation below.
        pal.alloc_scoped_async(io, async |scope| {
            let pota_pub_key = scope.dma_alloc(req.pota_pub_key.len())?;
            pota_pub_key.copy_from_slice(req.pota_pub_key);
            let pota_sig = scope.dma_alloc(req.pota_sig.len())?;
            pota_sig.copy_from_slice(req.pota_sig);
            verify_pota_signature(pal, io, scope, pota_pub_key, pota_sig).await
        })
        .await?;

        let bk3 = alloc.dma_alloc(BK3_LEN)?;
        unmask_bk3(pal, io, alloc, masked_bk3, bk3).await?;

        // Platform identity that binds the masking keys / backup envelope:
        // SVN (BKS1 lineage) and owner-seed id (BKS2 lineage).
        let svn = part_state::part_mfgr_svn(pal);
        let owner =
            u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;

        // ── PartLocalMK: fresh or restored ───────────────────────────
        let pota_pub_key: &[u8] = req.pota_pub_key;
        let root = BmkRoot { bk3, pota_pub_key };
        let part_local_mk = alloc.dma_alloc(PART_LOCAL_MK_LEN)?;
        match prev_local_mk_backup {
            None => {
                pal.rng_fill_bytes(io, &mut part_local_mk[..])?;
            }
            Some(prev) => {
                restore_part_local_mk(pal, io, alloc, &root, svn, prev, part_local_mk).await?;
            }
        }

        // Always (re)mask at the current `{svn, owner}` so the returned
        // backup advances to the current platform identity.
        let backup = alloc.dma_alloc(LOCAL_MK_BACKUP_LEN)?;
        mask_part_local_mk(pal, io, alloc, &root, svn, owner, part_local_mk, backup).await?;

        // ── EphemeralMK (random) ─────────────────────────────────────
        let ephemeral_mk = alloc.dma_alloc(EPHEMERAL_MK_LEN)?;
        pal.rng_fill_bytes(io, &mut ephemeral_mk[..])?;

        // ── Commit + respond ──────────────────────────────────────────
        // Stage the vault keys (async, independent slots) so the commit
        // below is a single await-free, atomic guards-first block.
        let (local_id, ephemeral_id) =
            stage_keys(pal, io, part_local_mk, ephemeral_mk, undo).await?;
        commit(pal, io, local_id, ephemeral_id, undo)?;
        encode_response(cmd_buf, backup)
    })
    .await
}

/// Reject any partition that is not an untouched `Enabled` one.
///
/// `EstablishCredential` (v1) leaves the partition `Enabled` but sets the
/// credential and `MK`; `PartInit` / `PartFinal` (v2) move it out of
/// `Enabled`.  Either way the partition is already provisioned.
fn ensure_unprovisioned<P: HsmPal>(pal: &P, io: &P::Io) -> HsmResult<()> {
    if part_state::part_state(pal, io)? != HsmPartState::Enabled
        || part_state::part_is_provisioned(pal, io)?
        || part_state::part_is_credential_set(pal, io)?
    {
        return Err(HsmError::PartitionAlreadyProvisioned);
    }
    Ok(())
}

/// Verifies the POTA signature over the partition identity public key.
///
/// The signature is computed by the host over
/// `SHA-384( 0x04 ‖ x ‖ y )`, the 97-byte SEC1-uncompressed form of
/// the partition identity P-384 public key, where `x`/`y` are the raw
/// coordinates in natural **big-endian** order (as used in DER / X.509).
/// We materialize the same 97-byte form locally from `part_id_pub_key`
/// and verify the supplied signature against it.  The signer public key and
/// the signature are consumed in the PAL's operand (device) byte order.
async fn verify_pota_signature<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    signer_pub_key_raw: &HsmDmaBuf,
    signature_raw: &HsmDmaBuf,
) -> HsmResult<()> {
    // Skip three bytes so the 96-byte key, which follows the `0x04` tag,
    // starts word-aligned for the PAL's ECC engine.
    let id_uncompressed = alloc.dma_alloc(P384_PUB_RAW_LEN + 4)?.split_at_mut(3).1;
    id_uncompressed[0] = 0x04;
    part_state::part_id_pub_key(pal, io, id_uncompressed.split_at_mut(1).1).await?;

    // `ecc_verify` consumes the digest in operand order.
    let digest = alloc.dma_alloc(HsmHashAlgo::Sha384.digest_len())?;
    pal.hash(
        io,
        HsmHashAlgo::Sha384,
        id_uncompressed,
        HsmDigestForm::Operand,
        Some(digest),
    )
    .await?;

    if !pal
        .ecc_verify(
            io,
            HsmEccCurve::P384,
            signer_pub_key_raw,
            digest,
            signature_raw,
        )
        .await?
    {
        return Err(HsmError::EccVerifyFailed);
    }
    Ok(())
}

/// Unmasks the partition `BK3` blob (the MOBK) in place under `BK_BOOT` and
/// copies the 48-byte plaintext into `bk3_out`.
///
/// `masked_bk3` is the envelope produced by a prior v1 `InitBk3`: BK3
/// sealed under the partition's `BK_BOOT` (an 80-byte AES-CBC-256 +
/// HMAC-SHA-384 masking key, recovered on demand because the raw key is
/// never stored).  `bk3_out` must be exactly [`BK3_LEN`] bytes.
async fn unmask_bk3<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    masked_bk3: &mut HsmDmaBuf,
    bk3_out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let bk_boot = alloc.dma_alloc(BK_BOOT_LEN)?;
    crate::ddi::recover_bk_boot(pal, io, bk_boot).await?;

    let layout = cbc::unmask(pal, io, bk_boot, masked_bk3).await?;
    if layout.plaintext_max_len < BK3_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    bk3_out
        .copy_from_slice(&masked_bk3[layout.plaintext_offset..layout.plaintext_offset + BK3_LEN]);
    Ok(())
}

/// Derives `PartLocalBMK` for `{svn, owner}` into a fresh scoped buffer.
///
/// Both restore and mask paths key on the same root; this helper avoids
/// repeating that boilerplate.
async fn derive_local_bmk<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    root: &BmkRoot<'_>,
    svn: u64,
    owner: u16,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let local_bmk = alloc.dma_alloc(MASKING_KEY_LEN)?;
    derive_masking_key(
        pal,
        io,
        root.bk3,
        PART_LOCAL_BMK_LABEL,
        root.pota_pub_key,
        svn,
        owner,
        local_bmk,
    )
    .await?;
    Ok(local_bmk)
}

/// Restore `PartLocalMK` from a prior `local_mk_backup`.
///
/// Reads the `{svn, owner}` the blob was masked under from its (cleartext
/// but tag-bound) metadata, re-derives the matching `PartLocalBMK`, and
/// unmasks the blob.  The anti-rollback policy (reject a blob from a
/// *newer* SVN; older-or-equal SVNs are accepted since the masking key is
/// re-derivable from the versioned device seeds) is enforced **after**
/// `unmask` authenticates the metadata, so a tampered cleartext SVN fails
/// the AEAD tag rather than spoofing the rollback error.
async fn restore_part_local_mk<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    root: &BmkRoot<'_>,
    cur_svn: u64,
    prev: &mut HsmDmaBuf,
    out_mk: &mut HsmDmaBuf,
) -> HsmResult<()> {
    // These bindings are needed *now* to re-derive the unmasking key but are
    // NOT yet authenticated, so the anti-rollback check waits for `unmask`.
    let (prev_svn, prev_owner) = peek_backup_svn_owner(prev)?;

    let local_bmk = derive_local_bmk(pal, io, alloc, root, prev_svn, prev_owner).await?;

    // `unmask` decrypts the envelope in place in the request buffer; on
    // success it has verified the AEAD tag, so `{prev_svn, prev_owner}` are
    // now authenticated.
    let view = unmask(pal, io, local_bmk, prev).await?;
    let len_ok = view.target_key.len() == out_mk.len();
    if len_ok {
        out_mk.copy_from_slice(view.target_key);
    }

    if prev_svn > cur_svn {
        return Err(HsmError::PartFinalBackupSvnRollback);
    }
    if !len_ok {
        // Firmware invariant: the AEAD tag has already verified the
        // envelope, so a genuine (firmware-minted) backup always holds a
        // `PART_LOCAL_MK_LEN` key — a mismatch signals corruption / a
        // sizing bug, not a client-supplied error.
        return Err(HsmError::InternalError);
    }
    Ok(())
}

/// Mask `part_local_mk` under the `PartLocalBMK` derived for the current
/// `{svn, owner}`, producing the `local_mk_backup` envelope.
#[allow(clippy::too_many_arguments)]
async fn mask_part_local_mk<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    root: &BmkRoot<'_>,
    svn: u64,
    owner: u16,
    part_local_mk: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let local_bmk = derive_local_bmk(pal, io, alloc, root, svn, owner).await?;

    let key_label = alloc.dma_alloc(PART_LOCAL_MK_ENVELOPE_LABEL.len())?;
    key_label.copy_from_slice(PART_LOCAL_MK_ENVELOPE_LABEL);

    let params = MaskParams {
        key_kind: HsmVaultKeyKind::PartitionLocalMaskingKey,
        key_attrs: MK_ATTRS,
        svn,
        owner_seed_id: owner,
        key_label,
    };

    mask(
        pal,
        io,
        alloc,
        AeadAlg::AesGcm256,
        local_bmk,
        &params,
        part_local_mk,
        Some(out),
    )
    .await?;
    Ok(())
}

/// Read the `{svn, owner_seed_id}` from a `local_mk_backup`'s
/// `MaskedKeyMetadata` AAD (cleartext, tag-bound) without the masking key.
///
/// `peek_metadata` surfaces any malformed envelope (bad magic / version /
/// too short) as `MaskedKeyDecodeFailed`; the exact length is already
/// enforced by the handler.
fn peek_backup_svn_owner(blob: &HsmDmaBuf) -> HsmResult<(u64, u16)> {
    let meta = peek_metadata(blob)?;
    Ok((meta.svn.get(), meta.owner_seed_id.get()))
}

/// Stage the partition-local and ephemeral masking-key vault entries,
/// recording each key's delete-inverse on the undo log.
///
/// Done **before** [`commit`] so that block can be a single await-free
/// (atomic) commit; a racing provisioning command stages its own keys
/// independently and only races in the atomic commit, where the loser
/// fails fast and its just-staged keys are reaped by the recorded inverses.
async fn stage_keys<'p, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    part_local_mk: &HsmDmaBuf,
    ephemeral_mk: &HsmDmaBuf,
    undo: &mut UndoLog<'p>,
) -> HsmResult<(HsmKeyId, HsmKeyId)> {
    let local_id = pal
        .vault_key_create(
            io,
            part_local_mk,
            HsmVaultKeyKind::PartitionLocalMaskingKey,
            None,
            MK_ATTRS,
            HsmVaultPct::None,
        )
        .await?;
    undo.push_vault_create(local_id)?;

    let ephemeral_id = pal
        .vault_key_create(
            io,
            ephemeral_mk,
            HsmVaultKeyKind::PartitionEphemeralMaskingKey,
            None,
            MK_ATTRS,
            HsmVaultPct::None,
        )
        .await?;
    undo.push_vault_create(ephemeral_id)?;

    Ok((local_id, ephemeral_id))
}

/// Commit the provisioned state in a single **await-free** guards-first
/// block: record the masking-key ids and advance the lifecycle from
/// `Enabled` straight to [`HsmPartState::Initialized`].
///
/// The two vault keys are already staged by [`stage_keys`]; only their
/// `key_id`s flow in here.  Each mutation's inverse is recorded *before*
/// applying, so a partial failure (or a later response / completion
/// failure) is rolled back by the dispatcher's walk.
///
/// Being await-free, this block is **atomic** on the cooperative executor: a
/// racing provisioning command that reaches the guard after this one
/// committed sees `STATE != Enabled` and **fails fast without mutating**.
fn commit<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    local_id: HsmKeyId,
    ephemeral_id: HsmKeyId,
    undo: &mut UndoLog<'_>,
) -> HsmResult<()> {
    // Guards-first: bail before recording or applying any inverse if the
    // partition is no longer `Enabled`.  Recording the inverses and then
    // failing would otherwise clobber the winner's just-committed state.
    if part_state::part_state(pal, io)? != HsmPartState::Enabled {
        return Err(HsmError::PartitionAlreadyProvisioned);
    }

    // Record every inverse *before* applying, in commit order (the undo walk
    // reverses them): clear the two new masking-key ids and restore STATE to
    // `Enabled`.
    undo.push_prop_restore_absent(HsmPartPropId::LOCAL_MK_KEY_ID)?;
    undo.push_prop_restore_absent(HsmPartPropId::EPHEMERAL_MK_KEY_ID)?;
    undo.push_prop_restore_scalar(HsmPartPropId::PART_STATE, HsmPartState::Enabled as u32)?;

    // Apply the mutations in the same order as the inverses above.
    part_state::part_set_local_mk_key_id(pal, io, local_id)?;
    part_state::part_set_ephemeral_mk_key_id(pal, io, ephemeral_id)?;
    part_state::part_set_state(pal, io, HsmPartState::Initialized)
}

/// Encode the `TborPartInitWithObkResp` into a fresh IO-scoped HsmDmaBuf.
fn encode_response(cmd_buf: &mut HsmCmdBuf<'_>, backup: &HsmDmaBuf) -> HsmResult<usize> {
    let resp = cmd_buf.encode_response(|buf| {
        let frame = TborPartInitWithObkResp::encode(buf, 0, false)?
            .local_mk_backup(backup)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
