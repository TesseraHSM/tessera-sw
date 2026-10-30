// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `PartFinal` (FinalizePart + ConfigPartSD) handler —
//! partition-provisioning Phase 2.
//!
//! `PartFinal` is a CO-session command that finalizes a partition after
//! [`PartInit`](super::part_init).  It is the firmware realization of the
//! `FinalizePart` primitive; the security-domain-local key
//! material of `ConfigPartSD` (SDLocalMK) is out of scope for now.
//!
//! Flow:
//!
//! 1. **Parse + gate** — CO-only; partition must be in
//!    [`HsmPartState::Initializing`]; the re-supplied `part_policy` must hash
//!    to the stored `policy_hash`; and the supplied PTA certificate chain
//!    (`cert_descriptors`, read out of band) must be anchored to the
//!    policy `POTAPubKey` with its terminal (PTA) certificate's public
//!    key equal to the partition's PTA key.
//! 2. **FinalizePart core** — derive `UPS` from the partition root (UMS),
//!    then `PartLocalBMK`; generate a fresh `PartLocalMK` or restore it
//!    from `prev_local_mk_backup`; provision the random `EphemeralMK`.
//! 3. **Commit** — vault the new keys (recording their ids), replace UMS
//!    with UPS in the partition root slot, and advance the lifecycle to
//!    [`HsmPartState::Initialized`].
//! 4. **Respond** — return the current `local_mk_backup`.

use tsra_fw_core_crypto_key_derive::derive_masking_key;
use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_core_crypto_x509_chain::parse_cert;
use tsra_fw_core_crypto_x509_chain::validate_issuing_chain;
use tsra_fw_core_crypto_x509_chain::MAX_CERT_DER_LEN;
use tsra_fw_ddi_tbor_types::evidence::CertDescriptor;
use tsra_fw_ddi_tbor_types::evidence::MAX_CERTS;
use tsra_fw_ddi_tbor_types::policy::PartPolicy;
use tsra_fw_ddi_tbor_types::policy::POLICY_MAX_KEY_LEN;
use tsra_fw_ddi_tbor_types::TborPartFinalReq;
use tsra_fw_ddi_tbor_types::TborPartFinalResp;
use tsra_fw_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use tsra_fw_hsm_oob::copy_oob;
use tsra_fw_hsm_oob::OobPtr;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmPartPropId;
use tsra_fw_hsm_pal_traits::HsmPartState;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionRole;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use tsra_fw_hsm_undo::UndoLog;

use super::*;

/// SHA-384 digest length (policy-hash comparison).
const SHA384_LEN: usize = 48;

/// AES-256-GCM masking-key length (the v2 AEAD envelope key).
const MASKING_KEY_LEN: usize = 32;

/// KDF labels and key-material lengths, mirroring the `part_init`
/// `kdf` submodule naming (`TSRA-<Command>-<Purpose>-v<N>`).
mod kdf {
    /// UMS (the partition root secret in the `ups_key_id` slot) → UPS
    /// derivation (KBKDF).  Context is empty for now: the handler already
    /// walks and validates the PTA certificate chain, but binding its hash
    /// (`PTACertChainHash`) into this derivation is deferred; when it
    /// lands, that hash becomes the KBKDF context.
    pub const UPS_LABEL: &[u8] = b"TSRA-PartFinal-UPS-v1";

    /// UPS length (HMAC-SHA-384-sized, matching `PartRoot`).
    pub const UPS_LEN: usize = 48;

    /// UPS → `PartLocalBMK` masking-key derivation (KBKDF).
    pub const PART_LOCAL_BMK_LABEL: &[u8] = b"TSRA-PartFinal-PartLocalBMK-v1";

    /// `PartLocalMK` length (the masked plaintext / `local_mk`).
    pub const PART_LOCAL_MK_LEN: usize = 32;

    /// `EphemeralMK` length (random masking key).
    pub const EPHEMERAL_MK_LEN: usize = 32;

    /// Opaque envelope label stamped into the `local_mk_backup`
    /// `MaskedKeyMetadata` (informational; bound by the AEAD tag).
    pub const PART_LOCAL_MK_ENVELOPE_LABEL: &[u8] = b"PartLocalMK";
}

/// Vault attributes for the partition root secret (UPS), mirroring the
/// `PartInit` `PartRoot` attributes: on-device, internal, never
/// extractable.
const PART_ROOT_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Vault attributes for `PartLocalMK` — partition-local scope.
const PART_LOCAL_MK_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Vault attributes for `EphemeralMK` — ephemeral scope (revoked on
/// partition reset).
const EPHEMERAL_MK_ATTRS: HsmVaultKeyAttrs = HsmVaultKeyAttrs::new()
    .with_local(true)
    .with_internal(true)
    .with_never_extractable(true);

/// Handle a TBOR `PartFinal` request.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    oob: Option<OobPtr>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let req = parse_request(cmd_buf.request_mut())?;

        // Lifecycle gate: PartFinal only runs against a partition that
        // `PartInit` left in `Initializing`.
        if super::super::part_state::part_state(pal, io)? != HsmPartState::Initializing {
            return Err(HsmError::InvalidArg);
        }

        // Integrity gate: the re-supplied policy must match the one
        // bound at `PartInit` (`SHA-384(part_policy) == policy_hash`).
        verify_policy_hash(pal, io, alloc, req.part_policy).await?;

        // Validate the typed policy (rejects malformed input) and recover
        // the `POTAPubKey` trust anchor for cert-chain validation.
        let policy = super::policy::from_bytes(req.part_policy)?;

        // Trust gate: walk the supplied PTA certificate chain, proving it
        // chains to the policy `POTAPubKey` and that its terminal (PTA)
        // certificate carries this partition's PTA key.
        //
        // Scope the validation buffers (terminal snapshot, chain-walk
        // scratch, and profile parse) to a nested allocator so they are
        // reclaimed before the UPS derivation and backup
        // restoration/masking below allocate. Restoring a backup with two
        // maximal P-384 certificates would otherwise stack the retained
        // validation buffers on top of the backup buffers and exhaust the
        // std/emu 8 KiB DMA heap, failing a valid finalization with
        // `NotEnoughSpace`.
        pal.alloc_scoped_async(io, async |val_alloc| {
            validate_pta_chain(pal, io, val_alloc, oob, req.cert_descriptors, policy).await
        })
        .await?;

        // Platform identity that binds the masking keys / backup
        // envelope: SVN (BKS1 lineage) and owner-seed id (BKS2 lineage).
        let svn = super::super::part_state::part_mfgr_svn(pal);
        let owner = u16::try_from(super::super::part_state::part_owner_svn(pal))
            .map_err(|_| HsmError::InvalidArg)?;

        // ── UPS derivation ────────────────────────────────────────────
        // Read the vaulted partition root (UMS — note the slot is
        // historically named `ups_key_id` but holds UMS until this
        // handler replaces it) and derive UPS = KBKDF(UMS, UPS_LABEL).
        let ums_key_id = super::super::part_state::part_ups_key_id(pal, io)?;
        let ups = alloc.dma_alloc(kdf::UPS_LEN)?;
        {
            // Inner scope: `ums` must be dropped before `commit` calls
            // vault operations on the same slot.
            let ums = pal.vault_key(io, ums_key_id)?;
            let label = alloc.dma_alloc(kdf::UPS_LABEL.len())?;
            label.copy_from_slice(kdf::UPS_LABEL);
            pal.sp800_108_kdf(io, HsmHashAlgo::Sha384, ums, Some(label), None, ups)
                .await?;
        }

        // ── PartLocalMK: fresh or restored ───────────────────────────
        let part_local_mk = alloc.dma_alloc(kdf::PART_LOCAL_MK_LEN)?;
        match req.prev_local_mk_backup {
            None => {
                pal.rng_fill_bytes(io, &mut part_local_mk[..])?;
            }
            Some(prev) => {
                restore_part_local_mk(pal, io, alloc, ups, svn, prev, part_local_mk).await?;
            }
        }

        // Always (re)mask at the current `{svn, owner}` so the returned
        // backup advances to the current platform identity.
        let curr_backup = alloc.dma_alloc(LOCAL_MK_BACKUP_LEN)?;
        mask_part_local_mk(pal, io, alloc, ups, svn, owner, part_local_mk, curr_backup).await?;

        // ── EphemeralMK (random) ─────────────────────────────────────
        let ephemeral_mk = alloc.dma_alloc(kdf::EPHEMERAL_MK_LEN)?;
        pal.rng_fill_bytes(io, &mut ephemeral_mk[..])?;

        // ── Commit + respond ──────────────────────────────────────────
        // Stage the finalized vault keys (async, independent slots) so the
        // commit below is a single await-free, atomic guards-first block.
        let (local_id, ephemeral_id, ups_id) =
            stage_final_keys(pal, io, ups, part_local_mk, ephemeral_mk, undo).await?;
        commit_final(pal, io, ums_key_id, local_id, ephemeral_id, ups_id, undo)?;
        encode_response(cmd_buf, curr_backup)
    })
    .await
}

/// Parsed-and-validated `PartFinal` request fields.
struct ParsedRequest<'a> {
    #[allow(dead_code)]
    sess_id: HsmSessId,
    /// Re-supplied unified `PartPolicy` blob (584 B), as a sub-view of
    /// the inbound buffer.
    part_policy: &'a HsmDmaBuf,
    /// PTA certificate-chain descriptors (`(index, length)` into the OOB
    /// SGL page), root → leaf.  The schema pins `1..=MAX_CERTS` entries.
    cert_descriptors: &'a [CertDescriptor],
    /// Optional previous `local_mk` backup to restore (`None` when the
    /// field is empty; otherwise exactly [`LOCAL_MK_BACKUP_LEN`]).  A
    /// **mutable** sub-view so the envelope can be AEAD-unmasked in place.
    prev_local_mk_backup: Option<&'a mut HsmDmaBuf>,
}

/// Decode the wire request, enforce the CO-only role gate, extract the
/// PTA `cert_descriptors`, and length-check the optional
/// `prev_local_mk_backup`.
fn parse_request<'a>(req_buf: &'a mut HsmDmaBuf) -> HsmResult<ParsedRequest<'a>> {
    let req = TborPartFinalReq::decode_mut(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id));

    // PartFinal is CO-only (parity with PartInit).
    if sess_id.role() != HsmSessionRole::CryptoOfficer {
        return Err(HsmError::InvalidPermissions);
    }

    // `decode_mut`'s view exposes shared (non-mutable) buffer fields as
    // raw `&HsmDmaBuf` bytes, so reinterpret the packed `cert_descriptors`
    // bytes as a typed slice here; a byte length that is not a whole
    // number of descriptors fails the cast and is rejected as `InvalidArg`.
    let cert_descriptors =
        <[CertDescriptor] as zerocopy::TryFromBytes>::try_ref_from_bytes(req.cert_descriptors)
            .map_err(|_| HsmError::InvalidArg)?;

    // The `part_policy` (584 B) length is pinned by the schema and was
    // already rejected at decode if malformed.  The optional
    // `prev_local_mk_backup` is variable (empty = absent); when present
    // it must be exactly the backup-envelope length.
    let prev = req.prev_local_mk_backup;
    let prev_local_mk_backup = match prev.len() {
        0 => None,
        n if n == LOCAL_MK_BACKUP_LEN => Some(prev),
        _ => return Err(HsmError::InvalidArg),
    };

    Ok(ParsedRequest {
        sess_id,
        part_policy: req.part_policy,
        cert_descriptors,
        prev_local_mk_backup,
    })
}

/// Walk the supplied PTA certificate chain and prove partition trust.
///
/// The chain travels **out of band** (each certificate read via
/// [`copy_oob`] by its descriptor `index`), and is walked root → leaf by
/// the firmware [`validate_chain`] state machine.  Two conditions gate
/// finalization:
///
/// 1. **Anchoring** — some non-leaf certificate's public key must equal
///    the policy `POTAPubKey`, binding the chain to the partition owner's
///    trust anchor.
/// 2. **PTA identity** — the chain's terminal certificate (the PTA
///    intermediate CA) must carry this partition's PTA public key.
///
/// # Errors
/// * [`HsmError::InvalidArg`] — no OOB region, a bad descriptor count, or
///   a malformed / unanchored chain.
/// * [`HsmError::PartFinalPtaMismatch`] — the chain is valid and
///   POTA-anchored, but its terminal (PTA) certificate's key is not the
///   partition PTA key.
/// * Any [`HsmError`] surfaced by certificate parsing or signature
///   verification.
async fn validate_pta_chain<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    oob: Option<OobPtr>,
    cert_descriptors: &[CertDescriptor],
    policy: &PartPolicy,
) -> HsmResult<()> {
    // The PTA chain travels out of band; without an OOB region there is
    // nothing to read.
    let oob = oob.ok_or(HsmError::InvalidArg)?;

    if cert_descriptors.is_empty() || cert_descriptors.len() > MAX_CERTS {
        return Err(HsmError::InvalidArg);
    }

    // Descriptors address out-of-band items by `index`, and the
    // snapshot-serving fetch closure below selects the terminal
    // certificate by that index. A certificate chain never legitimately
    // references the same out-of-band item twice, and duplicate indices
    // would make that selection ambiguous (e.g. a shorter non-terminal
    // descriptor sharing the terminal's index). Reject them outright so a
    // malformed host request cannot drive the fetch closure into a
    // length-mismatched copy.
    for (i, a) in cert_descriptors.iter().enumerate() {
        if cert_descriptors[i + 1..].iter().any(|b| b.index == a.index) {
            return Err(HsmError::InvalidArg);
        }
    }

    // Snapshot the expected PTA identity (partition PTA key) up front so
    // the property-store borrow is not held across the chain walk.
    let pta = super::super::part_state::part_pta_pub_key(pal, io)?;
    if pta.len() != POLICY_MAX_KEY_LEN {
        return Err(HsmError::InternalError);
    }

    // Policy `POTAPubKey` trust anchor (raw P-384 `X ‖ Y`, big-endian);
    // `from_bytes` has already pinned its length to a full Ecc384 key.
    let anchor = &policy.pota_pub_key.data[..POLICY_MAX_KEY_LEN];

    // Snapshot the terminal (PTA) certificate's DER **once**, up front,
    // into HSM-owned memory. Both the chain walk (which signature-verifies
    // the terminal) and the profile enforcement below consume this single
    // snapshot, so they cannot observe different host-controlled bytes
    // (TOCTOU): a host that swaps the OOB bytes between reads can no longer
    // pass signature validation with one certificate while the
    // subject/SKID/CA profile is checked against another.
    let terminal = cert_descriptors.last().ok_or(HsmError::InvalidArg)?;
    let terminal_index = usize::from(terminal.index);
    let terminal_len = usize::from(terminal.length.get());
    if terminal_len == 0 || terminal_len > MAX_CERT_DER_LEN {
        return Err(HsmError::InvalidArg);
    }
    let pta_der = alloc.dma_alloc(terminal_len)?;
    copy_oob(pal, io, &oob, terminal_index, pta_der).await?;

    // Walk the chain root → leaf, validating the terminal as an *issuing*
    // CA (it will later sign the on-demand slot-2 PID leaf): this enforces
    // `cA == true`, `keyCertSign`, and — crucially — the ancestor
    // `pathLenConstraint` budget on the PTA, so a chain whose ancestors
    // leave no room for the PID leaf is rejected here. The terminal is
    // served from `pta_der`; every other certificate still streams from
    // the out-of-band region.
    let mut pta_from_chain = [0u8; POLICY_MAX_KEY_LEN];
    validate_issuing_chain(
        pal,
        io,
        alloc,
        cert_descriptors,
        Some(anchor),
        &mut pta_from_chain,
        async |index, buf| {
            if index == terminal_index {
                // Defensive: duplicate indices are already rejected above,
                // so `buf` here is the terminal descriptor's buffer and its
                // length equals the snapshot's. Guard the copy anyway so a
                // length mismatch can never panic the firmware across the
                // host trust boundary.
                let snapshot: &[u8] = pta_der;
                if buf.len() != snapshot.len() {
                    return Err(HsmError::InvalidArg);
                }
                buf.copy_from_slice(snapshot);
                Ok(())
            } else {
                copy_oob(pal, io, &oob, index, buf).await
            }
        },
    )
    .await?;

    // The chain is cryptographically valid and POTA-anchored; its
    // terminal (PTA) certificate must carry this partition's PTA key.
    // Compare as byte slices (`pta` is a `HsmDmaBuf` DST over `[u8]`).
    let expected_pta: &[u8] = pta;
    if &pta_from_chain[..] != expected_pta {
        return Err(HsmError::PartFinalPtaMismatch);
    }

    // `validate_issuing_chain` does not pin the terminal certificate's
    // subject DN or SKID. Parse the **same snapshot** the walk verified
    // and enforce the deterministic subject/SKID/CA profile the on-demand
    // slot-2 PID leaf depends on; otherwise finalization could accept a
    // PTA that no future PID leaf can chain to.
    let pta_cert = parse_cert(pta_der)?;
    super::pta::validate_pta_profile(pal, io, alloc, &pta_cert).await?;

    Ok(())
}

/// Derives `PartLocalBMK` for `{svn, owner}` into a fresh scoped buffer.
///
/// Both restore and mask paths key on the same label (`PART_LOCAL_BMK_LABEL`)
/// and empty extra context; this helper avoids repeating that boilerplate.
async fn derive_local_bmk<'a, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    ups: &HsmDmaBuf,
    svn: u64,
    owner: u16,
) -> HsmResult<&'a mut HsmDmaBuf> {
    let local_bmk = alloc.dma_alloc(MASKING_KEY_LEN)?;
    derive_masking_key(
        pal,
        io,
        ups,
        kdf::PART_LOCAL_BMK_LABEL,
        &[],
        svn,
        owner,
        local_bmk,
    )
    .await?;
    Ok(local_bmk)
}

/// Verify `SHA-384(part_policy)` equals the partition's stored
/// `policy_hash` (bound at `PartInit`).
pub(crate) async fn verify_policy_hash<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    part_policy: &HsmDmaBuf,
) -> HsmResult<()> {
    let digest = alloc.dma_alloc(SHA384_LEN)?;
    pal.hash(io, HsmHashAlgo::Sha384, part_policy, digest, true)
        .await?;

    let stored = super::super::part_state::part_policy_hash(pal, io)?;
    if digest[..] != stored[..] {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
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
    ups: &HsmDmaBuf,
    cur_svn: u64,
    prev: &mut HsmDmaBuf,
    out_mk: &mut HsmDmaBuf,
) -> HsmResult<()> {
    // Peek the cleartext `{svn, owner}` bindings.  These are needed *now*
    // to re-derive the unmasking key, but they are NOT yet authenticated
    // (`peek_metadata`'s result must not be trusted until `unmask` verifies
    // the tag), so the anti-rollback policy below is deferred until after
    // `unmask` succeeds.
    let (prev_svn, prev_owner) = peek_backup_svn_owner(prev)?;

    let local_bmk = derive_local_bmk(pal, io, alloc, ups, prev_svn, prev_owner).await?;

    // `unmask` decrypts the envelope in place in the request buffer — no
    // scratch staging copy needed.  On success it has verified the AEAD tag
    // over the AAD, so `{prev_svn, prev_owner}` are now authenticated.
    let view = unmask(pal, io, local_bmk, prev).await?;
    let len_ok = view.target_key.len() == out_mk.len();
    if len_ok {
        out_mk.copy_from_slice(view.target_key);
    }

    // Anti-rollback, enforced on the now-authenticated `svn`: a backup
    // minted under a newer SVN cannot be restored on this (older)
    // firmware.  Enforcing this only after the tag is verified means a
    // tampered cleartext `svn` fails `unmask` (generic AEAD error) rather
    // than being able to spoof this specific rollback error.
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

/// Mask `part_local_mk` under the `PartLocalBMK` derived for the
/// current `{svn, owner}`, producing the `local_mk_backup` envelope.
#[allow(clippy::too_many_arguments)]
async fn mask_part_local_mk<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    ups: &HsmDmaBuf,
    svn: u64,
    owner: u16,
    part_local_mk: &HsmDmaBuf,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let local_bmk = derive_local_bmk(pal, io, alloc, ups, svn, owner).await?;

    let key_label = alloc.dma_alloc(kdf::PART_LOCAL_MK_ENVELOPE_LABEL.len())?;
    key_label.copy_from_slice(kdf::PART_LOCAL_MK_ENVELOPE_LABEL);

    let params = MaskParams {
        key_kind: HsmVaultKeyKind::PartitionLocalMaskingKey,
        key_attrs: PART_LOCAL_MK_ATTRS,
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
/// `MaskedKeyMetadata` AAD (cleartext, tag-bound) without the masking
/// key.  Offsets are fixed by the AES-256-GCM envelope layout
/// (`header(8) ‖ iv(12) ‖ metadata(96)`), pinned by the
/// [`LOCAL_MK_BACKUP_LEN`] length check.
fn peek_backup_svn_owner(blob: &HsmDmaBuf) -> HsmResult<(u64, u16)> {
    // Read the `{svn, owner_seed_id}` platform-identity bindings from the
    // envelope's cleartext metadata.  These are tag-bound but not yet
    // authenticated here — the subsequent `unmask` verifies the tag.
    // `prev`'s exact length is already enforced by `parse_request`, and
    // `peek_metadata` surfaces any malformed envelope (bad magic /
    // version / too short) as `MaskedKeyDecodeFailed`.
    let meta = peek_metadata(blob)?;
    Ok((meta.svn.get(), meta.owner_seed_id.get()))
}

/// Stage the three finalized vault keys — partition-local MK, ephemeral MK,
/// and the UPS that replaces UMS in the root slot — recording each key's
/// delete-inverse on the undo log.
///
/// Done **before** [`commit_final`] so that block can be a single await-free
/// (atomic) commit; concurrent `PartFinal`s stage their own keys
/// independently and only race in the atomic commit, where the loser
/// fails-fast and its just-staged keys are reaped by the recorded inverses.
async fn stage_final_keys<'p, P: HsmPal>(
    pal: &P,
    io: &P::Io,
    ups: &HsmDmaBuf,
    part_local_mk: &HsmDmaBuf,
    ephemeral_mk: &HsmDmaBuf,
    undo: &mut UndoLog<'p>,
) -> HsmResult<(HsmKeyId, HsmKeyId, HsmKeyId)> {
    let local_id = pal
        .vault_key_create(
            io,
            part_local_mk,
            HsmVaultKeyKind::PartitionLocalMaskingKey,
            None,
            PART_LOCAL_MK_ATTRS,
        )
        .await?;
    undo.push_vault_create(local_id)?;

    let ephemeral_id = pal
        .vault_key_create(
            io,
            ephemeral_mk,
            HsmVaultKeyKind::PartitionEphemeralMaskingKey,
            None,
            EPHEMERAL_MK_ATTRS,
        )
        .await?;
    undo.push_vault_create(ephemeral_id)?;

    let ups_id = pal
        .vault_key_create(
            io,
            ups,
            HsmVaultKeyKind::UniquePartitionSecret,
            None,
            PART_ROOT_ATTRS,
        )
        .await?;
    undo.push_vault_create(ups_id)?;

    Ok((local_id, ephemeral_id, ups_id))
}

/// Commit the finalized partition state in a single **await-free**
/// guards-first block: record the masking-key ids, replace UMS → UPS in the
/// root slot (soft-deleting the old UMS key), and advance the lifecycle to
/// [`HsmPartState::Initialized`].
///
/// The three vault keys are already staged by [`stage_final_keys`]; only
/// their `key_id`s flow in here.  Each mutation's inverse is recorded
/// *before* applying, so a partial failure (or a later response/completion
/// failure) is rolled back by the dispatcher's walk.  The UMS key is
/// **soft-deleted** ([`UndoLog::push_vault_disable`]) so the undo walk
/// re-enables it and the commit walk zeroizes it.
///
/// Being await-free, this block is **atomic** on the cooperative executor: a
/// racing `PartFinal` that reaches the guard after this one committed sees
/// `STATE != Initializing` and **fails-fast without mutating** — so no
/// partition lock is needed, and its empty field-undo cannot clobber this
/// commit.
fn commit_final<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    ums_key_id: HsmKeyId,
    local_id: HsmKeyId,
    ephemeral_id: HsmKeyId,
    ups_id: HsmKeyId,
    undo: &mut UndoLog<'_>,
) -> HsmResult<()> {
    use super::super::part_state;

    // Guards-first: bail before recording or applying any inverse if the
    // partition is no longer `Initializing` (e.g. a racing PartFinal already
    // finalized).  Recording the inverses and then failing would otherwise
    // clobber the winner's just-committed state.
    if part_state::part_state(pal, io)? != HsmPartState::Initializing {
        return Err(HsmError::InvalidArg);
    }

    // Record every inverse *before* applying, in commit order (the undo walk
    // reverses them): clear the two new masking-key ids, restore UPS_KEY_ID
    // to the prior UMS id, re-enable the soft-deleted UMS key, and restore
    // STATE to `Initializing`.
    undo.push_prop_restore_absent(HsmPartPropId::LOCAL_MK_KEY_ID)?;
    undo.push_prop_restore_absent(HsmPartPropId::EPHEMERAL_MK_KEY_ID)?;
    undo.push_prop_restore_scalar(HsmPartPropId::UPS_KEY_ID, u32::from(u16::from(ums_key_id)))?;
    undo.push_vault_disable(ums_key_id)?;
    undo.push_prop_restore_scalar(HsmPartPropId::PART_STATE, HsmPartState::Initializing as u32)?;

    // Apply the mutations in the same order as the inverses above.
    part_state::part_set_local_mk_key_id(pal, io, local_id)?;
    part_state::part_set_ephemeral_mk_key_id(pal, io, ephemeral_id)?;
    // The UPS_KEY_ID slot is write-once, so clear it before re-pointing.
    pal.part_prop_clear(io, HsmPartPropId::UPS_KEY_ID)?;
    part_state::part_set_ups_key_id(pal, io, ups_id)?;
    // Soft-delete the old UMS key: the commit walk zeroizes it, the undo
    // walk re-enables it (see the recorded `push_vault_disable`).
    pal.vault_key_disable(io, ums_key_id)?;

    part_state::part_set_state(pal, io, HsmPartState::Initialized)
}

/// Encode the `TborPartFinalResp` into a fresh IO-scoped HsmDmaBuf.
fn encode_response(cmd_buf: &mut HsmCmdBuf<'_>, backup: &HsmDmaBuf) -> HsmResult<usize> {
    let resp = cmd_buf.encode_response(|buf| {
        let frame = TborPartFinalResp::encode(buf, 0, false)?
            .local_mk_backup(backup)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
