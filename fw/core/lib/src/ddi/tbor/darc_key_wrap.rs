// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcKeyWrap` handler.
//!
//! Exports a **local EC private key** so it can be imported on another
//! device via [`DarcKeyUnwrap`](super::darc_key_unwrap).  The key is:
//!
//! 1. unmasked from its local vault envelope,
//! 2. re-encoded as an EC2 `COSE_Key`, and
//! 3. AES-KWP (RFC 5649) wrapped under a DARC Transfer Masking Key (TMK),
//!    where the TMK is supplied as the masked envelope produced by
//!    [`DarcTmkGen`](super::darc_tmk_gen) /
//!    [`DarcTmkImport`](super::darc_tmk_import).
//!
//! The produced `wrapped_key` is byte-for-byte what `DarcKeyUnwrap`
//! consumes, so wrapping under the generated TMK and unwrapping under the
//! same TMK (round-tripped through export/import) recovers the key.
//!
//! Flow:
//!
//! 1. Decode; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition whose security domain is initialized (both
//!    the TMK and the local key are masked under partition-provisioned
//!    masking keys).
//! 2. Route the masked TMK to its masking key, unmask it (must be a
//!    [`DarcTmk`](HsmVaultKeyKind::DarcTmk)), and recover the 32-byte TMK.
//! 3. Route the masked local key to its masking key, unmask it (must be
//!    an `Ecc{256,384,521}Private` key), and recover the vault scalar
//!    plus its vault attributes and masked-key label.
//! 4. Re-derive the public key, build the EC2 private `COSE_Key` — its
//!    `d` / `x` / `y` big-endian, its `key_ops` derived from the vault
//!    attributes, its `alg` from the curve, and its `kid` set to the
//!    key's own masked-key label — then AES-KWP-wrap it under the TMK.
//!
//! The command **persists nothing** (no vault write, no lifecycle
//! advance), so it records no rollback on the undo log.  Every recovered
//! secret (the TMK, the vault scalar, the big-endian `d`, and the COSE
//! plaintext) is scrubbed on EVERY exit path.  This command is
//! **Crypto-Officer-only**.

use tsra_fw_core_crypto_cose_key::encode_ec2_private_cose_key;
use tsra_fw_core_crypto_cose_key::key_op;
use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_ddi_tbor_types::TborDarcKeyWrapReq;
use tsra_fw_ddi_tbor_types::TborDarcKeyWrapResp;
use tsra_fw_ddi_tbor_types::DARC_UNWRAP_WRAPPED_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::MASKED_TMK_LEN;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::masking_key_id_for_scope;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// Fully-specified ECDSA `alg` identifier for `curve` (the non-deprecated
/// COSE "ESP" family; the deprecated polymorphic ES256/384/512 values are
/// rejected by the COSE encoder).
fn cose_alg_for_curve(curve: HsmEccCurve) -> i32 {
    match curve {
        HsmEccCurve::P256 => -9,  // ESP256
        HsmEccCurve::P384 => -51, // ESP384
        HsmEccCurve::P521 => -52, // ESP512
    }
}

/// The curve of an EC private vault key kind, or an error for any other
/// kind (the wrapped key must be an EC private key).
fn curve_from_ecc_kind(kind: HsmVaultKeyKind) -> HsmResult<HsmEccCurve> {
    match kind {
        HsmVaultKeyKind::Ecc256Private => Ok(HsmEccCurve::P256),
        HsmVaultKeyKind::Ecc384Private => Ok(HsmEccCurve::P384),
        HsmVaultKeyKind::Ecc521Private => Ok(HsmEccCurve::P521),
        _ => Err(HsmError::UnsupportedKeyType),
    }
}

/// Derive the COSE `key_ops` for the exported EC key from its vault
/// attributes — the inverse of `DarcKeyUnwrap`'s `cose_ops_to_usage`.
///
/// * `sign` / `verify` → the `[create signature, verify signature]`
///   signing group (possession of the private key implies both).
/// * `derive` → the `[derive key, derive bits]` (ECDH) group.
///
/// Both groups may be present (an on-device EC key is typically both
/// sign- and derive-capable); a subsequent `DarcKeyUnwrap` intersects the
/// advertised `key_ops` with the requested usage.  A key that grants
/// neither is rejected with [`HsmError::InvalidPermissions`].
fn cose_ops_for_attrs(attrs: HsmVaultKeyAttrs) -> HsmResult<([u8; 4], usize)> {
    let mut ops = [0u8; 4];
    let mut n = 0;
    if attrs.sign() || attrs.verify() {
        ops[n] = key_op::CREATE_SIGNATURE;
        ops[n + 1] = key_op::VERIFY_SIGNATURE;
        n += 2;
    }
    if attrs.derive() {
        ops[n] = key_op::DERIVE_KEY;
        ops[n + 1] = key_op::DERIVE_BITS;
        n += 2;
    }
    if n == 0 {
        return Err(HsmError::InvalidPermissions);
    }
    Ok((ops, n))
}

/// Convert a wire-LE coordinate `wire_le` (field-width low bytes are the
/// little-endian field element; any high bytes are zero pad) into the
/// big-endian COSE coordinate `be_out` (`field` bytes).
///
/// Returns [`HsmError::InvalidArg`] if any padding above the field width
/// is non-zero (a malformed wire coordinate).
fn wire_le_coord_to_be(be_out: &mut DmaBuf, wire_le: &DmaBuf, field: usize) -> HsmResult<()> {
    for i in 0..field {
        be_out[i] = wire_le[field - 1 - i];
    }
    for &b in wire_le[field..].iter() {
        if b != 0 {
            return Err(HsmError::InvalidArg);
        }
    }
    Ok(())
}

/// Handle a TBOR `DarcKeyWrap` request.
///
/// **Stateless**: unmasks and re-wraps the EC key without writing the
/// vault or advancing any lifecycle, so it records no rollback on the
/// `undo` log.  Every recovered secret (the TMK, the vault scalar, the
/// big-endian `d`, and the COSE plaintext) is scrubbed on EVERY exit
/// path — scope rewind does not clear DMA memory.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    // Session/state gating + masking-key routing use only the shared
    // `decode` view.  Every value captured out is `Copy`, so it outlives
    // the borrow.
    let (tmk_mk_id, key_mk_id): (HsmKeyId, HsmKeyId) = {
        let req = TborDarcKeyWrapReq::decode(req_buf)?;
        let sess_id = tsra_fw_hsm_pal_traits::HsmSessId::from(u16::from(req.session_id()));
        validate_crypto_officer_active_session(pal, io, sess_id)?;

        // The TMK and the local key are masked under partition-provisioned
        // masking keys, available only once the SD is initialized.
        if !part_state::part_state(pal, io)?.is_finalized() {
            return Err(HsmError::InvalidArg);
        }
        if !part_state::part_is_sd_initialized(pal, io)? {
            return Err(HsmError::InvalidArg);
        }

        // Route each masked blob to its masking key via the cleartext,
        // tag-bound metadata (before unmasking).
        let tmk_scope = peek_metadata(req.masked_tmk())?.usage_flags().scope();
        let tmk_mk_id = masking_key_id_for_scope(pal, io, tmk_scope)?;
        let key_scope = peek_metadata(req.masked_key())?.usage_flags().scope();
        let key_mk_id = masking_key_id_for_scope(pal, io, key_scope)?;

        (tmk_mk_id, key_mk_id)
    };

    // Fixed-size output slot allocated in the IO scope so it survives the
    // crypto scratch allocator's reset; filled inside the scope, read back
    // when the response is encoded.
    let wrapped_out = pal.dma_alloc(io, DARC_UNWRAP_WRAPPED_KEY_MAX_LEN)?;

    let wrapped_len = pal
        .alloc_scoped_async(io, async |alloc| -> HsmResult<usize> {
            // ── Recover the 32-byte TMK from its masked envelope. ──
            let masked_tmk = alloc.dma_alloc(MASKED_TMK_LEN)?;
            {
                let req = TborDarcKeyWrapReq::decode(req_buf)?;
                masked_tmk.copy_from_slice(req.masked_tmk());
            }
            let tmk_masking_key = pal.vault_key(io, tmk_mk_id)?;
            let unmask_res = async {
                let view = unmask(pal, io, tmk_masking_key, masked_tmk).await?;
                if !matches!(view.key_kind, HsmVaultKeyKind::DarcTmk) {
                    return Err(HsmError::UnsupportedKeyType);
                }
                let tmk = alloc.dma_alloc(view.target_key.len())?;
                tmk.copy_from_slice(view.target_key);
                Ok::<_, HsmError>(tmk)
            }
            .await;
            masked_tmk.zeroize();
            let tmk = unmask_res?;

            // ── Recover the local EC key, build its COSE_Key, and
            // AES-KWP-wrap it under the TMK.  Every recovered secret is
            // scrubbed on EVERY path — no fallible step may sit between a
            // secret's recovery and its `zeroize` guard, so all working
            // buffers are allocated and filled INSIDE the guarded blocks. ──
            let crypto_res = async {
                // Unmask the local EC key: recover the vault scalar (secret)
                // plus its curve, vault attributes, and masked-key label.
                let masked_key_len = {
                    let req = TborDarcKeyWrapReq::decode(req_buf)?;
                    req.masked_key().len()
                };
                let masked_key = alloc.dma_alloc(masked_key_len)?;
                {
                    let req = TborDarcKeyWrapReq::decode(req_buf)?;
                    masked_key.copy_from_slice(req.masked_key());
                }
                let key_masking_key = pal.vault_key(io, key_mk_id)?;
                let unmask_res = async {
                    let view = unmask(pal, io, key_masking_key, masked_key).await?;
                    let curve = curve_from_ecc_kind(view.key_kind)?;
                    let (ops_buf, ops_len) = cose_ops_for_attrs(view.key_attrs)?;
                    let vault = alloc.dma_alloc(view.target_key.len())?;
                    vault.copy_from_slice(view.target_key);
                    // `kid` is the key's own masked-key label (non-secret,
                    // bound in the GCM tag); copy it out before the view /
                    // blob are scrubbed.
                    let kid = alloc.dma_alloc(view.key_label.len())?;
                    kid.copy_from_slice(view.key_label);
                    Ok::<_, HsmError>((curve, ops_buf, ops_len, vault, kid))
                }
                .await;
                masked_key.zeroize();
                let (curve, ops_buf, ops_len, vault, kid) = unmask_res?;

                let build_res = async {
                    let field = curve.priv_key_len();
                    let wc = curve.wire_coord_len();
                    let wire_pub_len = curve.wire_pub_key_len();

                    // Re-derive the wire-LE public key and the big-endian
                    // COSE scalar `d` from the vault key.
                    let pub_wire = alloc.dma_alloc(wire_pub_len)?;
                    pal.ecc_pub_from_priv(io, curve, vault, &mut pub_wire[..wire_pub_len])
                        .await?;
                    let d = alloc.dma_alloc(field)?;
                    let d_res = async {
                        pal.ecc_vault_to_priv(io, curve, vault, Some(d))?;

                        // Big-endian coordinates from the wire-LE public key.
                        let x = alloc.dma_alloc(field)?;
                        let y = alloc.dma_alloc(field)?;
                        wire_le_coord_to_be(x, &pub_wire[0..wc], field)?;
                        wire_le_coord_to_be(y, &pub_wire[wc..2 * wc], field)?;

                        // Encode the EC2 private COSE_Key.
                        let cose = alloc.dma_alloc(DARC_UNWRAP_WRAPPED_KEY_MAX_LEN)?;
                        let cose_res = async {
                            let cose_len = encode_ec2_private_cose_key(
                                curve,
                                kid,
                                cose_alg_for_curve(curve),
                                &ops_buf[..ops_len],
                                x,
                                y,
                                d,
                                cose,
                            )?;

                            // AES-KWP-wrap the COSE plaintext under the TMK.
                            let wrapped_total = round_up_8(cose_len) + 8;
                            if wrapped_total > DARC_UNWRAP_WRAPPED_KEY_MAX_LEN {
                                return Err(HsmError::InvalidArg);
                            }
                            pal.aes_kwp_wrap(
                                io,
                                tmk,
                                &cose[..cose_len],
                                &mut wrapped_out[..wrapped_total],
                            )
                            .await?;
                            Ok::<_, HsmError>(wrapped_total)
                        }
                        .await;
                        cose.zeroize();
                        cose_res
                    }
                    .await;
                    d.zeroize();
                    d_res
                }
                .await;
                vault.zeroize();
                build_res
            }
            .await;

            tmk.zeroize();
            crypto_res
        })
        .await?;

    encode_response(pal, io, &wrapped_out[..wrapped_len])
}

/// Round `n` up to the next multiple of 8.
fn round_up_8(n: usize) -> usize {
    (n + 7) & !7
}

/// Encode the `DarcKeyWrap` response around the wrapped key.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    wrapped_key: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborDarcKeyWrapResp::encode(buf, 0, false)?
            .wrapped_key(wrapped_key)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
