// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcKeyUnwrap` handler.
//!
//! Imports an externally-generated **EC private key** that was:
//!
//! 1. encoded as an EC2 `COSE_Key`,
//! 2. AES-KWP (RFC 5649) wrapped under a DARC Transfer Masking Key (TMK),
//!    where
//! 3. the TMK is supplied as the masked envelope produced by
//!    [`DarcTmkImport`](super::darc_tmk_import).
//!
//! Flow:
//!
//! 1. Decode; gate to a Crypto-Officer, `Active` session on an
//!    `Initialized` partition whose security domain is initialized (the
//!    TMK is masked under the SDMK, and the output masking keys are
//!    provisioned by partition setup).  Restrict the output `scope` to
//!    `Ephemeral` / `Local`.
//! 2. Route the masked TMK to its masking key via its cleartext metadata,
//!    unmask it (must be a [`DarcTmk`](HsmVaultKeyKind::DarcTmk) key), and
//!    recover the 32-byte TMK.
//! 3. AES-KWP-unwrap `wrapped_key` with the TMK → the COSE_Key plaintext.
//! 4. Decode the EC2 private `COSE_Key` (P-256 / P-384 / P-521 only) →
//!    curve, `alg`, `key_ops`, and the big-endian `d` / `x` / `y`.
//! 5. Convert `d` to the vault representation, re-derive the public key,
//!    and enforce the COSE private/public consistency (`d·G == (x, y)`).
//! 6. Intersect the requested `key_usage` with the COSE `key_ops`, mask
//!    the recovered private key under the requested scope's masking key,
//!    and return the masked key plus the wire public key.
//!
//! The command **persists nothing** (no vault write, no lifecycle
//! advance), so it records no rollback on the undo log.  Every recovered
//! secret (the TMK, the COSE plaintext, and the vault scalar) is scrubbed
//! on EVERY exit path.  This command is **Crypto-Officer-only**.

use tsra_fw_core_crypto_cose_key::key_op;
use tsra_fw_core_crypto_cose_key::parse_ec2_private_cose_key;
use tsra_fw_core_crypto_cose_key::CoseKeyOps;
use tsra_fw_core_crypto_key_masking::aead::mask;
use tsra_fw_core_crypto_key_masking::aead::peek_metadata;
use tsra_fw_core_crypto_key_masking::aead::unmask;
use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
use tsra_fw_core_crypto_key_masking::aead::MaskParams;
use tsra_fw_ddi_tbor_types::KeyUsage;
use tsra_fw_ddi_tbor_types::TborDarcKeyUnwrapReq;
use tsra_fw_ddi_tbor_types::TborDarcKeyUnwrapResp;
use tsra_fw_ddi_tbor_types::DARC_UNWRAP_MASKED_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::DARC_UNWRAP_PUB_KEY_MAX_LEN;
use tsra_fw_ddi_tbor_types::MASKED_TMK_LEN;
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
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;

use super::masking_key_id_for_scope;
use super::resolve_masking_key;
use super::sd_backup;
use super::validate_crypto_officer_active_session;
use crate::part_state;

/// Envelope key-label recorded in the masked key's `MaskedKeyMetadata`.
const DARC_UNWRAP_KEY_LABEL: &[u8] = b"DarcKeyUnwrap";

/// The recovered EC private key's vault kind for `curve`.
fn ecc_vault_kind(curve: HsmEccCurve) -> HsmVaultKeyKind {
    match curve {
        HsmEccCurve::P256 => HsmVaultKeyKind::Ecc256Private,
        HsmEccCurve::P384 => HsmVaultKeyKind::Ecc384Private,
        HsmEccCurve::P521 => HsmVaultKeyKind::Ecc521Private,
    }
}

/// Map the COSE `key_ops` restriction onto the [`KeyUsage`] bits that are
/// meaningful for an EC private key.
///
/// * `create signature` / `verify signature` → the `sign`+`verify`
///   signing-key group (possession of the private key implies both).
/// * `derive key` / `derive bits` → the `derive` (ECDH) group.
///
/// Operations that are not applicable to an EC private key
/// (encrypt / wrap / MAC …) contribute nothing.
fn cose_ops_to_usage(ops: CoseKeyOps) -> u64 {
    let mut usage = 0u64;
    if ops.contains(key_op::CREATE_SIGNATURE) || ops.contains(key_op::VERIFY_SIGNATURE) {
        usage |= KeyUsage::SIGN | KeyUsage::VERIFY;
    }
    if ops.contains(key_op::DERIVE_KEY) || ops.contains(key_op::DERIVE_BITS) {
        usage |= KeyUsage::DERIVE;
    }
    usage
}

/// Derive the vault usage attributes for the recovered EC key from the
/// **effective** usage (the request's [`KeyUsage`] already intersected
/// with the COSE `key_ops`), plus the output `scope`.
///
/// Exactly one usage group must remain after the intersection — the
/// `sign`+`verify` signing group or the `derive` (ECDH) group.  An empty
/// or ambiguous intersection is rejected with
/// [`HsmError::InvalidPermissions`]: the caller asked for a permission the
/// COSE key does not grant (or asked for none).
fn attrs_for_ecc(scope: HsmKeyScope, usage: KeyUsage) -> HsmResult<HsmVaultKeyAttrs> {
    let sign_verify = usage.sign() && usage.verify();
    let derive = usage.derive();
    if sign_verify as u8 + derive as u8 != 1 {
        return Err(HsmError::InvalidPermissions);
    }
    let base = HsmVaultKeyAttrs::new().with_scope(scope);
    Ok(if sign_verify {
        base.with_sign(true).with_verify(true)
    } else {
        base.with_derive(true)
    })
}

/// Verify that the wire-LE public key `wire_pub` (`x_le ‖ y_le`, each
/// `curve.wire_coord_len()` bytes) re-derived from the recovered scalar
/// equals the big-endian COSE coordinates `x` / `y` — the COSE
/// private/public consistency requirement (spec §4.1, §10.9).
///
/// Public-key material, so an ordinary (non-constant-time) comparison is
/// appropriate.
fn pub_key_matches(curve: HsmEccCurve, x: &DmaBuf, y: &DmaBuf, wire_pub: &DmaBuf) -> bool {
    let coord_raw = curve.priv_key_len();
    let wc = curve.wire_coord_len();
    if wire_pub.len() != 2 * wc {
        return false;
    }
    coord_matches(&wire_pub[0..wc], x, coord_raw)
        && coord_matches(&wire_pub[wc..2 * wc], y, coord_raw)
}

/// Whether the wire-LE coordinate `wire_le` (field-width, low bytes are
/// the reversed field element, any high bytes are zero pad) equals the
/// big-endian coordinate `be` (`coord_raw` bytes).
fn coord_matches(wire_le: &DmaBuf, be: &DmaBuf, coord_raw: usize) -> bool {
    if be.len() != coord_raw {
        return false;
    }
    for i in 0..coord_raw {
        if wire_le[i] != be[coord_raw - 1 - i] {
            return false;
        }
    }
    // Any padding above the raw field width must be zero.
    for i in coord_raw..wire_le.len() {
        if wire_le[i] != 0 {
            return false;
        }
    }
    true
}

/// Handle a TBOR `DarcKeyUnwrap` request.
///
/// **Stateless**: recovers and re-masks the EC key without writing the
/// vault or advancing any lifecycle, so it records no rollback on the
/// `undo` log.  Every recovered secret (the TMK, the COSE plaintext, and
/// the vault scalar) is scrubbed on EVERY exit path — scope rewind does
/// not clear DMA memory.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    // Session/state gating + masking-key routing use only the shared
    // `decode` view.  Every value captured out is `Copy`, so it outlives
    // the borrow.
    let (tmk_mk_id, out_scope, sess_id, req_usage): (HsmKeyId, HsmKeyScope, HsmSessId, KeyUsage) = {
        let req = TborDarcKeyUnwrapReq::decode(req_buf)?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_crypto_officer_active_session(pal, io, sess_id)?;

        // The TMK is masked under the SDMK, and the output masking keys
        // are provisioned by partition / SD setup.
        if !part_state::part_state(pal, io)?.is_finalized() {
            return Err(HsmError::InvalidArg);
        }
        if !part_state::part_is_sd_initialized(pal, io)? {
            return Err(HsmError::InvalidArg);
        }

        // The recovered key may only be re-masked under a partition-scoped
        // masking key (`Ephemeral` / `Local`).
        let out_scope = HsmKeyScope(req.scope().0);
        match out_scope {
            HsmKeyScope::Ephemeral | HsmKeyScope::Local => {}
            _ => return Err(HsmError::UnsupportedKeyScope),
        }

        // Route the masked TMK to its masking key via the cleartext,
        // tag-bound metadata (before unmasking).
        let tmk_scope = peek_metadata(req.masked_tmk())?.usage_flags().scope();
        let tmk_mk_id = masking_key_id_for_scope(pal, io, tmk_scope)?;

        (tmk_mk_id, out_scope, sess_id, req.key_usage())
    };

    // Platform identity bound into the masked blob (anti-rollback on
    // re-import).
    let (svn, owner) = sd_backup::platform_svn_owner(pal)?;

    // Fixed-size output slots allocated in the IO scope so they survive
    // the crypto scratch allocator's reset; filled inside the scope, read
    // back when the response is encoded.
    let masked_out = pal.dma_alloc(io, DARC_UNWRAP_MASKED_KEY_MAX_LEN)?;
    let pub_out = pal.dma_alloc(io, DARC_UNWRAP_PUB_KEY_MAX_LEN)?;

    let (key_kind, masked_len, pub_len) = pal
        .alloc_scoped_async(io, async |alloc| -> HsmResult<(u8, usize, usize)> {
            // ── Recover the 32-byte TMK from its masked envelope. ──
            let masked_tmk = alloc.dma_alloc(MASKED_TMK_LEN)?;
            {
                let req = TborDarcKeyUnwrapReq::decode(req_buf)?;
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

            // ── AES-KWP-unwrap the COSE_Key, decode it, convert to the
            // vault scalar, re-derive + check the public key, and mask the
            // recovered key.  Every recovered secret is scrubbed on EVERY
            // path — no fallible step may sit between the TMK's recovery
            // and its `zeroize` guard, so `wrapped` is allocated and filled
            // INSIDE the guarded block. ──
            let crypto_res = async {
                let wrapped_len = {
                    let req = TborDarcKeyUnwrapReq::decode(req_buf)?;
                    req.wrapped_key().len()
                };
                let wrapped = alloc.dma_alloc(wrapped_len)?;
                {
                    let req = TborDarcKeyUnwrapReq::decode(req_buf)?;
                    wrapped.copy_from_slice(req.wrapped_key());
                }

                // KWP output is at most `input - 8` bytes.
                let cose = alloc.dma_alloc(wrapped_len)?;
                let cose_res = async {
                    let mli = pal.aes_kwp_unwrap(io, tmk, wrapped, cose).await?;

                    // Decode + all EC math while the COSE plaintext (which
                    // holds `d`) is borrowed; return only owned results so
                    // the borrow ends before `cose` is scrubbed.
                    let parsed = parse_ec2_private_cose_key(&cose[..mli])?;
                    let curve = parsed.curve;

                    // Effective usage = request ∩ COSE key_ops.
                    let effective =
                        KeyUsage::from_bits(req_usage.bits() & cose_ops_to_usage(parsed.key_ops));
                    let attrs = attrs_for_ecc(out_scope, effective)?;
                    let key_kind = ecc_vault_kind(curve);

                    let vault = alloc.dma_alloc(curve.wire_coord_len())?;
                    let vault_res = async {
                        pal.ecc_priv_to_vault(io, curve, parsed.d, Some(vault))?;

                        // Re-derive the wire public key and enforce COSE
                        // private/public consistency against `x` / `y`.
                        let wire_pub_len = curve.wire_pub_key_len();
                        pal.ecc_pub_from_priv(io, curve, vault, &mut pub_out[..wire_pub_len])
                            .await?;
                        if !pub_key_matches(curve, parsed.x, parsed.y, &pub_out[..wire_pub_len]) {
                            return Err(HsmError::InvalidArg);
                        }

                        // Mask the recovered private key under the output
                        // scope's masking key.
                        let masking_key = resolve_masking_key(pal, io, out_scope, sess_id)?;
                        let key_label = alloc.dma_alloc(DARC_UNWRAP_KEY_LABEL.len())?;
                        key_label.copy_from_slice(DARC_UNWRAP_KEY_LABEL);
                        let params = MaskParams {
                            key_kind,
                            key_attrs: attrs,
                            svn,
                            owner_seed_id: owner,
                            key_label,
                        };
                        let masked_len = mask(
                            pal,
                            io,
                            alloc,
                            AeadAlg::AesGcm256,
                            masking_key,
                            &params,
                            vault,
                            Some(masked_out),
                        )
                        .await?;
                        Ok::<_, HsmError>((key_kind.0, masked_len, wire_pub_len))
                    }
                    .await;
                    vault.zeroize();
                    vault_res
                }
                .await;
                cose.zeroize();
                cose_res
            }
            .await;

            tmk.zeroize();
            crypto_res
        })
        .await?;

    encode_response(
        pal,
        io,
        key_kind,
        &masked_out[..masked_len],
        &pub_out[..pub_len],
    )
}

/// Encode the `DarcKeyUnwrap` response around the masked key + public key.
fn encode_response<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    key_kind: u8,
    masked_key: &DmaBuf,
    pub_key: &DmaBuf,
) -> HsmResult<&'p DmaBuf> {
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborDarcKeyUnwrapResp::encode(buf, 0, false)?
            .key_kind(key_kind)?
            .masked_key(masked_key)?
            .pub_key(pub_key)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
