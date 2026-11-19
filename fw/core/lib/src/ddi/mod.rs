// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI command dispatch — split per wire codec.
//!
//! - [`mbor`] hosts the original MBOR-encoded DDI command handlers
//!   reached via the `OP_MBOR` SQE opcode.
//! - [`tbor`] hosts the TBOR-encoded DDI command handlers reached via
//!   the `OP_TBOR` SQE opcode.
//!
//! Both sub-modules expose a `dispatch` entry point invoked from
//! [`crate::Hsm::handle_mbor_op`] / [`crate::Hsm::handle_tbor_op`] and
//! a per-codec error encoder used when post-decode failures need to be
//! surfaced as a typed response body rather than a CQE status code.

pub(crate) mod mbor;
pub(crate) mod tbor;

// Re-expose crate-root symbols (HsmPal, HsmIo, HsmError, …) to the
// child modules' `use super::*;` imports.
use super::*;

/// Recovers the unmasked 80-byte `BK_BOOT` on demand.
///
/// Mirrors the reference firmware: the raw boot key is **never stored**
/// — only its BKx-masked form (`Masked_BK_BOOT`, persisted by `InitBk3`)
/// is.  This recomputes the partition's `BKx` from the firmware boot
/// seed bound to `(svn, owner)` and unmasks the persisted blob, leaving
/// `BK_BOOT` in `out`.
///
/// Shared across both wire codecs (`EstablishCredential` / `OpenSession`
/// / `InitBk3` in [`mbor`], and `OpenSessionFinish` in [`tbor`]), so it
/// lives at the command level rather than in either codec — keeping
/// `tbor` independent of `mbor`.
///
/// `out` must be exactly [`BK_BOOT_LEN`] (80) bytes.  Returns
/// [`HsmError::PartPropNotFound`] if `Masked_BK_BOOT` has not been
/// provisioned (i.e. before `InitBk3`).
pub(crate) async fn recover_bk_boot<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    // Copy the persisted masked BK_BOOT into a working buffer and
    // unmask it (the raw key is never stored; it is created masked at
    // partition allocation).
    let masked_len = crate::part_state::part_masked_bk_boot(pal, io)?.len();
    let masked_buf = pal.dma_alloc(io, masked_len)?;
    {
        let src = crate::part_state::part_masked_bk_boot(pal, io)?;
        masked_buf.copy_from_slice(&src[..masked_len]);
    }
    tsra_fw_core_crypto_key_derive::unmask_bk_boot(pal, io, masked_buf, out).await
}

/// BK3 plaintext length in bytes (the 48-byte owner backup key).
pub(crate) const BK3_LEN: usize = 48;

/// Length of a raw P-384 public key (`x ‖ y`, two 48-byte coordinates).
const P384_PUB_RAW_LEN: usize = 2 * 48;

/// Verifies the POTA signature over the partition identity public key.
///
/// The signature is computed by the host over
/// `SHA-384( 0x04 ‖ x ‖ y )`, the 97-byte SEC1-uncompressed form of
/// the partition identity P-384 public key, where `x`/`y` are the raw
/// coordinates in natural **big-endian** order (as used in DER / X.509).
/// We materialize the same 97-byte form locally from `part_id_pub_key`
/// and verify the supplied signature against it.  The signer public key
/// and the signature are consumed in the PAL's operand (device) byte
/// order.
///
/// Lives at the command level rather than in the `mbor` codec, so a `tbor`
/// command can reuse it without depending on `mbor`; `EstablishCredential`
/// is its only caller today.
pub(crate) async fn verify_pota_signature<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    signer_pub_key_raw: &HsmDmaBuf,
    signature_raw: &HsmDmaBuf,
) -> HsmResult<()> {
    let id_uncompressed = pal.dma_alloc(io, P384_PUB_RAW_LEN + 4)?.split_at_mut(3).1;
    id_uncompressed[0] = 0x04;
    crate::part_state::part_id_pub_key(pal, io, id_uncompressed.split_at_mut(1).1).await?;

    // `ecc_verify` consumes the digest in operand order.
    let digest = pal.dma_alloc(io, HsmHashAlgo::Sha384.digest_len())?;
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

/// Unmasks the partition `BK3` blob in place using `BK_BOOT` and
/// writes the 48-byte recovered plaintext into `bk3_out`.
///
/// `masked_bk3` is the envelope produced by a prior `InitBk3` call:
/// BK3 plaintext sealed under the partition's `BK_BOOT` (an 80-byte
/// AES-CBC-256 + HMAC-SHA-384 masking key).
///
/// `unmask` decrypts the ciphertext slot inside the
/// blob in place, so this helper takes the blob as `&mut HsmDmaBuf`.
/// After unmask, the 48-byte BK3 plaintext is copied out to `bk3_out` so
/// the caller can hold it for the remaining handler steps.
///
/// `bk3_out` must be exactly [`BK3_LEN`] (48) bytes.
///
/// Lives at the command level rather than in the `mbor` codec, so a `tbor`
/// command can reuse it without depending on `mbor`; `EstablishCredential`
/// is its only caller today.
pub(crate) async fn unmask_partition_bk3<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    masked_bk3: &mut HsmDmaBuf,
    bk3_out: &mut HsmDmaBuf,
) -> HsmResult<()> {
    let bk_boot = pal.dma_alloc(io, BK_BOOT_LEN)?;
    recover_bk_boot(pal, io, bk_boot).await?;

    let layout = tsra_fw_core_crypto_key_masking::cbc::unmask(pal, io, bk_boot, masked_bk3).await?;
    if layout.plaintext_max_len < BK3_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    bk3_out
        .copy_from_slice(&masked_bk3[layout.plaintext_offset..layout.plaintext_offset + BK3_LEN]);
    Ok(())
}

/// Map an HMAC vault kind to the hash algorithm whose digest length is
/// the MAC tag size.
///
/// Accepts both the fixed-length (`_HmacSha*`) and variable-length
/// (`VarLenHmacSha*`) HMAC kinds.  Any non-HMAC kind returns
/// [`HsmError::InvalidKeyType`].
///
/// Shared across both wire codecs (`Hmac` in [`mbor`], and the HMAC
/// crypto commands in [`tbor`]), so it lives at the command level rather
/// than in either codec — keeping `tbor` independent of `mbor`.
pub(crate) fn hmac_hash(kind: HsmVaultKeyKind) -> HsmResult<HsmHashAlgo> {
    match kind {
        HsmVaultKeyKind::_HmacSha256 | HsmVaultKeyKind::VarLenHmacSha256 => Ok(HsmHashAlgo::Sha256),
        HsmVaultKeyKind::_HmacSha384 | HsmVaultKeyKind::VarLenHmacSha384 => Ok(HsmHashAlgo::Sha384),
        HsmVaultKeyKind::_HmacSha512 | HsmVaultKeyKind::VarLenHmacSha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidKeyType),
    }
}
