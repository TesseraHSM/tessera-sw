// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unmasking pipeline ([`unmask`]): authenticate and
//! decrypt a masked-key AEAD blob in place, validate the embedded
//! [`MaskedKeyMetadata`], and hand the caller a borrowed
//! [`UnmaskedView`] covering the recovered plaintext.

use tsra_fw_core_crypto_aead_envelope::open_with_header as aead_open_with_header;
use tsra_fw_core_crypto_aead_envelope::parse_header as aead_parse_header;
use tsra_fw_core_crypto_aead_envelope::peek as aead_peek;
use tsra_fw_core_crypto_aead_envelope::peek_with_header as aead_peek_with_header;
use tsra_fw_core_crypto_aead_envelope::AeadHeader;
use tsra_fw_core_crypto_aead_envelope::HEADER_LEN as AEAD_HEADER_LEN;
use tsra_fw_hsm_pal_traits::copy_from_uncached;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmCrypto;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use zerocopy::FromBytes;

use crate::aead::format::MaskedKeyMetadata;
use crate::aead::format::META_FIELDS_LEN;
use crate::aead::format::META_LEN;

/// Borrowed view over a successfully unmasked blob.
///
/// All fields are sub-slices / references into the same `blob`
/// buffer passed to [`unmask`]; the `'a` lifetime ties them
/// back to that buffer.
#[derive(Debug)]
pub struct UnmaskedView<'a> {
    /// Vault key kind tag. Surfaced unchanged from the wire byte;
    /// values outside the known [`HsmVaultKeyKind`] variants appear
    /// as `Unknown(u8)` rather than failing decode, so callers can
    /// route or reject as they see fit.
    pub key_kind: HsmVaultKeyKind,

    /// Vault attribute bitfield (PKCS#11-style permissions).
    pub key_attrs: HsmVaultKeyAttrs,

    /// Partition SVN at mask time. Bound by the AEAD tag; the
    /// caller compares this against the current `part_mfgr_svn` to
    /// enforce anti-rollback policy.
    pub svn: u64,

    /// Owner-seed (BKS2) lineage identifier at mask time. Bound by
    /// the AEAD tag; the caller compares this against the current
    /// `part_owner_svn` to enforce lineage policy.
    pub owner_seed_id: u16,

    /// Caller-supplied label bound by the GCM tag. Length matches
    /// the original `params.key_label` length passed to
    /// [`mask`](crate::aead::mask).
    pub key_label: &'a [u8],

    /// Recovered target-key bytes (decrypted in place inside the
    /// caller's `blob`).  Borrows the `blob` buffer directly (a
    /// [`DmaBuf`] sub-view of the decrypted payload region), so callers
    /// that forward the key to another PAL/crypto verb needing a
    /// `&DmaBuf` can pass it through without an intermediate copy.
    pub target_key: &'a DmaBuf,
}

/// A word-aligned buffer for a metadata copy (burst copies need alignment).
#[repr(C, align(4))]
struct MetaCopy([u8; META_LEN]);

/// In-place unmask: parse, authenticate, decrypt, and validate a
/// masked-key blob.
///
/// `blob` MUST contain the complete blob produced by
/// [`mask`](crate::aead::mask) with the same `key`. `blob.len()` is taken
/// as the exact blob length.
///
/// `key`'s required length is determined by the AEAD algorithm byte
/// parsed from the blob's envelope header; mismatches surface as
/// [`HsmError::InvalidKeyLength`](tsra_fw_hsm_pal_traits::HsmError::InvalidKeyLength).
///
/// # Returns
///
/// * `Ok(view)` — tag verified, ciphertext decrypted in place, every
///   metadata invariant satisfied.
/// * `Err(HsmError::AesGcmDecryptTagDoesNotMatch)` — tag mismatch
///   (tamper / wrong key / corrupted blob).
/// * `Err(HsmError::MaskedKeyDecodeFailed)` — any metadata
///   invariant violation: AAD length not 192, bad magic, unsupported
///   version, `key_label_len > KEY_LABEL_MAX`, non-zero pad after
///   the label, or non-zero reserved tail.
/// * Any [`HsmError`] surfaced by
///   [`aead_envelope::open`](aead_open).
pub async fn unmask<'a>(
    crypto: &impl HsmCrypto,
    io: &impl HsmIo,
    key: &DmaBuf,
    blob: &'a mut DmaBuf,
) -> HsmResult<UnmaskedView<'a>> {
    let header = aead_parse_header(blob)?;
    unmask_with_header(crypto, io, key, blob, header).await
}

/// [`unmask`] for a blob whose head [`peek_head`] has read, so its
/// envelope header is not read again.
///
/// # Errors
///
/// As [`unmask`].
pub async fn unmask_with_head<'a>(
    crypto: &impl HsmCrypto,
    io: &impl HsmIo,
    key: &DmaBuf,
    blob: &'a mut DmaBuf,
    head: &BlobHead,
) -> HsmResult<UnmaskedView<'a>> {
    unmask_with_header(crypto, io, key, blob, head.header).await
}

async fn unmask_with_header<'a>(
    crypto: &impl HsmCrypto,
    io: &impl HsmIo,
    key: &DmaBuf,
    blob: &'a mut DmaBuf,
    header: AeadHeader,
) -> HsmResult<UnmaskedView<'a>> {
    // aead_envelope::open validates the key length against the alg in
    // the envelope header, verifies the AEAD tag, and decrypts the
    // ciphertext region in place. Tag mismatch surfaces as
    // HsmError::AesGcmDecryptTagDoesNotMatch.
    let env = aead_open_with_header(crypto, io, key, blob, header).await?;

    // Envelope-level schema check: only a 192 B metadata AAD is a
    // masked-key blob. The AEAD algorithm is unconstrained here —
    // the metadata format is alg-agnostic, so any AeadAlg supported
    // by aead_envelope is valid.
    if env.aad.len() != META_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }

    // Parse and validate the fields ahead of the label from a copy of the
    // AAD's first `META_FIELDS_LEN` bytes: the AAD sits in uncached DMA
    // memory, which one burst read fetches far faster than validation
    // reads it field by field. The rest of the copy stays zero, and the
    // label padding and reserved tail are not checked: the tag has just
    // authenticated every byte of the AAD, so `new_v1` built it, zeroing
    // them. (`peek_metadata`, on unauthenticated bytes, still checks.)
    // Reading all 192 bytes out of uncached memory for that check cost
    // ~5% of an AES-CBC command. `ref_from_bytes` never panics; the copy
    // is `META_LEN` bytes.
    let mut copy = MetaCopy([0; META_LEN]);
    copy_from_uncached(&mut copy.0[..META_FIELDS_LEN], &env.aad[..META_FIELDS_LEN]);
    let metadata =
        MaskedKeyMetadata::ref_from_bytes(&copy.0).map_err(|_| HsmError::MaskedKeyDecodeFailed)?;

    metadata.validate_v1_fields()?;

    // The label is borrowed from the blob, not the copy. validate_v1
    // guarantees key_label_len ≤ KEY_LABEL_MAX, so this range cannot fail.
    let key_label = env
        .aad
        .get(metadata.key_label_range()?)
        .ok_or(HsmError::MaskedKeyDecodeFailed)?;

    Ok(UnmaskedView {
        key_label,
        key_kind: metadata.key_kind(),
        key_attrs: metadata.usage_flags(),
        svn: metadata.svn.get(),
        owner_seed_id: metadata.owner_seed_id.get(),
        target_key: env.payload,
    })
}

/// Byte offset of `usage_flags` within [`MaskedKeyMetadata`]:
/// `magic(4) ‖ version(2) ‖ key_kind(1) ‖ key_label_len(1)`.
const USAGE_FLAGS_OFF: usize = 8;

/// Read just the key scope from a masked blob's metadata.
///
/// A handler needs the scope before it can resolve the masking key, but
/// at that point the blob is still **unauthenticated** -- the GCM tag has
/// not been checked. [`peek_metadata`] parses and fully validates the
/// metadata there, which costs roughly 4000 cycles per request and then
/// happens a second time inside [`unmask`], after authentication.
///
/// This reads the one field that is actually needed and validates
/// nothing else, because nothing else can be trusted yet. A corrupt or
/// attacker-chosen scope selects the wrong masking key, and the tag
/// check then fails; a corrupt anything-else is caught by
/// `validate_v1` inside `unmask`, which runs on authenticated bytes.
/// So the validation is not skipped, only moved to the point where its
/// input is trustworthy -- which is where it belonged.
pub fn peek_scope(blob: &DmaBuf) -> HsmResult<HsmKeyScope> {
    peek_head(blob).map(|head| head.scope)
}

/// Bytes of `usage_flags` [`peek_head`] reads: the low word, which holds
/// the scope (bits 17–19).
const USAGE_FLAGS_SCOPE_LEN: usize = 4;
const _: () = assert!(
    HsmVaultKeyAttrs::new()
        .with_scope(HsmKeyScope::SecurityDomain)
        .into_bits()
        >> (8 * USAGE_FLAGS_SCOPE_LEN)
        == 0,
    "the scope must lie in the bytes of `usage_flags` that `peek_head` reads"
);

/// Bytes of a blob [`peek_head`] reads: the envelope header, a 12-byte
/// IV, and the metadata up to the end of the low word of `usage_flags` —
/// 32 bytes, one eight-word burst.
const BLOB_HEAD_LEN: usize = AEAD_HEADER_LEN + 12 + USAGE_FLAGS_OFF + USAGE_FLAGS_SCOPE_LEN;

/// A word-aligned buffer for a blob's head (burst copies need alignment).
#[repr(C, align(4))]
struct HeadCopy([u8; BLOB_HEAD_LEN]);

/// What [`peek_head`] read from a masked-key blob: its key scope, and its
/// envelope header for [`unmask_with_head`].
#[derive(Debug, Clone, Copy)]
pub struct BlobHead {
    scope: HsmKeyScope,
    header: AeadHeader,
}

impl BlobHead {
    /// The scope whose masking key masked the blob. Unauthenticated until
    /// the blob is unmasked; see [`peek_scope`].
    pub fn scope(&self) -> HsmKeyScope {
        self.scope
    }
}

/// [`peek_scope`], also keeping the blob's envelope header for
/// [`unmask_with_head`]. The blob's cleartext start is read in one burst:
/// it sits in DMA memory, which the CPU may read uncached at a fixed cost
/// per load.
///
/// # Errors
///
/// As [`peek_scope`].
pub fn peek_head(blob: &DmaBuf) -> HsmResult<BlobHead> {
    let mut head = HeadCopy([0; BLOB_HEAD_LEN]);
    let header = match blob.get(..BLOB_HEAD_LEN) {
        Some(src) => {
            copy_from_uncached(&mut head.0, src);
            aead_parse_header(&head.0)?
        }
        // Too short to be a blob: let the envelope parse say why.
        None => aead_parse_header(blob)?,
    };
    let env = aead_peek_with_header(blob, header)?;
    if env.aad.len() != META_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    let flags = AEAD_HEADER_LEN + env.iv.len() + USAGE_FLAGS_OFF;
    let raw = head
        .0
        .get(flags..flags + USAGE_FLAGS_SCOPE_LEN)
        .and_then(|b| <[u8; USAGE_FLAGS_SCOPE_LEN]>::try_from(b).ok())
        .ok_or(HsmError::MaskedKeyDecodeFailed)?;
    Ok(BlobHead {
        scope: HsmVaultKeyAttrs::from_bits(u64::from(u32::from_le_bytes(raw))).scope(),
        header,
    })
}

/// Peek the cleartext [`MaskedKeyMetadata`] of a masked-key blob **without
/// the masking key** — i.e. without verifying the AEAD tag.
///
/// The metadata is the envelope's AAD region; it is cleartext but bound
/// by the tag, so a tampered blob would still fail [`unmask`]. This peek
/// exists purely for reading cleartext bindings (e.g. the `{svn,
/// owner_seed_id}` platform identity or the key `scope`) *before*
/// unmasking; its result MUST NOT be trusted until a subsequent `unmask`
/// verifies the tag.
///
/// The blob's envelope header and framing are validated exactly as
/// [`unmask`] validates them — magic, reserved byte, `alg`, `aad_len`
/// granularity, IV length (derived from the parsed `alg`), and the
/// minimum envelope length (`header ‖ iv ‖ aad ‖ tag`) — by delegating
/// to the envelope crate's key-free peek. Only the AEAD tag
/// verification and payload decryption are skipped, so this is the
/// key-free analogue of [`unmask`], sharing its `META_LEN` and v1
/// metadata checks.
///
/// # Errors
///
/// * [`HsmError::MaskedKeyDecodeFailed`] — the AAD region is not
///   `META_LEN` bytes, or the metadata fails v1 validation.
/// * Any [`HsmError`] surfaced by the envelope header / framing parse
///   (malformed header, unsupported `alg`, or a blob too short to hold a
///   complete `header ‖ iv ‖ aad ‖ tag` envelope).
pub fn peek_metadata(blob: &DmaBuf) -> HsmResult<&MaskedKeyMetadata> {
    // Parse + validate the envelope header and framing WITHOUT the
    // masking key (no tag verification, no decryption). This checks the
    // magic, reserved byte, `alg`, `aad_len` granularity, derives the IV
    // length from the parsed `alg`, and requires the full envelope length
    // (header ‖ iv ‖ aad ‖ tag) — so a non-envelope, wrong-alg, or
    // truncated (e.g. tag-less) blob is rejected here rather than yielding
    // "valid" metadata from a fixed offset.
    let env = aead_peek(blob)?;

    // Envelope-level schema check: only a META_LEN-byte AAD is a
    // masked-key blob. Identical to the check in `unmask`.
    if env.aad.len() != META_LEN {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }

    // Parse the META_LEN-byte AAD region as MaskedKeyMetadata.
    // `ref_from_bytes` never panics; the length check above guarantees a
    // META_LEN-byte slice.
    let metadata =
        MaskedKeyMetadata::ref_from_bytes(env.aad).map_err(|_| HsmError::MaskedKeyDecodeFailed)?;
    metadata.validate_v1()?;
    Ok(metadata)
}
