// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unmasking pipeline ([`unmask`]): authenticate and
//! decrypt a masked-key AEAD blob in place, validate the embedded
//! [`MaskedKeyMetadata`], and hand the caller a borrowed
//! [`UnmaskedView`] covering the recovered plaintext.

use core::mem::MaybeUninit;

use tsra_fw_core_crypto_aead_envelope::peek as aead_peek;
use tsra_fw_core_crypto_aead_envelope::peek_header as aead_peek_header;
use tsra_fw_core_crypto_aead_envelope::AeadAlg;
use tsra_fw_core_crypto_aead_envelope::AeadPeek;
use tsra_fw_core_crypto_aead_envelope::HEADER_LEN;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyMasking;
use tsra_fw_hsm_pal_traits::HsmKeyScope;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use tsra_fw_hsm_pal_traits::HsmVaultKeyKind;
use zerocopy::FromBytes;

use crate::aead::format::all_zero;
use crate::aead::format::MaskedKeyMetadata;
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
    /// [`HsmDmaBuf`] sub-view of the decrypted payload region), so callers
    /// that forward the key to another PAL/crypto verb needing a
    /// `&HsmDmaBuf` can pass it through without an intermediate copy.
    pub target_key: &'a HsmDmaBuf,
}

/// A word-aligned buffer for a metadata copy (burst copies need alignment).
#[repr(C, align(4))]
struct MetaCopy([MaybeUninit<u8>; META_LEN]);

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
///   invariant violation: AAD length not 192, unaligned payload, bad magic, unsupported
///   version, `key_label_len > KEY_LABEL_MAX`, non-zero pad after
///   the label, or non-zero reserved tail.
/// * Any [`HsmError`] surfaced by the masking PAL or envelope parser.
pub async fn unmask<'a, P: HsmKeyMasking>(
    crypto: &P,
    io: &P::Io,
    key: &HsmDmaBuf,
    blob: &'a mut HsmDmaBuf,
) -> HsmResult<UnmaskedView<'a>> {
    unmask_in(crypto, io, key, blob, None).await
}

/// [`unmask`] of a blob whose framing [`peek_frame`] has checked, as
/// `frame` attests: the framing is not read out of the blob again.
///
/// `frame` attests only the blob at the address and of the length
/// [`peek_frame`] saw, unchanged since; for any other, the framing is
/// checked as [`unmask`] checks it.
pub async fn unmask_framed<'a, P: HsmKeyMasking>(
    crypto: &P,
    io: &P::Io,
    key: &HsmDmaBuf,
    blob: &'a mut HsmDmaBuf,
    frame: MaskedFrame,
) -> HsmResult<UnmaskedView<'a>> {
    unmask_in(crypto, io, key, blob, Some(frame)).await
}

async fn unmask_in<'a, P: HsmKeyMasking>(
    crypto: &P,
    io: &P::Io,
    key: &HsmDmaBuf,
    blob: &'a mut HsmDmaBuf,
    frame: Option<MaskedFrame>,
) -> HsmResult<UnmaskedView<'a>> {
    if !frame.is_some_and(|f| f.attests(blob)) {
        check_frame(blob)?;
    }
    let alg = AeadAlg::AesGcm256;
    let aad_at = HEADER_LEN + alg.iv_len();
    let payload_at = aad_at + META_LEN;
    let tag_at = blob.len() - alg.tag_len();
    crypto
        .key_unmask_in_place(io, key, META_LEN, &mut blob[HEADER_LEN..])
        .await?;
    // Decryption leaves the header and the AAD as they were, so the AAD is
    // where the peek above found it; no need to parse the header again.
    let blob: &'a HsmDmaBuf = blob;
    let aad = &blob[aad_at..payload_at];

    // Parse and validate a copy of the 192 B AAD region: it sits in DMA
    // memory, which may be uncached, so one burst read fetches it far
    // faster than validation would read it field by field in place. The
    // copy overwrites the whole buffer, which is therefore not zeroed first.
    // `ref_from_bytes` never panics; the length check above guarantees a
    // 192 B slice.
    let mut copy = MetaCopy([const { MaybeUninit::uninit() }; META_LEN]);
    let Some(meta) = aad.copy_to_uninit(&mut copy.0) else {
        return Err(HsmError::MaskedKeyDecodeFailed);
    };
    let metadata =
        MaskedKeyMetadata::ref_from_bytes(meta).map_err(|_| HsmError::MaskedKeyDecodeFailed)?;

    metadata.validate_v1()?;
    let data_end = tag_at
        .checked_sub(metadata.data_pad_len as usize)
        .filter(|&n| n >= payload_at)
        .ok_or(HsmError::MaskedKeyDecodeFailed)?;
    if !all_zero(&blob[data_end..tag_at]) {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }

    // The label is borrowed from the blob, not the copy. validate_v1
    // guarantees key_label_len ≤ KEY_LABEL_MAX, so this range is in bounds.
    let key_label = aad
        .get(metadata.key_label_range()?)
        .ok_or(HsmError::MaskedKeyDecodeFailed)?;

    Ok(UnmaskedView {
        key_label,
        key_kind: metadata.key_kind(),
        key_attrs: metadata.usage_flags(),
        svn: metadata.svn.get(),
        owner_seed_id: metadata.owner_seed_id.get(),
        target_key: &blob[payload_at..data_end],
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
pub fn peek_scope(blob: &HsmDmaBuf) -> HsmResult<HsmKeyScope> {
    peek_frame(blob).map(|(scope, _)| scope)
}

/// That a masked blob's envelope framing is a v1 masked key's, as
/// [`peek_frame`] found it: the blob it was peeked at, by address and
/// length. [`unmask_framed`] takes it in place of reading the framing
/// again, which holds while the blob is unchanged.
#[derive(Clone, Copy, Debug)]
pub struct MaskedFrame {
    addr: usize,
    len: usize,
}

impl MaskedFrame {
    /// Whether this attests `blob`'s framing.
    fn attests(&self, blob: &HsmDmaBuf) -> bool {
        self.addr == blob.as_ptr() as usize && self.len == blob.len()
    }
}

/// [`peek_scope`], also returning a [`MaskedFrame`] for [`unmask_framed`],
/// which then need not read the framing out of the blob again.
pub fn peek_frame(blob: &HsmDmaBuf) -> HsmResult<(HsmKeyScope, MaskedFrame)> {
    let frame = MaskedFrame {
        addr: blob.as_ptr() as usize,
        len: blob.len(),
    };
    // The header and the usage flags are in a blob's first ten words: when
    // it is word-aligned, one burst reads them out of DMA memory rather than
    // a load for each field.
    if let Some(words) = blob.read_words::<PEEK_WORDS>() {
        let mut head = [0u8; HEADER_LEN];
        for (bytes, word) in head.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *bytes = word.to_ne_bytes();
        }
        let (alg, aad_len) = aead_peek_header(&head, blob.len())?;
        check_framing(alg, aad_len, blob.len())?;
        let mut raw = [0u8; 8];
        for (bytes, word) in raw
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(&words[FLAGS_WORD..])
        {
            *bytes = word.to_ne_bytes();
        }
        return Ok((
            HsmVaultKeyAttrs::from_bits(u64::from_le_bytes(raw)).scope(),
            frame,
        ));
    }
    let env = check_frame(blob)?;
    let raw = env
        .aad
        .get(USAGE_FLAGS_OFF..USAGE_FLAGS_OFF + 8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .ok_or(HsmError::MaskedKeyDecodeFailed)?;
    Ok((
        HsmVaultKeyAttrs::from_bits(u64::from_le_bytes(raw)).scope(),
        frame,
    ))
}

/// Word of a masked blob at which its usage flags start, after the envelope
/// header, the IV and the AAD's first `USAGE_FLAGS_OFF` bytes.
const FLAGS_WORD: usize = (HEADER_LEN + AeadAlg::AesGcm256.iv_len() + USAGE_FLAGS_OFF) / 4;

/// Words of a masked blob that [`peek_frame`] reads: up to the end of the
/// usage flags.
const PEEK_WORDS: usize = FLAGS_WORD + 2;

const _: () = assert!(
    (HEADER_LEN + AeadAlg::AesGcm256.iv_len() + USAGE_FLAGS_OFF).is_multiple_of(4)
        && PEEK_WORDS <= 10
);

/// `blob`'s envelope, if its framing is a v1 masked key's: AES-256-GCM,
/// with the metadata record as AAD and whole blocks of payload.
fn check_frame(blob: &HsmDmaBuf) -> HsmResult<AeadPeek<'_>> {
    let env = aead_peek(blob)?;
    check_framing(env.alg, env.aad.len(), blob.len())?;
    Ok(env)
}

/// That an envelope of `len` bytes with algorithm `alg` and `aad_len` bytes
/// of AAD, framing already checked, is framed as a v1 masked key.
fn check_framing(alg: AeadAlg, aad_len: usize, len: usize) -> HsmResult<()> {
    if alg != AeadAlg::AesGcm256
        || aad_len != META_LEN
        || !(len - alg.envelope_len(0, META_LEN)).is_multiple_of(16)
    {
        return Err(HsmError::MaskedKeyDecodeFailed);
    }
    Ok(())
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
/// verification and payload decryption are skipped; masked payloads must
/// additionally be block-aligned. This is the
/// key-free analogue of [`unmask`], sharing its `META_LEN` and v1
/// metadata checks.
///
/// # Errors
///
/// * [`HsmError::MaskedKeyDecodeFailed`] — the AAD region is not
///   `META_LEN` bytes, the payload is not block-aligned, or the metadata
///   fails v1 validation.
/// * Any [`HsmError`] surfaced by the envelope header / framing parse
///   (malformed header, unsupported `alg`, or a blob too short to hold a
///   complete `header ‖ iv ‖ aad ‖ tag` envelope).
pub fn peek_metadata(blob: &HsmDmaBuf) -> HsmResult<&MaskedKeyMetadata> {
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
    if env.alg != AeadAlg::AesGcm256
        || env.aad.len() != META_LEN
        || !(blob.len() - env.alg.envelope_len(0, META_LEN)).is_multiple_of(16)
    {
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
