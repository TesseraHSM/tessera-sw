// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// In-place AES-256-GCM key masking.
///
/// The exact operation buffer is laid out as:
///
/// ```text
/// [IV:16 | AAD:aad_len | zero-padded payload | tag:16]
/// ```
///
/// IV stores a 12-byte GCM nonce followed by `[0, 0, 0, 1]`.
/// Only the first 12 bytes are used; the unauthenticated suffix is ignored
/// on unmask and must not carry metadata.
/// The masking key is exactly 32 bytes.
/// AAD is opaque, authenticated, and never encrypted or interpreted.
/// AAD length must be a multiple of 32 bytes; the staged payload length
/// must be a multiple of 16 bytes.
/// The caller zero-pads plaintext and authenticates its padding count in AAD.
///
/// Neither operation moves regions. Implementations may use temporary
/// buffers internally.
/// On error, callers must not publish the buffer or use its payload.
pub trait HsmKeyMasking: HsmIoTypes {
    /// Validate AAD alignment and return `(total_len, data_pad_len)`,
    /// where `data_pad_len` is 0..=15 and rounds the payload up to 16 bytes.
    /// `total_len` is `16 + aad_len + payload_len + data_pad_len + 16`,
    /// excluding any outer envelope header, without allocation or crypto.
    /// Arithmetic overflow is rejected.
    fn key_mask_len(&self, aad_len: usize, payload_len: usize) -> HsmResult<(usize, u8)>;

    /// Mask caller-staged plaintext in place, generating the nonce and
    /// writing the authentication tag. AAD is unchanged.
    async fn key_mask_in_place(
        &self,
        io: &Self::Io,
        masking_key: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Authenticate and decrypt at the original payload offset.
    /// On success, IV, AAD and tag are unchanged.
    async fn key_unmask_in_place(
        &self,
        io: &Self::Io,
        masking_key: &HsmDmaBuf,
        aad_len: usize,
        data: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// The metadata validated out of a masked key whose blob carried the
    /// GCM tag `tag`, if the platform remembers it (see
    /// [`MaskedKeyMetaCache`]); by default it remembers none.
    fn masked_key_meta(&self, _tag: &MaskedKeyTag) -> Option<MaskedKeyMeta> {
        None
    }

    /// Remember `meta`, validated out of a masked key whose blob carried
    /// the GCM tag `tag` and has just been unmasked, for
    /// [`masked_key_meta`](Self::masked_key_meta).
    fn remember_masked_key_meta(&self, _tag: &MaskedKeyTag, _meta: MaskedKeyMeta) {}
}

/// A masked key's GCM tag, as words in memory order.
pub type MaskedKeyTag = [u32; 4];

/// The fields of a masked key's metadata record a caller uses, as the
/// record holds them, once the record has passed validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaskedKeyMeta {
    /// The vault attribute bits.
    pub usage_flags: u64,
    /// The partition SVN at mask time.
    pub svn: u64,
    /// The owner-seed lineage identifier at mask time.
    pub owner_seed_id: u16,
    /// The vault key kind byte.
    pub key_kind: u8,
    /// The label's length.
    pub key_label_len: u8,
    /// The zero bytes padding the payload.
    pub data_pad_len: u8,
}

/// Slots in a [`MaskedKeyMetaCache`].
pub const MASKED_KEY_META_SLOTS: usize = 16;

/// Masked-key metadata already validated, by the GCM tag of the blob it
/// was validated in, the oldest replaced first.
///
/// Validating a record means reading all of it, every byte of its label
/// slack and reserved tail included, out of DMA memory that may be
/// uncached. The tag covers the record, so a blob that carries a tag seen
/// before and verifies under its masking key carries that same record,
/// byte for byte: its validation has already been done. Only public data
/// is kept: the tag and the record travel in the clear in every blob.
pub struct MaskedKeyMetaCache {
    tags: [MaskedKeyTag; MASKED_KEY_META_SLOTS],
    metas: [MaskedKeyMeta; MASKED_KEY_META_SLOTS],
    /// Slots filled so far.
    len: u8,
    /// The slot the next record goes to.
    next: u8,
}

impl MaskedKeyMetaCache {
    /// An empty cache.
    pub const fn new() -> Self {
        const NONE: MaskedKeyMeta = MaskedKeyMeta {
            usage_flags: 0,
            svn: 0,
            owner_seed_id: 0,
            key_kind: 0,
            key_label_len: 0,
            data_pad_len: 0,
        };
        Self {
            tags: [[0; 4]; MASKED_KEY_META_SLOTS],
            metas: [NONE; MASKED_KEY_META_SLOTS],
            len: 0,
            next: 0,
        }
    }

    /// The record remembered for `tag`, if any.
    pub fn get(&self, tag: &MaskedKeyTag) -> Option<MaskedKeyMeta> {
        let len = usize::from(self.len).min(MASKED_KEY_META_SLOTS);
        (0..len)
            .find(|&i| self.tags[i][0] == tag[0] && self.tags[i] == *tag)
            .map(|i| self.metas[i])
    }

    /// Remember `meta` for `tag`, in place of the oldest record if every
    /// slot is taken.
    pub fn put(&mut self, tag: &MaskedKeyTag, meta: MaskedKeyMeta) {
        let i = usize::from(self.next) % MASKED_KEY_META_SLOTS;
        self.tags[i] = *tag;
        self.metas[i] = meta;
        self.next = ((i + 1) % MASKED_KEY_META_SLOTS) as u8;
        if usize::from(self.len) < MASKED_KEY_META_SLOTS {
            self.len += 1;
        }
    }
}

impl Default for MaskedKeyMetaCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(n: u8) -> MaskedKeyMeta {
        MaskedKeyMeta {
            key_kind: n,
            ..MaskedKeyMeta::default()
        }
    }

    /// A tag is found only once remembered, and an empty slot matches
    /// nothing, the all-zero tag included.
    #[test]
    fn remembers_only_what_it_was_given() {
        let mut cache = MaskedKeyMetaCache::new();
        assert_eq!(cache.get(&[0; 4]), None);
        cache.put(&[1, 2, 3, 4], meta(1));
        assert_eq!(cache.get(&[1, 2, 3, 4]), Some(meta(1)));
        assert_eq!(cache.get(&[1, 2, 3, 5]), None);
        assert_eq!(cache.get(&[0; 4]), None);
    }

    /// Once every slot is taken, each record replaces the oldest.
    #[test]
    fn replaces_the_oldest_record() {
        let mut cache = MaskedKeyMetaCache::new();
        let n = MASKED_KEY_META_SLOTS as u32;
        for i in 0..=n {
            cache.put(&[i, 0, 0, 0], meta(i as u8));
        }
        assert_eq!(cache.get(&[0, 0, 0, 0]), None);
        for i in 1..=n {
            assert_eq!(cache.get(&[i, 0, 0, 0]), Some(meta(i as u8)));
        }
    }
}
