// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Zero-copy decoders for TBOR request and response messages.
//!
//! `RequestView` and `ResponseView` borrow the input buffer and provide
//! infallible accessor methods after a single upfront validation pass.

use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;

use crate::toc::*;

// ── RequestView ───────────────────────────────────────────────────────

/// Zero-copy view over a TBOR request message.
///
/// After [`parse()`](Self::parse) succeeds, all accessors are infallible.
/// The view borrows the input buffer for the lifetime `'a`.
#[derive(Debug)]
pub struct RequestView<'a> {
    buf: &'a HsmDmaBuf,
    /// The message's first words, read with one burst by
    /// [`parse()`](Self::parse): the header, then as many of the TOC
    /// entries as fit ([`TOC_CACHED`]), so validating and decoding the
    /// message reads them from here rather than from DMA memory.
    head: [u32; HEAD_WORDS],
}

/// Words of a request's start a [`RequestView`] keeps.
const HEAD_WORDS: usize = 8;

/// TOC entries a [`RequestView`] keeps after the header: every hot request
/// has no more.
const TOC_CACHED: usize = HEAD_WORDS - REQ_HEADER_LEN / 4;

impl<'a> RequestView<'a> {
    /// Parse and structurally validate a request message.
    ///
    /// Validates:
    /// - Minimum buffer size (header + at least 1 TOC entry)
    /// - Protocol version
    /// - TOC count consistency with buffer length
    /// - Every known offset/length TOC entry is within the data section
    /// - Fixed-size types have correct lengths (uint32=4, uint64=8)
    ///
    /// Reserved bits are silently ignored per spec.
    pub fn parse(buf: &'a HsmDmaBuf) -> Result<Self, HsmError> {
        // Minimum: 8-byte header + 1 TOC entry = 12 bytes.
        if buf.len() < REQ_HEADER_LEN + 4 {
            return Err(HsmError::TborBufferTooShort);
        }

        let (head, _) = buf.read_head_words();
        let view = Self { buf, head };
        if view.version() != PROTOCOL_VERSION {
            return Err(HsmError::TborUnsupportedVersion);
        }

        // The words read cover every TOC entry up to `TOC_CACHED` that
        // passes this check.
        let toc_count = view.toc_count();
        let min_len = REQ_HEADER_LEN + toc_count * 4;
        if buf.len() < min_len {
            return Err(HsmError::TborMessageTruncated);
        }

        let data_size = buf.len() - view.data_start();

        // Validate all known offset/length TOC entries.
        validate_toc_entries(|i| view.toc_word(i), toc_count, data_size)?;

        Ok(view)
    }

    /// Header byte `i` (of the first header word).
    #[inline]
    fn head_byte(&self, i: usize) -> u8 {
        self.head[0].to_ne_bytes()[i]
    }

    /// Protocol version.
    #[inline]
    pub fn version(&self) -> u8 {
        self.head_byte(0)
    }

    /// Operation code.
    #[inline]
    pub fn opcode(&self) -> u8 {
        self.head_byte(3)
    }

    /// Number of TOC entries (1–32).
    #[inline]
    pub fn toc_count(&self) -> usize {
        (self.head_byte(2) & 0x1F) as usize + 1
    }

    /// The raw TOC word at `index` (see
    /// [`read_toc_word`](crate::toc::read_toc_word)), from the words
    /// [`parse()`](Self::parse) read when it is among them.
    #[inline]
    pub fn toc_word(&self, index: usize) -> u32 {
        match self.head.get(REQ_HEADER_LEN / 4 + index) {
            Some(word) if index < TOC_CACHED => u32::from_be_bytes(word.to_ne_bytes()),
            _ => read_toc_word(self.buf, REQ_HEADER_LEN, index),
        }
    }

    /// Byte offset where the variable-length data section starts.
    #[inline]
    pub fn data_start(&self) -> usize {
        REQ_HEADER_LEN + self.toc_count() * 4
    }

    /// Size of the variable-length data section.
    #[inline]
    pub fn data_size(&self) -> usize {
        self.buf.len() - self.data_start()
    }

    /// Total message length.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the message is empty (always `false` for valid messages).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The raw message bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a HsmDmaBuf {
        self.buf
    }

    /// The raw 6-bit entry type at the given TOC index.
    #[inline]
    pub fn toc_entry_type(&self, index: usize) -> u8 {
        raw_toc_entry_type(self.toc_word(index))
    }

    /// Decode a single TOC entry at the given index. Infallible after parse().
    #[inline]
    pub fn toc_entry(&self, index: usize) -> TocEntry<'a> {
        decode_toc_word(self.buf, self.toc_word(index), self.data_start())
    }

    /// Iterate all TOC entries in wire order.
    pub fn toc_iter(&self) -> impl Iterator<Item = TocEntry<'a>> + '_ {
        let count = self.toc_count();
        let data_start = self.data_start();
        (0..count).map(move |i| decode_toc_word(self.buf, self.toc_word(i), data_start))
    }

    /// The raw variable-length data section.
    #[inline]
    pub fn data_section(&self) -> &'a HsmDmaBuf {
        &self.buf[self.data_start()..]
    }
}

// ── ResponseView ───────────────────────────────────────────────────────

/// Zero-copy view over a TBOR response message.
///
/// After [`parse()`](Self::parse) succeeds, all accessors are infallible.
#[derive(Debug)]
pub struct ResponseView<'a> {
    buf: &'a HsmDmaBuf,
    /// The header's first word (version, flags, TOC count, reserved), read
    /// once by [`parse()`](Self::parse).
    head: [u8; 4],
}

impl<'a> ResponseView<'a> {
    /// Parse and structurally validate a response message.
    ///
    /// Validates:
    /// - Minimum buffer size (header + at least 1 TOC entry)
    /// - Protocol version
    /// - TOC count consistency with buffer length
    /// - Every known offset/length TOC entry is within the data section
    /// - Fixed-size types have correct lengths (uint32=4, uint64=8)
    ///
    /// Reserved bits are silently ignored per spec.
    pub fn parse(buf: &'a HsmDmaBuf) -> Result<Self, HsmError> {
        // Minimum: 8-byte header + 1 TOC entry = 12 bytes.
        if buf.len() < RESP_HEADER_LEN + 4 {
            return Err(HsmError::TborBufferTooShort);
        }

        let head = read_word_bytes(buf);
        let version = head[0];
        if version != PROTOCOL_VERSION {
            return Err(HsmError::TborUnsupportedVersion);
        }

        let toc_count = (head[2] & 0x1F) as usize + 1;
        let min_len = RESP_HEADER_LEN + toc_count * 4;
        if buf.len() < min_len {
            return Err(HsmError::TborMessageTruncated);
        }

        let data_start = RESP_HEADER_LEN + toc_count * 4;
        let data_size = buf.len() - data_start;

        validate_toc_entries(
            |i| read_toc_word(buf, RESP_HEADER_LEN, i),
            toc_count,
            data_size,
        )?;

        Ok(Self { buf, head })
    }

    /// Protocol version.
    #[inline]
    pub fn version(&self) -> u8 {
        self.head[0]
    }

    /// Flags byte.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.head[1]
    }

    /// The raw TOC word at `index` (see
    /// [`read_toc_word`](crate::toc::read_toc_word)).
    #[inline]
    pub fn toc_word(&self, index: usize) -> u32 {
        read_toc_word(self.buf, RESP_HEADER_LEN, index)
    }

    /// FIPS_APPROVED flag (bit 0 of flags).
    #[inline]
    pub fn fips_approved(&self) -> bool {
        self.head[1] & 0x01 != 0
    }

    /// Status code (4-byte LE unsigned integer).
    #[inline]
    pub fn status(&self) -> u32 {
        u32::from_le_bytes(read_word_bytes(&self.buf[4..]))
    }

    /// Number of TOC entries (1–32).
    #[inline]
    pub fn toc_count(&self) -> usize {
        (self.head[2] & 0x1F) as usize + 1
    }

    /// Byte offset where the variable-length data section starts.
    #[inline]
    pub fn data_start(&self) -> usize {
        RESP_HEADER_LEN + self.toc_count() * 4
    }

    /// Size of the variable-length data section.
    #[inline]
    pub fn data_size(&self) -> usize {
        self.buf.len() - self.data_start()
    }

    /// Total message length.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns `true` if the message is empty (always `false` for valid messages).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The raw message bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a HsmDmaBuf {
        self.buf
    }

    /// The raw 6-bit entry type at the given TOC index.
    #[inline]
    pub fn toc_entry_type(&self, index: usize) -> u8 {
        raw_toc_entry_type(read_toc_word(self.buf, RESP_HEADER_LEN, index))
    }

    /// Decode a single TOC entry at the given index. Infallible after parse().
    #[inline]
    pub fn toc_entry(&self, index: usize) -> TocEntry<'a> {
        decode_toc_entry(self.buf, RESP_HEADER_LEN, index, self.data_start())
    }

    /// Iterate all TOC entries in wire order.
    pub fn toc_iter(&self) -> impl Iterator<Item = TocEntry<'a>> + '_ {
        let count = self.toc_count();
        let data_start = self.data_start();
        (0..count).map(move |i| decode_toc_entry(self.buf, RESP_HEADER_LEN, i, data_start))
    }

    /// The raw variable-length data section.
    #[inline]
    pub fn data_section(&self) -> &'a HsmDmaBuf {
        &self.buf[self.data_start()..]
    }
}

// ── Shared validation ──────────────────────────────────────────────────

/// Validate all TOC entries for structural correctness.
///
/// For known offset/length types (2, 5, 6, 7): checks offset+length ≤ data_size.
/// For fixed-size types: checks uint32 length == 4, uint64 length == 8.
/// Unknown types (8–63) are silently skipped.
fn validate_toc_entries(
    toc_word: impl Fn(usize) -> u32,
    toc_count: usize,
    data_size: usize,
) -> Result<(), HsmError> {
    for i in 0..toc_count {
        let word = toc_word(i);
        let entry_type = raw_toc_entry_type(word);

        match entry_type {
            // Inline types (0, 1, 3, 4): no data section reference, nothing to validate.
            0 | 1 | 3 | 4 => {}

            // None type (8): inline, all 26 payload bits must be zero.
            8 => {
                if word & 0x03FF_FFFF != 0 {
                    return Err(HsmError::TborInvalidNonePayload);
                }
            }

            // Offset/length types: validate bounds.
            2 | 5 | 6 | 7 | 9 => {
                let length = raw_toc_length(word);
                let offset = raw_toc_offset(word);

                if offset + length > data_size {
                    return Err(HsmError::TborOffsetLengthOutOfBounds);
                }

                // Fixed-size type length checks.
                match entry_type {
                    5 if length != 4 => {
                        return Err(HsmError::TborInvalidFixedLength);
                    }
                    6 if length != 8 => {
                        return Err(HsmError::TborInvalidFixedLength);
                    }
                    _ => {}
                }
            }

            // Unknown types (8–63): silently skip per spec rule 6.
            _ => {}
        }
    }
    Ok(())
}
