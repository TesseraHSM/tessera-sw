// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Zero-copy decoders for TBOR request and response messages.
//!
//! `RequestView` and `ResponseView` borrow the input buffer and provide
//! infallible accessor methods after a single upfront validation pass.

use tsra_fw_hsm_pal_traits::copy_from_uncached;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;

use crate::toc::*;

// ── TOC cache ──────────────────────────────────────────────────────────

/// TOC entries kept in a [`TocCache`] after the longer (response) header,
/// so the cache is one eight-word burst; a request, with its shorter
/// header, gets one more. Every hot message has no more.
const TOC_CACHED_ENTRIES: usize = 6;

/// Bytes a [`TocCache`] holds: the longer (response) header and
/// [`TOC_CACHED_ENTRIES`] entries.
const TOC_CACHE_LEN: usize = RESP_HEADER_LEN + 4 * TOC_CACHED_ENTRIES;

/// The header and first TOC words of a parsed message, read once by
/// `parse`.
///
/// Messages sit in DMA memory, which the CPU may read uncached (on Uno each
/// load costs tens of cycles whatever its width, while a burst of eight
/// words costs little more than one), and decoders read the header and
/// every TOC word several times. Kept small so the views stay cheap to
/// move; TOC words past it are read from the message.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(4))]
struct TocCache([u8; TOC_CACHE_LEN]);

impl TocCache {
    /// Reads the start of `buf`, up to [`TOC_CACHE_LEN`] bytes.
    fn new(buf: &[u8]) -> Self {
        let mut cache = Self([0; TOC_CACHE_LEN]);
        let n = buf.len().min(TOC_CACHE_LEN);
        copy_from_uncached(&mut cache.0[..n], &buf[..n]);
        cache
    }

    /// TOC word `index` of `buf`, from the cache when it holds it. `buf`'s
    /// TOC must have been validated to lie within it.
    #[inline]
    fn word(&self, buf: &[u8], header_len: usize, index: usize) -> u32 {
        if header_len + 4 * (index + 1) <= TOC_CACHE_LEN {
            read_toc_word(&self.0, header_len, index)
        } else {
            read_toc_word(buf, header_len, index)
        }
    }
}

// ── RequestHead ───────────────────────────────────────────────────────

/// What [`RequestView::parse`] read of one request buffer, kept by
/// [`RequestView::head`] so a later decode of the same buffer
/// ([`RequestView::parse_with`]) need not read and validate it again.
#[derive(Debug, Clone, Copy)]
pub struct RequestHead {
    /// Address and length of the parsed buffer.
    addr: usize,
    len: usize,
    toc: TocCache,
    toc_count: usize,
}

// ── RequestView ───────────────────────────────────────────────────────

/// Zero-copy view over a TBOR request message.
///
/// After [`parse()`](Self::parse) succeeds, all accessors are infallible.
/// The view borrows the input buffer for the lifetime `'a`.
#[derive(Debug)]
pub struct RequestView<'a> {
    buf: &'a DmaBuf,
    /// Header and TOC, read once by [`parse`](Self::parse).
    toc: TocCache,
    toc_count: usize,
}

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
    pub fn parse(buf: &'a DmaBuf) -> Result<Self, HsmError> {
        // Minimum: 4-byte header + 1 TOC entry = 8 bytes.
        if buf.len() < REQ_HEADER_LEN + 4 {
            return Err(HsmError::TborBufferTooShort);
        }

        let toc = TocCache::new(buf);
        let version = toc.0[0];
        if version != PROTOCOL_VERSION {
            return Err(HsmError::TborUnsupportedVersion);
        }

        let toc_count = (toc.0[2] & 0x1F) as usize + 1;
        let min_len = REQ_HEADER_LEN + toc_count * 4;
        if buf.len() < min_len {
            return Err(HsmError::TborMessageTruncated);
        }

        let data_start = REQ_HEADER_LEN + toc_count * 4;
        let data_size = buf.len() - data_start;

        // Validate all known offset/length TOC entries.
        validate_toc_entries(|i| toc.word(buf, REQ_HEADER_LEN, i), toc_count, data_size)?;

        Ok(Self {
            buf,
            toc,
            toc_count,
        })
    }

    /// [`parse`](Self::parse), reusing `head` when it is this buffer's:
    /// the same address and length, so it holds what parsing `buf` reads
    /// and finds valid.
    ///
    /// # Errors
    ///
    /// As [`parse`](Self::parse).
    pub fn parse_with(buf: &'a DmaBuf, head: &RequestHead) -> Result<Self, HsmError> {
        if head.addr == buf.as_ptr() as usize && head.len == buf.len() {
            return Ok(Self {
                buf,
                toc: head.toc,
                toc_count: head.toc_count,
            });
        }
        Self::parse(buf)
    }

    /// What this parse read, for [`parse_with`](Self::parse_with) to reuse
    /// on the same buffer.
    pub fn head(&self) -> RequestHead {
        RequestHead {
            addr: self.buf.as_ptr() as usize,
            len: self.buf.len(),
            toc: self.toc,
            toc_count: self.toc_count,
        }
    }

    /// Protocol version.
    #[inline]
    pub fn version(&self) -> u8 {
        self.toc.0[0]
    }

    /// Operation code.
    #[inline]
    pub fn opcode(&self) -> u8 {
        self.toc.0[3]
    }

    /// Number of TOC entries (1–32).
    #[inline]
    pub fn toc_count(&self) -> usize {
        self.toc_count
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
    pub fn as_bytes(&self) -> &'a DmaBuf {
        self.buf
    }

    /// The raw 6-bit entry type at the given TOC index.
    #[inline]
    pub fn toc_entry_type(&self, index: usize) -> u8 {
        raw_toc_entry_type(self.toc_word(index))
    }

    /// The raw TOC word at the given index.
    #[inline]
    pub fn toc_word(&self, index: usize) -> u32 {
        self.toc.word(self.buf, REQ_HEADER_LEN, index)
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
    pub fn data_section(&self) -> &'a DmaBuf {
        &self.buf[self.data_start()..]
    }
}

// ── ResponseView ───────────────────────────────────────────────────────

/// Zero-copy view over a TBOR response message.
///
/// After [`parse()`](Self::parse) succeeds, all accessors are infallible.
#[derive(Debug)]
pub struct ResponseView<'a> {
    buf: &'a DmaBuf,
    /// Header and TOC, read once by [`parse`](Self::parse).
    toc: TocCache,
    toc_count: usize,
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
    pub fn parse(buf: &'a DmaBuf) -> Result<Self, HsmError> {
        // Minimum: 8-byte header + 1 TOC entry = 12 bytes.
        if buf.len() < RESP_HEADER_LEN + 4 {
            return Err(HsmError::TborBufferTooShort);
        }

        let toc = TocCache::new(buf);
        let version = toc.0[0];
        if version != PROTOCOL_VERSION {
            return Err(HsmError::TborUnsupportedVersion);
        }

        let toc_count = (toc.0[3] & 0x1F) as usize + 1;
        let min_len = RESP_HEADER_LEN + toc_count * 4;
        if buf.len() < min_len {
            return Err(HsmError::TborMessageTruncated);
        }

        let data_start = RESP_HEADER_LEN + toc_count * 4;
        let data_size = buf.len() - data_start;

        validate_toc_entries(|i| toc.word(buf, RESP_HEADER_LEN, i), toc_count, data_size)?;

        Ok(Self {
            buf,
            toc,
            toc_count,
        })
    }

    /// Protocol version.
    #[inline]
    pub fn version(&self) -> u8 {
        self.toc.0[0]
    }

    /// Flags byte.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.toc.0[1]
    }

    /// FIPS_APPROVED flag (bit 0 of flags).
    #[inline]
    pub fn fips_approved(&self) -> bool {
        self.toc.0[1] & 0x01 != 0
    }

    /// Status code (4-byte LE unsigned integer).
    #[inline]
    pub fn status(&self) -> u32 {
        u32::from_le_bytes([self.toc.0[4], self.toc.0[5], self.toc.0[6], self.toc.0[7]])
    }

    /// Number of TOC entries (1–32).
    #[inline]
    pub fn toc_count(&self) -> usize {
        self.toc_count
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
    pub fn as_bytes(&self) -> &'a DmaBuf {
        self.buf
    }

    /// The raw 6-bit entry type at the given TOC index.
    #[inline]
    pub fn toc_entry_type(&self, index: usize) -> u8 {
        raw_toc_entry_type(self.toc_word(index))
    }

    /// The raw TOC word at the given index.
    #[inline]
    pub fn toc_word(&self, index: usize) -> u32 {
        self.toc.word(self.buf, RESP_HEADER_LEN, index)
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
    pub fn data_section(&self) -> &'a DmaBuf {
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
    word_at: impl Fn(usize) -> u32,
    toc_count: usize,
    data_size: usize,
) -> Result<(), HsmError> {
    for i in 0..toc_count {
        let word = word_at(i);
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
