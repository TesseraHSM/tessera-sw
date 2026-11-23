// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Header trait and marker types that abstract the only structural
//! differences between a TBOR request and response message.
//!
//! Generic codec types ([`crate::view::View`] and [`crate::encode::Encoder`])
//! are parameterised over a [`Header`] impl; everything else — TOC
//! layout, validation, framing — is identical for both message kinds.

mod sealed {
    pub trait Sealed {}
}

/// Per-message-kind structural constants and serialisation glue.
///
/// Implemented only by [`Request`] and [`Response`]; downstream code
/// cannot add new headers (sealed trait).
pub trait Header: sealed::Sealed {
    /// Header size in bytes.
    const LEN: usize;

    /// Byte index inside the header that carries the (5-bit + 1) TOC-count field.
    const TOC_COUNT_BYTE: usize;

    /// Write a header into `buf[..Self::LEN]`. `toc_count` is the
    /// caller-provided count (1..=32); it is encoded biased by 1.
    fn write_header(buf: &mut [u8], hdr: &Self, toc_count: usize);
}

// ── Request ────────────────────────────────────────────────────────────

/// Request-message header data: API revision and opcode.
#[derive(Debug, Clone, Copy)]
pub struct Request {
    pub api_rev: (u16, u16),
    pub opcode: u8,
}

impl Request {
    /// Construct a request header for the selected API revision.
    #[inline]
    pub const fn new(api_rev: (u16, u16), opcode: u8) -> Self {
        Self { api_rev, opcode }
    }
}

impl sealed::Sealed for Request {}

impl Header for Request {
    const LEN: usize = 12;
    const TOC_COUNT_BYTE: usize = 4;

    fn write_header(buf: &mut [u8], hdr: &Self, toc_count: usize) {
        buf[..2].copy_from_slice(&hdr.api_rev.0.to_le_bytes());
        buf[2..4].copy_from_slice(&hdr.api_rev.1.to_le_bytes());
        buf[4..8].copy_from_slice(&[(toc_count - 1) as u8, hdr.opcode, 0, 0]);
        buf[8..12].fill(0);
    }
}

// ── Response ───────────────────────────────────────────────────────────

/// Response-message header data: API revision, flags and status.
#[derive(Debug, Clone, Copy)]
pub struct Response {
    pub api_rev: (u16, u16),
    pub flags: u8,
    pub status: u32,
}

impl Response {
    /// FIPS_APPROVED flag bit inside the flags byte.
    pub const FIPS_APPROVED_FLAG: u8 = 0x01;

    /// Construct a response header echoing the request's API revision.
    #[inline]
    pub const fn new(api_rev: (u16, u16), status: u32, fips_approved: bool) -> Self {
        Self {
            api_rev,
            flags: if fips_approved {
                Self::FIPS_APPROVED_FLAG
            } else {
                0
            },
            status,
        }
    }
}

impl sealed::Sealed for Response {}

impl Header for Response {
    const LEN: usize = 12;
    const TOC_COUNT_BYTE: usize = 4;

    fn write_header(buf: &mut [u8], hdr: &Self, toc_count: usize) {
        buf[..2].copy_from_slice(&hdr.api_rev.0.to_le_bytes());
        buf[2..4].copy_from_slice(&hdr.api_rev.1.to_le_bytes());
        buf[4..8].copy_from_slice(&[(toc_count - 1) as u8, hdr.flags, 0, 0]);
        buf[8..12].copy_from_slice(&hdr.status.to_le_bytes());
    }
}
