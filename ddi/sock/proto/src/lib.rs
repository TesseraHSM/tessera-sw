// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire protocol for the socket-based DDI transport.
//!
//! This crate defines the framing exchanged between the host-side socket
//! DDI transport (`tsra_ddi_sock`, the client) and the emulator-side
//! socket server that bridges requests to the Cortex-M firmware.
//!
//! The transport operates at the firmware's **SQE / CQE** boundary, just
//! like the in-process emulator: the client builds a submission entry and
//! reads the returned completion entry; the server is a dumb DMA-and-submit
//! shim that re-homes the host buffers and forwards the raw entries. The
//! request/response *payloads* (the MBOR or TBOR DDI body) are opaque to
//! both the protocol and the server.
//!
//! # Frame structure
//!
//! Every frame is length-delimited (a `u32` body length precedes the
//! body) and modelled on TBOR's self-describing shape — a fixed header, a
//! table of contents (TOC) of typed field descriptors, then a data
//! section holding the field bytes in TOC order. New fields can be added
//! without a format break: readers fetch the fields they need by
//! [`FieldId`] and ignore unknown entries.
//!
//! All multi-byte integers are little-endian.
//!
//! ```text
//! Frame = len:u32 + Body
//! Body  = Header + TOC[toc_count] + Data
//!
//! Request Header (8B)            Response Header (12B)
//!   magic    : u32 = MAGIC         magic    : u32 = MAGIC
//!   version  : u8  = VERSION       version  : u8  = VERSION
//!   kind     : u8  = 1 (Request)   kind     : u8  = 2 (Response)
//!   toc_count: u8                  toc_count: u8
//!   _rsvd    : u8                  _rsvd    : u8
//!                                  status   : u32  (transport status)
//!
//! TOC entry (12B)
//!   field_id  : u16   (see FieldId)
//!   field_type: u8    (see FieldType)
//!   _rsvd     : u8
//!   offset    : u32   (byte offset into Data section)
//!   length    : u32   (bytes in Data section)
//!
//! Data = field payloads located by (offset, length) in the data section
//! ```
//!
//! Submission request fields: [`FieldId::Sqe`], [`FieldId::Payload`],
//! [`FieldId::OobItems`] and [`FieldId::Tail`]. The SQE is either a 64-byte
//! command SQE or a 128-byte bulk (fast-path AES-GCM/XTS) SQE; its length
//! selects the queue. The request OOB field holds `count:u32` followed by
//! `dir:u32 + length:u32` for each item in index order, with the item bytes
//! after an input (`dir` 0) item; an output (`dir` 1) item carries no bytes.
//! Addresses never travel in this field; the server reconstructs SGL
//! descriptors in its own memory. The bulk SQE's buffer addresses are
//! client-local and are replaced by the server.
//!
//! Submission response fields: [`FieldId::Cqe`] (16 B command / 64 B bulk),
//! [`FieldId::Payload`], [`FieldId::OobItems`] and [`FieldId::Tail`]. The
//! response OOB field holds `count:u32` followed by `length:u32 + bytes` for
//! each output item, in index order.
//! Reset request/response kinds are 3/4, have no TOC fields, and use the same
//! request/response headers (the reset response carries transport status).
//! Client and server must be updated together; only one protocol is supported.

use std::io::Read;
use std::io::Write;

use zerocopy::little_endian::U16;
use zerocopy::little_endian::U32;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::Unaligned;

/// Frame magic: ASCII "DDI1" (`b"DDI1"`) interpreted as a little-endian `u32`.
pub const MAGIC: u32 = 0x3149_4444;

/// Protocol version carried in every frame.
pub const VERSION: u8 = 1;

/// Transport rejection when a session allocation is not owned by the connection.
pub const TRANSPORT_SESSION_NOT_OWNED: u32 = 3;

/// Maximum main request/response buffer, matching the firmware's two-page limit.
pub const MAX_DMA_BUFFER: u32 = 8192;

/// Submission queue entry size in dwords.
pub const SQE_DWORDS: usize = 16;

/// Completion queue entry size in dwords.
pub const CQE_DWORDS: usize = 4;

/// Bulk (fast-path) submission queue entry size in dwords.
pub const BULK_SQE_DWORDS: usize = 32;

/// Bulk (fast-path) completion queue entry size in dwords.
pub const BULK_CQE_DWORDS: usize = 16;

/// Maximum GCM tail (final partial block) length in bytes.
pub const MAX_TAIL: usize = 15;

/// Maximum size of a single field's data (guards against malformed
/// lengths). Sized above the firmware's 4 KiB DMA page.
pub const MAX_FIELD: u32 = 64 * 1024;

/// Maximum number of OOB items, matching the native Linux transport.
pub const MAX_OOB_ITEMS: usize = 64;

/// Maximum byte length of one OOB item.
pub const MAX_OOB_ITEM: u32 = 64 * 1024;

/// Maximum encoded OOB field, including count and per-item headers.
pub const MAX_OOB_FIELD: u32 = MAX_OOB_ITEMS as u32 * (MAX_OOB_ITEM + 8) + 4;

/// Maximum total frame body accepted on either side, including framing.
pub const MAX_FRAME: u32 = MAX_OOB_FIELD + MAX_FIELD + 1024;

/// Maximum number of TOC entries accepted in a frame.
pub const MAX_TOC: u8 = 16;

/// Frame kind discriminator (header `kind` byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Kind {
    Request = 1,
    Response = 2,
    ResetRequest = 3,
    ResetResponse = 4,
}

impl Kind {
    fn from_u8(v: u8) -> Result<Self, ProtoError> {
        match v {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::ResetRequest),
            4 => Ok(Self::ResetResponse),
            other => Err(ProtoError::BadKind(other)),
        }
    }
}

/// Logical identity of a TOC field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum FieldId {
    /// Raw submission queue entry (`[u32; 16]`, 64 bytes).
    Sqe = 1,

    /// Raw completion queue entry (`[u32; 4]`, 16 bytes).
    Cqe = 2,

    /// Opaque DDI body bytes (MBOR or TBOR encoded). On a request this
    /// is the source-buffer content; on a response it is the
    /// destination-buffer content the firmware produced.
    Payload = 3,

    /// Ordered OOB items, without addresses. On a request these are the
    /// device-read inputs and device-written output lengths; on a response
    /// the bytes the device wrote to each output.
    OobItems = 4,

    /// GCM tail (final partial block) bytes: the input on a bulk request,
    /// the output on its response. Empty otherwise.
    Tail = 5,
}

impl FieldId {
    fn as_u16(self) -> u16 {
        self as u16
    }

    fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Sqe),
            2 => Some(Self::Cqe),
            3 => Some(Self::Payload),
            4 => Some(Self::OobItems),
            5 => Some(Self::Tail),
            _ => None,
        }
    }
}

/// Encoding of a TOC field's bytes. Only [`Buffer`](FieldType::Buffer) is
/// used today; the byte is reserved so future fields can inline scalars
/// without a format break.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FieldType {
    /// Opaque byte buffer stored in the data section.
    Buffer = 0,
}

impl FieldType {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(v: u8) -> Result<Self, ProtoError> {
        match v {
            0 => Ok(Self::Buffer),
            other => Err(ProtoError::BadFieldType(other)),
        }
    }
}

/// One request OOB item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OobItem {
    /// Bytes the device reads.
    In(Vec<u8>),
    /// Length of a buffer the device writes; returned in the response.
    Out(u32),
}

impl OobItem {
    /// Item length in bytes.
    pub fn len(&self) -> usize {
        match self {
            Self::In(bytes) => bytes.len(),
            Self::Out(len) => *len as usize,
        }
    }

    /// Whether the item is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A request frame: the submission entry plus its source-buffer payload.
#[derive(Clone, Debug)]
pub struct Request {
    /// Raw submission queue entry: [`SQE_DWORDS`] for a command or
    /// [`BULK_SQE_DWORDS`] for a bulk operation. The server assigns every
    /// buffer address; all other fields (opcode, command id, lengths,
    /// session) are set by the client.
    pub sqe: Vec<u32>,

    /// Source buffer bytes: the DDI body (MBOR or TBOR encoded) of a
    /// command, or the source SGL data of a bulk operation.
    pub payload: Vec<u8>,

    /// Ordered OOB items. Each item becomes one server-owned SGL descriptor.
    pub oob_items: Vec<OobItem>,

    /// GCM tail input of a bulk operation.
    pub tail: Vec<u8>,
}

/// A submission or a sideband partition-reset request.
#[derive(Clone, Debug)]
pub enum RequestFrame {
    /// Submit an opaque firmware command with its buffers.
    Submit(Request),
    /// Disable and re-enable the endpoint's existing partition.
    Reset,
}

/// A response frame: the completion entry plus its destination-buffer
/// payload.
#[derive(Clone, Debug)]
pub struct Response {
    /// Transport-level status (0 = ok). Device-level status lives in the
    /// completion entry ([`cqe`](Self::cqe)).
    pub status: u32,

    /// Raw completion queue entry produced by the firmware:
    /// [`CQE_DWORDS`] for a command or [`BULK_CQE_DWORDS`] for a bulk
    /// operation.
    pub cqe: Vec<u32>,

    /// Destination buffer bytes the firmware produced.
    pub payload: Vec<u8>,

    /// Bytes written to each request [`OobItem::Out`], in index order.
    pub oob_items: Vec<Vec<u8>>,

    /// GCM tail output of a bulk operation.
    pub tail: Vec<u8>,
}

/// A firmware submission response or a sideband reset result.
#[derive(Clone, Debug)]
pub enum ResponseFrame {
    /// Firmware completion and output bytes.
    Submit(Response),
    /// Reset transport status (zero only after disable and enable succeed).
    Reset {
        /// Transport status.
        status: u32,
    },
}

/// Errors produced while reading or writing protocol frames.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// Underlying stream IO error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Frame did not start with the expected [`MAGIC`].
    #[error("bad frame magic: 0x{0:08x}")]
    BadMagic(u32),

    /// Frame carried an unsupported protocol version.
    #[error("unsupported protocol version: {0}")]
    BadVersion(u8),

    /// Frame carried an unknown kind discriminator.
    #[error("unknown frame kind: {0}")]
    BadKind(u8),

    /// TOC entry carried an unknown field type.
    #[error("unknown field type: {0}")]
    BadFieldType(u8),

    /// Frame declared more TOC entries than [`MAX_TOC`].
    #[error("too many TOC entries: {0} (max {MAX_TOC})")]
    TooManyToc(u8),

    /// A length field exceeded its bound.
    #[error("field/frame too large: {0} bytes")]
    TooLarge(u32),

    /// A required field was missing, or had the wrong size/shape.
    #[error("malformed frame: {0}")]
    Malformed(&'static str),
}

/// A parsed TOC entry.
#[derive(Clone, Copy)]
struct TocEntry {
    field_id: u16,
    field_type: FieldType,
    offset: u32,
    length: u32,
}

/// Fixed 8-byte frame header common to requests and responses. On a
/// response a `status: U32` immediately follows in the byte stream.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct FrameHeader {
    magic: U32,
    version: u8,
    kind: u8,
    toc_count: u8,
    _rsvd: u8,
}

/// 12-byte table-of-contents entry as laid out on the wire. Each field is
/// located by its `(offset, length)` within the data section, so fields
/// are independently addressable regardless of TOC order.
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct TocEntryRaw {
    field_id: U16,
    field_type: u8,
    _rsvd: u8,
    offset: U32,
    length: U32,
}

impl Request {
    /// Encode this request as a complete length-delimited frame.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        if !matches!(self.sqe.len(), SQE_DWORDS | BULK_SQE_DWORDS) {
            return Err(ProtoError::Malformed("SQE field has wrong size"));
        }
        let sqe_bytes = dwords_to_le_bytes(&self.sqe);
        let oob_bytes = encode_oob_req(&self.oob_items)?;
        let fields = [
            (FieldId::Sqe, sqe_bytes.as_slice()),
            (FieldId::Payload, self.payload.as_slice()),
            (FieldId::OobItems, oob_bytes.as_slice()),
            (FieldId::Tail, self.tail.as_slice()),
        ];
        encode_frame(Kind::Request, 0, &fields)
    }

    /// Decode a request from a complete frame body (no length prefix).
    pub fn decode(body: &[u8]) -> Result<Self, ProtoError> {
        let frame = Frame::parse(body, Kind::Request)?;
        let sqe = frame.dwords(FieldId::Sqe, &[SQE_DWORDS, BULK_SQE_DWORDS])?;
        let payload = frame.bytes(FieldId::Payload)?.to_vec();
        let oob_items = decode_oob_req(frame.bytes(FieldId::OobItems)?)?;
        let tail = frame.tail()?;
        Ok(Self {
            sqe,
            payload,
            oob_items,
            tail,
        })
    }
}

impl RequestFrame {
    /// Encode a complete frame body.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        match self {
            Self::Submit(request) => request.encode(),
            Self::Reset => encode_frame(Kind::ResetRequest, 0, &[]),
        }
    }

    /// Decode a complete frame body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtoError> {
        match frame_kind(body)? {
            Kind::Request => Request::decode(body).map(Self::Submit),
            Kind::ResetRequest => {
                let frame = Frame::parse(body, Kind::ResetRequest)?;
                if !frame.toc.is_empty() || !frame.data.is_empty() {
                    return Err(ProtoError::Malformed("reset request has fields or data"));
                }
                Ok(Self::Reset)
            }
            _ => Err(ProtoError::Malformed("unexpected request frame kind")),
        }
    }

    /// Write a length-delimited frame.
    pub fn write_to(&self, w: &mut impl Write) -> Result<(), ProtoError> {
        write_framed(w, &self.encode()?)
    }

    /// Read a length-delimited frame.
    pub fn read_from(r: &mut impl Read) -> Result<Self, ProtoError> {
        Self::decode(&read_framed(r)?)
    }
}

impl ResponseFrame {
    /// Encode a complete frame body.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        match self {
            Self::Submit(response) => response.encode(),
            Self::Reset { status } => encode_frame(Kind::ResetResponse, *status, &[]),
        }
    }

    /// Decode a complete frame body.
    pub fn decode(body: &[u8]) -> Result<Self, ProtoError> {
        match frame_kind(body)? {
            Kind::Response => Response::decode(body).map(Self::Submit),
            Kind::ResetResponse => {
                let frame = Frame::parse(body, Kind::ResetResponse)?;
                if !frame.toc.is_empty() || !frame.data.is_empty() {
                    return Err(ProtoError::Malformed("reset response has fields or data"));
                }
                Ok(Self::Reset {
                    status: frame.status,
                })
            }
            _ => Err(ProtoError::Malformed("unexpected response frame kind")),
        }
    }

    /// Write a length-delimited frame.
    pub fn write_to(&self, w: &mut impl Write) -> Result<(), ProtoError> {
        write_framed(w, &self.encode()?)
    }

    /// Read a length-delimited frame.
    pub fn read_from(r: &mut impl Read) -> Result<Self, ProtoError> {
        Self::decode(&read_framed(r)?)
    }
}

fn frame_kind(body: &[u8]) -> Result<Kind, ProtoError> {
    let (header, _) = FrameHeader::ref_from_prefix(body)
        .map_err(|_| ProtoError::Malformed("frame too short for header"))?;
    Kind::from_u8(header.kind)
}

fn field_limit(id: u16) -> u32 {
    if FieldId::from_u16(id) == Some(FieldId::OobItems) {
        MAX_OOB_FIELD
    } else {
        MAX_FIELD
    }
}

const OOB_DIR_IN: u32 = 0;
const OOB_DIR_OUT: u32 = 1;

fn check_oob_len(len: usize) -> Result<u32, ProtoError> {
    let len = u32::try_from(len).map_err(|_| ProtoError::TooLarge(u32::MAX))?;
    if len == 0 {
        return Err(ProtoError::Malformed("empty OOB item"));
    }
    if len > MAX_OOB_ITEM {
        return Err(ProtoError::TooLarge(len));
    }
    Ok(len)
}

fn check_oob_count(count: usize) -> Result<(), ProtoError> {
    if count > MAX_OOB_ITEMS {
        return Err(ProtoError::Malformed("too many OOB items"));
    }
    Ok(())
}

fn read_u32(bytes: &mut &[u8]) -> Result<u32, ProtoError> {
    let (value, rest) =
        U32::ref_from_prefix(bytes).map_err(|_| ProtoError::Malformed("truncated OOB length"))?;
    *bytes = rest;
    Ok(value.get())
}

fn read_item<'a>(bytes: &mut &'a [u8], len: u32) -> Result<&'a [u8], ProtoError> {
    if len as usize > bytes.len() {
        return Err(ProtoError::Malformed("truncated OOB item"));
    }
    let (item, rest) = bytes.split_at(len as usize);
    *bytes = rest;
    Ok(item)
}

fn encode_oob_req(items: &[OobItem]) -> Result<Vec<u8>, ProtoError> {
    check_oob_count(items.len())?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        let len = check_oob_len(item.len())?;
        let dir = match item {
            OobItem::In(_) => OOB_DIR_IN,
            OobItem::Out(_) => OOB_DIR_OUT,
        };
        bytes.extend_from_slice(&dir.to_le_bytes());
        bytes.extend_from_slice(&len.to_le_bytes());
        if let OobItem::In(data) = item {
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes)
}

fn decode_oob_req(mut bytes: &[u8]) -> Result<Vec<OobItem>, ProtoError> {
    let count = read_u32(&mut bytes)? as usize;
    check_oob_count(count)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let dir = read_u32(&mut bytes)?;
        let len = read_u32(&mut bytes)?;
        check_oob_len(len as usize)?;
        items.push(match dir {
            OOB_DIR_IN => OobItem::In(read_item(&mut bytes, len)?.to_vec()),
            OOB_DIR_OUT => OobItem::Out(len),
            _ => return Err(ProtoError::Malformed("bad OOB item direction")),
        });
    }
    if !bytes.is_empty() {
        return Err(ProtoError::Malformed("trailing OOB data"));
    }
    Ok(items)
}

fn encode_oob(items: &[Vec<u8>]) -> Result<Vec<u8>, ProtoError> {
    check_oob_count(items.len())?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for item in items {
        let len = check_oob_len(item.len())?;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(item);
    }
    Ok(bytes)
}

fn decode_oob(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>, ProtoError> {
    let count = read_u32(&mut bytes)? as usize;
    check_oob_count(count)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32(&mut bytes)?;
        check_oob_len(len as usize)?;
        items.push(read_item(&mut bytes, len)?.to_vec());
    }
    if !bytes.is_empty() {
        return Err(ProtoError::Malformed("trailing OOB data"));
    }
    Ok(items)
}

impl Request {
    /// Write a complete length-delimited request frame to `w`.
    pub fn write_to(&self, w: &mut impl Write) -> Result<(), ProtoError> {
        write_framed(w, &self.encode()?)
    }

    /// Read a complete length-delimited request frame from `r`.
    pub fn read_from(r: &mut impl Read) -> Result<Self, ProtoError> {
        Self::decode(&read_framed(r)?)
    }
}

impl Response {
    /// Encode this response as a complete length-delimited frame.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        if !matches!(self.cqe.len(), CQE_DWORDS | BULK_CQE_DWORDS) {
            return Err(ProtoError::Malformed("CQE field has wrong size"));
        }
        let cqe_bytes = dwords_to_le_bytes(&self.cqe);
        let oob_bytes = encode_oob(&self.oob_items)?;
        let fields = [
            (FieldId::Cqe, cqe_bytes.as_slice()),
            (FieldId::Payload, self.payload.as_slice()),
            (FieldId::OobItems, oob_bytes.as_slice()),
            (FieldId::Tail, self.tail.as_slice()),
        ];
        encode_frame(Kind::Response, self.status, &fields)
    }

    /// Decode a response from a complete frame body (no length prefix).
    pub fn decode(body: &[u8]) -> Result<Self, ProtoError> {
        let frame = Frame::parse(body, Kind::Response)?;
        let cqe = frame.dwords(FieldId::Cqe, &[CQE_DWORDS, BULK_CQE_DWORDS])?;
        let payload = frame.bytes(FieldId::Payload)?.to_vec();
        let oob_items = decode_oob(frame.bytes(FieldId::OobItems)?)?;
        let tail = frame.tail()?;
        Ok(Self {
            status: frame.status,
            cqe,
            payload,
            oob_items,
            tail,
        })
    }

    /// Write a complete length-delimited response frame to `w`.
    pub fn write_to(&self, w: &mut impl Write) -> Result<(), ProtoError> {
        write_framed(w, &self.encode()?)
    }

    /// Read a complete length-delimited response frame from `r`.
    pub fn read_from(r: &mut impl Read) -> Result<Self, ProtoError> {
        Self::decode(&read_framed(r)?)
    }
}

/// Serialize a frame body: header + TOC + data. `status` is only
/// meaningful for responses (0 for requests).
fn encode_frame(
    kind: Kind,
    status: u32,
    fields: &[(FieldId, &[u8])],
) -> Result<Vec<u8>, ProtoError> {
    if fields.len() > MAX_TOC as usize {
        return Err(ProtoError::TooManyToc(
            u8::try_from(fields.len()).unwrap_or(u8::MAX),
        ));
    }

    let mut body = Vec::new();

    // Header (+ status for responses).
    let header = FrameHeader {
        magic: U32::new(MAGIC),
        version: VERSION,
        kind: kind as u8,
        toc_count: fields.len() as u8,
        _rsvd: 0,
    };
    body.extend_from_slice(header.as_bytes());
    if matches!(kind, Kind::Response | Kind::ResetResponse) {
        body.extend_from_slice(U32::new(status).as_bytes());
    }

    // TOC. Offsets are assigned by laying the fields out contiguously in
    // the order they appear; readers locate each field by (offset, length).
    let mut offset: u32 = 0;
    for (id, data) in fields {
        let len = u32::try_from(data.len()).map_err(|_| ProtoError::TooLarge(u32::MAX))?;
        if len > field_limit(id.as_u16()) {
            return Err(ProtoError::TooLarge(len));
        }
        let entry = TocEntryRaw {
            field_id: U16::new(id.as_u16()),
            field_type: FieldType::Buffer.as_u8(),
            _rsvd: 0,
            offset: U32::new(offset),
            length: U32::new(len),
        };
        body.extend_from_slice(entry.as_bytes());
        offset += len;
    }

    // Data section.
    for (_, data) in fields {
        body.extend_from_slice(data);
    }

    // Enforce the overall frame bound: per-field `MAX_FIELD` checks above do
    // not bound the header + TOC + aggregate data size, so a combination of
    // fields could otherwise produce a body the reader side would reject.
    if body.len() > MAX_FRAME as usize {
        return Err(ProtoError::TooLarge(
            u32::try_from(body.len()).unwrap_or(u32::MAX),
        ));
    }

    Ok(body)
}

/// A parsed frame: its header status plus the located TOC + data section.
struct Frame<'a> {
    status: u32,
    toc: Vec<TocEntry>,
    data: &'a [u8],
}

impl<'a> Frame<'a> {
    /// Parse a frame body and validate the header against `expect`.
    fn parse(body: &'a [u8], expect: Kind) -> Result<Self, ProtoError> {
        if body.len() > MAX_FRAME as usize {
            return Err(ProtoError::TooLarge(
                u32::try_from(body.len()).unwrap_or(u32::MAX),
            ));
        }
        let (header, mut rest) = FrameHeader::ref_from_prefix(body)
            .map_err(|_| ProtoError::Malformed("frame too short for header"))?;
        if header.magic.get() != MAGIC {
            return Err(ProtoError::BadMagic(header.magic.get()));
        }
        if header.version != VERSION {
            return Err(ProtoError::BadVersion(header.version));
        }
        let kind = Kind::from_u8(header.kind)?;
        if kind != expect {
            return Err(ProtoError::Malformed("unexpected frame kind"));
        }
        let toc_count = header.toc_count;
        if toc_count > MAX_TOC {
            return Err(ProtoError::TooManyToc(toc_count));
        }

        let status = if matches!(kind, Kind::Response | Kind::ResetResponse) {
            let (s, r) = U32::ref_from_prefix(rest)
                .map_err(|_| ProtoError::Malformed("frame too short for status"))?;
            rest = r;
            s.get()
        } else {
            0
        };

        // TOC entries.
        let (toc_raw, data) = <[TocEntryRaw]>::ref_from_prefix_with_elems(rest, toc_count as usize)
            .map_err(|_| ProtoError::Malformed("frame too short for TOC"))?;

        let mut toc = Vec::with_capacity(toc_count as usize);
        let mut seen: Vec<FieldId> = Vec::new();
        let mut total: u64 = 0;
        for raw in toc_raw {
            let offset = raw.offset.get();
            let length = raw.length.get();
            if length > field_limit(raw.field_id.get()) {
                return Err(ProtoError::TooLarge(length));
            }
            // Reject duplicate known field IDs: `bytes()` resolves a field by
            // its first matching TOC entry, so a second entry for the same id
            // would be silently ignored and could be used to smuggle an
            // alternate interpretation (protocol confusion). Unknown ids are
            // still tolerated (and skipped) for forward compatibility.
            if let Some(known) = FieldId::from_u16(raw.field_id.get()) {
                if seen.contains(&known) {
                    return Err(ProtoError::Malformed("duplicate field id in TOC"));
                }
                seen.push(known);
            }
            // The field must lie wholly within the data section.
            if u64::from(offset) + u64::from(length) > data.len() as u64 {
                return Err(ProtoError::Malformed("field extends past data section"));
            }
            total += u64::from(length);
            toc.push(TocEntry {
                field_id: raw.field_id.get(),
                field_type: FieldType::from_u8(raw.field_type)?,
                offset,
                length,
            });
        }
        if total > u64::from(MAX_FRAME) {
            return Err(ProtoError::TooLarge(MAX_FRAME));
        }

        Ok(Self { status, toc, data })
    }

    /// Locate a field's bytes in the data section by id, using the field's
    /// explicit `(offset, length)` from its TOC entry.
    fn bytes(&self, id: FieldId) -> Result<&'a [u8], ProtoError> {
        for entry in &self.toc {
            if FieldId::from_u16(entry.field_id) == Some(id) {
                if entry.field_type != FieldType::Buffer {
                    return Err(ProtoError::Malformed("field is not a buffer"));
                }
                // Bounds were validated against the data section in `parse`.
                let start = entry.offset as usize;
                let end = start + entry.length as usize;
                return Ok(&self.data[start..end]);
            }
        }
        Err(ProtoError::Malformed("required field missing"))
    }

    /// Read a dword field (the SQE or CQE) whose length is one of `sizes`.
    fn dwords(&self, id: FieldId, sizes: &[usize]) -> Result<Vec<u32>, ProtoError> {
        let bytes = self.bytes(id)?;
        if !sizes.iter().any(|&dwords| bytes.len() == dwords * 4) {
            return Err(ProtoError::Malformed("SQE/CQE field has wrong size"));
        }
        Ok(bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect())
    }

    /// Read the GCM tail field.
    fn tail(&self) -> Result<Vec<u8>, ProtoError> {
        let bytes = self.bytes(FieldId::Tail)?;
        if bytes.len() > MAX_TAIL {
            return Err(ProtoError::Malformed("tail field too long"));
        }
        Ok(bytes.to_vec())
    }
}

/// Write a body prefixed with its `u32` little-endian length.
fn write_framed(w: &mut impl Write, body: &[u8]) -> Result<(), ProtoError> {
    w.write_all(&(body.len() as u32).to_le_bytes())?;
    w.write_all(body)?;
    w.flush()?;
    Ok(())
}

/// Read a `u32`-length-prefixed body.
fn read_framed(r: &mut impl Read) -> Result<Vec<u8>, ProtoError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(ProtoError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(body)
}

fn dwords_to_le_bytes(dwords: &[u32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(dwords.len() * 4);
    for dw in dwords {
        out.extend_from_slice(&dw.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn sample_sqe() -> Vec<u32> {
        let mut sqe = vec![0u32; SQE_DWORDS];
        sqe[0] = 0x0001_0002; // cmd dword
        sqe[1] = 8; // src_len
        sqe[6] = 4096; // dst_len
        sqe
    }

    #[test]
    fn request_round_trips() {
        let req = Request {
            sqe: sample_sqe(),
            payload: vec![1, 2, 3, 4, 5],
            oob_items: vec![OobItem::In(vec![0x11, 0x22]), OobItem::Out(7)],
            tail: vec![0xee; MAX_TAIL],
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();

        let got = Request::read_from(&mut buf.as_slice()).unwrap();
        assert_eq!(got.sqe, sample_sqe());
        assert_eq!(got.payload, vec![1, 2, 3, 4, 5]);
        assert_eq!(got.oob_items, req.oob_items);
        assert_eq!(got.tail, req.tail);
    }

    #[test]
    fn bulk_request_round_trips() {
        let req = Request {
            sqe: (0..BULK_SQE_DWORDS as u32).collect(),
            payload: vec![0x5a; 32],
            oob_items: Vec::new(),
            tail: vec![1, 2, 3],
        };
        let got = Request::decode(&req.encode().unwrap()).unwrap();
        assert_eq!(got.sqe, req.sqe);
        assert_eq!(got.tail, req.tail);
    }

    #[test]
    fn wrong_sized_entries_are_rejected() {
        let mut req = Request {
            sqe: vec![0; SQE_DWORDS + 1],
            payload: Vec::new(),
            oob_items: Vec::new(),
            tail: Vec::new(),
        };
        assert!(req.encode().is_err());
        req.sqe = vec![0; SQE_DWORDS];
        req.tail = vec![0; MAX_TAIL + 1];
        assert!(Request::decode(&req.encode().unwrap()).is_err());
        let resp = Response {
            status: 0,
            cqe: vec![0; CQE_DWORDS + 1],
            payload: Vec::new(),
            oob_items: Vec::new(),
            tail: Vec::new(),
        };
        assert!(resp.encode().is_err());
    }

    #[test]
    fn response_round_trips() {
        let resp = Response {
            status: 0,
            cqe: vec![0x000C_0000, 0, 0, 0x0001_0000],
            payload: vec![9, 8, 7],
            oob_items: vec![vec![4; 7]],
            tail: vec![5; 2],
        };
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();

        let got = Response::read_from(&mut buf.as_slice()).unwrap();
        assert_eq!(got.status, 0);
        assert_eq!(got.cqe, [0x000C_0000, 0, 0, 0x0001_0000]);
        assert_eq!(got.payload, vec![9, 8, 7]);
        assert_eq!(got.oob_items, resp.oob_items);
        assert_eq!(got.tail, resp.tail);
    }

    #[test]
    fn empty_payload_round_trips() {
        let req = Request {
            sqe: vec![0u32; SQE_DWORDS],
            payload: Vec::new(),
            oob_items: Vec::new(),
            tail: Vec::new(),
        };
        let mut buf = Vec::new();
        req.write_to(&mut buf).unwrap();
        let got = Request::read_from(&mut buf.as_slice()).unwrap();
        assert!(got.payload.is_empty());
        assert!(got.oob_items.is_empty());
    }

    #[test]
    fn transport_status_survives() {
        let resp = Response {
            status: 0x8001,
            cqe: vec![0u32; CQE_DWORDS],
            payload: Vec::new(),
            oob_items: Vec::new(),
            tail: Vec::new(),
        };
        let mut buf = Vec::new();
        resp.write_to(&mut buf).unwrap();
        let got = Response::read_from(&mut buf.as_slice()).unwrap();
        assert_eq!(got.status, 0x8001);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        body.push(VERSION);
        body.push(Kind::Request as u8);
        body.push(0); // toc_count
        body.push(0); // reserved
        let err = Request::decode(&body).unwrap_err();
        assert!(matches!(err, ProtoError::BadMagic(0xDEAD_BEEF)));
    }

    #[test]
    fn oversized_field_is_rejected() {
        let mut body = Vec::new();
        body.extend_from_slice(&MAGIC.to_le_bytes());
        body.push(VERSION);
        body.push(Kind::Request as u8);
        body.push(1); // toc_count
        body.push(0); // reserved
        body.extend_from_slice(&FieldId::Sqe.as_u16().to_le_bytes());
        body.push(FieldType::Buffer.as_u8());
        body.push(0);
        body.extend_from_slice(&0u32.to_le_bytes()); // offset
        body.extend_from_slice(&(MAX_FIELD + 1).to_le_bytes());
        let err = Request::decode(&body).unwrap_err();
        assert!(matches!(err, ProtoError::TooLarge(_)));
    }

    #[test]
    fn encode_rejects_frame_over_max_frame() {
        let field = vec![0u8; MAX_OOB_FIELD as usize];
        let fields = [
            (FieldId::OobItems, field.as_slice()),
            (FieldId::OobItems, field.as_slice()),
        ];
        let err = encode_frame(Kind::Request, 0, &fields).unwrap_err();
        assert!(matches!(err, ProtoError::TooLarge(_)));
    }

    #[test]
    fn missing_required_field_is_rejected() {
        let body = encode_frame(Kind::Request, 0, &[(FieldId::Payload, &[1, 2, 3])]).unwrap();
        let err = Request::decode(&body).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)));
    }

    #[test]
    fn duplicate_known_field_id_is_rejected() {
        // Two `Payload` TOC entries: `bytes()` would resolve only the first,
        // so the duplicate must be rejected at parse time as protocol confusion.
        let mut body = Vec::new();
        body.extend_from_slice(&MAGIC.to_le_bytes());
        body.push(VERSION);
        body.push(Kind::Request as u8);
        body.push(2); // toc_count
        body.push(0);
        for (id, offset, len) in [
            (FieldId::Payload.as_u16(), 0u32, 1u32),
            (FieldId::Payload.as_u16(), 1u32, 1u32),
        ] {
            body.extend_from_slice(&id.to_le_bytes());
            body.push(FieldType::Buffer.as_u8());
            body.push(0);
            body.extend_from_slice(&offset.to_le_bytes());
            body.extend_from_slice(&len.to_le_bytes());
        }
        body.extend_from_slice(&[0xAA, 0xBB]);
        let err = Request::decode(&body).unwrap_err();
        assert!(matches!(err, ProtoError::Malformed(_)));
    }

    #[test]
    fn unknown_field_is_skipped() {
        let cqe_bytes = dwords_to_le_bytes(&[0u32; 4]);
        let mut body = Vec::new();
        body.extend_from_slice(&MAGIC.to_le_bytes());
        body.push(VERSION);
        body.push(Kind::Response as u8);
        body.push(5); // toc_count
        body.push(0);
        body.extend_from_slice(&0u32.to_le_bytes()); // status
        for (id, offset, len) in [
            (FieldId::Cqe.as_u16(), 0u32, 16u32),
            (99u16, 16u32, 2u32),
            (FieldId::Payload.as_u16(), 18u32, 1u32),
            (FieldId::OobItems.as_u16(), 19u32, 4u32),
            (FieldId::Tail.as_u16(), 23u32, 0u32),
        ] {
            body.extend_from_slice(&id.to_le_bytes());
            body.push(FieldType::Buffer.as_u8());
            body.push(0);
            body.extend_from_slice(&offset.to_le_bytes());
            body.extend_from_slice(&len.to_le_bytes());
        }
        body.extend_from_slice(&cqe_bytes); // Cqe data
        body.extend_from_slice(&[0xAA, 0xBB]); // Unknown data
        body.extend_from_slice(&[0xCD]); // Payload data
        body.extend_from_slice(&0u32.to_le_bytes()); // Empty OOB list

        let got = Response::decode(&body).unwrap();
        assert_eq!(got.payload, vec![0xCD]);
    }

    #[test]
    fn fields_located_by_offset_regardless_of_layout_order() {
        // Lay the payload *before* the SQE in the data section, with the
        // TOC still listing SQE first. Offset-based lookup must resolve
        // each field correctly despite the mismatch between TOC order and
        // physical data order.
        let sqe = sample_sqe();
        let sqe_bytes = dwords_to_le_bytes(&sqe);
        let payload = [0x11u8, 0x22, 0x33];

        let mut body = Vec::new();
        body.extend_from_slice(&MAGIC.to_le_bytes());
        body.push(VERSION);
        body.push(Kind::Request as u8);
        body.push(4); // toc_count
        body.push(0); // reserved

        // TOC: SQE at offset 3 (after payload), Payload at offset 0.
        let sqe_len = sqe_bytes.len() as u32;
        for (id, offset, len) in [
            (FieldId::Sqe.as_u16(), 3u32, sqe_len),
            (FieldId::Payload.as_u16(), 0u32, payload.len() as u32),
            (FieldId::OobItems.as_u16(), 3 + sqe_len, 4),
            (FieldId::Tail.as_u16(), 7 + sqe_len, 0),
        ] {
            body.extend_from_slice(&id.to_le_bytes());
            body.push(FieldType::Buffer.as_u8());
            body.push(0);
            body.extend_from_slice(&offset.to_le_bytes());
            body.extend_from_slice(&len.to_le_bytes());
        }

        // Data section: payload first, then SQE.
        body.extend_from_slice(&payload);
        body.extend_from_slice(&sqe_bytes);
        body.extend_from_slice(&0u32.to_le_bytes());

        let got = Request::decode(&body).unwrap();
        assert_eq!(got.sqe, sqe);
        assert_eq!(got.payload, payload);
    }

    #[test]
    fn maximum_oob_request_round_trips() {
        let req = Request {
            sqe: sample_sqe(),
            payload: vec![0x55; MAX_FIELD as usize],
            oob_items: vec![OobItem::In(vec![0xaa; MAX_OOB_ITEM as usize]); MAX_OOB_ITEMS],
            tail: Vec::new(),
        };
        let body = req.encode().unwrap();
        assert!(body.len() <= MAX_FRAME as usize);
        let got = Request::decode(&body).unwrap();
        assert_eq!(got.oob_items, req.oob_items);
        assert_eq!(got.payload, req.payload);
    }

    #[test]
    fn malformed_oob_lists_are_rejected() {
        for bytes in [
            Vec::new(),
            65u32.to_le_bytes().to_vec(),
            [1u32.to_le_bytes(), 0u32.to_le_bytes()].concat(),
            [1u32.to_le_bytes(), (MAX_OOB_ITEM + 1).to_le_bytes()].concat(),
            [1u32.to_le_bytes(), 2u32.to_le_bytes(), [0, 0, 0, 0]].concat()[..9].to_vec(),
            [0u32.to_le_bytes(), [1, 0, 0, 0]].concat(),
        ] {
            assert!(decode_oob(&bytes).is_err(), "{bytes:?}");
        }
        assert!(encode_oob(&[Vec::new()]).is_err());
        assert!(encode_oob(&vec![vec![1]; MAX_OOB_ITEMS + 1]).is_err());
        assert!(encode_oob(&[vec![1; MAX_OOB_ITEM as usize + 1]]).is_err());

        let item = |dir: u32, len: u32| [1u32.to_le_bytes(), dir.to_le_bytes(), len.to_le_bytes()];
        for bytes in [
            item(2, 1).concat(),
            item(OOB_DIR_OUT, 0).concat(),
            item(OOB_DIR_OUT, MAX_OOB_ITEM + 1).concat(),
            item(OOB_DIR_IN, 1).concat(),
            [item(OOB_DIR_OUT, 1).concat(), vec![0]].concat(),
        ] {
            assert!(decode_oob_req(&bytes).is_err(), "{bytes:?}");
        }
        assert!(encode_oob_req(&[OobItem::Out(0)]).is_err());
    }

    #[test]
    fn reset_frames_round_trip_and_reject_wrong_shapes() {
        let mut bytes = Vec::new();
        RequestFrame::Reset.write_to(&mut bytes).unwrap();
        assert!(matches!(
            RequestFrame::read_from(&mut bytes.as_slice()).unwrap(),
            RequestFrame::Reset
        ));
        assert!(Request::decode(&bytes[4..]).is_err());
        for status in [0, 2] {
            let mut bytes = Vec::new();
            ResponseFrame::Reset { status }
                .write_to(&mut bytes)
                .unwrap();
            assert!(matches!(
                ResponseFrame::read_from(&mut bytes.as_slice()).unwrap(),
                ResponseFrame::Reset { status: value } if value == status
            ));
            assert!(Response::decode(&bytes[4..]).is_err());
        }
        let body = encode_frame(Kind::ResetRequest, 0, &[(FieldId::Payload, &[1])]).unwrap();
        assert!(RequestFrame::decode(&body).is_err());
        let mut body = RequestFrame::Reset.encode().unwrap();
        body.push(1);
        assert!(RequestFrame::decode(&body).is_err());
        let body = encode_frame(Kind::ResetResponse, 0, &[(FieldId::Payload, &[])]).unwrap();
        assert!(ResponseFrame::decode(&body).is_err());
    }
}
