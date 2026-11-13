// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Duo (api_rev 2.0) SQE / CQE layout.
//!
//! Duo uses a 128-byte submission entry and a 64-byte completion entry.
//! Only TBOR is carried; the opcode selects plain TBOR, session-encrypted
//! TBOR or a session flush.
//!
//! # SQE layout
//!
//! | DWORD  | Field(s)                                               |
//! |--------|--------------------------------------------------------|
//! | DW0    | [`DuoCmdDword`] — op, hint, cmd id                      |
//! | DW1    | session id (low 16 bits)                               |
//! | DW2-3  | out-of-band (OOB) SGL-descriptor-page pointer          |
//! | DW4    | out-of-band (OOB) total byte count                     |
//! | DW5    | reserved                                               |
//! | DW6    | source length (bytes)                                  |
//! | DW7-8  | source PRP1                                            |
//! | DW9-10 | source PRP2                                            |
//! | DW11   | destination length (bytes)                             |
//! | DW12-13| destination PRP1                                       |
//! | DW14-15| destination PRP2                                       |
//! | DW16   | frame id (low 8 bits)                                  |
//! | DW17   | key index                                              |
//! | DW18   | reserved                                               |
//! | DW19-22| request AES-GCM tag (16 bytes)                         |
//! | DW23-25| request AES-GCM IV (12 bytes)                          |
//! | DW26   | AAD length (bytes)                                     |
//! | DW27-31| reserved                                               |
//!
//! # CQE layout
//!
//! | DWORD  | Field(s)                                               |
//! |--------|--------------------------------------------------------|
//! | DW0    | [`DuoCmdDword`] echoed from the SQE                     |
//! | DW1-4  | response AES-GCM tag (16 bytes)                        |
//! | DW5-7  | response AES-GCM IV (12 bytes)                         |
//! | DW8-10 | reserved                                               |
//! | DW11   | destination length written (bytes)                     |
//! | DW12-13| reserved                                               |
//! | DW14   | [`DuoCqeDw14`] — sq head, sq id                         |
//! | DW15   | [`DuoCqeDw15`] — error, phase, status                   |
//!
//! Tag and IV bytes are packed into dwords little-endian, in byte order.

use bitfield_struct::bitfield;
use tsra_fw_hsm_pal_traits::HsmCqe;
use tsra_fw_hsm_pal_traits::HsmCqeSession;
use tsra_fw_hsm_pal_traits::HsmDmaAddr;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmSessCtrl;
use tsra_fw_hsm_pal_traits::HsmSqe;

use crate::host_status;
use crate::HostStatus;

/// Number of dwords in a Duo submission queue entry.
pub const DUO_SQE_DWORDS: usize = 32;

/// Number of dwords in a Duo completion queue entry.
pub const DUO_CQE_DWORDS: usize = 16;

/// Owned Duo submission queue entry.
pub type DuoRawSqe = [u32; DUO_SQE_DWORDS];

/// Owned Duo completion queue entry.
pub type DuoRawCqe = [u32; DUO_CQE_DWORDS];

/// AES-GCM tag length carried in the SQE and CQE.
pub const DUO_TAG_LEN: usize = 16;

/// AES-GCM IV length carried in the SQE and CQE.
pub const DUO_IV_LEN: usize = 12;

/// Duo SQE opcode.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuoOp {
    /// Plain TBOR command.
    Tbor = 0,

    /// TBOR command encrypted under the session transport keys.
    TborSecure = 1,

    /// Tear down the session named by the SQE session id.
    FlushSession = 2,
}

impl TryFrom<u8> for DuoOp {
    type Error = HsmError;

    #[inline]
    fn try_from(op: u8) -> Result<Self, Self::Error> {
        match op {
            0 => Ok(Self::Tbor),
            1 => Ok(Self::TborSecure),
            2 => Ok(Self::FlushSession),
            _ => Err(HsmError::InvalidArg),
        }
    }
}

/// Duo command dword (SQE DW0, echoed in CQE DW0).
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct DuoCmdDword {
    /// Opcode; see [`DuoOp`].
    #[bits(8)]
    pub op: u8,

    /// Hint.
    #[bits(8)]
    pub hint: u8,

    /// Command identifier.
    #[bits(16)]
    pub id: u16,
}

/// Duo CQE DW14: sq head and sq id.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct DuoCqeDw14 {
    /// Submission queue head pointer.
    #[bits(16)]
    pub sq_head: u16,

    /// Submission queue identifier.
    #[bits(16)]
    pub sq_id: u16,
}

/// Duo CQE DW15: error, phase and status.
#[bitfield(u32)]
#[derive(PartialEq, Eq)]
pub struct DuoCqeDw15 {
    /// Error code.
    #[bits(16)]
    pub error: u16,

    /// Phase bit.
    #[bits(1)]
    pub phase: bool,

    /// Reserved.
    #[bits(7)]
    _rsvd: u8,

    /// Status code; 0 = success.
    #[bits(8)]
    pub status: u8,
}

const SQE_SESSION_ID: usize = 1;
const SQE_OOB_PRP: usize = 2;
const SQE_OOB_LEN: usize = 4;
const SQE_SRC_LEN: usize = 6;
const SQE_SRC_PRP1: usize = 7;
const SQE_SRC_PRP2: usize = 9;
const SQE_DST_LEN: usize = 11;
const SQE_DST_PRP1: usize = 12;
const SQE_DST_PRP2: usize = 14;
const SQE_FRAME: usize = 16;
const SQE_KEY_INDEX: usize = 17;
const SQE_TAG: usize = 19;
const SQE_IV: usize = 23;
const SQE_AAD_LEN: usize = 26;

const CQE_TAG: usize = 1;
const CQE_IV: usize = 5;
const CQE_DST_LEN: usize = 11;
const CQE_DW14: usize = 14;
const CQE_DW15: usize = 15;

#[inline]
fn read_bytes<const N: usize>(words: &[u32]) -> [u8; N] {
    let mut out = [0u8; N];
    for (chunk, word) in out.chunks_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    out
}

#[inline]
fn write_bytes(words: &mut [u32], bytes: &[u8]) {
    for (word, chunk) in words.iter_mut().zip(bytes.chunks(4)) {
        let mut le = [0u8; 4];
        le[..chunk.len()].copy_from_slice(chunk);
        *word = u32::from_le_bytes(le);
    }
}

#[inline]
fn addr(words: &[u32], at: usize) -> HsmDmaAddr {
    HsmDmaAddr {
        lo: words[at],
        hi: words[at + 1],
    }
}

#[inline]
fn set_addr(words: &mut [u32], at: usize, addr: u64) {
    words[at] = addr as u32;
    words[at + 1] = (addr >> 32) as u32;
}

// ── SQE read view ───────────────────────────────────────────────────

/// Typed read-only wrapper around a raw Duo SQE.
///
/// Slice conversion rejects lengths other than [`DUO_SQE_DWORDS`] with
/// [`HsmError::InvalidArg`].
#[derive(Debug)]
pub struct DuoSqe<'a>(&'a DuoRawSqe);

impl<'a> From<&'a DuoRawSqe> for DuoSqe<'a> {
    #[inline]
    fn from(sqe: &'a DuoRawSqe) -> Self {
        Self(sqe)
    }
}

impl<'a> TryFrom<&'a [u32]> for DuoSqe<'a> {
    type Error = HsmError;

    #[inline]
    fn try_from(sqe: &'a [u32]) -> Result<Self, Self::Error> {
        let raw = sqe.try_into().map_err(|_| HsmError::InvalidArg)?;
        Ok(Self(raw))
    }
}

impl DuoSqe<'_> {
    /// Returns the parsed command dword (DW0).
    #[inline]
    pub fn cmd(&self) -> DuoCmdDword {
        DuoCmdDword::from(self.0[0])
    }

    /// Decoded opcode (DW0[7:0]); unknown values are
    /// [`HsmError::InvalidArg`].
    #[inline]
    pub fn op(&self) -> Result<DuoOp, HsmError> {
        DuoOp::try_from(self.cmd().op())
    }

    /// Command identifier (DW0[31:16]).
    #[inline]
    pub fn cmd_id(&self) -> u16 {
        self.cmd().id()
    }

    /// Session ID (DW1, low 16 bits).
    #[inline]
    pub fn session_id(&self) -> u16 {
        self.0[SQE_SESSION_ID] as u16
    }

    /// Out-of-band SGL-descriptor-page pointer (DW2–3); zero = none.
    #[inline]
    pub fn oob_prp(&self) -> HsmDmaAddr {
        addr(self.0, SQE_OOB_PRP)
    }

    /// Out-of-band SGL-descriptor-array byte count (DW4); zero = none.
    #[inline]
    pub fn oob_len(&self) -> u32 {
        self.0[SQE_OOB_LEN]
    }

    /// Source DMA buffer length in bytes (DW6).
    #[inline]
    pub fn src_len(&self) -> u32 {
        self.0[SQE_SRC_LEN]
    }

    /// Source PRP1 address (DW7–8).
    #[inline]
    pub fn src_prp1(&self) -> HsmDmaAddr {
        addr(self.0, SQE_SRC_PRP1)
    }

    /// Source PRP2 address (DW9–10).
    #[inline]
    pub fn src_prp2(&self) -> HsmDmaAddr {
        addr(self.0, SQE_SRC_PRP2)
    }

    /// Destination DMA buffer length in bytes (DW11).
    #[inline]
    pub fn dst_len(&self) -> u32 {
        self.0[SQE_DST_LEN]
    }

    /// Destination PRP1 address (DW12–13).
    #[inline]
    pub fn dst_prp1(&self) -> HsmDmaAddr {
        addr(self.0, SQE_DST_PRP1)
    }

    /// Destination PRP2 address (DW14–15).
    #[inline]
    pub fn dst_prp2(&self) -> HsmDmaAddr {
        addr(self.0, SQE_DST_PRP2)
    }

    /// Frame id (DW16, low 8 bits).
    #[inline]
    pub fn frame_id(&self) -> u8 {
        self.0[SQE_FRAME] as u8
    }

    /// Key index (DW17).
    #[inline]
    pub fn key_index(&self) -> u32 {
        self.0[SQE_KEY_INDEX]
    }

    /// Request AES-GCM tag (DW19–22).
    #[inline]
    pub fn gcm_tag(&self) -> [u8; DUO_TAG_LEN] {
        read_bytes(&self.0[SQE_TAG..SQE_TAG + 4])
    }

    /// Request AES-GCM IV (DW23–25).
    #[inline]
    pub fn iv(&self) -> [u8; DUO_IV_LEN] {
        read_bytes(&self.0[SQE_IV..SQE_IV + 3])
    }

    /// AAD length in bytes (DW26).
    #[inline]
    pub fn aad_len(&self) -> u32 {
        self.0[SQE_AAD_LEN]
    }
}

// ── SQE builder (host side) ─────────────────────────────────────────

/// Fluent builder for a [`DuoRawSqe`].
#[derive(Debug)]
pub struct DuoSqeBuilder(DuoRawSqe);

impl Default for DuoSqeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DuoSqeBuilder {
    /// Start a new zeroed SQE.
    #[inline]
    pub fn new() -> Self {
        Self([0u32; DUO_SQE_DWORDS])
    }

    /// Set the command dword (DW0).
    #[inline]
    pub fn cmd(mut self, cmd: DuoCmdDword) -> Self {
        self.0[0] = cmd.into();
        self
    }

    /// Set the session ID (DW1).
    #[inline]
    pub fn session_id(mut self, id: u16) -> Self {
        self.0[SQE_SESSION_ID] = u32::from(id);
        self
    }

    /// Set the out-of-band SGL-descriptor-page pointer (DW2–3).
    #[inline]
    pub fn oob_prp(mut self, addr: u64) -> Self {
        set_addr(&mut self.0, SQE_OOB_PRP, addr);
        self
    }

    /// Set the out-of-band SGL-descriptor-array byte count (DW4).
    #[inline]
    pub fn oob_len(mut self, len: u32) -> Self {
        self.0[SQE_OOB_LEN] = len;
        self
    }

    /// Set the source (DW6) and destination (DW11) buffer lengths.
    #[inline]
    pub fn buf_lens(mut self, src_len: u32, dst_len: u32) -> Self {
        self.0[SQE_SRC_LEN] = src_len;
        self.0[SQE_DST_LEN] = dst_len;
        self
    }

    /// Set the source PRP1 address (DW7–8).
    #[inline]
    pub fn src_prp1(mut self, addr: u64) -> Self {
        set_addr(&mut self.0, SQE_SRC_PRP1, addr);
        self
    }

    /// Set the destination PRP1 address (DW12–13).
    #[inline]
    pub fn dst_prp1(mut self, addr: u64) -> Self {
        set_addr(&mut self.0, SQE_DST_PRP1, addr);
        self
    }

    /// Set the frame id (DW16).
    #[inline]
    pub fn frame_id(mut self, id: u8) -> Self {
        self.0[SQE_FRAME] = u32::from(id);
        self
    }

    /// Set the key index (DW17).
    #[inline]
    pub fn key_index(mut self, index: u32) -> Self {
        self.0[SQE_KEY_INDEX] = index;
        self
    }

    /// Set the request AES-GCM tag (DW19–22).
    #[inline]
    pub fn gcm_tag(mut self, tag: &[u8; DUO_TAG_LEN]) -> Self {
        write_bytes(&mut self.0[SQE_TAG..SQE_TAG + 4], tag);
        self
    }

    /// Set the request AES-GCM IV (DW23–25).
    #[inline]
    pub fn iv(mut self, iv: &[u8; DUO_IV_LEN]) -> Self {
        write_bytes(&mut self.0[SQE_IV..SQE_IV + 3], iv);
        self
    }

    /// Set the AAD length (DW26).
    #[inline]
    pub fn aad_len(mut self, len: u32) -> Self {
        self.0[SQE_AAD_LEN] = len;
        self
    }

    /// Finish and return the owned [`DuoRawSqe`].
    #[inline]
    pub fn build(self) -> DuoRawSqe {
        self.0
    }
}

// ── CQE read/write view ─────────────────────────────────────────────

/// Typed read/write wrapper around a raw Duo CQE.
///
/// Slice conversion rejects lengths other than [`DUO_CQE_DWORDS`] with
/// [`HsmError::InvalidArg`].
#[derive(Debug)]
pub struct DuoCqe<'a>(&'a mut DuoRawCqe);

impl<'a> From<&'a mut DuoRawCqe> for DuoCqe<'a> {
    #[inline]
    fn from(cqe: &'a mut DuoRawCqe) -> Self {
        Self(cqe)
    }
}

impl<'a> TryFrom<&'a mut [u32]> for DuoCqe<'a> {
    type Error = HsmError;

    #[inline]
    fn try_from(cqe: &'a mut [u32]) -> Result<Self, Self::Error> {
        let raw = cqe.try_into().map_err(|_| HsmError::InvalidArg)?;
        Ok(Self(raw))
    }
}

impl DuoCqe<'_> {
    /// Zero all dwords.
    #[inline]
    pub fn clear(&mut self) {
        self.0.fill(0);
    }

    /// Command dword echoed from the SQE (DW0).
    #[inline]
    pub fn cmd(&self) -> DuoCmdDword {
        DuoCmdDword::from(self.0[0])
    }

    /// Sets the command dword (DW0).
    #[inline]
    pub fn set_cmd(&mut self, cmd: DuoCmdDword) {
        self.0[0] = cmd.into();
    }

    /// Command id echoed from the SQE (DW0[31:16]).
    #[inline]
    pub fn cmd_id(&self) -> u16 {
        self.cmd().id()
    }

    /// Response AES-GCM tag (DW1–4).
    #[inline]
    pub fn tag(&self) -> [u8; DUO_TAG_LEN] {
        read_bytes(&self.0[CQE_TAG..CQE_TAG + 4])
    }

    /// Sets the response AES-GCM tag (DW1–4).
    #[inline]
    pub fn set_tag(&mut self, tag: &[u8; DUO_TAG_LEN]) {
        write_bytes(&mut self.0[CQE_TAG..CQE_TAG + 4], tag);
    }

    /// Response AES-GCM IV (DW5–7).
    #[inline]
    pub fn iv(&self) -> [u8; DUO_IV_LEN] {
        read_bytes(&self.0[CQE_IV..CQE_IV + 3])
    }

    /// Sets the response AES-GCM IV (DW5–7).
    #[inline]
    pub fn set_iv(&mut self, iv: &[u8; DUO_IV_LEN]) {
        write_bytes(&mut self.0[CQE_IV..CQE_IV + 3], iv);
    }

    /// Length of data written to the destination buffer (DW11).
    #[inline]
    pub fn dst_len(&self) -> u32 {
        self.0[CQE_DST_LEN]
    }

    /// Sets the destination length (DW11).
    #[inline]
    pub fn set_dst_len(&mut self, len: u32) {
        self.0[CQE_DST_LEN] = len;
    }

    /// Returns the parsed DW14.
    #[inline]
    pub fn dw14(&self) -> DuoCqeDw14 {
        DuoCqeDw14::from(self.0[CQE_DW14])
    }

    /// Sets the submission queue head pointer (DW14[15:0]).
    #[inline]
    pub fn set_sq_head(&mut self, head: u16) {
        self.0[CQE_DW14] = self.dw14().with_sq_head(head).into();
    }

    /// Sets the submission queue id (DW14[31:16]).
    #[inline]
    pub fn set_sq_id(&mut self, id: u16) {
        self.0[CQE_DW14] = self.dw14().with_sq_id(id).into();
    }

    /// Returns the parsed DW15.
    #[inline]
    pub fn dw15(&self) -> DuoCqeDw15 {
        DuoCqeDw15::from(self.0[CQE_DW15])
    }

    /// Error code (DW15[15:0]).
    #[inline]
    pub fn error(&self) -> u16 {
        self.dw15().error()
    }

    /// Sets the error code (DW15[15:0]).
    #[inline]
    pub fn set_error(&mut self, error: u16) {
        self.0[CQE_DW15] = self.dw15().with_error(error).into();
    }

    /// Sets the phase bit (DW15[16]).
    #[inline]
    pub fn set_phase(&mut self, phase: bool) {
        self.0[CQE_DW15] = self.dw15().with_phase(phase).into();
    }

    /// Status code (DW15[31:24]); 0 = success.
    #[inline]
    pub fn status(&self) -> u8 {
        self.dw15().status()
    }

    /// Sets the status code (DW15[31:24]).
    #[inline]
    pub fn set_status(&mut self, status: u8) {
        self.0[CQE_DW15] = self.dw15().with_status(status).into();
    }
}

// ── Entries ─────────────────────────────────────────────────────────

/// A Duo submission queue entry.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuoSqeEntry(pub DuoRawSqe);

impl Default for DuoSqeEntry {
    fn default() -> Self {
        Self([0; DUO_SQE_DWORDS])
    }
}

impl DuoSqeEntry {
    /// Typed view of the entry.
    #[inline]
    pub fn view(&self) -> DuoSqe<'_> {
        DuoSqe(&self.0)
    }
}

impl HsmSqe for DuoSqeEntry {
    #[inline]
    fn opcode(&self) -> u16 {
        u16::from(self.view().cmd().op())
    }

    /// The SQE session id field is meaningful only for
    /// [`DuoOp::TborSecure`] and [`DuoOp::FlushSession`].
    #[inline]
    fn session_id(&self) -> Option<u16> {
        let sqe = self.view();
        match sqe.op() {
            Ok(DuoOp::TborSecure | DuoOp::FlushSession) => Some(sqe.session_id()),
            _ => None,
        }
    }

    #[inline]
    fn session_ctrl(&self) -> HsmSessCtrl {
        HsmSessCtrl::Unspecified
    }
}

/// A Duo completion queue entry.
///
/// The platform stamps its identity ([`DuoCqe::set_cmd`]) and routing
/// fields, and the transport protection fields of a secure response;
/// [`HsmCqe`] writes `dst_len` and the status.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuoCqeEntry(pub DuoRawCqe);

impl Default for DuoCqeEntry {
    fn default() -> Self {
        Self([0; DUO_CQE_DWORDS])
    }
}

impl DuoCqeEntry {
    /// Typed view of the entry.
    #[inline]
    pub fn view(&mut self) -> DuoCqe<'_> {
        DuoCqe(&mut self.0)
    }
}

impl HsmCqe for DuoCqeEntry {
    #[inline]
    fn set_ok(&mut self, dst_len: u32) {
        let mut cqe = self.view();
        cqe.set_dst_len(dst_len);
        cqe.set_status(HostStatus::SUCCESS as u8);
    }

    /// Duo CQEs carry no session fields.
    #[inline]
    fn set_ok_ex(&mut self, dst_len: u32, _sess: HsmCqeSession) {
        self.set_ok(dst_len);
    }

    #[inline]
    fn set_err(&mut self, err: HsmError) {
        let mut cqe = self.view();
        cqe.set_dst_len(0);
        cqe.set_iv(&[0; DUO_IV_LEN]);
        cqe.set_tag(&[0; DUO_TAG_LEN]);
        cqe.set_status(duo_status(host_status(err)));
    }
}

/// Narrows a host status to the Duo CQE's 8-bit status field.
#[inline]
pub fn duo_status(status: u16) -> u8 {
    u8::try_from(status).unwrap_or(HostStatus::INTERNAL_ERROR as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: [u8; DUO_TAG_LEN] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const IV: [u8; DUO_IV_LEN] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    ];

    fn dma(addr: u64) -> HsmDmaAddr {
        HsmDmaAddr {
            lo: addr as u32,
            hi: (addr >> 32) as u32,
        }
    }

    #[test]
    fn entry_sizes_match_duo_abi() {
        assert_eq!(core::mem::size_of::<DuoRawSqe>(), 128);
        assert_eq!(core::mem::size_of::<DuoRawCqe>(), 64);
    }

    #[test]
    fn sqe_fields_land_at_duo_offsets() {
        let raw = DuoSqeBuilder::new()
            .cmd(
                DuoCmdDword::new()
                    .with_op(DuoOp::TborSecure as u8)
                    .with_hint(0x5a)
                    .with_id(0x1234),
            )
            .session_id(0xbeef)
            .oob_prp(0x1111_2222_3333_4444)
            .oob_len(0x40)
            .buf_lens(0x100, 0x200)
            .src_prp1(0xaaaa_bbbb_cccc_dddd)
            .dst_prp1(0x0102_0304_0506_0708)
            .frame_id(7)
            .key_index(3)
            .gcm_tag(&TAG)
            .iv(&IV)
            .aad_len(9)
            .build();

        let bytes: [u8; 128] = core::array::from_fn(|i| raw[i / 4].to_le_bytes()[i % 4]);
        let u32_at =
            |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().expect("4 bytes"));
        let u64_at =
            |off: usize| u64::from_le_bytes(bytes[off..off + 8].try_into().expect("8 bytes"));
        assert_eq!(bytes[0], DuoOp::TborSecure as u8);
        assert_eq!(bytes[1], 0x5a);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0x1234);
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 0xbeef);
        assert_eq!(u64_at(8), 0x1111_2222_3333_4444);
        assert_eq!(u32_at(16), 0x40);
        assert_eq!(u32_at(24), 0x100);
        assert_eq!(u64_at(28), 0xaaaa_bbbb_cccc_dddd);
        assert_eq!(u32_at(44), 0x200);
        assert_eq!(u64_at(48), 0x0102_0304_0506_0708);
        assert_eq!(bytes[64], 7);
        assert_eq!(u32_at(68), 3);
        assert_eq!(bytes[76..92], TAG);
        assert_eq!(bytes[92..104], IV);
        assert_eq!(u32_at(104), 9);

        let sqe = DuoSqe::try_from(raw.as_slice()).expect("Duo SQE");
        assert_eq!(sqe.op(), Ok(DuoOp::TborSecure));
        assert_eq!(sqe.cmd_id(), 0x1234);
        assert_eq!(sqe.session_id(), 0xbeef);
        assert_eq!(sqe.oob_prp(), dma(0x1111_2222_3333_4444));
        assert_eq!(sqe.oob_len(), 0x40);
        assert_eq!(sqe.src_len(), 0x100);
        assert_eq!(sqe.src_prp1(), dma(0xaaaa_bbbb_cccc_dddd));
        assert_eq!(sqe.dst_len(), 0x200);
        assert_eq!(sqe.dst_prp1(), dma(0x0102_0304_0506_0708));
        assert_eq!(sqe.frame_id(), 7);
        assert_eq!(sqe.key_index(), 3);
        assert_eq!(sqe.gcm_tag(), TAG);
        assert_eq!(sqe.iv(), IV);
        assert_eq!(sqe.aad_len(), 9);
    }

    #[test]
    fn cqe_fields_land_at_duo_offsets() {
        let mut raw = [0u32; DUO_CQE_DWORDS];
        let mut cqe = DuoCqe::try_from(raw.as_mut_slice()).expect("Duo CQE");
        cqe.set_cmd(DuoCmdDword::new().with_id(0x4321));
        cqe.set_tag(&TAG);
        cqe.set_iv(&IV);
        cqe.set_dst_len(0x80);
        cqe.set_sq_head(5);
        cqe.set_sq_id(6);
        cqe.set_error(0x0102);
        cqe.set_phase(true);
        cqe.set_status(3);
        assert_eq!(cqe.cmd_id(), 0x4321);
        assert_eq!(cqe.tag(), TAG);
        assert_eq!(cqe.iv(), IV);
        assert_eq!(cqe.error(), 0x0102);
        assert_eq!(cqe.status(), 3);

        let bytes: [u8; 64] = core::array::from_fn(|i| raw[i / 4].to_le_bytes()[i % 4]);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0x4321);
        assert_eq!(bytes[4..20], TAG);
        assert_eq!(bytes[20..32], IV);
        assert_eq!(bytes[44..48], 0x80u32.to_le_bytes());
        assert_eq!(bytes[56..60], [5, 0, 6, 0]);
        assert_eq!(bytes[60..64], [0x02, 0x01, 1, 3]);
    }

    #[test]
    fn op_rejects_unknown_values() {
        for op in 3..=u8::MAX {
            assert_eq!(DuoOp::try_from(op), Err(HsmError::InvalidArg));
        }
        let raw = DuoSqeBuilder::new()
            .cmd(DuoCmdDword::new().with_op(3))
            .build();
        assert_eq!(DuoSqe::from(&raw).op(), Err(HsmError::InvalidArg));
    }

    #[test]
    fn slices_reject_other_lengths() {
        let words = [0u32; DUO_SQE_DWORDS + 1];
        for len in [0, 16, DUO_SQE_DWORDS - 1, DUO_SQE_DWORDS + 1] {
            assert_eq!(
                DuoSqe::try_from(&words[..len]).expect_err("bad SQE length"),
                HsmError::InvalidArg
            );
        }
        let mut words = [u32::MAX; DUO_CQE_DWORDS + 1];
        for len in [0, 4, DUO_CQE_DWORDS - 1, DUO_CQE_DWORDS + 1] {
            assert_eq!(
                DuoCqe::try_from(&mut words[..len]).expect_err("bad CQE length"),
                HsmError::InvalidArg
            );
        }
        assert_eq!(words, [u32::MAX; DUO_CQE_DWORDS + 1]);
    }
}
