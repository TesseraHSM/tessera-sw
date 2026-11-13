// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side Uno command SQE / CQE (API revision 1.x).
//!
//! # SQE layout ([`SQE_DWORDS`] dwords)
//!
//! | DWORD   | Field(s)                                        |
//! |---------|-------------------------------------------------|
//! | DW0     | [`CmdDword`] — op, set, psdt, cmd id            |
//! | DW1     | source length (bytes)                           |
//! | DW2-5   | source PRP pair                                 |
//! | DW6     | destination length (bytes)                      |
//! | DW7-10  | destination PRP pair                            |
//! | DW11    | [`SessionFlags`]                                |
//! | DW12    | session id (low 16 bits)                        |
//! | DW13-14 | out-of-band SGL-descriptor-page pointer         |
//! | DW15    | out-of-band SGL-descriptor-array byte count     |
//!
//! # CQE layout ([`CQE_DWORDS`] dwords)
//!
//! | DWORD | Field(s)                                                  |
//! |-------|-----------------------------------------------------------|
//! | DW0   | dst_len[15:0], session ctrl/flags                         |
//! | DW1   | session id[15:0], app vault id[23:16]                     |
//! | DW2   | sq head[15:0], sq id[31:16]                               |
//! | DW3   | cmd id[15:0], phase[16], status[27:17]                    |

use crate::CQE_DWORDS;
use crate::SQE_DWORDS;

/// Owned command submission queue entry.
pub type RawSqe = [u32; SQE_DWORDS];

/// Owned command completion queue entry.
pub type RawCqe = [u32; CQE_DWORDS];

/// SQE opcode of an MBOR command.
pub const OP_MBOR: u16 = 0;

/// SQE opcode of a TBOR command.
pub const OP_TBOR: u16 = 2;

/// Command dword (SQE DW0): op[9:0], set[13:10], psdt[15:14], id[31:16].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CmdDword(u32);

impl CmdDword {
    const OP_MASK: u32 = 0x3FF;

    /// A zeroed command dword.
    pub const fn new() -> Self {
        Self(0)
    }

    /// Wraps raw dword bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the raw dword bits.
    pub const fn into_bits(self) -> u32 {
        self.0
    }

    /// Sets the opcode (low 10 bits of `op`).
    pub const fn with_op(self, op: u16) -> Self {
        Self((self.0 & !Self::OP_MASK) | (op as u32 & Self::OP_MASK))
    }

    /// Sets the command id.
    pub const fn with_id(self, id: u16) -> Self {
        Self((self.0 & 0xFFFF) | ((id as u32) << 16))
    }

    /// Opcode.
    pub const fn op(self) -> u16 {
        (self.0 & Self::OP_MASK) as u16
    }

    /// Command id.
    pub const fn id(self) -> u16 {
        (self.0 >> 16) as u16
    }
}

/// Session flags (SQE DW11): ctrl[1:0], id_valid[2].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionFlags(u32);

impl SessionFlags {
    /// Zeroed session flags.
    pub const fn new() -> Self {
        Self(0)
    }

    /// Sets the session control (low 2 bits of `ctrl`).
    pub const fn with_ctrl(self, ctrl: u8) -> Self {
        Self((self.0 & !0x3) | (ctrl as u32 & 0x3))
    }

    /// Sets whether the SQE session id is valid.
    pub const fn with_id_valid(self, valid: bool) -> Self {
        Self((self.0 & !0x4) | ((valid as u32) << 2))
    }

    /// Returns the raw dword bits.
    pub const fn into_bits(self) -> u32 {
        self.0
    }
}

/// Fluent builder for a [`RawSqe`].
#[derive(Debug, Default)]
pub struct SqeBuilder(RawSqe);

impl SqeBuilder {
    /// Starts a zeroed SQE.
    pub fn new() -> Self {
        Self([0; SQE_DWORDS])
    }

    /// Sets the command dword (DW0).
    pub fn cmd(mut self, cmd: CmdDword) -> Self {
        self.0[0] = cmd.into_bits();
        self
    }

    /// Sets the source (DW1) and destination (DW6) buffer lengths.
    pub fn buf_lens(mut self, src_len: u32, dst_len: u32) -> Self {
        self.0[1] = src_len;
        self.0[6] = dst_len;
        self
    }

    /// Sets the session flags (DW11).
    pub fn session_flags(mut self, flags: SessionFlags) -> Self {
        self.0[11] = flags.into_bits();
        self
    }

    /// Sets the session id (DW12).
    pub fn session_id(mut self, id: u16) -> Self {
        self.0[12] = u32::from(id);
        self
    }

    /// Sets the out-of-band SGL-descriptor-array byte count (DW15).
    pub fn oob_len(mut self, len: u32) -> Self {
        self.0[15] = len;
        self
    }

    /// Returns the built SQE.
    pub fn build(self) -> RawSqe {
        self.0
    }
}

/// Decoded fields of a command [`RawCqe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cqe {
    /// Bytes the firmware wrote to the destination buffer.
    pub dst_len: u16,
    /// Host status code; 0 = success.
    pub status: u16,
    /// Command id echoed from the SQE.
    pub cmd_id: u16,
}

impl Cqe {
    /// Decodes `raw`.
    pub fn decode(raw: &RawCqe) -> Self {
        Self {
            dst_len: raw[0] as u16,
            status: ((raw[3] >> 17) & 0x7FF) as u16,
            cmd_id: raw[3] as u16,
        }
    }
}
