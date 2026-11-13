// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side Duo SQE / CQE (API revision 2.x).
//!
//! # SQE layout ([`DUO_SQE_DWORDS`] dwords)
//!
//! | DWORD   | Field(s)                                   |
//! |---------|--------------------------------------------|
//! | DW0     | op[7:0], hint[15:8], cmd id[31:16]         |
//! | DW1     | session id (low 16 bits)                   |
//! | DW2-3   | out-of-band SGL-descriptor-page pointer    |
//! | DW4     | out-of-band SGL-descriptor-array byte count|
//! | DW6     | source length (bytes)                      |
//! | DW7-10  | source PRP pair                            |
//! | DW11    | destination length (bytes)                 |
//! | DW12-15 | destination PRP pair                       |
//! | DW19-22 | request AES-GCM tag (16 bytes)             |
//! | DW23-25 | request AES-GCM IV (12 bytes)              |
//!
//! # CQE layout ([`DUO_CQE_DWORDS`] dwords)
//!
//! | DWORD   | Field(s)                                   |
//! |---------|--------------------------------------------|
//! | DW0     | command dword echoed from the SQE          |
//! | DW1-4   | response AES-GCM tag (16 bytes)            |
//! | DW5-7   | response AES-GCM IV (12 bytes)             |
//! | DW11    | destination length written (bytes)         |
//! | DW14    | sq head[15:0], sq id[31:16]                |
//! | DW15    | error[15:0], phase[16], status[31:24]      |
//!
//! Tag and IV bytes are packed into dwords little-endian, in byte order.

/// Number of dwords in a Duo submission queue entry.
pub const DUO_SQE_DWORDS: usize = crate::BULK_SQE_DWORDS;

/// Number of dwords in a Duo completion queue entry.
pub const DUO_CQE_DWORDS: usize = crate::BULK_CQE_DWORDS;

/// Owned Duo submission queue entry.
pub type DuoRawSqe = [u32; DUO_SQE_DWORDS];

/// Owned Duo completion queue entry.
pub type DuoRawCqe = [u32; DUO_CQE_DWORDS];

/// AES-GCM tag length carried in the SQE and CQE.
pub const DUO_TAG_LEN: usize = 16;

/// AES-GCM IV length carried in the SQE and CQE.
pub const DUO_IV_LEN: usize = 12;

const SQE_SESSION_ID: usize = 1;
const SQE_OOB_LEN: usize = 4;
const SQE_SRC_LEN: usize = 6;
const SQE_DST_LEN: usize = 11;
const SQE_TAG: usize = 19;
const SQE_IV: usize = 23;

const CQE_TAG: usize = 1;
const CQE_IV: usize = 5;
const CQE_DST_LEN: usize = 11;
const CQE_DW15: usize = 15;

/// Duo SQE opcode.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuoOp {
    /// Plain TBOR command.
    Tbor = 0,
    /// TBOR command encrypted under the session transport keys.
    TborSecure = 1,
    /// Tear down the session named by the SQE session id.
    FlushSession = 2,
}

/// Fluent builder for a [`DuoRawSqe`].
#[derive(Debug)]
pub struct DuoSqeBuilder(DuoRawSqe);

impl Default for DuoSqeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DuoSqeBuilder {
    /// Starts a zeroed SQE.
    pub fn new() -> Self {
        Self([0; DUO_SQE_DWORDS])
    }

    /// Sets the command dword (DW0) to `op` and command id `id`.
    pub fn cmd(mut self, op: DuoOp, id: u16) -> Self {
        self.0[0] = u32::from(op as u8) | (u32::from(id) << 16);
        self
    }

    /// Sets the session id (DW1).
    pub fn session_id(mut self, id: u16) -> Self {
        self.0[SQE_SESSION_ID] = u32::from(id);
        self
    }

    /// Sets the out-of-band SGL-descriptor-array byte count (DW4).
    pub fn oob_len(mut self, len: u32) -> Self {
        self.0[SQE_OOB_LEN] = len;
        self
    }

    /// Sets the source (DW6) and destination (DW11) buffer lengths.
    pub fn buf_lens(mut self, src_len: u32, dst_len: u32) -> Self {
        self.0[SQE_SRC_LEN] = src_len;
        self.0[SQE_DST_LEN] = dst_len;
        self
    }

    /// Sets the request AES-GCM tag (DW19–22).
    pub fn gcm_tag(mut self, tag: &[u8; DUO_TAG_LEN]) -> Self {
        write_bytes(&mut self.0[SQE_TAG..SQE_TAG + 4], tag);
        self
    }

    /// Sets the request AES-GCM IV (DW23–25).
    pub fn iv(mut self, iv: &[u8; DUO_IV_LEN]) -> Self {
        write_bytes(&mut self.0[SQE_IV..SQE_IV + 3], iv);
        self
    }

    /// Returns the built SQE.
    pub fn build(self) -> DuoRawSqe {
        self.0
    }
}

/// Decoded fields of a [`DuoRawCqe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DuoCqe {
    /// Command id echoed from the SQE.
    pub cmd_id: u16,
    /// Response AES-GCM tag.
    pub tag: [u8; DUO_TAG_LEN],
    /// Response AES-GCM IV.
    pub iv: [u8; DUO_IV_LEN],
    /// Bytes written to the destination buffer.
    pub dst_len: u32,
    /// Error code.
    pub error: u16,
    /// Status code; 0 = success.
    pub status: u8,
}

impl DuoCqe {
    /// Decodes `raw`.
    pub fn decode(raw: &DuoRawCqe) -> Self {
        Self {
            cmd_id: (raw[0] >> 16) as u16,
            tag: read_bytes(&raw[CQE_TAG..CQE_TAG + 4]),
            iv: read_bytes(&raw[CQE_IV..CQE_IV + 3]),
            dst_len: raw[CQE_DST_LEN],
            error: raw[CQE_DW15] as u16,
            status: (raw[CQE_DW15] >> 24) as u8,
        }
    }
}

fn read_bytes<const N: usize>(words: &[u32]) -> [u8; N] {
    let mut out = [0u8; N];
    for (chunk, word) in out.chunks_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    out
}

fn write_bytes(words: &mut [u32], bytes: &[u8]) {
    for (word, chunk) in words.iter_mut().zip(bytes.chunks(4)) {
        let mut le = [0u8; 4];
        le[..chunk.len()].copy_from_slice(chunk);
        *word = u32::from_le_bytes(le);
    }
}
