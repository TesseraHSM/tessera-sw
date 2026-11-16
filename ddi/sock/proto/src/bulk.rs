// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side bulk (fast-path AES-GCM / AES-XTS) SQE / CQE.
//!
//! Field offsets are byte offsets into the entry; byte `n` is bits
//! `8 * (n % 4)..` of dword `n / 4` (little-endian dwords).
//!
//! # SQE layout ([`BULK_SQE_DWORDS`] dwords)
//!
//! | Offset | Field |
//! |---|---|
//! | 4 | Command attributes: bit 0 decrypt, bit 2 SGL, bits 3-5 command type, bit 8 XTS, bits 14-15 XTS data unit |
//! | 6 | Command id |
//! | 8 | Session id |
//! | 10 | Short app id |
//! | 24 | Source data length |
//! | 28 | Source SGL data-block descriptor |
//! | 44 | Destination data length |
//! | 48 | Destination SGL data-block descriptor |
//! | 64 | Frame type |
//!
//! GCM fields: 68 key id, 72 AAD length, 76 tag, 92 IV, 104 padded AAD
//! length, 108 tail source length, 109 tail destination length, 112 tail
//! source address, 120 tail destination address.
//!
//! XTS fields: 68 key 1 id, 72 key 2 id, 76 tweak.
//!
//! # CQE layout ([`BULK_CQE_DWORDS`] dwords)
//!
//! | Offset | Field |
//! |---|---|
//! | 4 | GCM tag |
//! | 20 | GCM IV used |
//! | 44 | GCM tail bytes written |
//! | 48 | Service indicator (1 = approved) |
//! | 52 | Bytes written through the destination SGL |
//! | 60 | Error code |
//! | 62 | Bit 0 phase tag, bits 1-15 status code |

use crate::BULK_CQE_DWORDS;
use crate::BULK_SQE_DWORDS;

/// Owned bulk submission entry.
pub type RawBulkSqe = [u32; BULK_SQE_DWORDS];

/// Owned bulk completion entry.
pub type RawBulkCqe = [u32; BULK_CQE_DWORDS];

/// AES block length; SGL data lengths must be a multiple of it.
pub const BLOCK_LEN: u32 = 16;

/// Alignment of the padded GCM AAD region at the start of the source data.
pub const GCM_AAD_ALIGN: u32 = 32;

/// AES-GCM tag length.
pub const GCM_TAG_LEN: usize = 16;

/// AES-GCM IV length.
pub const GCM_IV_LEN: usize = 12;

/// AES-XTS tweak length.
pub const XTS_TWEAK_LEN: usize = 16;

const CMD_TYPE_AES: u16 = 5;
const FRAME_TYPE_AES: u8 = 1;
const SGL_TYPE_DATA_BLOCK: u8 = 0x0;

const ATTR_DECRYPT: u16 = 1 << 0;
const ATTR_SGL: u16 = 1 << 2;
const ATTR_CMD_TYPE_SHIFT: u16 = 3;
const ATTR_XTS: u16 = 1 << 8;
const ATTR_DUL_SHIFT: u16 = 14;

const SQE_ATTR: usize = 4;
const SQE_CID: usize = 6;
const SQE_SESSION_ID: usize = 8;
const SQE_APP_ID: usize = 10;
const SQE_SRC_LEN: usize = 24;
const SQE_SRC_SGL: usize = 28;
const SQE_DST_LEN: usize = 44;
const SQE_DST_SGL: usize = 48;
const SQE_FRAME_TYPE: usize = 64;
const SGL_LEN_OFF: usize = 8;
const SGL_TYPE_OFF: usize = 15;

const SQE_GCM_KEY_ID: usize = 68;
const SQE_GCM_AAD_LEN: usize = 72;
const SQE_GCM_TAG: usize = 76;
const SQE_GCM_IV: usize = 92;
const SQE_GCM_ALIGNED_AAD_LEN: usize = 104;
const SQE_GCM_TAIL_LEN: usize = 108;
const SQE_GCM_TAIL_SRC: usize = 112;
const SQE_GCM_TAIL_DST: usize = 120;

const SQE_XTS_KEY_ID1: usize = 68;
const SQE_XTS_KEY_ID2: usize = 72;
const SQE_XTS_TWEAK: usize = 76;

const CQE_TAG: usize = 4;
const CQE_IV: usize = 20;
const CQE_TAIL_LEN: usize = 44;
const CQE_SERVICE_INDICATOR: usize = 48;
const CQE_DATA_LEN: usize = 52;
const CQE_ERR: usize = 60;
const CQE_PHASE_STS: usize = 62;

/// Operation direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkDir {
    /// Encrypt.
    Encrypt,
    /// Decrypt.
    Decrypt,
}

/// AES-XTS data unit length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XtsDul {
    /// The whole transfer is one data unit.
    Full,
    /// 512-byte data units.
    B512,
    /// 4096-byte data units.
    B4096,
    /// 8192-byte data units.
    B8192,
}

impl XtsDul {
    fn raw(self) -> u16 {
        match self {
            Self::Full => 0,
            Self::B512 => 1,
            Self::B4096 => 2,
            Self::B8192 => 3,
        }
    }
}

/// GCM text tail (at most 15 bytes) carried outside the SGL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcmTail {
    /// Tail length, 1..=15.
    pub len: u8,
    /// Address of the input tail.
    pub src: u64,
    /// Address the output tail is written to.
    pub dst: u64,
}

/// AES-GCM command fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcmParams {
    /// Bulk key id.
    pub key_id: u32,
    /// AAD length without padding.
    pub aad_len: u32,
    /// Length of the zero-padded AAD region at the start of the source
    /// data (multiple of [`GCM_AAD_ALIGN`]).
    pub aligned_aad_len: u32,
    /// Expected tag (decrypt).
    pub tag: [u8; GCM_TAG_LEN],
    /// IV.
    pub iv: [u8; GCM_IV_LEN],
    /// Text tail outside the SGL, if any.
    pub tail: Option<GcmTail>,
}

/// AES-XTS command fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XtsParams {
    /// Data unit length.
    pub dul: XtsDul,
    /// Key 1 (data key) bulk id.
    pub key_id1: u32,
    /// Key 2 (tweak key) bulk id.
    pub key_id2: u32,
    /// Initial tweak.
    pub tweak: [u8; XTS_TWEAK_LEN],
}

/// Cipher-specific fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkParams {
    /// AES-GCM.
    Gcm(GcmParams),
    /// AES-XTS.
    Xts(XtsParams),
}

/// A bulk submission entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BulkSqe {
    /// Direction.
    pub dir: BulkDir,
    /// Command id.
    pub cid: u16,
    /// Session id.
    pub session_id: u16,
    /// Short app id.
    pub short_app_id: u8,
    /// Source data length.
    pub src_len: u32,
    /// Source address.
    pub src_addr: u64,
    /// Destination data length.
    pub dst_len: u32,
    /// Destination address.
    pub dst_addr: u64,
    /// Cipher-specific fields.
    pub params: BulkParams,
}

impl BulkSqe {
    fn attr(&self) -> u16 {
        let mut attr = ATTR_SGL | (CMD_TYPE_AES << ATTR_CMD_TYPE_SHIFT);
        if self.dir == BulkDir::Decrypt {
            attr |= ATTR_DECRYPT;
        }
        if let BulkParams::Xts(xts) = &self.params {
            attr |= ATTR_XTS | (xts.dul.raw() << ATTR_DUL_SHIFT);
        }
        attr
    }

    /// Encodes the submission entry, with a single SGL data-block
    /// descriptor per direction.
    pub fn encode(&self) -> RawBulkSqe {
        let mut e = [0u32; BULK_SQE_DWORDS];
        wr(&mut e, SQE_ATTR, &self.attr().to_le_bytes());
        wr(&mut e, SQE_CID, &self.cid.to_le_bytes());
        wr(&mut e, SQE_SESSION_ID, &self.session_id.to_le_bytes());
        wr(&mut e, SQE_APP_ID, &[self.short_app_id]);
        wr(&mut e, SQE_SRC_LEN, &self.src_len.to_le_bytes());
        encode_sgl(&mut e, SQE_SRC_SGL, self.src_addr, self.src_len);
        wr(&mut e, SQE_DST_LEN, &self.dst_len.to_le_bytes());
        encode_sgl(&mut e, SQE_DST_SGL, self.dst_addr, self.dst_len);
        wr(&mut e, SQE_FRAME_TYPE, &[FRAME_TYPE_AES]);

        match &self.params {
            BulkParams::Gcm(gcm) => {
                wr(&mut e, SQE_GCM_KEY_ID, &gcm.key_id.to_le_bytes());
                wr(&mut e, SQE_GCM_AAD_LEN, &gcm.aad_len.to_le_bytes());
                wr(&mut e, SQE_GCM_TAG, &gcm.tag);
                wr(&mut e, SQE_GCM_IV, &gcm.iv);
                wr(
                    &mut e,
                    SQE_GCM_ALIGNED_AAD_LEN,
                    &gcm.aligned_aad_len.to_le_bytes(),
                );
                if let Some(tail) = &gcm.tail {
                    wr(&mut e, SQE_GCM_TAIL_LEN, &[tail.len, tail.len]);
                    wr(&mut e, SQE_GCM_TAIL_SRC, &tail.src.to_le_bytes());
                    wr(&mut e, SQE_GCM_TAIL_DST, &tail.dst.to_le_bytes());
                }
            }
            BulkParams::Xts(xts) => {
                wr(&mut e, SQE_XTS_KEY_ID1, &xts.key_id1.to_le_bytes());
                wr(&mut e, SQE_XTS_KEY_ID2, &xts.key_id2.to_le_bytes());
                wr(&mut e, SQE_XTS_TWEAK, &xts.tweak);
            }
        }
        e
    }
}

/// Decoded fields of a [`RawBulkCqe`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BulkCqe {
    /// GCM tag (encrypt output).
    pub tag: [u8; GCM_TAG_LEN],
    /// GCM IV used for the operation.
    pub iv: [u8; GCM_IV_LEN],
    /// GCM tail bytes written to the tail destination.
    pub tail_len: u32,
    /// Whether an approved service was used.
    pub fips_approved: bool,
    /// Bytes written through the destination SGL.
    pub data_len: u32,
    /// Status code; 0 = success.
    pub sts: u16,
    /// Command-specific error code; 0 = success.
    pub err: u16,
}

impl BulkCqe {
    /// Decodes `c`.
    pub fn decode(c: &RawBulkCqe) -> Self {
        Self {
            tag: rd_arr(c, CQE_TAG),
            iv: rd_arr(c, CQE_IV),
            tail_len: rd_u32(c, CQE_TAIL_LEN),
            fips_approved: rd_u32(c, CQE_SERVICE_INDICATOR) != 0,
            data_len: rd_u32(c, CQE_DATA_LEN),
            sts: rd_u16(c, CQE_PHASE_STS) >> 1,
            err: rd_u16(c, CQE_ERR),
        }
    }

    /// Whether the CQE reports success.
    pub fn is_success(&self) -> bool {
        self.sts == 0 && self.err == 0
    }
}

fn encode_sgl(e: &mut RawBulkSqe, off: usize, addr: u64, len: u32) {
    wr(e, off, &addr.to_le_bytes());
    wr(e, off + SGL_LEN_OFF, &len.to_le_bytes());
    wr(e, off + SGL_TYPE_OFF, &[SGL_TYPE_DATA_BLOCK << 4]);
}

fn rd_u8<const N: usize>(d: &[u32; N], off: usize) -> u8 {
    (d[off / 4] >> (8 * (off % 4))) as u8
}

fn rd_u16<const N: usize>(d: &[u32; N], off: usize) -> u16 {
    u16::from(rd_u8(d, off)) | (u16::from(rd_u8(d, off + 1)) << 8)
}

fn rd_u32<const N: usize>(d: &[u32; N], off: usize) -> u32 {
    u32::from(rd_u16(d, off)) | (u32::from(rd_u16(d, off + 2)) << 16)
}

fn rd_arr<const N: usize, const M: usize>(d: &[u32; N], off: usize) -> [u8; M] {
    core::array::from_fn(|i| rd_u8(d, off + i))
}

fn wr<const N: usize>(d: &mut [u32; N], off: usize, v: &[u8]) {
    for (i, &b) in v.iter().enumerate() {
        let (w, sh) = ((off + i) / 4, 8 * ((off + i) % 4));
        d[w] = (d[w] & !(0xFF << sh)) | (u32::from(b) << sh);
    }
}
