// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bulk submission entry.
//!
//! Byte layout (little-endian):
//!
//! | Offset | Field |
//! |---|---|
//! | 0 | PASID (ignored) |
//! | 4 | Command attributes: bit 0 decrypt, bit 2 SGL, bits 3-5 command type, bit 8 XTS, bits 14-15 XTS data unit |
//! | 6 | Command id |
//! | 8 | Session id |
//! | 10 | Short app id |
//! | 24 | Source data length |
//! | 28 | Source SGL descriptor (address at 28) |
//! | 44 | Destination data length |
//! | 48 | Destination SGL descriptor (address at 48) |
//! | 64 | Frame type |
//! | 68.. | GCM or XTS fields (see [`GcmParams`] / [`XtsParams`]) |
//!
//! GCM fields: 68 key id, 72 AAD length, 76 tag, 92 IV, 104 padded AAD
//! length, 108 tail source length, 109 tail destination length, 112 tail
//! source address, 120 tail destination address.
//!
//! XTS fields: 68 key 1 id, 72 key 2 id, 76 tweak.
//!
//! SGL descriptors are not walked here: on Uno the bulk crypto engine
//! consumes them; the std platform supports only a single data-block
//! descriptor covering the whole buffer, which [`BulkSqe::encode`] emits.

use super::*;

const OFF_ATTR: usize = 4;
const OFF_CID: usize = 6;
const OFF_SESSION_ID: usize = 8;
const OFF_APP_ID: usize = 10;
const OFF_SRC_LEN: usize = 24;
const OFF_SRC_SGL: usize = 28;
const OFF_DST_LEN: usize = 44;
const OFF_DST_SGL: usize = 48;
const OFF_FRAME_TYPE: usize = 64;

const SGL_LEN_OFF: usize = 8;
const SGL_TYPE_OFF: usize = 15;
const SGL_TYPE_DATA_BLOCK: u8 = 0x0;

const OFF_GCM_KEY_ID: usize = 68;
const OFF_GCM_AAD_LEN: usize = 72;
const OFF_GCM_TAG: usize = 76;
const OFF_GCM_IV: usize = 92;
const OFF_GCM_ALIGNED_AAD_LEN: usize = 104;
const OFF_GCM_TAIL_SRC_LEN: usize = 108;
const OFF_GCM_TAIL_DST_LEN: usize = 109;
const OFF_GCM_TAIL_SRC: usize = 112;
const OFF_GCM_TAIL_DST: usize = 120;

const OFF_XTS_KEY_ID1: usize = 68;
const OFF_XTS_KEY_ID2: usize = 72;
const OFF_XTS_TWEAK: usize = 76;

const ATTR_DECRYPT: u16 = 1 << 0;
const ATTR_SGL: u16 = 1 << 2;
const ATTR_CMD_TYPE_SHIFT: u16 = 3;
const ATTR_CMD_TYPE_MASK: u16 = 0x7;
const ATTR_XTS: u16 = 1 << 8;
const ATTR_DUL_SHIFT: u16 = 14;

/// Returns DW1 (command attributes and command id) of a submission entry,
/// or zero if the entry is too short to hold it.
pub(crate) fn sqe_dw1(sqe: &HsmSqe) -> u32 {
    sqe.get(OFF_ATTR / 4).copied().unwrap_or(0)
}

/// Operation direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkDir {
    /// Encrypt.
    Encrypt,
    /// Decrypt.
    Decrypt,
}

/// Bulk cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkCipher {
    /// AES-GCM.
    Gcm,
    /// AES-XTS.
    Xts,
}

impl BulkCipher {
    /// Returns the cipher selected by command attributes `attr`.
    pub fn from_attr(attr: u16) -> Self {
        if attr & ATTR_XTS != 0 {
            Self::Xts
        } else {
            Self::Gcm
        }
    }
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
    fn from_raw(raw: u16) -> Self {
        match raw & 0x3 {
            0 => Self::Full,
            1 => Self::B512,
            2 => Self::B4096,
            _ => Self::B8192,
        }
    }

    fn raw(self) -> u16 {
        match self {
            Self::Full => 0,
            Self::B512 => 1,
            Self::B4096 => 2,
            Self::B8192 => 3,
        }
    }

    /// Returns the data unit length in bytes for a transfer of `total`.
    pub fn len(self, total: u32) -> u32 {
        match self {
            Self::Full => total,
            Self::B512 => 512,
            Self::B4096 => 4096,
            Self::B8192 => 8192,
        }
    }
}

/// GCM text tail (at most 15 bytes) carried outside the SGL.
///
/// The host keeps SGL lengths block-aligned and passes the final partial
/// block of text through one separate host buffer per direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcmTail {
    /// Tail length, 1..=15.
    pub len: u8,
    /// Host address of the input tail.
    pub src: u64,
    /// Host address the output tail is written to.
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
    /// data (multiple of 32).
    pub aligned_aad_len: u32,
    /// Expected tag (decrypt).
    pub tag: [u8; GCM_TAG_LEN],
    /// Host IV.
    pub iv: [u8; GCM_IV_LEN],
    /// Text tail outside the SGL, if any.
    pub tail: Option<GcmTail>,
}

impl GcmParams {
    /// Returns the SGL text length (after the AAD region) for source
    /// length `src_len`, excluding the tail.
    pub fn sgl_text_len(&self, src_len: u32) -> u32 {
        src_len.saturating_sub(self.aligned_aad_len)
    }

    /// Returns the total text length for source length `src_len`,
    /// including the tail.
    pub fn text_len(&self, src_len: u32) -> u32 {
        self.sgl_text_len(src_len) + self.tail.map_or(0, |t| u32::from(t.len))
    }
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

/// A parsed and validated bulk submission entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BulkSqe {
    /// Direction.
    pub dir: BulkDir,
    /// Host command id.
    pub cid: u16,
    /// Session id.
    pub session_id: u16,
    /// Short app id.
    pub short_app_id: u8,
    /// Source data length.
    pub src_len: u32,
    /// Source address (from the source SGL descriptor).
    pub src_addr: u64,
    /// Destination data length (equal to `src_len`).
    pub dst_len: u32,
    /// Destination address (from the destination SGL descriptor).
    pub dst_addr: u64,
    /// Cipher-specific fields.
    pub params: BulkParams,
}

impl BulkSqe {
    /// Returns the cipher.
    pub fn cipher(&self) -> BulkCipher {
        match self.params {
            BulkParams::Gcm(_) => BulkCipher::Gcm,
            BulkParams::Xts(_) => BulkCipher::Xts,
        }
    }

    /// Returns the encoded command attributes.
    pub fn attr(&self) -> u16 {
        let mut attr = ATTR_SGL | (u16::from(CMD_TYPE_AES) << ATTR_CMD_TYPE_SHIFT);
        if self.dir == BulkDir::Decrypt {
            attr |= ATTR_DECRYPT;
        }
        if let BulkParams::Xts(xts) = &self.params {
            attr |= ATTR_XTS | (xts.dul.raw() << ATTR_DUL_SHIFT);
        }
        attr
    }

    /// Parses and validates a submission entry in place.
    ///
    /// Checks the command and frame types, SGL-only data pointers, data
    /// lengths (block-aligned, at most [`MAX_DATA_LEN`], source equal to
    /// destination), the GCM AAD region and tail, and the XTS data unit.
    /// Keys, sessions and the partition are left to the caller.
    ///
    /// # Returns
    ///
    /// - `Err(HsmError::UnsupportedCmd)` — not a [`BULK_SQE_DWORDS`]-dword
    ///   entry, wrong command / frame type, or PRP data pointers.
    /// - `Err(HsmError::AesGcmInvalidBufferSize)` — invalid GCM lengths,
    ///   AAD region or tail.
    /// - `Err(HsmError::AesXtsInvalidBufferSize)` — invalid XTS lengths.
    /// - `Err(HsmError::AesXtsInvalidDul)` — length not a multiple of the
    ///   XTS data unit.
    pub fn parse(sqe: &HsmSqe) -> HsmResult<Self> {
        let entry: &RawBulkSqe = sqe.try_into().map_err(|_| HsmError::UnsupportedCmd)?;
        let attr = rd_u16(entry, OFF_ATTR);
        if (attr >> ATTR_CMD_TYPE_SHIFT) & ATTR_CMD_TYPE_MASK != u16::from(CMD_TYPE_AES)
            || attr & ATTR_SGL == 0
            || rd_u8(entry, OFF_FRAME_TYPE) != FRAME_TYPE_AES
        {
            Err(HsmError::UnsupportedCmd)?;
        }

        let dir = if attr & ATTR_DECRYPT != 0 {
            BulkDir::Decrypt
        } else {
            BulkDir::Encrypt
        };
        let cipher = BulkCipher::from_attr(attr);
        let len_err = match cipher {
            BulkCipher::Gcm => HsmError::AesGcmInvalidBufferSize,
            BulkCipher::Xts => HsmError::AesXtsInvalidBufferSize,
        };

        let src_len = rd_u32(entry, OFF_SRC_LEN);
        let dst_len = rd_u32(entry, OFF_DST_LEN);
        if src_len != dst_len || src_len > MAX_DATA_LEN || !src_len.is_multiple_of(BLOCK_LEN) {
            Err(len_err)?;
        }

        let params = match cipher {
            BulkCipher::Gcm => BulkParams::Gcm(Self::parse_gcm(entry, src_len)?),
            BulkCipher::Xts => BulkParams::Xts(Self::parse_xts(entry, attr, src_len)?),
        };

        Ok(Self {
            dir,
            cid: rd_u16(entry, OFF_CID),
            session_id: rd_u16(entry, OFF_SESSION_ID),
            short_app_id: rd_u8(entry, OFF_APP_ID),
            src_len,
            src_addr: rd_u64(entry, OFF_SRC_SGL),
            dst_len,
            dst_addr: rd_u64(entry, OFF_DST_SGL),
            params,
        })
    }

    fn parse_gcm(entry: &RawBulkSqe, src_len: u32) -> HsmResult<GcmParams> {
        let aad_len = rd_u32(entry, OFF_GCM_AAD_LEN);
        let aligned_aad_len = rd_u32(entry, OFF_GCM_ALIGNED_AAD_LEN);
        if !aligned_aad_len.is_multiple_of(GCM_AAD_ALIGN)
            || aligned_aad_len > src_len
            || aad_len > aligned_aad_len
        {
            Err(HsmError::AesGcmInvalidBufferSize)?;
        }

        let tail_len = rd_u8(entry, OFF_GCM_TAIL_SRC_LEN);
        if tail_len != rd_u8(entry, OFF_GCM_TAIL_DST_LEN) || tail_len > GCM_MAX_TAIL_LEN {
            Err(HsmError::AesGcmInvalidBufferSize)?;
        }
        let tail = if tail_len == 0 {
            None
        } else {
            let src = rd_u64(entry, OFF_GCM_TAIL_SRC);
            let dst = rd_u64(entry, OFF_GCM_TAIL_DST);
            if src == 0 || dst == 0 {
                Err(HsmError::AesGcmInvalidBufferSize)?;
            }
            Some(GcmTail {
                len: tail_len,
                src,
                dst,
            })
        };

        Ok(GcmParams {
            key_id: rd_u32(entry, OFF_GCM_KEY_ID),
            aad_len,
            aligned_aad_len,
            tag: rd_arr(entry, OFF_GCM_TAG),
            iv: rd_arr(entry, OFF_GCM_IV),
            tail,
        })
    }

    fn parse_xts(entry: &RawBulkSqe, attr: u16, src_len: u32) -> HsmResult<XtsParams> {
        if src_len == 0 {
            Err(HsmError::AesXtsInvalidBufferSize)?;
        }
        let dul = XtsDul::from_raw(attr >> ATTR_DUL_SHIFT);
        if !src_len.is_multiple_of(dul.len(src_len)) {
            Err(HsmError::AesXtsInvalidDul)?;
        }
        Ok(XtsParams {
            dul,
            key_id1: rd_u32(entry, OFF_XTS_KEY_ID1),
            key_id2: rd_u32(entry, OFF_XTS_KEY_ID2),
            tweak: rd_arr(entry, OFF_XTS_TWEAK),
        })
    }

    /// Encodes the submission entry.
    pub fn encode(&self) -> RawBulkSqe {
        let mut e = [0u32; BULK_SQE_DWORDS];
        wr(&mut e, OFF_ATTR, &self.attr().to_le_bytes());
        wr(&mut e, OFF_CID, &self.cid.to_le_bytes());
        wr(&mut e, OFF_SESSION_ID, &self.session_id.to_le_bytes());
        wr(&mut e, OFF_APP_ID, &[self.short_app_id]);
        wr(&mut e, OFF_SRC_LEN, &self.src_len.to_le_bytes());
        Self::encode_sgl(&mut e, OFF_SRC_SGL, self.src_addr, self.src_len);
        wr(&mut e, OFF_DST_LEN, &self.dst_len.to_le_bytes());
        Self::encode_sgl(&mut e, OFF_DST_SGL, self.dst_addr, self.dst_len);
        wr(&mut e, OFF_FRAME_TYPE, &[FRAME_TYPE_AES]);

        match &self.params {
            BulkParams::Gcm(gcm) => {
                wr(&mut e, OFF_GCM_KEY_ID, &gcm.key_id.to_le_bytes());
                wr(&mut e, OFF_GCM_AAD_LEN, &gcm.aad_len.to_le_bytes());
                wr(&mut e, OFF_GCM_TAG, &gcm.tag);
                wr(&mut e, OFF_GCM_IV, &gcm.iv);
                wr(
                    &mut e,
                    OFF_GCM_ALIGNED_AAD_LEN,
                    &gcm.aligned_aad_len.to_le_bytes(),
                );
                if let Some(tail) = &gcm.tail {
                    wr(&mut e, OFF_GCM_TAIL_SRC_LEN, &[tail.len, tail.len]);
                    wr(&mut e, OFF_GCM_TAIL_SRC, &tail.src.to_le_bytes());
                    wr(&mut e, OFF_GCM_TAIL_DST, &tail.dst.to_le_bytes());
                }
            }
            BulkParams::Xts(xts) => {
                wr(&mut e, OFF_XTS_KEY_ID1, &xts.key_id1.to_le_bytes());
                wr(&mut e, OFF_XTS_KEY_ID2, &xts.key_id2.to_le_bytes());
                wr(&mut e, OFF_XTS_TWEAK, &xts.tweak);
            }
        }
        e
    }

    fn encode_sgl(e: &mut RawBulkSqe, off: usize, addr: u64, len: u32) {
        wr(e, off, &addr.to_le_bytes());
        wr(e, off + SGL_LEN_OFF, &len.to_le_bytes());
        wr(e, off + SGL_TYPE_OFF, &[SGL_TYPE_DATA_BLOCK << 4]);
    }
}
