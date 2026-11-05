// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bulk completion entry.
//!
//! Byte layout (little-endian):
//!
//! | Offset | Field |
//! |---|---|
//! | 0 | Command attributes (echoed from the SQE) |
//! | 2 | Command id (echoed from the SQE) |
//! | 4 | GCM tag (zero for XTS) |
//! | 20 | GCM IV used (zero for XTS) |
//! | 32 | Reserved |
//! | 44 | GCM tail bytes written to the tail destination |
//! | 48 | Service indicator (1 = approved) |
//! | 52 | Bytes written through the destination SGL |
//! | 56 | SQ head (filled by hardware) |
//! | 58 | SQ id |
//! | 60 | Error code |
//! | 62 | Bit 0 phase tag (filled by hardware), bits 1-15 status code |

use super::*;

const OFF_ATTR: usize = 0;
const OFF_CID: usize = 2;
const OFF_TAG: usize = 4;
const OFF_IV: usize = 20;
const OFF_TAIL_LEN: usize = 44;
const OFF_SERVICE_INDICATOR: usize = 48;
const OFF_DATA_LEN: usize = 52;
const OFF_SQ_HEAD: usize = 56;
const OFF_SQ_ID: usize = 58;
const OFF_ERR: usize = 60;
const OFF_PHASE_STS: usize = 62;

/// A bulk completion entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BulkCqe {
    /// Command attributes of the completed SQE.
    pub attr: u16,
    /// Command id of the completed SQE.
    pub cid: u16,
    /// GCM tag (encrypt output).
    pub tag: [u8; GCM_TAG_LEN],
    /// GCM IV used for the operation.
    pub iv: [u8; GCM_IV_LEN],
    /// GCM tail bytes written to the tail destination.
    pub tail_len: u32,
    /// Service indicator: whether an approved service was used.
    pub fips_approved: bool,
    /// Bytes written through the destination SGL.
    pub data_len: u32,
    /// SQ head (hardware-owned; zero when built by firmware).
    pub sq_head: u16,
    /// SQ id.
    pub sq_id: u16,
    /// Status.
    pub status: BulkStatus,
    /// Phase tag (hardware-owned; false when built by firmware).
    pub phase: bool,
}

impl BulkCqe {
    /// Returns a success CQE for `sqe` on queue `sq_id`.
    ///
    /// The data and tail lengths cover the whole request; the tag, IV and
    /// service indicator are left for the caller to fill.
    pub fn success(sqe: &BulkSqe, sq_id: u16) -> Self {
        let tail_len = match &sqe.params {
            BulkParams::Gcm(gcm) => gcm.tail.map_or(0, |t| u32::from(t.len)),
            BulkParams::Xts(_) => 0,
        };
        Self {
            attr: sqe.attr(),
            cid: sqe.cid,
            tag: [0; GCM_TAG_LEN],
            iv: [0; GCM_IV_LEN],
            tail_len,
            fips_approved: false,
            data_len: sqe.dst_len,
            sq_head: 0,
            sq_id,
            status: BulkStatus::SUCCESS,
            phase: false,
        }
    }

    /// Returns the failure CQE of an IO.
    ///
    /// The command attributes and id are echoed from the raw SQE, so this
    /// works for entries [`BulkSqe::parse`] rejects (zero if the entry is
    /// too short to hold them).
    ///
    /// # Parameters
    ///
    /// - `sqe` — the IO's submission entry.
    /// - `sq_id` — the queue the IO came from.
    /// - `err` — the error the IO failed with.
    pub fn error(sqe: &HsmSqe, sq_id: u16, err: HsmError) -> Self {
        let dw1 = sqe_dw1(sqe);
        let attr = dw1 as u16;
        Self {
            attr,
            cid: (dw1 >> 16) as u16,
            tag: [0; GCM_TAG_LEN],
            iv: [0; GCM_IV_LEN],
            tail_len: 0,
            fips_approved: false,
            data_len: 0,
            sq_head: 0,
            sq_id,
            status: BulkStatus::from_error(BulkCipher::from_attr(attr), err),
            phase: false,
        }
    }

    /// Encodes the CQE.
    pub fn encode(&self) -> RawBulkCqe {
        let mut c = [0u32; BULK_CQE_DWORDS];
        wr(&mut c, OFF_ATTR, &self.attr.to_le_bytes());
        wr(&mut c, OFF_CID, &self.cid.to_le_bytes());
        wr(&mut c, OFF_TAG, &self.tag);
        wr(&mut c, OFF_IV, &self.iv);
        wr(&mut c, OFF_TAIL_LEN, &self.tail_len.to_le_bytes());
        wr(
            &mut c,
            OFF_SERVICE_INDICATOR,
            &u32::from(self.fips_approved).to_le_bytes(),
        );
        wr(&mut c, OFF_DATA_LEN, &self.data_len.to_le_bytes());
        wr(&mut c, OFF_SQ_HEAD, &self.sq_head.to_le_bytes());
        wr(&mut c, OFF_SQ_ID, &self.sq_id.to_le_bytes());
        wr(&mut c, OFF_ERR, &self.status.err.to_le_bytes());
        let phase_sts = (self.status.sts << 1) | u16::from(self.phase);
        wr(&mut c, OFF_PHASE_STS, &phase_sts.to_le_bytes());
        c
    }

    /// Writes the CQE into an IO's completion entry.
    ///
    /// # Returns
    ///
    /// - `Err(HsmError::InternalError)` — `cqe` is not a
    ///   [`BULK_CQE_DWORDS`]-dword entry.
    pub fn write(&self, cqe: &mut HsmCqe) -> HsmResult<()> {
        let cqe: &mut RawBulkCqe = cqe.try_into().map_err(|_| HsmError::InternalError)?;
        *cqe = self.encode();
        Ok(())
    }

    /// Sets the SQ id of an encoded CQE.
    ///
    /// The queue owner stamps it when posting, as for command CQEs.
    pub fn set_sq_id(cqe: &mut RawBulkCqe, sq_id: u16) {
        wr(cqe, OFF_SQ_ID, &sq_id.to_le_bytes());
    }

    /// Decodes a CQE.
    pub fn decode(c: &RawBulkCqe) -> Self {
        let phase_sts = rd_u16(c, OFF_PHASE_STS);
        Self {
            attr: rd_u16(c, OFF_ATTR),
            cid: rd_u16(c, OFF_CID),
            tag: rd_arr(c, OFF_TAG),
            iv: rd_arr(c, OFF_IV),
            tail_len: rd_u32(c, OFF_TAIL_LEN),
            fips_approved: rd_u32(c, OFF_SERVICE_INDICATOR) != 0,
            data_len: rd_u32(c, OFF_DATA_LEN),
            sq_head: rd_u16(c, OFF_SQ_HEAD),
            sq_id: rd_u16(c, OFF_SQ_ID),
            status: BulkStatus {
                sts: phase_sts >> 1,
                err: rd_u16(c, OFF_ERR),
            },
            phase: phase_sts & 1 != 0,
        }
    }
}
