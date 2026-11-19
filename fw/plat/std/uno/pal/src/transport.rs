// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Uno command transport: plaintext requests and responses over the SQE's
//! PRP pair.

use tsra_fw_hsm_io::validate_io_fields;
use tsra_fw_hsm_io::CqeEntry;
use tsra_fw_hsm_io::SqeEntry;
use tsra_fw_hsm_pal_traits::*;

use crate::StdHsmIo;
use crate::StdHsmPal;

/// Stamps a fresh CQE with the identity of its SQE.
pub(crate) fn stamp_cqe(sqe: &SqeEntry) -> CqeEntry {
    let mut cqe = CqeEntry::default();
    cqe.view().set_cmd_id(sqe.view().cmd_id());
    cqe
}

/// Host address and byte length of the SQE's OOB descriptor array.
pub(crate) fn oob_region(sqe: &SqeEntry) -> (HsmDmaAddr, u32) {
    let sqe = sqe.view();
    (sqe.oob_prp(), sqe.oob_len())
}

impl StdHsmPal {
    pub(crate) async fn transport_recv(
        &self,
        io: &StdHsmIo,
        sqe: &SqeEntry,
    ) -> HsmResult<HsmRequest<'_>> {
        let sqe = sqe.view();
        if sqe.cmd().psdt() != 0 {
            return Err(HsmError::SqeInvalidPsdt);
        }
        validate_io_fields(
            sqe.src_len(),
            sqe.dst_len(),
            sqe.src_prp1(),
            sqe.dst_prp1(),
            sqe.oob_len(),
            sqe.oob_prp(),
        )?;
        let len = sqe.src_len() as usize;
        let mut buf = self.dma_alloc_exchange(io, len.next_multiple_of(4))?;
        self.copy_mem_from_host(
            io,
            sqe.src_prp1(),
            sqe.src_prp2(),
            &mut buf.buffer_mut()[..len],
            true,
        )
        .await
        .map_err(|_| HsmError::FailedToStartDmaTransaction)?;
        Ok(HsmRequest {
            buf,
            len,
            resp_capacity: sqe.dst_len() as usize,
        })
    }

    pub(crate) async fn transport_send(
        &self,
        io: &mut StdHsmIo,
        sqe: SqeEntry,
        resp: &HsmDmaBuf,
    ) -> HsmResult<()> {
        let sqe = sqe.view();
        if resp.len() > sqe.dst_len() as usize {
            return Err(HsmError::InvalidArg);
        }
        self.copy_mem_to_host(io, resp, sqe.dst_prp1(), sqe.dst_prp2(), true)
            .await
            .map_err(|_| HsmError::FailedToStartDmaTransaction)
    }
}
