// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Duo command transport.
//!
//! [`DuoOp::Tbor`] requests and responses travel in plaintext over the
//! SQE's PRP pair. [`DuoOp::TborSecure`] ones are AES-256-GCM protected
//! under the SQE session's transport keys: the request with the VM→HSM key
//! (IV and tag in the SQE), the response with the HSM→VM key (a fresh IV
//! and the tag in the CQE).

use tsra_fw_hsm_io::duo::DuoCqeEntry;
use tsra_fw_hsm_io::duo::DuoOp;
use tsra_fw_hsm_io::duo::DuoSqeEntry;
use tsra_fw_hsm_io::validate_io_fields;
use tsra_fw_hsm_pal_traits::*;
use zeroize::Zeroizing;

use crate::StdHsmIo;
use crate::StdHsmPal;

/// Stamps a fresh CQE with the identity of its SQE.
pub(crate) fn stamp_cqe(sqe: &DuoSqeEntry) -> DuoCqeEntry {
    let mut cqe = DuoCqeEntry::default();
    cqe.view().set_cmd(sqe.view().cmd());
    cqe
}

/// Host address and byte length of the SQE's OOB descriptor array.
pub(crate) fn oob_region(sqe: &DuoSqeEntry) -> (HsmDmaAddr, u32) {
    let sqe = sqe.view();
    (sqe.oob_prp(), sqe.oob_len())
}

impl StdHsmPal {
    pub(crate) async fn transport_recv(
        &self,
        io: &StdHsmIo,
        sqe: &DuoSqeEntry,
    ) -> HsmResult<HsmRequest<'_>> {
        let view = sqe.view();
        validate_io_fields(
            view.src_len(),
            view.dst_len(),
            view.src_prp1(),
            view.dst_prp1(),
            view.oob_len(),
            view.oob_prp(),
        )?;
        self.transport_recv_payload(io, sqe).await
    }

    /// Fetches the request of a validated SQE, opening a protected one.
    pub(crate) async fn transport_recv_payload(
        &self,
        io: &StdHsmIo,
        sqe: &DuoSqeEntry,
    ) -> HsmResult<HsmRequest<'_>> {
        let sqe = sqe.view();
        let secure = sqe.op() == Ok(DuoOp::TborSecure);
        if secure && sqe.aad_len() != 0 {
            return Err(HsmError::InvalidArg);
        }
        let key = if secure {
            let id = HsmSessId::from(sqe.session_id());
            let key = self
                .session_transport_key(io, id, HsmSessionTransportDir::H2m)
                .map_err(|_| HsmError::SessionTransportError)?;
            let mut copy = Zeroizing::new([0u8; SESSION_TRANSPORT_KEY_LEN]);
            copy.copy_from_slice(key);
            Some(copy)
        } else {
            None
        };

        let len = sqe.src_len() as usize;
        let mut buf = self.dma_alloc_exchange(io, len.next_multiple_of(4))?;
        let data = &mut buf.buffer_mut()[..len];
        self.copy_mem_from_host(io, sqe.src_prp1(), sqe.src_prp2(), data, true)
            .await
            .map_err(|_| HsmError::FailedToStartDmaTransaction)?;
        if let Some(key) = key {
            let ciphertext = data.to_vec();
            self.aes
                .gcm_decrypt(&key[..], &sqe.iv(), None, &sqe.gcm_tag(), &ciphertext, data)
                .await
                .map_err(|_| HsmError::SessionTransportError)?;
        }
        Ok(HsmRequest {
            buf,
            len,
            resp_capacity: sqe.dst_len() as usize,
        })
    }

    pub(crate) async fn transport_send(
        &self,
        io: &mut StdHsmIo,
        sqe: DuoSqeEntry,
        resp: &HsmDmaBuf,
    ) -> HsmResult<()> {
        let sqe = sqe.view();
        if resp.len() > sqe.dst_len() as usize {
            return Err(HsmError::InvalidArg);
        }
        if sqe.op() != Ok(DuoOp::TborSecure) {
            return self
                .copy_mem_to_host(io, resp, sqe.dst_prp1(), sqe.dst_prp2(), true)
                .await
                .map_err(|_| HsmError::FailedToStartDmaTransaction);
        }

        let id = HsmSessId::from(sqe.session_id());
        let mut key = Zeroizing::new([0u8; SESSION_TRANSPORT_KEY_LEN]);
        key.copy_from_slice(
            self.session_transport_key(io, id, HsmSessionTransportDir::M2h)
                .map_err(|_| HsmError::SessionTransportError)?,
        );
        let mut iv = [0u8; SESSION_TRANSPORT_IV_LEN];
        let mut tag = [0u8; SESSION_TRANSPORT_TAG_LEN];
        self.rng_fill_bytes(io, &mut iv)?;
        let ciphertext = self.dma_alloc(io, resp.len())?;
        self.aes
            .gcm_encrypt(&key[..], &iv, None, resp, ciphertext, &mut tag)
            .await
            .map_err(|_| HsmError::SessionTransportError)?;
        self.copy_mem_to_host(io, ciphertext, sqe.dst_prp1(), sqe.dst_prp2(), true)
            .await
            .map_err(|_| HsmError::FailedToStartDmaTransaction)?;

        // Emulate the engine: it fills the protection fields of the
        // success CQE.
        if let crate::io::StdCqe::Cmd(cqe) = &mut io.cqe {
            let mut cqe = cqe.view();
            cqe.set_iv(&iv);
            cqe.set_tag(&tag);
        }
        Ok(())
    }
}
