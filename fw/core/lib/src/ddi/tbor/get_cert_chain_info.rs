// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetCertChainInfo` command handler.
//!
//! Out-of-session info command — the TBOR analogue of MBOR
//! `GetCertChainInfo`.  Returns the number of certificates and the
//! leaf-certificate SHA-256 thumbprint for the caller's partition at the
//! requested chain slot.  No session is required; the chain is read for
//! the caller's own bound partition, resolved internally by the PAL,
//! mirroring the MBOR handler.
//!
//! The handler is `async` because the underlying
//! [`HsmCertStore::get_cert_chain_info`](tsra_fw_hsm_pal_traits::HsmCertStore::get_cert_chain_info)
//! is async.

use tsra_fw_ddi_tbor_types::TborGetCertChainInfoReq;
use tsra_fw_ddi_tbor_types::TborGetCertChainInfoResp;
use tsra_fw_hsm_pal_traits::HsmCertBank;
use tsra_fw_hsm_pal_traits::HsmCertSlot;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;

/// Handle a TBOR `GetCertChainInfo` request.
///
/// Slot 2 generates a fresh PID leaf and fingerprints it; because each read
/// mints a new leaf, later reads need not match this fingerprint. No undo
/// log is needed.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let req = TborGetCertChainInfoReq::decode(cmd_buf.request())?;
    let slot = HsmCertSlot(req.slot_id());

    let info = if slot == HsmCertSlot::PartOwner {
        super::pta::chain_info(pal, io).await?
    } else {
        pal.get_cert_chain_info(io, slot, HsmCertBank::Ecc).await?
    };

    let resp = cmd_buf.encode_response(|buf| {
        let frame = TborGetCertChainInfoResp::encode(buf, 0, false)?
            .num_certs(info.count)?
            .thumbprint(&info.thumbprint)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;
    Ok(resp)
}
