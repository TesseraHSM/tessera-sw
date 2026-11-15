// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `GetCertificate` command handler.
//!
//! Out-of-session command — the TBOR analogue of MBOR `GetCertificate`.
//! Returns a single DER-encoded X.509 certificate from the caller's
//! partition at the requested `(slot_id, cert_id)`.  No session is
//! required; the PAL resolves the chain from the caller's bound IO
//! context, mirroring the MBOR handler.
//!
//! The certificate is written to out-of-band item `0`, whose length is a
//! capacity; the response carries the written length.  The handler queries
//! the certificate size, allocates a DMA buffer for it, has the PAL fill
//! it, and sends it to the host.  Slot 2 instead generates one fresh
//! certificate.  The handler is `async` because the underlying
//! [`HsmCertStore::get_cert`](tsra_fw_hsm_pal_traits::HsmCertStore::get_cert)
//! is async.

use tsra_fw_ddi_tbor_types::tbor_int::U16;
use tsra_fw_ddi_tbor_types::TborGetCertReq;
use tsra_fw_ddi_tbor_types::TborGetCertResp;
use tsra_fw_ddi_tbor_types::CERT_MAX_LEN;
use tsra_fw_ddi_tbor_types::CERT_OOB_INDEX;
use tsra_fw_hsm_pal_traits::HsmCertBank;
use tsra_fw_hsm_pal_traits::HsmCertSlot;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;

/// Handle a TBOR `GetCertificate` request.
///
/// Slot 2 generates one fresh PTA-issued PID certificate from the
/// partition's PTA/PID keys; only the bank matching the PTA algorithm
/// (ECC for a P-384 PTA, ML-DSA for an ML-DSA-87 PTA) is available. No undo
/// log is needed.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let req = TborGetCertReq::decode(cmd_buf.request())?;
    let slot = HsmCertSlot(req.slot_id());
    let bank = HsmCertBank(req.bank());
    let cert_id = req.cert_id();

    let cert: &HsmDmaBuf = if slot == HsmCertSlot::PartOwner {
        if cert_id != 0 {
            return Err(HsmError::InvalidArg);
        }
        super::pta::pid_certificate(pal, io, bank).await?
    } else {
        // Query the certificate size (no copy).
        let len = pal.get_cert(io, slot, bank, cert_id, None).await?;

        // A provisioned certificate that overflows the wire bound is an
        // internal provisioning invariant violation, not a caller-input
        // error.
        if len > CERT_MAX_LEN {
            return Err(HsmError::InternalError);
        }

        let buf = pal.dma_alloc(io, len)?;
        let actual = pal.get_cert(io, slot, bank, cert_id, Some(buf)).await?;
        if actual > len {
            return Err(HsmError::InternalError);
        }
        &buf[..actual]
    };

    let cert_len = u16::try_from(cert.len()).map_err(|_| HsmError::InternalError)?;
    pal.send_oob_bounded(io, CERT_OOB_INDEX, cert).await?;

    cmd_buf.encode_response(|buf| {
        let frame = TborGetCertResp::encode(buf, 0, false)?
            .cert_len(U16::new(cert_len))?
            .finish();
        Ok(frame.as_bytes().len())
    })
}
