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
//! Uses the reserve-then-fill pattern: query the certificate size first,
//! reserve the response `certificate` slot sized to it, then have the PAL
//! copy the DER bytes straight into the reserved slice — no scratch buffer
//! and no copy. Slot 2 instead generates one fresh certificate and copies
//! it into the response. The handler is `async` because the underlying
//! [`HsmCertStore::get_cert`](tsra_fw_hsm_pal_traits::HsmCertStore::get_cert)
//! is async.

use tsra_fw_ddi_tbor_types::TborGetCertReq;
use tsra_fw_ddi_tbor_types::TborGetCertResp;
use tsra_fw_ddi_tbor_types::CERT_MAX_LEN;
use tsra_fw_hsm_pal_traits::HsmCertBank;
use tsra_fw_hsm_pal_traits::HsmCertSlot;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;

/// Handle a TBOR `GetCertificate` request.
///
/// Slot 2 generates one fresh PTA-issued PID certificate from the
/// partition's PTA/PID keys and copies it into the response. No undo log is
/// needed.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    let req = TborGetCertReq::decode(cmd_buf.request())?;
    let slot = HsmCertSlot(req.slot_id());
    let cert_id = req.cert_id();

    if slot == HsmCertSlot::PartOwner {
        if cert_id != 0 {
            return Err(HsmError::InvalidArg);
        }
        let cert = super::pta::pid_certificate(pal, io).await?;
        let resp = cmd_buf.encode_response(|buf| {
            let frame = TborGetCertResp::encode(buf, 0, false)?
                .certificate(cert)?
                .finish();
            Ok(frame.as_bytes().len())
        })?;
        return Ok(resp);
    }

    // Query the certificate size (no copy).
    let len = pal
        .get_cert(io, slot, HsmCertBank::Ecc, cert_id, None)
        .await?;

    // A provisioned certificate that overflows the wire bound is an
    // internal provisioning invariant violation, not a caller-input error.
    if len > CERT_MAX_LEN {
        return Err(HsmError::InternalError);
    }

    // Build the response with the `certificate` slot reserved (sized but
    // unwritten), then have the PAL copy the DER bytes straight into the
    // reserved slot — no scratch buffer and no copy.
    let resp = cmd_buf.encode_response(|buf| {
        let frame = TborGetCertResp::encode(buf, 0, false)?
            .certificate_reserve(len)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    // `decode_mut` hands out a `&mut` view into the reserved slot; the view
    // is scoped so its borrow of `resp` ends before `resp` is returned.
    {
        let out = TborGetCertResp::decode_mut(&mut cmd_buf.buffer_mut()[..resp])?;
        let actual = pal
            .get_cert(io, slot, HsmCertBank::Ecc, cert_id, Some(out.certificate))
            .await?;
        if actual != len {
            return Err(HsmError::InternalError);
        }
    }

    Ok(resp)
}
