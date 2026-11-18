// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `ApiRev` command handler.
//!
//! `ApiRev` is the bootstrap TBOR command: it advertises the inclusive
//! range of SDK API revisions this platform supports. The wire schema
//! lives in [`tsra_fw_ddi_tbor_types::api_rev`] — the request body is
//! empty (the derive emits a synthetic `none` placeholder TOC entry), and
//! the response carries `(min_major, min_minor, max_major, max_minor)`.
//!
//! The range comes from the platform ([`HsmPalFeatures::API_REV_MIN`] /
//! [`HsmPalFeatures::API_REV_MAX`]) rather than a core feature, so a build that
//! unifies the `uno` and `duo` core features still reports each
//! platform's own range.

use tsra_fw_ddi_tbor_types::tbor_int::U16;
use tsra_fw_ddi_tbor_types::TborApiRevReq;
use tsra_fw_ddi_tbor_types::TborApiRevResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmPalFeatures;
use tsra_fw_hsm_pal_traits::HsmResult;

/// Handle a TBOR `ApiRev` request.
///
/// The caller (`dispatch`) has already structurally validated the
/// buffer via `RequestView::parse` and confirmed the opcode is
/// `API_REV`. This handler validates the typed request and encodes the
/// platform's API revision range.
pub(crate) fn handle<P: HsmPalFeatures>(cmd_buf: &mut HsmCmdBuf<'_>) -> HsmResult<usize> {
    TborApiRevReq::decode(cmd_buf.request())?;
    let frame = TborApiRevResp::encode(cmd_buf.buffer_mut(), 0, false)?
        .min_major(U16::new(P::API_REV_MIN.major))?
        .min_minor(U16::new(P::API_REV_MIN.minor))?
        .max_major(U16::new(P::API_REV_MAX.major))?
        .max_minor(U16::new(P::API_REV_MAX.minor))?
        .finish();
    Ok(frame.len())
}
