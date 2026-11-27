// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `TestAction::ForcePkaInstance` (action 12) FIPS-validation hook.
//!
//! Pins every later any-engine PKA request (ECC, RSA, staged commands) to one
//! UPKA engine, so approved services can be validated on a fixed engine, or
//! releases the pin. The payload `{1: force_pka_instance: u8}` selects the
//! engine; an empty payload releases the pin.
//!
//! The pin is device-global and held in CP1 RAM: it applies to every session
//! and partition until changed, and any CP1 reboot clears it. Self tests and
//! engine wipes that name a specific engine are unaffected. See
//! `UpkaDriver::force_engine`.

use tsra_fw_ddi_mbor::MborDecode;
use tsra_fw_ddi_mbor::MborDecoder;
use tsra_fw_ddi_mbor_derive::Ddi;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_uno_reg_soc::io_gsram::UPKA_ENGINE_CMD_COUNT;

use super::common::ReqHdr;
use super::test_action::encode_success;
use crate::UnoHsmIo;
use crate::pal::UnoHsmPal;

/// Action-specific `ForcePkaInstance` request data.
///
/// Mirrors the host test-hooks `DdiTestActionForcePkaInstanceReqInfo`
/// field-for-field without introducing a PAL-to-host dependency.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiTestActionForcePkaInstanceReqInfo {
    /// UPKA engine to pin to.
    #[ddi(id = 1)]
    force_pka_instance: u8,
}

/// Handle the nested `ForcePkaInstance` TestAction payload.
///
/// # Returns
///
/// - `Ok(&HsmDmaBuf)` — the pin was set or released.
/// - `Err(HsmError::SessionExpected)` — the request carries no session.
/// - `Err(HsmError::DdiDecodeFailed)` — the payload is malformed.
/// - `Err(HsmError::InvalidArg)` — the engine is out of range; the current
///   pin is unchanged.
pub(super) fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &UnoHsmIo,
    hdr: &ReqHdr,
    payload: &mut HsmDmaBuf,
) -> HsmResult<&'p HsmDmaBuf> {
    hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let engine = decode_engine(payload)?;

    // Prepare the response before changing the pin so an allocation or
    // encoding failure cannot change it and still return an error.
    let resp = encode_success(pal, io, hdr)?;
    pal.pka.force_engine(engine)?;
    Ok(resp)
}

/// Decode the requested engine; an empty payload releases the pin.
fn decode_engine(payload: &mut HsmDmaBuf) -> HsmResult<Option<u8>> {
    if payload.is_empty() {
        return Ok(None);
    }

    let payload_len = payload.len();
    let mut decoder = MborDecoder::new(payload);
    let request = DdiTestActionForcePkaInstanceReqInfo::mbor_decode(&mut decoder)
        .map_err(|_| HsmError::DdiDecodeFailed)?;
    if decoder.position() != payload_len {
        return Err(HsmError::DdiDecodeFailed);
    }

    engine_id(request.force_pka_instance).map(Some)
}

const fn engine_id(value: u8) -> HsmResult<u8> {
    if (value as u32) < UPKA_ENGINE_CMD_COUNT {
        Ok(value)
    } else {
        Err(HsmError::InvalidArg)
    }
}

// Compile-time unit tests for `engine_id`: this firmware crate has no
// runtime test target, so a failed assertion fails the build instead.
// Covers both ends of the valid range and the first/last invalid values.
const _: () = {
    assert!(matches!(engine_id(0), Ok(0)));
    assert!(matches!(engine_id(15), Ok(15)));
    assert!(matches!(engine_id(16), Err(HsmError::InvalidArg)));
    assert!(matches!(engine_id(u8::MAX), Err(HsmError::InvalidArg)));
};
