// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side dispatch for the in-session `DarcKexKeyGen` command
//! (opcode `0x20`) at the DDI layer.
//!
//! `DarcKexKeyGen` generates a new DARC key-exchange key for the requested
//! HPKE KEM (P-384, ML-KEM-1024 or MLKEM1024-P384) and returns the
//! **masked** (AEAD-GCM-256) private key plus its raw public key. Run on the target it yields the HPKE receiver identity; run on
//! the source it may be used as a recipient key for incoming transfers;
//! outgoing transfers authenticate with the source PID. The private key is
//! not stored on the device; the caller retains the masked blob and
//! unmasks it on-use in [`darc_tmk_export`](super::darc_tmk_export) /
//! [`darc_tmk_import`](super::darc_tmk_import).
//!
//! It runs **inside an already-open** security-domain (V2) session; the
//! request carries the active session id and the requested key `scope`.

use tsra_ddi_tbor_types::*;

use super::*;

/// Issue `DarcKexKeyGen` (opcode `0x20`) on the active session.
///
/// Ships the active session id, the requested key `scope` and `kem`.
/// Returns the new KEX key as a masked (AEAD-GCM-256) private-key blob plus
/// its public key. The key is not stored on-device. The public key is, per
/// `kem`:
///
/// * P-384: raw `x ‖ y` (96 bytes, big-endian per coordinate — the
///   certificate-leaf form, independent of the device's wire order);
/// * ML-KEM-1024: the 1568-byte encapsulation key;
/// * MLKEM1024-P384: the 1665-byte `ek_PQ ‖ SEC1 P-384 point`.
///
/// # Arguments
///
/// * `session` - The active security-domain (V2) session.
/// * `scope` - Requested key scope as the 1-byte `KeyScope` discriminant.
/// * `kem` - The recipient key's HPKE KEM.
///
/// # Errors
///
/// Surfaces DDI/device failures from the round-trip and
/// [`HsmError::MaskedKeyDecodeFailed`] if the returned blob is malformed.
pub(crate) fn darc_kex_key_gen(
    session: &HsmSession,
    scope: u8,
    kem: HsmTransferKem,
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let req = TborDarcKexKeyGenReq {
        session_id: session.ex_session_id()?,
        scope,
        kem: kem.wire(),
    };

    let mut cookie = None;
    let rev = session.api_rev();
    let resp = session.with_dev(|dev| {
        dev.exec_op_tbor(rev, &req, None, &mut cookie)
            .map_err(HsmError::from)
    })?;

    validate_masked_sealing_key(kem, &resp.masked_key)?;
    if resp.pub_key.len() != kem.pub_key_len() {
        return Err(HsmError::InternalError);
    }
    let mut pub_key = resp.pub_key;
    if kem == HsmTransferKem::P384 {
        let order = WireOrder::of(session);
        let (x, y) = pub_key.split_at_mut(KEX_PUB_KEY_LEN / 2);
        order.convert_in_place(x);
        order.convert_in_place(y);
    }
    Ok((resp.masked_key, pub_key))
}
