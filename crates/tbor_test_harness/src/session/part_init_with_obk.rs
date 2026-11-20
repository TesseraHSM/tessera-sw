// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helper for the TBOR `PartInitWithObk` command.
//!
//! Wraps the masked owner backup key (MOBK) in an AEAD-GCM envelope keyed by
//! [`SessionHandshake::param_key`] (AAD =
//! [`build_part_init_with_obk_aad(session_id)`](build_part_init_with_obk_aad))
//! and ships it, with the partition-owner (POTA) endorsement of the
//! partition identity, via [`TborPartInitWithObkReq`].

use tsra_crypto::aead_envelope;
use tsra_crypto::aead_envelope::AeadAlg;
use tsra_crypto::Rng;
use tsra_ddi_interface::DdiError;
use tsra_ddi_tbor_types::build_part_init_with_obk_aad;
use tsra_ddi_tbor_types::TborPartInitWithObkReq;
use tsra_ddi_tbor_types::TborPartInitWithObkResp;

use super::finish::SessionHandshake;
use crate::byte_order::dev_rev;
use crate::fixture::TestDev;
use crate::x509_fixture::CaKey;
use crate::x509_fixture::RAW_PUB_LEN;

/// A POTA key's endorsement of the partition identity, in the byte order the
/// `PartInitWithObk` wire carries: each 48-byte P-384 component (coordinate,
/// `r`, `s`) in device byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PotaEndorsement {
    /// POTA public key, raw `x ‖ y`.
    pub pub_key: Vec<u8>,
    /// Signature over `SHA-384(0x04 ‖ PID public key)`, raw `r ‖ s`.
    pub sig: Vec<u8>,
}

impl PotaEndorsement {
    /// Endorse `pid_pub_key` — the identity key as `PartInfo` reports it,
    /// raw big-endian `x ‖ y` — with `pota`.
    pub fn sign(pota: &CaKey, pid_pub_key: &[u8]) -> Self {
        let pid_pub: &[u8; RAW_PUB_LEN] = pid_pub_key.try_into().expect("96-byte PID public key");
        let (r, s) = pota.endorse(pid_pub);
        let raw_pub = pota.raw_pub();
        let dev_pair = |first: &[u8], second: &[u8]| [dev_rev(first), dev_rev(second)].concat();
        Self {
            pub_key: dev_pair(&raw_pub[..48], &raw_pub[48..]),
            sig: dev_pair(&r, &s),
        }
    }
}

/// Issue `PartInitWithObk` on the CO session represented by `session`.
///
/// `masked_bk3` is the MOBK (the blob MBOR `InitBk3` returned); it is wrapped
/// in the session-keyed envelope here.  `prev_local_mk_backup` is the
/// optional prior backup to restore (empty = first provisioning).
pub fn part_init_with_obk(
    dev: &TestDev,
    session: &SessionHandshake,
    masked_bk3: &[u8],
    endorsement: &PotaEndorsement,
    prev_local_mk_backup: &[u8],
) -> Result<TborPartInitWithObkResp, DdiError> {
    let req = TborPartInitWithObkReq {
        session_id: session.session_id,
        mobk_envelope: encrypt_mobk_envelope(session, masked_bk3)?,
        pota_pub_key: endorsement.pub_key.clone(),
        pota_sig: endorsement.sig.clone(),
        prev_local_mk_backup: prev_local_mk_backup.to_vec(),
    };
    dev.exec_op_tbor(&req, None, &mut None)
}

/// Build the wire-ready AEAD-GCM envelope for a `PartInitWithObk` MOBK.
///
/// Exposed so negative-path tests can mutate the envelope (e.g. flip a
/// ciphertext byte) before shipping it via a raw
/// [`TborPartInitWithObkReq`].
pub fn encrypt_mobk_envelope(
    session: &SessionHandshake,
    masked_bk3: &[u8],
) -> Result<Vec<u8>, DdiError> {
    seal_mobk_envelope(
        session,
        &build_part_init_with_obk_aad(session.session_id),
        masked_bk3,
    )
}

/// [`encrypt_mobk_envelope`] with a caller-chosen `aad`, so tests can bind
/// the envelope to another session or command than the one it is sent on.
pub fn seal_mobk_envelope(
    session: &SessionHandshake,
    aad: &[u8],
    masked_bk3: &[u8],
) -> Result<Vec<u8>, DdiError> {
    let iv = Rng::rand_vec(AeadAlg::AesGcm256.iv_len()).map_err(|_| DdiError::InvalidParameter)?;
    let total = aead_envelope::seal(
        AeadAlg::AesGcm256,
        &session.param_key,
        &iv,
        aad,
        masked_bk3,
        None,
    )
    .map_err(|_| DdiError::TborDecodeError)?;
    let mut envelope = vec![0u8; total];
    let written = aead_envelope::seal(
        AeadAlg::AesGcm256,
        &session.param_key,
        &iv,
        aad,
        masked_bk3,
        Some(&mut envelope),
    )
    .map_err(|_| DdiError::TborDecodeError)?;
    envelope.truncate(written);
    Ok(envelope)
}
