// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `Hash` command handler.
//!
//! Within an open session, compute a SHA-1 / 256 / 384 / 512 digest, or
//! SHAKE128 / SHAKE256 output of a requested length, of a host-supplied
//! message and return it.  A pure hashing utility — no key, no scope, no
//! partition state — the TBOR analogue of MBOR `ShaDigest`.
//!
//! Consumes the message into a hash context before reclaiming its storage
//! for the final digest. Available to both Crypto-Officer and Crypto-User.

use core::num::NonZeroU16;

use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::TborHashReq;
use tsra_fw_ddi_tbor_types::TborHashResp;
use tsra_fw_ddi_tbor_types::HASH_DIGEST_MAX_LEN;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::validate_active_session;

/// Map the wire [`HashAlgo`] and `out_len` onto the firmware hash algorithm.
///
/// The SHAKE XOFs require `out_len` (1 to [`HASH_DIGEST_MAX_LEN`] bytes); the
/// fixed-length digests reject it.
fn hsm_hash_algo(algo: HashAlgo, out_len: Option<u16>) -> HsmResult<HsmHashAlgo> {
    let xof_len = |len: u16| {
        NonZeroU16::new(len)
            .filter(|len| usize::from(len.get()) <= HASH_DIGEST_MAX_LEN)
            .ok_or(HsmError::InvalidArg)
    };
    match (algo, out_len) {
        (HashAlgo::Sha1, None) => Ok(HsmHashAlgo::Sha1),
        (HashAlgo::Sha256, None) => Ok(HsmHashAlgo::Sha256),
        (HashAlgo::Sha384, None) => Ok(HsmHashAlgo::Sha384),
        (HashAlgo::Sha512, None) => Ok(HsmHashAlgo::Sha512),
        (HashAlgo::Shake128, Some(len)) => Ok(HsmHashAlgo::Shake128(xof_len(len)?)),
        (HashAlgo::Shake256, Some(len)) => Ok(HsmHashAlgo::Shake256(xof_len(len)?)),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Handle a TBOR `Hash` request.
///
/// No partition lock or undo log is required: the command reads no mutable
/// partition state and persists nothing — it hashes the message and
/// returns the digest.
pub(crate) async fn handle<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    pal.alloc_scoped_async(io, async |alloc| {
        let req = TborHashReq::decode(cmd_buf.request())?;
        let sess_id = HsmSessId::from(u16::from(req.session_id()));
        validate_active_session(pal, io, sess_id)?;

        let algo = hsm_hash_algo(req.algo(), req.out_len())?;
        let mut ctx = pal.hash_begin(io, algo, alloc)?;
        pal.hash_continue(io, &mut ctx, req.msg()).await?;

        let len = TborHashResp::encode(cmd_buf.buffer_mut(), 0, false)?
            .digest_reserve(algo.digest_len())?
            .finish()
            .len();
        let out = TborHashResp::decode_mut(&mut cmd_buf.buffer_mut()[..len])?;
        pal.hash_finish(io, ctx, out.digest, true).await?;
        Ok(len)
    })
    .await
}
