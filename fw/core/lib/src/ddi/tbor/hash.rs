// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `Hash` command handler.
//!
//! Within an open session, compute a SHA-1 / 256 / 384 / 512 digest of a
//! host-supplied message and return it.  A pure hashing utility — no key,
//! no scope, no partition state — the TBOR analogue of MBOR `ShaDigest`.
//!
//! Consumes the message into a hash context before reclaiming its storage
//! for the final digest. Available to both Crypto-Officer and Crypto-User.

use tsra_fw_ddi_tbor_types::HashAlgo;
use tsra_fw_ddi_tbor_types::TborHashReq;
use tsra_fw_ddi_tbor_types::TborHashResp;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;

use super::validate_active_session;

/// Map the wire [`HashAlgo`] onto the firmware hash algorithm.
fn hsm_hash_algo(algo: HashAlgo) -> HsmResult<HsmHashAlgo> {
    match algo {
        HashAlgo::Sha1 => Ok(HsmHashAlgo::Sha1),
        HashAlgo::Sha256 => Ok(HsmHashAlgo::Sha256),
        HashAlgo::Sha384 => Ok(HsmHashAlgo::Sha384),
        HashAlgo::Sha512 => Ok(HsmHashAlgo::Sha512),
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

        let algo = hsm_hash_algo(req.algo())?;
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
