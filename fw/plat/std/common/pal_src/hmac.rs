// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmHmac`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer to the [`StdHmac`](crate::drivers::hmac::StdHmac)
//! driver. One-shot operations are backed by [`tsra_crypto`]'s
//! platform-abstracted HMAC (OpenSSL on Linux, CNG on Windows).
//!
//! Multi-step HMAC is implemented as a true streaming pipeline: the
//! caller-provided key bytes are imported into an [`HmacKey`] handle
//! at [`hmac_begin`] time and the resulting streaming context
//! ([`HmacAlgoSignContext`]) is held inside [`StdHmacCtx`].  Each
//! [`hmac_continue`] call feeds its `HsmDmaBuf` slice straight into the
//! HMAC state machine via [`SignStreamingOpContext::update`]; the
//! std PAL never accumulates message bytes in a heap buffer.  This
//! preserves the "must not panic on any input" trust-boundary
//! contract by removing the unbounded `Vec::extend_from_slice` path
//! that could OOM-abort on attacker-sized streams.
//!
//! ## Sensitive-byte handling
//!
//! - The caller's [`HsmDmaBuf`] key bytes are not copied into a PAL-
//!   side scratch buffer.  [`HmacKey::from_bytes`] reads the slice
//!   and copies into its own backend-owned storage; the caller's
//!   `HsmDmaBuf` remains under the IO scope's zero-on-free allocator
//!   contract and is wiped on release.
//! - The streaming HMAC state owned by [`HmacAlgoSignContext`] is a
//!   thin wrapper around an OpenSSL `EVP_MD_CTX` (Linux) or a CNG
//!   `BCRYPT_HASH_HANDLE` (Windows); both backends zeroize their
//!   internal HMAC key material on free.  No raw key bytes are
//!   retained inside [`StdHmacCtx`] itself.
//! - The driver-level one-shot sign / verify paths still own a
//!   short-lived `Vec` for cross-thread submission to the worker
//!   pool; that buffer is bounded by the single-call HsmDmaBuf size and
//!   freed before the next operation can be dispatched.

use tsra_crypto::HmacAlgo;
use tsra_crypto::HmacAlgoSignContext;
use tsra_crypto::HmacKey;
use tsra_crypto::ImportableKey;
use tsra_crypto::SignStreamingOpContext;
use tsra_crypto::Signer;

use super::*;
use crate::hash::to_hash_algo;
use crate::StdHsmPal;

/// Largest HMAC tag we may need to materialise locally for verify
/// (== SHA-512 digest length).
const MAX_HMAC_TAG_LEN: usize = 64;

/// Constant-time byte slice comparison.
///
/// Returns `true` iff `a` and `b` have the same length and contents.
/// The execution path depends only on `a.len()`, not on the byte
/// values, to keep verify decisions immune to timing side channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Std-PAL streaming HMAC context.
///
/// Holds the live [`HmacAlgoSignContext`] for an in-progress
/// multi-step HMAC.  No raw key or message bytes are buffered: each
/// [`hmac_continue`] call feeds its slice directly into the HMAC
/// state machine, and the key material is owned by the platform
/// crypto backend (which clears it on free via the context's own
/// `Drop` impl: OpenSSL `EVP_MD_CTX_free` / CNG `BCryptDestroyHash`).
///
/// Native streaming state owns its key on both backends. The supplied
/// storage is borrowed even though no DMA bytes are needed.
pub struct StdHmacCtx<'a> {
    algo: HsmHashAlgo,
    sign_ctx: Option<HmacAlgoSignContext<'static>>,
    _storage: &'a mut HsmDmaBuf,
}

impl HsmHmac for StdHsmPal {
    type HmacCtx<'a> = StdHmacCtx<'a>;

    async fn hmac_gen_key(
        &self,
        _io: &StdHsmIo,
        _algo: HsmHashAlgo,
        key_len: usize,
        key: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let Some(key) = key else {
            return Ok(key_len);
        };
        if key.len() < key_len {
            return Err(HsmError::InvalidArg);
        }
        self.hmac.gen_key(&mut key[..key_len]).await?;
        Ok(key_len)
    }

    async fn hmac_sign(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        key: &HsmDmaBuf,
        data: &HsmDmaBuf,
        tag: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let hash_algo = to_hash_algo(algo)?;
        let len = algo.digest_len();
        let Some(tag) = tag else {
            return Ok(len);
        };
        if tag.len() < len {
            return Err(HsmError::InvalidArg);
        }
        self.hmac
            .sign(hash_algo, key, data, &mut tag[..len])
            .await?;
        Ok(len)
    }

    async fn hmac_verify(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        key: &HsmDmaBuf,
        data: &HsmDmaBuf,
        tag: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        self.hmac.verify(to_hash_algo(algo)?, key, data, tag).await
    }

    fn hmac_state_size(&self, algo: HsmHashAlgo) -> HsmResult<usize> {
        to_hash_algo(algo)?;
        Ok(0)
    }

    async fn hmac_begin<'a>(
        &self,
        _io: &StdHsmIo,
        algo: HsmHashAlgo,
        key: &HsmDmaBuf,
        storage: &'a mut HsmDmaBuf,
    ) -> HsmResult<Self::HmacCtx<'a>>
    where
        Self: 'a,
    {
        let hash_algo = to_hash_algo(algo)?;
        // `HmacKey::from_bytes` copies the bytes into its own
        // backend-owned storage; the caller's `HsmDmaBuf` keeps owning
        // the original buffer and is wiped on release by the IO
        // scope's zero-on-free allocator contract.
        let hmac_key = HmacKey::from_bytes(key).map_err(|_| HsmError::HmacError)?;

        let hmac_algo = HmacAlgo::new(hash_algo);
        let sign_ctx: HmacAlgoSignContext<'static> =
            Signer::sign_init::<'static, HmacAlgo>(hmac_algo, hmac_key)
                .map_err(|_| HsmError::HmacError)?;

        Ok(StdHmacCtx {
            algo,
            sign_ctx: Some(sign_ctx),
            _storage: storage,
        })
    }

    async fn hmac_continue(
        &self,
        _io: &StdHsmIo,
        ctx: &mut Self::HmacCtx<'_>,
        data: &HsmDmaBuf,
    ) -> HsmResult<()> {
        ctx.sign_ctx
            .as_mut()
            .ok_or(HsmError::InvalidArg)?
            .update(data)
            .map_err(|_| HsmError::HmacError)
    }

    async fn hmac_finish(
        &self,
        _io: &StdHsmIo,
        ctx: &mut Self::HmacCtx<'_>,
        tag: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        if let Some(tag) = tag.as_ref() {
            if tag.len() < ctx.algo.digest_len() {
                return Err(HsmError::InvalidArg);
            }
        }
        finish_into_tag(ctx, tag)
    }

    async fn hmac_finish_into(
        &self,
        _io: &StdHsmIo,
        ctx: &mut Self::HmacCtx<'_>,
        dest: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        finish_into_tag(ctx, dest)
    }

    async fn hmac_finish_verify(
        &self,
        _io: &StdHsmIo,
        mut ctx: Self::HmacCtx<'_>,
        tag: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        let mut computed = [0u8; MAX_HMAC_TAG_LEN];
        let digest_len = to_hash_algo(ctx.algo)?.size();
        if digest_len > computed.len() {
            return Err(HsmError::HmacError);
        }
        let mut sign_ctx = ctx.sign_ctx.take().ok_or(HsmError::InvalidArg)?;
        sign_ctx
            .finish(Some(&mut computed[..digest_len]))
            .map_err(|_| HsmError::HmacError)?;

        // Constant-time compare against the caller-supplied tag.  We
        // accept any tag length the caller submitted; the comparator
        // returns false immediately on a length mismatch, which is
        // safe to leak (the tag length is not secret).
        let ok = constant_time_eq(&computed[..digest_len], tag);
        // Wipe the on-stack computed tag now that the decision is made.
        computed.fill(0);
        Ok(ok)
    }
}

/// Shared helper for the two non-verify finishers.  Writes the HMAC
/// tag into `out[..digest_len]`.
fn finish_into_tag(ctx: &mut StdHmacCtx<'_>, out: Option<&mut HsmDmaBuf>) -> HsmResult<usize> {
    if ctx.sign_ctx.is_none() {
        return Err(HsmError::InvalidArg);
    }
    let digest_len = to_hash_algo(ctx.algo)?.size();
    let Some(out) = out else {
        return Ok(digest_len);
    };
    let mut sign_ctx = ctx.sign_ctx.take().ok_or(HsmError::InvalidArg)?;
    let len = out.len().min(digest_len);
    if len == digest_len {
        sign_ctx
            .finish(Some(&mut out[..len]))
            .map_err(|_| HsmError::HmacError)?;
    } else {
        let mut computed = [0u8; MAX_HMAC_TAG_LEN];
        let result = sign_ctx
            .finish(Some(&mut computed[..digest_len]))
            .map_err(|_| HsmError::HmacError);
        if result.is_ok() {
            out[..len].copy_from_slice(&computed[..len]);
        }
        computed.fill(0);
        result?;
    }
    Ok(len)
}
