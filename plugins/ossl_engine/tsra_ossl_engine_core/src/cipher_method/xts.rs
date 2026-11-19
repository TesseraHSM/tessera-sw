// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-XTS with an attached HSM key.
//!
//! As with a raw key, each update is one data unit under the context's IV (the
//! tweak), which stays as set until the next IV. The HSM takes whole blocks
//! only (no ciphertext stealing), at most [`XTS_MAX_DATA_UNIT`] bytes per data
//! unit; anything else fails with nothing written.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::sync::Arc;

use tsra_ossl_engine_sys as ffi;
use zeroize::Zeroizing;

use super::AES_BLOCK;
use super::CtxKey;
use super::builtin_for;
use super::ctx_keys;
use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::RetCode;
use crate::error::catch_panic;
use crate::error::ossl_check;
use crate::error::result_to_int;

/// The IV size: one data unit's tweak.
pub const XTS_TWEAK_LEN: usize = 16;

/// The longest data unit the HSM takes, in bytes.
pub const XTS_MAX_DATA_UNIT: usize = 8192;

/// An HSM AES-XTS key; dropping the last reference releases it.
pub trait AesXtsKey: Send + Sync {
    /// Encrypt or decrypt the data unit `input` (whole blocks, at most
    /// [`XTS_MAX_DATA_UNIT`] bytes) under `tweak` into `output` (same length).
    fn xts(
        &self,
        encrypt: bool,
        tweak: &[u8; XTS_TWEAK_LEN],
        input: &[u8],
        output: &mut [u8],
    ) -> EngineResult<()>;
}

/// An attached key and its context's tweak.
#[derive(Clone)]
pub(super) struct XtsState {
    key: Arc<dyn AesXtsKey>,
    /// `None` until an IV is set after the attach.
    tweak: Option<[u8; XTS_TWEAK_LEN]>,
}

impl XtsState {
    /// The state of a context `key` was just attached to: no tweak yet.
    pub(super) fn new(key: Arc<dyn AesXtsKey>) -> Self {
        Self { key, tweak: None }
    }
}

/// The error for a context with no key.
fn no_key() -> EngineError {
    EngineError::Other(
        "no key set on this AES-XTS context (attach an HSM key with \
         TSRA_CTRL_SET_KEY_URI or initialize it with a key)"
            .into(),
    )
}

/// Fails unless `len` bytes are a data unit the HSM takes.
fn check_data_unit(len: usize) -> EngineResult<()> {
    if !(AES_BLOCK..=XTS_MAX_DATA_UNIT).contains(&len) || !len.is_multiple_of(AES_BLOCK) {
        return Err(EngineError::Other(format!(
            "an HSM AES-XTS key takes data units of whole blocks, {AES_BLOCK} to \
             {XTS_MAX_DATA_UNIT} bytes, not {len}"
        )));
    }
    Ok(())
}

/// `init` override, called on every init (`EVP_CIPH_ALWAYS_CALL_INIT`): an
/// IV for an attached key sets the tweak.
///
/// # Safety
/// Called only by `EVP_CipherInit_ex`; arguments per that contract.
#[allow(unsafe_code)]
pub(super) unsafe extern "C" fn c_init(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    key: *const c_uchar,
    iv: *const c_uchar,
    enc: c_int,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the arguments OpenSSL passed us.
        || result_to_int(unsafe { init_inner(ctx, key, iv, enc) }),
        RetCode::Fail.into(),
    )
}

/// A raw key goes to the shared init (keeping an attached key's tweak if it
/// comes without an IV), an IV for an attached key sets the tweak, and
/// anything else goes to the built-in.
///
/// # Safety
/// As [`c_init`].
#[allow(unsafe_code)]
unsafe fn init_inner(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    key: *const c_uchar,
    iv: *const c_uchar,
    enc: c_int,
) -> EngineResult<()> {
    if !key.is_null() {
        // A key-only init keeps the IV, as with the built-in: attaching wiped
        // the built-in's copy, so pass the attached key's tweak on.
        let tweak = match ctx_keys().lock().get(&(ctx as usize)) {
            Some(CtxKey::HsmXts(state)) if iv.is_null() => state.tweak,
            _ => None,
        };
        let iv = tweak.as_ref().map_or(iv, |t| t.as_ptr());
        // SAFETY: as this function's contract; a tweak holds the IV length.
        return unsafe { super::init_inner(ctx, key, iv, enc) };
    }
    if let Some(CtxKey::HsmXts(state)) = ctx_keys().lock().get_mut(&(ctx as usize)) {
        if !iv.is_null() {
            // SAFETY: iv holds the cipher's IV, XTS_TWEAK_LEN bytes.
            let tweak = unsafe { iv.cast::<[u8; XTS_TWEAK_LEN]>().read_unaligned() };
            // Keeps EVP_CIPHER_CTX_iv() current, as the built-in does.
            // SAFETY: the context's IV buffer holds XTS_TWEAK_LEN bytes.
            unsafe {
                ffi::EVP_CIPHER_CTX_iv_noconst(ctx)
                    .cast::<[u8; XTS_TWEAK_LEN]>()
                    .write_unaligned(tweak);
            }
            state.tweak = Some(tweak);
        }
        return Ok(());
    }
    // SAFETY: builtin_for returns a valid built-in cipher.
    let init = unsafe { ffi::EVP_CIPHER_meth_get_init(builtin_for(ctx)?) }
        .ok_or(EngineError::Other("built-in AES-XTS init missing".into()))?;
    // SAFETY: delegating the arguments OpenSSL passed us.
    ossl_check(unsafe { init(ctx, key, iv, enc) }, "AES-XTS init failed")
}

/// `do_cipher` override: the HSM for an attached key, the built-in for a raw
/// one, an error for neither.
///
/// # Safety
/// Called only by the EVP update functions and `EVP_Cipher`; `out`/`input`
/// hold `inl` bytes and are either the same buffer or disjoint.
#[allow(unsafe_code)]
pub(super) unsafe extern "C" fn c_do_cipher(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the arguments OpenSSL passed us.
        || result_to_int(unsafe { do_cipher_inner(ctx, out, input, inl) }),
        RetCode::Fail.into(),
    )
}

/// Dispatch one data unit to the context's key (see [`c_do_cipher`]).
///
/// # Safety
/// As [`c_do_cipher`].
#[allow(unsafe_code)]
unsafe fn do_cipher_inner(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> EngineResult<()> {
    let key = ctx_keys().lock().get(&(ctx as usize)).cloned();
    match key {
        Some(CtxKey::Software) => {
            // SAFETY: builtin_for returns a valid built-in cipher.
            let do_cipher = unsafe { ffi::EVP_CIPHER_meth_get_do_cipher(builtin_for(ctx)?) }
                .ok_or(EngineError::Other("built-in AES-XTS cipher missing".into()))?;
            // SAFETY: delegating the arguments OpenSSL passed us.
            let rc = unsafe { do_cipher(ctx, out, input, inl) };
            ossl_check(rc, "AES-XTS failed")
        }
        // SAFETY: as this function's contract.
        Some(CtxKey::HsmXts(state)) => unsafe { hsm_xts(ctx, &state, out, input, inl) },
        Some(CtxKey::HsmCbc(_) | CtxKey::HsmGcm(_)) | None => Err(no_key()),
    }
}

/// Run the data unit of `inl` bytes through the HSM key under the context's
/// tweak. Nothing is written unless the HSM call succeeds.
///
/// # Safety
/// As [`c_do_cipher`].
#[allow(unsafe_code)]
unsafe fn hsm_xts(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    state: &XtsState,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> EngineResult<()> {
    if out.is_null() || input.is_null() {
        return Err(EngineError::NullParam("cipher buffer"));
    }
    check_data_unit(inl)?;
    let tweak = state.tweak.ok_or(EngineError::Other(
        "no IV set on this AES-XTS context: set one after attaching the key".into(),
    ))?;
    // The SDK cannot advance this tweak and refuses it even for one data unit.
    if tweak == [u8::MAX; XTS_TWEAK_LEN] {
        return Err(EngineError::Other(
            "the all-ones IV is not supported with an HSM key on AES-XTS".into(),
        ));
    }
    // SAFETY: ctx is the live context OpenSSL passed the callback; the getter
    // only reads its direction.
    let encrypt = unsafe { ffi::EVP_CIPHER_CTX_encrypting(ctx) != 0 };
    // Copied out only on success; scrubbed, as it may be plaintext.
    let mut output = Zeroizing::new(vec![0u8; inl]);
    {
        // SAFETY: input holds inl bytes; it is no longer read once out, which
        // may be the same buffer, is written below.
        let data = unsafe { std::slice::from_raw_parts(input, inl) };
        // A device call: the table lock is not held.
        state.key.xts(encrypt, &tweak, data, &mut output)?;
    }
    // SAFETY: out holds inl bytes; output is our own buffer of inl bytes.
    unsafe { std::ptr::copy_nonoverlapping(output.as_ptr(), out, inl) };
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;
    use std::ffi::c_uint;
    use std::ptr::null;
    use std::ptr::null_mut;

    use super::super::XTS_NID;
    use super::super::builtin_cipher;
    use super::super::tests::LAST_BITS;
    use super::super::tests::OK;
    use super::super::tests::RELEASED;
    use super::super::tests::TOY_URI;
    use super::super::tests::XTS_CALLS;
    use super::super::tests::attach;
    use super::super::tests::engine_with_ciphers;
    use super::super::tests::free;
    use super::super::tests::init;
    use super::super::tests::new_ctx;
    use super::super::tests::our_cipher;
    use super::super::tests::pattern;
    use super::super::tests::raw_key;
    use super::super::tests::teardown;
    use super::super::tests::toy_xts;
    use super::*;

    /// The byte the failure tests pre-fill output buffers with.
    const UNTOUCHED: u8 = 0xAA;

    /// A tweak of distinct bytes counting up from `first`.
    fn tweak_from(first: u8) -> [u8; XTS_TWEAK_LEN] {
        std::array::from_fn(|i| first.wrapping_add(u8::try_from(i).unwrap()))
    }

    /// The IV `EVP_CIPHER_CTX_iv` reports for `ctx`.
    #[allow(unsafe_code)]
    fn ctx_iv(ctx: *mut ffi::EVP_CIPHER_CTX) -> [u8; XTS_TWEAK_LEN] {
        // SAFETY: ctx is live; its IV buffer holds XTS_TWEAK_LEN bytes.
        unsafe {
            ffi::EVP_CIPHER_CTX_iv(ctx)
                .cast::<[u8; XTS_TWEAK_LEN]>()
                .read_unaligned()
        }
    }

    /// The toy encryption of the data unit `msg` under `tweak`.
    fn toy_encrypt(tweak: &[u8; XTS_TWEAK_LEN], msg: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; msg.len()];
        toy_xts(true, tweak, msg, &mut out);
        out
    }

    /// A context with the toy key attached and `tweak` set, per the documented
    /// sequence.
    fn hsm_ctx(
        raw: *mut ffi::ENGINE,
        encrypt: bool,
        tweak: &[u8; XTS_TWEAK_LEN],
    ) -> *mut ffi::EVP_CIPHER_CTX {
        let ctx = new_ctx();
        assert!(init(
            ctx,
            our_cipher(raw, XTS_NID),
            raw,
            None,
            None,
            encrypt
        ));
        assert!(attach(ctx, Some(TOY_URI), 0));
        assert!(init(ctx, null(), null_mut(), None, Some(tweak), encrypt));
        ctx
    }

    /// One update of `data` into `out` (at least as long); the bytes written,
    /// or `None` if it failed.
    #[allow(unsafe_code)]
    fn update_into(ctx: *mut ffi::EVP_CIPHER_CTX, data: &[u8], out: &mut [u8]) -> Option<usize> {
        assert!(out.len() >= data.len());
        let mut n: c_int = 0;
        let len = c_int::try_from(data.len()).unwrap();
        // SAFETY: an update on a live context; out has room for data.
        let rc =
            unsafe { ffi::EVP_CipherUpdate(ctx, out.as_mut_ptr(), &mut n, data.as_ptr(), len) };
        (rc == OK).then(|| usize::try_from(n).unwrap())
    }

    /// One update of `data` as a data unit; its output, or `None` if it failed.
    fn update(ctx: *mut ffi::EVP_CIPHER_CTX, data: &[u8]) -> Option<Vec<u8>> {
        let mut out = vec![0u8; data.len()];
        let written = update_into(ctx, data, &mut out)?;
        out.truncate(written);
        Some(out)
    }

    /// The final: the bytes it wrote, or `None` if it failed.
    #[allow(unsafe_code)]
    fn finish(ctx: *mut ffi::EVP_CIPHER_CTX) -> Option<usize> {
        let mut out = [0u8; AES_BLOCK];
        let mut n: c_int = 0;
        // SAFETY: a final on a live context; out has room for one block.
        let rc = unsafe { ffi::EVP_CipherFinal_ex(ctx, out.as_mut_ptr(), &mut n) };
        (rc == OK).then(|| usize::try_from(n).unwrap())
    }

    /// One data unit through `cipher` (with `engine`, NULL for a built-in)
    /// under the raw `key`; `None` if a step fails.
    fn raw_crypt(
        cipher: *const ffi::EVP_CIPHER,
        engine: *mut ffi::ENGINE,
        key: &[u8],
        tweak: &[u8; XTS_TWEAK_LEN],
        encrypt: bool,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let ctx = new_ctx();
        let out = init(ctx, cipher, engine, Some(key), Some(tweak), encrypt)
            .then(|| update(ctx, data))
            .flatten();
        free(ctx);
        out
    }

    /// Whether the cipher data of `ctx` is all zero.
    #[allow(unsafe_code)]
    fn cipher_data_wiped(ctx: *mut ffi::EVP_CIPHER_CTX) -> bool {
        // SAFETY: ctx is live; its cipher data is the cipher's ctx_size bytes.
        unsafe {
            let size = ffi::EVP_CIPHER_impl_ctx_size(ffi::EVP_CIPHER_CTX_cipher(ctx));
            let data = ffi::EVP_CIPHER_CTX_get_cipher_data(ctx).cast::<u8>();
            std::slice::from_raw_parts(data, usize::try_from(size).unwrap())
                .iter()
                .all(|&b| b == 0)
        }
    }

    // A raw key runs the built-in: byte-identical to OpenSSL's own AES-XTS,
    // ciphertext stealing, long data units and its key check included, with
    // the key and the IV set together or apart.
    #[test]
    fn raw_key_runs_the_builtin() {
        let (engine, raw) = engine_with_ciphers();
        let tweak = tweak_from(9);
        let key = raw_key(XTS_NID);
        let (builtin, ours) = (builtin_cipher(XTS_NID).unwrap(), our_cipher(raw, XTS_NID));
        XTS_CALLS.with(|c| c.set(0));
        for len in [
            AES_BLOCK,
            17,
            47,
            512,
            XTS_MAX_DATA_UNIT.saturating_add(AES_BLOCK),
        ] {
            let msg = pattern(len);
            let ct = raw_crypt(ours, raw, &key, &tweak, true, &msg);
            assert!(ct.is_some(), "len {len}");
            assert_eq!(
                ct,
                raw_crypt(builtin, null_mut(), &key, &tweak, true, &msg),
                "len {len}"
            );
            assert_eq!(
                raw_crypt(ours, raw, &key, &tweak, false, &ct.unwrap()),
                Some(msg),
                "len {len}"
            );
        }
        let short = pattern(AES_BLOCK.saturating_sub(1));
        let block = pattern(AES_BLOCK);
        let equal_halves = vec![7u8; key.len()];
        for (cipher, e) in [(builtin, null_mut()), (ours, raw)] {
            assert!(
                raw_crypt(cipher, e, &key, &tweak, true, &short).is_none(),
                "under one block"
            );
            assert!(
                raw_crypt(cipher, e, &equal_halves, &tweak, true, &block).is_none(),
                "equal key halves"
            );
        }

        let msg = pattern(64);
        let expected = raw_crypt(builtin, null_mut(), &key, &tweak, true, &msg);
        let ctx = new_ctx();
        assert!(init(ctx, ours, raw, None, None, true));
        assert!(init(ctx, null(), null_mut(), None, Some(&tweak), true));
        assert!(update(ctx, &msg).is_none(), "IV but no key");
        assert!(init(ctx, null(), null_mut(), Some(&key), None, true));
        assert_eq!(update(ctx, &msg), expected);
        assert_eq!(update(ctx, &msg), expected, "the tweak stays as set");
        assert_eq!(finish(ctx), Some(0));
        free(ctx);
        assert_eq!(XTS_CALLS.with(Cell::get), 0, "no HSM key was attached");
        teardown(&engine, raw);
    }

    // An attached key gets each update as one data unit under the tweak, which
    // stays as set until the next IV; the final writes nothing; the loader is
    // asked for the cipher's key size.
    #[test]
    fn attached_key_runs_one_data_unit_per_update() {
        let (engine, raw) = engine_with_ciphers();
        let (tweak, tweak2) = (tweak_from(3), tweak_from(4));
        let bits = u32::try_from(raw_key(XTS_NID).len())
            .unwrap()
            .checked_mul(u8::BITS);
        let lens = [AES_BLOCK, 512, 4096, XTS_MAX_DATA_UNIT];
        XTS_CALLS.with(|c| c.set(0));
        for len in lens {
            let msg = pattern(len);
            let expected = toy_encrypt(&tweak, &msg);
            assert_ne!(expected, toy_encrypt(&tweak2, &msg));

            let ctx = hsm_ctx(raw, true, &tweak);
            assert_eq!(Some(LAST_BITS.with(Cell::get)), bits);
            assert_eq!(ctx_iv(ctx), tweak);
            assert_eq!(update(ctx, &msg).as_ref(), Some(&expected), "len {len}");
            assert_eq!(update(ctx, &msg).as_ref(), Some(&expected), "same tweak");
            assert_eq!(finish(ctx), Some(0));
            assert!(init(ctx, null(), null_mut(), None, Some(&tweak2), true));
            assert_eq!(ctx_iv(ctx), tweak2);
            assert_eq!(update(ctx, &msg), Some(toy_encrypt(&tweak2, &msg)));
            free(ctx);

            let ctx = hsm_ctx(raw, false, &tweak);
            assert_eq!(update(ctx, &expected), Some(msg), "len {len}");
            assert_eq!(finish(ctx), Some(0));
            free(ctx);
        }
        assert_eq!(
            XTS_CALLS.with(Cell::get),
            lens.len().saturating_mul(4),
            "one key call per update"
        );
        teardown(&engine, raw);
    }

    // Encrypting and decrypting in place (out == in) work.
    #[test]
    #[allow(unsafe_code)]
    fn in_place() {
        let (engine, raw) = engine_with_ciphers();
        let tweak = tweak_from(5);
        let msg = pattern(512);
        let expected = toy_encrypt(&tweak, &msg);
        for (encrypt, input, output) in [(true, &msg, &expected), (false, &expected, &msg)] {
            let ctx = hsm_ctx(raw, encrypt, &tweak);
            let mut buf = input.clone();
            let mut n: c_int = 0;
            let len = c_int::try_from(buf.len()).unwrap();
            let ptr = buf.as_mut_ptr();
            // SAFETY: an update on a live context, in place over buf.
            let rc = unsafe { ffi::EVP_CipherUpdate(ctx, ptr, &mut n, ptr, len) };
            assert_eq!((rc, n), (OK, len));
            assert_eq!(&buf, output, "encrypt {encrypt}");
            free(ctx);
        }
        teardown(&engine, raw);
    }

    // A partial block, a data unit over the limit, no data and NULL buffers
    // all fail before the key is called, with nothing written; the context
    // stays usable.
    #[test]
    #[allow(unsafe_code)]
    fn bad_data_units_fail_closed() {
        let (engine, raw) = engine_with_ciphers();
        let tweak = tweak_from(6);
        let ctx = hsm_ctx(raw, true, &tweak);
        XTS_CALLS.with(|c| c.set(0));
        for len in [
            1,
            AES_BLOCK.saturating_sub(1),
            AES_BLOCK.saturating_add(1),
            XTS_MAX_DATA_UNIT.saturating_sub(1),
            XTS_MAX_DATA_UNIT.saturating_add(1),
            XTS_MAX_DATA_UNIT.saturating_add(AES_BLOCK),
            XTS_MAX_DATA_UNIT.saturating_mul(2),
        ] {
            let mut out = vec![UNTOUCHED; len];
            assert!(
                update_into(ctx, &pattern(len), &mut out).is_none(),
                "len {len}"
            );
            assert!(out.iter().all(|&b| b == UNTOUCHED), "len {len}");
        }

        let msg = pattern(AES_BLOCK);
        let mut out = [UNTOUCHED; AES_BLOCK];
        let mut n: c_int = 0;
        let len = c_int::try_from(AES_BLOCK).unwrap();
        // SAFETY: calls on a live context; a NULL buffer is refused before it
        // is used, the others hold AES_BLOCK bytes.
        unsafe {
            // The EVP layer takes an empty update itself.
            assert_eq!(
                ffi::EVP_CipherUpdate(ctx, out.as_mut_ptr(), &mut n, msg.as_ptr(), 0),
                OK
            );
            assert_eq!(n, 0);
            // EVP_Cipher reaches the cipher even with no data.
            assert_ne!(ffi::EVP_Cipher(ctx, out.as_mut_ptr(), msg.as_ptr(), 0), OK);
            assert_ne!(
                ffi::EVP_CipherUpdate(ctx, null_mut(), &mut n, msg.as_ptr(), len),
                OK,
                "NULL output"
            );
            assert_ne!(
                ffi::EVP_CipherUpdate(ctx, out.as_mut_ptr(), &mut n, null(), len),
                OK,
                "NULL input"
            );
            let block = c_uint::try_from(AES_BLOCK).unwrap();
            assert_ne!(ffi::EVP_Cipher(ctx, null_mut(), null(), block), OK);
        }
        assert!(out.iter().all(|&b| b == UNTOUCHED));
        assert_eq!(XTS_CALLS.with(Cell::get), 0, "the key must not be called");

        assert_eq!(update(ctx, &msg), Some(toy_encrypt(&tweak, &msg)));
        free(ctx);
        teardown(&engine, raw);
    }

    // The all-ones tweak fails before the key is called, with nothing
    // written; a new IV makes the context usable again. A raw key takes it, as
    // the built-in does.
    #[test]
    fn all_ones_tweak_fails_closed() {
        let (engine, raw) = engine_with_ciphers();
        let ones = [u8::MAX; XTS_TWEAK_LEN];
        let msg = pattern(AES_BLOCK);
        let ctx = hsm_ctx(raw, true, &ones);
        XTS_CALLS.with(|c| c.set(0));
        let mut out = [UNTOUCHED; AES_BLOCK];
        assert!(update_into(ctx, &msg, &mut out).is_none());
        assert!(out.iter().all(|&b| b == UNTOUCHED));
        assert_eq!(XTS_CALLS.with(Cell::get), 0, "the key must not be called");
        let mut below = ones;
        below[0] = u8::MAX.saturating_sub(1);
        assert!(init(ctx, null(), null_mut(), None, Some(&below), true));
        assert_eq!(update(ctx, &msg), Some(toy_encrypt(&below, &msg)));
        free(ctx);

        let key = raw_key(XTS_NID);
        let ct = raw_crypt(our_cipher(raw, XTS_NID), raw, &key, &ones, true, &msg);
        assert!(ct.is_some());
        let builtin = builtin_cipher(XTS_NID).unwrap();
        assert_eq!(ct, raw_crypt(builtin, null_mut(), &key, &ones, true, &msg));
        teardown(&engine, raw);
    }

    // The tag controls belong to GCM: on this cipher they fail with the
    // built-in's error, attached key or not, NULL pointer included.
    #[test]
    #[allow(unsafe_code)]
    fn tag_ctrls_mirror_the_builtin() {
        let (engine, raw) = engine_with_ciphers();
        let tweak = tweak_from(10);
        let key = raw_key(XTS_NID);
        let builtin = new_ctx();
        assert!(init(
            builtin,
            builtin_cipher(XTS_NID).unwrap(),
            null_mut(),
            Some(&key),
            Some(&tweak),
            true
        ));
        let ours = new_ctx();
        assert!(init(
            ours,
            our_cipher(raw, XTS_NID),
            raw,
            Some(&key),
            Some(&tweak),
            true
        ));
        let hsm = hsm_ctx(raw, true, &tweak);
        let mut tag = [0u8; AES_BLOCK];
        let tag_len = c_int::try_from(tag.len()).unwrap();
        for typ in [ffi::EVP_CTRL_AEAD_SET_TAG, ffi::EVP_CTRL_AEAD_GET_TAG] {
            let typ = c_int::try_from(typ).unwrap();
            for ptr in [null_mut(), tag.as_mut_ptr().cast()] {
                // The result and the error it leaves on a cleared queue.
                // SAFETY: a ctrl call on a live context; ptr is NULL or holds
                // tag_len bytes.
                let ctrl = |ctx| unsafe {
                    ffi::ERR_clear_error();
                    let rc = ffi::EVP_CIPHER_CTX_ctrl(ctx, typ, tag_len, ptr);
                    (rc, ffi::ERR_get_error())
                };
                let expected = ctrl(builtin);
                assert_ne!(expected.0, OK, "ctrl {typ}");
                for ctx in [ours, hsm] {
                    assert_eq!(ctrl(ctx), expected, "ctrl {typ}");
                }
            }
        }
        for ctx in [builtin, ours, hsm] {
            free(ctx);
        }
        teardown(&engine, raw);
    }

    // An attached key needs an IV set after the attach: one set before does
    // not count, and each attach asks for a new one.
    #[test]
    fn no_iv_fails_closed() {
        let (engine, raw) = engine_with_ciphers();
        let tweak = tweak_from(7);
        let msg = pattern(32);
        XTS_CALLS.with(|c| c.set(0));

        let ctx = new_ctx();
        assert!(init(
            ctx,
            our_cipher(raw, XTS_NID),
            raw,
            None,
            Some(&tweak),
            true
        ));
        assert!(attach(ctx, Some(TOY_URI), 0));
        let mut out = vec![UNTOUCHED; msg.len()];
        assert!(update_into(ctx, &msg, &mut out).is_none(), "no IV");
        assert!(out.iter().all(|&b| b == UNTOUCHED));
        // An init without an IV keeps it unset.
        assert!(init(ctx, null(), null_mut(), None, None, true));
        assert!(update(ctx, &msg).is_none(), "still no IV");
        assert_eq!(XTS_CALLS.with(Cell::get), 0, "the key must not be called");

        assert!(init(ctx, null(), null_mut(), None, Some(&tweak), true));
        assert_eq!(update(ctx, &msg), Some(toy_encrypt(&tweak, &msg)));
        // An init without an IV keeps the one set.
        assert!(init(ctx, null(), null_mut(), None, None, true));
        assert_eq!(update(ctx, &msg), Some(toy_encrypt(&tweak, &msg)));

        assert!(attach(ctx, Some(TOY_URI), 0));
        assert!(update(ctx, &msg).is_none(), "a new key needs a new IV");
        free(ctx);
        teardown(&engine, raw);
    }

    // No key, an unknown or NULL key URI and a nonzero arg all fail; a failed
    // attach leaves an attached key and its tweak in place.
    #[test]
    fn no_key_fails_closed() {
        let (engine, raw) = engine_with_ciphers();
        let tweak = tweak_from(8);
        let msg = pattern(32);

        let ctx = new_ctx();
        assert!(init(
            ctx,
            our_cipher(raw, XTS_NID),
            raw,
            None,
            Some(&tweak),
            true
        ));
        let mut out = vec![UNTOUCHED; msg.len()];
        assert!(update_into(ctx, &msg, &mut out).is_none(), "no key");
        assert!(out.iter().all(|&b| b == UNTOUCHED));
        assert!(!attach(ctx, Some("bogus"), 0), "unknown key URI");
        assert!(!attach(ctx, None, 0), "NULL key URI");
        assert!(!attach(ctx, Some(TOY_URI), 1), "nonzero arg");
        assert!(init(ctx, null(), null_mut(), None, Some(&tweak), true));
        assert!(update(ctx, &msg).is_none(), "still no key");
        free(ctx);

        let ctx = hsm_ctx(raw, true, &tweak);
        RELEASED.with(|c| c.set(0));
        assert!(!attach(ctx, Some("bogus"), 0));
        assert!(!attach(ctx, None, 0));
        assert!(!attach(ctx, Some(TOY_URI), 1));
        assert_eq!(RELEASED.with(Cell::get), 0, "the key must stay attached");
        assert_eq!(update(ctx, &msg), Some(toy_encrypt(&tweak, &msg)));
        free(ctx);
        assert_eq!(RELEASED.with(Cell::get), 1);
        teardown(&engine, raw);
    }

    // A copied context runs like the original: it shares an attached key,
    // released with the last of them, and starts with its tweak, or carries
    // the raw key's schedule.
    #[test]
    #[allow(unsafe_code)]
    fn copies_keep_the_key_and_tweak() {
        let (engine, raw) = engine_with_ciphers();
        let (tweak, tweak2) = (tweak_from(1), tweak_from(2));
        let msg = pattern(48);
        let key = raw_key(XTS_NID);
        let builtin = builtin_cipher(XTS_NID).unwrap();
        let software = raw_crypt(builtin, null_mut(), &key, &tweak, true, &msg).unwrap();
        let software2 = raw_crypt(builtin, null_mut(), &key, &tweak2, true, &msg).unwrap();
        let raw_ctx = new_ctx();
        assert!(init(
            raw_ctx,
            our_cipher(raw, XTS_NID),
            raw,
            Some(&key),
            Some(&tweak),
            true
        ));
        RELEASED.with(|c| c.set(0));
        for (ctx, expected, expected2) in [
            (
                hsm_ctx(raw, true, &tweak),
                toy_encrypt(&tweak, &msg),
                toy_encrypt(&tweak2, &msg),
            ),
            (raw_ctx, software, software2),
        ] {
            let dup = new_ctx();
            // SAFETY: copying a live context into a fresh one.
            assert_eq!(unsafe { ffi::EVP_CIPHER_CTX_copy(dup, ctx) }, OK);
            assert_eq!(update(dup, &msg).as_ref(), Some(&expected));
            // A new IV on the copy leaves the original's.
            assert!(init(dup, null(), null_mut(), None, Some(&tweak2), true));
            assert_eq!(update(dup, &msg), Some(expected2));
            assert_eq!(update(ctx, &msg), Some(expected));
            let released = RELEASED.with(Cell::get);
            free(ctx);
            assert_eq!(
                RELEASED.with(Cell::get),
                released,
                "the copy still holds the key"
            );
            free(dup);
        }
        assert_eq!(RELEASED.with(Cell::get), 1);
        teardown(&engine, raw);
    }

    // The last key set wins. An attached key survives an init that names the
    // cipher again with the ENGINE (OpenSSL skips the reset then) and takes the
    // new IV; a raw key replaces it, releasing it; attaching again replaces the
    // raw key, wiping its schedule, or an attached key, releasing it.
    #[test]
    fn last_key_set_wins() {
        let (engine, raw) = engine_with_ciphers();
        let (tweak, tweak2) = (tweak_from(1), tweak_from(2));
        let key = raw_key(XTS_NID);
        let msg = pattern(48);
        let ours = our_cipher(raw, XTS_NID);
        let builtin = builtin_cipher(XTS_NID).unwrap();

        let ctx = hsm_ctx(raw, true, &tweak);
        RELEASED.with(|c| c.set(0));
        assert_eq!(update(ctx, &msg), Some(toy_encrypt(&tweak, &msg)));
        assert!(init(ctx, ours, raw, None, Some(&tweak2), true));
        assert_eq!(update(ctx, &msg), Some(toy_encrypt(&tweak2, &msg)));
        assert_eq!(RELEASED.with(Cell::get), 0, "the key must stay attached");

        assert!(init(
            ctx,
            null(),
            null_mut(),
            Some(&key),
            Some(&tweak),
            true
        ));
        assert_eq!(
            RELEASED.with(Cell::get),
            1,
            "the replaced key must be released"
        );
        let software = raw_crypt(builtin, null_mut(), &key, &tweak, true, &msg);
        assert!(software.is_some());
        assert_eq!(update(ctx, &msg), software);

        assert!(attach(ctx, Some(TOY_URI), 0));
        assert!(cipher_data_wiped(ctx), "the raw key schedule must be wiped");
        assert!(update(ctx, &msg).is_none(), "the raw key's IV is gone");
        assert!(init(ctx, null(), null_mut(), None, Some(&tweak), true));
        assert_eq!(update(ctx, &msg), Some(toy_encrypt(&tweak, &msg)));

        assert!(attach(ctx, Some(TOY_URI), 0));
        assert_eq!(
            RELEASED.with(Cell::get),
            2,
            "the replaced key must be released"
        );
        assert!(init(ctx, null(), null_mut(), None, Some(&tweak2), true));
        assert_eq!(update(ctx, &msg), Some(toy_encrypt(&tweak2, &msg)));

        // A raw key alone keeps the attached key's tweak.
        assert!(init(ctx, null(), null_mut(), Some(&key), None, true));
        assert_eq!(RELEASED.with(Cell::get), 3);
        assert_eq!(
            update(ctx, &msg),
            raw_crypt(builtin, null_mut(), &key, &tweak2, true, &msg)
        );
        // There is none to keep before the first IV.
        assert!(attach(ctx, Some(TOY_URI), 0));
        assert!(init(ctx, null(), null_mut(), Some(&key), None, true));
        assert!(update(ctx, &msg).is_none(), "no IV was set");
        free(ctx);
        assert_eq!(RELEASED.with(Cell::get), 4);
        teardown(&engine, raw);
    }
}
