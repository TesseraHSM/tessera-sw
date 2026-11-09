// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-GCM with an attached HSM key.
//!
//! The HSM runs GCM in one shot: AAD updates (`out` NULL) are buffered, the
//! single data update writes all output (callers size the final's buffer for
//! one block), and the final writes nothing. Decryption needs the whole tag,
//! set after the IV and before the data, and writes nothing if it fails. Each
//! message needs a new IV.

use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_void;
use std::sync::Arc;

use tsra_ossl_engine_sys as ffi;
use zeroize::Zeroizing;

use super::CtxKey;
use super::builtin_for;
use super::ctx_keys;
use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::RetCode;
use crate::error::catch_panic;
use crate::error::ossl_check;
use crate::error::result_to_int;

/// The only IV size the HSM takes.
pub const GCM_IV_LEN: usize = 12;

/// The HSM produces and verifies whole tags only.
pub const GCM_TAG_LEN: usize = 16;

/// The firmware's limit on one message: the AAD padded to 32 bytes, plus the
/// data.
pub const GCM_MAX_INPUT: usize = 16 * 1024;

/// The HSM pads the AAD to this.
const GCM_AAD_ALIGN: usize = 32;

/// Whether `aad_len` bytes of AAD and `data_len` of data fit [`GCM_MAX_INPUT`].
fn within_limit(aad_len: usize, data_len: usize) -> bool {
    aad_len
        .checked_next_multiple_of(GCM_AAD_ALIGN)
        .and_then(|aad| aad.checked_add(data_len))
        .is_some_and(|len| len <= GCM_MAX_INPUT)
}

/// `do_cipher` failure result of an `EVP_CIPH_FLAG_CUSTOM_CIPHER` cipher.
const CUSTOM_CIPHER_FAIL: c_int = -1;

/// An HSM AES-GCM key; dropping the last reference releases it.
pub trait AesGcmKey: Send + Sync {
    /// Encrypt `input` into `output` (same length); returns the tag.
    fn encrypt(
        &self,
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> EngineResult<[u8; GCM_TAG_LEN]>;

    /// Decrypt `input` into `output` (same length); fails unless `tag`
    /// verifies.
    fn decrypt(
        &self,
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        tag: &[u8; GCM_TAG_LEN],
        input: &[u8],
        output: &mut [u8],
    ) -> EngineResult<()>;
}

/// An attached key and its context's message state.
#[derive(Clone)]
pub(super) struct GcmState {
    key: Arc<dyn AesGcmKey>,
    /// `None` until set, and again once the message ends.
    iv: Option<[u8; GCM_IV_LEN]>,
    aad: Zeroizing<Vec<u8>>,
    /// The data went through the HSM.
    done: bool,
    /// This message's: to verify (decryption), or produced (encryption).
    tag: Option<[u8; GCM_TAG_LEN]>,
}

/// One message's HSM call.
struct Message {
    key: Arc<dyn AesGcmKey>,
    iv: [u8; GCM_IV_LEN],
    aad: Zeroizing<Vec<u8>>,
    /// `Some` (to verify) for decryption.
    tag: Option<[u8; GCM_TAG_LEN]>,
}

impl GcmState {
    /// The state of a context `key` was just attached to: no message yet.
    pub(super) fn new(key: Arc<dyn AesGcmKey>) -> Self {
        Self {
            key,
            iv: None,
            aad: Zeroizing::default(),
            done: false,
            tag: None,
        }
    }

    /// Starts a message with `iv`; a decryption must set its own tag.
    fn start(&mut self, iv: [u8; GCM_IV_LEN]) {
        self.iv = Some(iv);
        self.aad = Zeroizing::default();
        self.done = false;
        self.tag = None;
    }

    /// The next message needs a new IV.
    fn end(&mut self) {
        self.iv = None;
        self.aad = Zeroizing::default();
        self.done = false;
    }

    /// The IV, if the message still takes AAD and data.
    fn open_iv(&self) -> EngineResult<[u8; GCM_IV_LEN]> {
        if self.done {
            return Err("an HSM AES-GCM key takes the AAD, then the data in one update".into());
        }
        self.iv.ok_or_else(|| {
            "no IV set on this AES-GCM context: set one after attaching the key \
             (and for each message)"
                .into()
        })
    }

    /// Buffers `aad` for the message's one HSM call.
    fn add_aad(&mut self, aad: &[u8]) -> EngineResult<()> {
        self.open_iv()?;
        let total = self.aad.len().saturating_add(aad.len());
        if !within_limit(total, 0) {
            return Err(over_limit(total, 0));
        }
        self.aad.extend_from_slice(aad);
        Ok(())
    }

    /// Fails unless `len` bytes of data fit beside the AAD.
    fn check_data_len(&self, len: usize) -> EngineResult<()> {
        if within_limit(self.aad.len(), len) {
            Ok(())
        } else {
            Err(over_limit(self.aad.len(), len))
        }
    }

    /// The message's HSM call, if it may run now.
    fn take_message(&mut self, encrypt: bool) -> EngineResult<Message> {
        let iv = self.open_iv()?;
        let tag = match (encrypt, self.tag) {
            (true, _) => None,
            (false, Some(tag)) => Some(tag),
            (false, None) => {
                return Err("AES-GCM decryption with an HSM key needs the tag \
                            (EVP_CTRL_AEAD_SET_TAG) after the IV, before the \
                            ciphertext"
                    .into());
            }
        };
        Ok(Message {
            key: Arc::clone(&self.key),
            iv,
            aad: std::mem::take(&mut self.aad),
            tag,
        })
    }

    /// Keeps the tag an encryption produced.
    fn data_done(&mut self, tag: Option<[u8; GCM_TAG_LEN]>) {
        self.done = true;
        if tag.is_some() {
            self.tag = tag;
        }
    }
}

impl Message {
    /// Returns the tag an encryption produced.
    fn run(&self, data: &[u8], output: &mut [u8]) -> EngineResult<Option<[u8; GCM_TAG_LEN]>> {
        match &self.tag {
            None => self
                .key
                .encrypt(&self.iv, &self.aad, data, output)
                .map(Some),
            Some(tag) => self
                .key
                .decrypt(&self.iv, &self.aad, tag, data, output)
                .map(|()| None),
        }
    }
}

/// `None` without an attached key. Holds the table lock: `f` must not call the
/// HSM.
fn with_state<T>(ctx: *mut ffi::EVP_CIPHER_CTX, f: impl FnOnce(&mut GcmState) -> T) -> Option<T> {
    match ctx_keys().lock().get_mut(&(ctx as usize)) {
        Some(CtxKey::HsmGcm(state)) => Some(f(state)),
        _ => None,
    }
}

/// The error for a message over [`GCM_MAX_INPUT`].
fn over_limit(aad_len: usize, data_len: usize) -> EngineError {
    EngineError::Other(format!(
        "AES-GCM message of {aad_len} bytes of AAD and {data_len} of data exceeds the \
         HSM limit: {GCM_MAX_INPUT} bytes, AAD padded to {GCM_AAD_ALIGN}, plus data"
    ))
}

/// The error for a context with no key.
fn no_key() -> EngineError {
    EngineError::Other(
        "no key set on this AES-GCM context (attach an HSM key with \
         TSRA_CTRL_SET_KEY_URI or initialize it with a key)"
            .into(),
    )
}

/// Whether `ctx` was initialized for encryption.
#[allow(unsafe_code)]
fn encrypting(ctx: *mut ffi::EVP_CIPHER_CTX) -> bool {
    // SAFETY: ctx is a live context OpenSSL passed a callback; the getter only
    // reads its direction.
    unsafe { ffi::EVP_CIPHER_CTX_encrypting(ctx) != 0 }
}

/// Refuse an attach unless the IV length, which a raw-key use may have
/// changed, is [`GCM_IV_LEN`].
///
/// # Safety
/// `ctx` is a live context of our AES-GCM cipher.
#[allow(unsafe_code)]
pub(super) unsafe fn check_iv_len(ctx: *mut ffi::EVP_CIPHER_CTX) -> EngineResult<()> {
    // SAFETY: builtin_for returns a valid built-in cipher.
    let ctrl = unsafe { ffi::EVP_CIPHER_meth_get_ctrl(builtin_for(ctx)?) }
        .ok_or(EngineError::Other("built-in AES-GCM ctrl missing".into()))?;
    let mut len: c_int = 0;
    let get_ivlen = ffi::EVP_CTRL_GET_IVLEN as c_int;
    // SAFETY: the built-in shares our cipher data layout; GET_IVLEN writes one
    // int to ptr.
    let rc = unsafe { ctrl(ctx, get_ivlen, 0, (&raw mut len).cast::<c_void>()) };
    ossl_check(rc, "AES-GCM IV length query failed")?;
    if usize::try_from(len) != Ok(GCM_IV_LEN) {
        return Err(EngineError::Other(format!(
            "an HSM AES-GCM key takes {GCM_IV_LEN}-byte IVs, the context has {len}"
        )));
    }
    Ok(())
}

/// `init` override, called on every init (`EVP_CIPH_ALWAYS_CALL_INIT`): an
/// IV for an attached key starts a message.
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

/// A raw key goes to the shared init, an IV for an attached key starts a
/// message, and anything else goes to the built-in.
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
        // SAFETY: as this function's contract.
        return unsafe { super::init_inner(ctx, key, iv, enc) };
    }
    let attached = with_state(ctx, |state| {
        if !iv.is_null() {
            // SAFETY: an attached key's context has GCM_IV_LEN-byte IVs (see
            // check_iv_len and hsm_ctrl), which iv holds.
            state.start(unsafe { iv.cast::<[u8; GCM_IV_LEN]>().read_unaligned() });
        }
    });
    if attached.is_some() {
        return Ok(());
    }
    // SAFETY: builtin_for returns a valid built-in cipher.
    let init = unsafe { ffi::EVP_CIPHER_meth_get_init(builtin_for(ctx)?) }
        .ok_or(EngineError::Other("built-in AES-GCM init missing".into()))?;
    // SAFETY: delegating the arguments OpenSSL passed us.
    ossl_check(unsafe { init(ctx, key, iv, enc) }, "AES-GCM init failed")
}

/// `do_cipher` override (`EVP_CIPH_FLAG_CUSTOM_CIPHER`): bytes written, or -1.
///
/// # Safety
/// Called only by the EVP update/final functions and `EVP_Cipher`: `input` is
/// NULL for the final, else holds `inl` bytes, and `out` is NULL (AAD) or
/// holds `inl` bytes, in the same buffer as `input` or a disjoint one.
#[allow(unsafe_code)]
pub(super) unsafe extern "C" fn c_do_cipher(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the arguments OpenSSL passed us.
        || match unsafe { do_cipher_inner(ctx, out, input, inl) } {
            Ok(rc) => rc,
            Err(e) => {
                result_to_int::<()>(Err(e));
                CUSTOM_CIPHER_FAIL
            }
        },
        CUSTOM_CIPHER_FAIL,
    )
}

/// The built-in for a raw key, the HSM otherwise.
///
/// # Safety
/// As [`c_do_cipher`].
#[allow(unsafe_code)]
unsafe fn do_cipher_inner(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> EngineResult<c_int> {
    let software = matches!(
        ctx_keys().lock().get(&(ctx as usize)),
        Some(CtxKey::Software)
    );
    if software {
        // SAFETY: builtin_for returns a valid built-in cipher.
        let do_cipher = unsafe { ffi::EVP_CIPHER_meth_get_do_cipher(builtin_for(ctx)?) }
            .ok_or(EngineError::Other("built-in AES-GCM cipher missing".into()))?;
        // SAFETY: delegating the arguments OpenSSL passed us; the built-in's
        // result already follows the custom-cipher convention.
        return Ok(unsafe { do_cipher(ctx, out, input, inl) });
    }
    // SAFETY: as this function's contract.
    let written = unsafe { hsm_gcm(ctx, out, input, inl) }?;
    c_int::try_from(written).map_err(|_| EngineError::Other("AES-GCM output too long".into()))
}

/// One call for an attached key; returns the bytes written. Any failure ends
/// the message, so its final fails too.
///
/// # Safety
/// As [`c_do_cipher`].
#[allow(unsafe_code)]
unsafe fn hsm_gcm(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> EngineResult<usize> {
    // SAFETY: as this function's contract.
    let result = unsafe { hsm_gcm_inner(ctx, out, input, inl) };
    if result.is_err() {
        with_state(ctx, GcmState::end);
    }
    result
}

/// Buffers AAD, runs the HSM call on the data, or ends the message at the
/// final (running the call there for an empty message).
///
/// # Safety
/// As [`c_do_cipher`].
#[allow(unsafe_code)]
unsafe fn hsm_gcm_inner(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    out: *mut c_uchar,
    input: *const c_uchar,
    inl: usize,
) -> EngineResult<usize> {
    if input.is_null() {
        // The final: an empty message runs the HSM here.
        let pending = with_state(ctx, |state| !state.done).ok_or_else(no_key)?;
        let result = if pending {
            one_shot(ctx, &[], &mut [])
        } else {
            Ok(())
        };
        with_state(ctx, GcmState::end);
        return result.map(|()| 0);
    }
    if out.is_null() {
        // SAFETY: input holds inl bytes.
        let aad = unsafe { std::slice::from_raw_parts(input, inl) };
        return with_state(ctx, |state| state.add_aad(aad))
            .ok_or_else(no_key)?
            .map(|()| 0);
    }
    with_state(ctx, |state| state.check_data_len(inl)).ok_or_else(no_key)??;
    // Copied out only on success; scrubbed, as it may be plaintext.
    let mut output = Zeroizing::new(vec![0u8; inl]);
    {
        // SAFETY: input holds inl bytes; it is no longer read once out, which
        // may be the same buffer, is written below.
        let data = unsafe { std::slice::from_raw_parts(input, inl) };
        one_shot(ctx, data, &mut output)?;
    }
    // SAFETY: out holds inl bytes; output is our own buffer of inl bytes.
    unsafe { std::ptr::copy_nonoverlapping(output.as_ptr(), out, inl) };
    Ok(inl)
}

/// Run the message's HSM call over `data` into `output` (same length).
fn one_shot(ctx: *mut ffi::EVP_CIPHER_CTX, data: &[u8], output: &mut [u8]) -> EngineResult<()> {
    let encrypt = encrypting(ctx);
    let message = with_state(ctx, |state| state.take_message(encrypt)).ok_or_else(no_key)??;
    // A device call: outside the table lock.
    let tag = message.run(data, output)?;
    with_state(ctx, |state| state.data_done(tag));
    Ok(())
}

/// Controls for an attached key; `None` falls through to the shared handling.
///
/// # Safety
/// `ctx` is a live context of one of our ciphers; `ptr` per the control
/// (`EVP_CTRL_AEAD_SET_TAG`: `arg` bytes to read; `EVP_CTRL_AEAD_GET_TAG`:
/// room for `arg` bytes).
#[allow(unsafe_code)]
pub(super) unsafe fn hsm_ctrl(
    ctx: *mut ffi::EVP_CIPHER_CTX,
    typ: c_int,
    arg: c_int,
    ptr: *mut c_void,
) -> EngineResult<Option<c_int>> {
    let mut table = ctx_keys().lock();
    let Some(CtxKey::HsmGcm(state)) = table.get_mut(&(ctx as usize)) else {
        return Ok(None);
    };
    let len = usize::try_from(arg).ok();
    match u32::try_from(typ) {
        Ok(ffi::EVP_CTRL_AEAD_SET_IVLEN) => {
            if len != Some(GCM_IV_LEN) {
                return Err(EngineError::Other(format!(
                    "an HSM AES-GCM key takes {GCM_IV_LEN}-byte IVs, not {arg}"
                )));
            }
        }
        Ok(ffi::EVP_CTRL_AEAD_SET_TAG) => {
            if encrypting(ctx) || state.done {
                return Err("the AES-GCM tag is set for decryption, before the data".into());
            }
            if len != Some(GCM_TAG_LEN) {
                return Err(EngineError::Other(format!(
                    "an HSM AES-GCM key verifies whole {GCM_TAG_LEN}-byte tags, not {arg}"
                )));
            }
            if ptr.is_null() {
                return Err(EngineError::NullParam("AES-GCM tag"));
            }
            // SAFETY: ptr holds arg (GCM_TAG_LEN) bytes per this control.
            state.tag = Some(unsafe { ptr.cast::<[u8; GCM_TAG_LEN]>().read_unaligned() });
        }
        Ok(ffi::EVP_CTRL_AEAD_GET_TAG) => {
            if !encrypting(ctx) {
                return Err("the AES-GCM tag is read after encryption".into());
            }
            let len = len
                .filter(|n| (1..=GCM_TAG_LEN).contains(n))
                .ok_or_else(|| {
                    EngineError::Other(format!(
                        "AES-GCM tag length {arg} is not 1 to {GCM_TAG_LEN}"
                    ))
                })?;
            let tag = state
                .tag
                .ok_or(EngineError::Other("no AES-GCM tag produced yet".into()))?;
            if ptr.is_null() {
                return Err(EngineError::NullParam("AES-GCM tag"));
            }
            // SAFETY: ptr has room for arg (len) bytes per this control; tag
            // holds at least len.
            unsafe { std::ptr::copy_nonoverlapping(tag.as_ptr(), ptr.cast::<u8>(), len) };
        }
        Ok(
            ffi::EVP_CTRL_AEAD_TLS1_AAD
            | ffi::EVP_CTRL_AEAD_SET_IV_FIXED
            | ffi::EVP_CTRL_GCM_IV_GEN
            | ffi::EVP_CTRL_GCM_SET_IV_INV,
        ) => {
            return Err("TLS and IV-generation controls do not apply to an HSM AES-GCM key".into());
        }
        _ => return Ok(None),
    }
    Ok(Some(RetCode::Success.into()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::cell::Cell;
    use std::ptr::null;
    use std::ptr::null_mut;

    use super::super::GCM_NID;
    use super::super::builtin_cipher;
    use super::super::tests::GCM_CALLS;
    use super::super::tests::LAST_BITS;
    use super::super::tests::OK;
    use super::super::tests::RELEASED;
    use super::super::tests::TOY_URI;
    use super::super::tests::attach;
    use super::super::tests::engine_with_ciphers;
    use super::super::tests::free;
    use super::super::tests::init;
    use super::super::tests::new_ctx;
    use super::super::tests::our_cipher;
    use super::super::tests::pattern;
    use super::super::tests::raw_key;
    use super::super::tests::teardown;
    use super::super::tests::toy_gcm_tag;
    use super::super::tests::toy_gcm_xor;
    use super::*;

    /// Ciphertext and tag.
    fn toy_seal(iv: &[u8; GCM_IV_LEN], aad: &[u8], msg: &[u8]) -> (Vec<u8>, [u8; GCM_TAG_LEN]) {
        let mut ct = vec![0u8; msg.len()];
        toy_gcm_xor(iv, msg, &mut ct);
        let tag = toy_gcm_tag(iv, aad, &ct);
        (ct, tag)
    }

    /// A context with the toy key attached and `iv` set.
    fn hsm_ctx(
        raw: *mut ffi::ENGINE,
        encrypt: bool,
        iv: &[u8; GCM_IV_LEN],
    ) -> *mut ffi::EVP_CIPHER_CTX {
        let ctx = new_ctx();
        assert!(init(
            ctx,
            our_cipher(raw, GCM_NID),
            raw,
            None,
            None,
            encrypt
        ));
        assert!(attach(ctx, Some(TOY_URI), 0));
        assert!(init(ctx, null(), null_mut(), None, Some(iv), encrypt));
        ctx
    }

    /// One AAD update; whether it succeeded.
    #[allow(unsafe_code)]
    fn add_aad(ctx: *mut ffi::EVP_CIPHER_CTX, aad: &[u8]) -> bool {
        let mut n: c_int = 0;
        let len = c_int::try_from(aad.len()).unwrap();
        // SAFETY: an AAD update on a live context: NULL output, aad holds len
        // bytes.
        unsafe { ffi::EVP_CipherUpdate(ctx, null_mut(), &mut n, aad.as_ptr(), len) == OK }
    }

    /// `aad` in two updates, then `data` in `chunk`-byte ones.
    #[allow(unsafe_code)]
    fn updates(
        ctx: *mut ffi::EVP_CIPHER_CTX,
        aad: &[u8],
        data: &[u8],
        chunk: usize,
    ) -> Option<Vec<u8>> {
        let (aad1, aad2) = aad.split_at(aad.len() / 2);
        if !add_aad(ctx, aad1) || !add_aad(ctx, aad2) {
            return None;
        }
        let mut out = vec![0u8; data.len()];
        let mut total = 0usize;
        for piece in data.chunks(chunk) {
            let mut n: c_int = 0;
            let len = c_int::try_from(piece.len()).unwrap();
            // SAFETY: a data update on a live context; out has room for the
            // rest of data.
            let rc = unsafe {
                ffi::EVP_CipherUpdate(ctx, out[total..].as_mut_ptr(), &mut n, piece.as_ptr(), len)
            };
            if rc != OK {
                return None;
            }
            total = total.saturating_add(usize::try_from(n).unwrap());
        }
        out.truncate(total);
        Some(out)
    }

    /// The final: the bytes it wrote, or `None` if it failed.
    #[allow(unsafe_code)]
    fn finish(ctx: *mut ffi::EVP_CIPHER_CTX) -> Option<usize> {
        let mut out = [0u8; GCM_TAG_LEN];
        let mut n: c_int = 0;
        // SAFETY: a final on a live context; out has room for one block.
        let rc = unsafe { ffi::EVP_CipherFinal_ex(ctx, out.as_mut_ptr(), &mut n) };
        (rc == OK).then(|| usize::try_from(n).unwrap())
    }

    /// One control; whether it succeeded.
    #[allow(unsafe_code)]
    fn ctrl(ctx: *mut ffi::EVP_CIPHER_CTX, typ: u32, arg: usize, ptr: *mut c_void) -> bool {
        let (typ, arg) = (c_int::try_from(typ).unwrap(), c_int::try_from(arg).unwrap());
        // SAFETY: ctx is live; ptr is NULL or as the control needs (callers).
        unsafe { ffi::EVP_CIPHER_CTX_ctrl(ctx, typ, arg, ptr) == OK }
    }

    /// Sets the tag to verify; whether it was taken.
    fn set_tag(ctx: *mut ffi::EVP_CIPHER_CTX, tag: &[u8]) -> bool {
        let mut tag = tag.to_vec();
        let ptr = tag.as_mut_ptr().cast::<c_void>();
        ctrl(ctx, ffi::EVP_CTRL_AEAD_SET_TAG, tag.len(), ptr)
    }

    /// The first `len` bytes of the produced tag.
    fn get_tag(ctx: *mut ffi::EVP_CIPHER_CTX, len: usize) -> Option<Vec<u8>> {
        let mut tag = vec![0u8; len];
        let ptr = tag.as_mut_ptr().cast::<c_void>();
        ctrl(ctx, ffi::EVP_CTRL_AEAD_GET_TAG, len, ptr).then_some(tag)
    }

    /// Raw-key ciphertext and tag; `engine` is NULL for a built-in.
    fn raw_seal(
        cipher: *const ffi::EVP_CIPHER,
        engine: *mut ffi::ENGINE,
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        msg: &[u8],
        chunk: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        let ctx = new_ctx();
        assert!(init(
            ctx,
            cipher,
            engine,
            Some(&raw_key(GCM_NID)),
            Some(iv),
            true
        ));
        let ct = updates(ctx, aad, msg, chunk).unwrap();
        assert_eq!(finish(ctx), Some(0));
        let tag = get_tag(ctx, GCM_TAG_LEN).unwrap();
        free(ctx);
        (ct, tag)
    }

    /// Raw-key decryption, the tag set after the data as software GCM allows.
    fn raw_open(
        cipher: *const ffi::EVP_CIPHER,
        engine: *mut ffi::ENGINE,
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8],
    ) -> Option<Vec<u8>> {
        let ctx = new_ctx();
        assert!(init(
            ctx,
            cipher,
            engine,
            Some(&raw_key(GCM_NID)),
            Some(iv),
            false
        ));
        let pt = updates(ctx, aad, ct, 7);
        let verified = pt.is_some() && set_tag(ctx, tag) && finish(ctx).is_some();
        free(ctx);
        pt.filter(|_| verified)
    }

    /// Encrypts `msg` as a new message on `ctx`: ciphertext and tag.
    fn hsm_seal(
        ctx: *mut ffi::EVP_CIPHER_CTX,
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        msg: &[u8],
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        assert!(init(ctx, null(), null_mut(), None, Some(iv), true));
        let ct = updates(ctx, aad, msg, msg.len().max(1))?;
        if finish(ctx) != Some(0) {
            return None;
        }
        Some((ct, get_tag(ctx, GCM_TAG_LEN)?))
    }

    /// Decrypts `ct` as a new message on `ctx`, setting `tag` first if given.
    fn hsm_open(
        ctx: *mut ffi::EVP_CIPHER_CTX,
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        ct: &[u8],
        tag: Option<&[u8; GCM_TAG_LEN]>,
    ) -> Option<Vec<u8>> {
        assert!(init(ctx, null(), null_mut(), None, Some(iv), false));
        if tag.is_some_and(|tag| !set_tag(ctx, tag)) {
            return None;
        }
        let pt = updates(ctx, aad, ct, ct.len().max(1))?;
        (finish(ctx) == Some(0)).then_some(pt)
    }

    #[test]
    fn raw_key_runs_the_builtin() {
        let (engine, raw) = engine_with_ciphers();
        let (builtin, ours) = (builtin_cipher(GCM_NID).unwrap(), our_cipher(raw, GCM_NID));
        let iv = [9u8; GCM_IV_LEN];
        for aad_len in [0usize, 13, 40] {
            let aad = pattern(aad_len);
            for len in [0usize, 1, 15, 16, 17, 47] {
                let msg = pattern(len);
                for chunk in [1, 7, 64] {
                    let sealed = raw_seal(ours, raw, &iv, &aad, &msg, chunk);
                    assert_eq!(
                        sealed,
                        raw_seal(builtin, null_mut(), &iv, &aad, &msg, chunk),
                        "aad {aad_len}, len {len}, chunk {chunk}"
                    );
                    let (ct, mut tag) = sealed;
                    assert_eq!(raw_open(ours, raw, &iv, &aad, &ct, &tag), Some(msg.clone()));
                    tag[0] ^= 1;
                    assert_eq!(raw_open(ours, raw, &iv, &aad, &ct, &tag), None);
                }
            }
        }
        teardown(&engine, raw);
    }

    #[test]
    fn attached_key_runs_one_shot() {
        let (engine, raw) = engine_with_ciphers();
        let (iv, iv2) = ([3u8; GCM_IV_LEN], [4u8; GCM_IV_LEN]);
        let aad = pattern(21);
        let key_bits = u32::try_from(raw_key(GCM_NID).len())
            .unwrap()
            .checked_mul(u8::BITS);
        for len in [0usize, 1, 16, 47] {
            let msg = pattern(len);
            let (ct, tag) = toy_seal(&iv, &aad, &msg);
            let chunk = len.max(1);
            let ctx = hsm_ctx(raw, true, &iv);
            assert_eq!(Some(LAST_BITS.with(Cell::get)), key_bits);
            assert_eq!(
                updates(ctx, &aad, &msg, chunk),
                Some(ct.clone()),
                "len {len}"
            );
            assert_eq!(finish(ctx), Some(0), "the final writes nothing");
            assert_eq!(get_tag(ctx, GCM_TAG_LEN), Some(tag.to_vec()));
            assert_eq!(get_tag(ctx, 4), Some(tag[..4].to_vec()), "a tag prefix");
            assert_eq!(updates(ctx, &aad, &msg, chunk), None, "the IV is spent");
            assert!(init(ctx, null(), null_mut(), None, Some(&iv2), true));
            let (ct2, tag2) = toy_seal(&iv2, &aad, &msg);
            assert_eq!(updates(ctx, &aad, &msg, chunk), Some(ct2));
            assert_eq!(finish(ctx), Some(0));
            assert_eq!(get_tag(ctx, GCM_TAG_LEN), Some(tag2.to_vec()));
            free(ctx);

            let ctx = hsm_ctx(raw, false, &iv);
            assert!(set_tag(ctx, &tag));
            assert_eq!(updates(ctx, &aad, &ct, chunk), Some(msg), "len {len}");
            assert_eq!(finish(ctx), Some(0));
            free(ctx);
        }
        teardown(&engine, raw);
    }

    #[test]
    #[allow(unsafe_code)]
    fn misuse_fails_closed() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [5u8; GCM_IV_LEN];
        let (aad, msg) = (pattern(9), pattern(40));
        let (ct, tag) = toy_seal(&iv, &aad, &msg);
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        GCM_CALLS.with(|c| c.set(0));

        let ctx = new_ctx();
        assert!(init(ctx, our_cipher(raw, GCM_NID), raw, None, None, true));
        assert!(attach(ctx, Some(TOY_URI), 0));
        assert_eq!(updates(ctx, &[], &msg, msg.len()), None, "no IV");
        assert_eq!(finish(ctx), None, "no IV");
        free(ctx);

        let ctx = hsm_ctx(raw, true, &iv);
        assert_eq!(get_tag(ctx, GCM_TAG_LEN), None, "no tag yet");
        assert!(!set_tag(ctx, &tag), "a tag set while encrypting");
        assert_eq!(updates(ctx, &aad, &msg, 32), None, "a second data update");
        assert_eq!(finish(ctx), None, "the failed message's final");
        free(ctx);

        let ctx = hsm_ctx(raw, true, &iv);
        assert!(updates(ctx, &aad, &msg, msg.len()).is_some());
        assert!(!add_aad(ctx, &aad), "AAD after the data");
        for len in [0, GCM_TAG_LEN.saturating_add(1)] {
            assert_eq!(get_tag(ctx, len), None, "tag length {len}");
        }
        free(ctx);

        let ctx = hsm_ctx(raw, false, &iv);
        assert_eq!(updates(ctx, &aad, &ct, ct.len()), None, "no tag");
        assert_eq!(finish(ctx), None, "the failed message's final");
        free(ctx);

        let ctx = hsm_ctx(raw, false, &iv);
        assert!(!set_tag(ctx, &tag[..GCM_IV_LEN]), "a short tag");
        assert!(set_tag(ctx, &bad_tag));
        assert_eq!(
            get_tag(ctx, GCM_TAG_LEN),
            None,
            "a tag read while decrypting"
        );
        assert!(add_aad(ctx, &aad));
        let mut out = vec![0x5au8; ct.len()];
        let mut n: c_int = 0;
        let len = c_int::try_from(ct.len()).unwrap();
        // SAFETY: a data update on a live context; out holds len bytes.
        let rc = unsafe { ffi::EVP_CipherUpdate(ctx, out.as_mut_ptr(), &mut n, ct.as_ptr(), len) };
        assert_ne!(rc, OK, "a wrong tag");
        assert!(
            out.iter().all(|&b| b == 0x5a),
            "a failed decryption writes nothing"
        );
        assert_eq!(finish(ctx), None, "the failed message's final");
        free(ctx);

        let ctx = hsm_ctx(raw, true, &iv);
        let ivlen = ffi::EVP_CTRL_AEAD_SET_IVLEN;
        assert!(!ctrl(ctx, ivlen, GCM_TAG_LEN, null_mut()), "a 16-byte IV");
        assert!(ctrl(ctx, ivlen, GCM_IV_LEN, null_mut()));
        for typ in [
            ffi::EVP_CTRL_AEAD_TLS1_AAD,
            ffi::EVP_CTRL_AEAD_SET_IV_FIXED,
            ffi::EVP_CTRL_GCM_IV_GEN,
            ffi::EVP_CTRL_GCM_SET_IV_INV,
        ] {
            assert!(!ctrl(ctx, typ, GCM_IV_LEN, null_mut()), "control {typ}");
        }
        free(ctx);
        assert_eq!(
            GCM_CALLS.with(Cell::get),
            3,
            "only the data updates that passed the checks reach the key"
        );
        teardown(&engine, raw);
    }

    #[test]
    fn input_is_capped() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [6u8; GCM_IV_LEN];
        GCM_CALLS.with(|c| c.set(0));
        let over = vec![0u8; GCM_MAX_INPUT.saturating_add(1)];
        let ctx = hsm_ctx(raw, true, &iv);
        assert_eq!(updates(ctx, &[], &over, over.len()), None, "data");
        free(ctx);
        let ctx = hsm_ctx(raw, true, &iv);
        let half = vec![0u8; GCM_MAX_INPUT / 2];
        assert!(add_aad(ctx, &half) && add_aad(ctx, &half));
        assert!(!add_aad(ctx, &[0]), "AAD");
        free(ctx);
        // 20 bytes of AAD take 32.
        let aad = [0u8; 20];
        let room = GCM_MAX_INPUT.saturating_sub(32);
        let ctx = hsm_ctx(raw, true, &iv);
        let data = &over[..room.saturating_add(1)];
        assert_eq!(updates(ctx, &aad, data, data.len()), None, "padded AAD");
        free(ctx);
        assert_eq!(GCM_CALLS.with(Cell::get), 0);

        for (aad, len) in [(&[][..], GCM_MAX_INPUT), (&aad[..], room)] {
            let ctx = hsm_ctx(raw, true, &iv);
            let data = &over[..len];
            assert_eq!(updates(ctx, aad, data, len).map(|o| o.len()), Some(len));
            free(ctx);
        }
        teardown(&engine, raw);
    }

    // A copy mid-message carries the IV and AAD.
    #[test]
    #[allow(unsafe_code)]
    fn copies_keep_the_message() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [7u8; GCM_IV_LEN];
        let (aad, msg) = (pattern(10), pattern(33));
        let (ct, tag) = toy_seal(&iv, &aad, &msg);
        RELEASED.with(|c| c.set(0));
        let ctx = hsm_ctx(raw, true, &iv);
        assert!(add_aad(ctx, &aad));
        let dup = new_ctx();
        // SAFETY: copying a live context into a fresh one.
        assert_eq!(unsafe { ffi::EVP_CIPHER_CTX_copy(dup, ctx) }, OK);
        for c in [ctx, dup] {
            assert_eq!(updates(c, &[], &msg, msg.len()), Some(ct.clone()));
            assert_eq!(finish(c), Some(0));
            assert_eq!(get_tag(c, GCM_TAG_LEN), Some(tag.to_vec()));
        }
        free(ctx);
        assert_eq!(RELEASED.with(Cell::get), 0, "the copy still holds the key");
        free(dup);
        assert_eq!(RELEASED.with(Cell::get), 1);
        teardown(&engine, raw);
    }

    // An attach is also refused, before loading, while the IV length is not 12.
    #[test]
    fn last_key_set_wins() {
        let (engine, raw) = engine_with_ciphers();
        let (ours, builtin) = (our_cipher(raw, GCM_NID), builtin_cipher(GCM_NID).unwrap());
        let (iv, iv2) = ([1u8; GCM_IV_LEN], [2u8; GCM_IV_LEN]);
        let (aad, msg) = (pattern(5), pattern(40));
        RELEASED.with(|c| c.set(0));

        let ctx = hsm_ctx(raw, true, &iv);
        assert!(init(ctx, ours, raw, None, Some(&iv2), true));
        assert_eq!(
            updates(ctx, &aad, &msg, msg.len()),
            Some(toy_seal(&iv2, &aad, &msg).0)
        );
        assert_eq!(finish(ctx), Some(0));
        assert_eq!(RELEASED.with(Cell::get), 0, "the key must stay attached");

        assert!(init(
            ctx,
            null(),
            null_mut(),
            Some(&raw_key(GCM_NID)),
            Some(&iv),
            true
        ));
        assert_eq!(
            RELEASED.with(Cell::get),
            1,
            "the replaced key must be released"
        );
        let (software, _) = raw_seal(builtin, null_mut(), &iv, &aad, &msg, msg.len());
        assert_eq!(updates(ctx, &aad, &msg, msg.len()), Some(software));
        assert_eq!(finish(ctx), Some(0));

        let ivlen = ffi::EVP_CTRL_AEAD_SET_IVLEN;
        assert!(ctrl(ctx, ivlen, GCM_TAG_LEN, null_mut()));
        LAST_BITS.with(|c| c.set(0));
        assert!(!attach(ctx, Some(TOY_URI), 0), "a 16-byte IV length");
        assert_eq!(
            LAST_BITS.with(Cell::get),
            0,
            "refused before the key is loaded"
        );
        assert!(ctrl(ctx, ivlen, GCM_IV_LEN, null_mut()));
        assert!(attach(ctx, Some(TOY_URI), 0));
        assert!(init(ctx, null(), null_mut(), None, Some(&iv), true));
        assert_eq!(
            updates(ctx, &aad, &msg, msg.len()),
            Some(toy_seal(&iv, &aad, &msg).0)
        );
        assert_eq!(finish(ctx), Some(0));
        free(ctx);
        assert_eq!(RELEASED.with(Cell::get), 2);
        teardown(&engine, raw);
    }

    /// One context runs message after message, in either direction, each with
    /// its own IV and tag; a new message drops the last one's tag.
    #[test]
    fn context_reuse() {
        let (engine, raw) = engine_with_ciphers();
        let ivs = [[11u8; GCM_IV_LEN], [12u8; GCM_IV_LEN], [13u8; GCM_IV_LEN]];
        let (aad, msg) = (pattern(8), pattern(30));
        let ctx = hsm_ctx(raw, false, &ivs[0]);
        for iv in &ivs[..2] {
            let (ct, tag) = toy_seal(iv, &aad, &msg);
            assert_eq!(hsm_open(ctx, iv, &aad, &ct, Some(&tag)), Some(msg.clone()));
        }
        let (ct, _) = toy_seal(&ivs[1], &aad, &msg);
        assert_eq!(
            hsm_open(ctx, &ivs[1], &aad, &ct, None),
            None,
            "the last message's tag"
        );

        let (ct, tag) = toy_seal(&ivs[2], &aad, &msg);
        assert_eq!(
            hsm_seal(ctx, &ivs[2], &aad, &msg),
            Some((ct.clone(), tag.to_vec()))
        );
        assert_eq!(
            hsm_open(ctx, &ivs[2], &aad, &ct, None),
            None,
            "the encryption's tag"
        );
        assert_eq!(hsm_open(ctx, &ivs[2], &aad, &ct, Some(&tag)), Some(msg));
        free(ctx);
        teardown(&engine, raw);
    }

    /// A NULL tag pointer fails for an HSM key, a raw key and no key, and
    /// leaves the context usable.
    #[test]
    fn null_tag_fails_closed() {
        let (engine, raw) = engine_with_ciphers();
        let ours = our_cipher(raw, GCM_NID);
        let iv = [14u8; GCM_IV_LEN];
        let (aad, msg) = (pattern(6), pattern(20));
        let (ct, tag) = toy_seal(&iv, &aad, &msg);
        let (set, get) = (ffi::EVP_CTRL_AEAD_SET_TAG, ffi::EVP_CTRL_AEAD_GET_TAG);

        let ctx = hsm_ctx(raw, false, &iv);
        assert!(!ctrl(ctx, set, GCM_TAG_LEN, null_mut()), "HSM key, set");
        assert!(set_tag(ctx, &tag));
        assert_eq!(updates(ctx, &aad, &ct, ct.len()), Some(msg.clone()));
        free(ctx);
        let ctx = hsm_ctx(raw, true, &iv);
        assert_eq!(updates(ctx, &aad, &msg, msg.len()), Some(ct));
        assert_eq!(finish(ctx), Some(0));
        assert!(!ctrl(ctx, get, GCM_TAG_LEN, null_mut()), "HSM key, get");
        assert_eq!(get_tag(ctx, GCM_TAG_LEN), Some(tag.to_vec()));
        free(ctx);

        let key = raw_key(GCM_NID);
        let ctx = new_ctx();
        assert!(init(ctx, ours, raw, Some(&key), Some(&iv), false));
        assert!(!ctrl(ctx, set, GCM_TAG_LEN, null_mut()), "raw key, set");
        free(ctx);
        let ctx = new_ctx();
        assert!(init(ctx, ours, raw, Some(&key), Some(&iv), true));
        assert!(updates(ctx, &aad, &msg, msg.len()).is_some());
        assert_eq!(finish(ctx), Some(0));
        assert!(!ctrl(ctx, get, GCM_TAG_LEN, null_mut()), "raw key, get");
        assert!(get_tag(ctx, GCM_TAG_LEN).is_some());
        free(ctx);

        let ctx = new_ctx();
        assert!(init(ctx, ours, raw, None, Some(&iv), false));
        assert!(!ctrl(ctx, set, GCM_TAG_LEN, null_mut()), "no key, set");
        free(ctx);
        teardown(&engine, raw);
    }

    /// Without a key, the AAD, the data, the final and the tag all fail.
    #[test]
    fn no_key_fails_closed() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [15u8; GCM_IV_LEN];
        let (aad, msg) = (pattern(6), pattern(20));
        GCM_CALLS.with(|c| c.set(0));
        let ctx = new_ctx();
        assert!(init(
            ctx,
            our_cipher(raw, GCM_NID),
            raw,
            None,
            Some(&iv),
            true
        ));
        assert!(!add_aad(ctx, &aad), "AAD");
        assert_eq!(updates(ctx, &[], &msg, msg.len()), None, "data");
        assert_eq!(finish(ctx), None, "final");
        assert_eq!(get_tag(ctx, GCM_TAG_LEN), None, "tag");
        free(ctx);
        assert_eq!(GCM_CALLS.with(Cell::get), 0);
        teardown(&engine, raw);
    }

    /// Attaching a key over an attached one releases the old key and drops
    /// the open message: the next one needs a new IV.
    #[test]
    fn attach_replaces_an_attached_key() {
        let (engine, raw) = engine_with_ciphers();
        let iv = [16u8; GCM_IV_LEN];
        let (aad, msg) = (pattern(7), pattern(25));
        RELEASED.with(|c| c.set(0));
        let ctx = hsm_ctx(raw, true, &iv);
        assert!(add_aad(ctx, &aad));
        assert!(attach(ctx, Some(TOY_URI), 0));
        assert_eq!(
            RELEASED.with(Cell::get),
            1,
            "the replaced key must be released"
        );
        assert_eq!(updates(ctx, &[], &msg, msg.len()), None, "no IV");
        let (ct, tag) = toy_seal(&iv, &aad, &msg);
        assert_eq!(hsm_seal(ctx, &iv, &aad, &msg), Some((ct, tag.to_vec())));
        free(ctx);
        assert_eq!(RELEASED.with(Cell::get), 2);
        teardown(&engine, raw);
    }
}
