// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC `EVP_PKEY_METHOD` and key registry for HSM-backed HMAC keys.
//!
//! OpenSSL 1.1.1 has no `EVP_MAC`: HMAC runs through `EVP_PKEY_HMAC` keys and
//! `EVP_DigestSign*`, and the built-in method uses the key's payload (an
//! `ASN1_OCTET_STRING`) as the raw HMAC key. An HSM-backed key has no raw key,
//! so [`new_hmac_pkey`] gives it an empty payload (no data): the built-in
//! method refuses it at `EVP_DigestSignInit` (`HMAC_Init_ex` needs a key for a
//! new digest) instead of computing a MAC under a wrong key.
//!
//! Such a key is bound to the engine (`EVP_PKEY_set1_engine`), so its contexts
//! take the engine's HMAC method. The engine serves HMAC without advertising
//! it in its pkey-method list, so OpenSSL never makes it the default HMAC
//! method and other HMAC keys, e.g. libssl's, never reach it.
//!
//! The key behind an `EVP_PKEY` is found in a process-global registry by a
//! token stored as the payload's ASN1 type: unique per key and outside the
//! `V_ASN1_*` types, so no other HMAC key matches an entry, not even one that
//! reuses a freed key's memory. 1.1.1 reports no key free to an engine, so
//! entries stay until [`release_hmac_keys`] at engine teardown. `EVP_PKEY_cmp`
//! compares the payloads, so two different keys never compare equal.
//!
//! The method built by [`new_hmac_pkey_method`] copies the built-in HMAC method
//! and handles contexts on a registered key itself: the message is buffered
//! (the HSM computes HMAC in one call, over at most [`HMAC_MAX_MESSAGE`] bytes)
//! and MACed on the HSM at the final. Every other context runs the built-in
//! callbacks.

use std::collections::HashMap;
use std::ffi::c_int;
use std::ffi::c_uchar;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;

use parking_lot::Mutex;
use tsra_ossl_engine_sys as ffi;
use zeroize::Zeroizing;

use crate::engine::Engine;
use crate::error::CTRL_UNSUPPORTED;
use crate::error::EngineError;
use crate::error::EngineResult;
use crate::error::RetCode;
use crate::error::catch_panic;
use crate::error::ossl_check;
use crate::error::ossl_ok;
use crate::error::result_to_int;
use crate::pkey_method::ENGINE_METHODS;

/// Most message bytes one HMAC covers: the HSM's limit for a single HMAC call.
pub const HMAC_MAX_MESSAGE: usize = 1024;

/// An HSM HMAC key, as the engine registers it with [`new_hmac_pkey`].
pub trait HmacKey: Send + Sync {
    /// NID of the digest the key computes with (fixed by its key kind).
    fn md_nid(&self) -> c_int;

    /// MAC length in bytes.
    fn mac_len(&self) -> usize;

    /// HMAC over `message` (at most [`HMAC_MAX_MESSAGE`] bytes) with the HSM
    /// of `engine`, the engine the key was registered with.
    fn sign(&self, engine: &Engine, message: &[u8]) -> EngineResult<Vec<u8>>;
}

/// A registry entry: the engine the key belongs to (for teardown) and the key.
struct Entry {
    engine: usize,
    key: Arc<dyn HmacKey>,
}

/// Registered keys by token. Shared ownership lets an operation run the HSM
/// call without holding the registry lock.
static KEYS: OnceLock<Mutex<HashMap<c_int, Entry>>> = OnceLock::new();

/// The registry.
fn keys() -> &'static Mutex<HashMap<c_int, Entry>> {
    KEYS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Tokens are this bit plus an even counter: above every `V_ASN1_*` type, and
/// no two differ by 1, which 1.1.1f's HMAC `EVP_PKEY_cmp` (it returns the
/// payloads' `ASN1_STRING_cmp` difference) reports as equal.
const TOKEN_BASE: c_int = 0x4000_0000;

/// Counter behind [`next_token`].
static NEXT_TOKEN: AtomicI32 = AtomicI32::new(0);

/// A token no registered key has.
fn next_token() -> c_int {
    TOKEN_BASE | (NEXT_TOKEN.fetch_add(2, Ordering::Relaxed) & (TOKEN_BASE - 2))
}

/// The registered engine address and key behind `pkey`, if it is one of ours.
#[allow(unsafe_code)]
fn key_of(pkey: *const ffi::EVP_PKEY) -> Option<(usize, Arc<dyn HmacKey>)> {
    if pkey.is_null() {
        return None;
    }
    // SAFETY: pkey is a live EVP_PKEY; base_id reads its type, get0 its payload
    // (an ASN1 string for an HMAC key), get0_data and type that payload's
    // bytes and type.
    let token = unsafe {
        if ffi::EVP_PKEY_base_id(pkey) != ffi::EVP_PKEY_HMAC as c_int {
            return None;
        }
        let payload = ffi::EVP_PKEY_get0(pkey);
        if payload.is_null() || !ffi::ASN1_STRING_get0_data(payload.cast()).is_null() {
            return None;
        }
        ffi::ASN1_STRING_type(payload.cast())
    };
    keys()
        .lock()
        .get(&token)
        .map(|entry| (entry.engine, Arc::clone(&entry.key)))
}

/// Drop `engine`'s registry entries. Call from the engine's destroy hook.
pub fn release_hmac_keys(engine: &Engine) {
    let e = engine.as_ptr() as usize;
    keys().lock().retain(|_, entry| entry.engine != e);
}

/// A new `EVP_PKEY_HMAC` for `key`, bound to `engine`: its payload is empty
/// and carries the key's token, and HMAC with it runs on the HSM through this
/// module's method.
#[allow(unsafe_code)]
pub fn new_hmac_pkey(engine: &Engine, key: Box<dyn HmacKey>) -> EngineResult<*mut ffi::EVP_PKEY> {
    let token = next_token();
    // SAFETY: fresh objects; EVP_PKEY_assign takes the string on success,
    // otherwise it is freed here.
    let pkey = unsafe {
        let payload = ffi::ASN1_STRING_type_new(token);
        if payload.is_null() {
            return Err(EngineError::Other("ASN1_STRING_type_new failed".into()));
        }
        let pkey = ffi::EVP_PKEY_new();
        if pkey.is_null() {
            ffi::ASN1_STRING_free(payload);
            return Err(EngineError::Other("EVP_PKEY_new failed".into()));
        }
        if !ossl_ok(ffi::EVP_PKEY_assign(
            pkey,
            ffi::EVP_PKEY_HMAC as c_int,
            payload.cast(),
        )) {
            ffi::ASN1_STRING_free(payload);
            ffi::EVP_PKEY_free(pkey);
            return Err(EngineError::Other("EVP_PKEY_assign(HMAC) failed".into()));
        }
        pkey
    };
    // SAFETY: binds the key's pkey-method engine, so contexts on it resolve
    // to this engine's HMAC method.
    let rc = unsafe { ffi::EVP_PKEY_set1_engine(pkey, engine.as_ptr()) };
    if let Err(e) = ossl_check(rc, "EVP_PKEY_set1_engine failed") {
        // SAFETY: pkey is ours and not registered.
        unsafe { ffi::EVP_PKEY_free(pkey) };
        return Err(e);
    }
    keys().lock().insert(
        token,
        Entry {
            engine: engine.as_ptr() as usize,
            key: Arc::from(key),
        },
    );
    Ok(pkey)
}

/// Per-context state of a context on a registered key.
struct CtxState {
    /// Address of the key's engine; the key's `EVP_PKEY` keeps it alive.
    engine: usize,
    key: Arc<dyn HmacKey>,
    /// The message so far. It may be secret, so it is scrubbed on drop; see
    /// [`new_message`].
    message: Zeroizing<Vec<u8>>,
}

impl Clone for CtxState {
    /// A copy with the full message capacity (see [`new_message`]).
    fn clone(&self) -> Self {
        let mut message = new_message();
        message.extend_from_slice(&self.message);
        Self {
            engine: self.engine,
            key: Arc::clone(&self.key),
            message,
        }
    }
}

/// An empty message buffer for [`HMAC_MAX_MESSAGE`] bytes: it never
/// reallocates, which would leave unscrubbed message bytes behind.
fn new_message() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(Vec::with_capacity(HMAC_MAX_MESSAGE))
}

/// Side table: `EVP_PKEY_CTX` address → state, created in `init` for contexts
/// on a registered key and dropped in `cleanup`.
static CTX_STATE: OnceLock<Mutex<HashMap<usize, CtxState>>> = OnceLock::new();

/// The context side table.
fn ctx_state() -> &'static Mutex<HashMap<usize, CtxState>> {
    CTX_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The built-in HMAC callbacks, captured when the method is built.
#[derive(Clone, Copy, Default)]
struct Defaults {
    init: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX) -> c_int>,
    copy: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX, *mut ffi::EVP_PKEY_CTX) -> c_int>,
    cleanup: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX)>,
    signctx_init:
        Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX, *mut ffi::EVP_MD_CTX) -> c_int>,
    signctx: Option<
        unsafe extern "C" fn(
            *mut ffi::EVP_PKEY_CTX,
            *mut c_uchar,
            *mut usize,
            *mut ffi::EVP_MD_CTX,
        ) -> c_int,
    >,
    ctrl: Option<unsafe extern "C" fn(*mut ffi::EVP_PKEY_CTX, c_int, c_int, *mut c_void) -> c_int>,
}

static DEFAULTS: OnceLock<Defaults> = OnceLock::new();

/// The captured built-in callbacks.
fn defaults() -> EngineResult<Defaults> {
    DEFAULTS.get().copied().ok_or(EngineError::Other(
        "HMAC pkey method defaults missing".into(),
    ))
}

/// `init` override: the built-in init, plus state for a context on a
/// registered key.
/// # Safety
/// Called only by OpenSSL during `EVP_PKEY_CTX` construction.
#[allow(unsafe_code)]
unsafe extern "C" fn c_init(ctx: *mut ffi::EVP_PKEY_CTX) -> c_int {
    catch_panic(
        || {
            // The HMAC method needs no engine handoff; consume it so it does
            // not linger for the next context.
            let _ = crate::method_table::take_pending_engine();
            let Ok(d) = defaults() else {
                return RetCode::Fail.into();
            };
            if let Some(init) = d.init {
                // SAFETY: delegating the ctx OpenSSL passed us.
                if !ossl_ok(unsafe { init(ctx) }) {
                    return RetCode::Fail.into();
                }
            }
            // SAFETY: ctx is the context being initialized; pkey is NULL for
            // key generation.
            let pkey = unsafe { ffi::EVP_PKEY_CTX_get0_pkey(ctx) };
            if let Some((engine, key)) = key_of(pkey) {
                ctx_state().lock().insert(
                    ctx as usize,
                    CtxState {
                        engine,
                        key,
                        message: new_message(),
                    },
                );
            }
            RetCode::Success.into()
        },
        RetCode::Fail.into(),
    )
}

/// `copy` override: on a registered key, a fresh built-in state (inherited
/// callbacks such as keygen read it; the source's HMAC state was never keyed
/// and cannot be copied) and a copy of the state, including the message so
/// far (`EVP_DigestSignFinal` finalizes on a copy). Otherwise the built-in
/// copy.
/// # Safety
/// Called only by OpenSSL during `EVP_PKEY_CTX_dup`.
#[allow(unsafe_code)]
unsafe extern "C" fn c_copy(dst: *mut ffi::EVP_PKEY_CTX, src: *mut ffi::EVP_PKEY_CTX) -> c_int {
    catch_panic(
        || {
            let Ok(d) = defaults() else {
                return RetCode::Fail.into();
            };
            let state = ctx_state().lock().get(&(src as usize)).cloned();
            if let Some(state) = state {
                if let Some(init) = d.init {
                    // SAFETY: dst is the new context, its built-in data unset.
                    if !ossl_ok(unsafe { init(dst) }) {
                        return RetCode::Fail.into();
                    }
                }
                ctx_state().lock().insert(dst as usize, state);
                return RetCode::Success.into();
            }
            let Some(copy) = d.copy else {
                return RetCode::Fail.into();
            };
            // SAFETY: delegating the ctx pair OpenSSL passed us.
            unsafe { copy(dst, src) }
        },
        RetCode::Fail.into(),
    )
}

/// `cleanup` override: drop the state, then the built-in cleanup.
/// # Safety
/// Called only by OpenSSL during `EVP_PKEY_CTX_free`.
#[allow(unsafe_code)]
unsafe extern "C" fn c_cleanup(ctx: *mut ffi::EVP_PKEY_CTX) {
    catch_panic(
        || {
            ctx_state().lock().remove(&(ctx as usize));
            if let Ok(d) = defaults()
                && let Some(cleanup) = d.cleanup
            {
                // SAFETY: delegating the ctx OpenSSL passed us, exactly once.
                unsafe { cleanup(ctx) };
            }
        },
        (),
    );
}

/// Whether `ctx` is on a registered key.
fn owned(ctx: *mut ffi::EVP_PKEY_CTX) -> bool {
    ctx_state().lock().contains_key(&(ctx as usize))
}

/// `signctx_init` override: on a registered key, route the digest updates to
/// [`c_update`] (no digest runs); otherwise the built-in.
/// # Safety
/// Called only by OpenSSL's `EVP_DigestSignInit`.
#[allow(unsafe_code)]
unsafe extern "C" fn c_signctx_init(
    ctx: *mut ffi::EVP_PKEY_CTX,
    mctx: *mut ffi::EVP_MD_CTX,
) -> c_int {
    catch_panic(
        || {
            if !owned(ctx) {
                let Some(signctx_init) = defaults().ok().and_then(|d| d.signctx_init) else {
                    return RetCode::Fail.into();
                };
                // SAFETY: delegating the arguments OpenSSL passed us.
                return unsafe { signctx_init(ctx, mctx) };
            }
            // SAFETY: mctx is the digest context being initialized; NO_INIT
            // skips the digest's own init and the update hook replaces it.
            unsafe {
                ffi::EVP_MD_CTX_set_flags(mctx, ffi::EVP_MD_CTX_FLAG_NO_INIT_CONST);
                ffi::EVP_MD_CTX_set_update_fn(mctx, Some(c_update));
            }
            RetCode::Success.into()
        },
        RetCode::Fail.into(),
    )
}

/// Digest-update hook for a registered key: append to the message, refusing
/// more than [`HMAC_MAX_MESSAGE`] bytes in total.
/// # Safety
/// Installed by [`c_signctx_init`]; called by `EVP_DigestSignUpdate` with
/// `data` holding `count` bytes.
#[allow(unsafe_code)]
unsafe extern "C" fn c_update(
    mctx: *mut ffi::EVP_MD_CTX,
    data: *const c_void,
    count: usize,
) -> c_int {
    catch_panic(
        // SAFETY: forwarding the arguments OpenSSL passed us.
        || result_to_int(unsafe { update_inner(mctx, data, count) }),
        RetCode::Fail.into(),
    )
}

/// Inner body of [`c_update`].
///
/// # Safety
/// As [`c_update`].
#[allow(unsafe_code)]
unsafe fn update_inner(
    mctx: *mut ffi::EVP_MD_CTX,
    data: *const c_void,
    count: usize,
) -> EngineResult<()> {
    // SAFETY: mctx is a live digest context with a pkey context.
    let ctx = unsafe { ffi::EVP_MD_CTX_pkey_ctx(mctx) };
    let mut table = ctx_state().lock();
    let state = table
        .get_mut(&(ctx as usize))
        .ok_or(EngineError::Other("HMAC context has no HSM key".into()))?;
    if count == 0 {
        return Ok(());
    }
    if data.is_null() {
        return Err(EngineError::NullParam("data"));
    }
    if state.message.len().saturating_add(count) > HMAC_MAX_MESSAGE {
        return Err(EngineError::Other(format!(
            "HMAC with an HSM key covers at most {HMAC_MAX_MESSAGE} message bytes"
        )));
    }
    // SAFETY: data holds count bytes.
    state
        .message
        .extend_from_slice(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), count) });
    Ok(())
}

/// `signctx` override: on a registered key, the MAC size or the HSM MAC over
/// the message; otherwise the built-in.
/// # Safety
/// Called only by OpenSSL's `EVP_DigestSignFinal`.
#[allow(unsafe_code)]
unsafe extern "C" fn c_signctx(
    ctx: *mut ffi::EVP_PKEY_CTX,
    sig: *mut c_uchar,
    siglen: *mut usize,
    mctx: *mut ffi::EVP_MD_CTX,
) -> c_int {
    catch_panic(
        || {
            if !owned(ctx) {
                let Some(signctx) = defaults().ok().and_then(|d| d.signctx) else {
                    return RetCode::Fail.into();
                };
                // SAFETY: delegating the arguments OpenSSL passed us.
                return unsafe { signctx(ctx, sig, siglen, mctx) };
            }
            // SAFETY: forwarding the arguments OpenSSL passed us.
            result_to_int(unsafe { signctx_inner(ctx, sig, siglen) })
        },
        RetCode::Fail.into(),
    )
}

/// Inner body of [`c_signctx`] for a registered key.
///
/// # Safety
/// `sig` is NULL (size query) or holds `*siglen` bytes.
#[allow(unsafe_code)]
unsafe fn signctx_inner(
    ctx: *mut ffi::EVP_PKEY_CTX,
    sig: *mut c_uchar,
    siglen: *mut usize,
) -> EngineResult<()> {
    if siglen.is_null() {
        return Err(EngineError::NullParam("siglen"));
    }
    let state = ctx_state()
        .lock()
        .get(&(ctx as usize))
        .cloned()
        .ok_or(EngineError::Other("HMAC context has no HSM key".into()))?;
    let mac_len = state.key.mac_len();
    if sig.is_null() {
        // SAFETY: siglen is a valid out-param.
        unsafe { *siglen = mac_len };
        return Ok(());
    }
    // SAFETY: siglen is valid; it holds the size of sig.
    if unsafe { *siglen } < mac_len {
        return Err(EngineError::Other(format!(
            "HMAC output buffer holds fewer than {mac_len} bytes"
        )));
    }
    let engine_ptr = NonNull::new(state.engine as *mut ffi::ENGINE)
        .ok_or(EngineError::NullParam("HMAC key engine"))?;
    // SAFETY: the key's EVP_PKEY, which this context holds, keeps a reference
    // on its engine.
    let engine = unsafe { Engine::from_ptr(engine_ptr) };
    let mac = state.key.sign(&engine, &state.message)?;
    if mac.len() > mac_len {
        return Err(EngineError::Other("HSM returned an oversized HMAC".into()));
    }
    // SAFETY: sig holds at least mac_len >= mac.len() bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(mac.as_ptr(), sig, mac.len());
        *siglen = mac.len();
    }
    Ok(())
}

/// `ctrl` override: on a registered key, check the digest (it must be the
/// key's) and refuse a raw MAC key; otherwise the built-in.
/// # Safety
/// Called only by OpenSSL's `EVP_PKEY_CTX_ctrl`.
#[allow(unsafe_code)]
unsafe extern "C" fn c_ctrl(
    ctx: *mut ffi::EVP_PKEY_CTX,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    catch_panic(
        || {
            if !owned(ctx) {
                let Some(ctrl) = defaults().ok().and_then(|d| d.ctrl) else {
                    return CTRL_UNSUPPORTED;
                };
                // SAFETY: delegating the arguments OpenSSL passed us.
                return unsafe { ctrl(ctx, cmd, p1, p2) };
            }
            match cmd {
                c if c == ffi::EVP_PKEY_CTRL_MD_CONST => {
                    // SAFETY: for EVP_PKEY_CTRL_MD, p2 is the EVP_MD to use.
                    result_to_int(unsafe { check_md(ctx, p2.cast::<ffi::EVP_MD>()) })
                }
                // The digest init: start a new message.
                c if c == ffi::EVP_PKEY_CTRL_DIGESTINIT_CONST => {
                    if let Some(state) = ctx_state().lock().get_mut(&(ctx as usize)) {
                        state.message.clear();
                    }
                    RetCode::Success.into()
                }
                c if c == ffi::EVP_PKEY_CTRL_SET_MAC_KEY_CONST => result_to_int::<()>(Err(
                    EngineError::Other("an HSM HMAC key takes no raw key".into()),
                )),
                _ => CTRL_UNSUPPORTED,
            }
        },
        RetCode::Fail.into(),
    )
}

/// Refuse a digest other than the one the key computes with.
///
/// # Safety
/// `md` is NULL or a valid `EVP_MD`.
#[allow(unsafe_code)]
unsafe fn check_md(ctx: *mut ffi::EVP_PKEY_CTX, md: *const ffi::EVP_MD) -> EngineResult<()> {
    if md.is_null() {
        return Err(EngineError::NullParam("md"));
    }
    let want = ctx_state()
        .lock()
        .get(&(ctx as usize))
        .map(|state| state.key.md_nid())
        .ok_or(EngineError::Other("HMAC context has no HSM key".into()))?;
    // SAFETY: md is a valid EVP_MD.
    let got = unsafe { ffi::EVP_MD_type(md) };
    if got != want {
        return Err(EngineError::Other(format!(
            "the HMAC key computes with digest {}, not {}",
            digest_name(want),
            digest_name(got)
        )));
    }
    Ok(())
}

/// Short name of the digest `nid` (e.g. "SHA256").
#[allow(unsafe_code)]
fn digest_name(nid: c_int) -> String {
    // SAFETY: OBJ_nid2sn returns NULL or a static NUL-terminated string.
    let name = unsafe { ffi::OBJ_nid2sn(nid) };
    if name.is_null() {
        return format!("NID {nid}");
    }
    // SAFETY: name is a static NUL-terminated string.
    unsafe { std::ffi::CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned()
}

/// Build the HMAC `EVP_PKEY_METHOD`: a copy of the built-in with the context
/// lifecycle, `signctx` and `ctrl` overridden as described in the module docs.
#[allow(unsafe_code)]
pub fn new_hmac_pkey_method() -> EngineResult<*mut ffi::EVP_PKEY_METHOD> {
    // SAFETY: EVP_PKEY_meth_find returns the built-in const method.
    let builtin = unsafe { ffi::EVP_PKEY_meth_find(ffi::EVP_PKEY_HMAC as c_int) };
    if builtin.is_null() {
        return Err(EngineError::Other("built-in HMAC method missing".into()));
    }
    let mut d = Defaults::default();
    let mut ctrl_str = None;
    // SAFETY: builtin is a valid method; the getters write the out-params.
    unsafe {
        ffi::EVP_PKEY_meth_get_init(builtin, &mut d.init);
        ffi::EVP_PKEY_meth_get_copy(builtin, &mut d.copy);
        ffi::EVP_PKEY_meth_get_cleanup(builtin, &mut d.cleanup);
        ffi::EVP_PKEY_meth_get_signctx(builtin, &mut d.signctx_init, &mut d.signctx);
        ffi::EVP_PKEY_meth_get_ctrl(builtin, &mut d.ctrl, &mut ctrl_str);
    }
    let _ = DEFAULTS.set(d);

    // SAFETY: fresh method; meth_copy duplicates the built-in callbacks (incl.
    // keygen and ctrl_str); the setters install our overrides.
    unsafe {
        let method = ffi::EVP_PKEY_meth_new(ffi::EVP_PKEY_HMAC as c_int, 0);
        if method.is_null() {
            return Err(EngineError::Other("EVP_PKEY_meth_new failed".into()));
        }
        ffi::EVP_PKEY_meth_copy(method, builtin);
        ffi::EVP_PKEY_meth_set_init(method, Some(c_init));
        ffi::EVP_PKEY_meth_set_copy(method, Some(c_copy));
        ffi::EVP_PKEY_meth_set_cleanup(method, Some(c_cleanup));
        ffi::EVP_PKEY_meth_set_signctx(method, Some(c_signctx_init), Some(c_signctx));
        ffi::EVP_PKEY_meth_set_ctrl(method, Some(c_ctrl), ctrl_str);
        Ok(method)
    }
}

/// Register the HMAC method in `engine`'s pkey-method table. Released with the
/// other methods via
/// [`release_pkey_methods`](crate::pkey_method::release_pkey_methods).
pub fn register_hmac_pkey_method(engine: &Engine) -> EngineResult<()> {
    ENGINE_METHODS.register(engine, ffi::EVP_PKEY_HMAC as c_int, new_hmac_pkey_method)?;
    crate::pkey_method::install_pkey_meths_callback(engine)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::ptr::NonNull;
    use std::ptr::null_mut;

    use super::*;

    /// RFC 4231 test case 2: key, message and HMAC-SHA256.
    const RFC4231_KEY: &[u8] = b"Jefe";
    const RFC4231_MSG: &[u8] = b"what do ya want for nothing?";
    const RFC4231_MAC: [u8; 32] = [
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
        0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
        0x38, 0x43,
    ];

    /// A software HMAC-SHA256 key `key`.
    #[allow(unsafe_code)]
    fn software_key(key: &[u8]) -> *mut ffi::EVP_PKEY {
        // SAFETY: builds a key from a byte slice; the caller frees it.
        let pkey = unsafe {
            ffi::EVP_PKEY_new_raw_private_key(
                ffi::EVP_PKEY_HMAC as c_int,
                null_mut(),
                key.as_ptr(),
                key.len(),
            )
        };
        assert!(!pkey.is_null(), "software HMAC key");
        pkey
    }

    /// MAC `chunks` (one update each) with `pkey` and `md` through
    /// `EVP_DigestSign*`; the OpenSSL error text on failure.
    #[allow(unsafe_code)]
    fn try_mac(
        pkey: *mut ffi::EVP_PKEY,
        md: *const ffi::EVP_MD,
        chunks: &[&[u8]],
    ) -> Result<Vec<u8>, String> {
        // SAFETY: the EVP_DigestSign sequence on a live key; the context is
        // freed on every path.
        unsafe {
            let ctx = ffi::EVP_MD_CTX_new();
            assert!(!ctx.is_null());
            let ok = (|| {
                if ffi::EVP_DigestSignInit(ctx, null_mut(), md, null_mut(), pkey) != 1 {
                    return None;
                }
                for chunk in chunks {
                    if ffi::EVP_DigestUpdate(ctx, chunk.as_ptr().cast(), chunk.len()) != 1 {
                        return None;
                    }
                }
                let mut len = 0usize;
                if ffi::EVP_DigestSignFinal(ctx, null_mut(), &mut len) != 1 {
                    return None;
                }
                let mut mac = vec![0u8; len];
                if ffi::EVP_DigestSignFinal(ctx, mac.as_mut_ptr(), &mut len) != 1 {
                    return None;
                }
                mac.truncate(len);
                Some(mac)
            })();
            ffi::EVP_MD_CTX_free(ctx);
            ok.ok_or_else(|| {
                let mut text = String::new();
                loop {
                    let code = ffi::ERR_get_error();
                    if code == 0 {
                        break;
                    }
                    text.push_str(&format!("{code:x};"));
                }
                text
            })
        }
    }

    /// A stand-in HSM key: software HMAC-SHA256 under the RFC 4231 key.
    struct SoftwareBackedKey;
    impl HmacKey for SoftwareBackedKey {
        fn md_nid(&self) -> c_int {
            ffi::NID_sha256 as c_int
        }
        fn mac_len(&self) -> usize {
            RFC4231_MAC.len()
        }
        #[allow(unsafe_code)]
        fn sign(&self, _engine: &Engine, message: &[u8]) -> EngineResult<Vec<u8>> {
            let key = software_key(RFC4231_KEY);
            // SAFETY: EVP_sha256 returns a process-lifetime constant.
            let mac = try_mac(key, unsafe { ffi::EVP_sha256() }, &[message]);
            // SAFETY: key is ours.
            unsafe { ffi::EVP_PKEY_free(key) };
            mac.map_err(|e| EngineError::Other(format!("software HMAC: {e}")))
        }
    }

    /// An engine serving the HMAC method, and an engine key on it.
    #[allow(unsafe_code)]
    fn engine_and_key() -> (*mut ffi::ENGINE, Engine, *mut ffi::EVP_PKEY) {
        // SAFETY: a fresh ENGINE, freed by `teardown`.
        let raw = unsafe { ffi::ENGINE_new() };
        // SAFETY: raw is non-null and lives until `teardown`.
        let engine = unsafe { Engine::from_ptr(NonNull::new(raw).unwrap()) };
        register_hmac_pkey_method(&engine).unwrap();
        let pkey = new_hmac_pkey(&engine, Box::new(SoftwareBackedKey)).unwrap();
        (raw, engine, pkey)
    }

    /// Free `pkey`, drop the engine's keys and methods, free the engine.
    #[allow(unsafe_code)]
    fn teardown(raw: *mut ffi::ENGINE, engine: &Engine, pkey: *mut ffi::EVP_PKEY) {
        // SAFETY: pkey is ours; it holds an engine reference, so it goes first.
        unsafe { ffi::EVP_PKEY_free(pkey) };
        release_hmac_keys(engine);
        crate::pkey_method::release_pkey_methods(engine);
        // SAFETY: raw is the ENGINE_new reference.
        unsafe { ffi::ENGINE_free(raw) };
    }

    /// An engine key MACs through the key, in one update or in pieces, and a
    /// 1024-byte message is accepted.
    #[test]
    #[allow(unsafe_code)]
    fn engine_key_macs_through_its_key() {
        let (raw, engine, pkey) = engine_and_key();
        // SAFETY: EVP_sha256 returns a process-lifetime constant.
        let sha256 = unsafe { ffi::EVP_sha256() };
        assert_eq!(try_mac(pkey, sha256, &[RFC4231_MSG]).unwrap(), RFC4231_MAC);
        let (a, b) = RFC4231_MSG.split_at(10);
        assert_eq!(try_mac(pkey, sha256, &[a, &[], b]).unwrap(), RFC4231_MAC);
        let long = vec![0x5a; HMAC_MAX_MESSAGE];
        assert_eq!(
            try_mac(pkey, sha256, &[&long]).unwrap(),
            SoftwareBackedKey.sign(&engine, &long).unwrap()
        );
        teardown(raw, &engine, pkey);
    }

    /// A digest other than the key's, more than 1024 bytes (at the update that
    /// crosses the limit) and a short output buffer are refused.
    #[test]
    #[allow(unsafe_code)]
    fn engine_key_refuses_bad_use() {
        let (raw, engine, pkey) = engine_and_key();
        // SAFETY: the EVP digest accessors return process-lifetime constants.
        let (sha256, sha384, sha1) =
            unsafe { (ffi::EVP_sha256(), ffi::EVP_sha384(), ffi::EVP_sha1()) };
        assert!(
            try_mac(pkey, sha384, &[b"m"]).is_err(),
            "SHA-384 on a SHA-256 key"
        );
        assert!(try_mac(pkey, sha1, &[b"m"]).is_err(), "SHA-1");
        let long = vec![0x5a; HMAC_MAX_MESSAGE + 1];
        assert!(
            try_mac(pkey, sha256, &[&long[..1000], &long[1000..]]).is_err(),
            "1025 bytes"
        );
        // SAFETY: the EVP_DigestSign sequence on a live key; ctx freed below.
        unsafe {
            let ctx = ffi::EVP_MD_CTX_new();
            assert_eq!(
                ffi::EVP_DigestSignInit(ctx, null_mut(), sha256, null_mut(), pkey),
                1
            );
            let mut short = [0u8; 16];
            let mut len = short.len();
            assert_ne!(
                ffi::EVP_DigestSignFinal(ctx, short.as_mut_ptr(), &mut len),
                1,
                "a 16-byte buffer for a 32-byte MAC"
            );
            ffi::EVP_MD_CTX_free(ctx);
            ffi::ERR_clear_error();
        }
        teardown(raw, &engine, pkey);
    }

    /// Software HMAC keys run the built-in unchanged, and one without key
    /// bytes is refused; an engine key whose entry was released is refused.
    #[test]
    #[allow(unsafe_code)]
    fn other_keys_run_the_builtin() {
        let (raw, engine, pkey) = engine_and_key();
        // SAFETY: EVP_sha256 returns a process-lifetime constant; the keys
        // built here are freed below.
        unsafe {
            let sha256 = ffi::EVP_sha256();
            let sw = software_key(RFC4231_KEY);
            assert_eq!(try_mac(sw, sha256, &[RFC4231_MSG]).unwrap(), RFC4231_MAC);
            ffi::EVP_PKEY_free(sw);

            let empty = ffi::EVP_PKEY_new();
            assert_eq!(
                ffi::EVP_PKEY_assign(
                    empty,
                    ffi::EVP_PKEY_HMAC as c_int,
                    ffi::ASN1_STRING_new().cast()
                ),
                1
            );
            assert!(try_mac(empty, sha256, &[b"m"]).is_err(), "no key bytes");
            ffi::EVP_PKEY_free(empty);

            release_hmac_keys(&engine);
            assert!(try_mac(pkey, sha256, &[b"m"]).is_err(), "released key");
        }
        teardown(raw, &engine, pkey);
    }

    /// Only a registered key's own payload finds it: an empty HMAC key bound
    /// to the engine is refused, also one allocated right after an engine key
    /// was freed (which typically reuses its memory), and two engine keys
    /// compare unequal.
    #[test]
    #[allow(unsafe_code)]
    fn registry_finds_only_registered_keys() {
        let (raw, engine, pkey) = engine_and_key();
        // SAFETY: EVP_sha256 returns a process-lifetime constant; the keys
        // built here are freed below.
        unsafe {
            let sha256 = ffi::EVP_sha256();
            let other = new_hmac_pkey(&engine, Box::new(SoftwareBackedKey)).unwrap();
            assert_ne!(ffi::EVP_PKEY_cmp(pkey, other), 1);
            assert_ne!(ffi::EVP_PKEY_cmp(other, pkey), 1);
            ffi::EVP_PKEY_free(other);

            let foreign = ffi::EVP_PKEY_new();
            assert_eq!(
                ffi::EVP_PKEY_assign(
                    foreign,
                    ffi::EVP_PKEY_HMAC as c_int,
                    ffi::ASN1_STRING_new().cast()
                ),
                1
            );
            assert_eq!(ffi::EVP_PKEY_set1_engine(foreign, engine.as_ptr()), 1);
            assert!(try_mac(foreign, sha256, &[b"m"]).is_err(), "foreign key");
            ffi::EVP_PKEY_free(foreign);
        }
        teardown(raw, &engine, pkey);
    }

    /// A copied signing context carries on with the message so far, apart
    /// from the original.
    #[test]
    #[allow(unsafe_code)]
    fn copied_context_continues_the_message() {
        let (raw, engine, pkey) = engine_and_key();
        let (a, b) = RFC4231_MSG.split_at(10);
        // SAFETY: the EVP_DigestSign sequence on a live key; both contexts
        // are freed below.
        unsafe {
            let ctx = ffi::EVP_MD_CTX_new();
            let copy = ffi::EVP_MD_CTX_new();
            assert_eq!(
                ffi::EVP_DigestSignInit(ctx, null_mut(), ffi::EVP_sha256(), null_mut(), pkey),
                1
            );
            assert_eq!(ffi::EVP_DigestUpdate(ctx, a.as_ptr().cast(), a.len()), 1);
            assert_eq!(ffi::EVP_MD_CTX_copy_ex(copy, ctx), 1);
            assert_eq!(ffi::EVP_DigestUpdate(copy, b.as_ptr().cast(), b.len()), 1);
            for (mctx, want) in [
                (copy, RFC4231_MAC.to_vec()),
                (ctx, SoftwareBackedKey.sign(&engine, a).unwrap()),
            ] {
                let mut mac = [0u8; 32];
                let mut len = mac.len();
                assert_eq!(
                    ffi::EVP_DigestSignFinal(mctx, mac.as_mut_ptr(), &mut len),
                    1
                );
                assert_eq!(mac[..len], want[..]);
            }
            ffi::EVP_MD_CTX_free(copy);
            ffi::EVP_MD_CTX_free(ctx);
        }
        teardown(raw, &engine, pkey);
    }

    /// A state copy keeps the full message capacity, so updates on it never
    /// reallocate the message.
    #[test]
    fn state_copy_keeps_message_capacity() {
        let mut state = CtxState {
            engine: 0,
            key: Arc::new(SoftwareBackedKey),
            message: new_message(),
        };
        state.message.extend_from_slice(b"abc");
        let copy = state.clone();
        assert_eq!(copy.message.as_slice(), b"abc");
        assert!(copy.message.capacity() >= HMAC_MAX_MESSAGE);
    }

    /// Key generation on a duplicate of an engine-key context fails cleanly:
    /// the duplicate has the built-in state the inherited keygen reads.
    #[test]
    #[allow(unsafe_code)]
    fn duplicated_context_refuses_keygen() {
        let (raw, engine, pkey) = engine_and_key();
        // SAFETY: contexts on a live key, freed below.
        unsafe {
            let ctx = ffi::EVP_PKEY_CTX_new(pkey, null_mut());
            assert!(!ctx.is_null());
            let dup = ffi::EVP_PKEY_CTX_dup(ctx);
            assert!(!dup.is_null());
            assert_eq!(ffi::EVP_PKEY_keygen_init(dup), 1);
            let mut generated = null_mut();
            assert_ne!(ffi::EVP_PKEY_keygen(dup, &mut generated), 1);
            assert!(generated.is_null());
            ffi::EVP_PKEY_CTX_free(dup);
            ffi::EVP_PKEY_CTX_free(ctx);
            ffi::ERR_clear_error();
        }
        teardown(raw, &engine, pkey);
    }
}
