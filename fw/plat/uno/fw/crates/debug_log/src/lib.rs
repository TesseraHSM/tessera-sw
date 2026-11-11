// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Debug-log records for the Uno platform.
//!
//! With the tracing facade's `debug-log` feature, a bare-metal target
//! (`target_os = "none"`), and no `level-*` feature, the facade passes each
//! `error!`, `warn!`, and `info!` call to this crate's macro of the same
//! name. The macro records the call, or drops it:
//!
//! - **Record.** A call that fits a record (see "Calls that fit") passes one
//!   record to the platform's `__hsm_log_record`.
//! - **Drop.** Outside `fw/plat/uno/`, a call that doesn't fit leaves no
//!   record and formats nothing. Where the compiler generates code for it,
//!   it leaves a drop note, which the Uno xtask prints as a warning. Under
//!   `fw/plat/uno/`, a call that doesn't fit is a compile error instead.
//!
//! ## Records
//!
//! A platform that turns on debug-log output defines this function once:
//!
//! ```ignore
//! #[unsafe(no_mangle)]
//! pub fn __hsm_log_record(desc: u32, arg1: u32, arg2: u32)
//! ```
//!
//! Its sink stores each call as one 12-byte record of three little-endian
//! 32-bit words: the descriptor, then `arg1`, then `arg2`. The descriptor
//! holds, from the lowest byte up:
//!
//! | Byte | Field |
//! |---|---|
//! | 0 | Severity: 0 for an error, 1 for a warning, 2 for info |
//! | 1 | Component |
//! | 2 | Message number |
//! | 3 | 0 |
//!
//! This crate doesn't choose the descriptor. Each call that records refers to
//! an undefined symbol, `__tsra_log:<crate>:<kind>:<target>:<message>`, where
//! `<crate>` is the calling package and `<kind>` is `E+` for an error with a
//! code, `W` for a warning, or `I` for info. The platform's linker script
//! gives the symbol the descriptor as its value, and the call passes the
//! symbol's address. The symbol is never read, and a message that the
//! platform doesn't number stops the link with the symbol's name.
//!
//! ## Calls that fit
//!
//! A call fits a record when it follows these rules:
//!
//! - The target and the message are string literals.
//! - The target matches `[a-z0-9_]+`.
//! - The message isn't empty, doesn't end with a space, and holds no `"`,
//!   `\`, or control character.
//! - Each placeholder is `{}`, `{:x}`, `{:#x}`, `{:08x}`, or `{:#010x}`, and
//!   the call passes one value per placeholder, with no named argument.
//! - A call passes at most two values. Each is a `u32`, `u16`, `u8`, `bool`,
//!   or `usize` on a 32-bit target, or a reference to one.
//! - `error!` takes an error, then the message, then at most one value. The
//!   error's `.0` field is its code, which follows the same type rule. The
//!   code comes after the value: it's `arg1` when the call has no value, and
//!   `arg2` when it has one.
//!
//! A value that a call doesn't pass is 0. A call that records evaluates each
//! value once.
//!
//! ## Uno code
//!
//! A crate is Uno code when its manifest directory is under `fw/plat/uno/` in
//! the checkout that holds this crate. In Uno code, a call that doesn't fit
//! fails to compile, and a line that no record can hold uses the Uno trace
//! crate's `error_text!`. Each call in Uno code also leaves a marker in the
//! `.tsra_log_sites` section, which isn't loaded: the call's crate, target,
//! message, file, and line. The Uno xtask reads the markers, and fails when
//! one target and message comes from more than one line.
//!
//! ## Other code
//!
//! Outside `fw/plat/uno/`, such as in the core library, a call that fits
//! records, and copies of one message share its number. A call that doesn't
//! fit drops. Where the compiler generates code for it, it leaves a note in
//! the `.tsra_log_drops` section, which isn't loaded: the crate, the file
//! and line, and the reason, separated by tabs. The file comes from
//! `file!()`, and a note can't hold `\`, so build debug-log images on Linux
//! or WSL, where paths use `/`. A call dropped for its shape, target,
//! message, or placeholders evaluates none of its values. A call dropped for
//! a value's or the code's type evaluates that value once, and formats
//! nothing.
//!
//! An untyped integer literal, such as `5`, has the type `i32`, so it doesn't
//! fit. Two cases don't follow "record or drop":
//!
//! - A value whose type is a generic parameter always drops, even when the
//!   code runs with a type that fits. The macro decides from the type while
//!   the compiler checks the generic function, before it knows the type.
//! - A NUL character (`\0`) in a target or message stops the build, in every
//!   crate. Each call names a symbol after its message, and the compiler
//!   rejects a NUL in a symbol name.

#![cfg_attr(not(test), no_std)]

#[cfg(test)]
mod tests {
    mod checks;
    mod records;
}

#[allow(unsafe_code)]
unsafe extern "Rust" {
    /// Stores one debug-log record: the descriptor, then two values. See
    /// the crate docs.
    pub fn __hsm_log_record(desc: u32, arg1: u32, arg2: u32);
}

/// `info!` with debug-log output: records the call, or drops it. See the
/// crate docs.
#[macro_export]
macro_rules! info {
    ($tgt:literal, $msg:literal, $n:ident = $($rest:tt)*) => {
        $crate::__named!()
    };
    ($tgt:literal, $msg:literal, $a:expr, $n:ident = $($rest:tt)*) => {
        $crate::__named!()
    };
    ($tgt:literal, $msg:literal $(,)?) => {
        $crate::__rec!(v0, "I", $tgt, $msg)
    };
    ($tgt:literal, $msg:literal, $a:expr $(,)?) => {
        $crate::__rec!(v1, "I", $tgt, $msg, $a)
    };
    ($tgt:literal, $msg:literal, $a:expr, $b:expr $(,)?) => {
        $crate::__rec!(v2, "I", $tgt, $msg, $a, $b)
    };
    ($($t:tt)*) => {
        $crate::__drop!(
            "with debug-log output, `info!` takes a literal target, a literal message, and at most two values",
            "the call isn't a literal target, a literal message, and at most two values"
        )
    };
}

/// `warn!` with debug-log output: records the call, or drops it. See the
/// crate docs.
#[macro_export]
macro_rules! warn {
    ($tgt:literal, $msg:literal, $n:ident = $($rest:tt)*) => {
        $crate::__named!()
    };
    ($tgt:literal, $msg:literal, $a:expr, $n:ident = $($rest:tt)*) => {
        $crate::__named!()
    };
    ($tgt:literal, $msg:literal $(,)?) => {
        $crate::__rec!(v0, "W", $tgt, $msg)
    };
    ($tgt:literal, $msg:literal, $a:expr $(,)?) => {
        $crate::__rec!(v1, "W", $tgt, $msg, $a)
    };
    ($tgt:literal, $msg:literal, $a:expr, $b:expr $(,)?) => {
        $crate::__rec!(v2, "W", $tgt, $msg, $a, $b)
    };
    ($($t:tt)*) => {
        $crate::__drop!(
            "with debug-log output, `warn!` takes a literal target, a literal message, and at most two values",
            "the call isn't a literal target, a literal message, and at most two values"
        )
    };
}

/// `error!` with debug-log output: records the call, or drops it. The code
/// comes after the value: it's `arg1` when the call has no value, and `arg2`
/// when it has one. See the crate docs.
#[macro_export]
macro_rules! error {
    ($tgt:literal, $err:expr, $msg:literal, $n:ident = $($rest:tt)*) => {
        $crate::__named!()
    };
    ($tgt:literal, $err:expr, $msg:literal $(,)?) => {
        $crate::__rec!(e0, "E+", $tgt, $msg, $err)
    };
    ($tgt:literal, $err:expr, $msg:literal, $a:expr $(,)?) => {
        $crate::__rec!(e1, "E+", $tgt, $msg, $err, $a)
    };
    ($($t:tt)*) => {
        $crate::__drop!(
            "with debug-log output, `error!` takes a literal target, an error code, a literal message, and at most one value",
            "the call isn't a literal target, an error code, a literal message, and at most one value"
        )
    };
}

/// A call with a named argument, which no record holds.
#[doc(hidden)]
#[macro_export]
macro_rules! __named {
    () => {
        $crate::__drop!(
            "with debug-log output, a log message needs one placeholder per value, each one of the five forms in the Uno log crate's docs",
            "a named argument isn't one of the five forms"
        )
    };
}

/// A call of the wrong shape: a compile error in Uno code, and a drop note
/// elsewhere.
#[doc(hidden)]
#[macro_export]
macro_rules! __drop {
    ($uno:literal, $reason:literal) => {{
        const _: () = ::core::assert!(
            !$crate::__bin::in_uno(::core::env!("CARGO_MANIFEST_DIR")),
            $uno
        );
        $crate::__drop_note!($reason);
    }};
}

/// Adds a drop note, `<crate>\t<file>:<line>\t<reason>`, to a section that
/// isn't loaded. It emits no instructions. The file and the reason can't hold
/// `{`, `}`, `"`, or `\`.
#[doc(hidden)]
#[macro_export]
macro_rules! __drop_note {
    ($reason:literal) => {
        #[allow(unsafe_code)]
        // SAFETY: the block only adds bytes to a section that isn't loaded.
        unsafe {
            ::core::arch::asm!(
                ".pushsection .tsra_log_drops,\"\",%progbits",
                ::core::concat!(
                    ".asciz \"",
                    ::core::env!("CARGO_PKG_NAME"),
                    "\\t",
                    ::core::file!(),
                    ":",
                    ::core::line!(),
                    "\\t",
                    $reason,
                    "\""
                ),
                ".popsection",
                options(nomem, nostack, preserves_flags)
            );
        }
    };
}

/// The constants, Uno checks, and marker of one call with a literal target
/// and message. The marker is empty outside Uno code.
#[doc(hidden)]
#[macro_export]
macro_rules! __head {
    ($tgt:literal, $msg:literal, $count:literal) => {
        const __IN: bool = $crate::__bin::in_uno(::core::env!("CARGO_MANIFEST_DIR"));
        const _: () = ::core::assert!(
            !__IN || $crate::__bin::target_ok($tgt),
            "with debug-log output, a log target must match [a-z0-9_]+"
        );
        const _: () = ::core::assert!(
            !__IN || $crate::__bin::message_ok($msg),
            "with debug-log output, a log message can't be empty, end with a space, or hold a double quote, a backslash, or a control character"
        );
        const _: () = ::core::assert!(
            !__IN || $crate::__bin::placeholders($msg) == $count,
            "with debug-log output, a log message needs one placeholder per value, each one of the five forms in the Uno log crate's docs"
        );
        const __FITS: bool = $crate::__bin::target_ok($tgt)
            && $crate::__bin::message_ok($msg)
            && $crate::__bin::placeholders($msg) == $count;
        const __SITE: &str = ::core::concat!(
            ::core::env!("CARGO_PKG_NAME"),
            "\t",
            $tgt,
            "\t",
            $msg,
            "\t",
            ::core::file!(),
            ":",
            ::core::line!(),
            "\0"
        );
        #[allow(unsafe_code)]
        #[used]
        #[unsafe(link_section = ".tsra_log_sites")]
        static __SITE_MARK: [u8; if __IN { __SITE.len() } else { 0 }] =
            $crate::__bin::site(__SITE);
    };
}

/// One call with a literal target and message, by its number of values. A
/// value's fit comes from its type alone. The call names each value once,
/// borrowed as `format_args!` borrows it, and evaluates none when the
/// message doesn't fit. Uno code converts its error code directly; other
/// code decides the code's fit from its type, as for a value.
#[doc(hidden)]
#[macro_export]
macro_rules! __rec {
    (v0, $kind:literal, $tgt:literal, $msg:literal) => {
        $crate::__rec!(@go $kind, $tgt, $msg, 0, { (true, true, 0, 0) })
    };
    (v1, $kind:literal, $tgt:literal, $msg:literal, $a:expr) => {
        $crate::__rec!(@go $kind, $tgt, $msg, 1, {
            #[allow(unused_imports)]
            use $crate::__bin::{SelFallback as _, SelLogValue as _, ViaFallback as _, ViaLogValue as _};
            let __a = &$a;
            let __sel_a = $crate::__bin::sel_of(__a);
            if false {
                $crate::__bin::Strict::<{ $crate::__bin::in_uno(::core::env!("CARGO_MANIFEST_DIR")) }>::value(&__sel_a);
            }
            let __fits = (&__sel_a).__tsra_fits();
            (__fits, true, if __fits { (&$crate::__bin::Probe(__a)).__tsra_value() } else { 0 }, 0)
        })
    };
    (v2, $kind:literal, $tgt:literal, $msg:literal, $a:expr, $b:expr) => {
        $crate::__rec!(@go $kind, $tgt, $msg, 2, {
            #[allow(unused_imports)]
            use $crate::__bin::{SelFallback as _, SelLogValue as _, ViaFallback as _, ViaLogValue as _};
            let __a = &$a;
            let __b = &$b;
            let __sel_a = $crate::__bin::sel_of(__a);
            if false {
                $crate::__bin::Strict::<{ $crate::__bin::in_uno(::core::env!("CARGO_MANIFEST_DIR")) }>::value(&__sel_a);
            }
            let __sel_b = $crate::__bin::sel_of(__b);
            if false {
                $crate::__bin::Strict::<{ $crate::__bin::in_uno(::core::env!("CARGO_MANIFEST_DIR")) }>::value(&__sel_b);
            }
            let __fits = (&__sel_a).__tsra_fits() & (&__sel_b).__tsra_fits();
            (
                __fits,
                true,
                if __fits { (&$crate::__bin::Probe(__a)).__tsra_value() } else { 0 },
                if __fits { (&$crate::__bin::Probe(__b)).__tsra_value() } else { 0 },
            )
        })
    };
    (e0, $kind:literal, $tgt:literal, $msg:literal, $err:expr) => {
        $crate::__rec!(@go $kind, $tgt, $msg, 0, {
            #[allow(unused_imports)]
            use $crate::__bin::{SelFallback as _, SelLogValue as _, ViaFallback as _, ViaLogValue as _};
            if __IN {
                (true, true, $crate::__bin::Strict::<{ __IN }>::code(&$err.0), 0)
            } else {
                let __c = &$err.0;
                let __sel_c = $crate::__bin::sel_of(__c);
                if false {
                    $crate::__bin::Strict::<{ $crate::__bin::in_uno(::core::env!("CARGO_MANIFEST_DIR")) }>::value(&__sel_c);
                }
                let __fits_c = (&__sel_c).__tsra_fits();
                (true, __fits_c, if __fits_c { (&$crate::__bin::Probe(__c)).__tsra_value() } else { 0 }, 0)
            }
        })
    };
    (e1, $kind:literal, $tgt:literal, $msg:literal, $err:expr, $a:expr) => {
        $crate::__rec!(@go $kind, $tgt, $msg, 1, {
            #[allow(unused_imports)]
            use $crate::__bin::{SelFallback as _, SelLogValue as _, ViaFallback as _, ViaLogValue as _};
            let __a = &$a;
            let __sel_a = $crate::__bin::sel_of(__a);
            if false {
                $crate::__bin::Strict::<{ $crate::__bin::in_uno(::core::env!("CARGO_MANIFEST_DIR")) }>::value(&__sel_a);
            }
            let __fits_a = (&__sel_a).__tsra_fits();
            if __IN {
                (
                    __fits_a,
                    true,
                    if __fits_a { (&$crate::__bin::Probe(__a)).__tsra_value() } else { 0 },
                    $crate::__bin::Strict::<{ __IN }>::code(&$err.0),
                )
            } else {
                let __c = &$err.0;
                let __sel_c = $crate::__bin::sel_of(__c);
                if false {
                    $crate::__bin::Strict::<{ $crate::__bin::in_uno(::core::env!("CARGO_MANIFEST_DIR")) }>::value(&__sel_c);
                }
                let __fits_c = (&__sel_c).__tsra_fits();
                let __fits = __fits_a & __fits_c;
                (
                    __fits_a,
                    __fits_c,
                    if __fits { (&$crate::__bin::Probe(__a)).__tsra_value() } else { 0 },
                    if __fits { (&$crate::__bin::Probe(__c)).__tsra_value() } else { 0 },
                )
            }
        })
    };
    (@go $kind:literal, $tgt:literal, $msg:literal, $count:literal, $values:block) => {{
        $crate::__head!($tgt, $msg, $count);
        if __FITS {
            let (__ok_values, __ok_code, __v1, __v2): (bool, bool, u32, u32) = $values;
            if __ok_values & __ok_code {
                $crate::__record!($kind, $tgt, $msg, __v1, __v2);
            } else if !__ok_values {
                $crate::__drop_note!("a value doesn't convert to u32");
            } else {
                $crate::__drop_note!("the error code doesn't convert to u32");
            }
        } else {
            $crate::__drop_note!("the target, the message, or a placeholder doesn't fit");
        }
    }};
}

/// Takes the token's address, which is the descriptor, and records.
#[doc(hidden)]
#[macro_export]
macro_rules! __record {
    ($kind:literal, $tgt:literal, $msg:literal, $v1:expr, $v2:expr) => {{
        #[allow(unsafe_code)]
        unsafe extern "C" {
            // Never read: the platform's linker script gives it the
            // record's descriptor as its address.
            #[link_name = $crate::__token!($kind, $tgt, $msg)]
            static TOKEN: u8;
        }
        #[allow(unsafe_code, unused_unsafe)]
        // SAFETY: only the address is taken; the static is never read.
        let __token = unsafe { &raw const TOKEN };
        $crate::__bin::record(__token, $v1, $v2);
    }};
}

/// A call's token: `__tsra_log:<crate>:<kind>:<target>:<message>`.
#[doc(hidden)]
#[macro_export]
macro_rules! __token {
    ($kind:literal, $tgt:literal, $msg:literal) => {
        ::core::concat!(
            "__tsra_log:",
            ::core::env!("CARGO_PKG_NAME"),
            ":",
            $kind,
            ":",
            $tgt,
            ":",
            $msg
        )
    };
}

/// Support for the macros.
#[doc(hidden)]
pub mod __bin {
    /// A value that a record can carry: it converts to `u32` without loss.
    #[diagnostic::on_unimplemented(
        message = "`{Self}` can't be a log value with debug-log output",
        note = "with debug-log output, a log value must convert to `u32` without loss: a `u32`, `u16`, `u8`, `bool`, or `usize`, or a reference to one"
    )]
    pub trait LogValue: Copy {
        /// The value as a `u32`.
        fn to_u32(self) -> u32;
    }

    impl LogValue for u32 {
        #[inline(always)]
        fn to_u32(self) -> u32 {
            self
        }
    }

    impl LogValue for u16 {
        #[inline(always)]
        fn to_u32(self) -> u32 {
            u32::from(self)
        }
    }

    impl LogValue for u8 {
        #[inline(always)]
        fn to_u32(self) -> u32 {
            u32::from(self)
        }
    }

    impl LogValue for bool {
        #[inline(always)]
        fn to_u32(self) -> u32 {
            u32::from(self)
        }
    }

    #[cfg(target_pointer_width = "32")]
    impl LogValue for usize {
        #[inline(always)]
        fn to_u32(self) -> u32 {
            self as u32
        }
    }

    impl<T: LogValue> LogValue for &T {
        #[inline(always)]
        fn to_u32(self) -> u32 {
            (*self).to_u32()
        }
    }

    /// Converts a value that a call borrows, as `format_args!` does.
    #[inline(always)]
    pub fn value<T: LogValue>(value: &T) -> u32 {
        (*value).to_u32()
    }

    /// A value's type, without the value.
    pub struct Sel<T: ?Sized>(core::marker::PhantomData<T>);

    /// The selector for a value's type.
    #[inline(always)]
    pub fn sel_of<T: ?Sized>(_: &T) -> Sel<T> {
        Sel(core::marker::PhantomData)
    }

    /// Picked when the type is a [`LogValue`].
    pub trait SelLogValue {
        /// Whether the value fits: yes.
        fn __tsra_fits(&self) -> bool;
    }

    impl<T: LogValue> SelLogValue for Sel<T> {
        #[inline(always)]
        fn __tsra_fits(&self) -> bool {
            true
        }
    }

    /// An untyped integer literal falls back to `i32`, which no record holds.
    impl SelLogValue for Sel<i32> {
        #[inline(always)]
        fn __tsra_fits(&self) -> bool {
            false
        }
    }

    /// Picked, through one more reference, for any other type.
    pub trait SelFallback {
        /// Whether the value fits: no.
        fn __tsra_fits(&self) -> bool;
    }

    impl<T: ?Sized> SelFallback for &Sel<T> {
        #[inline(always)]
        fn __tsra_fits(&self) -> bool {
            false
        }
    }

    /// Holds a value on the recording path.
    pub struct Probe<'a, T: ?Sized>(pub &'a T);

    /// Converts a [`LogValue`].
    pub trait ViaLogValue {
        /// The value as a `u32`.
        fn __tsra_value(&self) -> u32;
    }

    impl<T: LogValue> ViaLogValue for Probe<'_, T> {
        #[inline(always)]
        fn __tsra_value(&self) -> u32 {
            (*self.0).to_u32()
        }
    }

    /// Type-checks the recording path for an untyped integer literal; never
    /// runs.
    impl ViaLogValue for Probe<'_, i32> {
        #[inline(always)]
        fn __tsra_value(&self) -> u32 {
            0
        }
    }

    /// Type-checks the recording path for any other type; never runs.
    pub trait ViaFallback {
        /// 0.
        fn __tsra_value(&self) -> u32;
    }

    impl<T: ?Sized> ViaFallback for &Probe<'_, T> {
        #[inline(always)]
        fn __tsra_value(&self) -> u32 {
            0
        }
    }

    /// In Uno code (`true`), a value's type must be a [`LogValue`].
    pub struct Strict<const IN_UNO: bool>;

    impl Strict<true> {
        /// Requires a [`LogValue`].
        #[inline(always)]
        pub fn value<T: LogValue>(_: &Sel<T>) {}

        /// Converts a Uno call's error code, which must be a [`LogValue`].
        #[inline(always)]
        pub fn code<T: LogValue>(code: &T) -> u32 {
            value(code)
        }
    }

    impl Strict<false> {
        /// Takes any type.
        #[inline(always)]
        pub fn value<T: ?Sized>(_: &Sel<T>) {}

        /// Never runs: other code converts its error code through the probe.
        #[inline(always)]
        pub fn code<T: ?Sized>(_: &T) -> u32 {
            0
        }
    }

    /// This crate's manifest directory, `<checkout>/fw/plat/uno/fw/crates/debug_log`.
    const SELF_DIR: &[u8] = env!("CARGO_MANIFEST_DIR").as_bytes();

    /// This crate's place under `<checkout>`, with either path separator.
    const SELF_SUFFIX: [&[u8]; 2] = [
        b"/fw/plat/uno/fw/crates/debug_log",
        b"\\fw\\plat\\uno\\fw\\crates\\debug_log",
    ];

    /// The length of `<checkout>/fw/plat/uno/`, with its last separator.
    const UNO_ROOT_LEN: usize = SELF_DIR.len() - SELF_SUFFIX[0].len() + "/fw/plat/uno/".len();

    const _: () = assert!(
        ends_with(SELF_DIR, SELF_SUFFIX[0]) || ends_with(SELF_DIR, SELF_SUFFIX[1]),
        "the Uno log crate must stay at fw/plat/uno/fw/crates/debug_log"
    );

    /// Whether `hay` ends with `tail`.
    const fn ends_with(hay: &[u8], tail: &[u8]) -> bool {
        if tail.len() > hay.len() {
            return false;
        }
        let start = hay.len() - tail.len();
        let mut i = 0;
        while i < tail.len() {
            if hay[start + i] != tail[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Whether a manifest directory lies under `fw/plat/uno/` in the checkout
    /// that holds this crate.
    pub const fn in_uno(dir: &str) -> bool {
        let dir = dir.as_bytes();
        if dir.len() < UNO_ROOT_LEN {
            return false;
        }
        let mut i = 0;
        while i < UNO_ROOT_LEN {
            if dir[i] != SELF_DIR[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Passes one record to the platform. The token's address is the
    /// record's descriptor.
    #[inline(always)]
    #[allow(unsafe_code)]
    pub fn record(token: *const u8, value1: u32, value2: u32) {
        let desc = token.addr() as u32;
        // SAFETY: the platform that turns on debug-log output defines
        // `__hsm_log_record` with this signature.
        unsafe { super::__hsm_log_record(desc, value1, value2) }
    }

    /// Whether a target matches `[a-z0-9_]+`.
    pub const fn target_ok(target: &str) -> bool {
        let bytes = target.as_bytes();
        if bytes.is_empty() {
            return false;
        }
        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Whether a message can be part of a symbol name in a linker script and
    /// be read back from a link error: it isn't empty, doesn't end with a
    /// space, and holds no `"`, `\`, or control character.
    pub const fn message_ok(message: &str) -> bool {
        let bytes = message.as_bytes();
        if bytes.is_empty() || bytes[bytes.len() - 1] == b' ' {
            return false;
        }
        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            if byte == b'"' || byte == b'\\' || byte.is_ascii_control() {
                return false;
            }
            i += 1;
        }
        true
    }

    /// The forms a placeholder can take, without its braces.
    const SPECS: [&[u8]; 5] = [b"", b":x", b":#x", b":08x", b":#010x"];

    /// Whether `bytes[start..end]` is one of [`SPECS`].
    const fn spec_ok(bytes: &[u8], start: usize, end: usize) -> bool {
        let mut s = 0;
        while s < SPECS.len() {
            let spec = SPECS[s];
            if spec.len() == end - start {
                let mut j = 0;
                while j < spec.len() && bytes[start + j] == spec[j] {
                    j += 1;
                }
                if j == spec.len() {
                    return true;
                }
            }
            s += 1;
        }
        false
    }

    /// The number of placeholders in a message, or `usize::MAX` if a brace
    /// isn't paired or a placeholder isn't `{}`, `{:x}`, `{:#x}`, `{:08x}`,
    /// or `{:#010x}`. `{{` and `}}` are literal braces.
    pub const fn placeholders(message: &str) -> usize {
        let bytes = message.as_bytes();
        let mut count = 0;
        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            let doubled = i + 1 < bytes.len() && bytes[i + 1] == byte;
            if (byte == b'{' || byte == b'}') && doubled {
                i += 2;
            } else if byte == b'{' {
                let start = i + 1;
                let mut end = start;
                while end < bytes.len() && bytes[end] != b'}' {
                    end += 1;
                }
                if end == bytes.len() || !spec_ok(bytes, start, end) {
                    return usize::MAX;
                }
                count += 1;
                i = end + 1;
            } else if byte == b'}' {
                return usize::MAX;
            } else {
                i += 1;
            }
        }
        count
    }

    /// Copies text into a byte array, for a marker.
    pub const fn site<const N: usize>(text: &str) -> [u8; N] {
        let bytes = text.as_bytes();
        let mut out = [0; N];
        let mut i = 0;
        while i < N && i < bytes.len() {
            out[i] = bytes[i];
            i += 1;
        }
        out
    }
}
