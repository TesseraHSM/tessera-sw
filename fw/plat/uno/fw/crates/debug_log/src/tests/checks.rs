// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests the debug-log checks, the value conversions, and the test for Uno
//! code.
//!
//! These tests call the functions that a call with debug-log output runs: the
//! checks run at compile time, and the conversions at run time.

use std::path::MAIN_SEPARATOR;

use crate::__bin;

#[test]
fn a_target_is_lowercase_letters_digits_and_underscores() {
    for target in ["core", "iic", "op_status", "fips", "x", "pqc2_timeout"] {
        assert!(__bin::target_ok(target), "{target:?}");
    }
    for target in [
        "",
        "Core",
        "op-status",
        "op status",
        "op:x",
        "\u{e9}",
        "core\n",
    ] {
        assert!(!__bin::target_ok(target), "{target:?}");
    }
}

#[test]
fn a_message_keeps_to_what_a_linker_script_and_a_link_error_carry() {
    for message in [
        "boot complete",
        "  MemManage: IACCVIOL",
        "slot {} fell back",
        "50% done",
        "{{literal}}",
        "x",
    ] {
        assert!(__bin::message_ok(message), "{message:?}");
    }
    for message in [
        "",
        "trailing space ",
        "say \"hi\"",
        "back\\slash",
        "tab\there",
        "line\nbreak",
        "delete\u{7f}",
    ] {
        assert!(!__bin::message_ok(message), "{message:?}");
    }
}

#[test]
fn placeholders_count_the_five_forms() {
    assert_eq!(__bin::placeholders("no values"), 0);
    assert_eq!(__bin::placeholders("depth={}"), 1);
    assert_eq!(__bin::placeholders("a={:x} b={:#x}"), 2);
    assert_eq!(__bin::placeholders("{:08x}{:#010x}"), 2);
    assert_eq!(__bin::placeholders("{{}} and {{ }}"), 0);
    assert_eq!(__bin::placeholders("{{{}}}"), 1);
}

#[test]
fn placeholders_reject_every_other_form() {
    for message in [
        "{:?}", "{0}", "{name}", "{:X}", "{:#X}", "{:8x}", "{:010x}", "{:#08x}", "{:>4}", "{", "}",
        "{:x", "a}b", "{}}",
    ] {
        assert_eq!(__bin::placeholders(message), usize::MAX, "{message:?}");
    }
}

#[test]
fn values_convert_to_u32_without_loss() {
    assert_eq!(__bin::value(&u32::MAX), u32::MAX);
    assert_eq!(__bin::value(&0_u32), 0);
    assert_eq!(__bin::value(&u16::MAX), 0xFFFF);
    assert_eq!(__bin::value(&u8::MAX), 0xFF);
    assert_eq!(__bin::value(&true), 1);
    assert_eq!(__bin::value(&false), 0);
    let depth = 7_u32;
    assert_eq!(__bin::value(&&depth), 7);
}

#[test]
fn a_site_marker_holds_the_text() {
    const SITE: &str = "src/io.rs:438";
    let marker: [u8; SITE.len()] = __bin::site(SITE);
    assert_eq!(&marker, SITE.as_bytes());
}

#[test]
fn uno_code_is_under_fw_plat_uno_in_this_checkout() {
    let sep = MAIN_SEPARATOR.to_string();
    let place = ["fw", "plat", "uno", "fw", "crates", "debug_log"].join(&sep);
    let root = env!("CARGO_MANIFEST_DIR")
        .strip_suffix(place.as_str())
        .expect("this crate's place in the checkout");
    let dir = |path: &str| format!("{root}{}", path.replace('/', &sep));
    for path in [
        "fw/plat/uno/fw/pal",
        "fw/plat/uno/fw/crates/debug_log",
        "fw/plat/uno/xtask/fixtures/log_image",
        "fw/plat/uno/xtask/fixtures/log_image/dep",
    ] {
        assert!(__bin::in_uno(&dir(path)), "{path}");
    }
    for path in [
        "fw/core/lib",
        "fw/core/tracing",
        "fw/plat/uno",
        "fw/plat/unox/fw/pal",
        "fw/plat/duo/fw/pal",
        "target/tsra_log_fixture_outside",
    ] {
        assert!(!__bin::in_uno(&dir(path)), "{path}");
    }
    let elsewhere = ["", "elsewhere", "fw", "plat", "uno", "fw", "pal"].join(&sep);
    assert!(!__bin::in_uno(&elsewhere));
    assert!(!__bin::in_uno(""));
}
