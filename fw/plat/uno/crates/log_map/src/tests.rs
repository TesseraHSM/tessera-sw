// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use super::header;
use super::*;

const HEAD: &str = "# Copyright (c) Microsoft Corporation.\n# Licensed under the MIT License.\n";

fn key(crate_name: &str, kind: Kind, target: &str, message: &str) -> Key {
    Key {
        crate_name: crate_name.to_string(),
        kind,
        target: target.to_string(),
        message: message.to_string(),
    }
}

/// The map whose files hold `rows`, each row in its component's file, after
/// the comment lines.
fn map(rows: &str) -> Map {
    let mut texts: BTreeMap<Component, String> = Component::ALL
        .into_iter()
        .map(|component| (component, HEAD.to_string()))
        .collect();
    for row in rows.lines() {
        let name = row.split('\t').nth(1).expect("a component field");
        let component = Component::from_name(name).expect("a component");
        let text = texts.get_mut(&component).expect("the component's file");
        text.push_str(row);
        text.push('\n');
    }
    let files: Vec<(Component, &str)> = texts
        .iter()
        .map(|(component, text)| (*component, text.as_str()))
        .collect();
    Map::parse_files(&files).expect("a valid map")
}

fn used(map: &Map) -> BTreeSet<String> {
    map.rows().map(|row| row.key.symbol()).collect()
}

#[test]
fn components_have_provisional_values_and_route_by_path() {
    assert_eq!(Component::Core.value(), 0xF9);
    assert_eq!(Component::Uno.value(), 0xFA);
    assert_eq!(Component::from_name("core"), Some(Component::Core));
    assert_eq!(Component::from_name("uno"), Some(Component::Uno));
    assert_eq!(Component::from_name("Uno"), None);
    for (path, component) in [
        ("fw/plat/uno/fw/pal/Cargo.toml", Component::Uno),
        ("fw/plat/uno/fw/crates/fault/Cargo.toml", Component::Uno),
        (
            "fw\\plat\\uno\\fw\\drivers\\iic\\Cargo.toml",
            Component::Uno,
        ),
        ("fw/core/lib/Cargo.toml", Component::Core),
        ("fw/plat/std/pal/Cargo.toml", Component::Core),
        ("fw/plat/unos/Cargo.toml", Component::Core),
    ] {
        assert_eq!(Component::of_crate_path(path), component, "{path}");
    }
}

#[test]
fn kinds_set_the_severity() {
    for (code, kind, severity, has_code) in [
        ("E", Kind::Error, 0, false),
        ("E+", Kind::ErrorCode, 0, true),
        ("W", Kind::Warn, 1, false),
        ("I", Kind::Info, 2, false),
    ] {
        assert_eq!(Kind::from_code(code), Some(kind));
        assert_eq!(kind.code(), code);
        assert_eq!(kind.severity(), severity);
        assert_eq!(kind.has_code(), has_code);
    }
    assert_eq!(Kind::from_code("D"), None);
}

#[test]
fn a_token_symbol_round_trips() {
    let k = key(
        "tsra_fw_uno_fault",
        Kind::ErrorCode,
        "fips",
        "  MemManage: IACCVIOL  {:#010x}",
    );
    let symbol = k.symbol();
    assert_eq!(
        symbol,
        "__tsra_log:tsra_fw_uno_fault:E+:fips:  MemManage: IACCVIOL  {:#010x}"
    );
    assert_eq!(Key::from_symbol(&symbol), Ok(k));
}

#[test]
fn a_bad_token_symbol_fails() {
    for symbol in [
        "__tsra_site:core:boot",
        "__tsra_log:crate:I:core",
        "__tsra_log:crate:X:core:boot",
        "__tsra_log:crate:I:Core:boot",
        "__tsra_log:crate:I:core:boot ",
        "__tsra_log:crate:I:core:value={:?}",
        "__tsra_log::I:core:boot",
    ] {
        assert!(Key::from_symbol(symbol).is_err(), "{symbol:?}");
    }
}

#[test]
fn a_key_follows_the_debug_log_rules() {
    assert_eq!(key("c", Kind::Info, "core", "boot {}").check(), Ok(()));
    for bad in [
        key("", Kind::Info, "core", "boot"),
        key("c d", Kind::Info, "core", "boot"),
        key("c", Kind::Info, "", "boot"),
        key("c", Kind::Info, "op-status", "boot"),
        key("c", Kind::Info, "core", ""),
        key("c", Kind::Info, "core", "boot "),
        key("c", Kind::Info, "core", "say \"hi\""),
        key("c", Kind::Info, "core", "back\\slash"),
        key("c", Kind::Info, "core", "tab\there"),
        key("c", Kind::Info, "core", "value={:?}"),
        key("c", Kind::Info, "core", "value={"),
        key("c", Kind::Info, "core", "value=}"),
        key("c", Kind::Info, "core", "{} {} {}"),
        key("c", Kind::ErrorCode, "core", "{} {}"),
    ] {
        assert!(bad.check().is_err(), "{bad:?}");
    }
    assert_eq!(key("c", Kind::Warn, "core", "{} {:#x}").check(), Ok(()));
    assert_eq!(key("c", Kind::ErrorCode, "core", "op {}").check(), Ok(()));
}

#[test]
fn descriptors_hold_severity_component_and_number() {
    let m =
        map("0\tcore\tE+\tc\tcore\tfailed\n1\tcore\tW\tc\tcore\tslow\n0\tuno\tI\tu\tboot\tready\n");
    let descriptors: Vec<u32> = m.rows().map(Row::descriptor).collect();
    assert_eq!(descriptors, [0x0000_F900, 0x0001_F901, 0x0000_FA02]);
    let last = Row {
        number: 255,
        component: Component::Uno,
        key: key("u", Kind::Info, "t", "m"),
    };
    assert_eq!(last.descriptor(), 0x00FF_FA02);
}

#[test]
fn a_map_round_trips_and_accepts_crlf() {
    let text = format!(
        "{HEAD}# number\tcomponent\tkind\tcrate\ttarget\tmessage\n0\tcore\tI\tc\tcore\ta: {{}} b {{:#x}}\n"
    );
    let m = Map::parse_files(&[(Component::Core, &text)]).expect("a valid map");
    assert_eq!(m.to_text(Component::Core), text);
    assert_eq!(m.to_text(Component::Uno), "");
    let crlf = text.replace('\n', "\r\n");
    let m = Map::parse_files(&[(Component::Core, &crlf)]).expect("a CRLF map");
    assert_eq!(m.to_text(Component::Core), text);
    let error = Map::parse_files(&[(Component::Core, &text), (Component::Core, HEAD)])
        .expect_err("two core texts");
    assert!(
        error
            .to_string()
            .contains("two texts for the core component's map file"),
        "{error}"
    );
}

#[test]
fn a_bad_row_fails_with_its_file_and_line() {
    for (rows, needle) in [
        ("0\tcore\tI\tc\tcore\n", "six"),
        ("256\tcore\tI\tc\tcore\tm\n", "0 to 255"),
        ("01\tcore\tI\tc\tcore\tm\n", "0 to 255"),
        ("-1\tcore\tI\tc\tcore\tm\n", "0 to 255"),
        ("+1\tcore\tI\tc\tcore\tm\n", "0 to 255"),
        ("\tcore\tI\tc\tcore\tm\n", "0 to 255"),
        ("0\tcpu\tI\tc\tcore\tm\n", "component"),
        ("0\tcore\tD\tc\tcore\tm\n", "kind"),
        ("\n", "six"),
    ] {
        let text = format!("{HEAD}{rows}");
        let error = Map::parse_files(&[(Component::Core, &text)]).expect_err(rows);
        let text = error.to_string();
        assert!(text.contains("core.tsv line 3: "), "{text}");
        assert!(text.contains(needle), "{text}");
    }
}

#[test]
fn a_row_in_another_components_file_fails() {
    for (file, row, expected) in [
        (
            Component::Core,
            "0\tuno\tI\tu\tboot\tready\n",
            "core.tsv line 3: the row's component is uno, but the file holds the core component's rows",
        ),
        (
            Component::Uno,
            "0\tcore\tI\tc\tcore\tready\n",
            "uno.tsv line 3: the row's component is core, but the file holds the uno component's rows",
        ),
    ] {
        let text = format!("{HEAD}{row}");
        let error = Map::parse_files(&[(file, &text)]).expect_err(row);
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn reading_the_map_directory_needs_every_components_file() {
    let dir = std::env::temp_dir().join(format!("tsra-log-map-dir-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("a directory");
    let core = format!("{HEAD}0\tcore\tE+\tc\tcore\tfailed\n");
    fs::write(dir.join("core.tsv"), &core).expect("core.tsv");
    let uno_path = dir.join("uno.tsv");
    let missing = Map::read_dir(&dir).expect_err("no uno.tsv").to_string();
    fs::write(&uno_path, format!("{HEAD}0\tcore\tI\tc\tcore\tready\n")).expect("uno.tsv");
    let misplaced = Map::read_dir(&dir).expect_err("a core row").to_string();
    let uno = format!("{HEAD}0\tuno\tI\tu\tboot\tready\n");
    fs::write(&uno_path, &uno).expect("uno.tsv");
    let read = Map::read_dir(&dir);
    let _ = fs::remove_dir_all(&dir);
    assert!(
        missing.starts_with(&format!(
            "can't read the uno component's message-map file {}: ",
            uno_path.display()
        )),
        "{missing}"
    );
    assert!(
        misplaced.starts_with(&format!(
            "{} line 3: the row's component is core",
            uno_path.display()
        )),
        "{misplaced}"
    );
    let read = read.expect("both files");
    assert_eq!(read.to_text(Component::Core), core);
    assert_eq!(read.to_text(Component::Uno), uno);
}

#[test]
fn a_valid_map_passes_the_check() {
    let m = map(concat!(
        "0\tcore\tE+\tcore_a\tcore\tfailed\n",
        "1\tcore\tW\tcore_a\tcore\tfailed\n",
        "0\tuno\tI\tuno_a\tboot\tready\n",
        "0\tcore\tE+\tcore_b\tcore\tfailed\n",
        "2\tcore\tI\tcore_b\tcore\tready\n",
        "1\tuno\tE+\ttsra_fw_uno_fault\tfips\t#### FIPS error state ####\n",
    ));
    assert_eq!(m.check(), Ok(()));
}

#[test]
fn the_check_finds_every_broken_rule() {
    for (rows, needle) in [
        ("0\tcore\tI\tc\tt\tm\n1\tcore\tI\tc\tt\tm\n", "second row"),
        (
            "0\tcore\tI\tc\tt\tm\n0\tuno\tI\tc\tt\tn\n",
            "two components",
        ),
        ("1\tcore\tI\tc\tt\tm\n", "next number in its component, 0"),
        (
            "0\tcore\tI\tc\tt\tm\n2\tcore\tI\tc\tt\tn\n",
            "next number in its component, 1",
        ),
        (
            "0\tcore\tI\tc\tt\tm\n1\tcore\tI\td\tt\tm\n",
            "reuse that number",
        ),
    ] {
        let errors = map(rows).check().expect_err(rows);
        assert!(
            errors.iter().any(|e| e.to_string().contains(needle)),
            "{rows:?}: {errors:?}"
        );
    }
}

#[test]
fn adding_rows_takes_the_next_numbers_in_a_fixed_order() {
    let new = [
        (key("uno_a", Kind::Info, "boot", "ready"), Component::Uno),
        (
            key("core_a", Kind::Warn, "core", "slow {}"),
            Component::Core,
        ),
        (
            key("core_a", Kind::ErrorCode, "core", "failed"),
            Component::Core,
        ),
    ];
    let mut forward = map("");
    let added = forward.add(&new).expect("rows added");
    let mut backward = map("");
    let mut reversed = new.clone();
    reversed.reverse();
    backward.add(&reversed).expect("rows added");
    assert_eq!(forward, backward);
    let lines: Vec<String> = added.iter().map(Row::to_line).collect();
    assert_eq!(
        lines,
        [
            "0\tcore\tE+\tcore_a\tcore\tfailed",
            "1\tcore\tW\tcore_a\tcore\tslow {}",
            "0\tuno\tI\tuno_a\tboot\tready",
        ]
    );
    assert_eq!(forward.check(), Ok(()));
    assert_eq!(forward.add(&new), Ok(Vec::new()));
}

#[test]
fn adding_rows_appends_each_to_its_components_file() {
    let mut m = map("0\tcore\tE+\tcore_a\tcore\tfailed\n0\tuno\tI\tuno_a\tboot\tready\n");
    let core = m.to_text(Component::Core);
    let uno = m.to_text(Component::Uno);
    let added = m
        .add(&[
            (key("uno_a", Kind::Warn, "boot", "slow"), Component::Uno),
            (key("core_a", Kind::Info, "core", "ready"), Component::Core),
        ])
        .expect("rows added");
    assert_eq!(added.len(), 2);
    assert_eq!(
        m.to_text(Component::Core),
        format!("{core}1\tcore\tI\tcore_a\tcore\tready\n")
    );
    assert_eq!(
        m.to_text(Component::Uno),
        format!("{uno}1\tuno\tW\tuno_a\tboot\tslow\n")
    );
    assert_eq!(m.check(), Ok(()));
}

#[test]
fn a_moved_call_reuses_its_number() {
    let mut m = map("0\tcore\tE+\tcore_a\tcore\tfailed\n1\tcore\tI\tcore_a\tcore\tready\n");
    let added = m
        .add(&[(
            key("core_b", Kind::ErrorCode, "core", "failed"),
            Component::Core,
        )])
        .expect("a row added");
    assert_eq!(added[0].number, 0);
    assert_eq!(m.check(), Ok(()));
}

#[test]
fn adding_a_bad_message_leaves_the_map_unchanged() {
    let mut m = map("");
    let error = m
        .add(&[
            (key("c", Kind::Info, "t", "ready"), Component::Core),
            (key("c", Kind::Info, "t", "{} {} {}"), Component::Core),
        ])
        .expect_err("a message with three values");
    assert!(error.to_string().contains("3 placeholders"), "{error}");
    assert_eq!(m.rows().count(), 0);
}

#[test]
fn a_component_has_256_numbers() {
    let mut m = map("");
    let keys: Vec<(Key, Component)> = (0..256)
        .map(|n| {
            (
                key("c", Kind::Info, "t", &format!("message {n:03}")),
                Component::Core,
            )
        })
        .collect();
    let added = m.add(&keys).expect("256 rows");
    assert_eq!(added.last().map(|row| row.number), Some(255));
    assert_eq!(m.check(), Ok(()));
    let error = m
        .add(&[(key("c", Kind::Info, "t", "one more"), Component::Core)])
        .expect_err("a 257th message");
    assert!(error.to_string().contains("all 256 numbers"), "{error}");
    let header = m.decoder_header(&used(&m)).expect("a header");
    assert!(
        header.contains("    [0] = \"[t] message 000\",\n"),
        "{header}"
    );
    assert!(
        header.contains("    [255] = \"[t] message 255\",\n"),
        "{header}"
    );
}

#[test]
fn the_base_map_must_be_a_prefix() {
    let base = format!("{HEAD}0\tcore\tI\tc\tt\tm\n1\tcore\tI\tc\tt\tn\n");
    let appended = format!("{base}2\tcore\tI\tc\tt\to\n");
    assert_eq!(check_prefix(&base, &base), Ok(()));
    assert_eq!(check_prefix(&base, &appended), Ok(()));
    assert_eq!(check_prefix(&base, &appended.replace('\n', "\r\n")), Ok(()));
    let edited = base.replace("\tn\n", "\tN\n");
    let deleted = format!("{HEAD}0\tcore\tI\tc\tt\tm\n");
    let inserted = format!("{HEAD}0\tcore\tI\tc\tt\tm\n2\tcore\tI\tc\tt\to\n1\tcore\tI\tc\tt\tn\n");
    for head in [edited, deleted, inserted] {
        assert!(check_prefix(&base, &head).is_err(), "{head:?}");
    }
}

#[test]
fn the_linker_script_provides_each_token() {
    let m = map("0\tcore\tE+\tc\tcore\tfailed: {}\n0\tuno\tI\tu\tboot\tready\n");
    assert_eq!(
        m.linker_script(),
        concat!(
            "/* Generated from the message map. Do not edit. */\n",
            "PROVIDE(\"__tsra_log:c:E+:core:failed: {}\" = 0x0000f900);\n",
            "PROVIDE(\"__tsra_log:u:I:boot:ready\" = 0x0000fa02);\n",
            "SECTIONS\n",
            "{\n",
            "  .tsra_log_sites (INFO) : { KEEP(*(.tsra_log_sites .tsra_log_sites.*)) }\n",
            "  .tsra_log_drops (INFO) : { KEEP(*(.tsra_log_drops)) }\n",
            "}\n",
            "INSERT AFTER .got;\n",
        )
    );
}

#[test]
fn the_decoder_header_has_one_format_per_number() {
    let m = map(concat!(
        "0\tcore\tE+\tc\tcore\tInvalid length: {}\n",
        "1\tcore\tW\tc\tgdma\tslot {:x} at {:#010x}\n",
        "2\tcore\tI\tc\tio\t50% of {{queue}} {:#x}?? {:08x}\n",
        "0\tcore\tE+\td\tcore\tInvalid length: {}\n",
    ));
    let header = m.decoder_header(&used(&m)).expect("a header");
    let expected = concat!(
        "#define TSRA_LOG_COMPONENT_CORE 0xF9\n",
        "#define TSRA_LOG_COMPONENT_UNO 0xFA\n",
        "\n",
        "static const char *const tsra_log_core_messages[256] = {\n",
        "    [0] = \"[core] Invalid length: %u [err:%08x]\",\n",
        "    [1] = \"[gdma] slot %x at 0x%08x\",\n",
        "    [2] = \"[io] 50%% of {queue} 0x%x?\\? %08x\",\n",
        "};\n",
        "\n",
        "static const char *const tsra_log_uno_messages[256] = {\n",
        "    0,\n",
        "};\n",
        "\n",
        "#endif /* TSRA_LOG_MESSAGES_H */\n",
    );
    assert!(header.ends_with(expected), "{header}");
    assert!(header.starts_with(
        "/*\n * Copyright (c) Microsoft Corporation.\n * Licensed under the MIT License.\n */\n"
    ));
}

/// Formats two values with the C library's `snprintf`.
#[cfg(unix)]
#[allow(unsafe_code)]
fn c_format(format: &str, value1: u32, value2: u32) -> String {
    use std::ffi::CString;
    use std::ffi::c_char;
    use std::ffi::c_int;
    unsafe extern "C" {
        fn snprintf(buffer: *mut c_char, size: usize, format: *const c_char, ...) -> c_int;
    }
    let format = CString::new(format).expect("no NUL");
    let mut buffer = vec![0u8; 256];
    // SAFETY: the buffer's size is passed, the format is NUL-terminated, and
    // each conversion in it takes an unsigned int, which `u32` is.
    let written = unsafe {
        snprintf(
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            format.as_ptr(),
            value1,
            value2,
        )
    };
    let written = usize::try_from(written).expect("snprintf succeeded");
    String::from_utf8(buffer[..written].to_vec()).expect("ASCII")
}

#[cfg(unix)]
#[test]
fn each_placeholder_prints_in_c_as_in_rust() {
    for value in [0, 1, 0xAB, 0x8000_0000, u32::MAX] {
        for (placeholder, rust) in [
            ("{}", format!("{value}")),
            ("{:x}", format!("{value:x}")),
            ("{:#x}", format!("{value:#x}")),
            ("{:08x}", format!("{value:08x}")),
            ("{:#010x}", format!("{value:#010x}")),
        ] {
            let c = header::format(placeholder).expect("a C format");
            assert_eq!(c_format(&c, value, 0), rust, "{placeholder} {value}");
        }
    }
}

#[cfg(unix)]
#[test]
fn a_record_decodes_like_the_text_output_line() {
    let m = map("0\tcore\tE+\tc\tcore\top {} failed, 50% {{done}}\n");
    let header = m.decoder_header(&used(&m)).expect("a header");
    let format = header
        .lines()
        .find_map(|line| line.strip_prefix("    [0] = \""))
        .and_then(|rest| rest.strip_suffix("\","))
        .expect("slot 0");
    // With text output, the facade formats this call's message as
    // "op 7 failed, 50% {done} [err:0000c0de]".
    assert_eq!(
        c_format(format, 7, 0xc0de),
        "[core] op 7 failed, 50% {done} [err:0000c0de]"
    );
    assert_eq!(
        c_format("[core] failed [err:%08x]", u32::MAX, 0),
        "[core] failed [err:ffffffff]"
    );
}

/// The firmware's message map: each component's file.
const FIRMWARE_MAP: [(Component, &str); Component::ALL.len()] = [
    (
        Component::Core,
        include_str!("../../../fw/pal/log_map/core.tsv"),
    ),
    (
        Component::Uno,
        include_str!("../../../fw/pal/log_map/uno.tsv"),
    ),
];

/// Compiles `header` as strict C99, with warnings as errors, and returns the
/// compiler's errors. Returns `None` if it compiles, or if there's no `cc`.
#[cfg(unix)]
fn c_errors(header: &str) -> Option<String> {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("tsra-log-map-c-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    std::fs::write(dir.join("log_messages.h"), header).expect("the header");
    // Uses both tables, so that -Wall doesn't report one as unused.
    std::fs::write(
        dir.join("decoder.c"),
        concat!(
            "#include \"log_messages.h\"\n",
            "const char *tsra_log_format(int component, unsigned char number) {\n",
            "    return component == TSRA_LOG_COMPONENT_CORE ? tsra_log_core_messages[number]\n",
            "                                                : tsra_log_uno_messages[number];\n",
            "}\n",
        ),
    )
    .expect("the C file");
    let output = std::process::Command::new("cc")
        .args([
            "-std=c99",
            "-pedantic-errors",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .args(["-Wtrigraphs", "-fsyntax-only", "decoder.c"])
        .current_dir(&dir)
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    match output {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("no cc, so the header isn't compiled");
            None
        }
        Err(e) => panic!("can't run cc: {e}"),
        Ok(output) if output.status.success() => None,
        Ok(output) => Some(String::from_utf8_lossy(&output.stderr).into_owned()),
    }
}

#[cfg(unix)]
#[test]
fn the_decoder_header_compiles_as_c() {
    // A full component, and an empty one.
    let full: String = (0..256)
        .map(|n| format!("{n}\tcore\tI\tc\tt\tmessage {n:03}\n"))
        .collect();
    let full = map(&full);
    // A percent sign, braces, a trigraph, an error code, and a deprecated
    // message.
    let special = map(concat!(
        "0\tuno\tI\td\tio\t50% of {{queue}} {:#x}??) {:08x}\n",
        "1\tuno\tE+\td\tio\top {} failed\n",
        "2\tuno\tW\td\tio\tgone\n",
    ));
    let mut special_used = used(&special);
    special_used.retain(|symbol| !symbol.ends_with(":gone"));
    let special = special.decoder_header(&special_used).expect("a header");
    assert!(special.contains("Deprecated message"), "{special}");
    for (name, header) in [
        ("full", full.decoder_header(&used(&full)).expect("a header")),
        ("special", special),
        (
            "firmware",
            include_str!("../../../fw/pal/log_messages.h").to_string(),
        ),
    ] {
        if let Some(errors) = c_errors(&header) {
            panic!("the {name} header doesn't compile as C:\n{errors}\n{header}");
        }
    }
}

#[test]
fn every_error_format_in_the_firmware_map_ends_with_the_code() {
    let m = Map::parse_files(&FIRMWARE_MAP).expect("the firmware's map");
    let header = m.decoder_header(&used(&m)).expect("a header");
    // Each slot's format, by component and number.
    let mut formats = std::collections::BTreeMap::new();
    let mut table = None;
    for line in header.lines() {
        if let Some(rest) = line.strip_prefix("static const char *const tsra_log_") {
            table = rest.split('_').next();
        } else if let Some(rest) = line.strip_prefix("    [") {
            let (number, rest) = rest.split_once("] = \"").expect("a slot");
            let (format, _) = rest.rsplit_once("\",").expect("a format");
            let number: u8 = number.parse().expect("a decimal number");
            formats.insert((table.expect("a table"), number), format);
        }
    }
    let mut errors = 0;
    for row in m.rows() {
        let format = formats[&(row.component.name(), row.number)];
        let (_, placeholders) = header::convert(&row.key.message).expect("a format");
        // `%%` prints a percent sign; every other `%` starts a conversion.
        let conversions = format.replace("%%", "").matches('%').count();
        if row.key.kind.has_code() {
            // The record carries the code last, after the message's values.
            assert!(format.ends_with(" [err:%08x]"), "{}", row.to_line());
            assert_eq!(conversions, placeholders + 1, "{}", row.to_line());
            errors += 1;
        } else {
            assert!(!format.contains("[err:"), "{}", row.to_line());
            assert_eq!(conversions, placeholders, "{}", row.to_line());
        }
    }
    assert!(errors > 0, "the firmware's map has no error rows");
}

#[test]
fn an_unused_message_is_marked_deprecated() {
    // Version 1 logs "booted" and "slow {}"; version 2 deletes "booted" and
    // rewords "slow {}" as "slow: {} ms".
    let mut m = map("0\tcore\tI\tc\tcore\tbooted\n1\tcore\tW\tc\tcore\tslow {}\n");
    let base = m.to_text(Component::Core);
    m.add(&[(key("c", Kind::Warn, "core", "slow: {} ms"), Component::Core)])
        .expect("a reworded row");
    let used_v2: BTreeSet<String> = [key("c", Kind::Warn, "core", "slow: {} ms").symbol()].into();
    let header = m.decoder_header(&used_v2).expect("a header");
    assert!(
        header.contains("    [0] = \"[core] booted\", // Deprecated message\n"),
        "{header}"
    );
    assert!(
        header.contains("    [1] = \"[core] slow %u\", // Deprecated message\n"),
        "{header}"
    );
    assert!(
        header.contains("    [2] = \"[core] slow: %u ms\",\n"),
        "{header}"
    );
    assert_eq!(check_prefix(&base, &m.to_text(Component::Core)), Ok(()));
    assert_eq!(m.check(), Ok(()));

    // Version 3 restores "booted", from another crate in the same component:
    // it takes its old number, and the mark goes away.
    let before = m.to_text(Component::Core);
    let restored = key("d", Kind::Info, "core", "booted");
    let added = m
        .add(&[(restored.clone(), Component::Core)])
        .expect("a restored row");
    assert_eq!(added[0].number, 0);
    let used_v3: BTreeSet<String> = [
        restored.symbol(),
        key("c", Kind::Warn, "core", "slow: {} ms").symbol(),
    ]
    .into();
    let header = m.decoder_header(&used_v3).expect("a header");
    assert!(
        header.contains("    [0] = \"[core] booted\",\n"),
        "{header}"
    );
    assert!(
        header.contains("    [1] = \"[core] slow %u\", // Deprecated message\n"),
        "{header}"
    );
    assert_eq!(check_prefix(&before, &m.to_text(Component::Core)), Ok(()));
    assert_eq!(m.check(), Ok(()));
}

#[test]
fn a_message_that_one_supported_image_uses_is_not_deprecated() {
    let m = map("0\tuno\tE+\tu\tbulk\tengine failed\n1\tuno\tI\tu\tboot\tready\n");
    let default_image: BTreeSet<String> = [key("u", Kind::Info, "boot", "ready").symbol()].into();
    let bulk_image: BTreeSet<String> =
        [key("u", Kind::ErrorCode, "bulk", "engine failed").symbol()].into();
    let all: BTreeSet<String> = default_image.union(&bulk_image).cloned().collect();
    let header = m.decoder_header(&all).expect("a header");
    assert!(!header.contains("Deprecated"), "{header}");
    let only_default = m.decoder_header(&default_image).expect("a header");
    assert!(
        only_default
            .contains("    [0] = \"[bulk] engine failed [err:%08x]\", // Deprecated message\n"),
        "{only_default}"
    );
}
