// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Tests the debug-log tools on a small fixture image
//! (`xtask/fixtures/log_image`), which links with debug-log output the way
//! the firmware does: locked and fix modes, the generated linker script, the
//! checks on each image, the cross-image source check, the decoder header's
//! deprecation marks, the order of the values in an `error!` record, text
//! output with `error_uart!`, the Uno log crate's compile-time checks, the
//! drops outside `fw/plat/uno/`, and the build matrix.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;
use clap::Parser;
use toml_edit::DocumentMut;
use toml_edit::Item;
use tsra_log_map::Component;
use tsra_log_map::Map;
use walkdir::WalkDir;

use crate::elf::Elf;
use crate::fw_util::FwPaths;
use crate::fw_util::NIGHTLY_TOOLCHAIN;
use crate::log_map;
use crate::log_map::DroppedCall;
use crate::log_map::ImageLog;
use crate::log_map::MissingRows;
use crate::log_map::Mode;
use crate::log_map::Output;
use crate::log_map::TEXT_HOOK;
use crate::Xtask;
use crate::XtaskCtx;

/// The message that only the fixture's variant images log.
const VARIANT_MESSAGE: &str = "only in one variant: {}";

/// The bytes of `.bss` that the fixture's log hook adds: three `u32` values.
const HOOK_BSS: u32 = 12;

/// Text of the fixture's `error_uart!` line, which only text output prints.
const TEXT_ONLY: &str = "a text-only line: ";

/// The function that gives the `error_uart!` line its value.
const TEXT_ONLY_VALUE: &str = "text_only_value";

/// The `level-*` features, from the one that prints the fewest calls.
const LEVELS: [&str; 5] = ["error", "warn", "info", "debug", "trace"];

/// Text that the fixture's calls print, each with the lowest level in
/// `LEVELS` that prints it: an `error!`, a `warn!`, and the dependency's
/// `info!`. Text output prints `TEXT_ONLY` at every level.
const PRINTED: &[(&str, &str)] = &[
    ("  MemManage: IACCVIOL ", "error"),
    ("queue at 50% of {capacity} ", "warn"),
    ("from the dependency: ", "info"),
];

/// The feature that turns on text output for the text builds of the
/// compile-time checks and of the copy outside `fw/plat/uno/`.
const TEXT_FEATURE: &str = "tsra_fw_uno_trace/level-info";

const TARGET: &[&str] = &["with debug-log output, a log target must match [a-z0-9_]+"];
const MESSAGE: &[&str] = &[
    "with debug-log output, a log message can't be empty, end with a space, or hold a double quote, a backslash, or a control character",
];
/// A NUL character also fails the token's name, in every crate.
const MESSAGE_NUL: &[&str] = &[
    "with debug-log output, a log message can't be empty, end with a space, or hold a double quote, a backslash, or a control character",
    "null character",
];
const PLACEHOLDERS: &[&str] =
    &["with debug-log output, a log message needs one placeholder per value"];
const INFO_SHAPE: &[&str] =
    &["with debug-log output, `info!` takes a literal target, a literal message, and at most two values"];
const WARN_SHAPE: &[&str] =
    &["with debug-log output, `warn!` takes a literal target, a literal message, and at most two values"];
const ERROR_SHAPE: &[&str] = &[
    "with debug-log output, `error!` takes a literal target, an error code, a literal message, and at most one value",
];
const VALUE: &[&str] = &["can't be a log value with debug-log output"];
/// A `&str` fails the `Sized` bound first; rustc then lists the `LogValue` types.
const VALUE_REF: &[&str] = &[
    "can't be a log value with debug-log output",
    "__bin::LogValue",
];

/// Each `error!` call in the fixture's own crate, by message, with its error
/// code and the record word that must carry the code. The decoder header
/// appends ` [err:%08x]` to an error's format, so the error code must be the
/// last value that the format uses: the first word for a message with no
/// placeholder, and the second for a message with one.
const ERROR_CALLS: &[(&str, &str, usize)] = &[
    ("failed", "Code(0x5a)", 1),
    ("  MemManage: IACCVIOL {:#x}", "Code(0x5b)", 2),
];

/// Each `fail_case` in the fixture that a compile-time check rejects, with
/// the messages that may reject it.
const FAIL_CASES: &[(&str, &[&str])] = &[
    ("target_upper", TARGET),
    ("target_dash", TARGET),
    ("target_empty", TARGET),
    ("message_empty", MESSAGE),
    ("message_trailing_space", MESSAGE),
    ("message_quote", MESSAGE),
    ("message_backslash", MESSAGE),
    ("message_control", MESSAGE),
    ("message_nul", MESSAGE_NUL),
    ("placeholder_debug", PLACEHOLDERS),
    ("placeholder_width", PLACEHOLDERS),
    ("placeholder_named", PLACEHOLDERS),
    ("placeholder_named_arg", PLACEHOLDERS),
    ("placeholder_missing", PLACEHOLDERS),
    ("placeholder_extra", PLACEHOLDERS),
    ("brace_unpaired", PLACEHOLDERS),
    ("three_values", INFO_SHAPE),
    ("warn_three_values", WARN_SHAPE),
    ("message_not_literal", INFO_SHAPE),
    ("target_not_literal", INFO_SHAPE),
    ("target_runtime", WARN_SHAPE),
    ("error_message_not_literal", ERROR_SHAPE),
    ("error_without_code", ERROR_SHAPE),
    ("error_two_values", ERROR_SHAPE),
    ("code_u64", VALUE),
    ("value_u64", VALUE),
    ("value_i32", VALUE),
    ("value_literal", VALUE),
    ("value_str", VALUE_REF),
];

/// Each `fail_case` in the fixture that repeats a message from another line,
/// which the map check rejects.
const REPEAT_CASES: &[&str] = &[
    "repeat_in_crate",
    "repeat_across_kinds",
    "repeat_across_crates",
];

/// The functions that give dropped calls their values in the fixture's
/// `outside` module, each with whether its call evaluates it without text
/// output: only a call dropped for a value's or the error code's type does.
/// With text output, each call evaluates its values.
const DROPPED_VALUES: &[(&str, bool)] = &[
    ("arg_placeholder", false),
    ("arg_named", false),
    ("arg_shape", false),
    ("arg_wide", true),
    ("arg_code", true),
    ("arg_long_code", true),
];

/// Test the debug-log tools on the fixture image.
#[derive(Parser)]
#[clap(about = "Test the debug-log tools on a small fixture image")]
pub struct LogFixture {}

/// Whether `text` is in a section that takes memory at run time.
fn in_loaded_section(elf: &Elf, text: &str) -> anyhow::Result<bool> {
    for section in elf.sections.iter().filter(|s| s.is_alloc()) {
        let bytes = elf.contents(section)?;
        if bytes.windows(text.len()).any(|w| w == text.as_bytes()) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether the image has a symbol whose mangled name holds `name`, such as a
/// function that the optimizer kept.
fn has_symbol(elf: &Elf, name: &str) -> bool {
    elf.symbols.iter().any(|symbol| symbol.name.contains(name))
}

/// The output that a fixture build with the Cargo arguments `args` asks for:
/// text when one of them turns on a crate's `level-*` feature.
fn fixture_output(args: &[&str]) -> Output {
    let text = args
        .iter()
        .flat_map(|arg| arg.split([',', ' ']))
        .any(|feature| {
            feature
                .rsplit_once('/')
                .is_some_and(|(_, name)| name.starts_with("level-"))
        });
    if text {
        Output::Text
    } else {
        Output::Records
    }
}

/// The two values that the call whose token is `symbol` passes to its record,
/// in macro-expanded source, without whitespace or the path of the Uno log
/// crate's helpers: the last two fields of the tuple that the call's Uno
/// branch (`if __IN`) gives before the record.
fn record_values(expanded: &str, symbol: &str) -> anyhow::Result<[String; 2]> {
    let token = format!("\"{symbol}\"");
    let at = expanded
        .find(&token)
        .with_context(|| format!("the expanded fixture has no token {token}"))?;
    let before = &expanded[..at];
    let values = before
        .rfind("let (__ok_values, __ok_code, __v1, __v2)")
        .with_context(|| format!("no record values come before the token {token}"))?;
    let branch = before[values..].find("if __IN {").with_context(|| {
        format!("the record values before the token {token} have no Uno branch")
    })?;
    let open = before[values + branch..]
        .find('(')
        .with_context(|| format!("the Uno branch before the token {token} has no tuple"))?;
    let mut fields = vec![String::new()];
    let mut depth = 0;
    for c in before[values + branch + open + 1..].chars() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' if depth == 0 => break,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                fields.push(String::new());
                continue;
            }
            c if c.is_whitespace() => continue,
            _ => {}
        }
        fields.last_mut().expect("a field").push(c);
    }
    if fields.last().is_some_and(String::is_empty) {
        fields.pop();
    }
    let fields: Vec<String> = fields
        .iter()
        .map(|field| field.replace("::tsra_fw_uno_debug_log::__bin::", ""))
        .collect();
    match fields.as_slice() {
        [_, _, value1, value2] => Ok([value1.clone(), value2.clone()]),
        _ => anyhow::bail!("the Uno branch before the token {token} gives {fields:?}"),
    }
}

/// Points each path dependency in the manifest at `path`, which reaches
/// outside its directory, at the same crate under `from`.
fn absolute_paths(path: &Path, from: &Path) -> anyhow::Result<()> {
    let text =
        fs::read_to_string(path).with_context(|| format!("can't read {}", path.display()))?;
    let mut doc: DocumentMut = text
        .parse()
        .with_context(|| format!("can't parse {}", path.display()))?;
    for table in ["dependencies", "build-dependencies"] {
        let Some(deps) = doc.get_mut(table).and_then(Item::as_table_like_mut) else {
            continue;
        };
        for (_, dep) in deps.iter_mut() {
            let Some(dep_path) = dep.get_mut("path") else {
                continue;
            };
            let Some(relative) = dep_path.as_str().map(str::to_owned) else {
                continue;
            };
            if relative.starts_with("..") {
                let absolute = from
                    .join(&relative)
                    .canonicalize()
                    .with_context(|| format!("can't find {relative} from {}", from.display()))?;
                *dep_path = toml_edit::value(absolute.to_string_lossy().into_owned());
            }
        }
    }
    fs::write(path, doc.to_string()).with_context(|| format!("can't write {}", path.display()))
}

/// Copies the log fixture's host crate for code above the PAL
/// (`xtask/fixtures/log_above_pal`) to the repository's `target/`, outside
/// `fw/plat/uno/`, where its calls follow the rules for code above the PAL,
/// and returns the copy's directory.
pub fn copy_above_pal(ctx: &XtaskCtx) -> anyhow::Result<PathBuf> {
    let source = FwPaths::new(ctx)?.log_above_pal_dir;
    let copy = log_map::repo_root(ctx)?
        .join("target")
        .join("tsra_log_above_pal");
    fs::create_dir_all(copy.join("src"))?;
    for file in ["Cargo.toml", "src/lib.rs"] {
        fs::copy(source.join(file), copy.join(file))
            .with_context(|| format!("can't copy {}", source.join(file).display()))?;
    }
    absolute_paths(&copy.join("Cargo.toml"), &source)?;
    Ok(copy)
}

/// Runs `cargo rustc` with [`NIGHTLY_TOOLCHAIN`] on the fixture's binary in
/// `dir`, with `cargo_args` for Cargo and `rustc_args` for the binary alone,
/// and returns whether it succeeded, with its standard error.
fn rustc(
    dir: &Path,
    map: &Path,
    cargo_args: &[&str],
    rustc_args: &[&str],
) -> anyhow::Result<(bool, String)> {
    let toolchain = format!("+{NIGHTLY_TOOLCHAIN}");
    let output = Command::new("cargo")
        .args([
            toolchain.as_str(),
            "rustc",
            "--release",
            "--bin",
            "tsra_log_fixture",
        ])
        .args(cargo_args)
        .arg("--")
        .args(rustc_args)
        .current_dir(dir)
        .env("TSRA_LOG_MAP", map)
        .output()
        .context("can't run cargo")?;
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    Ok((output.status.success(), stderr))
}

struct Fixture {
    dir: PathBuf,
    repo: PathBuf,
    scratch: PathBuf,
}

impl Fixture {
    fn elf(&self) -> PathBuf {
        self.dir
            .join("target/thumbv7em-none-eabi/release/tsra_log_fixture")
    }

    /// Builds the fixture with `cargo args` and the scratch map, and reads
    /// and checks the image, expecting the output that `args` asks for.
    fn build_with(&self, label: &str, args: &[&str], mode: Mode) -> anyhow::Result<ImageLog> {
        let envs = [("TSRA_LOG_MAP", self.scratch.as_os_str())];
        log_map::build_with_map(
            &self.dir,
            args,
            &envs,
            &self.scratch,
            &self.repo,
            mode,
            "cargo xtask log-fixture",
        )?;
        let map = Map::read_dir(&self.scratch)?;
        log_map::read_image(label, &self.elf(), &map, fixture_output(args))
    }

    /// Builds the fixture with the scratch map and `extra` Cargo arguments,
    /// and reads and checks the image.
    fn build(&self, label: &str, extra: &[&str], mode: Mode) -> anyhow::Result<ImageLog> {
        let toolchain = format!("+{NIGHTLY_TOOLCHAIN}");
        let mut args = vec![toolchain.as_str(), "build", "--release"];
        args.extend_from_slice(extra);
        self.build_with(label, &args, mode)
    }

    /// Copies the fixture outside `fw/plat/uno/`, to the repository's
    /// `target/`, where its calls follow the rules for code above the PAL,
    /// and returns the copy's directory.
    fn copy_outside(&self) -> anyhow::Result<PathBuf> {
        let copy = self.repo.join("target").join("tsra_log_fixture_outside");
        let walk = WalkDir::new(&self.dir)
            .into_iter()
            .filter_entry(|entry| entry.file_name() != "target");
        for entry in walk {
            let entry = entry?;
            let to = copy.join(entry.path().strip_prefix(&self.dir)?);
            if entry.file_type().is_dir() {
                fs::create_dir_all(&to)?;
            } else {
                fs::copy(entry.path(), &to)
                    .with_context(|| format!("can't copy {}", entry.path().display()))?;
            }
        }
        for manifest in ["Cargo.toml", "dep/Cargo.toml"] {
            let from = self.dir.join(manifest);
            let from = from.parent().context("a manifest's directory")?;
            absolute_paths(&copy.join(manifest), from)?;
        }
        Ok(copy)
    }
}

impl Xtask for LogFixture {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let toolchain = format!("+{NIGHTLY_TOOLCHAIN}");
        let dir = FwPaths::new(&ctx)?.log_fixture_dir;
        let scratch = dir.join("target").join("log_fixture").join("log_map");
        fs::create_dir_all(&scratch)?;
        let fixture = Fixture {
            repo: log_map::repo_root(&ctx)?,
            scratch,
            dir,
        };
        let golden_dir = fixture.dir.join("log_map");
        // Each component's golden map file: its component, name, and text.
        let mut golden_files = Vec::new();
        for component in Component::ALL {
            let name = component.file_name();
            let path = golden_dir.join(&name);
            let text = fs::read_to_string(&path)
                .with_context(|| format!("can't read {}", path.display()))?;
            golden_files.push((component, name, text));
        }
        let golden = Map::read_dir(&golden_dir)?;
        let expected: BTreeSet<String> = golden
            .rows()
            .filter(|row| row.key.message != VARIANT_MESSAGE)
            .map(|row| row.key.symbol())
            .collect();

        log::info!("--- locked mode names every message without a row");
        for (_, name, text) in &golden_files {
            let comments: String = text
                .lines()
                .take_while(|line| line.starts_with('#'))
                .map(|line| format!("{line}\n"))
                .collect();
            fs::write(fixture.scratch.join(name), comments)?;
        }
        let error = match fixture.build("default", &[], Mode::Locked) {
            Ok(_) => anyhow::bail!("locked mode linked the fixture with no map rows"),
            Err(e) => e,
        };
        let missing = error
            .downcast_ref::<MissingRows>()
            .with_context(|| format!("locked mode failed for another reason: {error:#}"))?;
        let named: BTreeSet<String> = missing.keys.iter().map(|key| key.symbol()).collect();
        anyhow::ensure!(
            named == expected,
            "locked mode named {named:#?}, but the fixture logs {expected:#?}"
        );

        log::info!("--- fix mode adds the rows that the map's files hold");
        let default = fixture.build("default", &[], Mode::Fix)?;
        let elf = Elf::read(&fixture.elf())?;
        anyhow::ensure!(
            !in_loaded_section(&elf, TEXT_ONLY)? && !has_symbol(&elf, TEXT_ONLY_VALUE),
            "the image with debug-log output keeps a text-only line or evaluates its value"
        );

        log::info!("--- reading an image fails when a token's row has another number or is gone");
        let row = golden
            .rows()
            .find(|row| row.key.message == "started")
            .context("the fixture map has no row for `started`")?;
        let line = row.to_line();
        let (_, rest) = line
            .split_once('\t')
            .context("a map row starts with its number")?;
        let (_, _, row_file) = golden_files
            .iter()
            .find(|(component, _, _)| *component == row.component)
            .context("the row's component has no map file")?;
        for (text, problem) in [
            (
                row_file.replace(&line, &format!("9\t{rest}")),
                "has the value",
            ),
            (row_file.replace(&format!("{line}\n"), ""), "has no row"),
        ] {
            anyhow::ensure!(
                text != *row_file,
                "the map edit for {problem:?} changed nothing"
            );
            // The edited file, with the other components' golden files.
            let files: Vec<(Component, &str)> = golden_files
                .iter()
                .map(|(component, _, golden_text)| {
                    let file = if *component == row.component {
                        &text
                    } else {
                        golden_text
                    };
                    (*component, file.as_str())
                })
                .collect();
            let error = log_map::read_image(
                "default",
                &fixture.elf(),
                &Map::parse_files(&files)?,
                Output::Records,
            )
            .err()
            .with_context(|| format!("the image passed with a map whose token {problem}"))?;
            let expected = format!("token {} {problem}", row.key.symbol());
            anyhow::ensure!(
                format!("{error:#}").contains(&expected),
                "the image failed without {expected:?}: {error:#}"
            );
        }
        let variant_a = fixture.build("variant_a", &["--features", "variant_a"], Mode::Fix)?;
        let variant_b = fixture.build("variant_b", &["--features", "variant_b"], Mode::Fix)?;
        for (_, name, text) in &golden_files {
            let scratch = fixture.scratch.join(name);
            anyhow::ensure!(
                fs::read_to_string(&scratch)? == *text,
                "fix mode wrote {}, which differs from {}",
                scratch.display(),
                golden_dir.join(name).display()
            );
        }
        let tokens: BTreeSet<String> = default.tokens.keys().cloned().collect();
        anyhow::ensure!(
            tokens == expected && default.sites.len() == expected.len() && default.drops.is_empty(),
            "the image refers to {tokens:#?}, has {} messages with markers, and drops {:?}, but \
             the fixture logs {expected:#?}",
            default.sites.len(),
            default.drops
        );

        log::info!("--- a message has one source line across images");
        log_map::check_sites(&[&default, &variant_a])?;
        let error = log_map::check_sites(&[&default, &variant_a, &variant_b])
            .err()
            .context("the source check passed a message from two lines")?;
        let text = format!("{error:#}");
        anyhow::ensure!(
            text.contains("(variant_a)") && text.contains("(variant_b)"),
            "the source check failed without naming both lines: {text}"
        );

        log::info!("--- the decoder header marks the messages that no image uses");
        let used: BTreeSet<String> = default.tokens.keys().cloned().collect();
        let header = golden.decoder_header(&used)?;
        let deprecated = format!(
            "\"[fixture] {}\", // Deprecated message",
            "only in one variant: %u"
        );
        anyhow::ensure!(
            header.matches("// Deprecated message").count() == 1 && header.contains(&deprecated),
            "the header doesn't mark exactly the variant's message:\n{header}"
        );
        let used: BTreeSet<String> = used
            .into_iter()
            .chain(variant_a.tokens.keys().cloned())
            .collect();
        let header = golden.decoder_header(&used)?;
        anyhow::ensure!(
            !header.contains("Deprecated"),
            "the header marks a message that an image uses:\n{header}"
        );

        log::info!("--- `error!` with debug-log output passes the error code last");
        let output = Command::new("cargo")
            .args([
                toolchain.as_str(),
                "rustc",
                "--release",
                "--bin",
                "tsra_log_fixture",
                "--",
                "-Zunpretty=expanded",
            ])
            .current_dir(&fixture.dir)
            .env("TSRA_LOG_MAP", &fixture.scratch)
            .output()
            .context("can't run cargo")?;
        anyhow::ensure!(
            output.status.success(),
            "can't expand the fixture's macros:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let expanded = String::from_utf8(output.stdout).context("the expansion isn't UTF-8")?;
        let errors: Vec<_> = golden
            .rows()
            .filter(|row| row.key.crate_name == "tsra_log_fixture" && row.key.kind.has_code())
            .collect();
        anyhow::ensure!(
            errors.len() == ERROR_CALLS.len(),
            "the fixture has {} error rows, but ERROR_CALLS lists {}",
            errors.len(),
            ERROR_CALLS.len()
        );
        for row in errors {
            let (code, word) = ERROR_CALLS
                .iter()
                .find(|(message, _, _)| *message == row.key.message)
                .map(|(_, code, word)| (*code, *word))
                .with_context(|| format!("ERROR_CALLS lacks {:?}", row.key.message))?;
            let values = record_values(&expanded, &row.key.symbol())?;
            let converted = format!("Strict::<{{__IN}}>::code(&{code}.0)");
            anyhow::ensure!(
                values[word - 1] == converted && !values[2 - word].contains(code),
                "error {:?} passes {values:?} to its record, not {converted} as word {word}",
                row.key.message
            );
        }

        log::info!(
            "--- above the PAL, calls record, drop, and print by their rules, and the facade \
             prints text alone on the host"
        );
        let above = copy_above_pal(&ctx)?;
        let output = Command::new("cargo")
            .args([toolchain.as_str(), "test", "--quiet"])
            .current_dir(&above)
            .output()
            .context("can't run cargo")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::ensure!(
            output.status.success() && stdout.contains("test result: ok. 6 passed"),
            "the tests above the PAL failed in {}:\n{stdout}{}",
            above.display(),
            String::from_utf8_lossy(&output.stderr)
        );

        log::info!("--- the linker script keeps cortex-m-rt's boundary symbols");
        let plain = fixture.build("no_debug_log", &["--no-default-features"], Mode::Locked)?;
        anyhow::ensure!(
            plain.tokens.is_empty() && plain.sites.is_empty(),
            "the image without debug-log output has tokens or markers"
        );
        let sym = |image: &ImageLog, name: &str| {
            image
                .boundary
                .get(name)
                .copied()
                .with_context(|| format!("image {} lacks {name}", image.label))
        };
        let size = |image: &ImageLog| -> anyhow::Result<i64> {
            Ok(i64::from(sym(image, "__ebss")?) - i64::from(sym(image, "__sbss")?))
        };
        let delta = size(&default)? - size(&plain)?;
        anyhow::ensure!(
            delta == i64::from(HOOK_BSS),
            ".bss grew by {delta} bytes with debug-log output, not by the hook's {HOOK_BSS}"
        );
        let plain_ebss = sym(&plain, "__ebss")?;
        for name in log_map::BOUNDARY_SYMBOLS {
            let (Some(&with), Some(&without)) =
                (default.boundary.get(name), plain.boundary.get(name))
            else {
                continue;
            };
            let shift = if without >= plain_ebss && name != "_stack_start" {
                HOOK_BSS
            } else {
                0
            };
            anyhow::ensure!(
                with == without.wrapping_add(shift),
                "{name} is {with:#x} with debug-log output, but {without:#x} + {shift} without it"
            );
        }

        log::info!(
            "--- a level-* feature prints the calls at or above its level, error_uart! \
             included; with the debug-log feature, each call records too"
        );
        let error_row = golden
            .rows()
            .find(|row| row.key.message == "  MemManage: IACCVIOL {:#x}")
            .context("the fixture map has no row for the IACCVIOL error")?;
        let loaded = format!(
            "the text {:?} of token {} is in a loaded section",
            "  MemManage: IACCVIOL ",
            error_row.key.symbol()
        );
        let hook = format!("the image defines the text hook {TEXT_HOOK}");
        let rank = |level: &str| LEVELS.iter().position(|l| *l == level);
        for level in LEVELS {
            let feature = format!("tsra_fw_uno_trace/level-{level}");
            for records in [true, false] {
                let (label, args) = if records {
                    (format!("level-{level}"), vec!["--features", &feature])
                } else {
                    (
                        format!("level-{level}-no-debug-log"),
                        vec!["--no-default-features", "--features", &feature],
                    )
                };
                let image = fixture.build(&label, &args, Mode::Locked)?;
                let elf = Elf::read(&fixture.elf())?;
                let recorded = if records {
                    image.tokens.keys().eq(default.tokens.keys()) && image.sites == default.sites
                } else {
                    image.tokens.is_empty() && image.sites.is_empty()
                };
                anyhow::ensure!(
                    recorded && image.drops.is_empty(),
                    "the {label} image refers to {:#?}, has markers for {:?}, and drops {:?}",
                    image.tokens.keys(),
                    image.sites.keys(),
                    image.drops
                );
                for (text, lowest) in PRINTED {
                    let printed = in_loaded_section(&elf, text)?;
                    anyhow::ensure!(
                        printed == (rank(level) >= rank(lowest)),
                        "the {label} image {} {text:?}",
                        if printed { "prints" } else { "doesn't print" }
                    );
                }
                anyhow::ensure!(
                    in_loaded_section(&elf, TEXT_ONLY)?
                        && has_symbol(&elf, TEXT_ONLY_VALUE)
                        && elf.symbol(TEXT_HOOK).is_some(),
                    "the {label} image doesn't print the error_uart! line through the text hook"
                );
                // Read as an image without text output, it fails on the hook,
                // and on the text of each call that it records and prints.
                let error = log_map::read_image(&label, &fixture.elf(), &golden, Output::Records)
                    .err()
                    .with_context(|| {
                        format!("the {label} image passed as one without text output")
                    })?;
                let error = format!("{error:#}");
                anyhow::ensure!(
                    error.contains(&hook) && error.contains(&loaded) == records,
                    "the {label} image failed as one without text output with: {error}"
                );
            }
        }

        log::info!("--- error_uart! takes text output from the Uno trace crate's level-* features");
        let image = fixture.build(
            "facade-level-warn",
            &["--features", "tsra_fw_hsm_core_tracing/level-warn"],
            Mode::Locked,
        )?;
        let elf = Elf::read(&fixture.elf())?;
        anyhow::ensure!(
            image.tokens.keys().eq(default.tokens.keys())
                && in_loaded_section(&elf, "  MemManage: IACCVIOL ")?
                && !in_loaded_section(&elf, TEXT_ONLY)?
                && !has_symbol(&elf, TEXT_ONLY_VALUE),
            "the facade's level-warn alone doesn't record each call and print error! without \
             error_uart!"
        );

        log::info!("--- reading an image fails when a message's text is in a loaded section");
        let cfg = "fail_case=\"text_loaded\"";
        let (ok, stderr) = rustc(&fixture.dir, &fixture.scratch, &[], &["--cfg", cfg])?;
        anyhow::ensure!(ok, "case text_loaded didn't build:\n{stderr}");
        let error = log_map::read_image("text_loaded", &fixture.elf(), &golden, Output::Records)
            .err()
            .context("the image passed with a message's text in a loaded section")?;
        anyhow::ensure!(
            format!("{error:#}").contains(&loaded),
            "the image failed without {loaded:?}: {error:#}"
        );
        // A build that asks for text may keep it.
        log_map::read_image("text_loaded", &fixture.elf(), &golden, Output::Text)
            .context("the image with a message's text failed as a text image")?;

        log::info!(
            "--- reading an image fails when it defines the text hook, but its build asked for \
             no text"
        );
        let cfg = "fail_case=\"text_hook\"";
        let (ok, stderr) = rustc(&fixture.dir, &fixture.scratch, &[], &["--cfg", cfg])?;
        anyhow::ensure!(ok, "case text_hook didn't build:\n{stderr}");
        let error = log_map::read_image("text_hook", &fixture.elf(), &golden, Output::Records)
            .err()
            .context("the image passed with the text hook")?;
        anyhow::ensure!(
            format!("{error:#}").contains(&hook),
            "the image failed without {hook:?}: {error:#}"
        );
        log_map::read_image("text_hook", &fixture.elf(), &golden, Output::Text)
            .context("the image with the text hook failed as a text image")?;

        log::info!("--- each debug-log check rejects its bad call, with and without text output");
        for (case, expected) in FAIL_CASES {
            let cfg = format!("fail_case=\"{case}\"");
            for features in [&[][..], &["--features", TEXT_FEATURE][..]] {
                let (ok, stderr) =
                    rustc(&fixture.dir, &fixture.scratch, features, &["--cfg", &cfg])?;
                anyhow::ensure!(
                    !ok,
                    "case {case} built with {features:?}, but a check should reject it"
                );
                anyhow::ensure!(
                    expected.iter().any(|e| stderr.contains(e)),
                    "case {case} failed with {features:?} without the expected message \
                     {expected:?}:\n{stderr}"
                );
            }
            log::info!("case {case}: rejected");
        }

        log::info!("--- the map check rejects a Uno message from two lines");
        for case in REPEAT_CASES {
            let cfg = format!("fail_case=\"{case}\"");
            let args = [
                toolchain.as_str(),
                "rustc",
                "--release",
                "--bin",
                "tsra_log_fixture",
                "--",
                "--cfg",
                cfg.as_str(),
            ];
            let image = fixture.build_with(case, &args, Mode::Fix)?;
            let error = log_map::check_sites(&[&image])
                .err()
                .with_context(|| format!("case {case} passed the map check"))?;
            let text = format!("{error:#}");
            anyhow::ensure!(
                text.contains("comes from more than one line"),
                "case {case} failed the map check for another reason: {text}"
            );
            log::info!("case {case}: rejected by the map check");
        }

        log::info!("--- outside fw/plat/uno, a call that doesn't fit drops with a note");
        let copy = fixture.copy_outside()?;
        let (ok, stderr) = rustc(&copy, &copy.join("log_map"), &[], &["--cfg", "outside"])?;
        anyhow::ensure!(
            ok && !stderr.contains("warning"),
            "the fixture's copy in {} didn't build cleanly:\n{stderr}",
            copy.display()
        );
        let path = copy.join("target/thumbv7em-none-eabi/release/tsra_log_fixture");
        let outside = log_map::read_image("outside", &path, &golden, Output::Records)?;
        log_map::report_drops(&outside, &fixture.repo);
        let source = fs::read_to_string(fixture.dir.join("src/main.rs"))?;
        let noted = |prefix: &str| -> BTreeSet<DroppedCall> {
            source
                .lines()
                .enumerate()
                .filter_map(|(index, line)| {
                    let reason = line.trim().strip_prefix(prefix)?;
                    Some(DroppedCall {
                        crate_name: "tsra_log_fixture".to_string(),
                        // The call is on the line after its comment.
                        site: format!("src/main.rs:{}", index + 2),
                        reason: reason.to_string(),
                    })
                })
                .collect()
        };
        let drops = noted("// drop: ");
        let uncalled = noted("// uncalled: ");
        let calls: BTreeSet<DroppedCall> = outside.drops.difference(&uncalled).cloned().collect();
        anyhow::ensure!(
            !drops.is_empty() && calls == drops,
            "the copy drops {calls:#?}, but the fixture marks {drops:#?}"
        );
        anyhow::ensure!(
            uncalled.len() == 1 && uncalled.is_subset(&outside.drops),
            "the drop note of the exported function with no caller isn't in the image: \
             {uncalled:#?}"
        );
        anyhow::ensure!(
            outside.tokens.keys().eq(default.tokens.keys()) && outside.sites.is_empty(),
            "the copy refers to {:#?} and has markers for {:?}, but its calls that fit \
             repeat the default image's messages",
            outside.tokens.keys(),
            outside.sites.keys()
        );
        let elf = Elf::read(&path)?;
        for (name, evaluated) in DROPPED_VALUES {
            anyhow::ensure!(
                has_symbol(&elf, name) == *evaluated,
                "the copy {} {name}",
                if *evaluated {
                    "doesn't evaluate"
                } else {
                    "evaluates"
                }
            );
        }
        // The link drops the function, but not its note.
        anyhow::ensure!(
            elf.symbol("tsra_log_fixture_uncalled").is_none(),
            "the copy keeps the exported function with no caller"
        );

        log::info!(
            "--- outside fw/plat/uno, with text output, the same calls drop with their notes, \
             and each call evaluates its values"
        );
        let (ok, stderr) = rustc(
            &copy,
            &copy.join("log_map"),
            &["--features", TEXT_FEATURE],
            &["--cfg", "outside"],
        )?;
        anyhow::ensure!(
            ok && !stderr.contains("warning"),
            "the fixture's copy in {} didn't build cleanly with {TEXT_FEATURE}:\n{stderr}",
            copy.display()
        );
        let text = log_map::read_image("outside-text", &path, &golden, Output::Text)?;
        anyhow::ensure!(
            text.drops == outside.drops
                && text.tokens.keys().eq(default.tokens.keys())
                && text.sites.is_empty(),
            "with {TEXT_FEATURE}, the copy drops {:#?}, refers to {:#?}, and has markers for \
             {:?}",
            text.drops,
            text.tokens.keys(),
            text.sites.keys()
        );
        let elf = Elf::read(&path)?;
        for (name, _) in DROPPED_VALUES {
            anyhow::ensure!(
                has_symbol(&elf, name),
                "with {TEXT_FEATURE}, the copy doesn't evaluate {name}"
            );
        }

        let cfg = "fail_case=\"message_nul\"";
        let (ok, stderr) = rustc(
            &copy,
            &copy.join("log_map"),
            &[],
            &["--cfg", "outside", "--cfg", cfg],
        )?;
        anyhow::ensure!(
            !ok && stderr.contains("null character"),
            "a NUL character in a message outside fw/plat/uno didn't fail the build:\n{stderr}"
        );

        log::info!("The log fixture passed.");
        Ok(())
    }
}
