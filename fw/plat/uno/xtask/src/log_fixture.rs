// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Tests the debug-log tools on a small fixture image
//! (`xtask/fixtures/log_image`), which links with debug-log output the way
//! the firmware does: locked and fix modes, the generated linker script, the
//! checks on each image, the cross-image source check, the decoder header's
//! deprecation marks, the order of the values in an `error!` record, text
//! output and `error_text!`, the Uno log crate's compile-time checks, the
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
use crate::Xtask;
use crate::XtaskCtx;

/// The message that only the fixture's variant images log.
const VARIANT_MESSAGE: &str = "only in one variant: {}";

/// The bytes of `.bss` that the fixture's log hook adds: three `u32` values.
const HOOK_BSS: u32 = 12;

/// Text of the fixture's `error_text!` line, which only text output prints.
const TEXT_ONLY: &str = "a text-only line: ";

/// The function that gives the `error_text!` line its value.
const TEXT_ONLY_VALUE: &str = "text_only_value";

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
/// `outside` module, each with whether its call evaluates it: only a call
/// dropped for a value's or the error code's type does.
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

/// Runs `cargo rustc` with [`NIGHTLY_TOOLCHAIN`] on the fixture's binary in
/// `dir`, with `rustc_args` for the binary alone, and returns whether it
/// succeeded, with its standard error.
fn rustc(dir: &Path, map: &Path, rustc_args: &[&str]) -> anyhow::Result<(bool, String)> {
    let toolchain = format!("+{NIGHTLY_TOOLCHAIN}");
    let output = Command::new("cargo")
        .args([
            toolchain.as_str(),
            "rustc",
            "--release",
            "--bin",
            "tsra_log_fixture",
            "--",
        ])
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
    /// and checks the image.
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
        let map = Map::parse(&fs::read_to_string(&self.scratch)?)?;
        log_map::read_image(label, &self.elf(), &map)
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
        let scratch_dir = dir.join("target").join("log_fixture");
        fs::create_dir_all(&scratch_dir)?;
        let fixture = Fixture {
            repo: log_map::repo_root(&ctx)?,
            scratch: scratch_dir.join("log_map.tsv"),
            dir,
        };
        let golden_path = fixture.dir.join("log_map.tsv");
        let golden_text = fs::read_to_string(&golden_path)
            .with_context(|| format!("can't read {}", golden_path.display()))?;
        let golden = Map::parse(&golden_text)?;
        let expected: BTreeSet<String> = golden
            .rows()
            .filter(|row| row.key.message != VARIANT_MESSAGE)
            .map(|row| row.key.symbol())
            .collect();

        log::info!("--- locked mode names every message without a row");
        let comments: String = golden_text
            .lines()
            .take_while(|line| line.starts_with('#'))
            .map(|line| format!("{line}\n"))
            .collect();
        fs::write(&fixture.scratch, &comments)?;
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

        log::info!("--- fix mode adds the rows that the map file holds");
        let default = fixture.build("default", &[], Mode::Fix)?;
        let elf = Elf::read(&fixture.elf())?;
        anyhow::ensure!(
            !in_loaded_section(&elf, TEXT_ONLY)? && !has_symbol(&elf, TEXT_ONLY_VALUE),
            "the image with debug-log output keeps the error_text! line or evaluates its value"
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
        for (text, problem) in [
            (
                golden_text.replace(&line, &format!("9\t{rest}")),
                "has the value",
            ),
            (golden_text.replace(&format!("{line}\n"), ""), "has no row"),
        ] {
            anyhow::ensure!(
                text != golden_text,
                "the map edit for {problem:?} changed nothing"
            );
            let error = log_map::read_image("default", &fixture.elf(), &Map::parse(&text)?)
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
        anyhow::ensure!(
            fs::read_to_string(&fixture.scratch)? == golden_text,
            "fix mode wrote {}, which differs from {}",
            fixture.scratch.display(),
            golden_path.display()
        );
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

        log::info!("--- above the PAL, `error!` passes the error code last too");
        let source = FwPaths::new(&ctx)?.log_above_pal_dir;
        let above = fixture.repo.join("target").join("tsra_log_above_pal");
        fs::create_dir_all(above.join("src"))?;
        for file in ["Cargo.toml", "src/lib.rs"] {
            fs::copy(source.join(file), above.join(file))
                .with_context(|| format!("can't copy {}", source.join(file).display()))?;
        }
        absolute_paths(&above.join("Cargo.toml"), &source)?;
        let output = Command::new("cargo")
            .args([toolchain.as_str(), "test", "--quiet"])
            .current_dir(&above)
            .output()
            .context("can't run cargo")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        anyhow::ensure!(
            output.status.success() && stdout.contains("test result: ok. 1 passed"),
            "the test of error records above the PAL failed in {}:\n{stdout}{}",
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
            "--- the debug-log feature with a level-* feature prints text, error_text! included, \
             and makes no records"
        );
        for level in ["error", "warn", "info", "debug", "trace"] {
            let feature = format!("tsra_fw_uno_trace/level-{level}");
            let image = fixture.build(
                &format!("level-{level}"),
                &["--features", feature.as_str()],
                Mode::Locked,
            )?;
            // Every level prints `error!` calls, so this text is in the image.
            let elf = Elf::read(&fixture.elf())?;
            let text = in_loaded_section(&elf, "  MemManage: IACCVIOL ")?
                && in_loaded_section(&elf, TEXT_ONLY)?
                && has_symbol(&elf, TEXT_ONLY_VALUE);
            anyhow::ensure!(
                image.tokens.is_empty() && image.sites.is_empty() && image.drops.is_empty() && text,
                "the debug-log feature with level-{level} doesn't print text only"
            );
            // Given the default image's tokens, `loaded_texts`, the search
            // that reading an image runs, finds this printed text.
            let texts = log_map::loaded_texts(&elf, default.tokens.keys())?;
            anyhow::ensure!(
                texts
                    .iter()
                    .any(|(_, found)| found == "  MemManage: IACCVIOL "),
                "loaded_texts finds {texts:?} in the level-{level} image, but not the text of \
                 an error! call"
            );
        }

        log::info!("--- error_text! takes text output from the Uno trace crate's level-* features");
        let image = fixture.build(
            "facade-level-warn",
            &["--features", "tsra_fw_hsm_core_tracing/level-warn"],
            Mode::Locked,
        )?;
        let elf = Elf::read(&fixture.elf())?;
        anyhow::ensure!(
            image.tokens.is_empty()
                && image.sites.is_empty()
                && in_loaded_section(&elf, "  MemManage: IACCVIOL ")?
                && !in_loaded_section(&elf, TEXT_ONLY)?
                && !has_symbol(&elf, TEXT_ONLY_VALUE),
            "the facade's level-warn alone doesn't print error! without error_text!"
        );

        log::info!("--- reading an image fails when a message's text is in a loaded section");
        let cfg = "fail_case=\"text_loaded\"";
        let (ok, stderr) = rustc(&fixture.dir, &fixture.scratch, &["--cfg", cfg])?;
        anyhow::ensure!(ok, "case text_loaded didn't build:\n{stderr}");
        let kept = "  MemManage: IACCVIOL ";
        let error_row = golden
            .rows()
            .find(|row| row.key.message == "  MemManage: IACCVIOL {:#x}")
            .context("the fixture map has no row for the IACCVIOL error")?;
        let expected = format!(
            "the text {kept:?} of token {} is in a loaded section",
            error_row.key.symbol()
        );
        let error = log_map::read_image("text_loaded", &fixture.elf(), &golden)
            .err()
            .context("the image passed with a message's text in a loaded section")?;
        anyhow::ensure!(
            format!("{error:#}").contains(&expected),
            "the image failed without {expected:?}: {error:#}"
        );

        log::info!("--- each debug-log check rejects its bad call");
        for (case, expected) in FAIL_CASES {
            let cfg = format!("fail_case=\"{case}\"");
            let (ok, stderr) = rustc(&fixture.dir, &fixture.scratch, &["--cfg", &cfg])?;
            anyhow::ensure!(!ok, "case {case} built, but a check should reject it");
            anyhow::ensure!(
                expected.iter().any(|e| stderr.contains(e)),
                "case {case} failed without the expected message {expected:?}:\n{stderr}"
            );
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
        let (ok, stderr) = rustc(&copy, &copy.join("log_map.tsv"), &["--cfg", "outside"])?;
        anyhow::ensure!(
            ok && !stderr.contains("warning"),
            "the fixture's copy in {} didn't build cleanly:\n{stderr}",
            copy.display()
        );
        let path = copy.join("target/thumbv7em-none-eabi/release/tsra_log_fixture");
        let outside = log_map::read_image("outside", &path, &golden)?;
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
        let cfg = "fail_case=\"message_nul\"";
        let (ok, stderr) = rustc(
            &copy,
            &copy.join("log_map.tsv"),
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
