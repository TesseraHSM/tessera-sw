// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Debug-log output: builds that add message-map rows (fix mode) or fail on a
//! message without one (locked mode), the checks on each linked image, the
//! decoder header, and the check of the map against the base branch's map.
//!
//! Which log calls survive optimization decides which messages need rows,
//! and which ones the decoder header marks as deprecated. So a compiler
//! update can fail a locked build or the header check with no source change.
//! Running `cargo xtask log-map` in fw/plat/uno and committing the map's
//! files and the header fixes both.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use anyhow::Context;
use clap::Parser;
use toml_edit::DocumentMut;
use tsra_log_map::Component;
use tsra_log_map::Key;
use tsra_log_map::Map;
use tsra_log_map::DROP_SECTION;
use tsra_log_map::SITE_SECTION;
use tsra_log_map::TOKEN_PREFIX;
use walkdir::WalkDir;
use xshell::cmd;
use xshell::Shell;

use crate::build::Build;
use crate::elf::Elf;
use crate::elf::SHN_ABS;
use crate::fw_util;
use crate::Xtask;
use crate::XtaskCtx;

/// The message map's directory, relative to the platform workspace. It holds
/// one file per component, named for the component, such as `uno.tsv`.
pub const MAP_DIR: &str = "fw/pal/log_map";

/// The decoder header, relative to the platform workspace.
pub const HEADER: &str = "fw/pal/log_messages.h";

/// The images that `cargo xtask log-map` and `cargo xtask precheck --build`
/// build and read, each one's name and features, in build order. A message
/// counts as in use for the decoder header if any of them logs it, so the
/// list holds the PAL's test-hook images as well as the supported images
/// (default, `bulk_crypto`, and emulator). The default image builds last, so
/// it is what remains in `target/` afterwards.
pub const MAP_IMAGES: [(&str, Option<&str>); 5] = [
    ("bulk_crypto", Some(fw_util::BULK_CRYPTO_FEATURE)),
    ("emulator", Some(fw_util::EMULATOR_FEATURE)),
    ("tsra_test_hooks", Some(fw_util::TEST_HOOKS_FEATURE)),
    (
        "fips_validation_hooks",
        Some(fw_util::FIPS_VALIDATION_HOOKS_FEATURE),
    ),
    ("default", None),
];

/// `cortex-m-rt`'s boundary symbols for RAM, which a misplaced section moves.
pub const BOUNDARY_SYMBOLS: [&str; 9] = [
    "__sdata",
    "__edata",
    "__sbss",
    "__ebss",
    "__suninit",
    "__euninit",
    "__sheap",
    "_stack_start",
    "_stack_end",
];

/// What a build does about a message that has no row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Add the row, then link again.
    Fix,
    /// Fail, naming the message.
    Locked,
}

/// A locked-mode failure: the messages that have no row.
#[derive(Debug)]
pub struct MissingRows {
    /// The messages, as their tokens' fields.
    pub keys: BTreeSet<Key>,
    /// The command that adds their rows.
    pub fix: String,
}

impl fmt::Display for MissingRows {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "the message map has no row for these messages:")?;
        for key in &self.keys {
            writeln!(
                f,
                "  {} {} [{}] {}",
                key.crate_name,
                key.kind.code(),
                key.target,
                key.message
            )?;
        }
        write!(
            f,
            "To add their rows, run `{}` in fw/plat/uno, then `cargo xtask log-map` to update \
             the decoder header, and commit the map's files in fw/plat/uno/{MAP_DIR} and \
             fw/plat/uno/{HEADER} with the change. A compiler update can cause this with no \
             source change, because it can change which log calls survive optimization; then \
             `cargo xtask log-map` alone adds the rows and updates the header, and committing \
             them fixes it.",
            self.fix
        )
    }
}

impl std::error::Error for MissingRows {}

/// The repository's root: three levels above the platform workspace.
pub fn repo_root(ctx: &XtaskCtx) -> anyhow::Result<PathBuf> {
    let repo = ctx
        .root
        .ancestors()
        .nth(3)
        .context("the platform workspace has no repository above it")?;
    anyhow::ensure!(
        repo.join("fw/plat/uno/Cargo.toml").exists(),
        "{} isn't the repository root",
        repo.display()
    );
    Ok(repo.to_path_buf())
}

/// Reads and parses the message map's files.
pub fn read_map(ctx: &XtaskCtx) -> anyhow::Result<Map> {
    Ok(Map::read_dir(&ctx.root.join(MAP_DIR))?)
}

/// Runs `cargo` with `args` in `dir`, passing its standard error through, and
/// returns whether it succeeded, with the standard error's text.
fn run_cargo(dir: &Path, args: &[&str], envs: &[(&str, &OsStr)]) -> anyhow::Result<(bool, String)> {
    log::info!("$ cargo {}", args.join(" "));
    let mut child = Command::new("cargo")
        .args(args)
        .current_dir(dir)
        .envs(envs.iter().copied())
        .stderr(Stdio::piped())
        .spawn()
        .context("can't run cargo")?;
    let stderr = child.stderr.take().context("cargo has no standard error")?;
    let mut text = String::new();
    for line in BufReader::new(stderr).split(b'\n') {
        let line = String::from_utf8_lossy(&line?).into_owned();
        eprintln!("{line}");
        text.push_str(&line);
        text.push('\n');
    }
    Ok((child.wait()?.success(), text))
}

/// Removes terminal color sequences (`ESC [ ... letter`) from a line.
fn strip_escapes(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
        } else if chars.next() == Some('[') {
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        }
    }
    out
}

/// The messages that a failed link reports as missing. Each symbol runs to
/// the end of its line, so the spaces in a message stay.
pub fn missing_rows(stderr: &str) -> anyhow::Result<BTreeSet<Key>> {
    const UNDEFINED: &str = "undefined symbol: ";
    let mut keys = BTreeSet::new();
    for line in stderr.lines() {
        let line = strip_escapes(line);
        if let Some(at) = line.find(UNDEFINED) {
            let symbol = &line[at + UNDEFINED.len()..];
            if symbol.starts_with(TOKEN_PREFIX) {
                keys.insert(Key::from_symbol(symbol)?);
            }
        }
    }
    Ok(keys)
}

/// Each package name under the repository's `fw/` directory, with the
/// components that its manifests' places in the tree give it.
fn crate_components(repo: &Path) -> anyhow::Result<BTreeMap<String, BTreeSet<Component>>> {
    let mut crates: BTreeMap<String, BTreeSet<Component>> = BTreeMap::new();
    let walk = WalkDir::new(repo.join("fw"))
        .into_iter()
        .filter_entry(|entry| entry.file_name() != "target");
    for entry in walk {
        let entry = entry?;
        if entry.file_name() != "Cargo.toml" {
            continue;
        }
        let text = fs::read_to_string(entry.path())?;
        let doc: DocumentMut = text
            .parse()
            .with_context(|| format!("can't parse {}", entry.path().display()))?;
        let Some(name) = doc
            .get("package")
            .and_then(|package| package.get("name"))
            .and_then(|name| name.as_str())
        else {
            continue;
        };
        let relative = entry
            .path()
            .strip_prefix(repo)?
            .to_string_lossy()
            .replace('\\', "/");
        crates
            .entry(name.to_string())
            .or_default()
            .insert(Component::of_crate_path(&relative));
    }
    Ok(crates)
}

/// The component of the package named `name`.
fn component_of(
    crates: &BTreeMap<String, BTreeSet<Component>>,
    name: &str,
) -> anyhow::Result<Component> {
    let components = crates
        .get(name)
        .with_context(|| format!("there's no package named {name} under fw/"))?;
    let mut iter = components.iter();
    match (iter.next(), iter.next()) {
        (Some(&component), None) => Ok(component),
        _ => anyhow::bail!("packages named {name} lie in more than one component"),
    }
}

/// Adds rows for `keys` to the map in the directory `map_dir`, and returns
/// the added rows. Each row goes at the end of its component's file, which
/// keeps its other bytes and its line endings.
fn add_rows(
    map_dir: &Path,
    keys: &BTreeSet<Key>,
    repo: &Path,
) -> anyhow::Result<Vec<tsra_log_map::Row>> {
    let mut files = Vec::new();
    for component in Component::ALL {
        let path = map_dir.join(component.file_name());
        let text =
            fs::read_to_string(&path).with_context(|| format!("can't read {}", path.display()))?;
        files.push((component, path, text));
    }
    let texts: Vec<(Component, &str)> = files
        .iter()
        .map(|(component, _, text)| (*component, text.as_str()))
        .collect();
    let mut map = Map::parse_files(&texts)
        .with_context(|| format!("can't parse the message map in {}", map_dir.display()))?;
    let crates = crate_components(repo)?;
    let keys = keys
        .iter()
        .map(|key| Ok((key.clone(), component_of(&crates, &key.crate_name)?)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let added = map.add(&keys)?;
    for (component, path, text) in files {
        let mut rows = added
            .iter()
            .filter(|row| row.component == component)
            .peekable();
        if rows.peek().is_none() {
            continue;
        }
        let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
        let mut out = text;
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(eol);
        }
        for row in rows {
            out.push_str(&row.to_line());
            out.push_str(eol);
            log::info!(
                "added a message-map row to {}: {}",
                path.display(),
                row.to_line()
            );
        }
        fs::write(&path, out).with_context(|| format!("can't write {}", path.display()))?;
    }
    Ok(added)
}

/// Runs `cargo args` in `dir`. When the link reports messages that have no
/// row, fix mode adds their rows to the map in the directory `map_dir` and
/// builds again; locked mode fails with [`MissingRows`], which names `fix` as
/// the command that adds them.
pub fn build_with_map(
    dir: &Path,
    args: &[&str],
    envs: &[(&str, &OsStr)],
    map_dir: &Path,
    repo: &Path,
    mode: Mode,
    fix: &str,
) -> anyhow::Result<()> {
    let mut added = false;
    loop {
        let (ok, stderr) = run_cargo(dir, args, envs)?;
        if ok {
            return Ok(());
        }
        let keys = missing_rows(&stderr)?;
        anyhow::ensure!(!keys.is_empty(), "`cargo {}` failed", args.join(" "));
        match mode {
            Mode::Locked => {
                return Err(MissingRows {
                    keys,
                    fix: fix.to_string(),
                }
                .into());
            }
            Mode::Fix => {
                anyhow::ensure!(
                    !added,
                    "the link still reports messages without rows after the map was updated"
                );
                add_rows(map_dir, &keys, repo)?;
                added = true;
            }
        }
    }
}

/// What one image's link left for debug-log output.
pub struct ImageLog {
    /// The image's name, such as `default`.
    pub label: String,
    /// Each message token that the image refers to, with its value.
    pub tokens: BTreeMap<String, u32>,
    /// Each target and message that Uno code logs, as `<target>:<message>`,
    /// with the files and lines of its calls, from the calls' markers.
    pub sites: BTreeMap<String, BTreeSet<String>>,
    /// Each call outside `fw/plat/uno` that the image drops from the debug
    /// log, from its drop note.
    pub drops: BTreeSet<DroppedCall>,
    /// `cortex-m-rt`'s boundary symbols for RAM that the image defines.
    pub boundary: BTreeMap<String, u32>,
}

/// A log call that an image drops from the debug log, from its drop note.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DroppedCall {
    /// The calling package.
    pub crate_name: String,
    /// The call's file and line, as the compiler gave them.
    pub site: String,
    /// Why the call doesn't fit a record.
    pub reason: String,
}

/// The NUL-terminated strings in an image's section; none if the image
/// lacks the section.
fn section_strings(elf: &Elf, name: &str) -> anyhow::Result<Vec<String>> {
    let Some(section) = elf.section(name) else {
        return Ok(Vec::new());
    };
    Ok(elf
        .contents(section)?
        .split(|&byte| byte == 0)
        .filter(|text| !text.is_empty())
        .map(|text| String::from_utf8_lossy(text).into_owned())
        .collect())
}

/// Reads markers, `<crate>\t<target>\t<message>\t<file>:<line>`, into each
/// target and message's files and lines.
fn parse_markers(markers: &[String]) -> anyhow::Result<BTreeMap<String, BTreeSet<String>>> {
    let mut sites: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for marker in markers {
        let fields: Vec<&str> = marker.split('\t').collect();
        let [_crate_name, target, message, site] = fields[..] else {
            anyhow::bail!("marker {marker:?} isn't a crate, a target, a message, and a line");
        };
        sites
            .entry(format!("{target}:{message}"))
            .or_default()
            .insert(site.to_string());
    }
    Ok(sites)
}

/// Reads drop notes, `<crate>\t<file>:<line>\t<reason>`. A note repeats for
/// each copy of the code that holds it; the set keeps one.
fn parse_drops(notes: &[String]) -> anyhow::Result<BTreeSet<DroppedCall>> {
    notes
        .iter()
        .map(|note| {
            let fields: Vec<&str> = note.split('\t').collect();
            let [crate_name, site, reason] = fields[..] else {
                anyhow::bail!("drop note {note:?} isn't a crate, a line, and a reason");
            };
            Ok(DroppedCall {
                crate_name: crate_name.to_string(),
                site: site.to_string(),
                reason: reason.to_string(),
            })
        })
        .collect()
}

/// A call's file and line, with a file under `repo` given relative to it. The
/// compiler gives absolute paths for crates outside the firmware workspace,
/// such as the core library.
fn short_site(site: &str, repo: &Path) -> String {
    let Some((file, line)) = site.rsplit_once(':') else {
        return site.to_string();
    };
    match Path::new(file).strip_prefix(repo) {
        Ok(relative) => format!("{}:{line}", relative.to_string_lossy().replace('\\', "/")),
        Err(_) => site.to_string(),
    }
}

/// Prints a warning for each call that `image` drops from the debug log.
/// Printed, not logged, so that the output shows it without `RUST_LOG`.
pub fn report_drops(image: &ImageLog, repo: &Path) {
    for call in &image.drops {
        eprintln!(
            "warning: dropped from the debug log: {}\n  --> {} ({}, image {})",
            call.reason,
            short_site(&call.site, repo),
            call.crate_name,
            image.label
        );
    }
}

/// The longest stretch of a message's text between placeholders, as a text
/// build would keep it.
fn longest_text(message: &str) -> String {
    let mut longest = String::new();
    let mut current = String::new();
    let mut chars = message.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' | '}' if chars.peek() == Some(&c) => {
                chars.next();
                current.push(c);
            }
            '{' => {
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                }
                if current.len() > longest.len() {
                    longest = std::mem::take(&mut current);
                }
                current.clear();
            }
            c => current.push(c),
        }
    }
    if current.len() > longest.len() {
        longest = current;
    }
    longest
}

/// Text shorter than this may occur in an image by chance.
const MIN_TEXT: usize = 12;

/// The tracing facade's text hook, which an image that prints defines.
pub const TEXT_HOOK: &str = "__hsm_trace_emit";

/// The output that an image's build asks for, which decides what the image
/// may hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    /// No text output: debug-log records, or nothing. The image must not
    /// define the text hook or hold a message's text.
    Records,
    /// Text output, which a `level-*` feature turns on: the image prints its
    /// messages, so it may hold their text.
    Text,
}

/// Each token whose message's text is in one of the image's loaded sections,
/// with that text: the longest stretch between placeholders, when it's at
/// least `MIN_TEXT` bytes.
pub fn loaded_texts<'a>(
    elf: &Elf,
    tokens: impl IntoIterator<Item = &'a String>,
) -> anyhow::Result<Vec<(&'a str, String)>> {
    let loaded = elf
        .sections
        .iter()
        .filter(|s| s.is_alloc())
        .map(|s| elf.contents(s))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut found = Vec::new();
    for name in tokens {
        let text = longest_text(&Key::from_symbol(name)?.message);
        if text.len() >= MIN_TEXT
            && loaded
                .iter()
                .any(|bytes| bytes.windows(text.len()).any(|w| w == text.as_bytes()))
        {
            found.push((name.as_str(), text));
        }
    }
    Ok(found)
}

/// The problems with `cortex-m-rt`'s RAM boundary symbols, given the `.bss`
/// and `.uninit` sections' addresses and sizes.
fn boundary_problems(
    boundary: &BTreeMap<String, u32>,
    bss: Option<(u32, u32)>,
    uninit: Option<(u32, u32)>,
) -> Vec<String> {
    let get = |name: &str| boundary.get(name).copied();
    let (Some(sbss), Some(ebss), Some(suninit), Some(euninit), Some(sheap), Some(stack_end)) = (
        get("__sbss"),
        get("__ebss"),
        get("__suninit"),
        get("__euninit"),
        get("__sheap"),
        get("_stack_end"),
    ) else {
        return vec![
            "the image lacks one of __sbss, __ebss, __suninit, __euninit, __sheap, and _stack_end"
                .to_string(),
        ];
    };
    let mut problems = Vec::new();
    if sbss == 0 || !(sbss <= ebss && ebss <= suninit && suninit <= euninit) {
        problems.push(format!(
            "the boundary symbols are out of order: __sbss {sbss:#x}, __ebss {ebss:#x}, \
             __suninit {suninit:#x}, __euninit {euninit:#x}"
        ));
    }
    for (section, bounds, start, end) in [
        (".bss", bss, sbss, ebss),
        (".uninit", uninit, suninit, euninit),
    ] {
        if let Some((addr, size)) = bounds {
            if addr != start || addr.wrapping_add(size) != end {
                problems.push(format!(
                    "{section} spans {addr:#x}..{:#x}, but its boundary symbols give {start:#x}..{end:#x}",
                    addr.wrapping_add(size)
                ));
            }
        }
    }
    // cortex-m-rt puts the heap start and the stack end at the end of RAM's
    // allocations, rounded up to 4 bytes.
    let end = euninit.wrapping_add(3) & !3;
    for (name, value) in [("__sheap", sheap), ("_stack_end", stack_end)] {
        if value != end {
            problems.push(format!(
                "{name} is {value:#x}, but cortex-m-rt puts it at __euninit rounded up to 4 bytes, {end:#x}"
            ));
        }
    }
    problems
}

/// Reads an image's tokens, markers, drop notes, and boundary symbols, and
/// checks them: each token has the value of its map row, the marker and
/// drop-note sections aren't loaded, and `cortex-m-rt`'s RAM boundary symbols
/// agree with the `.bss` and `.uninit` sections. `output` is what the image's
/// build asked for, not what the image holds: when it's
/// [`Output::Records`], the image must not define the text hook, and no
/// message's text may be loaded.
pub fn read_image(label: &str, path: &Path, map: &Map, output: Output) -> anyhow::Result<ImageLog> {
    let elf = Elf::read(path)?;
    let mut problems = Vec::new();
    let mut tokens = BTreeMap::new();
    for symbol in &elf.symbols {
        if symbol.name.starts_with(TOKEN_PREFIX) {
            let key = Key::from_symbol(&symbol.name)?;
            match map.find(&key) {
                Some(row) if symbol.section == SHN_ABS && row.descriptor() == symbol.value => {}
                Some(row) => problems.push(format!(
                    "token {} has the value {:#x}, but its row gives {:#x}",
                    symbol.name,
                    symbol.value,
                    row.descriptor()
                )),
                None => problems.push(format!("token {} has no row", symbol.name)),
            }
            tokens.insert(symbol.name.clone(), symbol.value);
        }
    }
    let sites = parse_markers(&section_strings(&elf, SITE_SECTION)?)
        .with_context(|| format!("image {label}"))?;
    let drops = parse_drops(&section_strings(&elf, DROP_SECTION)?)
        .with_context(|| format!("image {label}"))?;
    for section in [SITE_SECTION, DROP_SECTION] {
        if elf.section(section).is_some_and(|s| s.is_alloc()) {
            problems.push(format!(
                "the {section} section is loaded, but it must not be"
            ));
        }
    }
    // An image that prints defines the text hook and keeps its messages' text.
    if output == Output::Records {
        if elf.symbol(TEXT_HOOK).is_some() {
            problems.push(format!(
                "the image defines the text hook {TEXT_HOOK}, but its build asked for no text \
                 output"
            ));
        }
        for (name, text) in loaded_texts(&elf, tokens.keys())? {
            problems.push(format!(
                "the text {text:?} of token {name} is in a loaded section"
            ));
        }
    }
    let boundary: BTreeMap<String, u32> = BOUNDARY_SYMBOLS
        .iter()
        .filter_map(|name| elf.symbol(name).map(|s| (name.to_string(), s.value)))
        .collect();
    let bounds = |name: &str| elf.section(name).map(|s| (s.addr, s.size));
    problems.extend(boundary_problems(
        &boundary,
        bounds(".bss"),
        bounds(".uninit"),
    ));
    anyhow::ensure!(
        problems.is_empty(),
        "image {label} ({}):\n  {}",
        path.display(),
        problems.join("\n  ")
    );
    log::info!(
        "image {label}: {} message tokens, {} Uno messages with markers, {} dropped calls",
        tokens.len(),
        sites.len(),
        drops.len()
    );
    Ok(ImageLog {
        label: label.to_string(),
        tokens,
        sites,
        drops,
        boundary,
    })
}

/// Fails if one target and message in Uno code has more than one source line
/// across `images`.
pub fn check_sites(images: &[&ImageLog]) -> anyhow::Result<()> {
    let mut sites: BTreeMap<&str, BTreeMap<&str, Vec<&str>>> = BTreeMap::new();
    for image in images {
        for (message, lines) in &image.sites {
            for site in lines {
                sites
                    .entry(message)
                    .or_default()
                    .entry(site)
                    .or_default()
                    .push(&image.label);
            }
        }
    }
    let problems: Vec<String> = sites
        .iter()
        .filter(|(_, places)| places.len() > 1)
        .map(|(message, places)| {
            let places: Vec<String> = places
                .iter()
                .map(|(site, labels)| format!("{site} ({})", labels.join(", ")))
                .collect();
            format!(
                "{message:?} comes from more than one line: {}",
                places.join("; ")
            )
        })
        .collect();
    anyhow::ensure!(
        problems.is_empty(),
        "each target and message must come from one call, but:\n  {}\nGive each call its own message.",
        problems.join("\n  ")
    );
    Ok(())
}

/// Checks that each message has one source line across `images`, and returns
/// the decoder header for `map`, which marks the messages that none of
/// `images` uses as deprecated.
pub fn decoder_header(map: &Map, images: &[ImageLog]) -> anyhow::Result<String> {
    check_sites(&images.iter().collect::<Vec<_>>())?;
    let used: BTreeSet<String> = images
        .iter()
        .flat_map(|image| image.tokens.keys().cloned())
        .collect();
    Ok(map.decoder_header(&used)?)
}

/// Writes (fix mode) or checks (locked mode) the decoder header for the
/// message map and `images`; see [`decoder_header`]. A missing header counts
/// as empty; any other error reading it fails.
pub fn finish(ctx: &XtaskCtx, images: &[ImageLog], mode: Mode) -> anyhow::Result<()> {
    let header = decoder_header(&read_map(ctx)?, images)?;
    let path = ctx.root.join(HEADER);
    let current = match fs::read_to_string(&path) {
        Ok(text) => text.replace("\r\n", "\n"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("can't read fw/plat/uno/{HEADER}")),
    };
    if current == header {
        log::info!("fw/plat/uno/{HEADER} is up to date");
        return Ok(());
    }
    match mode {
        Mode::Fix => {
            fs::write(&path, header).with_context(|| format!("can't write {}", path.display()))?;
            log::info!("updated fw/plat/uno/{HEADER}");
            Ok(())
        }
        Mode::Locked => anyhow::bail!(
            "fw/plat/uno/{HEADER} doesn't match the message map and the images. Run \
             `cargo xtask log-map` in fw/plat/uno, then commit the header. A compiler update \
             can cause this with no source change, because it can change which log calls \
             survive optimization, and so which messages the header marks as deprecated."
        ),
    }
}

/// Former paths of the map's files, relative to the repository root, each
/// with its component. A change that moves or renames a component's map
/// file adds the old path here, so that [`check_against_base`] compares the
/// file with the base's file at the old path.
pub const FORMER_MAPS: &[(Component, &str)] = &[];

/// The xtask's fixtures, relative to the repository root. Their `*.tsv`
/// files are the fixtures' own maps, which the map check skips.
const FIXTURES: &str = "fw/plat/uno/xtask/fixtures/";

/// `component`'s map file, relative to the repository root.
fn map_file(component: Component) -> String {
    format!("fw/plat/uno/{MAP_DIR}/{}", component.file_name())
}

/// Each map file's path, current or former, relative to the repository
/// root, with its component. Fails if a path belongs to two components, or
/// isn't a `*.tsv` file under `fw/plat/uno`, outside [`FIXTURES`], with no
/// empty, `.`, or `..` part: the check looks for map files only there.
fn map_paths(former_maps: &[(Component, &str)]) -> anyhow::Result<BTreeMap<String, Component>> {
    let current = Component::ALL
        .into_iter()
        .map(|component| (component, map_file(component)));
    let former = former_maps
        .iter()
        .map(|&(component, path)| (component, path.to_string()));
    let mut paths = BTreeMap::new();
    for (component, path) in current.chain(former) {
        let parts_ok = path.split('/').all(|part| !matches!(part, "" | "." | ".."));
        anyhow::ensure!(
            parts_ok
                && path.starts_with("fw/plat/uno/")
                && !path.starts_with(FIXTURES)
                && path.ends_with(".tsv"),
            "the map file path {path:?} isn't a .tsv file under fw/plat/uno, outside \
             {FIXTURES}, with no empty, `.`, or `..` part; fix FORMER_MAPS in \
             fw/plat/uno/xtask/src/log_map.rs"
        );
        if let Some(other) = paths.insert(path.clone(), component) {
            anyhow::ensure!(
                other == component,
                "the map file path {path} belongs to two components, {} and {}; fix \
                 FORMER_MAPS in fw/plat/uno/xtask/src/log_map.rs",
                other.name(),
                component.name()
            );
        }
    }
    Ok(paths)
}

/// The tracked `*.tsv` files under `fw/plat/uno`, apart from [`FIXTURES`]:
/// in the index, or with `rev`, in that revision.
fn tsv_files(sh: &Shell, rev: Option<&str>) -> anyhow::Result<BTreeSet<String>> {
    let listed = match rev {
        None => cmd!(sh, "git ls-files -z -- fw/plat/uno").quiet().read()?,
        Some(rev) => cmd!(sh, "git ls-tree -r -z --name-only {rev} -- fw/plat/uno")
            .quiet()
            .read()?,
    };
    Ok(listed
        .split('\0')
        .filter(|path| path.ends_with(".tsv") && !path.starts_with(FIXTURES))
        .map(str::to_string)
        .collect())
}

/// Checks the map on its own, and each component's file against its file in
/// the git revision `base`: `base`'s file must be an exact prefix, and each
/// row after it must give its crate the component of the crate's place in
/// the tree. A component's file in `base` is at its current path or at a
/// path that [`FORMER_MAPS`] gives the component; if `base` has neither, the
/// file counts as empty, so each of its rows is new.
///
/// Map files live only under `fw/plat/uno`, where every tracked `*.tsv`
/// file, apart from [`FIXTURES`], must be one: on the branch, a component's
/// file at its current path, and in `base`, also a former path. So the check
/// fails on any other `*.tsv` file there, on a component with two files in
/// `base`, and on a component without its file on the branch. It also fails
/// if `base` can't be read.
pub fn check_against_base(ctx: &XtaskCtx, base: &str) -> anyhow::Result<()> {
    check_against_base_with(ctx, base, FORMER_MAPS)
}

fn check_against_base_with(
    ctx: &XtaskCtx,
    base: &str,
    former_maps: &[(Component, &str)],
) -> anyhow::Result<()> {
    let repo = repo_root(ctx)?;
    let paths = map_paths(former_maps)?;
    let mut problems = Vec::new();
    let mut heads = Vec::new();
    for component in Component::ALL {
        let path = map_file(component);
        match fs::read_to_string(repo.join(&path)) {
            Ok(text) => heads.push((component, path, text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => problems.push(format!(
                "{path} is missing, but every component needs its map file"
            )),
            Err(e) => return Err(e).with_context(|| format!("can't read {path}")),
        }
    }
    let texts: Vec<(Component, &str)> = heads
        .iter()
        .map(|(component, _, text)| (*component, text.as_str()))
        .collect();
    let head = Map::parse_files(&texts).context("can't parse the message map")?;
    if let Err(errors) = head.check() {
        problems.extend(errors.iter().map(ToString::to_string));
    }

    let sh = Shell::new()?;
    sh.change_dir(&repo);
    let commit = format!("{base}^{{commit}}");
    cmd!(sh, "git rev-parse --verify --quiet {commit}")
        .quiet()
        .ignore_stdout()
        .run()
        .with_context(|| {
            format!("can't read {base}; fetch it first, for example with `git fetch origin main`")
        })?;
    let current: BTreeSet<String> = Component::ALL.into_iter().map(map_file).collect();
    for path in tsv_files(&sh, None)? {
        if !current.contains(&path) {
            problems.push(format!(
                "{path} isn't a component's map file, but under fw/plat/uno, apart from \
                 {FIXTURES}, only the map files, fw/plat/uno/{MAP_DIR}/<component>.tsv, may \
                 be .tsv files"
            ));
        }
    }
    let mut base_files: BTreeMap<Component, Vec<String>> = BTreeMap::new();
    for path in tsv_files(&sh, Some(base))? {
        match paths.get(&path) {
            Some(&component) => base_files.entry(component).or_default().push(path),
            None => problems.push(format!(
                "{base} has {path}, which is neither a component's map file nor a former path \
                 in FORMER_MAPS. If this change moves or renames a map file, add its old path \
                 to FORMER_MAPS in fw/plat/uno/xtask/src/log_map.rs, so that the check \
                 compares the file with the one at the old path."
            )),
        }
    }

    let crates = crate_components(&repo)?;
    let mut new_rows = 0;
    for (component, path, head_text) in &heads {
        let base_text = match base_map(&sh, base, *component, &base_files) {
            Ok(Some(text)) => text,
            Ok(None) => {
                // Printed, not logged, so that the CI log shows it without RUST_LOG.
                eprintln!(
                    "note: {base} has no map file for the {} component; counting it as empty, \
                     so each of its rows is new",
                    component.name()
                );
                String::new()
            }
            Err(e) => {
                problems.push(format!("{e:#}"));
                continue;
            }
        };
        if let Err(e) = tsra_log_map::check_prefix(&base_text, head_text) {
            problems.push(format!("{path}: {e}"));
        }
        let base_rows = Map::parse_files(&[(*component, &base_text)])
            .with_context(|| {
                format!(
                    "can't parse {base}'s map file for the {} component",
                    component.name()
                )
            })?
            .rows()
            .count();
        let new = head
            .rows()
            .filter(|row| row.component == *component)
            .skip(base_rows);
        for row in new {
            new_rows += 1;
            match component_of(&crates, &row.key.crate_name) {
                Ok(owner) if owner == row.component => {}
                Ok(owner) => problems.push(format!(
                    "this row gives {} the component {}, but the crate's place in the tree gives {}: {}",
                    row.key.crate_name,
                    row.component.name(),
                    owner.name(),
                    row.to_line()
                )),
                Err(e) => problems.push(format!("{e:#}: {}", row.to_line())),
            }
        }
    }
    anyhow::ensure!(
        problems.is_empty(),
        "the message map fails its checks against {base}:\n  {}",
        problems.join("\n  ")
    );
    log::info!(
        "the message map passes its checks against {base}: {} rows, {new_rows} of them new",
        head.rows().count()
    );
    Ok(())
}

/// Reads `component`'s map file in `base`, given `files`, the map files that
/// `base` has, by component. Returns `None` if `base` has none for
/// `component`, and fails if it has more than one.
fn base_map(
    sh: &Shell,
    base: &str,
    component: Component,
    files: &BTreeMap<Component, Vec<String>>,
) -> anyhow::Result<Option<String>> {
    match files.get(&component).map(Vec::as_slice).unwrap_or_default() {
        [] => Ok(None),
        [path] => {
            let spec = format!("{base}:{path}");
            Ok(Some(cmd!(sh, "git show {spec}").quiet().read()?))
        }
        paths => anyhow::bail!(
            "{base} has more than one map file for the {} component: {}",
            component.name(),
            paths.join(" and ")
        ),
    }
}

/// Add message-map rows for debug-log output, and update the decoder header.
#[derive(Parser)]
#[clap(
    about = "Build the supported and test-hook images, adding message-map rows for new debug-log messages, and update the decoder header"
)]
pub struct LogMap {
    /// Change nothing: fail on a message without a row, or on an out-of-date
    /// decoder header.
    #[clap(long)]
    pub check: bool,
}

impl Xtask for LogMap {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let mode = if self.check { Mode::Locked } else { Mode::Fix };
        let mut images = Vec::new();
        for (label, features) in MAP_IMAGES {
            log::info!("=== {label} image ===");
            let build = Build {
                features: features.map(str::to_string),
                no_default_features: false,
                locked: self.check,
            };
            images.push(build.build_firmware(&ctx, label)?);
        }
        finish(&ctx, &images, mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_rows_keep_every_space() {
        let stderr = concat!(
            "error: linking with `rust-lld` failed: exit status: 1\n",
            "  = note: rust-lld: error: undefined symbol: __tsra_log:tsra_fw_uno_fault:E+:fips:  MemManage: IACCVIOL {:#x}\r\n",
            "          >>> referenced by mod.rs:12\n",
            "          rust-lld: error: undefined symbol: \u{1b}[1m__tsra_log:c:I:t:a: b\u{1b}[0m\n",
            "          rust-lld: error: undefined symbol: memcpy\n",
        );
        let keys: Vec<String> = missing_rows(stderr)
            .expect("valid tokens")
            .iter()
            .map(Key::symbol)
            .collect();
        assert_eq!(
            keys,
            [
                "__tsra_log:c:I:t:a: b",
                "__tsra_log:tsra_fw_uno_fault:E+:fips:  MemManage: IACCVIOL {:#x}",
            ]
        );
        assert!(missing_rows("rust-lld: error: undefined symbol: __tsra_log:c:I:t:ends ").is_err());
    }

    #[test]
    fn the_longest_text_skips_placeholders() {
        assert_eq!(longest_text("op {} failed with {:#x}"), " failed with ");
        assert_eq!(longest_text("{{brace}} {}"), "{brace} ");
        assert_eq!(longest_text("{}"), "");
    }

    fn image(label: &str, sites: &[(&str, &str)]) -> ImageLog {
        let markers: Vec<String> = sites
            .iter()
            .map(|(message, site)| format!("c\tt\t{message}\t{site}"))
            .collect();
        ImageLog {
            label: label.to_string(),
            tokens: BTreeMap::new(),
            sites: parse_markers(&markers).expect("markers"),
            drops: BTreeSet::new(),
            boundary: BTreeMap::new(),
        }
    }

    #[test]
    fn markers_give_each_message_its_lines() {
        let markers = [
            "tsra_fw_uno_pal\tgdma\tslot {} fell back\tpal/src/gdma.rs:393",
            "tsra_fw_uno_pal\tgdma\tslot {} fell back\tpal/src/gdma.rs:401",
            "tsra_fw_uno_pal\tgdma\tslot {} fell back\tpal/src/gdma.rs:393",
            "tsra_fw_uno_fault\tfault\tCFSR={:#010x}\tcrates/fault/src/lib.rs:7",
        ]
        .map(String::from);
        let sites = parse_markers(&markers).expect("markers");
        let lines =
            |message: &str| -> Vec<&str> { sites[message].iter().map(String::as_str).collect() };
        assert_eq!(sites.len(), 2);
        assert_eq!(
            lines("gdma:slot {} fell back"),
            ["pal/src/gdma.rs:393", "pal/src/gdma.rs:401"]
        );
        assert_eq!(lines("fault:CFSR={:#010x}"), ["crates/fault/src/lib.rs:7"]);
        for bad in ["c\tt\tm", "c\tt\tm\tf.rs:1\tx"] {
            assert!(parse_markers(&[bad.to_string()]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn drop_notes_keep_one_of_each_call() {
        let reason = "the target, the message, or a placeholder doesn't fit";
        let note = format!("tsra_fw_hsm_core\t/repo/fw/core/lib/src/error.rs:18\t{reason}");
        let other =
            "tsra_fw_hsm_core\t/repo/fw/core/lib/src/io_uno.rs:135\ta value doesn't convert to u32";
        let notes = [note.clone(), other.to_string(), note];
        let drops = parse_drops(&notes).expect("notes");
        assert_eq!(drops.len(), 2);
        let first = drops.first().expect("a dropped call");
        assert_eq!(first.crate_name, "tsra_fw_hsm_core");
        assert_eq!(first.site, "/repo/fw/core/lib/src/error.rs:18");
        assert_eq!(first.reason, reason);
        for bad in ["c\tf.rs:1", "c\tf.rs:1\tr\tx"] {
            assert!(parse_drops(&[bad.to_string()]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_site_under_the_repository_gets_a_relative_path() {
        let repo = Path::new("/home/dev/tessera-sw");
        assert_eq!(
            short_site("/home/dev/tessera-sw/fw/core/lib/src/error.rs:18", repo),
            "fw/core/lib/src/error.rs:18"
        );
        for site in [
            "pal/src/io.rs:446",
            "/home/dev/tessera-sw-old/fw/core/lib/src/error.rs:18",
            "/tmp/outside/src/main.rs:9",
            "no line",
        ] {
            assert_eq!(short_site(site, repo), site);
        }
    }

    #[test]
    fn a_message_has_one_source_line_across_images() {
        let a = image("a", &[("m", "src/x.rs:10"), ("n", "src/x.rs:11")]);
        let b = image("b", &[("m", "src/x.rs:10")]);
        let c = image("c", &[("m", "src/y.rs:20")]);
        assert!(check_sites(&[&a, &b]).is_ok());
        let error = check_sites(&[&a, &b, &c])
            .expect_err("two lines")
            .to_string();
        assert!(error.contains("src/x.rs:10 (a, b)"), "{error}");
        assert!(error.contains("src/y.rs:20 (c)"), "{error}");
    }

    #[test]
    fn boundary_symbols_must_agree_with_their_sections() {
        // The default image's values.
        let good = [
            ("__sbss", 0x2000_0020),
            ("__ebss", 0x2001_5f7c),
            ("__suninit", 0x2001_5f7c),
            ("__euninit", 0x2001_5f7c),
            ("__sheap", 0x2001_5f7c),
            ("_stack_end", 0x2001_5f7c),
        ];
        let symbols = |pairs: &[(&str, u32)]| -> BTreeMap<String, u32> {
            pairs
                .iter()
                .map(|(name, value)| (name.to_string(), *value))
                .collect()
        };
        let bss = Some((0x2000_0020, 0x15f5c));
        let uninit = Some((0x2001_5f7c, 0));
        assert_eq!(
            boundary_problems(&symbols(&good), bss, uninit),
            Vec::<String>::new()
        );

        // The marker section placed after .bss moved the .uninit symbols to 0.
        let mut moved = good;
        moved[2].1 = 0;
        moved[3].1 = 0;
        assert!(!boundary_problems(&symbols(&moved), bss, uninit).is_empty());

        let mut heap = good;
        heap[4].1 += 4;
        let problems = boundary_problems(&symbols(&heap), bss, uninit);
        assert!(
            problems.iter().any(|p| p.starts_with("__sheap")),
            "{problems:?}"
        );

        assert!(!boundary_problems(&symbols(&good[..5]), bss, uninit).is_empty());
    }

    #[test]
    fn a_message_that_only_a_test_hook_image_logs_is_not_deprecated() {
        // Every image logs "ready"; each test-hook image also logs a message
        // that no other image logs.
        let map = Map::parse_files(&[(
            Component::Uno,
            concat!(
                "0\tuno\tI\ttsra_fw_uno_pal\tboot\tready\n",
                "1\tuno\tI\ttsra_fw_uno_pal\ttest\tcrash hook ran\n",
                "2\tuno\tI\ttsra_fw_uno_pal\ttest\tfips hook ran\n",
            ),
        )])
        .expect("a map");
        let rows: Vec<_> = map.rows().collect();
        let hook_rows = [
            (fw_util::TEST_HOOKS_FEATURE, rows[1]),
            (fw_util::FIPS_VALIDATION_HOOKS_FEATURE, rows[2]),
        ];
        let is_hook = |features: Option<&str>| hook_rows.iter().any(|(f, _)| features == Some(*f));
        let image = |label: &str, features: Option<&str>| {
            let mut tokens = BTreeMap::from([(rows[0].key.symbol(), rows[0].descriptor())]);
            for (feature, row) in hook_rows {
                if features == Some(feature) {
                    tokens.insert(row.key.symbol(), row.descriptor());
                }
            }
            ImageLog {
                label: label.to_string(),
                tokens,
                sites: BTreeMap::new(),
                drops: BTreeSet::new(),
                boundary: BTreeMap::new(),
            }
        };

        let all: Vec<ImageLog> = MAP_IMAGES
            .iter()
            .map(|(label, features)| image(label, *features))
            .collect();
        let header = decoder_header(&map, &all).expect("a header");
        assert!(!header.contains("Deprecated"), "{header}");

        // Without the test-hook images, both of their messages are marked.
        let supported: Vec<ImageLog> = MAP_IMAGES
            .iter()
            .filter(|(_, features)| !is_hook(*features))
            .map(|(label, features)| image(label, *features))
            .collect();
        let header = decoder_header(&map, &supported).expect("a header");
        assert_eq!(
            header.matches("// Deprecated message").count(),
            2,
            "{header}"
        );
        assert!(
            header.contains("    [1] = \"[test] crash hook ran\", // Deprecated message\n"),
            "{header}"
        );
    }

    /// The map's comment lines, as a map file starts.
    const MAP_HEAD: &str =
        "# Copyright (c) Microsoft Corporation.\n# Licensed under the MIT License.\n";
    const CORE_ROW: &str = "0\tcore\tE+\ttsra_fw_hsm_core\tcore\tfailed\n";
    const CORE_ROW_1: &str = "1\tcore\tW\ttsra_fw_hsm_core\tcore\tslow\n";
    const UNO_ROW: &str = "0\tuno\tI\ttsra_fw_uno_pal\tboot\tready\n";
    const UNO_ROW_1: &str = "1\tuno\tW\ttsra_fw_uno_pal\tboot\tslow\n";

    /// A git repository in a new directory under the system's temporary
    /// directory, with stub manifests for the crates that the map check
    /// looks up. Dropping it removes the directory.
    struct TempRepo {
        root: PathBuf,
    }

    impl TempRepo {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("tsra-xtask-log-map-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            let repo = Self { root };
            repo.write("fw/plat/uno/Cargo.toml", "[workspace]\n");
            repo.write(
                "fw/plat/uno/fw/pal/Cargo.toml",
                "[package]\nname = \"tsra_fw_uno_pal\"\n",
            );
            repo.write(
                "fw/core/lib/Cargo.toml",
                "[package]\nname = \"tsra_fw_hsm_core\"\n",
            );
            repo.git(&["init", "-q"]);
            repo
        }

        fn ctx(&self) -> XtaskCtx {
            XtaskCtx {
                root: self.root.join("fw/plat/uno"),
            }
        }

        /// Writes a file, relative to the repository root.
        fn write(&self, path: &str, text: &str) {
            let path = self.root.join(path);
            fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            fs::write(&path, text).expect("a file");
        }

        /// Writes core's and uno's map files.
        fn write_maps(&self, core: &str, uno: &str) {
            self.write(&map_file(Component::Core), core);
            self.write(&map_file(Component::Uno), uno);
        }

        /// Removes a file, relative to the repository root, from the index
        /// and the working tree.
        fn remove(&self, path: &str) {
            self.git(&["rm", "-q", "--", path]);
        }

        fn git(&self, args: &[&str]) -> String {
            let output = Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
                .args(["-c", "commit.gpgsign=false"])
                .args(args)
                .output()
                .expect("git runs");
            assert!(
                output.status.success(),
                "git {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).expect("UTF-8")
        }

        /// Commits the whole tree, and returns the commit's hash.
        fn commit(&self) -> String {
            self.git(&["add", "-A"]);
            self.git(&["commit", "-q", "--no-verify", "--allow-empty", "-m", "base"]);
            self.git(&["rev-parse", "HEAD"]).trim().to_string()
        }

        /// Checks the map in the working tree against `base`.
        fn check(&self, base: &str) -> Result<(), String> {
            self.check_with(base, &[])
        }

        /// Checks the map in the working tree against `base`, with
        /// `former_maps` as the map files' old paths.
        fn check_with(&self, base: &str, former_maps: &[(Component, &str)]) -> Result<(), String> {
            check_against_base_with(&self.ctx(), base, former_maps).map_err(|e| format!("{e:#}"))
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn the_base_check_fails_closed_without_the_base() {
        let repo = TempRepo::new();
        repo.write_maps(&format!("{MAP_HEAD}{CORE_ROW}"), MAP_HEAD);
        repo.commit();
        let error = repo.check("origin/main").expect_err("no origin/main");
        assert!(error.contains("can't read origin/main"), "{error}");
    }

    #[test]
    fn each_base_file_must_stay_a_prefix_of_its_file() {
        let repo = TempRepo::new();
        let core = format!("{MAP_HEAD}{CORE_ROW}");
        let uno = format!("{MAP_HEAD}{UNO_ROW}");
        repo.write_maps(&core, &uno);
        let base = repo.commit();
        assert_eq!(repo.check(&base), Ok(()));
        repo.write_maps(&format!("{core}{CORE_ROW_1}"), &format!("{uno}{UNO_ROW_1}"));
        assert_eq!(repo.check(&base), Ok(()));
        for (core_now, uno_now, expected) in [
            (
                core.replace("failed", "lost"),
                uno.clone(),
                "core.tsv: map line 3 differs from the base map",
            ),
            (
                core.clone(),
                uno.replace("ready", "set"),
                "uno.tsv: map line 3 differs from the base map",
            ),
            (
                MAP_HEAD.to_string(),
                uno.clone(),
                "core.tsv: the map lost base line 3",
            ),
            (
                core.clone(),
                format!("{MAP_HEAD}{UNO_ROW_1}{UNO_ROW}"),
                "uno.tsv: map line 3 differs from the base map",
            ),
        ] {
            repo.write_maps(&core_now, &uno_now);
            let error = repo.check(&base).expect_err(expected);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn a_missing_base_file_counts_as_empty() {
        let repo = TempRepo::new();
        let neither = repo.commit();
        let core = format!("{MAP_HEAD}{CORE_ROW}");
        repo.write(&map_file(Component::Core), &core);
        let only_core = repo.commit();
        repo.write(&map_file(Component::Uno), &format!("{MAP_HEAD}{UNO_ROW}"));
        assert_eq!(repo.check(&neither), Ok(()));
        assert_eq!(repo.check(&only_core), Ok(()));
        // Each row of a file that the base lacks is new, so the check looks
        // up its crate.
        repo.write(
            &map_file(Component::Uno),
            &format!("{MAP_HEAD}0\tuno\tI\ttsra_fw_uno_gone\tboot\told\n"),
        );
        for base in [&neither, &only_core] {
            let error = repo.check(base).expect_err("a crate that's gone");
            assert!(
                error.contains("there's no package named tsra_fw_uno_gone"),
                "{error}"
            );
        }
        // A file that the base has must still stay a prefix.
        repo.write_maps(MAP_HEAD, &format!("{MAP_HEAD}{UNO_ROW}"));
        assert_eq!(repo.check(&neither), Ok(()));
        let error = repo.check(&only_core).expect_err("core's row is gone");
        assert!(
            error.contains("core.tsv: the map lost base line 3"),
            "{error}"
        );
    }

    #[test]
    fn a_moved_file_must_name_its_old_path_and_keep_its_rows() {
        let core = format!("{MAP_HEAD}{CORE_ROW}");
        let uno = format!("{MAP_HEAD}{UNO_ROW}");
        // Moved to another directory, and renamed.
        for old in [
            "fw/plat/uno/fw/old/uno.tsv",
            "fw/plat/uno/fw/pal/log_map/messages.tsv",
        ] {
            let repo = TempRepo::new();
            repo.write(&map_file(Component::Core), &core);
            repo.write(old, &uno);
            let base = repo.commit();
            repo.remove(old);
            let listed = [(Component::Uno, old)];
            // What the branch's file keeps, and how the check fails when
            // FORMER_MAPS lists the old path.
            for (kept, uno_now, listed_error) in [
                ("every row", format!("{uno}{UNO_ROW_1}"), None),
                (
                    "no row",
                    MAP_HEAD.to_string(),
                    Some("uno.tsv: the map lost base line 3"),
                ),
                (
                    "only new rows",
                    format!("{MAP_HEAD}{}", UNO_ROW.replace("ready", "set")),
                    Some("uno.tsv: map line 3 differs from the base map"),
                ),
            ] {
                repo.write(&map_file(Component::Uno), &uno_now);
                let error = repo.check(&base).expect_err(kept);
                let unlisted = format!(
                    "{base} has {old}, which is neither a component's map file nor a former path"
                );
                assert!(error.contains(&unlisted), "{kept}: {error}");
                match listed_error {
                    None => assert_eq!(repo.check_with(&base, &listed), Ok(()), "{kept}"),
                    Some(expected) => {
                        let error = repo.check_with(&base, &listed).expect_err(kept);
                        assert!(error.contains(expected), "{kept}: {error}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_former_path_must_be_a_map_file_path_of_one_component() {
        let repo = TempRepo::new();
        repo.write_maps(
            &format!("{MAP_HEAD}{CORE_ROW}"),
            &format!("{MAP_HEAD}{UNO_ROW}"),
        );
        let base = repo.commit();
        let old = "fw/plat/uno/fw/old.tsv";
        assert_eq!(repo.check_with(&base, &[(Component::Uno, old)]), Ok(()));
        let core = map_file(Component::Core);
        let place = "isn't a .tsv file under fw/plat/uno, outside";
        for (former, expected) in [
            (
                vec![(Component::Uno, old), (Component::Core, old)],
                format!("{old} belongs to two components, uno and core"),
            ),
            (
                vec![(Component::Uno, core.as_str())],
                format!("{core} belongs to two components, core and uno"),
            ),
            (vec![(Component::Uno, "fw/plat/old.tsv")], place.to_string()),
            (
                vec![(Component::Uno, "fw/plat/uno/xtask/fixtures/old.tsv")],
                place.to_string(),
            ),
            (
                vec![(Component::Uno, "fw/plat/uno/fw/old.txt")],
                place.to_string(),
            ),
            (
                vec![(Component::Uno, "fw/plat/uno/../uno/fw/old.tsv")],
                place.to_string(),
            ),
            (
                vec![(Component::Uno, "fw/plat/uno/./fw/old.tsv")],
                place.to_string(),
            ),
            (
                vec![(Component::Uno, "fw/plat/uno//fw/old.tsv")],
                place.to_string(),
            ),
        ] {
            let error = repo.check_with(&base, &former).expect_err(&expected);
            assert!(error.contains(&expected), "{former:?}: {error}");
        }
    }

    #[test]
    fn a_base_with_two_files_for_one_component_fails() {
        let repo = TempRepo::new();
        let old = "fw/plat/uno/fw/old/uno.tsv";
        let uno = format!("{MAP_HEAD}{UNO_ROW}");
        repo.write_maps(&format!("{MAP_HEAD}{CORE_ROW}"), &uno);
        repo.write(old, &uno);
        let base = repo.commit();
        repo.remove(old);
        let error = repo
            .check_with(&base, &[(Component::Uno, old)])
            .expect_err("two files");
        let expected = format!(
            "{base} has more than one map file for the uno component: {old} and {}",
            map_file(Component::Uno)
        );
        assert!(error.contains(&expected), "{error}");
    }

    #[test]
    fn a_base_file_of_a_removed_component_fails() {
        let repo = TempRepo::new();
        repo.write_maps(
            &format!("{MAP_HEAD}{CORE_ROW}"),
            &format!("{MAP_HEAD}{UNO_ROW}"),
        );
        let gone = "fw/plat/uno/fw/pal/log_map/cpu.tsv";
        repo.write(gone, &format!("{MAP_HEAD}0\tcpu\tI\tc\tboot\tready\n"));
        let base = repo.commit();
        repo.remove(gone);
        let error = repo.check(&base).expect_err("a removed component");
        assert!(
            error.contains(&format!("{base} has {gone}, which is neither")),
            "{error}"
        );
    }

    #[test]
    fn only_the_map_files_are_tsv_files_under_fw_plat_uno() {
        let repo = TempRepo::new();
        repo.write_maps(
            &format!("{MAP_HEAD}{CORE_ROW}"),
            &format!("{MAP_HEAD}{UNO_ROW}"),
        );
        // The fixtures' maps and .tsv files outside fw/plat/uno don't count,
        // in the base or on the branch.
        let fixture = "fw/plat/uno/xtask/fixtures/log_image/log_map";
        repo.write(
            &format!("{fixture}/uno.tsv"),
            &format!("{MAP_HEAD}0\tuno\tI\ttsra_log_fixture\tfixture\tready\n"),
        );
        repo.write("plugins/tools/signatures.tsv", "a\tb\n");
        let base = repo.commit();
        repo.write(&format!("{fixture}/core.tsv"), MAP_HEAD);
        repo.write("plugins/tools/more.tsv", "c\td\n");
        repo.git(&["add", "-A"]);
        assert_eq!(repo.check(&base), Ok(()));
        // Another .tsv file under fw/plat/uno fails once it's tracked.
        let notes = "fw/plat/uno/fw/pal/notes.tsv";
        repo.write(notes, "a\tb\n");
        assert_eq!(repo.check(&base), Ok(()));
        repo.git(&["add", "--", notes]);
        let error = repo.check(&base).expect_err("an unrelated .tsv file");
        assert!(
            error.contains(&format!("{notes} isn't a component's map file")),
            "{error}"
        );
    }

    #[test]
    fn a_branch_without_a_components_file_fails() {
        let repo = TempRepo::new();
        repo.write_maps(
            &format!("{MAP_HEAD}{CORE_ROW}"),
            &format!("{MAP_HEAD}{UNO_ROW}"),
        );
        let base = repo.commit();
        let core = map_file(Component::Core);
        repo.remove(&core);
        let error = repo.check(&base).expect_err("no core.tsv");
        assert!(
            error.contains(&format!(
                "{core} is missing, but every component needs its map file"
            )),
            "{error}"
        );
    }

    #[test]
    fn a_row_moved_to_the_other_file_fails() {
        let repo = TempRepo::new();
        let core = format!("{MAP_HEAD}{CORE_ROW}");
        repo.write_maps(&core, &format!("{MAP_HEAD}{UNO_ROW}{UNO_ROW_1}"));
        let base = repo.commit();
        // uno's row 1 moves to core's file, as core's next row.
        repo.write_maps(
            &format!("{core}1\tcore\tW\ttsra_fw_uno_pal\tboot\tslow\n"),
            &format!("{MAP_HEAD}{UNO_ROW}"),
        );
        let error = repo.check(&base).expect_err("a moved row");
        assert!(
            error.contains("uno.tsv: the map lost base line 4"),
            "{error}"
        );
    }

    #[test]
    fn a_new_row_must_give_its_crate_the_crates_component() {
        let repo = TempRepo::new();
        // The base row's crate is gone from the tree; base rows aren't
        // checked again.
        let uno = format!("{MAP_HEAD}0\tuno\tI\ttsra_fw_uno_gone\tboot\told\n");
        repo.write_maps(MAP_HEAD, &uno);
        let base = repo.commit();
        let check = |core_rows: &str, uno_rows: &str| {
            repo.write_maps(
                &format!("{MAP_HEAD}{core_rows}"),
                &format!("{uno}{uno_rows}"),
            );
            repo.check(&base)
        };
        assert_eq!(check("", &UNO_ROW.replacen('0', "1", 1)), Ok(()));
        assert_eq!(check(CORE_ROW, ""), Ok(()));
        let error = check("0\tcore\tI\ttsra_fw_uno_pal\tboot\tready\n", "").expect_err("core");
        assert!(
            error.contains("the crate's place in the tree gives uno"),
            "{error}"
        );
        let error = check("", "1\tuno\tI\ttsra_fw_uno_none\tboot\tready\n").expect_err("no crate");
        assert!(
            error.contains("there's no package named tsra_fw_uno_none"),
            "{error}"
        );
    }

    #[test]
    fn adding_rows_appends_each_to_its_components_file_with_its_line_endings() {
        let repo = TempRepo::new();
        // core's file is CRLF, without a final line ending; uno's is LF.
        let core = format!("# map\r\n{}", CORE_ROW.trim_end());
        let uno = format!("# map\n{UNO_ROW}");
        repo.write("map/core.tsv", &core);
        repo.write("map/uno.tsv", &uno);
        let key = |crate_name: &str, target: &str| Key {
            crate_name: crate_name.to_string(),
            kind: tsra_log_map::Kind::Warn,
            target: target.to_string(),
            message: "slow".to_string(),
        };
        let keys = BTreeSet::from([
            key("tsra_fw_hsm_core", "core"),
            key("tsra_fw_uno_pal", "boot"),
        ]);
        let dir = repo.root.join("map");
        let added = add_rows(&dir, &keys, &repo.root).expect("two rows");
        assert_eq!(added.len(), 2);
        let read = |file: &str| fs::read_to_string(dir.join(file)).expect("a map file");
        assert_eq!(
            read("core.tsv"),
            format!("{core}\r\n{}\r\n", CORE_ROW_1.trim_end())
        );
        assert_eq!(read("uno.tsv"), format!("{uno}{UNO_ROW_1}"));
    }

    #[test]
    fn finish_writes_the_header_in_fix_mode_and_checks_it_in_locked_mode() {
        let repo = TempRepo::new();
        let ctx = repo.ctx();
        repo.write_maps(MAP_HEAD, &format!("{MAP_HEAD}{UNO_ROW}"));
        let map = read_map(&ctx).expect("a map");
        let row = map.rows().next().expect("a row");
        let images = [ImageLog {
            label: "default".to_string(),
            tokens: BTreeMap::from([(row.key.symbol(), row.descriptor())]),
            sites: BTreeMap::new(),
            drops: BTreeSet::new(),
            boundary: BTreeMap::new(),
        }];
        let stale = |error: anyhow::Error| {
            let error = format!("{error:#}");
            assert!(error.contains("doesn't match the message map"), "{error}");
        };
        // A missing header fails in locked mode, and fix mode writes it.
        stale(finish(&ctx, &images, Mode::Locked).expect_err("no header"));
        finish(&ctx, &images, Mode::Fix).expect("a new header");
        finish(&ctx, &images, Mode::Locked).expect("an up-to-date header");
        // A stale header fails in locked mode, and fix mode rewrites it.
        let path = ctx.root.join(HEADER);
        let header = fs::read_to_string(&path).expect("the header");
        fs::write(&path, header.replace("ready", "set")).expect("a stale header");
        stale(finish(&ctx, &images, Mode::Locked).expect_err("a stale header"));
        finish(&ctx, &images, Mode::Fix).expect("a rewritten header");
        assert_eq!(fs::read_to_string(&path).expect("the header"), header);
    }

    #[test]
    fn finish_fails_when_it_cant_read_the_header() {
        let repo = TempRepo::new();
        let ctx = repo.ctx();
        repo.write_maps(MAP_HEAD, &format!("{MAP_HEAD}{UNO_ROW}"));
        // A directory where the header goes can't be read as a file.
        fs::create_dir_all(ctx.root.join(HEADER)).expect("a directory");
        for mode in [Mode::Fix, Mode::Locked] {
            let error = format!("{:#}", finish(&ctx, &[], mode).expect_err("no header"));
            assert!(
                error.contains(&format!("can't read fw/plat/uno/{HEADER}")),
                "{mode:?}: {error}"
            );
        }
    }
}
