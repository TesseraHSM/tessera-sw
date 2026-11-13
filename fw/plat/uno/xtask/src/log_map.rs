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
//! Running `cargo xtask log-map` in fw/plat/uno and committing the map and
//! the header fixes both.

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

/// The message map, relative to the platform workspace.
pub const MAP: &str = "fw/pal/log_map.tsv";

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
             the decoder header, and commit fw/plat/uno/{MAP} and fw/plat/uno/{HEADER} with \
             the change. A compiler update can cause this with no source change, because it \
             can change which log calls survive optimization; then `cargo xtask log-map` \
             alone adds the rows and updates the header, and committing both fixes it.",
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

/// Reads and parses the message map.
pub fn read_map(ctx: &XtaskCtx) -> anyhow::Result<Map> {
    let path = ctx.root.join(MAP);
    let text =
        fs::read_to_string(&path).with_context(|| format!("can't read {}", path.display()))?;
    Map::parse(&text).with_context(|| format!("can't parse {}", path.display()))
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

/// Adds rows for `keys` to the map file at `path`, keeping its other bytes,
/// and returns the added rows.
fn add_rows(
    path: &Path,
    keys: &BTreeSet<Key>,
    repo: &Path,
) -> anyhow::Result<Vec<tsra_log_map::Row>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("can't read {}", path.display()))?;
    let mut map = Map::parse(&text).with_context(|| format!("can't parse {}", path.display()))?;
    let crates = crate_components(repo)?;
    let keys = keys
        .iter()
        .map(|key| Ok((key.clone(), component_of(&crates, &key.crate_name)?)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let added = map.add(&keys)?;
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = text;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str(eol);
    }
    for row in &added {
        out.push_str(&row.to_line());
        out.push_str(eol);
        log::info!("added a message-map row: {}", row.to_line());
    }
    fs::write(path, out).with_context(|| format!("can't write {}", path.display()))?;
    Ok(added)
}

/// Runs `cargo args` in `dir`. When the link reports messages that have no
/// row, fix mode adds their rows to the map file at `map` and builds again;
/// locked mode fails with [`MissingRows`], which names `fix` as the command
/// that adds them.
pub fn build_with_map(
    dir: &Path,
    args: &[&str],
    envs: &[(&str, &OsStr)],
    map: &Path,
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
                add_rows(map, &keys, repo)?;
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
/// drop-note sections aren't loaded, no message's text is loaded, and
/// `cortex-m-rt`'s RAM boundary symbols agree with the `.bss` and `.uninit`
/// sections.
pub fn read_image(label: &str, path: &Path, map: &Map) -> anyhow::Result<ImageLog> {
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
    for (name, text) in loaded_texts(&elf, tokens.keys())? {
        problems.push(format!(
            "the text {text:?} of token {name} is in a loaded section"
        ));
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
/// message map and `images`; see [`decoder_header`].
pub fn finish(ctx: &XtaskCtx, images: &[ImageLog], mode: Mode) -> anyhow::Result<()> {
    let header = decoder_header(&read_map(ctx)?, images)?;
    let path = ctx.root.join(HEADER);
    let current = fs::read_to_string(&path)
        .map(|text| text.replace("\r\n", "\n"))
        .unwrap_or_default();
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
/// Checks the map on its own and against the map at the git revision `base`:
/// `base`'s map must be an exact prefix, and each row after it must give its
/// crate the component of the crate's place in the tree. Fails if `base`
/// can't be read. If `base` has no map yet, every row counts as new.
pub fn check_against_base(ctx: &XtaskCtx, base: &str) -> anyhow::Result<()> {
    let repo = repo_root(ctx)?;
    let head_text = fs::read_to_string(ctx.root.join(MAP))
        .with_context(|| format!("can't read fw/plat/uno/{MAP}"))?;
    let head = Map::parse(&head_text).context("can't parse the message map")?;
    let mut problems: Vec<String> = match head.check() {
        Ok(()) => Vec::new(),
        Err(errors) => errors.iter().map(ToString::to_string).collect(),
    };

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
    let path = format!("fw/plat/uno/{MAP}");
    let listed = cmd!(sh, "git ls-tree --name-only {base} -- {path}")
        .quiet()
        .read()?;
    let base_text = if listed.trim().is_empty() {
        log::warn!("{base} has no message map; counting it as empty, so every row is new");
        String::new()
    } else {
        let spec = format!("{base}:{path}");
        cmd!(sh, "git show {spec}").quiet().read()?
    };
    if let Err(e) = tsra_log_map::check_prefix(&base_text, &head_text) {
        problems.push(e.to_string());
    }
    let base_rows = Map::parse(&base_text)
        .with_context(|| format!("can't parse {base}'s message map"))?
        .rows()
        .count();
    let crates = crate_components(&repo)?;
    for row in head.rows().skip(base_rows) {
        match component_of(&crates, &row.key.crate_name) {
            Ok(component) if component == row.component => {}
            Ok(component) => problems.push(format!(
                "this row gives {} the component {}, but the crate's place in the tree gives {}: {}",
                row.key.crate_name,
                row.component.name(),
                component.name(),
                row.to_line()
            )),
            Err(e) => problems.push(format!("{e:#}: {}", row.to_line())),
        }
    }
    anyhow::ensure!(
        problems.is_empty(),
        "the message map fails its checks against {base}:\n  {}",
        problems.join("\n  ")
    );
    log::info!(
        "the message map passes its checks against {base}: {} rows, {} of them new",
        head.rows().count(),
        head.rows().count() - base_rows
    );
    Ok(())
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
        let map = Map::parse(concat!(
            "0\tuno\tI\ttsra_fw_uno_pal\tboot\tready\n",
            "1\tuno\tI\ttsra_fw_uno_pal\ttest\tcrash hook ran\n",
            "2\tuno\tI\ttsra_fw_uno_pal\ttest\tfips hook ran\n",
        ))
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
            header.contains("    [0x01] = \"[test] crash hook ran\", // Deprecated message\n"),
            "{header}"
        );
    }
}
