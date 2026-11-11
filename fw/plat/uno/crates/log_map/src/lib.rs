// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The Uno firmware's message map for debug-log output.
//!
//! With debug-log output, each `error!`, `warn!`, or `info!` call that fits a
//! record refers to a link-time token named
//! `__tsra_log:<crate>:<kind>:<target>:<message>`, and the map gives each
//! token a number. A record's descriptor is the severity, then the component,
//! then the number, one byte each from the lowest up, then a zero byte.
//!
//! The map is a text file with one row per token: the number, component,
//! kind, crate, target, and message, separated by tabs. Lines that start with
//! `#` are comments. Rows are never edited or deleted, so a number keeps its
//! meaning for every decoder. Within a component, rows that decode the same
//! way (same target, message, and error-code suffix) share a number, and
//! every other row takes the next number, from 0 up to 255.
//!
//! This crate parses and checks the map, adds rows, and writes the linker
//! script and the decoder header that come from it.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

mod header;

#[cfg(test)]
mod tests;

/// The prefix of a message's link-time token.
pub const TOKEN_PREFIX: &str = "__tsra_log:";

/// The section that holds the markers of Uno code's calls, outside the loaded
/// image.
pub const SITE_SECTION: &str = ".tsra_log_sites";

/// The section that holds the notes of dropped calls, outside the loaded
/// image.
pub const DROP_SECTION: &str = ".tsra_log_drops";

/// An error in the map or in a token, with a message for the developer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// The side of the PAL that a message comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Component {
    /// Code above the PAL.
    Core,
    /// The Uno platform, below the PAL: crates under `fw/plat/uno/`.
    Uno,
}

impl Component {
    /// Every component, in the decoder header's order.
    pub const ALL: [Component; 2] = [Component::Core, Component::Uno];

    /// The descriptor's component byte. Both values are provisional until
    /// the decoder and HSP owners allocate them.
    pub const fn value(self) -> u8 {
        match self {
            Component::Core => 0xF9,
            Component::Uno => 0xFA,
        }
    }

    /// The name that the map uses.
    pub const fn name(self) -> &'static str {
        match self {
            Component::Core => "core",
            Component::Uno => "uno",
        }
    }

    /// The component that a map name stands for.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The component of a crate whose manifest is at `path`, relative to the
    /// repository root.
    pub fn of_crate_path(path: &str) -> Self {
        let path = path.replace('\\', "/");
        if path.starts_with("fw/plat/uno/") {
            Component::Uno
        } else {
            Component::Core
        }
    }
}

/// The kind of call, in a token and in the map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// An error without a code: `E`.
    Error,
    /// An error with a code, which the record carries last: `E+`.
    ErrorCode,
    /// A warning: `W`.
    Warn,
    /// Information: `I`.
    Info,
}

impl Kind {
    /// The kind's code in a token and in the map.
    pub const fn code(self) -> &'static str {
        match self {
            Kind::Error => "E",
            Kind::ErrorCode => "E+",
            Kind::Warn => "W",
            Kind::Info => "I",
        }
    }

    /// The kind that a code stands for.
    pub fn from_code(code: &str) -> Option<Self> {
        [Kind::Error, Kind::ErrorCode, Kind::Warn, Kind::Info]
            .into_iter()
            .find(|k| k.code() == code)
    }

    /// The descriptor's severity byte, as the HSP debug log numbers it.
    pub const fn severity(self) -> u8 {
        match self {
            Kind::Error | Kind::ErrorCode => 0,
            Kind::Warn => 1,
            Kind::Info => 2,
        }
    }

    /// Whether the record's last value is an error code.
    pub const fn has_code(self) -> bool {
        matches!(self, Kind::ErrorCode)
    }
}

/// The fields of a message's link-time token.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    /// The calling crate's package name.
    pub crate_name: String,
    /// The kind of call.
    pub kind: Kind,
    /// The call's target.
    pub target: String,
    /// The call's message.
    pub message: String,
}

impl Key {
    /// The token's symbol name.
    pub fn symbol(&self) -> String {
        format!(
            "{TOKEN_PREFIX}{}:{}:{}:{}",
            self.crate_name,
            self.kind.code(),
            self.target,
            self.message
        )
    }

    /// The key that a token's symbol name holds. The message is the rest of
    /// the name, colons and spaces included.
    pub fn from_symbol(symbol: &str) -> Result<Self, Error> {
        let rest = symbol
            .strip_prefix(TOKEN_PREFIX)
            .ok_or_else(|| Error::new(format!("not a log token: {symbol:?}")))?;
        let mut fields = rest.splitn(4, ':');
        let (Some(crate_name), Some(kind), Some(target), Some(message)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(Error::new(format!(
                "a log token needs four fields: {symbol:?}"
            )));
        };
        let kind = Kind::from_code(kind)
            .ok_or_else(|| Error::new(format!("unknown kind {kind:?} in {symbol:?}")))?;
        let key = Key {
            crate_name: crate_name.to_string(),
            kind,
            target: target.to_string(),
            message: message.to_string(),
        };
        key.check()?;
        Ok(key)
    }

    /// Checks each field against the rules that the Uno log crate applies
    /// for debug-log output.
    pub fn check(&self) -> Result<(), Error> {
        let crate_ok = !self.crate_name.is_empty()
            && self
                .crate_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if !crate_ok {
            return Err(Error::new(format!("bad crate name {:?}", self.crate_name)));
        }
        let target_ok = !self.target.is_empty()
            && self
                .target
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !target_ok {
            return Err(Error::new(format!(
                "bad target {:?}: it must match [a-z0-9_]+",
                self.target
            )));
        }
        let bytes = self.message.as_bytes();
        let message_ok = !bytes.is_empty()
            && bytes.last() != Some(&b' ')
            && !bytes
                .iter()
                .any(|&b| b == b'"' || b == b'\\' || b.is_ascii_control());
        if !message_ok {
            return Err(Error::new(format!(
                "bad message {:?}: it can't be empty, end with a space, or hold a double quote, a backslash, or a control character",
                self.message
            )));
        }
        let (_, values) = header::convert(&self.message)?;
        let limit = if self.kind.has_code() { 1 } else { 2 };
        if values > limit {
            return Err(Error::new(format!(
                "message {:?} has {values} placeholders, but a record of kind {} carries at most {limit} values",
                self.message,
                self.kind.code()
            )));
        }
        Ok(())
    }
}

/// Fields that decide how a decoder prints a record. Rows with the same
/// fields share a number.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Slot {
    component: Component,
    target: String,
    message: String,
    has_code: bool,
}

/// One row of the map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    /// The message number in its component.
    pub number: u8,
    /// The component.
    pub component: Component,
    /// The token's fields.
    pub key: Key,
}

impl Row {
    /// The record's descriptor: the token symbol's value.
    pub fn descriptor(&self) -> u32 {
        u32::from(self.key.kind.severity())
            | u32::from(self.component.value()) << 8
            | u32::from(self.number) << 16
    }

    fn slot(&self) -> Slot {
        Slot {
            component: self.component,
            target: self.key.target.clone(),
            message: self.key.message.clone(),
            has_code: self.key.kind.has_code(),
        }
    }

    /// The row as a line of the map, without the line ending.
    pub fn to_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            self.number,
            self.component.name(),
            self.key.kind.code(),
            self.key.crate_name,
            self.key.target,
            self.key.message
        )
    }

    fn from_line(line: &str) -> Result<Self, Error> {
        let fields: Vec<&str> = line.split('\t').collect();
        let [number, component, kind, crate_name, target, message] = fields[..] else {
            return Err(Error::new(format!(
                "a row needs six tab-separated fields, but it has {}",
                fields.len()
            )));
        };
        let number = Some(number)
            .filter(|n| n.bytes().all(|b| b.is_ascii_digit()))
            .filter(|n| *n == "0" || !n.starts_with('0'))
            .and_then(|n| n.parse::<u8>().ok())
            .ok_or_else(|| Error::new(format!("bad number {number:?}: it must be 0 to 255")))?;
        let component = Component::from_name(component)
            .ok_or_else(|| Error::new(format!("unknown component {component:?}")))?;
        let kind =
            Kind::from_code(kind).ok_or_else(|| Error::new(format!("unknown kind {kind:?}")))?;
        let key = Key {
            crate_name: crate_name.to_string(),
            kind,
            target: target.to_string(),
            message: message.to_string(),
        };
        key.check()?;
        Ok(Row {
            number,
            component,
            key,
        })
    }
}

/// A line of the map file.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Line {
    Comment(String),
    Row(Row),
}

/// The message map.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Map {
    lines: Vec<Line>,
}

impl Map {
    /// Parses a map file. Line endings may be `\n` or `\r\n`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut lines = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.strip_suffix('\r').unwrap_or(line);
            let parsed = if line.starts_with('#') {
                Line::Comment(line.to_string())
            } else {
                Line::Row(
                    Row::from_line(line)
                        .map_err(|e| Error::new(format!("map line {}: {e}", index + 1)))?,
                )
            };
            lines.push(parsed);
        }
        Ok(Self { lines })
    }

    /// The map file's text, with `\n` line endings.
    pub fn to_text(&self) -> String {
        let mut text = String::new();
        for line in &self.lines {
            match line {
                Line::Comment(comment) => text.push_str(comment),
                Line::Row(row) => text.push_str(&row.to_line()),
            }
            text.push('\n');
        }
        text
    }

    /// The rows, in map order.
    pub fn rows(&self) -> impl Iterator<Item = &Row> {
        self.lines.iter().filter_map(|line| match line {
            Line::Row(row) => Some(row),
            Line::Comment(_) => None,
        })
    }

    /// The row for a token, if the map has one.
    pub fn find(&self, key: &Key) -> Option<&Row> {
        self.rows().find(|row| &row.key == key)
    }

    /// Checks the whole map: each token has one row, each crate one
    /// component, and the numbering rule holds in each component. Returns
    /// every problem found.
    pub fn check(&self) -> Result<(), Vec<Error>> {
        let mut errors = Vec::new();
        let mut keys = BTreeSet::new();
        let mut crates: BTreeMap<&str, Component> = BTreeMap::new();
        let mut slots: BTreeMap<Slot, u8> = BTreeMap::new();
        let mut next: BTreeMap<Component, u16> = BTreeMap::new();
        for row in self.rows() {
            let line = row.to_line();
            if !keys.insert(&row.key) {
                errors.push(Error::new(format!(
                    "a second row for the same token: {line}"
                )));
            }
            let component = *crates.entry(&row.key.crate_name).or_insert(row.component);
            if component != row.component {
                errors.push(Error::new(format!(
                    "crate {} has rows in two components: {line}",
                    row.key.crate_name
                )));
            }
            match slots.get(&row.slot()) {
                Some(&number) if number != row.number => errors.push(Error::new(format!(
                    "this row decodes like number {number} in its component, so it must reuse that number: {line}"
                ))),
                Some(_) => {}
                None => {
                    let expected = next.entry(row.component).or_insert(0);
                    if u16::from(row.number) != *expected {
                        errors.push(Error::new(format!(
                            "this row must take the next number in its component, {expected}: {line}"
                        )));
                    }
                    *expected = u16::from(row.number) + 1;
                    slots.insert(row.slot(), row.number);
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Adds a row for each token that has none, and returns the added rows.
    /// Each takes its slot's number, if the component has the slot, or the
    /// component's next number. Tokens are added in order of component, then
    /// symbol, so the result doesn't depend on the order of `keys`. On an
    /// error, the map is unchanged.
    pub fn add(&mut self, keys: &[(Key, Component)]) -> Result<Vec<Row>, Error> {
        let mut missing: Vec<(Component, &Key)> = keys
            .iter()
            .filter(|(key, _)| self.find(key).is_none())
            .map(|(key, component)| (*component, key))
            .collect();
        missing.sort_by_key(|(component, key)| (*component, key.symbol()));
        missing.dedup();
        for (_, key) in &missing {
            key.check()?;
        }
        let mut slots: BTreeMap<Slot, u8> = BTreeMap::new();
        let mut next: BTreeMap<Component, u16> = BTreeMap::new();
        for row in self.rows() {
            slots.entry(row.slot()).or_insert(row.number);
            let n = next.entry(row.component).or_insert(0);
            *n = (*n).max(u16::from(row.number) + 1);
        }
        let mut added = Vec::new();
        for (component, key) in missing {
            let mut row = Row {
                number: 0,
                component,
                key: key.clone(),
            };
            let slot = row.slot();
            row.number = match slots.get(&slot) {
                Some(&number) => number,
                None => {
                    let n = next.entry(component).or_insert(0);
                    let number = u8::try_from(*n).map_err(|_| {
                        Error::new(format!(
                            "component {} has used all 256 numbers; {} can't get one",
                            component.name(),
                            key.symbol()
                        ))
                    })?;
                    *n += 1;
                    slots.insert(slot, number);
                    number
                }
            };
            added.push(row);
        }
        self.lines.extend(added.iter().cloned().map(Line::Row));
        Ok(added)
    }

    /// The linker script that gives each token its descriptor and keeps the
    /// markers and drop notes out of the loaded image. `PROVIDE` defines only
    /// the tokens that the image refers to, so the image's symbol table lists
    /// the messages it uses.
    pub fn linker_script(&self) -> String {
        let mut script = String::from("/* Generated from the message map. Do not edit. */\n");
        for row in self.rows() {
            script.push_str(&format!(
                "PROVIDE(\"{}\" = {:#010x});\n",
                row.key.symbol(),
                row.descriptor()
            ));
        }
        script.push_str(&format!(
            "SECTIONS\n{{\n  {SITE_SECTION} (INFO) : {{ KEEP(*({SITE_SECTION} {SITE_SECTION}.*)) }}\n  {DROP_SECTION} (INFO) : {{ KEEP(*({DROP_SECTION})) }}\n}}\nINSERT AFTER .got;\n"
        ));
        script
    }

    /// The decoder header. `used` holds the token symbols that the supported
    /// images with debug-log output refer to; a slot that none of them uses
    /// is marked as deprecated.
    pub fn decoder_header(&self, used: &BTreeSet<String>) -> Result<String, Error> {
        header::write(self, used)
    }
}

/// The name of the linker script that [`build_script`] writes.
pub const LINKER_SCRIPT: &str = "tsra_log.x";

/// For a build script: reads and checks the map at `map`, writes
/// [`LINKER_SCRIPT`] to `out_dir`, and passes it to the linker, which then
/// reports every missing row. The caller puts `out_dir` on the link search
/// path.
///
/// # Panics
///
/// Panics, which fails the build, if the map can't be read or breaks a rule.
pub fn build_script(map: &Path, out_dir: &Path) {
    println!("cargo:rerun-if-changed={}", map.display());
    let text = fs::read_to_string(map)
        .unwrap_or_else(|e| panic!("can't read the message map {}: {e}", map.display()));
    let parsed = Map::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", map.display()));
    if let Err(errors) = parsed.check() {
        let list: Vec<String> = errors.iter().map(ToString::to_string).collect();
        panic!("{}:\n{}", map.display(), list.join("\n"));
    }
    let script = out_dir.join(LINKER_SCRIPT);
    fs::write(&script, parsed.linker_script())
        .unwrap_or_else(|e| panic!("can't write {}: {e}", script.display()));
    println!("cargo:rustc-link-arg=-T{LINKER_SCRIPT}");
    println!("cargo:rustc-link-arg=--error-limit=0");
}

/// Checks that `head` only appends to `base`: every line of `base` is the
/// same line at the same place in `head`.
pub fn check_prefix(base: &str, head: &str) -> Result<(), Error> {
    let base: Vec<&str> = base
        .lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    let head: Vec<&str> = head
        .lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    for (index, line) in base.iter().enumerate() {
        match head.get(index) {
            Some(other) if other == line => {}
            Some(other) => {
                return Err(Error::new(format!(
                    "map line {} differs from the base map, but rows are append-only: base {line:?}, now {other:?}",
                    index + 1
                )));
            }
            None => {
                return Err(Error::new(format!(
                    "the map lost base line {}, but rows are append-only: {line:?}",
                    index + 1
                )));
            }
        }
    }
    Ok(())
}
