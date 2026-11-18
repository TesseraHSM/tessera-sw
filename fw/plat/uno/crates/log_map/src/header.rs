// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The decoder header: one C format string per message number.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Write as _;

use super::Component;
use super::Error;
use super::Map;
use super::Row;

/// Converts a message to a C `printf` format: `{}` to `%u`, `{:x}` to `%x`,
/// `{:#x}` to `0x%x`, `{:08x}` to `%08x`, and `{:#010x}` to `0x%08x`, so each
/// value prints as Rust prints it. `%` becomes `%%`, and `{{` and `}}` become
/// braces.
pub(crate) fn format(message: &str) -> Result<String, Error> {
    convert(message).map(|(text, _)| text)
}

/// Converts a message as [`format`] does, and counts its placeholders. The
/// placeholder forms are the Uno log crate's (`placeholders` in
/// `fw/plat/uno/fw/crates/debug_log/src/lib.rs`); change both together.
pub(crate) fn convert(message: &str) -> Result<(String, usize), Error> {
    let mut out = String::new();
    let mut count = 0;
    let mut chars = message.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut spec = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(ch) => spec.push(ch),
                        None => {
                            return Err(Error::new(format!(
                                "an unclosed placeholder in {message:?}"
                            )));
                        }
                    }
                }
                out.push_str(match spec.as_str() {
                    "" => "%u",
                    ":x" => "%x",
                    ":#x" => "0x%x",
                    ":08x" => "%08x",
                    ":#010x" => "0x%08x",
                    other => {
                        return Err(Error::new(format!(
                            "the placeholder {{{other}}} in {message:?} isn't {{}}, {{:x}}, {{:#x}}, {{:08x}}, or {{:#010x}}"
                        )));
                    }
                });
                count += 1;
            }
            '}' => {
                return Err(Error::new(format!("an unpaired }} in {message:?}")));
            }
            '%' => out.push_str("%%"),
            other => out.push(other),
        }
    }
    Ok((out, count))
}

/// A row's decoder format: `[target] message`, with ` [err:%08x]` for an
/// error code, which the record carries last.
fn slot_format(row: &Row) -> Result<String, Error> {
    let mut text = format!("[{}] {}", row.key.target, format(&row.key.message)?);
    if row.key.kind.has_code() {
        text.push_str(" [err:%08x]");
    }
    Ok(text)
}

/// Escapes text for a C string literal. `??` becomes `?\?`, so that no C
/// compiler reads a trigraph.
fn c_string(text: &str) -> String {
    let mut out = String::new();
    let mut previous = '\0';
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '?' if previous == '?' => out.push_str("\\?"),
            other => out.push(other),
        }
        previous = c;
    }
    out
}

const PREAMBLE: &str = "/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 */

/*
 * The HSP debug-log messages of the tessera-sw CP1 firmware, for the
 * decoder. Generated from the message map, fw/plat/uno/fw/pal/log_map.tsv,
 * by `cargo xtask log-map` in fw/plat/uno. Do not edit.
 *
 * A record is three little-endian 32-bit words: the descriptor, then two
 * values. The descriptor holds the severity, the component, and the message
 * number, one byte each from the lowest up, then a zero byte. Each message
 * below is a printf format for the record's two values, in order. A
 * deprecated message is one that no image built by `cargo xtask log-map`
 * logs anymore, test-hook images included; its number keeps its meaning.
 */

#ifndef TSRA_LOG_MESSAGES_H
#define TSRA_LOG_MESSAGES_H

/* Provisional until the decoder and HSP owners allocate the values. */
";

/// Writes the decoder header for a map. `used` holds the token symbols that
/// any of the map tool's images refers to.
pub(crate) fn write(map: &Map, used: &BTreeSet<String>) -> Result<String, Error> {
    let mut slots: BTreeMap<(Component, u8), (String, bool)> = BTreeMap::new();
    for row in map.rows() {
        let text = c_string(&slot_format(row)?);
        let in_use = used.contains(&row.key.symbol());
        let slot = slots
            .entry((row.component, row.number))
            .or_insert_with(|| (text.clone(), false));
        if slot.0 != text {
            return Err(Error::new(format!(
                "number {} in component {} has two texts: {:?} and {text:?}",
                row.number,
                row.component.name(),
                slot.0
            )));
        }
        slot.1 |= in_use;
    }
    let mut out = String::from(PREAMBLE);
    for component in Component::ALL {
        let name = component.name();
        let _ = writeln!(
            out,
            "#define TSRA_LOG_COMPONENT_{} {:#04X}",
            name.to_ascii_uppercase(),
            component.value()
        );
    }
    for component in Component::ALL {
        let _ = writeln!(
            out,
            "\nstatic const char *const tsra_log_{}_messages[256] = {{",
            component.name()
        );
        let mut empty = true;
        for (&(_, number), (text, in_use)) in slots.range((component, 0)..=(component, u8::MAX)) {
            empty = false;
            let note = if *in_use {
                ""
            } else {
                " // Deprecated message"
            };
            let _ = writeln!(out, "    [{number}] = \"{text}\",{note}");
        }
        if empty {
            out.push_str("    0,\n");
        }
        out.push_str("};\n");
    }
    out.push_str("\n#endif /* TSRA_LOG_MESSAGES_H */\n");
    Ok(out)
}
