// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Common helper functions

use std::collections::BTreeSet;
use std::path::PathBuf;

use xshell::cmd;
use xshell::Shell;

/// Return files tracked by git (excluding those from .gitignore), including
/// those which have not yet been staged / committed.
pub fn git_ls_files() -> anyhow::Result<Vec<PathBuf>> {
    let sh = Shell::new()?;

    macro_rules! as_set {
        ($cmd:literal) => {{
            let output = cmd!(sh, $cmd).output()?.stdout;
            let output = String::from_utf8_lossy(&output).to_string();
            output
                .split('\n')
                .map(PathBuf::from)
                .collect::<BTreeSet<_>>()
        }};
    }

    // "extra" corresponds to files not-yet committed to git
    let all = as_set!("git ls-files");
    let extra = as_set!("git ls-files --others --exclude-standard");
    let deleted = as_set!("git ls-files --deleted");

    let mut allow_list = all;
    allow_list.extend(extra);
    allow_list = allow_list.difference(&deleted).cloned().collect();

    // Vec is returned in sorted order because of BTreeSet iteration order
    Ok(allow_list.into_iter().collect())
}

/// Return target directory xtask builds to so that it doesn't overwrite itself
pub fn target_dir() -> anyhow::Result<PathBuf> {
    let sh = Shell::new()?;
    // use CARGO_TARGET_DIR if set, otherwise use local target directory
    let mut target_dir = PathBuf::from(sh.var("CARGO_TARGET_DIR").unwrap_or("target".to_string()));
    target_dir.push("xtask");
    Ok(target_dir)
}

/// Env var holding the `;`-separated `key=value` test configuration
/// (mirrors `ddi_sock_server::TEST_ARGS_ENV`).
pub const TEST_ARGS_ENV: &str = "TSRA_TEST_ARGS";

/// Returns the value of `key` in the `TSRA_TEST_ARGS` string `args`.
fn test_arg(args: &str, key: &str) -> Option<String> {
    args.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == key).then(|| v.trim().to_owned())
    })
}

/// Returns `args` with `key` set to `value`. An existing value for `key` is
/// replaced when `overwrite` is set and kept otherwise.
pub fn with_test_arg(args: &str, key: &str, value: &str, overwrite: bool) -> String {
    let mut pairs: Vec<String> = args
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    let existing = pairs
        .iter()
        .position(|p| p.split_once('=').is_some_and(|(k, _)| k.trim() == key));
    match existing {
        Some(i) if overwrite => pairs[i] = format!("{key}={value}"),
        Some(_) => {}
        None => pairs.push(format!("{key}={value}")),
    }
    pairs.join(";")
}

/// Sets `key` in the shell's `TSRA_TEST_ARGS` (see [`with_test_arg`]).
fn set_test_arg(sh: &Shell, key: &str, value: &str, overwrite: bool) {
    let args = sh.var(TEST_ARGS_ENV).unwrap_or_default();
    sh.set_var(TEST_ARGS_ENV, with_test_arg(&args, key, value, overwrite));
}

/// Transport values accepted by `--transport`.
pub const TRANSPORTS: [&str; 2] = ["sock", "ioctl"];

/// API revision values accepted by `--api-rev`.
pub const API_REVS: [&str; 2] = ["1_0", "1_1"];

/// Add the requested transport/API revision selection to `TSRA_TEST_ARGS` for the
/// test processes and, when the effective transport is `sock` (the
/// simulator), build the standalone sock
/// server (see [`prepare_ddi_sock_server`]).
pub fn prepare_test_env(
    sh: &Shell,
    toolchain: &Option<String>,
    transport: Option<&str>,
    api_rev: Option<&str>,
) -> anyhow::Result<()> {
    if let Some(transport) = transport {
        set_test_arg(sh, "transport", transport, true);
    }
    if let Some(api_rev) = api_rev {
        set_test_arg(sh, "api_rev", api_rev, true);
    }
    // Match `tsra_ddi::DdiTransport::parse`: trimmed, case-insensitive.
    let args = sh.var(TEST_ARGS_ENV).unwrap_or_default();
    if test_arg(&args, "transport").is_some_and(|t| t.eq_ignore_ascii_case("sock")) {
        prepare_ddi_sock_server(sh, toolchain)?;
    }
    Ok(())
}

/// Build the `ddi_sock_server` binary and point `server_bin` in
/// `TSRA_TEST_ARGS` at it for tests that spawn a standalone simulated HSM.
/// Skipped when `server_bin` is already set.
fn prepare_ddi_sock_server(sh: &Shell, toolchain: &Option<String>) -> anyhow::Result<()> {
    if test_arg(&sh.var(TEST_ARGS_ENV).unwrap_or_default(), "server_bin").is_some() {
        return Ok(());
    }
    cmd!(
        sh,
        "cargo {toolchain...} build -p ddi_sock_server --bin ddi_sock_server --features test-args"
    )
    .quiet()
    .run()?;
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("xtask has no parent directory"))?;
    let target = sh
        .var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("target"));
    let bin = workspace_root
        .join(target)
        .join("debug")
        .join(format!("ddi_sock_server{}", std::env::consts::EXE_SUFFIX));
    let bin = bin
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("ddi_sock_server path is not UTF-8: {bin:?}"))?;
    anyhow::ensure!(
        !bin.contains(';'),
        "ddi_sock_server path must not contain `;`: {bin}"
    );
    set_test_arg(sh, "server_bin", bin, false);
    Ok(())
}
