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

/// Build the `ddi_sock_server` binary and point `DDI_SOCK_SERVER_BIN` at it
/// for tests that spawn a standalone simulated HSM. Skipped unless the `sock`
/// feature is requested or when `DDI_SOCK_SERVER_BIN` is already set.
pub fn prepare_ddi_sock_server(
    sh: &Shell,
    toolchain: &Option<String>,
    features: Option<&str>,
) -> anyhow::Result<()> {
    let wants_sock = features.is_some_and(|f| f.split([',', ' ']).any(|f| f == "sock"));
    if !wants_sock || sh.var("DDI_SOCK_SERVER_BIN").is_ok() {
        return Ok(());
    }
    cmd!(
        sh,
        "cargo {toolchain...} build -p ddi_sock_server --bin ddi_sock_server"
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
    sh.set_var("DDI_SOCK_SERVER_BIN", bin);
    Ok(())
}
