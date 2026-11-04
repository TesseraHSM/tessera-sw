// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware host unit-test command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Firmware crates whose unit tests run on the host.
///
/// The firmware workspace builds for the thumb target, so its crates
/// default to `test = false`; a crate listed here enables its lib tests and
/// keeps them free of hardware access.
const HOST_TESTED: &[&str] = &[
    "tsra_fw_uno_drivers_pqc",
    "tsra_fw_uno_drivers_soc",
    "tsra_fw_uno_drivers_session_store",
    "tsra_fw_uno_pct",
];

#[derive(Parser)]
#[clap(about = "Run firmware unit tests on the host")]
pub struct Test {}

impl Xtask for Test {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let _dir = sh.push_dir(&fw.fw_dir);

        let host = host_triple(&sh)?;
        for krate in HOST_TESTED {
            log::info!("Running {krate} unit tests on {host}...");
            cmd!(sh, "cargo nextest run -p {krate} --target {host}").run()?;
        }
        Ok(())
    }
}

/// Host target triple of the toolchain the firmware workspace selects.
fn host_triple(sh: &Shell) -> anyhow::Result<String> {
    let version = cmd!(sh, "rustc -vV").read()?;
    version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("`rustc -vV` reported no host triple"))
}
