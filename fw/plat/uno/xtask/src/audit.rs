// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware dependency audit command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Run cargo audit on firmware dependencies.
#[derive(Parser)]
#[clap(about = "Run cargo audit on firmware dependencies")]
pub struct Audit {}

impl Xtask for Audit {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;

        for (label, dir) in fw.firmware_workspaces() {
            let _dir = sh.push_dir(dir);
            log::info!("Running audit on {label}...");
            cmd!(sh, "cargo audit --deny warnings").run()?;
        }
        Ok(())
    }
}
