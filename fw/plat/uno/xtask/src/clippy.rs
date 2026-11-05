// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware clippy command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::fw_util::BULK_CRYPTO_FEATURE;
use crate::Xtask;
use crate::XtaskCtx;

/// Run clippy lints on firmware.
#[derive(Parser)]
#[clap(about = "Run clippy lints on firmware")]
pub struct Clippy {}

impl Xtask for Clippy {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;

        // Firmware workspaces (nightly, thumb target).
        for (label, dir) in fw.firmware_workspaces() {
            let _dir = sh.push_dir(dir);
            log::info!("Running clippy on {label} workspace...");
            cmd!(sh, "cargo +nightly clippy -- -D warnings").run()?;
        }

        // The bulk-crypto fastpath flavor compiles different PAL paths; lint it
        // too so it cannot rot unnoticed.
        {
            let _dir = sh.push_dir(&fw.fw_dir);
            log::info!("Running clippy on firmware workspace ({BULK_CRYPTO_FEATURE})...");
            cmd!(
                sh,
                "cargo +nightly clippy --features {BULK_CRYPTO_FEATURE} -- -D warnings"
            )
            .run()?;
        }

        // Top platform workspace (xtask + reggen + systemrdl, host target).
        {
            let _dir = sh.push_dir(&ctx.root);
            log::info!("Running clippy on platform workspace...");
            cmd!(sh, "cargo clippy --workspace -- -D warnings").run()?;
        }

        Ok(())
    }
}
