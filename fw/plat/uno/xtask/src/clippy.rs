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
use crate::fw_util::EMULATOR_FEATURE;
use crate::fw_util::NIGHTLY_TOOLCHAIN;
use crate::fw_util::TRACE_UART_FEATURE;
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
        let toolchain = format!("+{NIGHTLY_TOOLCHAIN}");

        // Firmware workspaces (nightly, thumb target).
        for (label, dir) in fw.firmware_workspaces() {
            let _dir = sh.push_dir(dir);
            log::info!("Running clippy on {label} workspace...");
            cmd!(sh, "cargo {toolchain} clippy -- -D warnings").run()?;
        }

        // Other firmware flavors compile different paths: the bulk-crypto
        // fastpath flavor (PAL), the emulator flavor (semihosting), and a trace
        // flavor (text output). Lint them too so they cannot rot unnoticed.
        {
            let _dir = sh.push_dir(&fw.fw_dir);
            for features in [BULK_CRYPTO_FEATURE, EMULATOR_FEATURE, TRACE_UART_FEATURE] {
                log::info!("Running clippy on firmware workspace ({features})...");
                cmd!(
                    sh,
                    "cargo {toolchain} clippy --features {features} -- -D warnings"
                )
                .run()?;
            }
        }

        // Log fixture workspace (nightly, thumb target).
        {
            let _dir = sh.push_dir(&fw.log_fixture_dir);
            log::info!("Running clippy on log fixture workspace...");
            cmd!(sh, "cargo {toolchain} clippy -- -D warnings").run()?;
        }

        // Log fixture's host crate for code above the PAL (nightly, host target).
        {
            let _dir = sh.push_dir(&fw.log_above_pal_dir);
            log::info!("Running clippy on log fixture's host crate...");
            cmd!(sh, "cargo {toolchain} clippy --all-targets -- -D warnings").run()?;
        }

        // Top platform workspace (xtask + log_map + reggen + systemrdl, host target).
        {
            let _dir = sh.push_dir(&ctx.root);
            log::info!("Running clippy on platform workspace...");
            cmd!(sh, "cargo clippy --workspace -- -D warnings").run()?;
        }

        Ok(())
    }
}
