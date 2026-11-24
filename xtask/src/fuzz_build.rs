// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run fuzz build

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run fuzz build
#[derive(Parser)]
#[clap(about = "Run fuzz build")]
pub struct FuzzBuild {
    /// Override toolchain to use for fuzz build
    #[clap(long)]
    pub toolchain: Option<String>,
}

impl Xtask for FuzzBuild {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running fuzz build");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = self
            .toolchain
            .or_else(|| sh.var("RUST_TOOLCHAIN").ok())
            .map(|s| format!("+{s}"));

        // Elevate warnings to errors, but do not clobber existing RUSTFLAGS (e.g., custom linker)
        let existing = sh.var("RUSTFLAGS").unwrap_or_default();
        let new_rf = if existing.trim().is_empty() {
            "-D warnings".to_string()
        } else {
            format!("{existing} -D warnings")
        };
        sh.set_var("RUSTFLAGS", new_rf);

        // Elevate cargo build warnings to errors
        sh.set_var("CARGO_BUILD_WARNINGS", "deny");

        cmd!(sh, "cargo {rust_toolchain...} fuzz build")
            .quiet()
            .run()?;

        log::trace!("done fuzz build");
        Ok(())
    }
}
