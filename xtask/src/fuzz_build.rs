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

        cmd!(sh, "cargo {rust_toolchain...} fuzz build")
            .quiet()
            .run()?;

        log::trace!("done fuzz build");
        Ok(())
    }
}
