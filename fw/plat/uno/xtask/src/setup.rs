// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use anyhow::Context;
use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific checks
#[derive(Parser)]
#[clap(about = "Install all dependencies needed for project")]
pub struct Setup {
    /// Force overwriting existing crates or binaries
    #[clap(long)]
    pub force: bool,

    /// Override a configuration value in install::Install subtasks
    #[clap(long)]
    pub config: Option<String>,

    /// Skip installing cargo-audit
    #[clap(long)]
    pub skip_audit: bool,
}

impl Xtask for Setup {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running setup");

        let sh = Shell::new()?;
        let workspace_root = ctx
            .root
            .ancestors()
            .nth(3)
            .context("failed to locate repository workspace root")?;
        let _dir = sh.push_dir(workspace_root);
        let force = self.force.then_some("--force");
        let skip_audit = self.skip_audit.then_some("--skip-audit");
        let mut config = Vec::new();
        if let Some(value) = self.config.as_deref() {
            config.extend(["--config", value]);
        }

        cmd!(
            sh,
            "cargo xtask setup {force...} {skip_audit...} {config...}"
        )
        .run()?;

        log::trace!("done setup");
        Ok(())
    }
}
