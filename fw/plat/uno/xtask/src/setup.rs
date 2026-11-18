// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::NIGHTLY_TOOLCHAIN;
use crate::install;
use crate::rustup_component_add;
use crate::Xtask;
use crate::XtaskCtx;

/// Version constants for installed dependencies
const CARGO_NEXTEST_VERSION: &str = "0.9.132";
const CARGO_AUDIT_VERSION: &str = "0.22.0";

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
        let toolchain = format!("+{NIGHTLY_TOOLCHAIN}");

        // Add required cross-compilation targets.
        {
            let tgt = "thumbv7em-none-eabi";
            cmd!(sh, "rustup target add {tgt}").quiet().run()?;
            cmd!(sh, "rustup {toolchain} target add {tgt}")
                .quiet()
                .run()?;
        }

        // Run Install Cargo nextest
        let install_cargo_nextest = install::Install {
            crate_name: format!("cargo-nextest@{}", CARGO_NEXTEST_VERSION),
            force: self.force,
            config: self.config.clone(),
            no_default_features: true,
            features: Some(vec!["default-no-update".to_string()]),
        };
        install_cargo_nextest.run(ctx.clone())?;

        // Check cargo-nextest version
        cmd!(sh, "cargo nextest --version").quiet().run()?;

        // Run Install cargo-audit
        if !self.skip_audit {
            let install_cargo_audit = install::Install {
                crate_name: format!("cargo-audit@{}", CARGO_AUDIT_VERSION),
                force: self.force,
                config: self.config.clone(),
                no_default_features: false,
                features: None,
            };
            install_cargo_audit.run(ctx.clone())?;

            // Check cargo-audit version
            cmd!(sh, "cargo audit --version").quiet().run()?;
        }

        // Add Clippy (default toolchain)
        let add_clippy = rustup_component_add::RustupComponentAdd {
            component: "clippy".to_string(),
            toolchain: None,
        };
        // ignore failure in adding Clippy
        if add_clippy.run(ctx.clone()).is_ok() {
            // Check Clippy version
            let _ = cmd!(sh, "cargo clippy --version").quiet().run();
        }

        // Add Clippy (nightly)
        let add_clippy = rustup_component_add::RustupComponentAdd {
            component: "clippy".to_string(),
            toolchain: Some(NIGHTLY_TOOLCHAIN.to_string()),
        };
        // ignore failure in adding Clippy (nightly)
        if add_clippy.run(ctx.clone()).is_ok() {
            // Check Clippy (nightly) version
            let _ = cmd!(sh, "cargo {toolchain} clippy --version").quiet().run();
        }

        // Add Fmt (nightly)
        let add_fmt = rustup_component_add::RustupComponentAdd {
            component: "rustfmt".to_string(),
            toolchain: Some(NIGHTLY_TOOLCHAIN.to_string()),
        };
        // ignore failure in adding Fmt (nightly)
        if add_fmt.run(ctx.clone()).is_ok() {
            // Check Fmt (nightly) version
            let _ = cmd!(sh, "cargo {toolchain} fmt --version").quiet().run();
        }

        // Add rust-src (nightly)
        let add_rust_src = rustup_component_add::RustupComponentAdd {
            component: "rust-src".to_string(),
            toolchain: Some(NIGHTLY_TOOLCHAIN.to_string()),
        };
        // ignore failure in adding rust-src (nightly)
        if add_rust_src.run(ctx.clone()).is_ok() {
            // Check rust-src (nightly) version
            let _ = cmd!(sh, "rustup {toolchain} component list --installed")
                .quiet()
                .run();
        }

        log::trace!("done setup");
        Ok(())
    }
}
