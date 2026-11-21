// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Aggregate pre-commit checks for the uno firmware workspace.
//!
//! By default every stage runs; pass one or more `--<stage>` flags to run a
//! subset. The `--skip-audit` flag opts out of `cargo audit` (useful for
//! offline runs).

use clap::Parser;

use crate::Xtask;
use crate::XtaskCtx;

#[derive(Parser, Debug, Clone, Default)]
struct Stage {
    /// Run setup.
    #[clap(long)]
    setup: bool,
    /// Run reggen --check.
    #[clap(long)]
    reggen: bool,
    /// Run fmt checks (firmware).
    #[clap(long)]
    fmt: bool,
    /// Run clippy checks (firmware).
    #[clap(long)]
    clippy: bool,
    /// Run copyright header check.
    #[clap(long)]
    copyright: bool,
    /// Run cargo audit (firmware).
    #[clap(long)]
    audit: bool,
    /// Run release builds (the five message-map firmware images, locked to
    /// the map, and the fastpath PQC image), check the decoder header, and
    /// run the log fixture.
    #[clap(long)]
    build: bool,
    /// Run unit tests (firmware and platform workspace, host target).
    #[clap(long)]
    test: bool,
    /// Check the debug-log message map against the base branch's map.
    #[clap(long)]
    log_map: bool,
}

impl Stage {
    fn any(&self) -> bool {
        self.setup
            || self.reggen
            || self.fmt
            || self.clippy
            || self.copyright
            || self.audit
            || self.build
            || self.test
            || self.log_map
    }

    fn all() -> Self {
        Self {
            setup: true,
            reggen: true,
            fmt: true,
            clippy: true,
            copyright: true,
            audit: true,
            build: true,
            test: true,
            log_map: true,
        }
    }
}

/// Run pre-commit checks across the uno firmware workspace.
#[derive(Parser)]
#[clap(
    about = "Run all pre-commit checks (setup, fmt, clippy, test, copyright, audit, log map, build, reggen)"
)]
pub struct Precheck {
    #[clap(flatten)]
    stage: Stage,
    /// Skip `cargo audit` (useful offline).
    #[clap(long)]
    skip_audit: bool,
    /// The git revision whose message map `--log-map` checks against.
    #[clap(long, default_value = "origin/main")]
    log_map_base: String,
}

impl Xtask for Precheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let mut errors: Vec<(&str, anyhow::Error)> = Vec::new();

        // No flags = run everything.
        let stage = if self.stage.any() {
            self.stage
        } else {
            Stage::all()
        };

        if stage.setup {
            log::info!("=== setup ===");
            if let Err(e) = (crate::setup::Setup {
                force: false,
                config: None,
                skip_audit: self.skip_audit,
            })
            .run(ctx.clone())
            {
                errors.push(("setup", e));
            }
        }

        if stage.reggen {
            log::info!("=== reggen --check (uno) ===");
            if let Err(e) = (crate::reggen::Reggen {
                soc: Some("uno".to_string()),
                cpu: None,
                name: None,
                rdl: None,
                regs_dir: None,
                regs_crate: None,
                bus_crate: None,
                devs_dir: None,
                check: true,
            })
            .run(ctx.clone())
            {
                errors.push(("reggen uno", e));
            }

            log::info!("=== reggen --check (cortex-m) ===");
            if let Err(e) = (crate::reggen::Reggen {
                soc: None,
                cpu: Some("cortex_m".to_string()),
                name: None,
                rdl: None,
                regs_dir: None,
                regs_crate: None,
                bus_crate: None,
                devs_dir: None,
                check: true,
            })
            .run(ctx.clone())
            {
                errors.push(("reggen cortex-m", e));
            }
        }

        if stage.fmt {
            log::info!("=== fmt (firmware) ===");
            if let Err(e) = (crate::fmt::Fmt { fix: false }).run(ctx.clone()) {
                errors.push(("fmt", e));
            }
        }

        if stage.clippy {
            log::info!("=== clippy (firmware) ===");
            if let Err(e) = (crate::clippy::Clippy {}).run(ctx.clone()) {
                errors.push(("clippy", e));
            }
        }

        if stage.test {
            log::info!("=== test (firmware and platform workspace, host) ===");
            if let Err(e) = (crate::test::Test {}).run(ctx.clone()) {
                errors.push(("test", e));
            }
        }

        if stage.copyright {
            log::info!("=== copyright ===");
            if let Err(e) = (crate::copyright::Copyright { fix: false }).run(ctx.clone()) {
                errors.push(("copyright", e));
            }
        }

        if stage.audit && !self.skip_audit {
            log::info!("=== audit (firmware) ===");
            if let Err(e) = (crate::audit::Audit {}).run(ctx.clone()) {
                errors.push(("audit", e));
            }
        }

        if stage.log_map {
            log::info!("=== message map against {} ===", self.log_map_base);
            if let Err(e) = crate::log_map::check_against_base(&ctx, &self.log_map_base) {
                errors.push(("log map", e));
            }
        }

        if stage.build {
            // Every image that `cargo xtask log-map` reads, the test-hook
            // images included, so the decoder header check sees the same
            // messages. The default image builds last, so it is what remains
            // in `target/` afterwards. Each build is locked: a debug-log
            // message without a map row fails it.
            let mut images = Vec::new();
            for (label, features) in crate::log_map::MAP_IMAGES {
                log::info!("=== build (firmware, {label}) ===");
                let build = crate::build::Build {
                    features: features.map(str::to_string),
                    no_default_features: false,
                    locked: true,
                };
                match build.build_firmware(&ctx, label) {
                    Ok(image) => images.push(image),
                    Err(e) => errors.push(("build", e.context(format!("the {label} image")))),
                }
            }

            log::info!("=== build (fastpath PQC firmware) ===");
            if let Err(e) = crate::build::build_fastpath_pqc(&ctx) {
                errors.push(("build (fastpath PQC)", e));
            }

            if images.len() == crate::log_map::MAP_IMAGES.len() {
                log::info!("=== message sources and decoder header ===");
                if let Err(e) = crate::log_map::finish(&ctx, &images, crate::log_map::Mode::Locked)
                {
                    errors.push(("decoder header", e));
                }
            }

            log::info!("=== log fixture ===");
            if let Err(e) = (crate::log_fixture::LogFixture {}).run(ctx.clone()) {
                errors.push(("log fixture", e));
            }
        }

        if errors.is_empty() {
            log::info!("All prechecks passed!");
            Ok(())
        } else {
            for (name, err) in &errors {
                log::error!("{name}: {err:#}");
            }
            anyhow::bail!("{} precheck(s) failed", errors.len());
        }
    }
}
