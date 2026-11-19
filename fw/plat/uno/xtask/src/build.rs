// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware build command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::fw_util::NIGHTLY_TOOLCHAIN;
use crate::log_map;
use crate::log_map::ImageLog;
use crate::log_map::Mode;
use crate::log_map::Output;
use crate::Xtask;
use crate::XtaskCtx;

/// The app features that turn on text output.
const TEXT_FEATURES: [&str; 2] = ["trace-uart", "trace-semihosting"];

/// The output that a firmware build with `features` asks for: text when one
/// of them is an app feature in [`TEXT_FEATURES`].
fn app_output(features: Option<&str>) -> Output {
    let text = features
        .into_iter()
        .flat_map(|features| features.split([',', ' ']))
        .map(|feature| feature.strip_prefix("tsra_fw_uno_app/").unwrap_or(feature))
        .any(|feature| TEXT_FEATURES.contains(&feature));
    if text {
        Output::Text
    } else {
        Output::Records
    }
}

/// Build firmware.
#[derive(Parser)]
#[clap(about = "Build firmware")]
pub struct Build {
    /// Features to include in the firmware build.
    #[clap(long)]
    pub features: Option<String>,

    /// Build without the crate's default features.
    #[clap(long)]
    pub no_default_features: bool,

    /// Fail on a debug-log message that has no row in the message map,
    /// instead of adding the row.
    #[clap(long)]
    pub locked: bool,
}

impl Xtask for Build {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let label = self
            .features
            .clone()
            .unwrap_or_else(|| "default".to_string());
        self.build_firmware(&ctx, &label)?;
        build_fastpath_pqc(&ctx)
    }
}

impl Build {
    /// Builds the SP firmware image, honouring the requested feature
    /// selection, and reads and checks what its link left for debug-log
    /// output, expecting text output only when a feature turns on a trace
    /// flavor. A message without a row in the message map gets one, unless
    /// the build is locked. Prints a warning for each log call that the image
    /// drops from the debug log, and fails if a Uno message comes from more
    /// than one line.
    pub fn build_firmware(&self, ctx: &XtaskCtx, label: &str) -> anyhow::Result<ImageLog> {
        let fw = FwPaths::new(ctx)?;
        let toolchain = format!("+{NIGHTLY_TOOLCHAIN}");
        let mut args = vec![toolchain.as_str(), "build", "--release"];
        if self.no_default_features {
            args.push("--no-default-features");
        }
        if let Some(features) = self
            .features
            .as_ref()
            .filter(|features| !features.trim().is_empty())
        {
            args.push("--features");
            args.push(features);
        }
        let mode = if self.locked { Mode::Locked } else { Mode::Fix };
        let fix = format!("cargo xtask build {}", args[3..].join(" "));

        log::info!("Building firmware...");
        log_map::build_with_map(
            &fw.fw_dir,
            &args,
            &[],
            &ctx.root.join(log_map::MAP),
            &log_map::repo_root(ctx)?,
            mode,
            fix.trim_end(),
        )?;
        log::info!("Firmware build complete.");
        let image = log_map::read_image(
            label,
            &fw.elf,
            &log_map::read_map(ctx)?,
            app_output(self.features.as_deref()),
        )?;
        log_map::report_drops(&image, &log_map::repo_root(ctx)?);
        log_map::check_sites(&[&image])?;
        Ok(image)
    }
}

/// Builds the fastpath PQC firmware workspace (single feature-less image).
pub fn build_fastpath_pqc(ctx: &XtaskCtx) -> anyhow::Result<()> {
    let sh = Shell::new()?;
    let fw = FwPaths::new(ctx)?;
    let toolchain = format!("+{NIGHTLY_TOOLCHAIN}");
    let _dir = sh.push_dir(&fw.pqc_dir);
    log::info!("Building fastpath PQC firmware...");
    cmd!(sh, "cargo {toolchain} build --release").run()?;
    log::info!("Fastpath PQC firmware build complete.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_trace_flavor_asks_for_text() {
        for features in [
            "tsra_fw_uno_app/trace-uart",
            "trace-semihosting",
            "tsra_fw_uno_pal/tsra_test_hooks,tsra_fw_uno_app/trace-uart",
            "tsra_fw_uno_app/bulk_crypto tsra_fw_uno_app/trace-semihosting",
        ] {
            assert_eq!(app_output(Some(features)), Output::Text, "{features}");
        }
        for features in [
            None,
            Some(""),
            Some("tsra_fw_uno_app/semihosting"),
            Some("tsra_fw_uno_app/bulk_crypto,tsra_fw_uno_pal/tsra_test_hooks"),
            Some("tsra_fw_uno_app/trace-uart-x"),
        ] {
            assert_eq!(app_output(features), Output::Records, "{features:?}");
        }
    }
}
