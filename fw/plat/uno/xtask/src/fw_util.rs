// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Shared helpers for firmware xtask commands.

use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use toml_edit::DocumentMut;

use crate::XtaskCtx;

/// Feature that builds the firmware for the bulk-crypto fastpath firmware
/// instead of the PQC one (`tsra_fw_uno_pal/bulk_crypto`).  Given in
/// `package/feature` form because the firmware workspace is virtual.
pub const BULK_CRYPTO_FEATURE: &str = "tsra_fw_uno_app/bulk_crypto";

/// Resolved firmware workspace paths.
#[derive(Debug)]
pub struct FwPaths {
    /// Firmware workspace directory (SP firmware).
    pub fw_dir: PathBuf,

    /// Fastpath PQC firmware workspace directory.
    pub pqc_dir: PathBuf,

    /// Default release ELF path for the firmware app binary.
    pub elf: PathBuf,
}

impl FwPaths {
    /// Resolve the firmware workspace directory and default ELF path.
    pub fn new(ctx: &XtaskCtx) -> anyhow::Result<Self> {
        let fw_dir = ctx.root.join("fw");
        let workspace_toml = fw_dir.join("Cargo.toml");
        anyhow::ensure!(
            workspace_toml.exists(),
            "no firmware workspace at {}",
            workspace_toml.display()
        );

        let pqc_dir = ctx.root.join("pqc");
        let pqc_toml = pqc_dir.join("Cargo.toml");
        anyhow::ensure!(
            pqc_toml.exists(),
            "no fastpath PQC workspace at {}",
            pqc_toml.display()
        );

        let app_toml = app_toml_path(&fw_dir);
        let bin_name = read_bin_name(&app_toml).with_context(|| {
            format!(
                "failed to discover firmware binary name from {}",
                app_toml.display()
            )
        })?;
        let elf = fw_dir
            .join("target")
            .join("thumbv7em-none-eabi")
            .join("release")
            .join(bin_name);

        Ok(Self {
            fw_dir,
            pqc_dir,
            elf,
        })
    }

    /// Firmware workspace directories that build for the thumb target with
    /// nightly: the SP firmware and the fastpath PQC firmware. Each entry is
    /// a `(label, directory)` pair for logging.
    pub fn firmware_workspaces(&self) -> [(&'static str, &std::path::Path); 2] {
        [
            ("firmware", self.fw_dir.as_path()),
            ("fastpath PQC", self.pqc_dir.as_path()),
        ]
    }
}

fn app_toml_path(fw_dir: &std::path::Path) -> PathBuf {
    let app_toml = fw_dir.join("app").join("Cargo.toml");
    if app_toml.exists() {
        app_toml
    } else {
        fw_dir.join("Cargo.toml")
    }
}

fn read_bin_name(app_toml: &std::path::Path) -> anyhow::Result<String> {
    let toml = fs::read_to_string(app_toml)?;
    let doc = toml.parse::<DocumentMut>()?;

    if let Some(bin_name) = doc["bin"]
        .as_array_of_tables()
        .and_then(|bins| bins.iter().find_map(|bin| bin["name"].as_str()))
    {
        return Ok(bin_name.to_string());
    }

    if let Some(package_name) = doc["package"]["name"].as_str() {
        return Ok(package_name.to_string());
    }

    anyhow::bail!(
        "missing [[bin]] name and package name in {}",
        app_toml.display()
    )
}
