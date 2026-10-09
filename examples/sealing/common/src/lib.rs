// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared application support for the independent root and leaf executables.
//! Demo PKI, transport, persistence and display belong here, not in the
//! transport-independent `tsra_sealing_api`. No application depends on the
//! other application; each owns its CLI and provisioning environment.

pub mod display;
pub mod evidence;
pub mod http;
pub mod key_check;
pub mod pki;
mod recovery_wire;
pub mod runtime;
pub mod store;
pub mod wire;

/// Validate a named leaf's single-component registry identifier.
pub fn leaf_name(name: &str) -> anyhow::Result<String> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'),
        "leaf name must contain 1-64 lowercase ASCII letters, digits, hyphens or underscores"
    );
    Ok(name.to_owned())
}
