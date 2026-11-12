// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Command-line interface. Parsing never accesses or resets the device.

use std::path::PathBuf;

use clap::Args;
use clap::Parser;
use clap::Subcommand;

/// Root service for the TSRA sealing example.
#[derive(Parser, Debug)]
#[command(name = "root_svc", version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Initialize a factory-reset partition and create a security domain,
    /// sealing a remote backup of it.
    Create(CreateArgs),

    /// Restore the partition and security domain from saved local backups.
    RestoreLocal(RestoreArgs),

    /// Restore the SD from the saved same-partition remote backup.
    RestoreRemote(RestoreArgs),
    /// Clone a security domain onto a fresh, distinct partition.
    Clone(CloneArgs),
}

#[derive(Args, Debug)]
pub(crate) struct CloneArgs {
    /// Loopback primary URL, e.g. http://127.0.0.1:8080.
    #[arg(long)]
    pub primary: String,
    /// Destination name; use a different name than the primary.
    #[arg(long)]
    pub name: String,
    /// New directory for this peer's recovery state.
    #[arg(long, value_name = "DIR")]
    pub state_dir: PathBuf,
}

#[derive(Args, Debug)]
pub(crate) struct CreateArgs {
    /// Backend device/partition path. When omitted, the first partition
    /// the backend advertises is used.
    #[arg(long, value_name = "PATH")]
    pub device: Option<String>,

    /// Partition name. SHA-256 hashed to derive the 32-byte TEE machine
    /// seed sealed into the partition at initialization.
    #[arg(long, value_name = "NAME")]
    pub name: String,

    /// Directory for recovery backups, demo authority signers and ECC keys.
    /// Existing provisioning state is never overwritten by this command.
    #[arg(long, value_name = "DIR", default_value = "sealing-state")]
    pub state_dir: PathBuf,

    /// Have an external software SA reseal a backup to an HSM receiver for recovery.
    /// Still requires the partition-local masking-key backup after reboot.
    #[arg(long)]
    pub remote_restorable: bool,

    /// Serve peer cloning and named leaf enrollment (loopback IP:port only).
    #[arg(long, value_name = "ADDR", value_parser = crate::peer::http::listen_addr)]
    pub listen: Option<std::net::SocketAddr>,
}

/// Shared options for both same-partition recovery commands.
#[derive(Args, Debug)]
pub(crate) struct RestoreArgs {
    /// Backend device/partition path (reserved for multi-partition backends).
    #[arg(long, value_name = "PATH")]
    pub device: Option<String>,

    /// Directory containing saved authority signers, keys and recovery records.
    #[arg(long, value_name = "DIR", default_value = "sealing-state")]
    pub state_dir: PathBuf,

    /// Explicitly factory-reset the partition before restoring the SD.
    #[arg(long)]
    pub reset: bool,

    /// Serve peer cloning and named leaf enrollment (loopback IP:port only).
    #[arg(long, value_name = "ADDR", value_parser = crate::peer::http::listen_addr)]
    pub listen: Option<std::net::SocketAddr>,
}
