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
    /// Refuse device access unless built with the emulator backend.
    #[arg(long, global = true)]
    pub require_emu: bool,
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

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn command_definitions_are_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn create_requires_name_and_preserves_defaults() {
        assert!(Cli::try_parse_from(["root_svc", "create"]).is_err());
        let cli = Cli::try_parse_from(["root_svc", "create", "--name", "demo"])
            .expect("create with required name");
        let Command::Create(args) = cli.command else {
            panic!("expected create");
        };
        assert_eq!(args.name, "demo");
        assert_eq!(args.state_dir, PathBuf::from("sealing-state"));
        assert!(args.device.is_none());
        assert!(!args.remote_restorable);
    }

    #[test]
    fn create_accepts_remote_recovery_options() {
        let cli = Cli::try_parse_from([
            "root_svc",
            "create",
            "--name",
            "demo",
            "--remote-restorable",
            "--state-dir",
            "recovery",
            "--device",
            "device",
        ])
        .expect("create with remote recovery options");
        let Command::Create(args) = cli.command else {
            panic!("expected create");
        };
        assert!(args.remote_restorable);
        assert_eq!(args.state_dir, PathBuf::from("recovery"));
        assert_eq!(args.device.as_deref(), Some("device"));
    }

    #[test]
    fn restore_commands_share_options_and_require_explicit_reset() {
        for operation in ["restore-local", "restore-remote"] {
            let cli =
                Cli::try_parse_from(["root_svc", operation]).expect("restore with default options");
            let (Command::RestoreLocal(args) | Command::RestoreRemote(args)) = cli.command else {
                panic!("expected restore");
            };
            assert!(!args.reset);
            assert_eq!(args.state_dir, PathBuf::from("sealing-state"));
            assert!(args.device.is_none());

            let cli = Cli::try_parse_from([
                "root_svc",
                operation,
                "--reset",
                "--state-dir",
                "recovery",
                "--device",
                "device",
            ])
            .expect("restore with explicit reset and state directory");
            let (Command::RestoreLocal(args) | Command::RestoreRemote(args)) = cli.command else {
                panic!("expected restore");
            };
            assert!(args.reset);
            assert_eq!(args.state_dir, PathBuf::from("recovery"));
            assert_eq!(args.device.as_deref(), Some("device"));
            for invalid in ["--remote-restorable", "--name"] {
                assert!(Cli::try_parse_from(["root_svc", operation, invalid]).is_err());
            }
        }
        assert!(Cli::try_parse_from(["root_svc", "create", "--name", "demo", "--reset"]).is_err());
    }

    #[test]
    fn commands_are_top_level() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        for name in ["create", "restore-local", "restore-remote", "clone"] {
            assert!(command.find_subcommand(name).is_some());
            assert!(help.contains(name));
        }
        for removed in ["svc", "app", "create-leaf"] {
            assert!(command.find_subcommand(removed).is_none());
            assert!(Cli::try_parse_from(["root_svc", removed]).is_err());
        }
        let cli = Cli::try_parse_from([
            "root_svc",
            "clone",
            "--primary",
            "http://127.0.0.1:8080",
            "--name",
            "secondary",
            "--state-dir",
            "secondary-state",
        ])
        .expect("top-level clone");
        assert!(matches!(cli.command, Command::Clone(_)));
    }

    #[test]
    fn root_does_not_offer_leaf_preregistration() {
        assert!(Cli::try_parse_from([
            "root_svc",
            "create-leaf",
            "--name",
            "orders",
            "--root",
            "http://127.0.0.1:8080",
        ])
        .is_err());
    }
}
