// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Root service CLI for the TSRA sealing example.
//!
//! `cli` defines the command line; `commands` coordinates creation and
//! same-partition recovery; `display` verifies and formats evidence.
//! Authority setup, remote resealing, persistence and key checks live in
//! their respective modules. Demo signers are stored on disk; production
//! services should use HSM-backed or external authority signers.
//!
//! Peer-cloning demo (build with `--features emu` for separate emulators):
//! ```text
//! root_svc create --name primary --state-dir primary-state --listen 127.0.0.1:8080
//! root_svc clone --name secondary --state-dir secondary-state --primary http://127.0.0.1:8080
//! root_svc restore-local --state-dir secondary-state
//! ```
//! `restore-local` and `restore-remote` also accept `--listen`.
//! Use `create --remote-restorable` to prepare remote recovery first.
//! On an initialized hardware partition, recovery requires explicit `--reset`.
//!
//! HTTP is an unauthenticated loopback-only demo, not a production trust
//! boundary. Do not forward its port or put it behind a remotely accessible
//! proxy. Emulator manufacturer roots are per-process: evidence is verified
//! against supplied roots, not a trusted manufacturer registry.
//! Primary POTA/SATA software private keys never cross HTTP. A cloned peer
//! therefore needs its saved primary issuer URL online for local recovery;
//! it cannot itself serve PTA issuance with `--listen`.
//! `clone` prints verified, readable summaries of the exchanged authority
//! certificates, PTA enrollment and receiver/sender evidence, never private
//! keys or backup blobs. Supplied-root verification is not hardware admission.
//!
//! Named leaf services (independent root and leaf application packages):
//! ```text
//! root_svc create --name root --state-dir root-state --listen 127.0.0.1:8080
//! leaf_svc create --name orders --root http://127.0.0.1:8080 --state-dir orders-state
//! leaf_svc restore-local --state-dir orders-state
//! leaf_svc restore-remote --state-dir orders-state
//! ```
//! `leaf_svc create` first registers itself over HTTP, then enrolls and creates
//! its SD. Registration is idempotent and never regenerates existing keys.
//! There is no separate pre-registration command.
//! The root must remain running while registering/enrolling leaves. Registration
//! creates independent POTA/SATA signers and an HSM sealing receiver per name,
//! not an SD on the root. The leaf creates its own SD through the common API.
//! Its full policy requires trusted SA, binds SAPOTA to root POTA, and disables
//! peer cloning. The root returns a leaf-SATA receiver chain and two-chain
//! evidence anchored to root POTA. The receiver is a local-scoped sealing key:
//! reopening it requires recovery of the root's original local masking key.
//!
//! Root records are `leaf-registration-NAME.json` (private signers, public
//! authorities and masked receiver), `leaf-binding-NAME.json` (full policy and
//! durable PTA public key), and `leaf-remote-NAME.json` (creation backup).
//! Leaf records add `leaf.json` (public authorities, full policies, root URL and
//! random private machine seed) and `leaf-backup.json` (durable upload outbox)
//! to the shared recovery/key files. Private root signers never cross HTTP.
//! All these files use the store's atomic publication and Unix 0600 rules.
//!
//! Enrollment is HTTP-only: no enrollment file or bearer token. Before initial
//! binding, any local caller can claim an unbound name. The first verified PTA
//! CSR binds the primary; subsequent issuance requires the same policy and
//! that instance's pinned PTA key. Additional instances must first be explicitly
//! authorized at `POST .../instances`, then enroll their own PTA using `join`.
//! They share the leaf policy and SD, not the original instance's seed or local MK.
//! PID changes across reset, whereas the UDS/seed/policy-derived PTA persists.
//! Keep the random leaf seed private. Supplied manufacturer roots are demo
//! consistency checks, not hardware admission. No separate device-owner
//! authority is configured; its optional evidence chain is sent empty.
//! Production deployments need authenticated registration/enrollment and
//! trusted manufacturer/owner roots; do not expose this listener remotely.
//!
//! Creation uploads its backup automatically. HTTP backup uploads are immutable
//! and idempotent; failed delivery preserves the local outbox and recovery
//! state. There is no separate upload command.
//! Interrupted enrollment has no automatic resume: preserve all state rather
//! than deleting it or creating again. Local recovery needs the root online.
//! Remote recovery uses the root's stored original backup, not the leaf's
//! local SD backups or upload copy. The leaf restores its partition-local MK
//! and mints a fresh receiver. Root verifies both original and recovering
//! leaf evidence against the bound policy and their respective pinned PTAs, then SATA-endorses
//! their PID chains for the HSM reseal operation. BKS3 never leaves the HSM.
//! The root-held receiver becomes the resealed backup's authenticated sender.
//! Its v2 report attests the root policy, which the leaf verifies against its
//! saved root policy. Firmware authenticates that key using leaf SATA and
//! root POTA via SAPOTA; it does not require root and leaf policies to match.
//! Root's original backup and receiver key remain unchanged.
//! `leaf-remote-prepared.json` preserves the recovering partition and masked
//! receiver before HTTP; `leaf-resealed.json` saves the verified response
//! before restore. Failures never fall back to local SD restore. Retry remote
//! recovery using the retained partition/seed records (with `--reset` when
//! resetting an initialized hardware partition is required).
//! Joining instances instead generate a fresh local MK and receiver. Root
//! reseals the existing SD to them while existing instances remain online.
//! The original backup source's PTA pin is retained separately. An immutable
//! catalog distributes only the service's SD-scoped masked signing key and
//! public identity; each joining instance creates its own local/short-lived keys.
//!
//! Leaf routes share the root listener: `POST /v1/leaves` registers a name;
//! `GET /v1/leaves/NAME` returns public configuration and any bound full policy;
//! `POST .../policy` returns the complete candidate policy for a backing PID;
//! `POST .../pta-cert` verifies and binds enrollment; `GET .../receiver`
//! refreshes receiver attestation; `POST .../backup` persists the creation
//! backup; `GET .../recovery` checks availability before resetting the leaf;
//! `POST .../reseal` returns the receiver-addressed backup, original SDMK
//! backup, and root sender chain/evidence; `POST .../instances` authorizes an
//! instance and `GET .../instances/ID` reports its enrollment state;
//! `POST`/`GET .../catalog` publish/fetch the masked SD-key catalog.
//! Root logs each dispatched leaf call to stderr with a request ID, validated
//! leaf/instance identifiers, operation, start/completion, HTTP result status
//! and elapsed milliseconds. Bodies, certificates, reports and key/backup
//! material are not included. Completion means the handler finished, not that
//! the caller received the response. Malformed HTTP/JSON is rejected by the
//! transport before dispatch and uses its existing rejection diagnostic.
//! Each app owns its CLI, environment
//! and orchestration. Shared
//! JSON, filesystem, PKI and display helpers live in `tsra_sealing_common`,
//! not in the transport-independent `tsra_sealing_api`.
//!
//! Build both apps before the cross-application process tests:
//! ```text
//! cargo build --features emu -p tsra_sealing_root_svc -p tsra_sealing_leaf_svc
//! cargo nextest run --features emu -p tsra_sealing_root_svc -p tsra_sealing_leaf_svc -p tsra_sealing_common
//! ```

use anyhow::Result;
use clap::Parser;
use tsra_sealing_common::display;
use tsra_sealing_common::key_check;
use tsra_sealing_common::pki;
use tsra_sealing_common::store;

mod cli;
mod commands;
mod env;
mod leaf;
mod peer;
mod remote;
#[cfg(all(test, feature = "emu"))]
mod state_tests;

/// Run the root-service command line.
pub fn run_root() -> Result<()> {
    let args = cli::Cli::parse();
    anyhow::ensure!(
        !args.require_emu || cfg!(feature = "emu"),
        "this operation requires an emulator build"
    );
    match args.command {
        cli::Command::Create(args) => commands::create(&args),
        cli::Command::RestoreLocal(args) => commands::restore_local(&args),
        cli::Command::RestoreRemote(args) => commands::restore_remote(&args),
        cli::Command::Clone(args) => peer::clone(&args),
    }
}
