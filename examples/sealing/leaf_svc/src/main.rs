// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Independent leaf application. `create` registers its name over HTTP before
//! enrollment; local recovery uses the saved root issuer and private seed.
//!
//! ```text
//! leaf_svc create --name orders --root http://127.0.0.1:8080 --state-dir orders-state
//! leaf_svc restore-local --state-dir orders-state
//! leaf_svc restore-remote --state-dir orders-state
//! ```
//! The root must already be serving with `--listen`. No pre-registration
//! command or enrollment file is required. Authority signers and the backup
//! receiver stay at the root; the leaf has its own policy, seed and SD.
//! Leaf policy requires trusted SA, binds SAPOTA to root POTA, and disables
//! peer cloning. HTTP is a loopback-only demo without authenticated admission.
//! `restore-remote` uses the root's stored creation backup and a fresh leaf
//! receiver, with all opening/resealing inside the root HSM. It requires the
//! original leaf enrollment metadata and partition-local MK backup, but no
//! local SD backup or `leaf-backup.json`. Both restores need the root online;
//! use `--reset` to reset an initialized hardware partition explicitly.
//! `leaf-remote-prepared.json` and `leaf-resealed.json` retain intermediate
//! recovery material. A failed attempt can be retried with `restore-remote`;
//! on hardware, reset before repeating partition initialization.
//! Add `--listen 127.0.0.1:PORT` to retain the partition instance and serve
//! health and challenge signing. The provisioning session is closed; each
//! signature uses a fresh session. `--require-emu` rejects non-emu builds.
//! Creation uploads its backup automatically. Failed uploads retain local
//! recovery and `leaf-backup.json`; there is no separate upload command.
//! `join --name NAME --instance ID --root URL --state-dir DIR` enrolls a
//! concurrent instance after explicit root authorization. It restores the same
//! SD through resealing with its own PTA, seed and local MK, then imports the
//! shared SD-scoped signing key from the root catalog. Existing instances
//! keep running. `--listen` and `--events` are supported on this path as well.

use tsra_sealing_common::display;
use tsra_sealing_common::key_check;
use tsra_sealing_common::leaf_name as validate_name;
use tsra_sealing_common::pki;
use tsra_sealing_common::store;

mod commands;
mod env;
mod worker;

fn main() -> anyhow::Result<()> {
    commands::run()
}
