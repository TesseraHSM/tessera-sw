// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared recovery-session and post-recovery display helpers for the apps.

use std::path::Path;

use anyhow::Result;
use tsra_sealing_api::SealingSession;

use crate::key_check;
use crate::key_check::SavedKey;

pub fn open_restore_session(reset: bool, source: &str) -> Result<SealingSession> {
    if reset {
        println!("Opening and resetting partition for {source} restore...");
        SealingSession::open_reset()
    } else {
        println!("Opening partition without reset for {source} restore...");
        SealingSession::open_keep()
    }
}

pub fn finish_restore(
    session: &SealingSession,
    keys: Option<&[SavedKey]>,
    state_dir: &Path,
) -> Result<()> {
    println!("  refreshed local recovery state: {}", state_dir.display());
    match keys {
        Some(keys) => {
            key_check::check_after_restore(&session.session, keys, &mut std::io::stdout().lock())?
        }
        None => println!("ECC scope checks skipped: no keys saved by the original create command."),
    }
    Ok(())
}
