// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition and session bring-up for the sealing example.
//!
//! Every workflow begins the same way: find the backend partition, open
//! it at its maximum supported API revision, rotate the Crypto-Officer
//! (CO) pre-shared key away from the factory default, and hand back a live
//! authenticated CO session. The security-domain operations
//! (`part_init_ex`, `part_final_ex`, and the `sd_*` calls) all refuse to
//! run under the default PSK, so rotating it is mandatory bring-up rather
//! than an optional hardening step.

use anyhow::Context;
use anyhow::Result;
use tsra_api::HsmApiRev;
use tsra_api::HsmPartition;
use tsra_api::HsmPartitionManager;
use tsra_api::HsmPskId;
use tsra_api::HsmSession;
use tsra_api::HsmSessionExType;
use tsra_api::HsmSessionPsk;
use tsra_api::PSK_LEN;

/// A fixed non-default Crypto-Officer PSK, rotated in during bring-up to
/// clear the default-PSK gate the security-domain operations require.
///
/// Using a fixed value is a deliberate demo simplification; a production
/// deployment would derive or provision a unique CO PSK per partition and
/// never embed it in source.
const ROTATED_CO_PSK: [u8; PSK_LEN] = [
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
];

/// A partition opened at its maximum API revision together with a live,
/// authenticated Crypto-Officer session under the rotated PSK.
///
/// The partition must outlive the session, so both are owned here and the
/// session is dropped first (fields drop in declaration order).
pub struct SealingSession {
    /// The authenticated CO session under the rotated PSK.
    pub session: HsmSession,
    /// The partition the session was opened on.
    pub partition: HsmPartition,
    /// The negotiated API revision.
    pub rev: HsmApiRev,
}

impl SealingSession {
    /// Open a new authenticated CO session on an already-initialized
    /// partition without resetting it or rotating its PSK.
    pub fn open_co_session(partition: &HsmPartition, rev: HsmApiRev) -> Result<HsmSession> {
        partition
            .open_session_ex(
                rev,
                HsmSessionPsk::with_psk(HsmPskId::CO, &ROTATED_CO_PSK),
                HsmSessionExType::Authenticated,
            )
            .context("open rotated CO session")
    }

    /// Open the backend partition, **factory-reset it**, rotate the CO
    /// PSK, and return a live CO session.
    ///
    /// Use this at the start of `create`, where the partition is
    /// expected to begin from factory state.
    pub fn open_reset() -> Result<Self> {
        let (partition, rev) = open_partition(true)?;
        let session = open_rotated_co_session(&partition, rev)?;
        Ok(Self {
            session,
            partition,
            rev,
        })
    }

    /// Open the backend partition **without** resetting it, then rotate
    /// the CO PSK and return a live CO session.
    pub fn open_keep() -> Result<Self> {
        let (partition, rev) = open_partition(false)?;
        let session = open_rotated_co_session(&partition, rev)?;
        Ok(Self {
            session,
            partition,
            rev,
        })
    }
}

/// Locate the backend's first partition and open it at its maximum
/// supported API revision, optionally factory-resetting it first.
fn open_partition(reset: bool) -> Result<(HsmPartition, HsmApiRev)> {
    let info = HsmPartitionManager::partition_info_list()
        .into_iter()
        .next()
        .context("backend should advertise at least one partition")?;
    let rev = info
        .api_rev_range
        .context("partition should report an api-rev range")?
        .max();
    let part = HsmPartitionManager::open_partition(&info.path, rev).context("open partition")?;
    if reset {
        part.reset().context("factory-reset partition")?;
    }
    Ok((part, rev))
}

/// Open the default-PSK CO session, rotate its PSK to [`ROTATED_CO_PSK`],
/// and reopen under the rotated PSK. Returns the rotated CO session.
fn open_rotated_co_session(part: &HsmPartition, rev: HsmApiRev) -> Result<HsmSession> {
    {
        let bootstrap = part
            .open_session_ex(
                rev,
                HsmSessionPsk::new(HsmPskId::CO),
                HsmSessionExType::Authenticated,
            )
            .context("open bootstrap CO session")?;
        bootstrap
            .change_psk(&ROTATED_CO_PSK)
            .context("rotate CO PSK")?;
    }
    SealingSession::open_co_session(part, rev)
}
