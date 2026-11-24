// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Recovery records carry a single signed HPKE Base envelope.

use anyhow::Result;
use jzon::JsonValue;
use tsra_sealing_api::RemoteBackup;
use tsra_sealing_api::RemoteRecovery;

use crate::wire;

pub fn encode(remote: &RemoteRecovery) -> Result<JsonValue> {
    remote.validate()?;
    Ok(jzon::object! {
        version: 3,
        masked_receiver_key: hex::encode(&remote.masked_receiver_key),
        pok_remote_backup: hex::encode(&remote.backup.pok_remote_backup),
        sd_mk_backup: hex::encode(&remote.sd_mk_backup),
        sender_pid_pub_key: hex::encode(&remote.sender_pid_pub_key),
        receiver_cert_chain: wire::encode_chain(&remote.receiver_cert_chain),
        sender: wire::encode_identity(&remote.backup.evidence),
    })
}

pub fn decode(record: &JsonValue) -> Result<RemoteRecovery> {
    anyhow::ensure!(
        record["version"].as_u32() == Some(3),
        "unsupported remote backup version; legacy HPKE Auth records cannot be restored"
    );
    let remote = RemoteRecovery {
        masked_receiver_key: wire::blob(record, "masked_receiver_key")?,
        sd_mk_backup: wire::blob(record, "sd_mk_backup")?,
        sender_pid_pub_key: wire::blob(record, "sender_pid_pub_key")?,
        receiver_cert_chain: wire::chain(record, "receiver_cert_chain")?,
        backup: RemoteBackup {
            pok_remote_backup: wire::blob(record, "pok_remote_backup")?,
            evidence: wire::identity(&record["sender"])?,
        },
    };
    remote.validate()?;
    Ok(remote)
}
