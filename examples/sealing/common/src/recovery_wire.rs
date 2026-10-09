// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Existing versioned remote-recovery file format, independent of either app.

use anyhow::Context;
use anyhow::Result;
use jzon::JsonValue;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::RemoteBackup;
use tsra_sealing_api::RemoteRecovery;

pub fn encode(remote: &RemoteRecovery) -> Result<JsonValue> {
    remote.validate()?;
    fn chain(certs: &[Vec<u8>]) -> Result<JsonValue> {
        let mut encoded = jzon::array![];
        for certificate in certs {
            encoded.push(hex::encode(certificate))?;
        }
        Ok(encoded)
    }
    let evidence = &remote.backup.evidence;
    let external = !remote.sender_cert_chain.is_empty();
    let mut record = jzon::object! {
        version: if external { 2 } else { 1 },
        masked_receiver_key: hex::encode(&remote.masked_receiver_key),
        pok_remote_backup: hex::encode(&remote.backup.pok_remote_backup),
        sd_mk_backup: hex::encode(&remote.sd_mk_backup),
        sender: jzon::object! {
            mfgr_cert_chain: chain(&evidence.mfgr_cert_chain)?,
            owner_cert_chain: chain(&evidence.owner_cert_chain)?,
            part_owner_cert_chain: chain(&evidence.part_owner_cert_chain)?,
            report: hex::encode(&evidence.report),
        },
    };
    if external {
        record["creation_sender"] = record["sender"].clone();
        record.remove("sender");
        record["sender_cert_chain"] = chain(&remote.sender_cert_chain)?;
        record["receiver_cert_chain"] = chain(&remote.receiver_cert_chain)?;
    }
    Ok(record)
}

pub fn decode(record: &JsonValue) -> Result<RemoteRecovery> {
    fn blob(record: &JsonValue, name: &str) -> Result<Vec<u8>> {
        hex::decode(
            record[name]
                .as_str()
                .with_context(|| format!("missing remote {name}"))?,
        )
        .with_context(|| format!("invalid hex in remote {name}"))
    }
    fn chain(record: &JsonValue, name: &str) -> Result<Vec<Vec<u8>>> {
        anyhow::ensure!(record[name].is_array(), "invalid remote {name}");
        record[name]
            .members()
            .map(|cert| {
                hex::decode(cert.as_str().context("remote certificate must be hex")?)
                    .context("invalid remote certificate hex")
            })
            .collect()
    }
    let version = record["version"]
        .as_u32()
        .context("missing remote version")?;
    anyhow::ensure!(
        version == 1 || version == 2,
        "unsupported remote backup version"
    );
    let sender = if version == 2 {
        &record["creation_sender"]
    } else {
        &record["sender"]
    };
    let remote = RemoteRecovery {
        masked_receiver_key: blob(record, "masked_receiver_key")?,
        sd_mk_backup: blob(record, "sd_mk_backup")?,
        sender_cert_chain: if version == 2 {
            chain(record, "sender_cert_chain")?
        } else {
            Vec::new()
        },
        receiver_cert_chain: if version == 2 {
            chain(record, "receiver_cert_chain")?
        } else {
            Vec::new()
        },
        backup: RemoteBackup {
            pok_remote_backup: blob(record, "pok_remote_backup")?,
            evidence: Evidence {
                mfgr_cert_chain: chain(sender, "mfgr_cert_chain")?,
                owner_cert_chain: chain(sender, "owner_cert_chain")?,
                part_owner_cert_chain: chain(sender, "part_owner_cert_chain")?,
                report: blob(sender, "report")?,
            },
        },
    };
    remote.validate()?;
    Ok(remote)
}
