// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Demo HTTP encoding: binary fields are hex, certificate chains are
//! root-first DER arrays. These JSON details never enter the sealing API.

use anyhow::Context;
use anyhow::Result;
use jzon::JsonValue;
use tsra_sealing_api::Evidence;
use tsra_sealing_api::PeerBackup;
use tsra_sealing_api::ResealedBackup;

pub fn blob(value: &JsonValue, field: &str) -> Result<Vec<u8>> {
    hex::decode(
        value[field]
            .as_str()
            .with_context(|| format!("missing {field}"))?,
    )
    .with_context(|| format!("invalid hex in {field}"))
}

pub fn chain(value: &JsonValue, field: &str) -> Result<Vec<Vec<u8>>> {
    anyhow::ensure!(value[field].is_array(), "missing {field} certificate array");
    anyhow::ensure!(value[field].len() <= 8, "too many certificates in {field}");
    value[field]
        .members()
        .map(|cert| {
            hex::decode(cert.as_str().context("certificate must be hex")?)
                .context("invalid certificate hex")
        })
        .collect()
}

pub fn encode_chain(chain: &[Vec<u8>]) -> JsonValue {
    JsonValue::Array(chain.iter().map(|cert| hex::encode(cert).into()).collect())
}

pub fn evidence(value: &JsonValue) -> Result<Evidence> {
    Ok(Evidence {
        mfgr_cert_chain: chain(value, "manufacturer")?,
        owner_cert_chain: chain(value, "owner")?,
        part_owner_cert_chain: chain(value, "partition_owner")?,
        report: blob(value, "report")?,
    })
}

pub fn encode_evidence(evidence: &Evidence) -> JsonValue {
    jzon::object! {
        manufacturer: encode_chain(&evidence.mfgr_cert_chain),
        owner: encode_chain(&evidence.owner_cert_chain),
        partition_owner: encode_chain(&evidence.part_owner_cert_chain),
        report: hex::encode(&evidence.report),
    }
}

pub fn backup(value: &JsonValue) -> Result<PeerBackup> {
    Ok(PeerBackup {
        pok_peer_backup: blob(value, "peer_backup")?,
        sd_mk_backup: blob(value, "sd_mk_backup")?,
        sender_evidence: evidence(&value["sender"])?,
    })
}

pub fn encode_backup(backup: &PeerBackup) -> JsonValue {
    jzon::object! {
        peer_backup: hex::encode(&backup.pok_peer_backup),
        sd_mk_backup: hex::encode(&backup.sd_mk_backup),
        sender: encode_evidence(&backup.sender_evidence),
    }
}

pub fn resealed_backup(value: &JsonValue) -> Result<ResealedBackup> {
    anyhow::ensure!(
        value["version"].as_u32() == Some(1),
        "invalid resealed backup version"
    );
    let backup = ResealedBackup {
        pok_remote_backup: blob(value, "pok_remote_backup")?,
        sd_mk_backup: blob(value, "sd_mk_backup")?,
        sender_cert_chain: chain(&value["sender"], "chain")?,
        sender_evidence: evidence(&value["sender"]["evidence"])?,
    };
    backup.validate()?;
    Ok(backup)
}
