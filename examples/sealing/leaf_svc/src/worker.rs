// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::net::SocketAddr;

use anyhow::Context;
use anyhow::Result;
use tiny_http::Server;
use tsra_sealing_api::SealingSession;
use tsra_sealing_common::http;
use tsra_sealing_common::key_check;
use tsra_sealing_common::key_check::SavedKey;

pub fn bind(address: Option<SocketAddr>) -> Result<Option<Server>> {
    http::bind(address.map(|addr| addr.to_string()).as_deref())
}

pub fn serve(
    listener: Option<Server>,
    session: SealingSession,
    keys: &[SavedKey],
    name: &str,
) -> Result<()> {
    let Some(listener) = listener else {
        return Ok(());
    };
    let SealingSession {
        session,
        partition,
        rev,
    } = session;
    drop(session);
    let identity = key_check::domain_identity(keys)?;
    http::serve(listener, |method, path, request| match (method, path) {
        ("GET", "/v1/health") => Ok(jzon::object! {
            status: "ok", name: name, identity: identity.clone(),
            backend: if cfg!(feature = "emu") { "emu" } else { "device" },
        }),
        ("POST", "/v1/sign") => {
            let challenge = request["challenge"].as_str().context("missing challenge")?;
            anyhow::ensure!(
                !challenge.is_empty() && challenge.len() <= 512,
                "challenge must be between 1 and 512 bytes"
            );
            let session = SealingSession::open_co_session(&partition, rev)?;
            key_check::sign_domain_challenge(&session, keys, challenge)
        }
        _ => anyhow::bail!("unsupported leaf worker route"),
    })
}
