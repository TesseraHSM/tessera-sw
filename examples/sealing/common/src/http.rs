// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Loopback-only demo transport. No TLS, credentials, redirects or proxies.
//! HSM work stays on the calling thread; requests are handled sequentially.

use std::io::Read;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use jzon::JsonValue;
use tiny_http::Header;
use tiny_http::Response;
use tiny_http::Server;

pub const MAX_BODY: usize = 128 * 1024;

pub fn listen_addr(value: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = value.parse().context("listen address must be an IP:port")?;
    anyhow::ensure!(
        addr.ip().is_loopback(),
        "demo peer HTTP must bind a loopback address"
    );
    Ok(addr)
}

pub struct Client {
    base: String,
    agent: ureq::Agent,
}

impl Client {
    /// Idempotently register a named leaf without changing an existing identity.
    pub fn register_leaf(&self, name: &str) -> Result<()> {
        crate::leaf_name(name)?;
        let response = self.post("/v1/leaves", &jzon::object! { name: name })?;
        anyhow::ensure!(
            response["name"].as_str() == Some(name) && response["status"] == "registered",
            "invalid leaf registration response"
        );
        Ok(())
    }

    pub fn new(base: &str) -> Result<Self> {
        let address = base
            .strip_prefix("http://")
            .context("demo peer URL must use http://")?;
        let addr = listen_addr(address.trim_end_matches('/'))?;
        anyhow::ensure!(addr.port() != 0, "peer URL must specify a nonzero port");
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .max_redirects(0)
            .proxy(None)
            .build();
        Ok(Self {
            base: format!("http://{addr}"),
            agent: config.into(),
        })
    }

    pub fn get(&self, path: &str) -> Result<JsonValue> {
        let mut response = self.agent.get(format!("{}{path}", self.base)).call()?;
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY as u64)
            .read_to_string()?;
        jzon::parse(&text).context("invalid peer JSON response")
    }

    pub fn post(&self, path: &str, value: &JsonValue) -> Result<JsonValue> {
        let body = value.dump();
        anyhow::ensure!(body.len() <= MAX_BODY, "peer request too large");
        let mut response = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("Content-Type", "application/json")
            .send(body.as_bytes())?;
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_BODY as u64)
            .read_to_string()?;
        jzon::parse(&text).context("invalid peer JSON response")
    }
}

/// Bind before provisioning so an invalid/unavailable address cannot reset a
/// partition. No requests are handled until provisioning has completed.
pub fn bind(listen: Option<&str>) -> Result<Option<Server>> {
    listen
        .map(|address| {
            let address = listen_addr(address)?;
            Server::http(address).map_err(|error| anyhow::anyhow!("bind peer listener: {error}"))
        })
        .transpose()
}

pub fn serve(
    server: Server,
    mut handle: impl FnMut(&str, &str, &JsonValue) -> Result<JsonValue>,
) -> Result<()> {
    println!("Peer HTTP listening on http://{}", server.server_addr());
    eprintln!("Demo only: unauthenticated loopback HTTP; supplied manufacturer roots are not trusted hardware identities.");
    for mut request in server.incoming_requests() {
        let path = request.url().to_owned();
        let method = request.method().as_str().to_owned();
        let result = (|| {
            anyhow::ensure!(
                request.body_length().unwrap_or(0) <= MAX_BODY,
                "peer request too large"
            );
            let mut body = Vec::new();
            request
                .as_reader()
                .take((MAX_BODY + 1) as u64)
                .read_to_end(&mut body)?;
            anyhow::ensure!(body.len() <= MAX_BODY, "peer request too large");
            let value = if body.is_empty() {
                JsonValue::Null
            } else {
                jzon::parse(std::str::from_utf8(&body)?)?
            };
            handle(&method, &path, &value)
        })();
        let (status, value) = match result {
            Ok(value) => (200, value),
            Err(error) => {
                // Do not log request bodies, CSR bytes or backup material.
                eprintln!("peer request rejected: {error:#}");
                (400, jzon::object! { error: "peer request rejected" })
            }
        };
        let header = Header::from_bytes("Content-Type", "application/json")
            .map_err(|_| anyhow::anyhow!("invalid content type"))?;
        if let Err(error) = request.respond(
            Response::from_string(value.dump())
                .with_status_code(status)
                .with_header(header),
        ) {
            eprintln!("peer response delivery failed: {error}");
        }
    }
    anyhow::bail!("peer HTTP listener stopped")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_literal_loopback_addresses_are_accepted() {
        for valid in ["http://127.0.0.1:8080", "http://[::1]:8080/"] {
            assert!(Client::new(valid).is_ok());
        }
        for invalid in [
            "http://0.0.0.0:8080",
            "http://192.0.2.1:8080",
            "http://localhost:8080",
            "http://127.0.0.1:8080@evil",
            "http://127.0.0.1:8080/path",
            "https://127.0.0.1:8080",
            "http://127.0.0.1:0",
        ] {
            assert!(Client::new(invalid).is_err(), "{invalid}");
        }
        assert!(listen_addr("0.0.0.0:8080").is_err());
    }
}
