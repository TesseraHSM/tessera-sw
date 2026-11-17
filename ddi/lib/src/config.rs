// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::OnceLock;

use crate::DdiTransport;

/// Runtime connection settings, shared by hardware and simulator clients.
pub const DDI_ARGS_ENV: &str = "TSRA_DDI_ARGS";

static PROCESS_CONFIG: OnceLock<DdiConfig> = OnceLock::new();

/// Connection configuration for the SDK's DDI transport.
///
/// Socket servers may front either hardware or a simulator. Selecting one
/// never changes credentials, provisioning requirements, or retry policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DdiConfig {
    /// Transport to use.
    pub transport: DdiTransport,
    /// Socket server endpoint, used only with the socket transport.
    pub sock: Option<String>,
}

impl DdiConfig {
    /// Parses `transport=ioctl` or `transport=sock;sock=<endpoint>`.
    ///
    /// Unknown keys, duplicates, unsupported transports, and empty values
    /// are rejected. Unset settings retain their platform defaults.
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut config = Self::default();
        let mut seen = Vec::new();
        for pair in value.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (key, value) = pair
                .split_once('=')
                .map(|(key, value)| (key.trim(), value.trim()))
                .ok_or_else(|| format!("{DDI_ARGS_ENV}: expected key=value, got {pair:?}"))?;
            if value.is_empty() || seen.contains(&key) {
                return Err(format!("{DDI_ARGS_ENV}: empty or duplicate key {key:?}"));
            }
            seen.push(key);
            match key {
                "transport" => {
                    config.transport = DdiTransport::parse(value).ok_or_else(|| {
                        format!("{DDI_ARGS_ENV}: unsupported transport {value:?}")
                    })?;
                }
                "sock" => config.sock = Some(value.to_owned()),
                _ => return Err(format!("{DDI_ARGS_ENV}: unknown key {key:?}")),
            }
        }
        Ok(config)
    }

    /// Reads process-local settings, or [`DDI_ARGS_ENV`] if none were set.
    ///
    /// Invalid configuration is returned as an error, never a panic.
    pub fn from_env() -> Result<Self, String> {
        if let Some(config) = PROCESS_CONFIG.get() {
            return Ok(config.clone());
        }
        match std::env::var(DDI_ARGS_ENV) {
            Ok(value) => Self::parse(&value),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(error) => Err(format!("{DDI_ARGS_ENV}: {error}")),
        }
    }

    /// Sets this process's connection settings once, without affecting
    /// child processes. Returns the supplied settings if already configured.
    pub fn set_process(config: Self) -> Result<(), Self> {
        PROCESS_CONFIG.set(config)
    }
}

impl std::fmt::Display for DdiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transport={}", self.transport)?;
        if let Some(sock) = &self.sock {
            write!(f, ";sock={sock}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_runtime_connections_without_test_features() {
        let config = DdiConfig::parse(" transport=SOCK ; sock=tcp://127.0.0.1:1234 ")
            .expect("valid connection");
        assert_eq!(config.transport, DdiTransport::Sock);
        assert_eq!(config.sock.as_deref(), Some("tcp://127.0.0.1:1234"));
        assert_eq!(DdiConfig::parse(&config.to_string()), Ok(config));
        assert_eq!(DdiConfig::parse(""), Ok(DdiConfig::default()));
        assert_eq!(
            DdiConfig::parse("transport=ioctl")
                .expect("ioctl transport")
                .transport,
            DdiTransport::Ioctl
        );
    }

    #[test]
    fn rejects_test_controls_and_invalid_connections() {
        for value in [
            "transport",
            "transport=",
            "transport=emulator",
            "transport=sock;transport=ioctl",
            "transport=native",
            "sock=",
            "fast_backoff=1",
            "api_rev=1_1",
            "server_bin=/test/server",
            "resource_count=4",
        ] {
            assert!(DdiConfig::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn runtime_selection_ignores_test_configuration() {
        const CHILD: &str = "TSRA_DDI_CONFIG_TEST_CHILD";
        if let Ok(expected) = std::env::var(CHILD) {
            let ddi = crate::TsraDdi::default();
            match expected.as_str() {
                "ioctl" => assert_eq!(ddi.transport(), Some(DdiTransport::Ioctl)),
                "sock" => assert_eq!(ddi.transport(), Some(DdiTransport::Sock)),
                "invalid" => assert_eq!(ddi.transport(), None),
                _ => panic!("unexpected test case"),
            }
            return;
        }
        for (value, expected) in [
            (None, "ioctl"),
            (Some("transport=ioctl"), "ioctl"),
            (Some("transport=sock;sock=tcp://127.0.0.1:1234"), "sock"),
            (Some("transport=invalid"), "invalid"),
            (Some("fast_backoff=1"), "invalid"),
        ] {
            let mut child =
                std::process::Command::new(std::env::current_exe().expect("test executable"));
            child
                .args([
                    "--exact",
                    "config::tests::runtime_selection_ignores_test_configuration",
                ])
                .env(CHILD, expected)
                .env("TSRA_TEST_ARGS", "malformed-test-controls")
                .env_remove(DDI_ARGS_ENV);
            if let Some(value) = value {
                child.env(DDI_ARGS_ENV, value);
            }
            let output = child.output().expect("configuration test subprocess");
            assert!(output.status.success(), "{value:?}: {output:?}");
        }
    }
}
