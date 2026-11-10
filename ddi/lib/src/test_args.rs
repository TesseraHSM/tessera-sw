// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test configuration from the [`TEST_ARGS_ENV`] environment variable.
//!
//! The variable holds `;`-separated `key=value` pairs, for example
//! `TSRA_TEST_ARGS="transport=sock;api_rev=1_1;fast_backoff=1"`:
//!
//! | Key              | Value                                                  |
//! |------------------|--------------------------------------------------------|
//! | `transport`      | DDI transport: `sock`, `native`, `nix` or `win`         |
//! | `api_rev`        | API revision used by `tsra_api_tests`: `1_0` or `1_1`   |
//! | `fast_backoff`   | `1` for the reduced resiliency retry backoff, or `0`    |
//! | `sock`           | Socket server endpoint for the sock transport           |
//! | `resource_count` | Partition resources of the sock server, `1..=65`        |
//! | `server_bin`     | Path to a standalone `ddi_sock_server` binary           |
//!
//! The variable is only read when the `test-args` feature is enabled (test
//! builds); otherwise [`TestArgs::from_env`] returns the defaults, which
//! select the native transport. [`TestArgs::set_process`] overrides it for
//! the current process only.

use std::fmt;
use std::sync::OnceLock;

/// Environment variable holding the test configuration.
pub const TEST_ARGS_ENV: &str = "TSRA_TEST_ARGS";

/// Process-local configuration set by [`TestArgs::set_process`].
static PROCESS_ARGS: OnceLock<TestArgs> = OnceLock::new();

/// Parsed [`TEST_ARGS_ENV`] configuration. `None`/`false` means unset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TestArgs {
    /// DDI transport name (see [`crate::DdiTransport::parse`]).
    pub transport: Option<String>,
    /// API revision used by `tsra_api_tests`: `1_0` or `1_1`.
    pub api_rev: Option<String>,
    /// Whether to use the reduced resiliency retry backoff.
    pub fast_backoff: bool,
    /// Socket server endpoint for the sock transport.
    pub sock: Option<String>,
    /// Number of partition resources allocated by the sock server.
    pub resource_count: Option<u32>,
    /// Path to a standalone `ddi_sock_server` binary.
    pub server_bin: Option<String>,
}

impl TestArgs {
    /// Parses `;`-separated `key=value` pairs. Whitespace around pairs, keys
    /// and values is ignored, as are empty pairs. Unknown keys, repeated
    /// keys, empty values and invalid values are errors.
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut args = Self::default();
        let mut seen = Vec::new();
        for pair in value.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (key, val) = pair
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .ok_or_else(|| format!("{TEST_ARGS_ENV}: expected `key=value`, got {pair:?}"))?;
            if val.is_empty() {
                return Err(format!("{TEST_ARGS_ENV}: empty value for `{key}`"));
            }
            if seen.contains(&key) {
                return Err(format!("{TEST_ARGS_ENV}: duplicate key `{key}`"));
            }
            seen.push(key);
            let invalid = || format!("{TEST_ARGS_ENV}: invalid {key}={val:?}");
            match key {
                "transport" => args.transport = Some(val.to_owned()),
                "api_rev" => match val {
                    "1_0" | "1_1" => args.api_rev = Some(val.to_owned()),
                    _ => return Err(invalid()),
                },
                "fast_backoff" => match val {
                    "1" => args.fast_backoff = true,
                    "0" => args.fast_backoff = false,
                    _ => return Err(invalid()),
                },
                "sock" => args.sock = Some(val.to_owned()),
                "resource_count" => {
                    args.resource_count = Some(val.parse().map_err(|_| invalid())?);
                }
                "server_bin" => args.server_bin = Some(val.to_owned()),
                _ => return Err(format!("{TEST_ARGS_ENV}: unknown key `{key}`")),
            }
        }
        Ok(args)
    }

    /// Reads [`TEST_ARGS_ENV`] when the `test-args` feature is enabled;
    /// otherwise, or when the variable is unset, returns the defaults.
    ///
    /// # Panics
    ///
    /// Panics if the variable is set but cannot be parsed. This only happens
    /// in test builds, where a misconfigured run should fail loudly.
    pub fn from_env() -> Self {
        #[cfg(feature = "test-args")]
        if let Some(args) = PROCESS_ARGS.get() {
            return args.clone();
        }
        #[cfg(feature = "test-args")]
        if let Some(value) = std::env::var_os(TEST_ARGS_ENV) {
            let value = value
                .into_string()
                .unwrap_or_else(|v| panic!("{TEST_ARGS_ENV} is not valid UTF-8: {v:?}"));
            return Self::parse(&value).unwrap_or_else(|e| panic!("{e}"));
        }
        Self::default()
    }
}

impl TestArgs {
    /// Sets the configuration [`TestArgs::from_env`] returns in this process
    /// (with the `test-args` feature), in place of [`TEST_ARGS_ENV`], without
    /// changing the environment that child processes inherit. Can be set
    /// once; returns `args` back if it was already set.
    pub fn set_process(args: TestArgs) -> Result<(), TestArgs> {
        PROCESS_ARGS.set(args)
    }
}

impl fmt::Display for TestArgs {
    /// Formats the set keys in the [`TestArgs::parse`] syntax.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pairs = [
            ("transport", self.transport.clone()),
            ("api_rev", self.api_rev.clone()),
            ("fast_backoff", self.fast_backoff.then(|| "1".to_owned())),
            ("sock", self.sock.clone()),
            ("resource_count", self.resource_count.map(|c| c.to_string())),
            ("server_bin", self.server_bin.clone()),
        ];
        let mut sep = "";
        for (key, value) in pairs {
            if let Some(value) = value {
                write!(f, "{sep}{key}={value}")?;
                sep = ";";
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_keys_and_round_trip() {
        let args = TestArgs::parse(
            " transport = sock ;api_rev=1_1;fast_backoff=1;sock=tcp://127.0.0.1:1;\
             resource_count=4;server_bin=/x/ddi_sock_server; ",
        )
        .expect("valid test args");
        assert_eq!(args.transport.as_deref(), Some("sock"));
        assert_eq!(args.api_rev.as_deref(), Some("1_1"));
        assert!(args.fast_backoff);
        assert_eq!(args.sock.as_deref(), Some("tcp://127.0.0.1:1"));
        assert_eq!(args.resource_count, Some(4));
        assert_eq!(args.server_bin.as_deref(), Some("/x/ddi_sock_server"));
        assert_eq!(TestArgs::parse(&args.to_string()), Ok(args));
        assert_eq!(TestArgs::parse(""), Ok(TestArgs::default()));
        assert_eq!(TestArgs::default().to_string(), "");
    }

    #[test]
    fn parse_rejects_invalid_input() {
        for bad in [
            "transport",
            "transport=",
            "bogus=1",
            "api_rev=session_ex",
            "fast_backoff=yes",
            "resource_count=four",
            "transport=sock;transport=nix",
        ] {
            assert!(TestArgs::parse(bad).is_err(), "{bad:?} should be rejected");
        }
    }
}
