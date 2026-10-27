// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parser for `tsra://` key URIs, used by `ENGINE_load_private_key` and the
//! AES ciphers' key control.
//!
//! Grammar (mirrors the OpenSSL 3.x provider's STORE):
//!
//! ```text
//! tsra://<masked-key-file-path>;type=<ec|rsa|rsa-pss|aes>
//! ```
//!
//! The identifier is a filesystem path to a masked-key blob; `type=` is
//! mandatory. `aes` keys are not private keys: they are attached to a cipher
//! context (see [`crate::aes`]), and `ENGINE_load_private_key` rejects them.
//!
//! Note: unlike the provider's STORE — which ignores unrecognized attributes —
//! this parser is stricter and rejects unknown or malformed attributes, so a
//! typo fails fast rather than being silently dropped.

use std::path::PathBuf;
use std::str::FromStr;

use tsra_ossl_engine_core::error::EngineError;
use tsra_ossl_engine_core::error::EngineResult;

const SCHEME: &str = "tsra://";

/// Key type selected by the URI `type=` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ec,
    Rsa,
    RsaPss,
    Aes,
}

impl FromStr for KeyType {
    type Err = EngineError;

    /// Parse a URI `type=` value into a [`KeyType`]. Case-insensitive, mirroring
    /// the provider's STORE (which compares with `strcasecmp`).
    fn from_str(value: &str) -> EngineResult<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ec" => Ok(KeyType::Ec),
            "rsa" => Ok(KeyType::Rsa),
            "rsa-pss" => Ok(KeyType::RsaPss),
            "aes" => Ok(KeyType::Aes),
            _ => Err(EngineError::Other(format!(
                "unknown tsra key type: {value}"
            ))),
        }
    }
}

/// A parsed `tsra://<path>;type=<t>` key URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyUri {
    /// Path to the masked-key blob on disk.
    pub masked_key_path: PathBuf,
    /// Declared key type.
    pub key_type: KeyType,
}

/// Parse an `tsra://` key URI.
pub fn parse(uri: &str) -> EngineResult<KeyUri> {
    let rest = uri
        .strip_prefix(SCHEME)
        .ok_or_else(|| EngineError::Other(format!("key id is not an {SCHEME} URI: {uri}")))?;

    let (path, attrs) = rest.split_once(';').unwrap_or((rest, ""));
    if path.is_empty() {
        return Err(EngineError::Other("tsra URI has no key path".into()));
    }

    let mut key_type = None;
    for attr in attrs.split(';').filter(|a| !a.is_empty()) {
        let (key, value) = attr
            .split_once('=')
            .ok_or_else(|| EngineError::Other(format!("malformed tsra URI attribute: {attr}")))?;
        // Attribute names are case-insensitive, mirroring the provider's STORE
        // (which compares with `strcasecmp`).
        match key.to_ascii_lowercase().as_str() {
            "type" => key_type = Some(value.parse::<KeyType>()?),
            _ => {
                return Err(EngineError::Other(format!(
                    "unknown tsra URI attribute: {key}"
                )));
            }
        }
    }

    let key_type = key_type
        .ok_or_else(|| EngineError::Other("tsra URI missing required type= attribute".into()))?;

    Ok(KeyUri {
        masked_key_path: PathBuf::from(path),
        key_type,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn parses_relative_ec() {
        let u = parse("tsra://./key.bin;type=ec").unwrap();
        assert_eq!(u.masked_key_path, PathBuf::from("./key.bin"));
        assert_eq!(u.key_type, KeyType::Ec);
    }

    #[test]
    fn parses_absolute_rsa() {
        let u = parse("tsra:///var/lib/tsra/k.bin;type=rsa").unwrap();
        assert_eq!(u.masked_key_path, PathBuf::from("/var/lib/tsra/k.bin"));
        assert_eq!(u.key_type, KeyType::Rsa);
    }

    #[test]
    fn parses_rsa_pss() {
        assert_eq!(
            parse("tsra://k;type=rsa-pss").unwrap().key_type,
            KeyType::RsaPss
        );
    }

    // The provider's STORE compares the attribute name and value with
    // strcasecmp, so mixed case must parse the same here.
    #[test]
    fn parses_uppercase_attr_name_and_value() {
        let u = parse("tsra://./key.bin;TYPE=EC").unwrap();
        assert_eq!(u.key_type, KeyType::Ec);
    }

    #[test]
    fn parses_mixed_case_rsa_pss() {
        assert_eq!(
            parse("tsra://k;Type=Rsa-PSS").unwrap().key_type,
            KeyType::RsaPss
        );
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!(parse("./key.bin;type=ec").is_err());
    }

    #[test]
    fn rejects_empty_path() {
        assert!(parse("tsra://;type=ec").is_err());
    }

    #[test]
    fn rejects_missing_type() {
        assert!(parse("tsra://./key.bin").is_err());
    }

    #[test]
    fn rejects_unknown_type() {
        assert!(parse("tsra://k;type=dsa").is_err());
    }

    #[test]
    fn parses_aes() {
        assert_eq!(parse("tsra://k;type=AES").unwrap().key_type, KeyType::Aes);
    }

    #[test]
    fn rejects_unknown_attribute() {
        assert!(parse("tsra://k;type=ec;foo=bar").is_err());
    }

    #[test]
    fn rejects_malformed_attribute() {
        assert!(parse("tsra://k;type").is_err());
    }
}
