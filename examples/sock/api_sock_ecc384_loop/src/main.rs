// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Generate, sign, and verify session-scoped P-384 keys over TCP on Windows or Linux.
//!
//! Run with `cargo run -p tsra_api_sock_ecc384_loop --features sock -- [ENDPOINT] [COUNT]`.
//! Defaults are `tcp://127.0.0.1:1234` and one iteration on both platforms.
//! Use only a disposable test partition: this example rotates the default CO PSK
//! to a fixed, publicly known test value and reuses that value on later runs.

use tsra_api::*;

const DEFAULT_ENDPOINT: &str = "tcp://127.0.0.1:1234";
const TOOL_CO_PSK: [u8; PSK_LEN] = [0xA5; PSK_LEN];

#[derive(Debug, PartialEq, Eq)]
struct Options {
    endpoint: String,
    count: usize,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Options, String> {
    let endpoint = args.next().unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned());
    if endpoint
        .strip_prefix("tcp://")
        .is_none_or(|address| address.is_empty())
    {
        return Err("endpoint must have the form tcp://HOST:PORT".to_owned());
    }
    let count = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| format!("invalid iteration count: {error}"))?
        .unwrap_or(1);
    if count == 0 {
        return Err("iteration count must be greater than zero".to_owned());
    }
    if args.next().is_some() {
        return Err("usage: tsra_api_sock_ecc384_loop [ENDPOINT] [COUNT]".to_owned());
    }
    Ok(Options { endpoint, count })
}

fn open_session(endpoint: &str) -> Result<HsmSession, Box<dyn std::error::Error>> {
    std::env::set_var("TSRA_DDI_SOCK", endpoint);

    let info = HsmPartitionManager::partition_info_list()
        .into_iter()
        .find(|info| info.path == endpoint)
        .ok_or("the TCP endpoint was not discovered")?;
    let rev = info
        .api_rev_range
        .ok_or("failed to query the API revision; check the endpoint and TCP server")?
        .max();
    let partition = HsmPartitionManager::open_partition(&info.path, rev)
        .map_err(|error| format!("failed to open HSM partition: {error}"))?;

    let default_session = partition.open_session_ex(
        rev,
        HsmSessionPsk::new(HsmPskId::CO),
        HsmSessionExType::Authenticated,
    );

    match default_session {
        Ok(session) => {
            session
                .change_psk(&TOOL_CO_PSK)
                .map_err(|error| format!("failed to rotate the default CO PSK: {error}"))?;
            Ok(session)
        }
        Err(default_error) => partition
            .open_session_ex(
                rev,
                HsmSessionPsk::with_psk(HsmPskId::CO, &TOOL_CO_PSK),
                HsmSessionExType::Authenticated,
            )
            .map_err(|rotated_error| {
                format!(
                    "failed to open TBOR V2 session with the default PSK ({default_error}) \
                     or the tool PSK ({rotated_error})"
                )
                .into()
            }),
    }
}

fn generate_key_pair(
    session: &HsmSession,
) -> Result<(HsmEccPrivateKey, HsmEccPublicKey), HsmError> {
    let private_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384)
        .can_sign(true)
        .scope(HsmKeyScope::Session)
        .build()?;
    let public_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384)
        .can_verify(true)
        .scope(HsmKeyScope::Session)
        .build()?;

    HsmKeyManager::generate_key_pair(
        session,
        &mut HsmEccKeyGenAlgo::default(),
        private_props,
        public_props,
    )
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = parse_args(std::env::args().skip(1))?;
    let session = open_session(&options.endpoint)?;

    for index in 1..=options.count {
        let (private_key, public_key) = generate_key_pair(&session).map_err(|error| {
            format!("ECC P-384 key generation failed at iteration {index}: {error}")
        })?;
        let message = format!("TSRA TCP ECC P-384 loop iteration {index}");
        let digest = openssl::sha::sha384(message.as_bytes());
        let signature = HsmSigner::sign_vec(&mut HsmEccSignAlgo::default(), &private_key, &digest)
            .map_err(|error| format!("ECC P-384 signing failed at iteration {index}: {error}"))?;
        let verified = HsmVerifier::verify(
            &mut HsmEccSignAlgo::default(),
            &public_key,
            &digest,
            &signature,
        )
        .map_err(|error| format!("ECC P-384 verification failed at iteration {index}: {error}"))?;
        if !verified {
            return Err(format!("ECC P-384 verification failed at iteration {index}").into());
        }

        let signature_prefix = signature
            .get(..32)
            .ok_or_else(|| format!("ECC P-384 signature was too short at iteration {index}"))?;
        println!(
            "ECC P-384 {index}/{} succeeded: generated key, signed SHA-384 digest, \
             verified signature={}",
            options.count,
            hex(signature_prefix)
        );
    }
    println!(
        "Completed {} iteration(s) over {}",
        options.count, options.endpoint
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        assert_eq!(
            parse_args(std::iter::empty()).expect("default options"),
            Options {
                endpoint: DEFAULT_ENDPOINT.to_owned(),
                count: 1
            }
        );
    }

    #[test]
    fn explicit_options() {
        assert_eq!(
            parse_args(["tcp://localhost:2345", "5"].into_iter().map(str::to_owned))
                .expect("explicit options"),
            Options {
                endpoint: "tcp://localhost:2345".to_owned(),
                count: 5
            }
        );
    }

    #[test]
    fn rejects_invalid_counts() {
        for count in ["0", "-1", "invalid", "184467440737095516160"] {
            assert!(
                parse_args([DEFAULT_ENDPOINT, count].into_iter().map(str::to_owned)).is_err(),
                "{count}"
            );
        }
    }

    #[test]
    fn rejects_non_tcp_endpoints() {
        for endpoint in ["", "tcp://", "vsock://4:1234", "/tmp/tsra-ddi.sock"] {
            assert!(
                parse_args([endpoint].into_iter().map(str::to_owned)).is_err(),
                "{endpoint}"
            );
        }
    }

    #[test]
    fn rejects_extra_arguments() {
        assert!(parse_args(
            [DEFAULT_ENDPOINT, "1", "extra"]
                .into_iter()
                .map(str::to_owned)
        )
        .is_err());
    }

    #[test]
    fn hex_encoding() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0x10, 0x80, 0xff]), "000f1080ff");
    }
}
