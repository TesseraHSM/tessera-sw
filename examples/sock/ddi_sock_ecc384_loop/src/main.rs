// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Generate, sign, and verify session-scoped P-384 keys over the socket DDI.
//!
//! Build with `cargo build -p tsra_ddi_sock_ecc384_loop --features sock`.
//! Run as `tsra_ddi_sock_ecc384_loop [ENDPOINT] [COUNT]`; the default endpoint
//! is `vsock://4:1234`. Unix socket paths are also supported.
//! Use only a disposable test partition: this tool rotates the default CO PSK
//! to a fixed, publicly known test value and reuses that value on later runs.

#[cfg(unix)]
mod unix {
    use tsra_api::*;

    const DEFAULT_ENDPOINT: &str = "vsock://4:1234";
    const TOOL_CO_PSK: [u8; PSK_LEN] = [0xA5; PSK_LEN];

    fn parse_args() -> Result<(String, usize), Box<dyn std::error::Error>> {
        let mut args = std::env::args().skip(1);
        let endpoint = args.next().unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned());
        let count = args
            .next()
            .map(|value| value.parse::<usize>())
            .transpose()
            .map_err(|error| format!("invalid iteration count: {error}"))?
            .unwrap_or(1);

        if count == 0 {
            return Err("iteration count must be greater than zero".into());
        }
        if args.next().is_some() {
            return Err("usage: tsra_ddi_sock_ecc384_loop [ENDPOINT] [COUNT]".into());
        }

        Ok((endpoint, count))
    }

    fn open_session(endpoint: &str) -> Result<HsmSession, Box<dyn std::error::Error>> {
        std::env::set_var("TSRA_DDI_SOCK", endpoint);

        let info = HsmPartitionManager::partition_info_list()
            .into_iter()
            .next()
            .ok_or("no HSM partition found through the socket transport")?;
        let rev = info
            .api_rev_range
            .ok_or("the HSM did not report a supported API revision")?
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

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        let (endpoint, count) = parse_args()?;
        let session = open_session(&endpoint)?;

        for index in 1..=count {
            let (private_key, public_key) = generate_key_pair(&session).map_err(|error| {
                format!("ECC P-384 key generation failed at iteration {index}: {error}")
            })?;
            let message = format!("TSRA ECC P-384 loop iteration {index}");
            let digest = openssl::sha::sha384(message.as_bytes());
            let signature =
                HsmSigner::sign_vec(&mut HsmEccSignAlgo::default(), &private_key, &digest)
                    .map_err(|error| {
                        format!("ECC P-384 signing failed at iteration {index}: {error}")
                    })?;
            let verified = HsmVerifier::verify(
                &mut HsmEccSignAlgo::default(),
                &public_key,
                &digest,
                &signature,
            )
            .map_err(|error| {
                format!("ECC P-384 verification failed at iteration {index}: {error}")
            })?;

            if !verified {
                return Err(format!("ECC P-384 verification failed at iteration {index}").into());
            }

            let signature_prefix = signature
                .get(..32)
                .ok_or_else(|| format!("ECC P-384 signature was too short at iteration {index}"))?;
            println!(
                "ECC P-384 {index}/{count} succeeded: generated key, signed SHA-384 digest, \
             verified signature={}",
                hex(signature_prefix)
            );
        }

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        unix::run()
    }
    #[cfg(not(unix))]
    {
        Err("the DDI socket tool requires a Unix target".into())
    }
}
