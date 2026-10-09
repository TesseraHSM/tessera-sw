// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Prove that the original masked ECC keys have the expected recovery scopes.

use std::io::Write;

use anyhow::Context;
use anyhow::Result;
use jzon::JsonValue;
use tsra_api::HsmEccCurve;
use tsra_api::HsmEccKeyGenAlgo;
use tsra_api::HsmEccSignAlgo;
use tsra_api::HsmError;
use tsra_api::HsmKeyClass;
use tsra_api::HsmKeyCommonProps;
use tsra_api::HsmKeyKind;
use tsra_api::HsmKeyManager;
use tsra_api::HsmKeyPropsBuilder;
use tsra_api::HsmKeyScope;
use tsra_api::HsmSession;
use tsra_crypto::EccCurve;
use tsra_crypto::EccPublicKey;
use tsra_crypto::EcdsaAlgo;
use tsra_crypto::HashAlgo;
use tsra_crypto::HashOp;
use tsra_crypto::ImportableKey;
use tsra_crypto::Rng;
use tsra_crypto::VerifyOp;

const SCOPES: [(&str, HsmKeyScope); 4] = [
    ("local", HsmKeyScope::Local),
    ("security-domain", HsmKeyScope::SecurityDomain),
    ("ephemeral", HsmKeyScope::Ephemeral),
    ("session", HsmKeyScope::Session),
];

pub struct SavedKey {
    scope: HsmKeyScope,
    masked_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl SavedKey {
    fn validate(&self) -> Result<()> {
        let (scope, curve) = HsmEccSignAlgo::masked_key_info(&self.masked_key)
            .context("decode saved masked ECC signing key")?;
        anyhow::ensure!(
            scope == self.scope && curve == HsmEccCurve::P384,
            "saved ECC key has the wrong scope or curve"
        );
        anyhow::ensure!(
            EccPublicKey::from_bytes(&self.public_key)?.curve() == EccCurve::P384,
            "saved ECC public key must be P-384"
        );
        Ok(())
    }

    fn sign(&self, session: &HsmSession, challenge: &[u8]) -> Result<[u8; 96]> {
        let mut digest = [0u8; 48];
        HashAlgo::sha384().hash(challenge, Some(&mut digest))?;
        let mut signature = [0u8; 96];
        let len =
            HsmEccSignAlgo::sign_masked(session, &self.masked_key, &digest, Some(&mut signature))?;
        anyhow::ensure!(len == signature.len(), "incorrect P-384 signature length");
        Ok(signature)
    }

    fn verify(&self, challenge: &[u8], signature: &[u8]) -> Result<()> {
        let public_key = EccPublicKey::from_bytes(&self.public_key)?;
        anyhow::ensure!(
            EcdsaAlgo::new(HashAlgo::sha384()).verify(&public_key, challenge, signature)?,
            "signature does not match the original public key"
        );
        Ok(())
    }
}

pub fn generate(session: &HsmSession) -> Result<Vec<SavedKey>> {
    generate_with_domain(session, None)
}

fn generate_with_domain(
    session: &HsmSession,
    mut domain: Option<SavedKey>,
) -> Result<Vec<SavedKey>> {
    let mut keys = Vec::new();
    for (name, scope) in SCOPES {
        if scope == HsmKeyScope::SecurityDomain {
            if let Some(key) = domain.take() {
                let challenge = Rng::rand_vec(32)?;
                key.verify(&challenge, &key.sign(session, &challenge)?)?;
                keys.push(key);
                continue;
            }
        }
        let private_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Private)
            .key_kind(HsmKeyKind::Ecc)
            .ecc_curve(HsmEccCurve::P384)
            .is_session(scope == HsmKeyScope::Session)
            .scope(scope)
            .can_sign(true)
            .build()?;
        let public_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Public)
            .key_kind(HsmKeyKind::Ecc)
            .ecc_curve(HsmEccCurve::P384)
            .is_session(scope == HsmKeyScope::Session)
            .scope(scope)
            .can_verify(true)
            .build()?;
        let (private_key, public_key) = HsmKeyManager::generate_key_pair(
            session,
            &mut HsmEccKeyGenAlgo::default(),
            private_props,
            public_props,
        )
        .with_context(|| format!("generate {name} ECC key"))?;
        let key = SavedKey {
            scope,
            masked_key: private_key.masked_key_vec()?,
            public_key: public_key.pub_key_der_vec()?,
        };
        key.validate()?;
        let challenge = Rng::rand_vec(32)?;
        key.verify(
            &challenge,
            &key.sign(session, &challenge)
                .with_context(|| format!("sign with {name} key"))?,
        )
        .with_context(|| format!("verify {name} key before saving"))?;
        keys.push(key);
    }
    Ok(keys)
}

fn domain_key(keys: &[SavedKey]) -> Result<&SavedKey> {
    let key = keys
        .iter()
        .find(|key| key.scope == HsmKeyScope::SecurityDomain)
        .context("missing security-domain signing key")?;
    key.validate()?;
    Ok(key)
}

/// Export only the SD-masked signing key and its public identity, bound to the
/// service's full policy. No local, ephemeral or session key enters the catalog.
pub fn domain_catalog(keys: &[SavedKey], service: &str, policy: &[u8]) -> Result<JsonValue> {
    crate::leaf_name(service)?;
    let key = domain_key(keys)?;
    Ok(jzon::object! {
        version: 1, service: service, policy: hex::encode(policy),
        scope: "security-domain", algorithm: "ECDSA P-384 / SHA-384",
        masked_key: hex::encode(&key.masked_key), public_key: hex::encode(&key.public_key),
        fingerprint: domain_identity(keys)?["fingerprint"].clone(),
    })
}

fn catalog_key(record: &JsonValue, service: &str, policy: &[u8]) -> Result<SavedKey> {
    let key = SavedKey {
        scope: HsmKeyScope::SecurityDomain,
        masked_key: crate::wire::blob(record, "masked_key")?,
        public_key: crate::wire::blob(record, "public_key")?,
    };
    key.validate()?;
    anyhow::ensure!(
        *record == domain_catalog(std::slice::from_ref(&key), service, policy)?,
        "domain catalog metadata, service, policy or fingerprint mismatch"
    );
    Ok(key)
}

/// Validate immutable catalog framing and public identity without accessing an
/// SD. The joining HSM authenticates the masked blob and proves the key pairing.
pub fn validate_domain_catalog(record: &JsonValue, service: &str, policy: &[u8]) -> Result<()> {
    catalog_key(record, service, policy)?;
    Ok(())
}

/// Import only the catalog's SD key, prove it can sign in this domain, and
/// generate independent local, ephemeral and session scope-check keys.
pub fn generate_from_domain_catalog(
    session: &HsmSession,
    record: &JsonValue,
    service: &str,
    policy: &[u8],
) -> Result<Vec<SavedKey>> {
    generate_with_domain(session, Some(catalog_key(record, service, policy)?))
}

/// Public identity only; never expose the masked private key to a UI.
pub fn domain_identity(keys: &[SavedKey]) -> Result<JsonValue> {
    let key = domain_key(keys)?;
    let mut hash = [0u8; 48];
    HashAlgo::sha384().hash(&key.public_key, Some(&mut hash))?;
    Ok(jzon::object! {
        public_key: hex::encode(&key.public_key),
        fingerprint: hex::encode(hash),
        algorithm: "ECDSA P-384 / SHA-384",
    })
}

/// Sign inside the HSM and verify against the original saved public key.
pub fn sign_domain_challenge(
    session: &HsmSession,
    keys: &[SavedKey],
    challenge: &str,
) -> Result<JsonValue> {
    let key = domain_key(keys)?;
    let signature = key.sign(session, challenge.as_bytes())?;
    key.verify(challenge.as_bytes(), &signature)?;
    Ok(jzon::object! {
        identity: domain_identity(keys)?,
        challenge: challenge,
        signature: hex::encode(signature),
        verified: true,
    })
}

pub fn encode(keys: &[SavedKey]) -> Result<JsonValue> {
    anyhow::ensure!(keys.len() == SCOPES.len(), "missing ECC scope check keys");
    let mut record = jzon::object! {};
    for ((name, scope), key) in SCOPES.into_iter().zip(keys) {
        anyhow::ensure!(scope == key.scope, "incorrect ECC scope check key order");
        key.validate()?;
        record[name] = jzon::object! {
            masked_key: hex::encode(&key.masked_key),
            public_key: hex::encode(&key.public_key),
        };
    }
    Ok(record)
}

pub fn decode(record: &JsonValue) -> Result<Vec<SavedKey>> {
    let legacy = !record.has_key("session") && record.len() == SCOPES.len() - 1;
    anyhow::ensure!(
        record.is_object() && (record.len() == SCOPES.len() || legacy),
        "saved ECC scope checks must contain local, security-domain, ephemeral and session keys (session may be absent in older records)"
    );
    let mut keys = Vec::new();
    for (name, scope) in SCOPES {
        if legacy && scope == HsmKeyScope::Session {
            continue;
        }
        let entry = &record[name];
        let read = |field: &str| -> Result<Vec<u8>> {
            hex::decode(
                entry[field]
                    .as_str()
                    .with_context(|| format!("missing {name} {field}"))?,
            )
            .with_context(|| format!("invalid hex in {name} {field}"))
        };
        let key = SavedKey {
            scope,
            masked_key: read("masked_key")?,
            public_key: read("public_key")?,
        };
        key.validate()
            .with_context(|| format!("validate saved {name} key"))?;
        keys.push(key);
    }
    Ok(keys)
}

pub fn check_after_restore(
    session: &HsmSession,
    keys: &[SavedKey],
    output: &mut impl Write,
) -> Result<()> {
    anyhow::ensure!(
        keys.len() == SCOPES.len() || keys.len() == SCOPES.len() - 1,
        "missing ECC scope check keys"
    );
    writeln!(
        output,
        "\nECC scope checks (P-384, original saved masked keys):"
    )?;
    for ((name, scope), key) in SCOPES.into_iter().zip(keys) {
        anyhow::ensure!(scope == key.scope, "incorrect ECC scope check key order");
        key.validate()?;
        let challenge = Rng::rand_vec(32)?;
        let result = key.sign(session, &challenge);
        if matches!(scope, HsmKeyScope::Ephemeral | HsmKeyScope::Session) {
            match result {
                Err(error)
                    if error.downcast_ref::<HsmError>()
                        == Some(&HsmError::MaskedKeyAuthenticationFailed) =>
                {
                    writeln!(
                        output,
                        "  {name}: rejected as expected (masked-key authentication failed)"
                    )?;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("unexpected error signing with {name} key"))
                }
                Ok(_) => anyhow::bail!("{name} ECC key unexpectedly survived local restore"),
            }
            if keys.len() < SCOPES.len() {
                writeln!(
                    output,
                    "  session: skipped (no session key saved by the original create command)"
                )?;
            }
        } else {
            let signature = result.with_context(|| format!("sign with original {name} key"))?;
            key.verify(&challenge, &signature)
                .with_context(|| format!("verify signature from original {name} key"))?;
            writeln!(output, "  {name}: sign + verify passed")?;
        }
    }
    Ok(())
}

pub fn print_created(output: &mut impl Write) -> Result<()> {
    writeln!(
        output,
        "\nECC scope checks (P-384, generated after SD creation):"
    )?;
    for (name, _) in SCOPES {
        writeln!(
            output,
            "  {name}: sign + verify passed; original masked key saved"
        )?;
    }
    Ok(())
}
