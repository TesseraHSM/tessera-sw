// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-opcode NSSR (live-migration reset) suite for the MBOR DDI.
//!
//! Each test sets up state, performs an NSSR (`dev.erase()`; the emulator
//! disables and re-enables the partition), sends one opcode and asserts the
//! exact reply. [`guard`] fails when a `DdiOp` variant has no row here.
//!
//! In-session keyed rows assert three checkpoints: (1) the old session is
//! rejected, then recovery A (`EstablishCredential` with the saved BMK +
//! `ReopenSession` under the same id); (2) the old key id is gone, then
//! recovery B (`UnmaskKey` of the saved masked key); (3) the op succeeds and
//! its output matches the pre-NSSR material.
//!
//! | Opcode | Class | Reply right after NSSR | Recovery | Reply after recovery | Notes |
//! |---|---|---|---|---|---|
//! | GetApiRev | NoSession | Success, unchanged | — | — | |
//! | GetDeviceInfo | NoSession | Success, unchanged | — | — | |
//! | GetCertChainInfo | NoSession | Success, new thumbprint | — | — | same cert count |
//! | GetCertificate | NoSession | Success, new leaf | — | — | device certs unchanged; identity key regenerated |
//! | GetEstablishCredEncryptionKey | NoSession | Success, new key + nonce | — | — | NSSR re-arms the consumed tunnel key (`KeyNotFound` before) |
//! | EstablishCredential | NoSession | `EccVerifyFailed` with a pre-NSSR POTA endorsement | re-endorse new identity | Success | pre-NSSR nonce → `NonceMismatch` (`nssr_mid_establish_credential`) |
//! | GetSessionEncryptionKey | NoSession | `CredentialsNotEstablished` | A (credential) | Success, new key | |
//! | InitBk3 | NoSession | `Bk3AlreadyInitialized` | — | — | one-shot survives; fails on the emulator (NOTE) |
//! | GetSealedBk3 | NoSession | Success, same blob | — | — | sealed BK3 survives; fails on the emulator (NOTE) |
//! | SetSealedBk3 | NoSession | `SealedBk3AlreadySet` | — | — | write-once survives; fails on the emulator (NOTE) |
//! | SetInitBk3Pin | NoSession | `InvalidArg` | — | `InvalidArg` | unknown to firmware (NOTE) |
//! | SecureInitBk3 | NoSession | `InvalidArg` | — | `InvalidArg` | unknown to firmware (NOTE) |
//! | OpenSession | Open | `CredentialsNotEstablished` | A (credential) | Success, new id | pre-NSSR payload → `NonceMismatch` |
//! | CloseSession | Close | Success | — | slot gone: `FileHandleSessionIdDoesNotMatch` | sock transport answers first |
//! | ReopenSession | InSession (gate-exempt) | `PartitionNotProvisioned` | A (credential) | Success, same id | Active slot → `ProcessedIoEventInInvalidState` |
//! | DeleteKey | InSession | `SessionNeedsRenegotiation` | A, B | Success | old id → `KeyNotFound` |
//! | AttestKey | InSession | `SessionNeedsRenegotiation` | A, B | Success | same key, signed by the new identity |
//! | RsaModExp | InSession | `SessionNeedsRenegotiation` | A, B | Success, same output | old id → `KeyNotFound` |
//! | RsaUnwrap | InSession | `SessionNeedsRenegotiation` | A, `GetUnwrappingKey` | Success, same key | old id → `KeyNotFound`; `UnmaskKey` → `InvalidKeyType` |
//! | GetUnwrappingKey | InSession | `SessionNeedsRenegotiation` | A | Success, same key | per-allocation key is re-imported |
//! | EccGenerateKeyPair | InSession | `SessionNeedsRenegotiation` | A | Success | |
//! | EccSign | InSession | `SessionNeedsRenegotiation` | A, B | Success, verifies with pre-NSSR key | old id → `KeyNotFound` |
//! | AesGenerateKey | InSession | `SessionNeedsRenegotiation` | A | Success | |
//! | AesEncryptDecrypt | InSession | `SessionNeedsRenegotiation` | A, B | Success, same plaintext | old id → `KeyNotFound` |
//! | EcdhKeyExchange | InSession | `SessionNeedsRenegotiation` | A, B | Success, same secret | old id → `KeyNotFound` |
//! | HkdfDerive | InSession | `SessionNeedsRenegotiation` | A, B | Success, same derived key | old id → `KeyNotFound` |
//! | KbkdfCounterHmacDerive | InSession | `SessionNeedsRenegotiation` | A, B | Success, same derived key | old id → `KeyNotFound` |
//! | Hmac | InSession | `SessionNeedsRenegotiation` | A, B | Success, same tag | old id → `KeyNotFound` |
//! | ChangePin | InSession | `SessionNeedsRenegotiation` | A | Success | pre-NSSR payload → `NonceMismatch` |
//! | UnmaskKey | InSession | `SessionNeedsRenegotiation` | A | Success, keys work | app and session keys |
//! | ShaDigest | InSession | `SessionNeedsRenegotiation` | A | Success, same digest | |
//! | OpenKey | InSession | `SessionNeedsRenegotiation` | A | `UnsupportedCmd` | no firmware handler |
//! | Invalid | — | — | — | — | excluded: sentinel |
//! | AES-GCM bulk | fast path | `SessionNeedsRenegotiation` | A, B | Success, same ciphertext | sock transport only; old id → `FpError(2)` |
//! | AES-XTS bulk | fast path | `SessionNeedsRenegotiation` | A, B | Success, same ciphertext | sock transport only; old id → `FpError(1)` |
//!
//! Mid-sequence rows (`nssr_mid_*`) put the NSSR between two steps of one
//! flow.
//!
//! The three BK3 rows in [`bk3`] are expected to fail on the emulator until
//! its NSSR preserves provisioning like a hardware `Migrate` (see its NOTE).

#![cfg(test)]

mod bk3;
mod bulk;
mod guard;
mod keyed;
mod keyless;
mod lifecycle;
mod mid_sequence;
mod no_session;

use std::fmt::Debug;

use tsra_ddi::*;
use tsra_ddi_mbor_codec::MborByteArray;
use tsra_ddi_mbor_types::*;

use super::common::*;

type Dev = <DdiTest as Ddi>::Dev;

const REV: Option<DdiApiRev> = Some(DdiApiRev { major: 1, minor: 0 });

/// Reference plaintext (a multiple of the AES block size).
const MSG: [u8; 64] = [0x5A; 64];

/// Simulated live-migration NSSR.
fn nssr(dev: &Dev) {
    dev.erase().expect("NSSR (erase) must succeed");
}

fn empty() -> MborByteArray<1024> {
    MborByteArray::from_slice(&[]).expect("empty byte array")
}

/// Asserts that `result` failed with exactly `expected`.
#[track_caller]
fn assert_status<T: Debug>(result: Result<T, DdiError>, expected: DdiStatus, what: &str) {
    match result {
        Err(DdiError::DdiStatus(status)) if status == expected => {}
        other => panic!("{what}: expected {expected:?}, got {other:?}"),
    }
}

/// Checkpoint 1: an in-session op on the migrated slot must renegotiate.
#[track_caller]
fn assert_stale_session<T: Debug>(result: Result<T, DdiError>) {
    assert_status(
        result,
        DdiStatus::SessionNeedsRenegotiation,
        "checkpoint 1 (stale session)",
    );
}

/// A provisioned partition with one open session on `dev`, plus everything
/// the host persists to recover it after an NSSR.
struct Lm(LMSetupResult);

impl Lm {
    fn new(dev: &mut Dev, ddi: &DdiTest, path: &str) -> Self {
        Self(common_setup_for_lm(dev, ddi, path))
    }

    fn sid(&self) -> u16 {
        self.0.session_id
    }

    fn reestablish_credential(&self, dev: &mut Dev) {
        helper_common_establish_credential_with_bmk(
            dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            self.0.masked_bk3,
            self.0.partition_bmk,
            empty(),
        );
    }

    /// Pre-built `ReopenSession` credential for this session's seed.
    fn reopen_credential(&self, dev: &Dev) -> (DdiEncryptedSessionCredential, DdiDerPublicKey) {
        encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN, self.0.random_seed)
    }

    fn reopen_with(
        &self,
        dev: &Dev,
        (credential, pub_key): (DdiEncryptedSessionCredential, DdiDerPublicKey),
    ) -> Result<DdiReopenSessionResp, DdiError> {
        let resp = helper_reopen_session(
            dev,
            self.sid(),
            REV,
            credential,
            pub_key,
            self.0.session_bmk,
        )?;
        assert_eq!(
            resp.data.sess_id,
            self.sid(),
            "ReopenSession must keep the id"
        );
        Ok(resp.data)
    }

    fn reopen(&self, dev: &Dev) -> Result<DdiReopenSessionResp, DdiError> {
        self.reopen_with(dev, self.reopen_credential(dev))
    }

    /// Recovery A: re-establish the credential with the saved BMK, then
    /// `ReopenSession` the migrated slot under the same id.
    fn recover_session(&self, dev: &mut Dev) -> DdiReopenSessionResp {
        self.reestablish_credential(dev);
        self.reopen(dev)
            .expect("ReopenSession must re-key the migrated slot")
    }

    /// Recovery B: re-import a pre-NSSR masked key into the recovered session.
    fn unmask(&self, dev: &Dev, masked_key: MborByteArray<3072>) -> DdiUnmaskKeyResp {
        helper_unmask_key(dev, Some(self.sid()), REV, masked_key)
            .expect("UnmaskKey must restore the pre-NSSR key")
            .data
    }

    /// Keyless contract: NSSR → checkpoint 1 → recovery A.
    fn cycle<T: Debug>(&self, dev: &mut Dev, op: impl Fn(&Dev) -> Result<T, DdiError>) {
        nssr(dev);
        assert_stale_session(op(dev));
        self.recover_session(dev);
    }

    /// Keyed contract up to checkpoint 3: NSSR → checkpoint 1 → recovery A →
    /// checkpoint 2 (old `key_id`) → recovery B. Returns the restored key.
    fn cycle_keyed<T: Debug>(
        &self,
        dev: &mut Dev,
        key_id: u16,
        masked_key: MborByteArray<3072>,
        op: impl Fn(&Dev, u16) -> Result<T, DdiError>,
    ) -> DdiUnmaskKeyResp {
        nssr(dev);
        assert_stale_session(op(dev, key_id));
        self.recover_session(dev);
        assert_status(
            op(dev, key_id),
            DdiStatus::KeyNotFound,
            "checkpoint 2 (stale key)",
        );
        self.unmask(dev, masked_key)
    }
}

fn key_props(usage: DdiKeyUsage, availability: DdiKeyAvailability) -> DdiKeyProperties {
    helper_key_properties(usage, availability)
}

/// AES-CBC over `msg` with a fixed IV; returns the output bytes.
fn aes_cbc(
    dev: &Dev,
    sid: u16,
    key_id: u16,
    op: DdiAesOp,
    msg: &[u8],
) -> Result<Vec<u8>, DdiError> {
    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(sid),
        REV,
        key_id,
        op,
        MborByteArray::from_slice(msg).expect("AES message"),
        MborByteArray::from_slice(&[0x11; 16]).expect("AES IV"),
    )?;
    Ok(resp.data.msg.as_slice().to_vec())
}

/// Generates an AES-256 CBC key with the given availability.
fn aes_key(dev: &Dev, sid: u16, availability: DdiKeyAvailability) -> DdiAesGenerateKeyResp {
    helper_aes_generate(
        dev,
        Some(sid),
        REV,
        DdiAesKeySize::Aes256,
        key_props(DdiKeyUsage::EncryptDecrypt, availability),
    )
    .expect("AesGenerateKey")
    .data
}

/// Generates a P-256 key pair with the given usage.
fn ecc_key(dev: &Dev, sid: u16, usage: DdiKeyUsage) -> DdiEccGenerateKeyPairResp {
    helper_ecc_generate_key_pair(
        dev,
        Some(sid),
        REV,
        DdiEccCurve::P256,
        key_props(usage, DdiKeyAvailability::Session),
    )
    .expect("EccGenerateKeyPair")
    .data
}
