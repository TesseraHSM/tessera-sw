// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA (FIPS 204) and ML-KEM (FIPS 203) operations for the HSM PAL.
//!
//! Unlike the other crypto families in this module, ML-DSA is not
//! computed on the HSM core.  The PAL dispatches it to a fastpath (FP)
//! core over IPC and returns the result, so implementations are thin
//! forwarders rather than algorithm code.
//!
//! Includes ML-KEM key generation, encapsulation, and decapsulation.

use super::*;

/// Length of the ML-DSA message representative μ (FIPS 204).
pub const MLDSA_MU_LEN: usize = 64;

/// How the `message` input of an ML-DSA signature operation is interpreted.
///
/// FIPS 204 signs and verifies the 64-byte message representative
/// `μ = SHAKE256(tr || M', 64)`, where `tr` is the hash of the public key and
/// `M'` encodes the domain, the context string and the input.  The type
/// selects what the caller supplies and so how much of `μ` is computed for
/// it.  Discriminants follow the engine's 2-bit message-type encoding.
///
/// The pre-hash types are currently unsupported: implementations reject
/// them with [`HsmError::UnsupportedCmd`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMlDsaMsgType {
    /// Pure ML-DSA (FIPS 204 §5.2): `message` is the message `M`, and
    /// `μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)`.
    Pure = 0,

    /// Pre-hash ML-DSA (HashML-DSA, FIPS 204 §5.4): `message` is the
    /// 11-byte DER object identifier of the pre-hash function followed by
    /// the message digest `PHM`, and
    /// `μ = SHAKE256(tr || 0x01 || len(ctx) || ctx || OID || PHM, 64)`.
    PreHash = 1,

    /// Pre-hash ML-DSA computed from the message: `message` is the 11-byte
    /// OID followed by the message `M` itself; the implementation computes
    /// `PHM` from `M`, then `μ` as for [`PreHash`](Self::PreHash).
    PreHashMessage = 2,

    /// External μ: `message` is the [`MLDSA_MU_LEN`]-byte `μ`, used as is.
    /// It already binds the context string, so `ctx` must be empty.
    ExternalMu = 3,
}

impl HsmMlDsaMsgType {
    /// Check an input of this type for the parts that do not depend on the
    /// implementation: an external `μ` is exactly [`MLDSA_MU_LEN`] bytes and
    /// comes without a context string.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — the input is well formed for this type.
    /// - `Err(HsmError::InvalidArg)` — it is not.
    pub fn check_input(self, message: &[u8], ctx: &[u8]) -> HsmResult<()> {
        match self {
            Self::ExternalMu if message.len() != MLDSA_MU_LEN || !ctx.is_empty() => {
                Err(HsmError::InvalidArg)
            }
            _ => Ok(()),
        }
    }
}

/// Asynchronous ML-DSA signature operations.
///
/// Async because every method is a round trip to an FP core: the
/// implementation yields while the request is in flight.
///
/// Every signing and verification method takes an [`HsmMlDsaMsgType`]
/// saying how its `message` is to be read.
pub trait HsmMlDsa {
    /// Replace the prefix of a key/signature region with an ML-DSA signature.
    ///
    /// The expanded secret key occupies the final parameter-set key-length bytes
    /// of `key_signature`; any preceding bytes are scratch. The signature is
    /// written at the start of this region after all inputs have been consumed.
    /// `message` and `ctx` are disjoint from it. The caller wipes private bytes
    /// not replaced by the signature.
    ///
    /// `msg_type` says how `message` is to be read; see
    /// [`mldsa_sign`](Self::mldsa_sign) for the errors.
    async fn mldsa_sign_in_place(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        key_signature: &mut HsmDmaBuf,
        msg_type: HsmMlDsaMsgType,
        message: &HsmDmaBuf,
        ctx: &HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Generate an ML-DSA keypair.
    ///
    /// Returns both the 32-byte `xi` seed and the expanded secret key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `kind` — parameter set as a seed-kind [`HsmVaultKeyKind`]
    ///   ([`MlDsa44Seed`](HsmVaultKeyKind::MlDsa44Seed) /
    ///   [`MlDsa65Seed`](HsmVaultKeyKind::MlDsa65Seed) /
    ///   [`MlDsa87Seed`](HsmVaultKeyKind::MlDsa87Seed)).
    /// - `seed` — output; must be exactly 32 bytes.  The implementation
    ///   fills it from the device's entropy source: the seed is the private
    ///   key, and the fastpath cores have no entropy source of their own.
    /// - `pub_key` — output; must be exactly the parameter set's public
    ///   key length (1312 / 1952 / 2592 bytes for ML-DSA-44 / -65 / -87).
    /// - `sec_key` — output; expanded secret key (2560 / 4032 / 4896 bytes).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `seed`, `pub_key`, and `sec_key` populated.
    /// - `Err(HsmError::InvalidArg)` — `kind` is not a seed kind, or an
    ///   output buffer is the wrong length.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    async fn mldsa_gen_key(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        seed: &mut HsmDmaBuf,
        pub_key: &mut HsmDmaBuf,
        sec_key: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Sign a message with an expanded secret key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `kind` — parameter set as a seed-kind [`HsmVaultKeyKind`].
    /// - `sec_key` — expanded secret key (2560 / 4032 / 4896 bytes).
    /// - `msg_type` — how `message` is to be read.
    /// - `message` — the input to sign, as `msg_type` defines it: the
    ///   message itself, or the 64-byte `μ`.
    /// - `ctx` — FIPS 204 context string, up to 255 bytes; empty for an
    ///   external `μ`.
    /// - `signature` — output; must be exactly the parameter set's
    ///   signature length (2420 / 3309 / 4627).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `signature` populated.
    /// - `Err(HsmError::InvalidArg)` — bad kind or buffer length, or a
    ///   `message`/`ctx` not valid for `msg_type`.
    /// - `Err(HsmError::UnsupportedCmd)` — `msg_type` is a pre-hash type.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    #[allow(clippy::too_many_arguments)]
    async fn mldsa_sign(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        sec_key: &HsmDmaBuf,
        msg_type: HsmMlDsaMsgType,
        message: &HsmDmaBuf,
        ctx: &HsmDmaBuf,
        signature: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Verify a signature under a public key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `kind` — parameter set as a seed-kind [`HsmVaultKeyKind`].
    /// - `pub_key` — encoded public key, exactly the parameter set's length.
    /// - `msg_type` — how `message` is to be read.
    /// - `message`, `ctx` — the signed input, as `msg_type` defines it, and
    ///   its FIPS 204 context (empty for an external `μ`).
    /// - `signature` — exactly the parameter set's signature length.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` / `Ok(false)` — the signature verified, or did not.
    ///   An invalid signature is an ordinary outcome, not an error, so it
    ///   cannot be conflated with a transport fault.
    /// - `Err(HsmError::InvalidArg)` — bad kind or buffer length, or a
    ///   `message`/`ctx` not valid for `msg_type`.
    /// - `Err(HsmError::UnsupportedCmd)` — `msg_type` is a pre-hash type.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    #[allow(clippy::too_many_arguments)]
    async fn mldsa_verify(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        pub_key: &HsmDmaBuf,
        msg_type: HsmMlDsaMsgType,
        message: &HsmDmaBuf,
        ctx: &HsmDmaBuf,
        signature: &HsmDmaBuf,
    ) -> HsmResult<bool>;
}

/// Asynchronous ML-KEM key-encapsulation operations.
///
/// Async because every method is a round trip to an FP core: the
/// implementation yields while the request is in flight.
pub trait HsmMlKem {
    /// Replace a public-key region's prefix with an ML-KEM ciphertext.
    ///
    /// `pub_key_ciphertext` initially contains exactly one encoded public key.
    /// The key must be consumed before its prefix is overwritten by ciphertext.
    /// `shared_secret` is a disjoint 32-byte output owned by the caller.
    async fn mlkem_encaps_in_place(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        pub_key_ciphertext: &mut HsmDmaBuf,
        shared_secret: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Generate an ML-KEM (FIPS 203) key pair.
    ///
    /// Returns both the 64-byte `(d ‖ z)` seed pair and the expanded key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `kind` — parameter set as a seed-kind [`HsmVaultKeyKind`]
    ///   (`MlKem512Seed` / `MlKem768Seed` / `MlKem1024Seed`).
    /// - `seed` — output; must be exactly 64 bytes.  Filled from the
    ///   device's entropy source, for the same reason as ML-DSA's seed.
    /// - `pub_key` — output; the encapsulation key, exactly the parameter
    ///   set's length (800 / 1184 / 1568).
    /// - `sec_key` — output; expanded decapsulation key (1632 / 2400 / 3168 bytes).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `seed`, `pub_key`, and `sec_key` populated.
    /// - `Err(HsmError::InvalidArg)` — bad kind or buffer length.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    async fn mlkem_gen_key(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        seed: &mut HsmDmaBuf,
        pub_key: &mut HsmDmaBuf,
        sec_key: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Encapsulate to an ML-KEM public key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `kind` — parameter set as a seed-kind [`HsmVaultKeyKind`].
    /// - `pub_key` — the encapsulation key, exactly the parameter set's
    ///   length.
    /// - `ciphertext` — output, exactly the parameter set's ciphertext
    ///   length (768 / 1088 / 1568).
    /// - `shared_secret` — output, 32 bytes.  This is key material: the
    ///   caller is expected to mask it before it leaves the device.
    ///
    /// The randomness encapsulation needs is drawn by the implementation
    /// from the device's entropy source, for the same reason as the seeds.
    async fn mlkem_encaps(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        pub_key: &HsmDmaBuf,
        ciphertext: &mut HsmDmaBuf,
        shared_secret: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Decapsulate an ML-KEM ciphertext.
    ///
    /// The caller supplies an expanded decapsulation key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `kind` — parameter set as a seed-kind [`HsmVaultKeyKind`].
    /// - `sec_key` — expanded decapsulation key (1632 / 2400 / 3168 bytes).
    /// - `ciphertext` — exactly the parameter set's ciphertext length.
    /// - `shared_secret` — output, 32 bytes.  Key material; the caller is
    ///   expected to mask it before it leaves the device.
    ///
    /// ML-KEM decapsulation never fails: a ciphertext that does not decrypt
    /// yields an implicit-rejection secret rather than an error, so there
    /// is no boolean here.
    async fn mlkem_decaps(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        sec_key: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        shared_secret: &mut HsmDmaBuf,
    ) -> HsmResult<()>;
}
