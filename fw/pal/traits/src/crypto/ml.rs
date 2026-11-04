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

/// Length of an ML-KEM shared secret (FIPS 203), the same for every
/// parameter set.
pub const MLKEM_SHARED_SECRET_LEN: usize = 32;

/// ML-DSA parameter set (FIPS 204).
///
/// The PAL's own selector, as [`HsmRsaKey`] is for RSA: ML-DSA operations
/// take it rather than a vault key kind, and callers map a stored key's
/// kind onto it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMlDsaParamSet {
    /// ML-DSA-44.
    MlDsa44,

    /// ML-DSA-65.
    MlDsa65,

    /// ML-DSA-87.
    MlDsa87,
}

impl HsmMlDsaParamSet {
    /// Encoded public key length: 1312 / 1952 / 2592 bytes.
    pub const fn pub_key_len(&self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Expanded secret key length: 2560 / 4032 / 4896 bytes.
    pub const fn sec_key_len(&self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }

    /// Signature length: 2420 / 3309 / 4627 bytes.
    pub const fn sig_len(&self) -> usize {
        match self {
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    /// The parameter set whose public key is `len` bytes long, if any.  The
    /// three lengths are distinct, so this is unambiguous.
    pub const fn from_pub_key_len(len: usize) -> Option<Self> {
        match len {
            1312 => Some(Self::MlDsa44),
            1952 => Some(Self::MlDsa65),
            2592 => Some(Self::MlDsa87),
            _ => None,
        }
    }
}

/// ML-KEM parameter set (FIPS 203).
///
/// The PAL's own selector, as [`HsmRsaKey`] is for RSA: ML-KEM operations
/// take it rather than a vault key kind, and callers map a stored key's
/// kind onto it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMlKemParamSet {
    /// ML-KEM-512.
    MlKem512,

    /// ML-KEM-768.
    MlKem768,

    /// ML-KEM-1024.
    MlKem1024,
}

impl HsmMlKemParamSet {
    /// Encapsulation (public) key length: 800 / 1184 / 1568 bytes.
    pub const fn pub_key_len(&self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Expanded decapsulation (private) key length: 1632 / 2400 / 3168
    /// bytes.
    pub const fn sec_key_len(&self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Ciphertext length: 768 / 1088 / 1568 bytes.
    pub const fn ciphertext_len(&self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// The parameter set whose encapsulation key is `len` bytes long, if
    /// any.  The three lengths are distinct, so this is unambiguous.
    pub const fn from_pub_key_len(len: usize) -> Option<Self> {
        match len {
            800 => Some(Self::MlKem512),
            1184 => Some(Self::MlKem768),
            1568 => Some(Self::MlKem1024),
            _ => None,
        }
    }
}

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

/// How an ML-DSA signature gets its per-signature randomness `rnd`
/// (FIPS 204, Algorithm 2): drawn fresh for a hedged signature, or fixed at
/// `{0}^32` for a deterministic one, which always yields the same signature
/// for the same key and input.
///
/// Values and meanings follow PKCS#11's `CK_HEDGE_TYPE`.  Only signing takes
/// one; verification is the same for both variants.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMlDsaHedge {
    /// Hedged or deterministic, as the implementation chooses
    /// (`CKH_HEDGE_PREFERRED`).
    Preferred = 0,

    /// Hedged, or fail (`CKH_HEDGE_REQUIRED`).
    Required = 1,

    /// Deterministic, or fail (`CKH_DETERMINISTIC_REQUIRED`).
    Deterministic = 2,
}

/// Asynchronous ML-DSA signature operations.
///
/// Async because every method is a round trip to an FP core: the
/// implementation yields while the request is in flight.
///
/// Every signing and verification method takes an [`HsmMlDsaMsgType`]
/// saying how its `message` is to be read; the signing methods also take an
/// [`HsmMlDsaHedge`] saying how the signature is randomized.
pub trait HsmMlDsa {
    /// Replace the prefix of a key/signature region with an ML-DSA signature.
    ///
    /// The expanded secret key occupies the final parameter-set key-length bytes
    /// of `key_signature`; any preceding bytes are scratch. The signature is
    /// written at the start of this region after all inputs have been consumed.
    /// `message` and `ctx` are disjoint from it. The caller wipes private bytes
    /// not replaced by the signature.
    ///
    /// `msg_type` says how `message` is to be read and `hedge` how the
    /// signature is randomized; see [`mldsa_sign`](Self::mldsa_sign) for the
    /// errors.
    #[allow(clippy::too_many_arguments)]
    async fn mldsa_sign_in_place(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
        key_signature: &mut HsmDmaBuf,
        msg_type: HsmMlDsaMsgType,
        hedge: HsmMlDsaHedge,
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
    /// - `param_set` — the ML-DSA parameter set.
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
    /// - `Err(HsmError::InvalidArg)` — an output buffer is the wrong length.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    async fn mldsa_gen_key(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
        seed: &mut HsmDmaBuf,
        pub_key: &mut HsmDmaBuf,
        sec_key: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Sign a message with an expanded secret key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param_set` — the ML-DSA parameter set.
    /// - `sec_key` — expanded secret key (2560 / 4032 / 4896 bytes).
    /// - `msg_type` — how `message` is to be read.
    /// - `hedge` — whether the signature is hedged or deterministic.
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
    /// - `Err(HsmError::InvalidArg)` — bad buffer length, or a
    ///   `message`/`ctx` not valid for `msg_type`.
    /// - `Err(HsmError::UnsupportedCmd)` — `msg_type` is a pre-hash type,
    ///   or the implementation cannot sign as `hedge` requires.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    #[allow(clippy::too_many_arguments)]
    async fn mldsa_sign(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
        sec_key: &HsmDmaBuf,
        msg_type: HsmMlDsaMsgType,
        hedge: HsmMlDsaHedge,
        message: &HsmDmaBuf,
        ctx: &HsmDmaBuf,
        signature: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Verify a signature under a public key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param_set` — the ML-DSA parameter set.
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
    /// - `Err(HsmError::InvalidArg)` — bad buffer length, or a
    ///   `message`/`ctx` not valid for `msg_type`.
    /// - `Err(HsmError::UnsupportedCmd)` — `msg_type` is a pre-hash type.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    #[allow(clippy::too_many_arguments)]
    async fn mldsa_verify(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlDsaParamSet,
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
        param_set: HsmMlKemParamSet,
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
    /// - `param_set` — the ML-KEM parameter set.
    /// - `seed` — output; must be exactly 64 bytes.  Filled from the
    ///   device's entropy source, for the same reason as ML-DSA's seed.
    /// - `output` — output, the encapsulation key followed by the expanded
    ///   decapsulation key, exactly 2432 / 3584 / 4736 bytes for
    ///   ML-KEM-512 / 768 / 1024:
    ///
    ///   | Offset | Length | Field |
    ///   |---|---|---|
    ///   | 0 | 800 / 1184 / 1568 | Encapsulation (public) key |
    ///   | 800 / 1184 / 1568 | 1632 / 2400 / 3168 | Expanded decapsulation (private) key |
    ///
    ///   The decapsulation key is private key material.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `seed` and `output` populated.
    /// - `Err(HsmError::InvalidArg)` — `seed` not 64 bytes, or
    ///   `output` not exactly the two key lengths combined.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    async fn mlkem_gen_key(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        seed: &mut HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Encapsulate to an ML-KEM public key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param_set` — the ML-KEM parameter set.
    /// - `pub_key` — the encapsulation key, exactly the parameter set's
    ///   length.
    /// - `output` — output, the shared secret followed by the ciphertext,
    ///   exactly 800 / 1120 / 1600 bytes for ML-KEM-512 / 768 / 1024:
    ///
    ///   | Offset | Length | Field |
    ///   |---|---|---|
    ///   | 0 | [`MLKEM_SHARED_SECRET_LEN`] (32) | Shared secret |
    ///   | 32 | 768 / 1088 / 1568 | Ciphertext |
    ///
    ///   The shared secret is key material: the caller is expected to mask
    ///   it before it leaves the device.
    ///
    /// The randomness encapsulation needs is drawn by the implementation
    /// from the device's entropy source, for the same reason as the seeds.
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `output` populated.
    /// - `Err(HsmError::InvalidArg)` — `output` not exactly
    ///   the shared secret and ciphertext lengths combined.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    async fn mlkem_encaps(
        &self,
        io: &impl HsmIo,
        param_set: HsmMlKemParamSet,
        pub_key: &HsmDmaBuf,
        output: &mut HsmDmaBuf,
    ) -> HsmResult<()>;

    /// Decapsulate an ML-KEM ciphertext.
    ///
    /// The caller supplies an expanded decapsulation key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param_set` — the ML-KEM parameter set.
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
        param_set: HsmMlKemParamSet,
        sec_key: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        shared_secret: &mut HsmDmaBuf,
    ) -> HsmResult<()>;
}
