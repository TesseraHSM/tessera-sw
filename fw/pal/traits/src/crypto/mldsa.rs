// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA (FIPS 204) operations for the HSM PAL.
//!
//! Unlike the other crypto families in this module, ML-DSA is not
//! computed on the HSM core.  The PAL dispatches it to a fastpath (FP)
//! core over IPC and returns the result, so implementations are thin
//! forwarders rather than algorithm code.
//!
//! Only key generation exists today, as the first step of bringing the
//! HSM → FP path up; sign and verify follow.

use super::*;

/// Asynchronous ML-DSA operations trait.
///
/// Async because every method is a round trip to an FP core: the
/// implementation yields while the request is in flight.
pub trait HsmMlDsa {
    /// Generate an ML-DSA keypair.
    ///
    /// The private half is returned as the compact 32-byte `xi` seed
    /// rather than an expanded secret key, matching what the TBOR wire
    /// carries.
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
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `seed` and `pub_key` populated.
    /// - `Err(HsmError::InvalidArg)` — `kind` is not a seed kind, or an
    ///   output buffer is the wrong length.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    async fn mldsa_gen_key(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
    ) -> HsmResult<()>;

    /// Sign a message under a key given by its seed.
    ///
    /// The caller supplies the 32-byte seed rather than an expanded secret
    /// key, matching what the TBOR wire carries; the implementation
    /// re-derives the key pair.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `kind` — parameter set as a seed-kind [`HsmVaultKeyKind`].
    /// - `seed` — the 32-byte seed recovered from the caller's masked key.
    /// - `message` — the message to sign.
    /// - `ctx` — FIPS 204 context string, up to 255 bytes.
    /// - `signature` — output; must be exactly the parameter set's
    ///   signature length (2420 / 3309 / 4627).
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `signature` populated.
    /// - `Err(HsmError::InvalidArg)` — bad kind or buffer length.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    async fn mldsa_sign(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        sec_key: &[u8],
        message: &[u8],
        ctx: &[u8],
        signature: &mut [u8],
    ) -> HsmResult<()>;

    /// Verify a signature under a public key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `kind` — parameter set as a seed-kind [`HsmVaultKeyKind`].
    /// - `pub_key` — encoded public key, exactly the parameter set's length.
    /// - `message`, `ctx` — the signed message and its FIPS 204 context.
    /// - `signature` — exactly the parameter set's signature length.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` / `Ok(false)` — the signature verified, or did not.
    ///   An invalid signature is an ordinary outcome, not an error, so it
    ///   cannot be conflated with a transport fault.
    /// - `Err(HsmError::InvalidArg)` — bad kind or buffer length.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    async fn mldsa_verify(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        pub_key: &[u8],
        message: &[u8],
        ctx: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool>;

    /// Generate an ML-KEM (FIPS 203) key pair.
    ///
    /// The private half is returned as the compact 64-byte `(d ‖ z)` seed
    /// pair rather than an expanded decapsulation key, matching what the
    /// TBOR wire carries.
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
    ///
    /// # Returns
    ///
    /// - `Ok(())` — `seed` and `pub_key` populated.
    /// - `Err(HsmError::InvalidArg)` — bad kind or buffer length.
    /// - `Err(HsmError)` — propagated from the FP offload path.
    async fn mlkem_gen_key(
        &self,
        io: &impl HsmIo,
        kind: HsmVaultKeyKind,
        seed: &mut [u8],
        pub_key: &mut [u8],
        sec_key: &mut [u8],
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
        pub_key: &[u8],
        ciphertext: &mut [u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()>;

    /// Decapsulate an ML-KEM ciphertext.
    ///
    /// The caller supplies the 64-byte `(d ‖ z)` seed pair rather than an
    /// expanded decapsulation key, matching what the TBOR wire carries; the
    /// implementation re-derives the key pair.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `kind` — parameter set as a seed-kind [`HsmVaultKeyKind`].
    /// - `seed` — the 64-byte seed pair recovered from the caller's masked
    ///   key.
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
        sec_key: &[u8],
        ciphertext: &[u8],
        shared_secret: &mut [u8],
    ) -> HsmResult<()>;
}
