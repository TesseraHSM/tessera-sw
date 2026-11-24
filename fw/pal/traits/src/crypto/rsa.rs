// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA cryptographic operations trait for the HSM PAL.
//!
//! Defines [`HsmRsaPct`] and the [`HsmRsa`] trait that PAL implementations
//! use to expose RSA key generation and modular exponentiation.
//!
//! On Cortex-M7 hardware this would delegate to the PKA (Public Key
//! Accelerator) engine. On the standard (host-native) PAL it would use
//! OpenSSL's RSA primitives.
//!
//! ## Key representation
//!
//! All key parameters are plain `&[u8]` byte slices containing the raw
//! key material. Each PAL implementation is responsible for parsing
//! them into whatever internal representation it needs.
//!
//! ## Key buffer alignment
//!
//! Hardware engines require RSA key material to start
//! at a **4-byte aligned** address, with **`roundup8(len)`** bytes of
//! readable memory behind it. Callers must uphold this; implementations
//! may rely on it. PAL allocations are 4-byte aligned, and keys unmasked
//! in place from a masked-key blob meet both requirements (see the
//! masked-key format in `tsra_fw_core_crypto_key_masking`).
//!
//! ## Modular exponentiation
//!
//! RSA signing and decryption are expressed as private-key modular
//! exponentiation (`mod_exp_priv`), while encryption and verification
//! use public-key modular exponentiation (`mod_exp_pub`). This matches
//! the hardware PKA register model where the engine performs a single
//! `base^exp mod n` operation regardless of the higher-level use case.
//!
//! ## Output buffer convention
//!
//! All methods take mandatory `&mut [u8]` output buffers. The caller is
//! responsible for providing buffers of the correct size (key size in
//! bytes for RSA operations).

use super::*;

// ── RSA key size ───────────────────────────────────────────────────

/// RSA key type: modulus size, public/private, and CRT format.
///
/// Each variant encodes three properties:
/// - **Modulus size** — 2048, 3072, or 4096 bits.
/// - **Key role** — public (`Pub`) or private (`Priv`/`CrtPriv`).
/// - **Private key format** — standard (`Priv`) or Chinese Remainder
///   Theorem (`CrtPriv`). CRT is irrelevant for public keys.
///
/// Use [`pub_variant`](Self::pub_variant) to obtain the corresponding
/// public key variant from any private variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmRsaKey {
    /// RSA-2048 public key.
    Rsa2048Pub,

    /// RSA-2048 non-CRT private key.
    Rsa2048Priv,

    /// RSA-2048 CRT private key.
    Rsa2048CrtPriv,

    /// RSA-3072 public key.
    Rsa3072Pub,

    /// RSA-3072 non-CRT private key.
    Rsa3072Priv,

    /// RSA-3072 CRT private key.
    Rsa3072CrtPriv,

    /// RSA-4096 public key.
    Rsa4096Pub,

    /// RSA-4096 non-CRT private key.
    Rsa4096Priv,

    /// RSA-4096 CRT private key.
    Rsa4096CrtPriv,
}

impl HsmRsaKey {
    /// Modulus size in bytes (`k`).
    pub const fn modulus_len(&self) -> usize {
        match self {
            Self::Rsa2048Pub | Self::Rsa2048Priv | Self::Rsa2048CrtPriv => 256,
            Self::Rsa3072Pub | Self::Rsa3072Priv | Self::Rsa3072CrtPriv => 384,
            Self::Rsa4096Pub | Self::Rsa4096Priv | Self::Rsa4096CrtPriv => 512,
        }
    }

    /// Whether this is a public key variant.
    pub const fn is_public(&self) -> bool {
        matches!(self, Self::Rsa2048Pub | Self::Rsa3072Pub | Self::Rsa4096Pub)
    }

    /// Whether this is a private key variant (CRT or non-CRT).
    pub const fn is_private(&self) -> bool {
        !self.is_public()
    }

    /// Whether this variant uses CRT (Chinese Remainder Theorem) format.
    pub const fn is_crt(&self) -> bool {
        matches!(
            self,
            Self::Rsa2048CrtPriv | Self::Rsa3072CrtPriv | Self::Rsa4096CrtPriv
        )
    }

    /// Return the corresponding public key variant.
    ///
    /// Maps any private variant to the public variant of the same
    /// modulus size. Public variants map to themselves.
    pub const fn pub_variant(&self) -> Self {
        match self {
            Self::Rsa2048Pub | Self::Rsa2048Priv | Self::Rsa2048CrtPriv => Self::Rsa2048Pub,
            Self::Rsa3072Pub | Self::Rsa3072Priv | Self::Rsa3072CrtPriv => Self::Rsa3072Pub,
            Self::Rsa4096Pub | Self::Rsa4096Priv | Self::Rsa4096CrtPriv => Self::Rsa4096Pub,
        }
    }

    /// Maximum plaintext length for PKCS#1 v1.5 encryption: `k - 11`.
    pub const fn max_pkcs1_message(&self) -> usize {
        self.modulus_len() - 11
    }

    /// Maximum plaintext length for OAEP encryption: `k - 2*hLen - 2`, or 0
    /// if `algo`'s digest is too long for the modulus (e.g. a long SHAKE
    /// output, which OAEP does not support anyway).
    pub const fn max_oaep_message(&self, algo: HsmHashAlgo) -> usize {
        self.modulus_len().saturating_sub(2 * algo.digest_len() + 2)
    }

    /// Encoded PKCS#1 v1.5 block length, excluding backend scratch.
    /// The PAL manages temporary DMA scratch in internal allocator scopes.
    pub const fn pkcs1_work_len(&self) -> usize {
        self.modulus_len()
    }

    /// OAEP encoding and MGF storage estimate, excluding backend scratch.
    /// The PAL manages temporary DMA scratch in internal allocator scopes.
    pub const fn oaep_work_len(&self, algo: HsmHashAlgo) -> usize {
        let k = self.modulus_len();
        let h_len = algo.digest_len();
        let db_len = k.saturating_sub(h_len + 1);
        k + algo.mgf1_state_len(db_len)
    }

    /// PSS encoding and MGF storage estimate, excluding backend scratch.
    /// The PAL manages temporary DMA scratch in internal allocator scopes.
    pub const fn pss_work_len(&self, algo: HsmHashAlgo) -> usize {
        let k = self.modulus_len();
        let h_len = algo.digest_len();
        k + algo.mgf1_state_len(h_len)
    }
}

/// Pairwise Consistency Test (PCT) mode for RSA key generation and key
/// import.
///
/// FIPS 140-3 requires a PCT after key generation and key import to
/// verify the key pair is functional. The test mode determines which
/// operation is used for verification.
pub enum HsmRsaPct {
    /// No PCT — skip the consistency test.
    None,

    /// Sign-verify PCT: sign a test message with the private key and
    /// verify it with the public key.
    SignVerify,

    /// Encrypt-decrypt PCT: encrypt test data with the public key and
    /// verify the private key recovers the original.
    EncryptDecrypt,
}

/// Asynchronous RSA operations trait.
///
/// PAL implementations provide this to the core for RSA key generation
/// and modular exponentiation. The async signatures allow hardware-backed
/// implementations to yield while the PKA engine processes operations.
pub trait HsmRsa: HsmIoTypes + HsmCryptoOrder {
    /// Generate an RSA key pair.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector (2048 / 3072 / 4096).
    /// - `pct` — Pairwise Consistency Test selector.  When not
    ///   [`HsmRsaPct::None`], a sign / verify or encrypt / decrypt
    ///   round-trip is performed (FIPS 140-3 requirement).
    /// - `out` — `None` to query private/public output capacity bounds without
    ///   generating a key or running a PCT; `Some((priv_key, pub_key))` to
    ///   generate into caller buffers. Serialization is backend-defined.
    ///   Temporary DMA scratch is scoped internally.
    ///
    /// # Returns
    ///
    /// - `Ok((priv_len, pub_len))` — capacity bounds in query mode;
    ///   otherwise actual byte counts written. Output tails are untouched.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError)` — PKA / RNG failure or PCT failed (the key
    ///   pair is rejected).
    async fn rsa_gen_keypair(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        pct: HsmRsaPct,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)>;

    /// Private-key modular exponentiation: `x = y^d mod n`.
    ///
    /// Used by RSA decryption and signing primitives.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `key` — RSA private key in PAL-defined serialization
    ///   matching `key_size.is_crt()`.
    /// - `y` — input integer; must be exactly
    ///   `key_size.modulus_len()` bytes, in operand order
    ///   ([`HsmCryptoOrder::BYTE_ORDER`]), and must satisfy
    ///   `1 < y < n - 1`, where `n` is the private key's modulus.
    /// - `out` — `None` to query the modulus length without exponentiation
    ///   or DMA scratch allocation; `Some(x)` to write the operand-order result.
    ///   The buffer must fit the modulus; any tail is left untouched.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required capacity in query mode; otherwise bytes written.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch or `y` does
    ///   not satisfy `1 < y < n - 1`.
    /// - `Err(HsmError)` — PKA driver failure.
    async fn mod_exp_priv(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        key: &HsmDmaBuf,
        y: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Compute the private primitive, replacing the input integer with its result.
    ///
    /// `key_type` selects the modulus size and CRT/non-CRT layout.
    /// `y_x` is exactly `key_type.modulus_len()` bytes and disjoint from `key`.
    /// The implementation must consume the input before publishing the result.
    /// Operand sizes, byte order, and input bounds match [`Self::mod_exp_priv`].
    /// This input/output buffer is an explicit exception to output-size queries.
    async fn mod_exp_priv_in_place(
        &self,
        io: &Self::Io,
        key_type: HsmRsaKey,
        key: &HsmDmaBuf,
        y_x: &mut HsmDmaBuf,
    ) -> Result<(), HsmError>;

    /// Public-key modular exponentiation: `y = x^e mod n`.
    ///
    /// Used by RSA encryption and signature-verification primitives.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `key` — RSA public key as `n || e`, where the modulus is exactly
    ///   `key_size.modulus_len()` bytes and the exponent is exactly four
    ///   bytes. Each integer is encoded independently in operand order
    ///   ([`HsmCryptoOrder::BYTE_ORDER`]); this is not DER.
    /// - `x` — input integer; must be exactly
    ///   `key_size.modulus_len()` bytes, in operand order
    ///   ([`HsmCryptoOrder::BYTE_ORDER`]) and satisfy `0 <= x < n`.
    /// - `out` — `None` to query the modulus length without exponentiation
    ///   or DMA scratch allocation; `Some(y)` to write the operand-order result.
    ///   The buffer must fit the modulus; any tail is left untouched.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required capacity in query mode; otherwise bytes written.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError)` — PKA driver failure.
    async fn mod_exp_pub(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        key: &HsmDmaBuf,
        x: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Derive the raw operand-order public key (`n || e`) from a
    /// vault-stored RSA private key.
    ///
    /// Used to recover the public key of a vault-stored private key
    /// (e.g. the partition unwrapping key) without persisting a
    /// separate copy.
    ///
    /// `priv_key` is in the PAL's own vault representation — raw key
    /// material on real PKA hardware, the crypto crate's HSM byte layout
    /// in the std/OpenSSL PAL — and this method converts it into the
    /// modulus followed by a fixed 4-byte exponent, both in operand order
    /// ([`HsmCryptoOrder::BYTE_ORDER`]).  The PAL owns the whole
    /// vault-format → operand-format conversion.
    ///
    /// Follows the query/alloc/use convention: pass `pub_out = None` to
    /// query the wire length the caller must allocate, then
    /// `pub_out = Some(buf)` to serialize.
    ///
    /// # Returns
    /// - `Ok(len)` — wire byte length (`modulus_len + 4`); in `Some`
    ///   mode those bytes are written into `pub_out`.
    /// - `Err(HsmError::InvalidArg)` — `priv_key` is not valid vault
    ///   format.
    /// - `Err(HsmError::RsaInvalidKeyLength)` — `pub_out` is too small
    ///   or the derived public-key components do not fit the wire
    ///   format.
    /// - `Err(HsmError::RsaGenerateError)` — deriving or reading the
    ///   public key failed for another reason.
    fn rsa_priv_pub_key(
        &self,
        io: &Self::Io,
        priv_key: &HsmDmaBuf,
        pub_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Convert a DER-encoded RSA private key (recovered from a
    /// `CKM_RSA_AES_KEY_WRAP` unwrap) into the PAL's vault representation,
    /// returning a borrow of the vault bytes plus the modulus length used to
    /// classify the vault key kind (256 / 384 / 512 for RSA-2048 / 3072 / 4096).
    ///
    /// The vault representation is PAL-defined and **layout-dependent on
    /// `crt`**, and each PAL chooses where the vault bytes live — so no output
    /// buffer is threaded through the caller:
    /// - When the vault layout is **no larger** than the source DER, the PAL
    ///   converts **in place** and returns a prefix of `der`. This is the
    ///   common case: it reuses the large recovered RSA material (up to
    ///   ~2.3 KB for RSA-4096) as the vault buffer rather than duplicating it,
    ///   important under the PAL's fixed per-slot DMA budget. Both std/OpenSSL
    ///   layouts (non-CRT `n|e|p|q`, CRT `n|e|d|p|q|dp|dq|qinv`) and the Uno
    ///   non-CRT PKA form (`d|n|e`) are smaller than the DER.
    /// - When the vault operand is **larger** than the DER (e.g. the Uno CRT
    ///   PKA form `p|q|dp|dq|n|n1q|n2p|e`, `5k+4` bytes, whose derived
    ///   `n1q`/`n2p` need async PKA arithmetic), the PAL allocates its own
    ///   buffer and returns a borrow of it.
    ///
    /// This mutable input is an explicit in-place exception to output-size queries.
    ///
    /// The implementation is responsible for scrubbing any plaintext key
    /// material it leaves behind (e.g. the recovered DER when it is not reused
    /// as the vault buffer).
    ///
    /// A PAL that checks imported keys runs the pairwise consistency test
    /// that `pct` selects on the converted key pair before it returns.
    ///
    /// # Returns
    /// - `Ok((vault, modulus_len))` — `vault` holds the vault-format private key.
    /// - `Err(HsmError::InvalidArg)` — `der` is not a valid RSA private key.
    /// - `Err(HsmError::PctValidationRsaUnwrapRsaKeyFailed)` — the key pair
    ///   failed its PCT.
    async fn rsa_priv_der_to_vault<'a>(
        &'a self,
        io: &Self::Io,
        der: &'a mut HsmDmaBuf,
        crt: bool,
        pct: HsmRsaPct,
    ) -> HsmResult<(&'a HsmDmaBuf, usize)>;

    /// PKCS#1 v1.5 encrypt (EME-PKCS1-v1_5).
    ///
    /// Pads `message` with random non-zero bytes per RFC 8017 §7.2.1
    /// and encrypts under `pub_key`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `pub_key` — RSA public key.
    /// - `message` — plaintext; must satisfy
    ///   `message.len() <= key_size.max_pkcs1_message()`.
    /// - `out` — `None` to validate and query the ciphertext length without
    ///   scratch allocation, RNG or PKA operations; `Some(output)` to encrypt.
    ///   Temporary DMA scratch, including nested operations, is scoped internally.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required output capacity in query mode;
    ///   otherwise `output[..len]` holds the ciphertext.
    /// - `Err(HsmError::InvalidArg)` — message too long or buffer
    ///   too small.
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — RNG / PKA failure.
    async fn rsa_pkcs1_encrypt(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        pub_key: &HsmDmaBuf,
        message: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// PKCS#1 v1.5 decrypt (EME-PKCS1-v1_5).
    ///
    /// Decrypts `ciphertext` under `priv_key` and strips PKCS#1 v1.5
    /// padding.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `priv_key` — RSA private key.
    /// - `ciphertext` — must be exactly
    ///   `key_size.modulus_len()` bytes.
    /// - `out` — `None` to validate and query plaintext capacity without
    ///   scratch allocation or decryption; `Some(output)` to
    ///   decrypt. The capacity is an upper bound, not a recovered length.
    ///   A smaller output is accepted if the recovered plaintext fits.
    ///   Temporary DMA scratch is scoped internally.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — capacity bound in query mode;
    ///   otherwise the recovered plaintext length, with `output[..len]` valid.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::RsaPkcs1DecryptFailed)` — padding check
    ///   failed (likely wrong key or tampered ciphertext).
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — PKA failure.
    async fn rsa_pkcs1_decrypt(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        priv_key: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// PKCS#1 v1.5 sign (EMSA-PKCS1-v1_5, pre-hashed).
    ///
    /// Builds DigestInfo from `message_hash`, applies EMSA padding,
    /// and signs.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — hash algorithm whose OID is embedded in
    ///   DigestInfo.
    /// - `priv_key` — RSA private key.
    /// - `message_hash` — pre-computed digest;
    ///   `algo.digest_len()` bytes.
    /// - `out` — `None` to validate and query signature length without
    ///   scratch allocation or signing; `Some(signature)` to sign.
    ///   Temporary DMA scratch is scoped internally.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required output capacity in query mode;
    ///   otherwise `signature[..len]` is populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_pkcs1_sign(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        message_hash: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// PKCS#1 v1.5 verify (EMSA-PKCS1-v1_5, pre-hashed).
    ///
    /// Verifies `signature` against `message_hash` under `pub_key`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — hash algorithm whose OID is expected in
    ///   DigestInfo.
    /// - `pub_key` — RSA public key.
    /// - `message_hash` — pre-computed digest.
    /// - `signature` — signature to verify;
    ///   `key_size.modulus_len()` bytes.
    ///
    /// Temporary DMA scratch is allocated and reclaimed in an internal scope.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — signature valid.
    /// - `Ok(false)` — signature does not verify.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — PKA failure.
    ///
    /// `pub_key` is `n || e(4)` and `signature` is modulus-sized, both in
    /// operand order. `message_hash` is a standard digest byte string.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_pkcs1_verify(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        message_hash: &HsmDmaBuf,
        signature: &HsmDmaBuf,
    ) -> HsmResult<bool>;

    /// OAEP encrypt (EME-OAEP, RFC 8017 §7.1.1).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — OAEP hash (label hash + MGF1).
    /// - `pub_key` — RSA public key.
    /// - `message` — plaintext; must satisfy `message.len() <=
    ///   key_size.max_oaep_message(algo)`.
    /// - `label` — OAEP label; `&[]` for the default empty label.
    /// - `out` — `None` to validate and query ciphertext length without
    ///   scratch allocation or encryption; `Some(output)` to encrypt.
    ///   Temporary DMA scratch is scoped internally.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required output capacity in query mode;
    ///   otherwise `output[..len]` holds the ciphertext.
    /// - `Err(HsmError::InvalidArg)` — message too long or buffer
    ///   too small.
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — RNG / SHA / PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_oaep_encrypt(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        message: &HsmDmaBuf,
        label: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// OAEP decrypt (EME-OAEP, RFC 8017 §7.1.2).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — OAEP hash.
    /// - `priv_key` — RSA private key.
    /// - `ciphertext` — must be exactly
    ///   `key_size.modulus_len()` bytes.
    /// - `label` — OAEP label; must equal the encryption-time
    ///   label.
    /// - `out` — `None` to validate and query plaintext capacity without
    ///   scratch allocation or decryption; `Some(output)` to
    ///   decrypt. The capacity is an upper bound. An output smaller than
    ///   the bound is accepted if the recovered plaintext fits. A recovered
    ///   plaintext longer than `output` fails with
    ///   [`HsmError::RsaInvalidKeyLength`], so a caller that accepts only
    ///   a bounded plaintext (e.g. a small KEK) may size `output` to that
    ///   bound.
    ///   Temporary DMA scratch is scoped internally.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — capacity bound in query mode;
    ///   otherwise the recovered plaintext length, with `output[..len]` valid.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::RsaOaepDecryptFailed)` — OAEP unmasking
    ///   detected tampering or label mismatch.
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — SHA / PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_oaep_decrypt(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        ciphertext: &HsmDmaBuf,
        label: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// PSS sign (EMSA-PSS, RFC 8017 §9.1.1, pre-hashed).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — PSS hash (H and MGF1).
    /// - `priv_key` — RSA private key.
    /// - `message_hash` — pre-computed digest;
    ///   `algo.digest_len()` bytes.
    /// - `salt_len` — PSS salt length in bytes.
    /// - `out` — `None` to validate and query signature length without
    ///   scratch allocation, RNG or signing; `Some(signature)` to sign.
    ///   Temporary DMA scratch is scoped internally.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required output capacity in query mode;
    ///   otherwise `signature[..len]` is populated.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch or
    ///   `salt_len` exceeds the EMSA-PSS limit.
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — RNG / SHA / PKA failure.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_pss_sign(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        message_hash: &HsmDmaBuf,
        salt_len: usize,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// PSS verify (EMSA-PSS, RFC 8017 §9.1.2, pre-hashed).
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `key_size` — modulus size selector.
    /// - `algo` — PSS hash.
    /// - `pub_key` — RSA public key.
    /// - `message_hash` — pre-computed digest;
    ///   `algo.digest_len()` bytes.
    /// - `salt_len` — expected PSS salt length in bytes.
    /// - `signature` — signature to verify;
    ///   `key_size.modulus_len()` bytes.
    ///
    /// Temporary DMA scratch is allocated and reclaimed in an internal scope.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — signature valid.
    /// - `Ok(false)` — signature does not verify.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch.
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — SHA / PKA failure.
    ///
    /// `pub_key` is `n || e(4)` and `signature` is modulus-sized, both in
    /// operand order. `message_hash` is a standard digest byte string.
    #[allow(clippy::too_many_arguments)]
    async fn rsa_pss_verify(
        &self,
        io: &Self::Io,
        key_size: HsmRsaKey,
        algo: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        message_hash: &HsmDmaBuf,
        salt_len: usize,
        signature: &HsmDmaBuf,
    ) -> HsmResult<bool>;
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU16;

    use super::HsmHashAlgo;
    use super::HsmRsaKey;

    /// A SHAKE output longer than the modulus must not underflow the OAEP
    /// sizes: OAEP rejects SHAKE, but these helpers run first.
    #[test]
    fn oaep_sizes_do_not_underflow_for_long_shake() {
        let shake = HsmHashAlgo::Shake256(NonZeroU16::new(300).expect("nonzero"));
        assert_eq!(HsmRsaKey::Rsa2048Pub.max_oaep_message(shake), 0);
        let _ = HsmRsaKey::Rsa2048Pub.oaep_work_len(shake);
        assert_eq!(
            HsmRsaKey::Rsa2048Pub.max_oaep_message(HsmHashAlgo::Sha256),
            256 - 2 * 32 - 2
        );
    }
}
