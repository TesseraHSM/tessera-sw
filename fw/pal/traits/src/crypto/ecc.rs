// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Elliptic Curve Cryptography (ECC) trait for the HSM PAL.
//!
//! Defines [`EccCurve`] and the [`HsmEcc`] trait that PAL implementations
//! use to expose ECC key generation, raw EC sign/verify, and ECDSA
//! sign/verify operations.
//!
//! **Status**: The trait is defined but not yet included in the
//! [`HsmCrypto`] supertrait bound — no PAL implements it yet. It will
//! be wired in when the `EccSign`, `EccGenerateKeyPair`, and
//! `EcdhKeyExchange` DDI handlers are implemented in `fw/core`.
//!
//! ## Output buffer convention
//!
//! All methods that produce output take mandatory `&mut` parameters.
//! The caller is responsible for providing buffers of the correct size.
//! Use [`EccCurve::priv_key_len`], [`EccCurve::pub_key_len`],
//! [`EccCurve::sig_len`], and [`EccCurve::secret_len`] to determine
//! the required sizes.
//!
//! ## Private-key encoding
//!
//! Private keys are opaque, PAL-specific HSM/vault encodings. Their buffer
//! lengths use [`HsmEccCurve::wire_priv_key_len`], but their byte order and
//! padding placement are not specified by [`HsmCryptoOrder::BYTE_ORDER`]
//! or the value-first operand-lane rule:
//!
//! - std Uno and std Duo use big-endian scalars with leading zero padding.
//!   A std Duo P-521 key is `zeros(6) || d_be(66)`, not
//!   `d_be(66) || zeros(6)`.
//! - Hardware Uno uses little-endian scalars with trailing zero padding:
//!   `d_le(66) || zeros(2)` for P-521.
//!
//! Pass generated or imported HSM-format keys back to the same PAL unchanged.
//! Use [`HsmEcc::ecc_priv_to_vault`] and [`HsmEcc::ecc_vault_to_priv`] to
//! convert between a canonical big-endian scalar and the PAL's private-key
//! encoding; do not apply generic operand byte-order conversions to keys.
//!
//! ## ECDSA operands
//!
//! **`ecc_sign` / `ecc_sign_in_place` / `ecc_verify`** take a pre-computed
//! message digest; the caller hashes the message. Each takes one packed
//! input of coordinate lanes followed by a digest lane, as the hardware
//! engines read it:
//!
//! - sign: `k ‖ digest` ([`HsmEccCurve::ecdsa_sign_input_len`]);
//! - verify: `r ‖ s ‖ digest` ([`HsmEccCurve::ecdsa_verify_input_len`]).
//!
//! ## Key buffer alignment
//!
//! Hardware engines require ECC key material to start at a **4-byte
//! aligned** address, with **`roundup8(len)`** bytes of readable memory
//! behind it. Callers must uphold this; implementations may rely on it.
//! Four-byte alignment alone does not guarantee enough backing storage:
//! callers must explicitly allocate at least `roundup8(len)` bytes and
//! pass only the logical `len`-byte key slice to the PAL. This holds for:
//!
//! - keys unmasked in place from a masked-key blob: the TBOR field is
//!   `align = 4`, the key starts at a 4-byte aligned offset within the
//!   blob, and the masked-key format pads the key to a multiple of 16
//!   bytes, which covers `roundup8(len)`.
//!
//! With [`HsmCryptoOrder::ECC_COORD_PAD`] of 8, key lanes are already a
//! multiple of 8 bytes.

use super::*;

/// Supported NIST elliptic curves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmEccCurve {
    /// NIST P-256 (secp256r1) — 32-byte key components.
    P256,

    /// NIST P-384 (secp384r1) — 48-byte key components.
    P384,

    /// NIST P-521 (secp521r1) — 66-byte key components.
    P521,
}

impl HsmEccCurve {
    /// Return the **raw cryptographic** scalar / coordinate length in
    /// bytes for this curve (i.e. `ceil(bit_size / 8)`).
    ///
    /// This is the natural mathematical size of a single field element
    /// (private scalar, X coordinate, Y coordinate, or ECDSA `r`/`s`
    /// component) before any hardware alignment padding is applied.
    ///
    /// | Curve  | Raw |
    /// |--------|-----|
    /// | P-256  | 32  |
    /// | P-384  | 48  |
    /// | P-521  | 66  |
    ///
    /// **This is _not_ the PAL operand size.**  Use
    /// [`HsmEccCurve::wire_coord_len`] /
    /// [`HsmEccCurve::wire_priv_key_len`] /
    /// [`HsmEccCurve::wire_pub_key_len`] /
    /// [`HsmEccCurve::wire_sig_len`] to size buffers exchanged with
    /// the driver, the PAL, or any HSM-format consumer.
    pub fn priv_key_len(&self) -> usize {
        match self {
            HsmEccCurve::P256 => 32,
            HsmEccCurve::P384 => 48,
            HsmEccCurve::P521 => 66,
        }
    }

    /// Return the length in bytes of the ECDSA digest lane for `hash` with
    /// lane padding `pad` ([`HsmCryptoOrder::ECC_COORD_PAD`]): the digest
    /// length rounded up to `pad`, and at least one coordinate lane
    /// ([`HsmEccCurve::wire_coord_len`]).
    ///
    /// The lane holds the digest in [`HsmDigestForm::Operand`] form at its
    /// start, followed by zero bytes. Because it is at least a coordinate
    /// lane, a field-width engine read stays inside it, and a `k ‖ digest`
    /// sign input is long enough to hold `r ‖ s`.
    pub fn ecdsa_digest_lane_len(&self, hash: HsmHashAlgo, pad: usize) -> usize {
        self.wire_coord_len(pad)
            .max(hash.digest_len().next_multiple_of(pad))
    }

    /// Return the length in bytes of the ECDSA sign input
    /// `k ‖ digest`: one coordinate lane and one digest lane
    /// ([`HsmEccCurve::ecdsa_digest_lane_len`]).
    pub fn ecdsa_sign_input_len(&self, hash: HsmHashAlgo, pad: usize) -> usize {
        self.wire_coord_len(pad) + self.ecdsa_digest_lane_len(hash, pad)
    }

    /// Return the length in bytes of the ECDSA verify input
    /// `r ‖ s ‖ digest`: two coordinate lanes and one digest lane
    /// ([`HsmEccCurve::ecdsa_digest_lane_len`]).
    pub fn ecdsa_verify_input_len(&self, hash: HsmHashAlgo, pad: usize) -> usize {
        self.wire_sig_len(pad) + self.ecdsa_digest_lane_len(hash, pad)
    }

    /// Return the **raw cryptographic** public-key length in bytes
    /// (`X || Y`, each [`HsmEccCurve::priv_key_len`] bytes).
    ///
    /// **This is _not_ the PAL operand size.**  See
    /// [`HsmEccCurve::wire_pub_key_len`].
    pub fn pub_key_len(&self) -> usize {
        self.priv_key_len() * 2
    }

    /// Return the PAL operand private-key length in bytes for lane
    /// padding `pad` ([`HsmCryptoOrder::ECC_COORD_PAD`]) — the size of an
    /// HSM-format private scalar buffer. This specifies its length, not
    /// its PAL-specific byte order or padding placement.
    ///
    /// Alias of [`HsmEccCurve::wire_coord_len`] kept for caller-site
    /// clarity at private-key allocation sites.
    pub fn wire_priv_key_len(&self, pad: usize) -> usize {
        self.wire_coord_len(pad)
    }

    /// Raw cryptographic signature length.  See
    /// [`HsmEccCurve::wire_sig_len`] for the HSM/wire-format size.
    pub fn sig_len(&self) -> usize {
        self.priv_key_len() * 2
    }

    /// Return the PAL operand lane length in bytes of one scalar,
    /// coordinate or signature component for lane padding `pad`
    /// ([`HsmCryptoOrder::ECC_COORD_PAD`]): the raw length rounded up to a
    /// multiple of `pad`.  The value occupies the start of the lane in
    /// operand byte order and the rest is zero. Private-key buffers use
    /// the same length, but their encoding is PAL-specific.
    ///
    /// | Curve  | Raw | pad 4 | pad 8 |
    /// |--------|-----|-------|-------|
    /// | P-256  | 32  | 32    | 32    |
    /// | P-384  | 48  | 48    | 48    |
    /// | P-521  | 66  | 68    | 72    |
    ///
    /// This is the single source of truth for sizing any buffer that
    /// crosses the PAL boundary — private-key scratch, public-key
    /// scratch, signature scratch.
    pub fn wire_coord_len(&self, pad: usize) -> usize {
        self.priv_key_len().next_multiple_of(pad)
    }

    /// Return the OKM byte length required for FIPS 186-5 §A.2.1
    /// extra-random-bits deterministic key generation. Independent of
    /// the platform, so a seed derives the same key on every platform.
    pub fn a2_1_okm_len(&self) -> usize {
        self.wire_coord_len(4) + 8
    }

    /// Return the PAL operand public-key byte length (two coordinates:
    /// `X || Y`).  See [`HsmEccCurve::wire_coord_len`].
    pub fn wire_pub_key_len(&self, pad: usize) -> usize {
        self.wire_coord_len(pad) * 2
    }

    /// Return the PAL operand ECDSA signature byte length (two
    /// components: `r || s`).  See [`HsmEccCurve::wire_coord_len`].
    pub fn wire_sig_len(&self, pad: usize) -> usize {
        self.wire_coord_len(pad) * 2
    }

    /// Return the ECDH shared-secret length in bytes (raw X
    /// coordinate, no padding — this matches the cryptographic
    /// definition, not the HSM wire format).
    pub fn secret_len(&self) -> usize {
        self.priv_key_len()
    }
}

/// ECC Pairwise Consistency Test (PCT) mode for key generation and key
/// import.
///
/// FIPS 140-3 requires a PCT after key generation and key import to
/// verify the key pair is functional.  The variant selects which
/// operation is used for verification, or skips the test entirely.
#[derive(Clone, Copy)]
pub enum HsmEccPct {
    /// No PCT — skip the consistency test.
    None,

    /// Sign / verify round-trip with the key pair under test.
    SignVerify,

    /// ECDH key-agreement self-test against a known public-key
    /// counterpart.
    KeyAgreement,
}

/// Source of the per-signature ECDSA nonce `k`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmEcdsaNonce {
    /// The PAL generates `k` from its DRBG. The `k` lane of the sign
    /// input is ignored.
    Generated = 0,

    /// The `k` lane of the sign input holds a caller-supplied `k` in
    /// operand order. PALs whose engine always generates `k` reject it
    /// with [`HsmError::CryptoUnsupportedMode`].
    Supplied = 1,
}

/// Asynchronous ECC operations.
///
/// PAL implementations provide this to core for ECC key generation,
/// signing, verification, and ECDH.  The `async` signatures let
/// hardware-backed implementations yield while the PKA engine runs.
///
/// Nonces, coordinates, signature components, digests and shared
/// secrets are in the platform's operand order
/// ([`HsmCryptoOrder::BYTE_ORDER`]), each in a lane of
/// [`HsmEccCurve::wire_coord_len`] for [`HsmCryptoOrder::ECC_COORD_PAD`].
/// Private keys instead use the PAL-specific HSM/vault encoding documented
/// above; preserve that encoding or use the private-key conversion methods.
pub trait HsmEcc: HsmIoTypes + HsmCryptoOrder {
    /// Generates an ECC key pair on the chosen curve, optionally
    /// writing the keys into caller-provided buffers.
    ///
    /// Uses the canonical query-alloc-use workflow:
    ///
    /// 1. **Query** — call with `out = None`.  No key generation
    ///    or scratch allocation happens; the method returns `(priv_len, pub_len)`
    ///    byte counts the caller must allocate. The output sizes are deterministic
    ///    per-curve: `priv_len = curve.wire_coord_len(Self::ECC_COORD_PAD)`
    ///    (raw HSM scalar) and
    ///    `pub_len = curve.wire_pub_key_len(Self::ECC_COORD_PAD)`.
    /// 2. **Alloc** — caller allocates disjoint DMA output buffers.
    /// 3. **Use** — call with `out = Some((priv_out, pub_out))`.
    ///    The method manages temporary DMA storage in internal allocator scopes,
    ///    including nested PCT scratch, and writes the raw
    ///    HSM-format private scalar into `priv_out[..priv_len]` and
    ///    the operand-order public key into `pub_out[..pub_len]`,
    ///    and returns the same lengths reported by the query call.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve selector.
    /// - `pct` — pairwise consistency test selector.
    /// - `out` — `None` to query buffer sizes; `Some((priv_out,
    ///   pub_out))` to actually generate. Each output buffer must
    ///   be at least as large as the corresponding length returned
    ///   by an earlier query call.
    ///
    /// # Returns
    ///
    /// - `Ok((priv_len, pub_len))` — in query mode, the upper-bound
    ///   sizes the caller must allocate; in use mode, the actual
    ///   bytes written into `priv_out` / `pub_out` (always `≤` the
    ///   query bounds).
    /// - `Err(HsmError::InvalidArg)` — `out` is `Some` and one of
    ///   the output buffers is too short.
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — PKA / RNG / PCT / DMA failure.
    async fn ecc_gen_keypair(
        &self,
        io: &Self::Io,
        curve: HsmEccCurve,
        pct: HsmEccPct,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)>;

    /// Derive an ECC keypair deterministically from a KDF-derived
    /// `root` secret (the caller's `PartRoot`).
    ///
    /// The PAL owns the entire derivation from `root`: it applies its
    /// platform-appropriate FIPS 186-5 §A.2 method — a hardware PAL
    /// whose modular unit cannot reduce by the even value `n − 1` uses
    /// §A.2.2 rejection sampling, while a software PAL may use §A.2.1
    /// extra-random-bits. `root` is the per-partition secret; PALs fan
    /// the per-key material out of it via a domain-separated
    /// HKDF-Expand internally.
    ///
    /// # Determinism is per-platform, not across platforms
    ///
    /// The same `root` regenerates the same keypair on **every call on
    /// a given PAL**, which is what makes the partition identity stable
    /// across resets. It does **not** produce the same keypair on two
    /// different PALs: the HKDF info string, the OKM length and the
    /// §A.2 method are all chosen per platform, so `std` and `uno`
    /// derive different scalars from an identical `root` by
    /// construction. Tests must therefore not assert a fixed public key
    /// across backends, and an emulated key is not a prediction of the
    /// on-silicon key.
    ///
    /// # Parameters
    ///
    /// - `root` — the key-derivation root. Must be `curve.wire_coord_len(Self::ECC_COORD_PAD)`
    ///   bytes (48 for P-384, the `PartRoot` size); any other length is
    ///   [`HsmError::InvalidArg`]. Validated in **both** query and use
    ///   mode, so the error does not depend on `out`.
    /// - `pct` — pairwise consistency test selector.
    /// - `out` — `None` to query `(priv_len, pub_len)` without derivation,
    ///   scratch allocation or a PCT, or `Some((priv_out, pub_out))` to
    ///   derive into caller buffers. Scratch is scoped internally.
    ///
    /// # Errors
    ///
    /// - [`HsmError::InvalidArg`] — `root` is the wrong length, or `out`
    ///   is `Some` and a buffer is too short.
    /// - [`HsmError::UnsupportedCmd`] — the PAL does not implement the
    ///   requested `curve`. Reported in query mode too, so query and use
    ///   mode agree.
    async fn ecc_gen_keypair_from_root(
        &self,
        io: &Self::Io,
        curve: HsmEccCurve,
        root: &HsmDmaBuf,
        pct: HsmEccPct,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)>;

    /// ECDSA sign over a pre-computed message digest.
    ///
    /// The caller hashes the message; this method performs no hashing.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve the private key is on.
    /// - `hash` — the algorithm that produced the digest: SHA-1, SHA-256,
    ///   SHA-384 or SHA-512. It sizes the digest lane, and a digest longer
    ///   than the curve order is truncated to its leftmost bits (FIPS 186-5
    ///   §6.4.1).
    /// - `priv_key` — signing key in PAL-specific HSM-format scalar bytes
    ///   (`curve.wire_priv_key_len(Self::ECC_COORD_PAD)`), not a value-first
    ///   operand lane.
    /// - `nonce` — the source of `k`.
    /// - `input` — exactly
    ///   [`curve.ecdsa_sign_input_len(hash, Self::ECC_COORD_PAD)`](HsmEccCurve::ecdsa_sign_input_len)
    ///   bytes: a `k` lane of `curve.wire_coord_len(Self::ECC_COORD_PAD)`
    ///   bytes, then a digest lane
    ///   ([`HsmEccCurve::ecdsa_digest_lane_len`]) holding the digest in
    ///   [`HsmDigestForm::Operand`] form, followed by zero bytes. With
    ///   [`HsmEcdsaNonce::Supplied`] the `k` lane holds `k` in operand
    ///   order, and a PAL that signs with it zeroes the lane before return;
    ///   with [`HsmEcdsaNonce::Generated`] it is ignored and left unchanged.
    /// - `out` — `None` to query the signature length without signing or
    ///   allocating DMA scratch; `Some(signature)`, disjoint from `input`,
    ///   to write `r || s` in operand order. Any output tail is left
    ///   untouched.
    ///
    /// Arguments are checked in both modes.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required capacity in query mode; otherwise bytes
    ///   written (`curve.wire_sig_len(Self::ECC_COORD_PAD)`).
    /// - `Err(HsmError::UnsupportedDigestHashAlgorithm)` — `hash` is not
    ///   SHA-1 or SHA-2.
    /// - `Err(HsmError::CryptoUnsupportedMode)` — the PAL cannot use a
    ///   supplied `k`.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch, or a non-zero
    ///   byte after the digest in its lane.
    /// - `Err(HsmError)` — PKA / RNG failure.
    #[allow(clippy::too_many_arguments)]
    async fn ecc_sign(
        &self,
        io: &Self::Io,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        nonce: HsmEcdsaNonce,
        input: &mut HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// ECDSA sign, replacing the prefix of the `k ‖ digest` input with the
    /// signature.
    ///
    /// `k_sig` is the sign input of [`Self::ecc_sign`], disjoint from
    /// `priv_key`. The implementation consumes every input before it
    /// publishes the result. Because the digest lane is at least one
    /// coordinate lane, `r || s` fits in `k_sig` and overwrites the whole
    /// `k` lane; the bytes after it are left over from the digest. A
    /// supplied `k` that the PAL signs with is zeroed, on success or error.
    ///
    /// This input/output buffer is an explicit exception to output-size
    /// queries.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — `k_sig[..len]` holds `r || s`, where `len` is
    ///   `curve.wire_sig_len(Self::ECC_COORD_PAD)`.
    /// - Errors as listed on [`Self::ecc_sign`].
    async fn ecc_sign_in_place(
        &self,
        io: &Self::Io,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        nonce: HsmEcdsaNonce,
        k_sig: &mut HsmDmaBuf,
    ) -> HsmResult<usize>;

    /// ECDSA verify of a signature over a pre-computed message digest.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve the public key is on.
    /// - `hash` — the algorithm that produced the digest, as for
    ///   [`Self::ecc_sign`].
    /// - `pub_key` — verification key; uncompressed `x || y`, exactly
    ///   `curve.wire_pub_key_len(Self::ECC_COORD_PAD)` bytes, each
    ///   coordinate in operand order.
    /// - `input` — exactly
    ///   [`curve.ecdsa_verify_input_len(hash, Self::ECC_COORD_PAD)`](HsmEccCurve::ecdsa_verify_input_len)
    ///   bytes: the signature `r || s` in two coordinate lanes, then the
    ///   digest lane as for [`Self::ecc_sign`].
    ///
    /// Temporary DMA storage, including the hardware status word, is
    /// allocated and reclaimed in an internal allocator scope.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — signature valid.
    /// - `Ok(false)` — signature does not verify.
    /// - `Err(HsmError::UnsupportedDigestHashAlgorithm)` — `hash` is not
    ///   SHA-1 or SHA-2.
    /// - `Err(HsmError::InvalidArg)` — buffer-size mismatch, a non-zero
    ///   byte after the digest in its lane, or a malformed public key.
    /// - `Err(HsmError::NotEnoughSpace)` — insufficient scoped scratch space.
    /// - `Err(HsmError)` — propagated from the PKA driver.
    async fn ecc_verify(
        &self,
        io: &Self::Io,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        input: &HsmDmaBuf,
    ) -> HsmResult<bool>;

    /// Convert a PKCS#8 DER-encoded ECC private key (recovered from a
    /// `CKM_RSA_AES_KEY_WRAP` unwrap) into the PAL's vault representation
    /// (raw HSM-format scalar bytes), returning the key's curve.
    ///
    /// Follows the query/alloc/use convention: pass `out = None` to query
    /// the vault byte length the caller must allocate (the curve's
    /// [`wire_coord_len`](HsmEccCurve::wire_coord_len)), then
    /// `out = Some(buf)` to serialize.
    ///
    /// In use mode, a PAL that checks imported keys runs the pairwise
    /// consistency test that `pct` selects on the converted key pair before
    /// it returns; query mode ignores `pct`.  Such a PAL can also check the
    /// key's structure, such as whether the public key that `der` carries
    /// matches the private key.
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — `der` is not a valid PKCS#8 ECC
    ///   private key, or `out` is too small.
    /// - [`HsmError::KeyDecodeFailed`] — the PAL's structure check found no
    ///   public key in `der`, or found `[0]` curve parameters.
    /// - [`HsmError::KeyStructuralValidationFailed`] — the PAL's structure
    ///   check rejected the key's public key.
    /// - [`HsmError::PctValidationRsaUnwrapEccKeyFailed`] — the key pair
    ///   failed its PCT.
    async fn ecc_priv_der_to_vault(
        &self,
        io: &Self::Io,
        der: &HsmDmaBuf,
        pct: HsmEccPct,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<(usize, HsmEccCurve)>;

    /// Convert a raw big-endian ECC private scalar `d` on `curve` into
    /// the PAL's vault representation (raw HSM-format scalar bytes).
    ///
    /// The scalar is the COSE EC2 `d` field encoding: unsigned,
    /// big-endian, exactly [`curve.priv_key_len()`](HsmEccCurve::priv_key_len)
    /// bytes (P-256 32, P-384 48, P-521 66).  The scalar is validated to
    /// be in `[1, n-1]`; the resulting public point (`d·G`) is *not*
    /// derived here — the caller re-derives it (via
    /// [`ecc_pub_from_priv`](HsmEcc::ecc_pub_from_priv)) both to return
    /// the wire public key and to enforce the COSE private/public
    /// consistency check.
    ///
    /// Follows the query/alloc/use convention: pass `out = None` to query
    /// the vault byte length the caller must allocate (the curve's
    /// [`wire_coord_len`](HsmEccCurve::wire_coord_len)), then
    /// `out = Some(buf)` to serialize.
    ///
    /// This is the raw-scalar sibling of
    /// [`ecc_priv_der_to_vault`](HsmEcc::ecc_priv_der_to_vault) (which
    /// takes a self-describing PKCS#8 DER blob); here the curve is
    /// supplied by the caller because a raw scalar carries no curve.
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — `d` is not exactly the curve field
    ///   width, is out of range (`0` or `>= n`), or `out` is too small.
    fn ecc_priv_to_vault(
        &self,
        io: &Self::Io,
        curve: HsmEccCurve,
        d: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Serialize a vault-stored ECC private key back to the raw
    /// big-endian COSE EC2 `d` scalar at the curve's field width.
    ///
    /// The inverse of [`ecc_priv_to_vault`](HsmEcc::ecc_priv_to_vault):
    /// `vault` is the PAL's vault representation (raw HSM-format scalar
    /// bytes, [`wire_coord_len`](HsmEccCurve::wire_coord_len)); the
    /// output is the unsigned big-endian scalar, exactly
    /// [`priv_key_len`](HsmEccCurve::priv_key_len) bytes (P-256 32,
    /// P-384 48, P-521 66) — the encoding the COSE EC2 `d` field
    /// requires. Because the vault representation is backend-defined,
    /// callers that need canonical COSE `d` bytes MUST go
    /// through this primitive rather than reading the vault scalar
    /// directly.
    ///
    /// Follows the query/alloc/use convention: pass `out = None` to
    /// query the scalar byte length
    /// ([`priv_key_len`](HsmEccCurve::priv_key_len)), then
    /// `out = Some(buf)` to serialize.
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — `vault` is not the curve's
    ///   [`wire_coord_len`](HsmEccCurve::wire_coord_len), is not a valid
    ///   scalar, or `out` is too small.
    fn ecc_vault_to_priv(
        &self,
        io: &Self::Io,
        curve: HsmEccCurve,
        vault: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Derive the operand-order public key (`x || y`) from a
    /// vault-stored ECC private key.
    ///
    /// The ECC analogue of
    /// [`HsmRsa::rsa_priv_pub_key`](crate::HsmRsa::rsa_priv_pub_key):
    /// `priv_key` is in the PAL's vault representation (raw HSM-format
    /// scalar bytes).  Follows the query/alloc/use convention — pass
    /// `pub_out = None` to query the wire length
    /// ([`wire_pub_key_len`](HsmEccCurve::wire_pub_key_len)), then
    /// `pub_out = Some(buf)` to serialize.
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — `priv_key` is not a valid vault-format
    ///   ECC private key, or `pub_out` is too small.
    async fn ecc_priv_pub_key(
        &self,
        io: &Self::Io,
        priv_key: &HsmDmaBuf,
        pub_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Derive the operand-order public point from a vault key reference.
    ///
    /// Accepts the same raw-scalar key representation as
    /// [`Self::ecc_priv_pub_key`]. The PAL snapshots the key before yielding
    /// and writes directly into `out`, returning the number of bytes written.
    /// Pass `None` to query the wire length without snapshotting the key,
    /// allocating DMA scratch or deriving a public point. In use mode,
    /// the output must be 4-byte aligned and fit the curve's wire public-key
    /// length; any output tail is left untouched.
    ///
    /// Propagates vault lookup, invalid-scalar, undersized-buffer, allocation
    /// and ECC-engine errors.
    async fn ecc_vault_pub_key(
        &self,
        io: &Self::Io,
        key_id: HsmKeyId,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Derive the public key from a raw private scalar (`pub = priv · G`).
    ///
    /// Computes the public point by base-point scalar multiplication and
    /// serializes it in operand order. Performs no
    /// hashing and no signing.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve the private key is on.
    /// - `priv_key` — private scalar in operand order,
    ///   `curve.wire_priv_key_len(Self::ECC_COORD_PAD)` bytes.
    /// - `out` — `None` to query the public-key length without deriving a
    ///   point or allocating DMA scratch; `Some(pub_key)` to write `x || y`
    ///   in operand order. Any output tail is left untouched.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required capacity in query mode; otherwise bytes written.
    /// - `Err(HsmError::InvalidArg)` — `priv_key` not `wire_priv_key_len`
    ///   bytes, `pub_key` shorter than `wire_pub_key_len`, or an invalid
    ///   private scalar.
    /// - `Err(HsmError)` — propagated from the PKA driver.
    async fn ecc_pub_from_priv(
        &self,
        io: &Self::Io,
        curve: HsmEccCurve,
        priv_key: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// ECDH key agreement: derives a shared secret from a local
    /// private key and a remote public key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `curve` — NIST curve both keys are on.
    /// - `priv_key` — local private key in raw HSM-format scalar bytes
    ///   (`curve.wire_coord_len(Self::ECC_COORD_PAD)`).
    /// - `pub_key` — remote uncompressed point; exactly
    ///   `curve.wire_pub_key_len(Self::ECC_COORD_PAD)` bytes (`x || y`),
    ///   each coordinate in operand order.
    /// - `out` — `None` to query `curve.secret_len()` without deriving a
    ///   secret or allocating DMA scratch; `Some(secret)` to write the x-coordinate of
    ///   the shared point in operand order. Conversion to the standard
    ///   big-endian form (e.g. before an HKDF) is the caller's. Any output tail
    ///   is left untouched.
    ///
    /// # Returns
    ///
    /// - `Ok(len)` — required capacity in query mode; otherwise bytes written.
    /// - `Err(HsmError::InvalidArg)` — buffer mismatch or invalid
    ///   public-key point.
    /// - `Err(HsmError)` — PKA driver failure.
    async fn ecdh_derive(
        &self,
        io: &Self::Io,
        curve: HsmEccCurve,
        priv_key: &HsmDmaBuf,
        pub_key: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;
}

#[cfg(test)]
mod tests {
    use super::HsmEccCurve;

    /// Every supported curve. Kept in sync with [`index_in_all`] by
    /// [`all_lists_every_curve`].
    const ALL: [HsmEccCurve; 3] = [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521];

    /// Position of `curve` in [`ALL`].
    ///
    /// This match has no wildcard arm, so adding a variant to
    /// [`HsmEccCurve`] stops this module compiling until the variant is
    /// given an arm here -- and [`all_lists_every_curve`] then fails
    /// unless it is also appended to [`ALL`] at that index. Without this,
    /// `ALL` was just a hand-written list that a new variant could bypass
    /// silently, skipping every check below.
    fn index_in_all(curve: HsmEccCurve) -> usize {
        match curve {
            HsmEccCurve::P256 => 0,
            HsmEccCurve::P384 => 1,
            HsmEccCurve::P521 => 2,
        }
    }

    /// `ALL` must list every curve, in `index_in_all` order.
    #[test]
    fn all_lists_every_curve() {
        for (i, curve) in ALL.iter().enumerate() {
            assert_eq!(
                index_in_all(*curve),
                i,
                "ALL is out of sync with index_in_all: {curve:?} is listed at \
                 index {i} but indexed as {}",
                index_in_all(*curve)
            );
        }
    }

    /// `wire_priv_key_len` must stay pairwise distinct across the
    /// supported curves.
    ///
    /// Callers are allowed to recover the curve from a raw scalar's
    /// length -- `HsmEcc::ecc_priv_pub_key` does exactly that, and
    /// `ecc_pub_from_priv` delegates to it. That inference is only sound
    /// while no two curves share a wire length. If a new variant ever
    /// collides, this fails instead of the firmware quietly computing on
    /// the wrong curve.
    #[test]
    fn wire_priv_key_len_is_unambiguous() {
        for (i, a) in ALL.iter().enumerate() {
            for b in ALL.iter().skip(i + 1) {
                for pad in [1, 4, 8] {
                    assert_ne!(
                        a.wire_priv_key_len(pad),
                        b.wire_priv_key_len(pad),
                        "{a:?} and {b:?} share a pad-{pad} scalar length, so \
                         recovering the curve from a scalar length is no longer sound"
                    );
                }
            }
        }
    }
}
