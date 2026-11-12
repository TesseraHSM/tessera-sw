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

/// Length of the ML-DSA key-generation seed `ξ` (FIPS 204), the same for
/// every parameter set.
pub const MLDSA_SEED_LEN: usize = 32;

/// Length of the ML-KEM key-generation seed pair `d || z` (FIPS 203), the
/// same for every parameter set.
pub const MLKEM_SEED_LEN: usize = 64;

/// Length of an ML-KEM shared secret (FIPS 203), the same for every
/// parameter set.
pub const MLKEM_SHARED_SECRET_LEN: usize = 32;

/// ML-DSA parameter set (FIPS 204).
///
/// The PAL's own selector, as [`HsmRsaKey`] is for RSA: ML-DSA operations
/// take it rather than a vault key kind, and callers map a stored key's
/// kind onto it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMlDsaParam {
    /// ML-DSA-44.
    MlDsa44,

    /// ML-DSA-65.
    MlDsa65,

    /// ML-DSA-87.
    MlDsa87,
}

impl HsmMlDsaParam {
    /// Encoded public key length: 1312 / 1952 / 2592 bytes.
    pub const fn pk_len(&self) -> usize {
        match self {
            Self::MlDsa44 => 1312,
            Self::MlDsa65 => 1952,
            Self::MlDsa87 => 2592,
        }
    }

    /// Expanded secret key length: 2560 / 4032 / 4896 bytes.
    pub const fn sk_len(&self) -> usize {
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
    pub const fn from_pk_len(len: usize) -> Option<Self> {
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
pub enum HsmMlKemParam {
    /// ML-KEM-512.
    MlKem512,

    /// ML-KEM-768.
    MlKem768,

    /// ML-KEM-1024.
    MlKem1024,
}

impl HsmMlKemParam {
    /// Encapsulation (public) key length: 800 / 1184 / 1568 bytes.
    pub const fn pk_len(&self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Expanded decapsulation (private) key length: 1632 / 2400 / 3168
    /// bytes.
    pub const fn sk_len(&self) -> usize {
        match self {
            Self::MlKem512 => 1632,
            Self::MlKem768 => 2400,
            Self::MlKem1024 => 3168,
        }
    }

    /// Ciphertext length: 768 / 1088 / 1568 bytes.
    pub const fn ct_len(&self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// The parameter set whose encapsulation key is `len` bytes long, if
    /// any.  The three lengths are distinct, so this is unambiguous.
    pub const fn from_pk_len(len: usize) -> Option<Self> {
        match len {
            800 => Some(Self::MlKem512),
            1184 => Some(Self::MlKem768),
            1568 => Some(Self::MlKem1024),
            _ => None,
        }
    }
}

/// How the message part of an [`HsmMlDsaMsg`] is read.
///
/// FIPS 204 signs and verifies the 64-byte message representative
/// `μ = SHAKE256(tr || M', 64)`, where `tr` is the hash of the public key and
/// `M'` encodes the domain, the context string and the input.  The type
/// selects what the caller supplies and so how much of `μ` is computed for
/// it.  The pre-hash types name their hash function, as PKCS#11's
/// `CK_HASH_SIGN_ADDITIONAL_CONTEXT` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMlDsaMsgType {
    /// Pure ML-DSA (FIPS 204 §5.2, `CKM_ML_DSA`): the message is `M`, and
    /// `μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || M, 64)`.
    Pure,

    /// HashML-DSA with a caller-computed digest (FIPS 204 §5.4,
    /// `CKM_HASH_ML_DSA`): the message is `OID(hash) || PHM`, and
    /// `μ = SHAKE256(tr || 0x01 || len(ctx) || ctx || OID || PHM, 64)`.
    PreHash(HsmHashAlgo),

    /// HashML-DSA over the message (`CKM_HASH_ML_DSA_<H>`): the message is
    /// `OID(hash) || M`; the implementation computes `PHM = hash(M)`, then
    /// `μ` as for [`PreHash`](Self::PreHash).
    HashMsg(HsmHashAlgo),

    /// External μ: the message is the [`MLDSA_MU_LEN`]-byte `μ`, used as
    /// is.  It already binds the context string, so there is none.
    ExternalMu,
}

impl HsmMlDsaMsgType {
    /// The pre-hash function, for [`PreHash`](Self::PreHash) and
    /// [`HashMsg`](Self::HashMsg).
    pub const fn hash_algo(self) -> Option<HsmHashAlgo> {
        match self {
            Self::PreHash(algo) | Self::HashMsg(algo) => Some(algo),
            Self::Pure | Self::ExternalMu => None,
        }
    }
}

/// Length of a FIPS 204 pre-hash function OID (DER, tag and length
/// included).
pub const MLDSA_OID_LEN: usize = 11;

impl HsmHashAlgo {
    /// The DER object identifier HashML-DSA binds into `μ` for this hash
    /// function (FIPS 204 §5.4), or `None` if FIPS 204 does not allow it as
    /// a pre-hash.  SHAKE128 and SHAKE256 are allowed only with their FIPS
    /// 204 output lengths, 32 and 64 bytes.
    pub const fn mldsa_oid(self) -> Option<&'static [u8; MLDSA_OID_LEN]> {
        /// `2.16.840.1.101.3.4.2.<arc>` (NIST hash algorithms).
        const fn oid(arc: u8) -> [u8; MLDSA_OID_LEN] {
            [
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, arc,
            ]
        }
        const SHA256: [u8; MLDSA_OID_LEN] = oid(0x01);
        const SHA384: [u8; MLDSA_OID_LEN] = oid(0x02);
        const SHA512: [u8; MLDSA_OID_LEN] = oid(0x03);
        const SHA3_256: [u8; MLDSA_OID_LEN] = oid(0x08);
        const SHA3_384: [u8; MLDSA_OID_LEN] = oid(0x09);
        const SHA3_512: [u8; MLDSA_OID_LEN] = oid(0x0a);
        const SHAKE128: [u8; MLDSA_OID_LEN] = oid(0x0b);
        const SHAKE256: [u8; MLDSA_OID_LEN] = oid(0x0c);
        match self {
            Self::Sha256 => Some(&SHA256),
            Self::Sha384 => Some(&SHA384),
            Self::Sha512 => Some(&SHA512),
            Self::Sha3_256 => Some(&SHA3_256),
            Self::Sha3_384 => Some(&SHA3_384),
            Self::Sha3_512 => Some(&SHA3_512),
            Self::Shake128(len) if len.get() == 32 => Some(&SHAKE128),
            Self::Shake256(len) if len.get() == 64 => Some(&SHAKE256),
            Self::Sha1 | Self::Shake128(_) | Self::Shake256(_) => None,
        }
    }
}

/// A validated, borrowed ML-DSA signing or verification input, laid out as
/// the engine reads it: `data = ctx[..ctx_len] || message`.
///
/// Callers place the context and message contiguously (typically straight
/// from the host request), so implementations pass `data` through without
/// allocating or copying.  [`new`](Self::new) checks every rule that does
/// not depend on the implementation, so a value of this type is always well
/// formed.
#[derive(Debug, Clone, Copy)]
pub struct HsmMlDsaMsg<'a> {
    msg_type: HsmMlDsaMsgType,
    ctx_len: u8,
    data: &'a HsmDmaBuf,
}

impl<'a> HsmMlDsaMsg<'a> {
    /// Wrap `data = ctx[..ctx_len] || message`.
    ///
    /// The FIPS 204 255-byte context limit is enforced by `ctx_len`'s type.
    ///
    /// # Returns
    ///
    /// - `Ok(msg)` — the input is well formed for `msg_type`.
    /// - `Err(HsmError::InvalidArg)` if:
    ///   - `ctx_len` exceeds `data.len()`;
    ///   - [`ExternalMu`](HsmMlDsaMsgType::ExternalMu) has a context, or a
    ///     message that is not [`MLDSA_MU_LEN`] bytes;
    ///   - [`PreHash`](HsmMlDsaMsgType::PreHash) /
    ///     [`HashMsg`](HsmMlDsaMsgType::HashMsg): the hash has no
    ///     [`mldsa_oid`](HsmHashAlgo::mldsa_oid), or the message does not
    ///     start with exactly that OID;
    ///   - [`PreHash`](HsmMlDsaMsgType::PreHash): the digest after the OID
    ///     is not the hash's [`digest_len`](HsmHashAlgo::digest_len).
    pub fn new(msg_type: HsmMlDsaMsgType, ctx_len: u8, data: &'a HsmDmaBuf) -> HsmResult<Self> {
        let message = data
            .get(usize::from(ctx_len)..)
            .ok_or(HsmError::InvalidArg)?;
        let well_formed = match msg_type {
            HsmMlDsaMsgType::Pure => true,
            HsmMlDsaMsgType::ExternalMu => ctx_len == 0 && message.len() == MLDSA_MU_LEN,
            HsmMlDsaMsgType::PreHash(algo) | HsmMlDsaMsgType::HashMsg(algo) => {
                let oid = algo.mldsa_oid().ok_or(HsmError::InvalidArg)?;
                message.starts_with(oid)
                    && (matches!(msg_type, HsmMlDsaMsgType::HashMsg(_))
                        || message.len() == MLDSA_OID_LEN + algo.digest_len())
            }
        };
        if !well_formed {
            return Err(HsmError::InvalidArg);
        }
        Ok(Self {
            msg_type,
            ctx_len,
            data,
        })
    }

    /// How the message is read.
    pub fn msg_type(&self) -> HsmMlDsaMsgType {
        self.msg_type
    }

    /// The whole `ctx || message` region, as handed to the engine.
    pub fn data(&self) -> &'a HsmDmaBuf {
        self.data
    }

    /// The FIPS 204 context string; empty for an external `μ`.
    pub fn ctx(&self) -> &'a HsmDmaBuf {
        &self.data[..usize::from(self.ctx_len)]
    }

    /// The message part: `M`, `OID || PHM`, `OID || M` or `μ`, as
    /// [`msg_type`](Self::msg_type) says.
    pub fn message(&self) -> &'a HsmDmaBuf {
        &self.data[usize::from(self.ctx_len)..]
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

/// Where [`HsmMlDsa::mldsa_gen_keypair`] and
/// [`HsmMlKem::mlkem_gen_keypair`] get the key-generation seed (`ξ` for
/// ML-DSA, `d || z` for ML-KEM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMlSeedSrc {
    /// Draw a fresh seed from the device's entropy source and write it into
    /// the seed buffer (FIPS 204 Algorithm 1, `ML-DSA.KeyGen`; FIPS 203
    /// Algorithm 19, `ML-KEM.KeyGen`).
    Random,

    /// Use the seed the caller placed in the seed buffer, which is left
    /// unchanged (FIPS 204 Algorithm 6, `ML-DSA.KeyGen_internal`; FIPS 203
    /// Algorithm 16, `ML-KEM.KeyGen_internal`).  For re-expanding a stored
    /// or imported seed only: FIPS 204 §6 and FIPS 203 §7.1 require the
    /// module, not the application, to generate the seed of a new key.
    Caller,
}

/// Pairwise consistency test run on an ML-DSA key pair by
/// [`HsmMlDsa::mldsa_gen_keypair`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMlDsaPct {
    /// No PCT — skip the consistency test.
    None,

    /// Sign / verify round-trip with the key pair under test.
    SignVerify,
}

/// Pairwise consistency test run on an ML-KEM key pair by
/// [`HsmMlKem::mlkem_gen_keypair`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmMlKemPct {
    /// No PCT — skip the consistency test.
    None,

    /// Encapsulate / decapsulate round-trip with the key pair under test.
    EncapsDecaps,
}

/// Asynchronous ML-DSA signature operations.
///
/// Async because every method is a round trip to an FP core: the
/// implementation yields while the request is in flight.
///
/// Signing and verification take an [`HsmMlDsaMsg`], the validated
/// `ctx || message` input; signing also takes an [`HsmMlDsaHedge`] saying how
/// the signature is randomized.
///
/// Errors common to signing and verification:
///
/// - `Err(HsmError::InvalidArg)` — a key or signature buffer of the wrong
///   length, or a message larger than the implementation accepts.
/// - `Err(HsmError::UnsupportedCmd)` — the implementation does not support
///   the message type, its hash function, or the requested hedging.
/// - `Err(HsmError)` — propagated from the FP offload path.
pub trait HsmMlDsa: HsmIoTypes {
    /// Generates an ML-DSA key pair, optionally writing it into
    /// caller-provided buffers.
    ///
    /// Uses the same query-alloc-use workflow as
    /// [`HsmEcc::ecc_gen_keypair`]:
    ///
    /// 1. **Query** — call with `out = None`.  Nothing is generated and
    ///    `seed` is not touched; the method returns `(sk_len, pk_len)`
    ///    = ([`HsmMlDsaParam::sk_len`], [`HsmMlDsaParam::pk_len`]).
    /// 2. **Alloc** — caller allocates two DMA buffers of those sizes.
    /// 3. **Use** — call with `out = Some((sk, pk))`.  The method takes `ξ`
    ///    from `seed_src`, derives the key pair from it, writes the expanded
    ///    private key into `sk[..sk_len]` and the encoded public key into
    ///    `pk[..pk_len]`, and returns the same lengths as the query call.
    ///
    /// The outputs map onto PKCS#11 3.2 `CKM_ML_DSA_KEY_PAIR_GEN`: `seed` is
    /// the private key's `CKA_SEED`, `sk` its `CKA_VALUE`, and `pk` the
    /// public key's `CKA_VALUE`.  All three are private key material except
    /// `pk`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param` — the ML-DSA parameter set.
    /// - `seed_src` — whether `ξ` is generated or supplied in `seed`.
    /// - `pct` — pairwise consistency test selector.
    /// - `seed` — the seed `ξ`, exactly [`MLDSA_SEED_LEN`] bytes.  Filled
    ///   for [`HsmMlSeedSrc::Random`], read for
    ///   [`HsmMlSeedSrc::Caller`]; either way it holds the key pair's `ξ`
    ///   on success.
    /// - `out` — `None` to query buffer sizes; `Some((sk, pk))` to generate.
    ///   Each buffer must be at least as large as the corresponding queried
    ///   length.
    ///
    /// # Returns
    ///
    /// - `Ok((sk_len, pk_len))` — the sizes to allocate (query mode) or the
    ///   bytes written (use mode).
    /// - `Err(HsmError::InvalidArg)` — `seed` is not [`MLDSA_SEED_LEN`]
    ///   bytes (checked in both modes), or an output buffer is too short.
    /// - `Err(HsmError)` — RNG, offload, or PCT failure.
    async fn mldsa_gen_keypair(
        &self,
        io: &Self::Io,
        param: HsmMlDsaParam,
        seed_src: HsmMlSeedSrc,
        pct: HsmMlDsaPct,
        seed: &mut HsmDmaBuf,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)>;

    /// Signs `msg` with an expanded secret key.
    ///
    /// Uses the query-alloc-use workflow: with `sig = None` the method
    /// checks its inputs, signs nothing, and returns
    /// [`HsmMlDsaParam::sig_len`]; with `sig = Some(..)` it signs.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param` — the ML-DSA parameter set.
    /// - `sk` — expanded secret key, exactly [`HsmMlDsaParam::sk_len`] bytes.
    /// - `hedge` — whether the signature is hedged or deterministic.
    /// - `msg` — the input to sign.
    /// - `sig` — `None` to query; `Some(sig)` with at least
    ///   [`HsmMlDsaParam::sig_len`] bytes, of which the leading `sig_len` are
    ///   written.
    ///
    /// # Returns
    ///
    /// - `Ok(sig_len)` — the size to allocate (query mode) or the bytes
    ///   written.
    /// - Errors as listed on [`HsmMlDsa`].
    async fn mldsa_sign(
        &self,
        io: &Self::Io,
        param: HsmMlDsaParam,
        sk: &HsmDmaBuf,
        hedge: HsmMlDsaHedge,
        msg: HsmMlDsaMsg<'_>,
        sig: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;

    /// Signs `msg`, replacing the prefix of a key/signature region with the
    /// signature.
    ///
    /// The expanded secret key occupies the final [`HsmMlDsaParam::sk_len`]
    /// bytes of `sk_sig`; any preceding bytes are scratch.  The signature is
    /// written at the start of `sk_sig` after all inputs have been consumed,
    /// so `sk_sig` must be at least [`HsmMlDsaParam::sig_len`] bytes.  The
    /// caller wipes private bytes not replaced by the signature.
    ///
    /// # Returns
    ///
    /// - `Ok(sig_len)` — `sk_sig[..sig_len]` holds the signature.
    /// - Errors as listed on [`HsmMlDsa`].
    async fn mldsa_sign_in_place(
        &self,
        io: &Self::Io,
        param: HsmMlDsaParam,
        sk_sig: &mut HsmDmaBuf,
        hedge: HsmMlDsaHedge,
        msg: HsmMlDsaMsg<'_>,
    ) -> HsmResult<usize>;

    /// Verifies `sig` over `msg` under a public key.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param` — the ML-DSA parameter set.
    /// - `pk` — encoded public key, exactly [`HsmMlDsaParam::pk_len`] bytes.
    /// - `msg` — the signed input.
    /// - `sig` — exactly [`HsmMlDsaParam::sig_len`] bytes.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` / `Ok(false)` — the signature verified, or did not.
    ///   An invalid signature is an ordinary outcome, not an error, so it
    ///   cannot be conflated with a transport fault.
    /// - Errors as listed on [`HsmMlDsa`].
    async fn mldsa_verify(
        &self,
        io: &Self::Io,
        param: HsmMlDsaParam,
        pk: &HsmDmaBuf,
        msg: HsmMlDsaMsg<'_>,
        sig: &HsmDmaBuf,
    ) -> HsmResult<bool>;
}

/// Asynchronous ML-KEM key-encapsulation operations.
///
/// Async because every method is a round trip to an FP core: the
/// implementation yields while the request is in flight.
pub trait HsmMlKem: HsmIoTypes {
    /// Generates an ML-KEM key pair, optionally writing it into
    /// caller-provided buffers.
    ///
    /// Uses the same query-alloc-use workflow as
    /// [`HsmMlDsa::mldsa_gen_keypair`]:
    ///
    /// 1. **Query** — call with `out = None`.  Nothing is generated and
    ///    `seed` is not touched; the method returns `(sk_len, pk_len)`
    ///    = ([`HsmMlKemParam::sk_len`], [`HsmMlKemParam::pk_len`]).
    /// 2. **Alloc** — caller allocates two DMA buffers of those sizes.
    /// 3. **Use** — call with `out = Some((sk, pk))`.  The method takes
    ///    `d || z` from `seed_src`, derives the key pair from it, writes the
    ///    expanded decapsulation key into `sk[..sk_len]` and the
    ///    encapsulation key into `pk[..pk_len]`, and returns the same
    ///    lengths as the query call.
    ///
    /// The outputs map onto PKCS#11 3.2 `CKM_ML_KEM_KEY_PAIR_GEN`: `seed` is
    /// the private key's `CKA_SEED`, `sk` its `CKA_VALUE`, and `pk` the
    /// public key's `CKA_VALUE`.  All three are private key material except
    /// `pk`.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param` — the ML-KEM parameter set.
    /// - `seed_src` — whether `d || z` is generated or supplied in `seed`.
    /// - `pct` — pairwise consistency test selector.
    /// - `seed` — the seed pair `d || z`, exactly [`MLKEM_SEED_LEN`] bytes.
    ///   Filled for [`HsmMlSeedSrc::Random`], read for
    ///   [`HsmMlSeedSrc::Caller`]; either way it holds the key pair's
    ///   `d || z` on success.
    /// - `out` — `None` to query buffer sizes; `Some((sk, pk))` to generate.
    ///   Each buffer must be at least as large as the corresponding queried
    ///   length.
    ///
    /// # Returns
    ///
    /// - `Ok((sk_len, pk_len))` — the sizes to allocate (query mode) or the
    ///   bytes written (use mode).
    /// - `Err(HsmError::InvalidArg)` — `seed` is not [`MLKEM_SEED_LEN`]
    ///   bytes (checked in both modes), or an output buffer is too short.
    /// - `Err(HsmError)` — RNG, offload, or PCT failure.
    async fn mlkem_gen_keypair(
        &self,
        io: &Self::Io,
        param: HsmMlKemParam,
        seed_src: HsmMlSeedSrc,
        pct: HsmMlKemPct,
        seed: &mut HsmDmaBuf,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)>;

    /// Encapsulate to an ML-KEM public key (FIPS 203 `ML-KEM.Encaps`).
    ///
    /// Follows the same query-alloc-use pattern as
    /// [`HsmMlKem::mlkem_gen_keypair`]:
    ///
    /// 1. **Query** — call with `out = None`.  Nothing is computed and `pk`
    ///    is not read; the method returns `(ct_len, ss_len)` =
    ///    ([`HsmMlKemParam::ct_len`], [`MLKEM_SHARED_SECRET_LEN`]).
    /// 2. **Alloc** — caller allocates two DMA buffers of those sizes.
    /// 3. **Use** — call with `out = Some((ct, ss))`.  The method writes the
    ///    ciphertext into `ct[..ct_len]` and the shared secret into
    ///    `ss[..ss_len]`, and returns the same lengths as the query call.
    ///
    /// This maps onto PKCS#11 3.2 `C_EncapsulateKey` with `CKM_ML_KEM`
    /// (which takes no mechanism parameter).  The shared secret is key
    /// material: the caller is expected to mask it before it leaves the
    /// device.  The randomness encapsulation needs is drawn by the
    /// implementation from the device's entropy source.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param` — the ML-KEM parameter set.
    /// - `pk` — the encapsulation key, exactly [`HsmMlKemParam::pk_len`]
    ///   bytes.
    /// - `out` — `None` to query buffer sizes; `Some((ct, ss))` to
    ///   encapsulate.  Each buffer must be at least as large as the
    ///   corresponding queried length.
    ///
    /// # Returns
    ///
    /// - `Ok((ct_len, ss_len))` — the sizes to allocate (query mode) or the
    ///   bytes written (use mode).
    /// - `Err(HsmError::InvalidArg)` — `pk` has the wrong length or an
    ///   output buffer is too short.
    /// - `Err(HsmError)` — RNG or offload failure.
    async fn mlkem_encaps(
        &self,
        io: &Self::Io,
        param: HsmMlKemParam,
        pk: &HsmDmaBuf,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)>;

    /// Encapsulate, replacing the public key with the ciphertext.
    ///
    /// Same as [`HsmMlKem::mlkem_encaps`], except that `pk_ct` holds the
    /// encapsulation key in `pk_ct[..pk_len]` on entry and the ciphertext
    /// in `pk_ct[..ct_len]` on return.  Every parameter set has
    /// `ct_len <= pk_len`, so `pk_ct` needs at least `pk_len` bytes.  The
    /// key is consumed before its prefix is overwritten.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param` — the ML-KEM parameter set.
    /// - `pk_ct` — encapsulation key in, ciphertext out; at least
    ///   [`HsmMlKemParam::pk_len`] bytes.
    /// - `ss` — shared-secret output, at least [`MLKEM_SHARED_SECRET_LEN`]
    ///   bytes; disjoint from `pk_ct`.
    ///
    /// # Returns
    ///
    /// - `Ok((ct_len, ss_len))` — bytes written to `pk_ct` and `ss`.
    /// - `Err(HsmError::InvalidArg)` — a buffer is too short.
    /// - `Err(HsmError)` — RNG or offload failure.
    async fn mlkem_encaps_in_place(
        &self,
        io: &Self::Io,
        param: HsmMlKemParam,
        pk_ct: &mut HsmDmaBuf,
        ss: &mut HsmDmaBuf,
    ) -> HsmResult<(usize, usize)>;

    /// Decapsulate an ML-KEM ciphertext (FIPS 203 `ML-KEM.Decaps`).
    ///
    /// Maps onto PKCS#11 3.2 `C_DecapsulateKey` with `CKM_ML_KEM`.
    ///
    /// 1. **Query** — call with `ss = None`.  Nothing is computed and `sk`
    ///    and `ct` are not read; the method returns
    ///    [`MLKEM_SHARED_SECRET_LEN`].
    /// 2. **Use** — call with `ss = Some(buf)`.  The method writes the
    ///    shared secret into `buf[..ss_len]` and returns `ss_len`.
    ///
    /// ML-KEM decapsulation never fails on a bad ciphertext: one that does
    /// not decrypt yields an implicit-rejection secret rather than an
    /// error, so there is no boolean here.
    ///
    /// # Parameters
    ///
    /// - `io` — caller's I/O context (per-IO scope).
    /// - `param` — the ML-KEM parameter set.
    /// - `sk` — expanded decapsulation key, exactly
    ///   [`HsmMlKemParam::sk_len`] bytes.
    /// - `ct` — ciphertext, exactly [`HsmMlKemParam::ct_len`] bytes.
    /// - `ss` — `None` to query; otherwise the shared-secret output, at
    ///   least [`MLKEM_SHARED_SECRET_LEN`] bytes.  Key material; the caller
    ///   is expected to mask it before it leaves the device.
    ///
    /// # Returns
    ///
    /// - `Ok(ss_len)` — the size to allocate (query mode) or the bytes
    ///   written (use mode).
    /// - `Err(HsmError::InvalidArg)` — `sk` or `ct` has the wrong length,
    ///   or `ss` is too short.
    /// - `Err(HsmError)` — offload failure.
    async fn mlkem_decaps(
        &self,
        io: &Self::Io,
        param: HsmMlKemParam,
        sk: &HsmDmaBuf,
        ct: &HsmDmaBuf,
        ss: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize>;
}
