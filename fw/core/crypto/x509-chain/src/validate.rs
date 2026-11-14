// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 certificate chain validation state machine.
//!
//! [`ChainValidator`] processes certificates one at a time, from root
//! (index 0) to leaf (index `chain_len - 1`). The streaming walker retains
//! adjacent DER certificates in disjoint views of one DMA allocation.
//! Parsing borrows those views without copying issuer bytes, and scoped
//! metadata and crypto scratch are reclaimed after every step.
//!
//! ## Validation checks per certificate (RFC 5280 §6.1.3, simplified)
//!
//! 1. **Signature** — verify `tbs_raw` with the appropriate key.
//! 2. **Name chain** — `curr.issuer == prev.subject` (byte compare).
//! 3. **AKID↔SKID** — if both present.
//! 4. **BasicConstraints** — `cA=true` required for non-leaf certs.
//! 5. **KeyUsage** — `keyCertSign` required for CA certs, with
//!    algorithm-specific restrictions on EC, RSA-PSS and ML-DSA keys.
//! 6. **Critical extensions** — reject unrecognized (checked in parser).
//!
//! No time validation, no CRL, no policy processing.

use core::ops::AsyncFnMut;

use tsra_fw_ddi_tbor_types::evidence::CertDescriptor;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::HsmAlloc;
use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEcc;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHash;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmMlDsa;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsg;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsgType;
use tsra_fw_hsm_pal_traits::HsmMlDsaPubKey;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRsa;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::ecdsa;
use crate::parse::parse_cert;
use crate::types::key_usage;
use crate::types::CertInfo;
use crate::types::EcPubKey;
use crate::types::PubKey;
use crate::types::RsaPubKey;
use crate::types::SigAlgo;
use crate::types::StepResult;

struct IssuerInfo<'a> {
    pub_key: PubKey<'a>,
    subject_raw: &'a HsmDmaBuf,
    skid: Option<&'a [u8]>,
}

impl<'a> From<&CertInfo<'a>> for IssuerInfo<'a> {
    fn from(cert: &CertInfo<'a>) -> Self {
        Self {
            pub_key: cert.pub_key,
            subject_raw: cert.subject_raw,
            skid: cert.skid,
        }
    }
}

/// X.509 certificate chain validator.
///
/// Processes one certificate at a time.
/// The caller must keep the previous certificate's DER buffer alive
/// when calling [`step`](Self::step), so the validator can borrow
/// the previous certificate's parsed fields for comparison.
///
/// ## State
///
/// Only three integers are stored between calls — everything else
/// is borrowed from the certificate DER buffers:
///
/// - `index` — current certificate position (0-based).
/// - `chain_len` — total number of certificates in the chain.
/// - `max_path_len` — remaining permitted CA depth.
#[derive(Debug)]
pub struct ChainValidator {
    /// Total number of certificates in the chain (including root).
    chain_len: u16,

    /// Index of the next certificate to process (0-based).
    index: u16,

    /// Maximum remaining path length (from BasicConstraints).
    max_path_len: u16,

    /// When `true`, the terminal certificate is itself an issuing CA
    /// (it will go on to sign a further, out-of-chain leaf), so the
    /// CA-only constraints — `cA == true`, `keyCertSign`, and the
    /// remaining `pathLenConstraint` budget — are enforced on it too.
    terminal_is_issuing_ca: bool,
}

impl ChainValidator {
    /// Create a new chain validator.
    ///
    /// `max_path_len` is initialized to `chain_len` so it never
    /// constrains validation by itself; it is then tightened by each
    /// non-leaf certificate's `pathLenConstraint`.
    ///
    /// # Parameters
    /// * `chain_len` — total number of certificates to validate,
    ///   including the root. Must be ≥ 1; passing `0` causes the
    ///   first call to [`step`](Self::step) to fail with
    ///   [`HsmError::X509AlreadyComplete`].
    ///
    /// # Returns
    /// A fresh [`ChainValidator`] positioned before the root
    /// certificate (`index == 0`).
    pub fn new(chain_len: u16) -> Self {
        Self {
            chain_len,
            index: 0,
            max_path_len: chain_len,
            terminal_is_issuing_ca: false,
        }
    }

    /// Like [`new`](Self::new), but validates the terminal certificate
    /// as an issuing CA rather than an end-entity leaf.
    ///
    /// Use this when the terminal certificate will itself sign a
    /// further certificate that is *not* part of this chain (for
    /// example a PTA certificate that later signs an on-demand PID
    /// leaf). The terminal must then satisfy the CA constraints —
    /// `cA == true`, `keyCertSign` (when KeyUsage is present), and the
    /// remaining ancestor `pathLenConstraint` budget — so a chain that
    /// could never issue that extra leaf is rejected up front.
    pub fn new_issuing(chain_len: u16) -> Self {
        Self {
            chain_len,
            index: 0,
            max_path_len: chain_len,
            terminal_is_issuing_ca: true,
        }
    }

    /// Process one certificate in the chain.
    ///
    /// Must be called exactly `chain_len` times, in order from root
    /// (index 0) to leaf (index `chain_len - 1`).
    ///
    /// # Parameters
    /// * `pal` — PAL providing hashing, ECC, RSA and ML-DSA verification.
    /// * `io` — I/O context for the current operation.
    /// * `alloc` — scoped allocator for temporary DMA buffers
    ///   (digest and decoded signature). The caller's DER buffers
    ///   must already be in DMA-accessible memory (`&HsmDmaBuf`).
    /// * `prev` — the parsed previous certificate, or `None` for the
    ///   root (index 0). The previous cert's DER buffer must still be
    ///   alive so `prev`'s slices are valid.
    /// * `curr` — the parsed current certificate. Its DER buffer must
    ///   be alive for the duration of this call.
    ///
    /// # Returns
    /// * [`StepResult::NeedNext`] — chain validation is incomplete;
    ///   caller should provide the next certificate.
    /// * [`StepResult::Valid`] — the entire chain has been validated;
    ///   contains the leaf's verified public key and subject.
    /// * [`StepResult::Invalid`] — validation failed.
    pub async fn step<'a, P>(
        &mut self,
        pal: &P,
        io: &P::Io,
        alloc: &impl HsmScopedAlloc,
        prev: Option<&CertInfo<'_>>,
        curr: &'a CertInfo<'a>,
    ) -> StepResult<'a>
    where
        P: HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    {
        let prev = prev.map(IssuerInfo::from);
        self.step_with_issuer(pal, io, alloc, prev.as_ref(), curr)
            .await
    }

    async fn step_with_issuer<'a, P>(
        &mut self,
        pal: &P,
        io: &P::Io,
        alloc: &impl HsmScopedAlloc,
        prev: Option<&IssuerInfo<'_>>,
        curr: &'a CertInfo<'a>,
    ) -> StepResult<'a>
    where
        P: HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    {
        if self.index >= self.chain_len {
            return StepResult::Invalid(HsmError::X509AlreadyComplete);
        }

        let is_root = self.index == 0;
        let is_leaf = self.index == self.chain_len - 1;

        if let Err(error) = Self::check_key_usage(curr) {
            return StepResult::Invalid(error);
        }

        let verify_key = match self.select_verify_key(is_root, prev, curr) {
            Ok(key) => key,
            Err(error) => return StepResult::Invalid(error),
        };

        // Non-leaf certificates are always CAs. The terminal certificate
        // is additionally treated as a CA when it is an issuing CA (it
        // will sign a further out-of-chain leaf), so its `pathLen` budget
        // and `keyCertSign` usage are enforced too.
        if !is_leaf || self.terminal_is_issuing_ca {
            if let Err(error) = self.apply_ca_constraints(curr) {
                return StepResult::Invalid(error);
            }
        }

        if let Err(error) = self
            .verify_signature(pal, io, alloc, verify_key, curr)
            .await
        {
            return StepResult::Invalid(error);
        }

        self.index += 1;

        if is_leaf {
            StepResult::Valid {
                leaf_pub_key: &curr.pub_key,
                leaf_subject: curr.subject_raw,
            }
        } else {
            StepResult::NeedNext
        }
    }

    /// Choose the public key that should verify the current
    /// certificate's signature, and enforce the per-certificate name
    /// chaining checks.
    ///
    /// For the root, the certificate must be self-signed (issuer ==
    /// subject byte-for-byte) and its own public key is used. For a
    /// non-root certificate the previous certificate's subject must
    /// match the current certificate's issuer, and — if both sides
    /// publish the relevant key identifiers — the AKID must match
    /// the issuer's SKID.
    ///
    /// # Parameters
    /// * `is_root` — `true` when validating the chain's root
    ///   certificate (`self.index == 0`).
    /// * `prev` — the previously validated certificate, or `None`
    ///   when `is_root` is `true`.
    /// * `curr` — the certificate currently being validated.
    ///
    /// # Returns
    /// * `Ok(&PubKey)` — the public key to verify `curr`'s
    ///   signature with (either `curr.pub_key` for the root or
    ///   `prev.pub_key` for non-roots).
    /// * `Err(HsmError::X509NotSelfSigned)` if `is_root` and the
    ///   issuer/subject names disagree.
    /// * `Err(HsmError::X509IssuerMismatch)` if `prev` is `None` for
    ///   a non-root, or the issuer/subject names disagree.
    /// * `Err(HsmError::X509AkidSkidMismatch)` if both AKID and SKID
    ///   are present but do not match.
    #[inline(never)]
    fn select_verify_key<'a>(
        &self,
        is_root: bool,
        prev: Option<&'a IssuerInfo<'a>>,
        curr: &'a CertInfo<'a>,
    ) -> HsmResult<&'a PubKey<'a>> {
        if is_root {
            if **curr.issuer_raw != **curr.subject_raw {
                return Err(HsmError::X509NotSelfSigned);
            }
            return Ok(&curr.pub_key);
        }

        let prev = prev.ok_or(HsmError::X509IssuerMismatch)?;

        if **curr.issuer_raw != **prev.subject_raw {
            return Err(HsmError::X509IssuerMismatch);
        }

        if let (Some(akid), Some(skid)) = (curr.akid, prev.skid) {
            if akid != skid {
                return Err(HsmError::X509AkidSkidMismatch);
            }
        }

        Ok(&prev.pub_key)
    }

    #[inline(never)]
    fn check_key_usage(curr: &CertInfo<'_>) -> HsmResult<()> {
        let Some(usage) = curr.key_usage else {
            return Ok(());
        };
        let signatures = key_usage::DIGITAL_SIGNATURE | key_usage::NON_REPUDIATION;
        let ca_signatures = if curr
            .basic_constraints
            .is_some_and(|constraints| constraints.ca)
        {
            key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN
        } else {
            0
        };
        let allowed = match curr.pub_key {
            PubKey::MlDsa { .. } => signatures | key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN,
            PubKey::Rsa(key) if key.pss_only => signatures | ca_signatures,
            PubKey::Ec(_) => {
                if usage & (key_usage::ENCIPHER_ONLY | key_usage::DECIPHER_ONLY) != 0
                    && usage & key_usage::KEY_AGREEMENT == 0
                {
                    return Err(HsmError::X509KeyUsageInvalid);
                }
                signatures
                    | ca_signatures
                    | key_usage::KEY_AGREEMENT
                    | key_usage::ENCIPHER_ONLY
                    | key_usage::DECIPHER_ONLY
            }
            PubKey::Rsa(_) => return Ok(()),
        };
        if usage == 0 || usage & !allowed != 0 {
            return Err(HsmError::X509KeyUsageInvalid);
        }
        Ok(())
    }

    /// Apply the CA-only constraints to a non-leaf certificate.
    ///
    /// Enforces:
    /// 1. BasicConstraints is present and `cA == true`.
    /// 2. The remaining permitted CA depth (`max_path_len`) is
    ///    non-zero, and is decremented by one for this certificate.
    /// 3. The certificate's own `pathLenConstraint`, if present,
    ///    further tightens `max_path_len`.
    /// 4. If KeyUsage is present, the `keyCertSign` bit is set.
    ///
    /// # Parameters
    /// * `curr` — the non-leaf (CA) certificate currently being
    ///   validated. The leaf certificate must not be passed here.
    ///
    /// # Returns
    /// * `Ok(())` — all CA constraints are satisfied;
    ///   `self.max_path_len` may have been reduced.
    /// * `Err(HsmError::X509NotCa)` if BasicConstraints is missing
    ///   or has `cA == false`.
    /// * `Err(HsmError::X509PathLenExceeded)` if the remaining path
    ///   budget is zero before this certificate is consumed.
    /// * `Err(HsmError::X509KeyUsageInvalid)` if KeyUsage is present
    ///   but lacks `keyCertSign`.
    #[inline(never)]
    fn apply_ca_constraints(&mut self, curr: &CertInfo<'_>) -> HsmResult<()> {
        let basic_constraints = match curr.basic_constraints {
            Some(constraints) if constraints.ca => constraints,
            _ => return Err(HsmError::X509NotCa),
        };

        if self.max_path_len == 0 {
            return Err(HsmError::X509PathLenExceeded);
        }
        self.max_path_len -= 1;

        if let Some(path_len) = basic_constraints.path_len {
            if path_len < self.max_path_len {
                self.max_path_len = path_len;
            }
        }

        if let Some(key_usage_bits) = curr.key_usage {
            if key_usage_bits & key_usage::KEY_CERT_SIGN == 0 {
                return Err(HsmError::X509KeyUsageInvalid);
            }
        }

        Ok(())
    }

    async fn verify_signature<P>(
        &self,
        pal: &P,
        io: &P::Io,
        alloc: &impl HsmScopedAlloc,
        verify_key: &PubKey<'_>,
        curr: &CertInfo<'_>,
    ) -> HsmResult<()>
    where
        P: HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    {
        match (curr.sig_algo, verify_key) {
            (
                SigAlgo::EcdsaSha256 | SigAlgo::EcdsaSha384 | SigAlgo::EcdsaSha512,
                PubKey::Ec(key),
            ) => self.verify_ecdsa(pal, io, alloc, key, curr).await,
            (SigAlgo::RsaPkcs1(_) | SigAlgo::RsaPss(_), PubKey::Rsa(key)) => {
                self.verify_rsa(pal, io, alloc, key, curr).await
            }
            (
                SigAlgo::MlDsa(param),
                PubKey::MlDsa {
                    param: key_param,
                    key,
                },
            ) if param == *key_param => {
                if curr.signature.len() != param.sig_len() {
                    return Err(HsmError::X509SignatureInvalid);
                }
                let msg = HsmMlDsaMsg::new(HsmMlDsaMsgType::Pure, 0, curr.tbs_raw)?;
                if pal
                    .mldsa_verify(io, param, HsmMlDsaPubKey::Encoded(key), msg, curr.signature)
                    .await?
                {
                    Ok(())
                } else {
                    Err(HsmError::X509SignatureInvalid)
                }
            }
            _ => Err(HsmError::X509UnsupportedAlgorithm),
        }
    }

    async fn verify_rsa<P>(
        &self,
        pal: &P,
        io: &P::Io,
        alloc: &impl HsmScopedAlloc,
        key: &RsaPubKey<'_>,
        curr: &CertInfo<'_>,
    ) -> HsmResult<()>
    where
        P: HsmHash + HsmRsa,
    {
        let hash = curr
            .sig_algo
            .hash_algo()
            .ok_or(HsmError::X509UnsupportedAlgorithm)?;
        let k = key.key_size.modulus_len();
        if key.modulus.len() != k || key.exponent.is_empty() || key.exponent.len() > 4 {
            return Err(HsmError::X509ParseError);
        }
        if !matches!(
            hash,
            HsmHashAlgo::Sha256 | HsmHashAlgo::Sha384 | HsmHashAlgo::Sha512
        ) {
            return Err(HsmError::X509UnsupportedAlgorithm);
        }
        match curr.sig_algo {
            SigAlgo::RsaPkcs1(_) if !key.pss_only => {}
            SigAlgo::RsaPss(params) => {
                if usize::from(params.salt_len) > k - hash.digest_len() - 2 {
                    return Err(HsmError::X509UnsupportedAlgorithm);
                }
                if let Some(restrictions) = key.pss_params {
                    if params.hash != restrictions.hash || params.salt_len < restrictions.salt_len {
                        return Err(HsmError::X509UnsupportedAlgorithm);
                    }
                }
            }
            _ => return Err(HsmError::X509UnsupportedAlgorithm),
        }
        if curr.signature.len() != k || **curr.signature >= **key.modulus {
            return Err(HsmError::X509SignatureInvalid);
        }

        let digest = alloc.dma_alloc(hash.digest_len())?;
        pal.hash(io, hash, curr.tbs_raw, digest, HsmDigestForm::Standard)
            .await?;
        let public = alloc.dma_alloc_zeroed(k + 4)?;
        public[..k].copy_from_slice(key.modulus);
        public[k + 4 - key.exponent.len()..].copy_from_slice(key.exponent);
        byte_order::int_from_be(P::BYTE_ORDER, &mut public[..k]);
        byte_order::int_from_be(P::BYTE_ORDER, &mut public[k..]);
        let signature = alloc.dma_alloc(k)?;
        signature.copy_from_slice(curr.signature);
        byte_order::int_from_be(P::BYTE_ORDER, signature);
        let valid = match curr.sig_algo {
            SigAlgo::RsaPkcs1(_) => {
                pal.rsa_pkcs1_verify(io, key.key_size, hash, public, digest, signature, alloc)
                    .await?
            }
            SigAlgo::RsaPss(params) => {
                pal.rsa_pss_verify(
                    io,
                    key.key_size,
                    hash,
                    public,
                    digest,
                    usize::from(params.salt_len),
                    signature,
                    alloc,
                )
                .await?
            }
            _ => return Err(HsmError::X509UnsupportedAlgorithm),
        };
        if valid {
            Ok(())
        } else {
            Err(HsmError::X509SignatureInvalid)
        }
    }

    /// Verify the ECDSA signature on the current certificate.
    ///
    /// Hashes `curr.tbs_raw` with the algorithm declared in
    /// `curr.sig_algo`, decodes the DER `r || s` signature into a
    /// raw fixed-width buffer, copies the verifier public key into
    /// the hardware's expected wire format (zero-padded coordinates
    /// for P-521), and asks the PAL to verify.
    ///
    /// `curr.tbs_raw` and `verify_key.point` are already in DMA
    /// memory; only the digest, raw signature, and reformatted
    /// public key need temporary DMA allocations from `alloc`.
    ///
    /// # Parameters
    /// * `pal` — PAL providing both [`HsmHash`] and [`HsmEcc`].
    /// * `io` — I/O context for the in-flight HSM operation.
    /// * `alloc` — scoped DMA allocator for the digest, raw
    ///   signature, and public-key buffers.
    /// * `verify_key` — the issuer's EC public key (its `curve`
    ///   field selects the hardware sizes used below).
    /// * `curr` — the certificate whose signature is being
    ///   verified.
    ///
    /// # Returns
    /// * `Ok(())` — the signature is valid for `curr.tbs_raw`
    ///   under `verify_key`.
    /// * `Err(HsmError::X509SignatureInvalid)` if the PAL reports
    ///   the signature is cryptographically invalid.
    /// * Any other [`HsmError`] propagated from `dma_alloc`,
    ///   `pal.hash`, `pal.ecc_verify`, or DER decoding of the raw
    ///   signature.
    async fn verify_ecdsa<P>(
        &self,
        pal: &P,
        io: &P::Io,
        alloc: &impl HsmScopedAlloc,
        verify_key: &EcPubKey<'_>,
        curr: &CertInfo<'_>,
    ) -> HsmResult<()>
    where
        P: HsmHash + HsmEcc,
    {
        let hash_algo = curr
            .sig_algo
            .hash_algo()
            .ok_or(HsmError::X509UnsupportedAlgorithm)?;
        let digest_len = hash_algo.digest_len();
        let curve = verify_key.curve;
        let coord_len = curve.priv_key_len();

        let operand_len = curve.ecdsa_digest_len();
        let digest_dma = alloc.dma_alloc(digest_len.max(operand_len))?;
        pal.hash(
            io,
            hash_algo,
            curr.tbs_raw,
            &mut digest_dma[..digest_len],
            HsmDigestForm::Standard,
        )
        .await?;
        // Truncate the big-endian hash or left-pad it to the PAL's fixed
        // digest field before converting to operand order.
        if digest_len < operand_len {
            let padding = operand_len - digest_len;
            digest_dma.copy_within(..digest_len, padding);
            digest_dma[..padding].fill(0);
        }
        let digest_dma = &mut digest_dma[..operand_len];
        byte_order::int_from_be(P::BYTE_ORDER, digest_dma);

        // X.509 carries the public key and signature as big-endian
        // `x ‖ y` / `r ‖ s`; convert each pair in place to the operand
        // layout `ecc_verify` expects.
        let pk_dma = alloc.dma_alloc(curve.wire_pub_key_len(P::BYTE_ORDER))?;
        let point = verify_key
            .point
            .get(..2 * coord_len)
            .ok_or(HsmError::X509ParseError)?;
        pk_dma[..2 * coord_len].copy_from_slice(point);
        byte_order::pair_from_be(P::BYTE_ORDER, curve, pk_dma)?;

        let sig_dma = alloc.dma_alloc(curve.wire_sig_len(P::BYTE_ORDER))?;
        ecdsa::decode_ecdsa_sig(curr.signature, curve, sig_dma)?;
        byte_order::pair_from_be(P::BYTE_ORDER, curve, sig_dma)?;

        let result_dma = alloc.dma_alloc(4)?;

        pal.ecc_verify(io, curve, pk_dma, digest_dma, sig_dma, result_dma)
            .await?;

        if (result_dma[0] & 1) == 0 {
            Ok(())
        } else {
            Err(HsmError::X509SignatureInvalid)
        }
    }
}

struct ChainWalker<'a> {
    validator: ChainValidator,
    anchor: Option<&'a [u8]>,
    anchored: bool,
    leaf_out: &'a mut [u8],
}

impl ChainWalker<'_> {
    async fn step<P>(
        &mut self,
        pal: &P,
        io: &P::Io,
        alloc: &impl HsmScopedAlloc,
        current: &HsmDmaBuf,
        previous: &HsmDmaBuf,
    ) -> HsmResult<bool>
    where
        P: HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    {
        let current = alloc.alloc_val(parse_cert(current)?)?;
        let previous = if previous.is_empty() {
            None
        } else {
            Some(&*alloc.alloc_val(IssuerInfo::from(&parse_cert(previous)?))?)
        };

        if let Some(anchor) = self.anchor {
            if self.validator.index + 1 < self.validator.chain_len {
                if let PubKey::Ec(key) = &current.pub_key {
                    if &**key.point == anchor {
                        self.anchored = true;
                    }
                }
            }
        }

        match self
            .validator
            .step_with_issuer(pal, io, alloc, previous, current)
            .await
        {
            StepResult::Valid { leaf_pub_key, .. } => {
                if !self.anchored {
                    return Err(HsmError::InvalidArg);
                }
                let point = leaf_pub_key.as_bytes();
                if point.len() != self.leaf_out.len() {
                    return Err(HsmError::InvalidArg);
                }
                self.leaf_out.copy_from_slice(point);
                Ok(true)
            }
            StepResult::NeedNext => Ok(false),
            StepResult::Invalid(error) => Err(error),
        }
    }
}

/// Maximum accepted DER length of a single certificate in a chain.
///
/// Certificate lengths in `descriptors` come from an untrusted request and
/// size the reused DMA buffers, so they are bounded here: a hostile
/// descriptor cannot force an oversized allocation.
/// ML-DSA-87 certificates need roughly 7.5 KiB. The actual DER allocation
/// tracks the largest adjacent pair of descriptors, not this ceiling.
pub const MAX_CERT_DER_LEN: usize = 8192;

/// Walk and validate a certificate chain, root → leaf, returning the
/// leaf public key.
///
/// The chain is described by `descriptors` — one [`CertDescriptor`] per
/// certificate, ordered root (`descriptors[0]`) → leaf
/// (`descriptors[descriptors.len() - 1]`). Each descriptor carries the
/// certificate's byte `length` and an `index` naming where its DER lives
/// out of band. The `fetch` callback is invoked with that `index` (widened
/// to `usize`) and must copy the certificate's DER into the provided DMA
/// buffer; the *source* of the bytes (an OOB SGL block, a side-band buffer,
/// …) is left entirely to the caller. Adjacent certificates remain in
/// disjoint views at opposite ends of one DMA allocation, sized to the
/// largest adjacent pair. Parsing and verification borrow these views
/// without copying DER or issuer bytes. Per-step metadata and crypto
/// scratch are reclaimed before the next fetch, bounding memory use
/// independently of chain depth. The supplied allocator must belong to `io`.
///
/// Per certificate the validator checks the signature, issuer↔
/// subject name chaining, AKID↔SKID, and CA `BasicConstraints`/`KeyUsage`
/// (see [`ChainValidator`]).
///
/// # Anchoring
///
/// * `anchor == None` — the chain is trusted by its self-signed root
///   alone (no external anchor).
/// * `anchor == Some(pubkey)` — some **non-leaf** (issuing) certificate's
///   EC public key MUST equal `pubkey` (raw big-endian `X‖Y`), binding the
///   chain to an external trust anchor (e.g. a policy POTA / SATA key).
///
/// On success `leaf_out` is filled with [`PubKey::as_bytes`]: raw
/// big-endian `X‖Y`, DER RSAPublicKey, or raw ML-DSA bytes. Its length
/// must exactly match. Existing 96-byte leaf consumers remain P-384-only.
///
/// # Errors
///
/// * [`HsmError::InvalidArg`] — empty `descriptors`, a zero-length
///   certificate, `leaf_out`'s length does not match the leaf public-key
///   length, or the `anchor` requirement was not satisfied.
/// * [`HsmError::InternalError`] — the validator did not reach the leaf
///   after every certificate was consumed (internal invariant).
/// * Any [`HsmError`] surfaced by `fetch`, [`parse_cert`], or signature
///   verification.
pub async fn validate_chain<P, F>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    descriptors: &[CertDescriptor],
    anchor: Option<&[u8]>,
    leaf_out: &mut [u8],
    fetch: F,
) -> HsmResult<()>
where
    P: HsmAlloc + HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    F: for<'a> AsyncFnMut(usize, &'a mut HsmDmaBuf) -> HsmResult<()>,
{
    validate_chain_inner(pal, io, alloc, descriptors, anchor, leaf_out, fetch, false).await
}

/// Like [`validate_chain`], but validates the terminal certificate as an
/// issuing CA rather than an end-entity leaf.
///
/// The terminal certificate must then satisfy the CA constraints —
/// `cA == true`, `keyCertSign` (when KeyUsage is present), and the
/// remaining ancestor `pathLenConstraint` budget — because it will go on
/// to sign a further certificate that is not part of this chain (for
/// example a PTA certificate that later signs an on-demand PID leaf). A
/// chain whose ancestors leave no path-length budget for that extra leaf
/// is therefore rejected here rather than silently producing evidence that
/// can never validate. `leaf_out` still receives the terminal
/// certificate's public key.
pub async fn validate_issuing_chain<P, F>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    descriptors: &[CertDescriptor],
    anchor: Option<&[u8]>,
    leaf_out: &mut [u8],
    fetch: F,
) -> HsmResult<()>
where
    P: HsmAlloc + HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    F: for<'a> AsyncFnMut(usize, &'a mut HsmDmaBuf) -> HsmResult<()>,
{
    validate_chain_inner(pal, io, alloc, descriptors, anchor, leaf_out, fetch, true).await
}

#[allow(clippy::too_many_arguments)]
async fn validate_chain_inner<P, F>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    descriptors: &[CertDescriptor],
    anchor: Option<&[u8]>,
    leaf_out: &mut [u8],
    mut fetch: F,
    terminal_is_issuing_ca: bool,
) -> HsmResult<()>
where
    P: HsmAlloc + HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    F: for<'a> AsyncFnMut(usize, &'a mut HsmDmaBuf) -> HsmResult<()>,
{
    if descriptors.is_empty() || descriptors.len() > u16::MAX as usize {
        return Err(HsmError::InvalidArg);
    }

    // Bound and align adjacent DER views before any fetch or allocation.
    let mut capacity = 0usize;
    let mut previous_size = 0usize;
    for d in descriptors {
        let len = usize::from(d.length.get());
        // Lengths come from an untrusted request; reject empty or
        // oversized certificates before they can size a DMA allocation.
        if len == 0 || len > MAX_CERT_DER_LEN {
            return Err(HsmError::InvalidArg);
        }
        let size = len.next_multiple_of(4);
        capacity = capacity.max(previous_size + size);
        previous_size = size;
    }

    let walker = alloc.alloc_val(ChainWalker {
        validator: if terminal_is_issuing_ca {
            ChainValidator::new_issuing(descriptors.len() as u16)
        } else {
            ChainValidator::new(descriptors.len() as u16)
        },
        anchor,
        anchored: anchor.is_none(),
        leaf_out,
    })?;

    let der = alloc.dma_alloc(capacity)?;
    let mut previous_len = 0usize;

    for (i, d) in descriptors.iter().enumerate() {
        let len = usize::from(d.length.get());
        let (curr, previous) = if i % 2 == 0 {
            let (left, right) = der.split_at_mut(len.next_multiple_of(4));
            let previous_start = right.len() - previous_len.next_multiple_of(4);
            (
                &mut left[..len],
                &right[previous_start..previous_start + previous_len],
            )
        } else {
            let (left, right) = der.split_at_mut(capacity - len.next_multiple_of(4));
            (&mut right[..len], &left[..previous_len])
        };
        fetch(usize::from(d.index), curr).await?;

        let complete = pal
            .alloc_scoped_async(io, async |scratch| {
                walker.step(pal, io, scratch, curr, previous).await
            })
            .await?;
        if complete {
            return Ok(());
        }
        previous_len = len;
    }

    // `ChainValidator::new(descriptors.len())` yields `Valid` on the final
    // (leaf) step, so reaching here means the counts disagreed.
    Err(HsmError::InternalError)
}
