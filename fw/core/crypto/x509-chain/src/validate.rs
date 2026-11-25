// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 certificate chain validation state machine.
//!
//! [`ChainValidator`] processes certificates one at a time, from root
//! (index 0) to leaf (index `chain_len - 1`). The streaming walker holds
//! one certificate's DER at a time. After a certificate verifies, only the
//! fields its successor needs (subject, SubjectPublicKeyInfo and SKID) are
//! carried forward in a small bounded buffer, so peak memory is one
//! certificate plus one issuer key rather than two certificates. Scoped
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
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHash;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmMlDsa;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsg;
use tsra_fw_hsm_pal_traits::HsmMlDsaMsgType;
use tsra_fw_hsm_pal_traits::HsmMlDsaParamSet;
use tsra_fw_hsm_pal_traits::HsmMlDsaPubKey;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmRsa;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::ecdsa;
use crate::parse::parse_cert;
use crate::parse::parse_spki;
use crate::spki::mldsa87_spki_thumbprint_in_place;
use crate::spki::p384_spki_thumbprint;
use crate::spki::P384_SPKI_LEN;
use crate::spki::SPKI_THUMBPRINT_LEN;
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
        let is_ca = curr
            .basic_constraints
            .is_some_and(|constraints| constraints.ca);
        if usage == 0 || (usage & key_usage::KEY_CERT_SIGN != 0 && !is_ca) {
            return Err(HsmError::X509KeyUsageInvalid);
        }
        let signatures = key_usage::DIGITAL_SIGNATURE | key_usage::NON_REPUDIATION;
        let ca_signatures = if is_ca {
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
        if usage & !allowed != 0 {
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
        pal.hash(
            io,
            hash,
            curr.tbs_raw,
            HsmDigestForm::Standard,
            Some(digest),
        )
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
                pal.rsa_pkcs1_verify(io, key.key_size, hash, public, digest, signature)
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
    /// memory; only the packed signature-and-digest input and the
    /// reformatted public key need temporary DMA allocations from
    /// `alloc`.
    ///
    /// # Parameters
    /// * `pal` — PAL providing both [`HsmHash`] and [`HsmEcc`].
    /// * `io` — I/O context for the in-flight HSM operation.
    /// * `alloc` — scoped DMA allocator for the packed
    ///   signature-and-digest and public-key buffers.
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
        let curve = verify_key.curve;
        let coord_len = curve.priv_key_len();

        // X.509 carries the public key and signature as big-endian
        // `x ‖ y` / `r ‖ s`; convert each pair in place to the operand
        // layout `ecc_verify` expects.
        let pk_dma = alloc.dma_alloc(curve.wire_pub_key_len(P::ECC_COORD_PAD))?;
        let point = verify_key
            .point
            .get(..2 * coord_len)
            .ok_or(HsmError::X509ParseError)?;
        pk_dma[..2 * coord_len].copy_from_slice(point);
        byte_order::pair_from_be::<P>(curve, pk_dma)?;

        // `r ‖ s ‖ digest`, with the operand-order digest at the start of
        // its zeroed lane; the PAL truncates an over-long digest.
        let input = alloc.dma_alloc(curve.ecdsa_verify_input_len(hash_algo, P::ECC_COORD_PAD))?;
        input.fill(0);
        let (sig, digest) = input.split_at_mut(curve.wire_sig_len(P::ECC_COORD_PAD));
        ecdsa::decode_ecdsa_sig(curr.signature, curve, sig)?;
        byte_order::pair_from_be::<P>(curve, sig)?;
        pal.hash(
            io,
            hash_algo,
            curr.tbs_raw,
            HsmDigestForm::Operand,
            Some(&mut digest[..hash_algo.digest_len()]),
        )
        .await?;

        if pal.ecc_verify(io, curve, hash_algo, pk_dma, input).await? {
            Ok(())
        } else {
            Err(HsmError::X509SignatureInvalid)
        }
    }
}

struct ChainWalker<'a> {
    validator: ChainValidator,
    anchor: Option<&'a [u8; SPKI_THUMBPRINT_LEN]>,
    anchored: bool,
    leaf: LeafSink<'a>,
    /// Bytes of the leaf public key written to [`LeafSink::Out`].
    leaf_len: usize,
}

/// What chain validation does with the validated leaf public key
/// ([`PubKey::as_bytes`] form).
pub enum LeafSink<'a> {
    /// Discard it (issuing-chain validation).
    None,
    /// Copy it into the prefix of the buffer.
    Out(&'a mut [u8]),
    /// Require it to equal these bytes, compared in place without a copy.
    Expect(&'a [u8]),
}

impl ChainWalker<'_> {
    async fn step<P>(
        &mut self,
        pal: &P,
        io: &P::Io,
        alloc: &impl HsmScopedAlloc,
        current: &HsmDmaBuf,
        previous: Option<&IssuerInfo<'_>>,
    ) -> HsmResult<bool>
    where
        P: HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    {
        let current = alloc.alloc_val(parse_cert(current)?)?;

        // Trust-anchor binding: some non-leaf (issuing) P-384 or
        // ML-DSA-87 certificate's public-key thumbprint must equal the
        // anchor.
        if let Some(anchor) = self.anchor {
            if !self.anchored && self.validator.index + 1 < self.validator.chain_len {
                self.anchored = match &current.pub_key {
                    PubKey::Ec(key) if key.curve == HsmEccCurve::P384 => {
                        let spki = alloc.dma_alloc(P384_SPKI_LEN)?;
                        let thumb = alloc.dma_alloc(SPKI_THUMBPRINT_LEN)?;
                        p384_spki_thumbprint(pal, io, spki, key.point, thumb).await?;
                        &thumb[..] == anchor.as_slice()
                    }
                    // Hash the SPKI in place: copying a 2.6 KiB ML-DSA
                    // SPKI would not fit beside the DER and issuer carry.
                    PubKey::MlDsa {
                        param: HsmMlDsaParamSet::MlDsa87,
                        ..
                    } => {
                        let thumb = alloc.dma_alloc(SPKI_THUMBPRINT_LEN)?;
                        mldsa87_spki_thumbprint_in_place(pal, io, current.spki_raw, thumb).await?;
                        &thumb[..] == anchor.as_slice()
                    }
                    _ => false,
                };
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
                match &mut self.leaf {
                    LeafSink::None => {}
                    LeafSink::Out(leaf_out) => {
                        let out = leaf_out
                            .get_mut(..point.len())
                            .ok_or(HsmError::InvalidArg)?;
                        out.copy_from_slice(point);
                    }
                    LeafSink::Expect(expected) => {
                        if point != *expected {
                            return Err(HsmError::InvalidArg);
                        }
                    }
                }
                self.leaf_len = point.len();
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
/// size the reused DMA buffer, so they are bounded here: a hostile
/// descriptor cannot force an oversized allocation.
/// ML-DSA-87 certificates need roughly 7.5 KiB. The actual DER allocation
/// tracks the largest descriptor, not this ceiling.
pub const MAX_CERT_DER_LEN: usize = 8192;

/// Maximum bytes carried forward from a verified issuer to its successor:
/// raw subject Name, SubjectPublicKeyInfo and SKID.  Covers an ML-DSA-87
/// SPKI (2614 bytes) with room for a generous subject; an issuer exceeding
/// it is rejected.
pub const MAX_ISSUER_CARRY_LEN: usize = 3584;

/// Lengths of the issuer fields held in the carry buffer, laid out as
/// `subject ‖ spki ‖ skid`.
#[derive(Clone, Copy)]
struct IssuerCarry {
    subject_len: usize,
    spki_len: usize,
    skid_len: Option<usize>,
}

impl IssuerCarry {
    /// Copy `cert`'s issuer-side fields into `carry`.
    fn store(cert: &CertInfo<'_>, carry: &mut HsmDmaBuf) -> HsmResult<Self> {
        let subject: &[u8] = cert.subject_raw;
        let spki: &[u8] = cert.spki_raw;
        let skid = cert.skid.unwrap_or(&[]);
        let total = subject.len() + spki.len() + skid.len();
        if total > carry.len() {
            return Err(HsmError::InvalidArg);
        }
        let (dst_subject, rest) = carry.split_at_mut(subject.len());
        let (dst_spki, rest) = rest.split_at_mut(spki.len());
        dst_subject.copy_from_slice(subject);
        dst_spki.copy_from_slice(spki);
        rest[..skid.len()].copy_from_slice(skid);
        Ok(Self {
            subject_len: subject.len(),
            spki_len: spki.len(),
            skid_len: cert.skid.map(<[u8]>::len),
        })
    }

    /// Rebuild the issuer view over `carry`.
    fn view(self, carry: &HsmDmaBuf) -> HsmResult<IssuerInfo<'_>> {
        let spki_end = self.subject_len + self.spki_len;
        let spki: &[u8] = &carry[self.subject_len..spki_end];
        Ok(IssuerInfo {
            pub_key: parse_spki(carry, spki)?,
            subject_raw: &carry[..self.subject_len],
            skid: self.skid_len.map(|len| {
                let skid: &[u8] = &carry[spki_end..spki_end + len];
                skid
            }),
        })
    }
}

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
/// …) is left entirely to the caller. One DMA buffer, sized to the largest
/// descriptor, is reused for every certificate; after a certificate
/// verifies, only its subject, SubjectPublicKeyInfo and SKID (at most
/// [`MAX_ISSUER_CARRY_LEN`] bytes) are carried forward to verify the next.
/// Per-step metadata and crypto scratch are reclaimed before the next
/// fetch, bounding memory use independently of chain depth. The supplied
/// allocator must belong to `io`.
///
/// Per certificate the validator checks the signature, issuer↔
/// subject name chaining, AKID↔SKID, and CA `BasicConstraints`/`KeyUsage`
/// (see [`ChainValidator`]).
///
/// # Anchoring
///
/// * `anchor == None` — the chain is trusted by its self-signed root
///   alone (no external anchor).
/// * `anchor == Some(thumbprint)` — some **non-leaf** (issuing)
///   certificate's P-384 or ML-DSA-87 SubjectPublicKeyInfo thumbprint (see
///   [`p384_spki_thumbprint`] and [`mldsa87_spki_thumbprint`]) MUST equal
///   `thumbprint`, binding the chain to an external trust anchor (e.g. a
///   policy POTA / SATA key).
///
/// On success the prefix of `leaf_out` is filled with [`PubKey::as_bytes`]:
/// raw big-endian `X‖Y`, DER RSAPublicKey, or raw ML-DSA bytes, and its
/// length is returned. Callers classify the key by that length.
///
/// # Errors
///
/// * [`HsmError::InvalidArg`] — empty `descriptors`, a zero-length or
///   oversized certificate, an issuer whose carried fields exceed
///   [`MAX_ISSUER_CARRY_LEN`], `leaf_out` is smaller than the leaf
///   public key, or the `anchor` requirement was not satisfied.
/// * [`HsmError::InternalError`] — the validator did not reach the leaf
///   after every certificate was consumed (internal invariant).
/// * Any [`HsmError`] surfaced by `fetch`, [`parse_cert`], or signature
///   verification.
pub async fn validate_chain<P, F>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    descriptors: &[CertDescriptor],
    anchor: Option<&[u8; SPKI_THUMBPRINT_LEN]>,
    leaf_out: &mut [u8],
    fetch: F,
) -> HsmResult<usize>
where
    P: HsmAlloc + HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    F: for<'a> AsyncFnMut(usize, &'a mut HsmDmaBuf) -> HsmResult<()>,
{
    validate_chain_inner(
        pal,
        io,
        alloc,
        descriptors,
        anchor,
        LeafSink::Out(leaf_out),
        fetch,
        false,
    )
    .await
    .map(|(_, leaf_len)| leaf_len)
}

/// Like [`validate_chain`], but with the leaf public key handled by `leaf`
/// (e.g. [`LeafSink::Expect`] compares it in place, so callers can check
/// that several chains certify one key without a second leaf-sized
/// buffer). Returns the leaf public key length.
///
/// # Errors
///
/// As [`validate_chain`]; additionally [`HsmError::InvalidArg`] when the
/// leaf public key differs from a [`LeafSink::Expect`] key.
pub async fn validate_chain_into<P, F>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    descriptors: &[CertDescriptor],
    anchor: Option<&[u8; SPKI_THUMBPRINT_LEN]>,
    leaf: LeafSink<'_>,
    fetch: F,
) -> HsmResult<usize>
where
    P: HsmAlloc + HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    F: for<'a> AsyncFnMut(usize, &'a mut HsmDmaBuf) -> HsmResult<()>,
{
    validate_chain_inner(pal, io, alloc, descriptors, anchor, leaf, fetch, false)
        .await
        .map(|(_, leaf_len)| leaf_len)
}

/// Like [`validate_chain`], but validates the terminal certificate as an
/// issuing CA rather than an end-entity leaf, and returns the terminal
/// certificate's verified DER.
///
/// The terminal certificate must then satisfy the CA constraints —
/// `cA == true`, `keyCertSign` (when KeyUsage is present), and the
/// remaining ancestor `pathLenConstraint` budget — because it will go on
/// to sign a further certificate that is not part of this chain (for
/// example a PTA certificate that later signs an on-demand PID leaf). A
/// chain whose ancestors leave no path-length budget for that extra leaf
/// is therefore rejected here rather than silently producing evidence that
/// can never validate.
///
/// The returned DER lives in `alloc` and is exactly the bytes whose
/// signature was verified, so callers can parse it for further profile
/// checks without re-reading host-controlled memory.
pub async fn validate_issuing_chain<'a, P, F>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    descriptors: &[CertDescriptor],
    anchor: Option<&[u8; SPKI_THUMBPRINT_LEN]>,
    fetch: F,
) -> HsmResult<&'a HsmDmaBuf>
where
    P: HsmAlloc + HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    F: for<'b> AsyncFnMut(usize, &'b mut HsmDmaBuf) -> HsmResult<()>,
{
    validate_chain_inner(
        pal,
        io,
        alloc,
        descriptors,
        anchor,
        LeafSink::None,
        fetch,
        true,
    )
    .await
    .map(|(der, _)| der)
}

#[allow(clippy::too_many_arguments)]
async fn validate_chain_inner<'a, P, F>(
    pal: &P,
    io: &P::Io,
    alloc: &'a impl HsmScopedAlloc,
    descriptors: &[CertDescriptor],
    anchor: Option<&[u8; SPKI_THUMBPRINT_LEN]>,
    leaf: LeafSink<'_>,
    mut fetch: F,
    terminal_is_issuing_ca: bool,
) -> HsmResult<(&'a HsmDmaBuf, usize)>
where
    P: HsmAlloc + HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
    F: for<'b> AsyncFnMut(usize, &'b mut HsmDmaBuf) -> HsmResult<()>,
{
    let (terminal, issuers) = descriptors.split_last().ok_or(HsmError::InvalidArg)?;
    if descriptors.len() > u16::MAX as usize {
        return Err(HsmError::InvalidArg);
    }

    // Bound every length before any fetch or allocation.  Lengths come
    // from an untrusted request; reject empty or oversized certificates
    // before they can size a DMA allocation.
    let mut der_capacity = 0usize;
    for d in descriptors {
        let len = usize::from(d.length.get());
        if len == 0 || len > MAX_CERT_DER_LEN {
            return Err(HsmError::InvalidArg);
        }
        der_capacity = der_capacity.max(len);
    }
    // An issuer's carried fields are a strict subset of its DER.
    let carry_capacity = issuers
        .iter()
        .map(|d| usize::from(d.length.get()))
        .max()
        .unwrap_or(0)
        .min(MAX_ISSUER_CARRY_LEN);

    let walker = alloc.alloc_val(ChainWalker {
        validator: if terminal_is_issuing_ca {
            ChainValidator::new_issuing(descriptors.len() as u16)
        } else {
            ChainValidator::new(descriptors.len() as u16)
        },
        anchor,
        anchored: anchor.is_none(),
        leaf,
        leaf_len: 0,
    })?;

    let der = alloc.dma_alloc(der_capacity)?;
    let carry = alloc.dma_alloc(carry_capacity.max(1))?;
    let mut issuer: Option<IssuerCarry> = None;

    for d in issuers {
        let curr = &mut der[..usize::from(d.length.get())];
        fetch(usize::from(d.index), curr).await?;
        walk_one(pal, io, walker, curr, carry, &mut issuer, false).await?;
    }

    let len = usize::from(terminal.length.get());
    let curr = &mut der[..len];
    fetch(usize::from(terminal.index), curr).await?;
    walk_one(pal, io, walker, curr, carry, &mut issuer, true).await?;
    let leaf_len = walker.leaf_len;
    let der: &'a HsmDmaBuf = der;
    Ok((&der[..len], leaf_len))
}

/// Validate the fetched certificate `cert` against the carried `issuer`;
/// unless it is the `terminal` certificate, carry its issuer fields
/// forward.
///
/// Kept separate from (and not generic over the fetch callback of)
/// [`validate_chain_inner`], so every caller shares one copy.
async fn walk_one<P>(
    pal: &P,
    io: &P::Io,
    walker: &mut ChainWalker<'_>,
    cert: &HsmDmaBuf,
    carry: &mut HsmDmaBuf,
    issuer: &mut Option<IssuerCarry>,
    terminal: bool,
) -> HsmResult<()>
where
    P: HsmAlloc + HsmHash + HsmEcc + HsmRsa + HsmMlDsa,
{
    let carried: &HsmDmaBuf = carry;
    let complete = pal
        .alloc_scoped_async(io, async |scratch| {
            let previous = issuer.map(|i| i.view(carried)).transpose()?;
            walker.step(pal, io, scratch, cert, previous.as_ref()).await
        })
        .await?;
    // The validator yields `Valid` exactly on the final step.
    if complete != terminal {
        return Err(HsmError::InternalError);
    }
    if !terminal {
        *issuer = Some(IssuerCarry::store(&parse_cert(cert)?, carry)?);
    }
    Ok(())
}
