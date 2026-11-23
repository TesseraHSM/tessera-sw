// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmEcc`] implementation for the standard (host-native) PAL.
//!
//! Thin delegation layer between the trait boundary (raw HSM
//! wire-format bytes) and the
//! [`StdEcc`](crate::drivers::ecc::StdEcc) driver (OpenSSL key
//! handles + PAL operand-order byte interfaces).  Responsibilities at this
//! layer are deliberately limited to:
//!
//! 1. **Enum mapping** — [`HsmEccCurve`] → [`tsra_crypto::EccCurve`].
//! 2. **Private-key HSM round-trip** — exporting a freshly generated
//!    handle to the raw HSM scalar in [`ecc_gen_keypair`] and
//!    importing the scalar back into a handle in [`ecc_sign`] /
//!    [`ecdh_derive`].
//! 3. **Delegation** — every operand-order ↔ OpenSSL-BE conversion
//!    lives inside the driver's `_op`-suffixed methods (a no-op on
//!    big-endian PALs), so this layer is free of byte-shuffling
//!    boilerplate.
//!
//! ## Key formats at the trait boundary
//!
//! | Direction | Private key | Public key |
//! |-----------|-------------|------------|
//! | Trait → PAL (input)  | Big-endian scalar `&HsmDmaBuf` (`wire_coord_len` bytes) | Operand-order `x \|\| y` `&HsmDmaBuf` (`wire_pub_key_len` bytes) |
//! | PAL → Trait (output) | Big-endian scalar `&mut HsmDmaBuf` (`wire_coord_len` bytes) | Operand-order `x \|\| y` `&mut HsmDmaBuf` (`wire_pub_key_len` bytes) |
//! | PAL → Driver (internal) | `EccPrivateKey` handle | Operand-order bytes (`_op` slices) |
//! | Driver → OpenSSL (internal) | `EccPrivateKey` handle | `EccPublicKey` handle (raw BE coords) |
//!
//! The trait-level [`HsmEcc::ecc_gen_keypair`] query mode reports
//! [`HsmEccCurve::wire_coord_len`] as the private-key length and
//! [`HsmEccCurve::wire_pub_key_len`] as the public-key length; use
//! mode returns the same deterministic sizes.

use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EccPublicKey;
use tsra_crypto::HashAlgo;
use tsra_crypto::PrivateKey;
use zeroize::Zeroizing;

use super::*;
use crate::drivers::ecc::export_priv;
use crate::drivers::ecc::import_priv;
use crate::drivers::ecc::EccForm;

/// Domain-separation label for the PTA keypair HKDF-Expand.
///
/// Byte-identical to the uno PAL's private copy
/// (`fw/plat/uno/fw/pal/src/crypto/ecc_det.rs`) so the two platforms
/// share one label to rotate, but note that a shared label alone does
/// **not** make the derivations agree: the info strings, OKM lengths
/// and FIPS 186-5 §A.2 methods differ (see
/// [`HsmEcc::ecc_gen_keypair_from_root`]), so the derived keypair is
/// platform-specific by construction.
const KEYPAIR_LABEL_PTA: &[u8] = b"TSRA-PartInit-PTA-v1";

/// Map the PAL-level [`HsmEccCurve`] to the crypto library's
/// [`tsra_crypto::EccCurve`].
fn to_ecc_curve(curve: HsmEccCurve) -> EccCurve {
    match curve {
        HsmEccCurve::P256 => EccCurve::P256,
        HsmEccCurve::P384 => EccCurve::P384,
        HsmEccCurve::P521 => EccCurve::P521,
    }
}

/// Map the crypto library's [`tsra_crypto::EccCurve`] back to the
/// PAL-level [`HsmEccCurve`].
fn from_ecc_curve(curve: EccCurve) -> HsmEccCurve {
    match curve {
        EccCurve::P256 => HsmEccCurve::P256,
        EccCurve::P384 => HsmEccCurve::P384,
        EccCurve::P521 => HsmEccCurve::P521,
    }
}

/// Checks an ECDSA input of `lanes` coordinate lanes followed by a digest
/// lane against the trait contract, and returns the digest's range.
///
/// # Errors
/// * [`HsmError::UnsupportedDigestHashAlgorithm`] — `hash` is not SHA-1 or
///   SHA-2.
/// * [`HsmError::InvalidArg`] — `input` has the wrong length, or a byte
///   after the digest in its lane is not zero.
fn ecdsa_digest_range(
    curve: HsmEccCurve,
    hash: HsmHashAlgo,
    lanes: usize,
    input: &[u8],
) -> HsmResult<core::ops::Range<usize>> {
    if !matches!(
        hash,
        HsmHashAlgo::Sha1 | HsmHashAlgo::Sha256 | HsmHashAlgo::Sha384 | HsmHashAlgo::Sha512
    ) {
        return Err(HsmError::UnsupportedDigestHashAlgorithm);
    }
    let pad = StdHsmPal::ECC_COORD_PAD;
    let at = lanes * curve.wire_coord_len(pad);
    let end = at + hash.digest_len();
    if input.len() != at + curve.ecdsa_digest_lane_len(hash, pad)
        || input[end..].iter().any(|&b| b != 0)
    {
        return Err(HsmError::InvalidArg);
    }
    Ok(at..end)
}

/// Checks the ECDSA nonce source: OpenSSL always generates `k`.
fn check_nonce(nonce: HsmEcdsaNonce) -> HsmResult<()> {
    match nonce {
        HsmEcdsaNonce::Generated => Ok(()),
        HsmEcdsaNonce::Supplied => Err(HsmError::CryptoUnsupportedMode),
    }
}

impl StdHsmPal {
    pub(crate) fn ecc_public_from_wire(
        curve: EccCurve,
        wire: &[u8],
        form: EccForm,
    ) -> HsmResult<EccPublicKey> {
        let coord_len = curve.point_size();
        let wire_len = from_ecc_curve(curve).wire_coord_len(form.pad);
        if wire.len() != 2 * wire_len {
            return Err(HsmError::InvalidArg);
        }
        let mut x = [0u8; 66];
        let mut y = [0u8; 66];
        for (src, dst) in [(wire, &mut x[..]), (&wire[wire_len..], &mut y[..])] {
            if src[coord_len..wire_len].iter().any(|&byte| byte != 0) {
                return Err(HsmError::InvalidArg);
            }
            if form.order.is_be() {
                dst[..coord_len].copy_from_slice(&src[..coord_len]);
            } else {
                for (d, s) in dst[..coord_len]
                    .iter_mut()
                    .zip(src[..coord_len].iter().rev())
                {
                    *d = *s;
                }
            }
        }
        EccPublicKey::from_coordinates(curve, &x[..coord_len], &y[..coord_len])
            .map_err(|_| HsmError::EccPublicKeyValidationFailed)
    }

    pub(crate) async fn ecc_pair_pct(
        &self,
        private: &EccPrivateKey,
        public: &EccPublicKey,
        pct: HsmEccPct,
    ) -> HsmResult<bool> {
        if matches!(pct, HsmEccPct::None) {
            return Ok(true);
        }
        let curve = private.curve();
        if !matches!(pct, HsmEccPct::None) {
            let derived = private
                .public_key()
                .map_err(|_| HsmError::EccGenerateError)?;
            let len = from_ecc_curve(curve).pub_key_len();
            let mut expected = [0u8; 136];
            let mut actual = [0u8; 136];
            self.ecc
                .pub_coords(&derived, EccForm::BE, &mut expected[..len])
                .await?;
            self.ecc
                .pub_coords(public, EccForm::BE, &mut actual[..len])
                .await?;
            if expected[..len] != actual[..len] {
                return Ok(false);
            }
        }
        let result = match pct {
            HsmEccPct::None => Ok(true),
            HsmEccPct::SignVerify => {
                let mut digest = [0u8; 64];
                let (algo, digest_len) = match curve {
                    EccCurve::P256 => (HashAlgo::sha256(), 32),
                    EccCurve::P384 => (HashAlgo::sha384(), 48),
                    EccCurve::P521 => (HashAlgo::sha512(), 64),
                };
                self.hash
                    .hash(algo, &[100u8; 68], &mut digest[..digest_len])
                    .await?;
                let signature = self.ecc.ecc_sign(private, &digest[..digest_len]).await?;
                self.ecc
                    .ecc_verify(public, &digest[..digest_len], &signature)
                    .await
            }
            HsmEccPct::KeyAgreement => {
                let mut scalar = [0x11u8; 66];
                let len = curve.point_size();
                scalar[0] = 0;
                let peer = EccPrivateKey::from_scalar(curve, &scalar[..len])
                    .map_err(|_| HsmError::EccGenerateError)?;
                let peer_public = peer.public_key().map_err(|_| HsmError::EccGenerateError)?;
                let mut first = Zeroizing::new([0u8; 66]);
                let mut second = Zeroizing::new([0xffu8; 66]);
                self.ecc
                    .ecdh_derive(private, &peer_public, &mut first[..len])
                    .await?;
                self.ecc
                    .ecdh_derive(&peer, public, &mut second[..len])
                    .await?;
                let diff = first[..len]
                    .iter()
                    .zip(&second[..len])
                    .fold(0u8, |diff, (a, b)| diff | (a ^ b));
                Ok(core::hint::black_box(diff) == 0)
            }
        };
        #[cfg(test)]
        if self.ecc_pct_fail.get() {
            return Ok(false);
        }
        result
    }
}

impl HsmEcc for StdHsmPal {
    /// Generate an ECC key pair on the specified curve, query-alloc-use
    /// style.
    ///
    /// In **query mode** (`out = None`) returns the std-PAL upper
    /// bounds: raw HSM scalar size for the private key
    /// ([`HsmEccCurve::wire_coord_len`]) and the wire-format LE
    /// public-key length ([`HsmEccCurve::wire_pub_key_len`]). In
    /// **use mode** (`out = Some((priv_out, pub_out))`) it asks the
    /// driver to generate a fresh keypair and write the wire-LE
    /// public key into internally scoped scratch, then exports the
    /// private key as raw HSM-format scalar bytes into a separate
    /// scratch slot, and finally copies both into the caller's two
    /// output buffers.  Returns the actual byte counts written
    /// (both deterministic for raw HSM bytes).
    async fn ecc_gen_keypair(
        &self,
        io: &StdHsmIo,
        curve: HsmEccCurve,
        pct: HsmEccPct,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let priv_len = curve.wire_coord_len(StdHsmPal::ECC_COORD_PAD);
        let wire_pub_len = curve.wire_pub_key_len(StdHsmPal::ECC_COORD_PAD);

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, wire_pub_len));
        };

        if priv_out.len() < priv_len || pub_out.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            // Use the contiguous `priv || pub` workspace a real PKA
            // engine would write into.  The driver fills the pub half
            // directly in operand order; we vault-serialize the priv half
            // ourselves.
            let scratch = scope.dma_alloc(priv_len + wire_pub_len)?;
            let (scratch_priv, scratch_pub) = scratch.split_at_mut(priv_len);

            let (pk, pub_key) = self.ecc.gen_keypair(to_ecc_curve(curve)).await?;
            self.ecc
                .pub_coords(&pub_key, EccForm::of::<StdHsmPal>(), scratch_pub)
                .await?;
            export_priv(&pk, scratch_priv)?;
            if !matches!(pct, HsmEccPct::None) {
                let vault_key = import_priv(&scratch_priv[..priv_len])
                    .map_err(|_| HsmError::PctValidationEccGenKeyFailed)?;
                let output_public = Self::ecc_public_from_wire(
                    to_ecc_curve(curve),
                    scratch_pub,
                    EccForm::of::<Self>(),
                )
                .map_err(|_| HsmError::PctValidationEccGenKeyFailed)?;
                if !self.ecc_pair_pct(&vault_key, &output_public, pct).await? {
                    return Err(HsmError::PctValidationEccGenKeyFailed);
                }
            }

            priv_out[..priv_len].copy_from_slice(&scratch_priv[..priv_len]);
            pub_out[..wire_pub_len].copy_from_slice(scratch_pub);

            Ok((priv_len, wire_pub_len))
        })
        .await
    }

    /// Deterministically derive an ECC keypair from the `PartRoot`.
    ///
    /// Software (§A.2.1) counterpart to the uno PAL: HKDF-Expand-SHA384
    /// the `PartRoot` into `a2_1_okm_len` bytes of OKM (info =
    /// `KEYPAIR_LABEL_PTA ‖ u16_be(okm_len)`), then apply FIPS 186-5
    /// §A.2.1 extra-random-bits reduction.
    ///
    /// The uno PAL uses a different info string, OKM length and §A.2
    /// method (§A.2.2 rejection sampling — its PKA cannot reduce by the
    /// even `n − 1`), so an identical `PartRoot` yields a **different**
    /// keypair there. Determinism is per-platform; see the trait doc.
    async fn ecc_gen_keypair_from_root(
        &self,
        io: &StdHsmIo,
        curve: HsmEccCurve,
        root: &HsmDmaBuf,
        pct: HsmEccPct,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        let priv_len = curve.wire_coord_len(StdHsmPal::ECC_COORD_PAD);
        let wire_pub_len = curve.wire_pub_key_len(StdHsmPal::ECC_COORD_PAD);

        // `root` is the derivation input in both modes, so validate it
        // before the query-mode return — the documented `InvalidArg` on a
        // wrong-sized root must not depend on `out`. Mirrors the uno PAL.
        if root.len() != priv_len {
            return Err(HsmError::InvalidArg);
        }

        let Some((priv_out, pub_out)) = out else {
            return Ok((priv_len, wire_pub_len));
        };

        if priv_out.len() < priv_len || pub_out.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }

        self.alloc_scoped_async(io, async |scope| {
            let info_len = KEYPAIR_LABEL_PTA.len() + 2;
            let info_aligned_len = info_len.next_multiple_of(4);
            let okm_len = to_ecc_curve(curve).a2_1_okm_len();
            let workspace_len = (info_aligned_len + okm_len).max(priv_len + wire_pub_len);
            let workspace = scope.dma_alloc(workspace_len)?;
            // Derive the §A.2.1 OKM from PartRoot: HKDF-Expand-SHA384 with
            // info = KEYPAIR_LABEL_PTA ‖ u16_be(okm_len). Mirrors the uno
            // PAL's domain separation so both platforms fan out of the same
            // PartRoot.
            let (info, rest) = workspace.split_at_mut(info_aligned_len);
            let info = &mut info[..info_len];
            info[..KEYPAIR_LABEL_PTA.len()].copy_from_slice(KEYPAIR_LABEL_PTA);
            info[KEYPAIR_LABEL_PTA.len()..].copy_from_slice(&(okm_len as u16).to_be_bytes());
            let okm = &mut rest[..okm_len];

            self.hkdf_expand(io, HsmHashAlgo::Sha384, root, Some(&*info), &mut *okm)
                .await?;
            let pk = EccPrivateKey::from_okm_a2_1(to_ecc_curve(curve), &*okm)
                .map_err(|_| HsmError::EccGenerateError)?;

            let scratch = &mut workspace[..priv_len + wire_pub_len];
            let (scratch_priv, scratch_pub) = scratch.split_at_mut(priv_len);

            export_priv(&pk, scratch_priv)?;
            let pub_key = pk
                .public_key()
                .map_err(|_| HsmError::EccGetCoordinatesError)?;
            self.ecc
                .pub_coords(&pub_key, EccForm::of::<StdHsmPal>(), scratch_pub)
                .await?;
            if !matches!(pct, HsmEccPct::None) {
                let vault_key = import_priv(&scratch_priv[..priv_len])
                    .map_err(|_| HsmError::PctValidationEccGenKeyFailed)?;
                let output_public = Self::ecc_public_from_wire(
                    to_ecc_curve(curve),
                    scratch_pub,
                    EccForm::of::<Self>(),
                )
                .map_err(|_| HsmError::PctValidationEccGenKeyFailed)?;
                if !self.ecc_pair_pct(&vault_key, &output_public, pct).await? {
                    return Err(HsmError::PctValidationEccGenKeyFailed);
                }
            }
            priv_out[..priv_len].copy_from_slice(&scratch_priv[..priv_len]);
            pub_out[..wire_pub_len].copy_from_slice(scratch_pub);

            Ok((priv_len, wire_pub_len))
        })
        .await
    }

    /// ECDSA sign over a pre-computed digest.
    ///
    /// Parses the vault-format private key into an OpenSSL handle and
    /// delegates to the driver's operand-order sign method, which
    /// performs the byte-order conversions internally.
    async fn ecc_sign(
        &self,
        _io: &StdHsmIo,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        nonce: HsmEcdsaNonce,
        input: &mut HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let digest = ecdsa_digest_range(curve, hash, 1, input)?;
        check_nonce(nonce)?;
        let wire_len = curve.wire_sig_len(StdHsmPal::ECC_COORD_PAD);
        if priv_key.len() != curve.wire_priv_key_len(Self::ECC_COORD_PAD) {
            return Err(HsmError::InvalidArg);
        }
        let Some(signature) = out else {
            return Ok(wire_len);
        };
        if signature.len() < wire_len {
            return Err(HsmError::InvalidArg);
        }
        let key = import_priv(priv_key)?;
        self.ecc
            .ecc_sign_op(&key, &input[digest], &mut signature[..wire_len])
            .await?;
        Ok(wire_len)
    }

    /// ECDSA sign, writing `r ‖ s` over the start of `k_sig`.
    ///
    /// OpenSSL signs from a copy of the digest, so the signature is staged
    /// on the stack before it overwrites the input.
    async fn ecc_sign_in_place(
        &self,
        _io: &StdHsmIo,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        priv_key: &HsmDmaBuf,
        nonce: HsmEcdsaNonce,
        k_sig: &mut HsmDmaBuf,
    ) -> HsmResult<usize> {
        let digest = ecdsa_digest_range(curve, hash, 1, k_sig)?;
        check_nonce(nonce)?;
        let wire_len = curve.wire_sig_len(StdHsmPal::ECC_COORD_PAD);
        if priv_key.len() != curve.wire_priv_key_len(Self::ECC_COORD_PAD) {
            return Err(HsmError::InvalidArg);
        }
        let key = import_priv(priv_key)?;
        let mut signature = [0u8; 144];
        self.ecc
            .ecc_sign_op(&key, &k_sig[digest], &mut signature[..wire_len])
            .await?;
        k_sig[..wire_len].copy_from_slice(&signature[..wire_len]);
        Ok(wire_len)
    }

    /// ECDSA verify of `r ‖ s` over a pre-computed digest.
    ///
    /// Delegates to the driver's operand-order verify method which
    /// constructs the OpenSSL pub-key handle from the operand-order
    /// coordinates and performs byte-order conversions internally.
    async fn ecc_verify(
        &self,
        _io: &StdHsmIo,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
        pub_key: &HsmDmaBuf,
        input: &HsmDmaBuf,
    ) -> HsmResult<bool> {
        let digest = ecdsa_digest_range(curve, hash, 2, input)?;
        let wire_pub_len = curve.wire_pub_key_len(StdHsmPal::ECC_COORD_PAD);
        let wire_sig_len = curve.wire_sig_len(StdHsmPal::ECC_COORD_PAD);
        if pub_key.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }
        self.ecc
            .ecc_verify_op(
                to_ecc_curve(curve),
                &pub_key[..wire_pub_len],
                &input[digest],
                &input[..wire_sig_len],
            )
            .await
    }

    /// Derive the public key from a raw private scalar (`pub = priv · G`).
    ///
    /// Delegates to the driver's `pub_from_priv_op`, which runs the
    /// OpenSSL key reconstruction and public-point derivation on the
    /// worker pool and emits the operand-order form.
    async fn ecc_pub_from_priv(
        &self,
        _io: &StdHsmIo,
        curve: HsmEccCurve,
        priv_key: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let wire_priv_len = curve.wire_priv_key_len(StdHsmPal::ECC_COORD_PAD);
        let wire_pub_len = curve.wire_pub_key_len(StdHsmPal::ECC_COORD_PAD);
        if priv_key.len() != wire_priv_len {
            return Err(HsmError::InvalidArg);
        }
        let Some(pub_key) = out else {
            Self::ecc_private_curve(priv_key)?;
            return Ok(wire_pub_len);
        };
        if pub_key.len() < wire_pub_len {
            return Err(HsmError::InvalidArg);
        }
        self.ecc
            .pub_from_priv_op(
                to_ecc_curve(curve),
                &priv_key[..wire_priv_len],
                &mut pub_key[..wire_pub_len],
            )
            .await?;
        Ok(wire_pub_len)
    }

    /// ECDH key agreement — derives a shared secret.
    ///
    /// Parses the local vault-format private key into an OpenSSL
    /// handle and delegates to the driver's operand-order ECDH method
    /// which constructs the remote pub-key handle internally from
    /// the operand-order coordinates.
    async fn ecdh_derive(
        &self,
        _io: &StdHsmIo,
        curve: HsmEccCurve,
        priv_key: &HsmDmaBuf,
        pub_key: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let wire_pub_len = curve.wire_pub_key_len(StdHsmPal::ECC_COORD_PAD);
        if priv_key.len() != curve.wire_priv_key_len(Self::ECC_COORD_PAD)
            || pub_key.len() < wire_pub_len
        {
            return Err(HsmError::InvalidArg);
        }
        let secret_len = curve.secret_len();
        let Some(secret) = out else {
            return Ok(secret_len);
        };
        if secret.len() < secret_len {
            return Err(HsmError::InvalidArg);
        }
        let pk = import_priv(priv_key)?;
        self.ecc
            .ecdh_derive_op(
                &pk,
                to_ecc_curve(curve),
                &pub_key[..wire_pub_len],
                &mut secret[..secret_len],
            )
            .await?;
        Ok(secret_len)
    }

    async fn ecc_priv_der_to_vault(
        &self,
        _io: &StdHsmIo,
        der: &HsmDmaBuf,
        pct: HsmEccPct,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<(usize, HsmEccCurve)> {
        // The std PAL vault is the big-endian scalar, zero-padded to the
        // wire coordinate length. Like Uno, the key must carry a well-formed
        // public key and a valid scalar in both modes; use mode also checks
        // the public key against the scalar and runs `pct`. The key is built
        // from the scalar alone: backends validate or keep the DER's embedded
        // public key, which would bypass or change the status of that check.
        let key = crate::key_assurance::parse_ec_private_key(der).ok_or(HsmError::InvalidArg)?;
        let embedded = crate::key_assurance::embedded_public_key(&key)?;
        let (curve, scalar) = (key.curve, key.scalar);
        crate::key_assurance::check_ecc_scalar(curve, scalar)?;
        let vault_len = curve.wire_coord_len(StdHsmPal::ECC_COORD_PAD);
        let Some(out) = out else {
            return Ok((vault_len, curve));
        };
        if out.len() < vault_len {
            return Err(HsmError::InvalidArg);
        }
        let pad = vault_len - scalar.len();
        out[..pad].fill(0);
        out[pad..vault_len].copy_from_slice(scalar);
        let pk = import_priv(&out[..vault_len])?;
        self.check_ecc_import(curve, pct, &pk, embedded).await?;
        Ok((vault_len, curve))
    }

    fn ecc_priv_to_vault(
        &self,
        _io: &StdHsmIo,
        curve: HsmEccCurve,
        d: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // The COSE EC2 `d` field is the raw big-endian scalar at the
        // curve's field width; reject any other length before import.
        if d.len() != curve.priv_key_len() {
            return Err(HsmError::InvalidArg);
        }
        crate::key_assurance::check_ecc_scalar(curve, d)?;
        let priv_len = curve.wire_coord_len(StdHsmPal::ECC_COORD_PAD);
        if let Some(out) = out {
            if out.len() < priv_len {
                return Err(HsmError::InvalidArg);
            }
            let pk = EccPrivateKey::from_scalar(to_ecc_curve(curve), d)
                .map_err(|_| HsmError::InvalidArg)?;
            export_priv(&pk, &mut out[..priv_len]).map_err(|_| HsmError::InvalidArg)?;
        }
        Ok(priv_len)
    }

    fn ecc_vault_to_priv(
        &self,
        _io: &StdHsmIo,
        curve: HsmEccCurve,
        vault: &HsmDmaBuf,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        // std PAL vault format is raw big-endian HSM scalar bytes, left
        // zero-padded to `wire_coord_len`. Parse and validate it, then
        // return the canonical big-endian COSE `d` at the field width.
        if vault.len() != curve.wire_coord_len(StdHsmPal::ECC_COORD_PAD) {
            return Err(HsmError::InvalidArg);
        }
        if Self::ecc_private_curve(vault)? != curve {
            return Err(HsmError::InvalidArg);
        }
        let priv_len = curve.priv_key_len();
        if let Some(out) = out {
            if out.len() < priv_len {
                return Err(HsmError::InvalidArg);
            }
            let pk = import_priv(vault)?;
            export_priv(&pk, &mut out[..priv_len]).map_err(|_| HsmError::InvalidArg)?;
        }
        Ok(priv_len)
    }

    async fn ecc_priv_pub_key(
        &self,
        _io: &StdHsmIo,
        priv_key: &HsmDmaBuf,
        pub_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let len = Self::ecc_private_curve(priv_key)?.wire_pub_key_len(Self::ECC_COORD_PAD);
        let Some(pub_out) = pub_out else {
            return Ok(len);
        };
        if pub_out.len() < len {
            return Err(HsmError::InvalidArg);
        }
        self.ecc_public_point(import_priv(priv_key)?, Some(&mut pub_out[..len]))
            .await
    }

    async fn ecc_vault_pub_key(
        &self,
        io: &StdHsmIo,
        key_id: HsmKeyId,
        out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        if out
            .as_ref()
            .is_some_and(|buf| !(buf.as_ptr() as usize).is_multiple_of(4))
        {
            return Err(HsmError::InvalidArg);
        }
        let key = self.vault_key(io, key_id)?;
        let len = Self::ecc_private_curve(key)?.wire_pub_key_len(Self::ECC_COORD_PAD);
        let Some(out) = out else {
            return Ok(len);
        };
        if out.len() < len {
            return Err(HsmError::InvalidArg);
        }
        let pk = import_priv(key)?;
        self.ecc_public_point(pk, Some(&mut out[..len])).await
    }
}

impl StdHsmPal {
    fn ecc_private_curve(private: &HsmDmaBuf) -> HsmResult<HsmEccCurve> {
        let curve = match private.len() {
            32 => HsmEccCurve::P256,
            48 => HsmEccCurve::P384,
            66 | 68 | 72 => HsmEccCurve::P521,
            _ => return Err(HsmError::InvalidArg),
        };
        let (padding, scalar) = private.split_at(private.len() - curve.priv_key_len());
        if padding.iter().any(|&b| b != 0) {
            return Err(HsmError::InvalidArg);
        }
        crate::key_assurance::check_ecc_scalar(curve, scalar)?;
        Ok(curve)
    }

    async fn ecc_public_point(
        &self,
        pk: EccPrivateKey,
        pub_out: Option<&mut HsmDmaBuf>,
    ) -> HsmResult<usize> {
        let wire_pub_len = from_ecc_curve(pk.curve()).wire_pub_key_len(StdHsmPal::ECC_COORD_PAD);
        if let Some(out) = pub_out {
            if out.len() < wire_pub_len {
                return Err(HsmError::InvalidArg);
            }
            let pub_key = pk
                .public_key()
                .map_err(|_| HsmError::EccGetCoordinatesError)?;
            self.ecc
                .pub_coords(
                    &pub_key,
                    EccForm::of::<StdHsmPal>(),
                    &mut out[..wire_pub_len],
                )
                .await?;
        }
        Ok(wire_pub_len)
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;
    use tsra_crypto::ExportableKey;

    use super::*;
    use crate::StdHsmIo;
    use crate::StdHsmPal;

    /// P-384 `PartRoot` size — the only curve the PTA derivation uses.
    const ROOT_LEN: usize = 48;

    fn standard_hash(curve: HsmEccCurve) -> HsmHashAlgo {
        match curve {
            HsmEccCurve::P256 => HsmHashAlgo::Sha256,
            HsmEccCurve::P384 => HsmHashAlgo::Sha384,
            HsmEccCurve::P521 => HsmHashAlgo::Sha512,
        }
    }

    /// A zeroed `k ‖ digest` input with a `0x42` digest.
    fn sign_input(
        alloc: &impl HsmScopedAlloc,
        curve: HsmEccCurve,
        hash: HsmHashAlgo,
    ) -> HsmResult<&mut HsmDmaBuf> {
        let pad = StdHsmPal::ECC_COORD_PAD;
        let input = alloc.dma_alloc(curve.ecdsa_sign_input_len(hash, pad))?;
        input.fill(0);
        let coord = curve.wire_coord_len(pad);
        input[coord..coord + hash.digest_len()].fill(0x42);
        Ok(input)
    }

    fn pal_and_io() -> (StdHsmPal, StdHsmIo) {
        let (_tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, Handle::current());
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(HsmPartId::from(0u8), 0, reply_tx);
        (pal, io)
    }

    /// Derives a PTA keypair from `root_bytes`, returning `(priv, pub)`.
    async fn derive(root_bytes: &[u8]) -> HsmResult<(Vec<u8>, Vec<u8>)> {
        let (pal, io) = pal_and_io();
        pal.alloc_scoped_async(&io, async |alloc| {
            let curve = HsmEccCurve::P384;
            let priv_len = curve.wire_coord_len(StdHsmPal::ECC_COORD_PAD);
            let pub_len = curve.wire_pub_key_len(StdHsmPal::ECC_COORD_PAD);

            let root = alloc.dma_alloc(root_bytes.len())?;
            root.copy_from_slice(root_bytes);
            let priv_out = alloc.dma_alloc(priv_len)?;
            let pub_out = alloc.dma_alloc(pub_len)?;
            pal.ecc_gen_keypair_from_root(
                &io,
                curve,
                &*root,
                HsmEccPct::None,
                Some((priv_out, pub_out)),
            )
            .await?;

            Ok((priv_out[..priv_len].to_vec(), pub_out[..pub_len].to_vec()))
        })
        .await
    }

    /// Queries the sizes for `root_len`, returning the raw result.
    async fn query(root_len: usize) -> HsmResult<(usize, usize)> {
        let (pal, io) = pal_and_io();
        pal.alloc_scoped_async(&io, async |alloc| {
            let root = alloc.dma_alloc(root_len)?;
            pal.ecc_gen_keypair_from_root(&io, HsmEccCurve::P384, &*root, HsmEccPct::None, None)
                .await
        })
        .await
    }

    async fn generate(
        pal: &StdHsmPal,
        io: &StdHsmIo,
        curve: HsmEccCurve,
        root: Option<&HsmDmaBuf>,
        out: Option<(&mut HsmDmaBuf, &mut HsmDmaBuf)>,
    ) -> HsmResult<(usize, usize)> {
        match root {
            Some(root) => {
                pal.ecc_gen_keypair_from_root(io, curve, root, HsmEccPct::SignVerify, out)
                    .await
            }
            None => {
                pal.ecc_gen_keypair(io, curve, HsmEccPct::SignVerify, out)
                    .await
            }
        }
    }

    fn allocation_marks(pal: &StdHsmPal, io: &StdHsmIo) -> (usize, usize) {
        let pool = pal.iic.pool();
        (
            pool.nondma_mark(io.slot).get(),
            pool.dma_mark(io.slot).get(),
        )
    }

    #[tokio::test]
    async fn output_queries_and_short_buffers_preserve_storage() {
        for curve in [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521] {
            let (pal, io) = pal_and_io();
            pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
                let private = alloc.dma_alloc(curve.wire_priv_key_len(StdHsmPal::ECC_COORD_PAD))?;
                let public_len = curve.wire_pub_key_len(StdHsmPal::ECC_COORD_PAD);
                let public = alloc.dma_alloc(public_len)?;
                let priv_pub_storage = alloc.dma_alloc(public_len.max(144) + 4)?;
                priv_pub_storage.fill(0xCC);
                pal.ecc_gen_keypair(&io, curve, HsmEccPct::None, Some((private, public)))
                    .await?;
                let hash = standard_hash(curve);
                let input = sign_input(alloc, curve, hash)?;
                let signature_len = curve.wire_sig_len(StdHsmPal::ECC_COORD_PAD);
                let signature = alloc.dma_alloc(signature_len + 4)?;
                let derived_storage = alloc.dma_alloc(public_len + 5)?;
                derived_storage.fill(0xCC);
                let derived = &mut derived_storage[1..];
                let secret_len = curve.secret_len();
                let secret = alloc.dma_alloc(secret_len + 4)?;
                signature.fill(0xCC);
                secret.fill(0xCC);
                let marks = allocation_marks(&pal, &io);

                pal.alloc_scoped_async(&io, async |reserve| -> HsmResult<()> {
                    let mark = pal.iic.pool().dma_mark(io.slot).get().next_multiple_of(4);
                    let _remaining = reserve.dma_alloc(buf_pool::DMA_BUF_SIZE - mark)?;
                    let full_marks = allocation_marks(&pal, &io);
                    assert_eq!(
                        pal.ecc_sign(
                            &io,
                            curve,
                            hash,
                            private,
                            HsmEcdsaNonce::Generated,
                            input,
                            None,
                        )
                        .await?,
                        signature_len
                    );
                    assert_eq!(
                        pal.ecc_pub_from_priv(&io, curve, private, None).await?,
                        public_len
                    );
                    assert_eq!(
                        pal.ecdh_derive(&io, curve, private, public, None).await?,
                        secret_len
                    );
                    assert_eq!(pal.ecc_priv_pub_key(&io, private, None).await?, public_len);
                    let raw_len = curve.priv_key_len();
                    let scalar = &private[private.len() - raw_len..];
                    assert_eq!(
                        pal.ecc_priv_to_vault(&io, curve, scalar, None)?,
                        private.len()
                    );
                    assert_eq!(pal.ecc_vault_to_priv(&io, curve, private, None)?, raw_len);
                    for outcome in [
                        pal.ecc_sign(
                            &io,
                            curve,
                            hash,
                            private,
                            HsmEcdsaNonce::Generated,
                            input,
                            Some(&mut signature[..signature_len - 1]),
                        )
                        .await,
                        pal.ecc_pub_from_priv(
                            &io,
                            curve,
                            private,
                            Some(&mut derived[..public_len - 1]),
                        )
                        .await,
                        pal.ecdh_derive(
                            &io,
                            curve,
                            private,
                            public,
                            Some(&mut secret[..secret_len - 1]),
                        )
                        .await,
                    ] {
                        assert_eq!(outcome, Err(HsmError::InvalidArg));
                    }
                    assert_eq!(allocation_marks(&pal, &io), full_marks);
                    Ok(())
                })
                .await?;
                assert_eq!(allocation_marks(&pal, &io), marks);
                assert!(signature.iter().all(|&b| b == 0xCC));
                assert!(derived.iter().all(|&b| b == 0xCC));
                assert!(secret.iter().all(|&b| b == 0xCC));

                for _ in 0..2 {
                    assert_eq!(
                        pal.ecc_sign(
                            &io,
                            curve,
                            hash,
                            private,
                            HsmEcdsaNonce::Generated,
                            input,
                            Some(signature),
                        )
                        .await?,
                        signature_len
                    );
                    assert_eq!(
                        pal.ecc_pub_from_priv(&io, curve, private, Some(&mut *derived))
                            .await?,
                        public_len
                    );
                    assert_eq!(
                        pal.ecc_priv_pub_key(&io, private, Some(&mut *priv_pub_storage))
                            .await?,
                        public_len
                    );
                    assert_eq!(
                        pal.ecdh_derive(&io, curve, private, public, Some(secret))
                            .await?,
                        secret_len
                    );
                    assert_eq!(allocation_marks(&pal, &io), marks);
                    assert_eq!(&derived[..public_len], &public[..]);
                    assert_eq!(&priv_pub_storage[..public_len], &public[..]);
                    assert!(priv_pub_storage[public_len..]
                        .iter()
                        .all(|&byte| byte == 0xCC));
                    assert!(secret[..secret_len].iter().any(|&b| b != 0xCC));
                    assert_eq!(&signature[signature_len..], &[0xCC; 4]);
                    assert_eq!(&derived[public_len..], &[0xCC; 4]);
                    assert_eq!(&secret[secret_len..], &[0xCC; 4]);
                }
                assert_eq!(derived_storage[0], 0xCC);
                Ok(())
            })
            .await
            .expect("query/size ECC outputs");
        }
    }

    #[tokio::test]
    async fn verification_returns_validity_without_caller_scratch() {
        let hashes = [
            HsmHashAlgo::Sha1,
            HsmHashAlgo::Sha256,
            HsmHashAlgo::Sha384,
            HsmHashAlgo::Sha512,
        ];
        for curve in [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521] {
            for hash in hashes {
                let (pal, io) = pal_and_io();
                pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
                    let pad = StdHsmPal::ECC_COORD_PAD;
                    let private = alloc.dma_alloc(curve.wire_coord_len(pad))?;
                    let public = alloc.dma_alloc(curve.wire_pub_key_len(pad))?;
                    pal.ecc_gen_keypair(&io, curve, HsmEccPct::None, Some((private, public)))
                        .await?;
                    let coord = curve.wire_coord_len(pad);
                    let input = alloc.dma_alloc(curve.ecdsa_verify_input_len(hash, pad))?;
                    input.fill(0);
                    let sign_len = curve.ecdsa_sign_input_len(hash, pad);
                    let digest_len = hash.digest_len();
                    input[coord..coord + digest_len].fill(0x42);
                    let signed = pal
                        .ecc_sign_in_place(
                            &io,
                            curve,
                            hash,
                            private,
                            HsmEcdsaNonce::Generated,
                            &mut input[..sign_len],
                        )
                        .await?;
                    assert_eq!(signed, curve.wire_sig_len(pad));
                    input[2 * coord..].fill(0);
                    input[2 * coord..2 * coord + digest_len].fill(0x42);

                    let mark = pal.iic.pool().dma_mark(io.slot).get().next_multiple_of(4);
                    let _remaining = alloc.dma_alloc(buf_pool::DMA_BUF_SIZE - mark)?;
                    let marks = allocation_marks(&pal, &io);
                    for valid in [true, false, true] {
                        assert_eq!(
                            pal.ecc_verify(&io, curve, hash, public, input).await?,
                            valid,
                        );
                        assert_eq!(allocation_marks(&pal, &io), marks);
                        // Truncation drops the low end of an over-long digest,
                        // so flip both ends to reach the bits that are kept.
                        input[2 * coord] ^= 1;
                        input[2 * coord + digest_len - 1] ^= 1;
                    }
                    let last = input.len() - 1;
                    for (algo, len, error) in [
                        (hash, last, HsmError::InvalidArg),
                        (
                            HsmHashAlgo::Sha3_256,
                            input.len(),
                            HsmError::UnsupportedDigestHashAlgorithm,
                        ),
                    ] {
                        assert_eq!(
                            pal.ecc_verify(&io, curve, algo, public, &input[..len])
                                .await,
                            Err(error),
                        );
                    }
                    if input.len() > 2 * coord + digest_len {
                        input[last] = 1;
                        assert_eq!(
                            pal.ecc_verify(&io, curve, hash, public, input).await,
                            Err(HsmError::InvalidArg),
                        );
                    }
                    assert_eq!(allocation_marks(&pal, &io), marks);
                    Ok(())
                })
                .await
                .expect("boolean ECC verification");
            }
        }
    }

    #[tokio::test]
    async fn supplied_nonce_is_unsupported() {
        let (pal, io) = pal_and_io();
        pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
            let curve = HsmEccCurve::P256;
            let pad = StdHsmPal::ECC_COORD_PAD;
            let private = alloc.dma_alloc(curve.wire_coord_len(pad))?;
            let public = alloc.dma_alloc(curve.wire_pub_key_len(pad))?;
            pal.ecc_gen_keypair(&io, curve, HsmEccPct::None, Some((private, public)))
                .await?;
            let hash = standard_hash(curve);
            let input = sign_input(alloc, curve, hash)?;
            let supplied = HsmEcdsaNonce::Supplied;
            assert_eq!(
                pal.ecc_sign(&io, curve, hash, private, supplied, input, None)
                    .await,
                Err(HsmError::CryptoUnsupportedMode),
            );
            assert_eq!(
                pal.ecc_sign_in_place(&io, curve, hash, private, supplied, input)
                    .await,
                Err(HsmError::CryptoUnsupportedMode),
            );
            Ok(())
        })
        .await
        .expect("supplied nonce");
    }

    #[tokio::test]
    async fn keypair_reclaims_scratch_and_preserves_outputs_on_allocation_failure() {
        let (pal, io) = pal_and_io();
        for curve in [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521] {
            pal.alloc_scoped_async(&io, async |alloc| -> HsmResult<()> {
                let root = alloc.dma_alloc(curve.wire_coord_len(StdHsmPal::ECC_COORD_PAD))?;
                root.fill(0xA5);
                for root in [None, Some(&*root)] {
                    let sizes = generate(&pal, &io, curve, root, None).await?;
                    let (private_len, public_len) = sizes;
                    let private = alloc.dma_alloc(private_len + 4)?;
                    let public_storage = alloc.dma_alloc(public_len + 5)?;
                    public_storage.fill(0xA5);
                    let public = &mut public_storage[1..];
                    private.fill(0xA5);
                    public.fill(0xA5);
                    let marks = allocation_marks(&pal, &io);

                    for short_private in [true, false] {
                        let private_size = private_len - usize::from(short_private);
                        let public_size = public_len - usize::from(!short_private);
                        let outcome = generate(
                            &pal,
                            &io,
                            curve,
                            root,
                            Some((&mut private[..private_size], &mut public[..public_size])),
                        )
                        .await;
                        assert_eq!(outcome, Err(HsmError::InvalidArg));
                        assert_eq!(allocation_marks(&pal, &io), marks);
                        assert!(private.iter().all(|&b| b == 0xA5));
                        assert!(public.iter().all(|&b| b == 0xA5));
                    }
                    pal.alloc_scoped_async(&io, async |reserve| -> HsmResult<()> {
                        let mark = pal.iic.pool().dma_mark(io.slot).get().next_multiple_of(4);
                        let _remaining = reserve.dma_alloc(buf_pool::DMA_BUF_SIZE - mark)?;
                        let full_marks = allocation_marks(&pal, &io);
                        assert_eq!(generate(&pal, &io, curve, root, None).await?, sizes);
                        let outcome =
                            generate(&pal, &io, curve, root, Some((&mut *private, &mut *public)))
                                .await;
                        assert_eq!(outcome, Err(HsmError::NotEnoughSpace));
                        assert_eq!(allocation_marks(&pal, &io), full_marks);
                        Ok(())
                    })
                    .await?;
                    assert_eq!(allocation_marks(&pal, &io), marks);
                    assert!(private.iter().all(|&b| b == 0xA5));
                    assert!(public.iter().all(|&b| b == 0xA5));
                    for _ in 0..2 {
                        assert_eq!(
                            generate(&pal, &io, curve, root, Some((&mut *private, &mut *public)))
                                .await?,
                            sizes,
                        );
                        assert_eq!(allocation_marks(&pal, &io), marks);
                        assert!(private[..private_len].iter().any(|&b| b != 0xA5));
                        assert!(public[..public_len].iter().any(|&b| b != 0xA5));
                        assert_eq!(&private[private_len..], &[0xA5; 4]);
                        assert_eq!(&public[public_len..], &[0xA5; 4]);
                    }
                    assert_eq!(public_storage[0], 0xA5);
                }
                Ok(())
            })
            .await
            .expect("key generation with internally scoped scratch");
        }
    }

    /// A wrong-sized `root` is rejected in **use** mode.
    #[tokio::test]
    async fn wrong_root_length_rejected_in_use_mode() {
        for bad in [ROOT_LEN - 1, ROOT_LEN + 1, 0] {
            let err = derive(&vec![0x5Au8; bad]).await.unwrap_err();
            assert_eq!(err, HsmError::InvalidArg, "root len {bad} must be rejected");
        }
    }

    /// ...and in **query** mode too: the documented `InvalidArg` must not
    /// depend on whether `out` is `Some`, so query and use mode agree.
    #[tokio::test]
    async fn wrong_root_length_rejected_in_query_mode() {
        assert_eq!(query(ROOT_LEN - 1).await.unwrap_err(), HsmError::InvalidArg);
        assert_eq!(query(ROOT_LEN + 1).await.unwrap_err(), HsmError::InvalidArg);
    }

    /// Query mode reports the P-384 sizes a caller must allocate.
    #[tokio::test]
    async fn query_mode_reports_p384_sizes() {
        let (priv_len, pub_len) = query(ROOT_LEN).await.unwrap();
        assert_eq!(priv_len, ROOT_LEN);
        assert_eq!(pub_len, ROOT_LEN * 2);
    }

    /// The derivation is deterministic **on this PAL**: the same root
    /// regenerates the same keypair, which is what keeps the partition
    /// identity stable across resets. (It deliberately does not match the
    /// uno PAL — see the trait doc.)
    #[tokio::test]
    async fn same_root_regenerates_same_keypair() {
        let root = [0xA5u8; ROOT_LEN];
        let (priv_a, pub_a) = derive(&root).await.unwrap();
        let (priv_b, pub_b) = derive(&root).await.unwrap();

        assert_eq!(priv_a, priv_b);
        assert_eq!(pub_a, pub_b);
        assert!(
            priv_a.iter().any(|&b| b != 0),
            "scalar must not be all-zero"
        );
    }

    /// Distinct roots must yield distinct keypairs — the whole point of
    /// fanning per-partition keys out of `PartRoot`.
    #[tokio::test]
    async fn different_roots_give_different_keypairs() {
        let (priv_a, pub_a) = derive(&[0xA5u8; ROOT_LEN]).await.unwrap();
        let (priv_b, pub_b) = derive(&[0x5Au8; ROOT_LEN]).await.unwrap();

        assert_ne!(priv_a, priv_b);
        assert_ne!(pub_a, pub_b);
    }

    #[tokio::test]
    async fn pairwise_tests_reject_mismatched_keys() {
        let (pal, _) = pal_and_io();
        for curve in [EccCurve::P256, EccCurve::P384, EccCurve::P521] {
            let (private, public) = pal.ecc.gen_keypair(curve).await.unwrap();
            let (_, other_public) = pal.ecc.gen_keypair(curve).await.unwrap();
            for pct in [HsmEccPct::SignVerify, HsmEccPct::KeyAgreement] {
                let good_pct = match pct {
                    HsmEccPct::SignVerify => HsmEccPct::SignVerify,
                    HsmEccPct::KeyAgreement => HsmEccPct::KeyAgreement,
                    HsmEccPct::None => unreachable!(),
                };
                assert!(pal.ecc_pair_pct(&private, &public, good_pct).await.unwrap());
                assert!(!pal
                    .ecc_pair_pct(&private, &other_public, pct)
                    .await
                    .unwrap());
            }
        }
    }

    #[tokio::test]
    async fn key_agreement_rejects_negated_public_point() {
        let (pal, _) = pal_and_io();
        let curve = EccCurve::P256;
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        let private = EccPrivateKey::from_scalar(curve, &scalar).unwrap();
        let public = private.public_key().unwrap();
        let (x, y) = public.coord_vec().unwrap();
        let mut negative_y =
            hex::decode("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
                .unwrap();
        let mut borrow = 0i16;
        for (out, &value) in negative_y.iter_mut().zip(y.iter()).rev() {
            let difference = i16::from(*out) - i16::from(value) - borrow;
            *out = difference as u8;
            borrow = i16::from(difference < 0);
        }
        let negative = EccPublicKey::from_coordinates(curve, &x, &negative_y).unwrap();
        assert!(!pal
            .ecc_pair_pct(&private, &negative, HsmEccPct::KeyAgreement)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn generated_key_pct_failure_is_reported_before_output() {
        let (pal, io) = pal_and_io();
        pal.ecc_pct_fail.set(true);
        pal.alloc_scoped_async(&io, async |alloc| {
            let curve = HsmEccCurve::P384;
            let private = alloc
                .dma_alloc(curve.wire_coord_len(StdHsmPal::ECC_COORD_PAD))
                .unwrap();
            let public = alloc
                .dma_alloc(curve.wire_pub_key_len(StdHsmPal::ECC_COORD_PAD))
                .unwrap();
            private.fill(0xa5);
            public.fill(0xa5);
            let err = pal
                .ecc_gen_keypair(&io, curve, HsmEccPct::SignVerify, Some((private, public)))
                .await
                .unwrap_err();
            assert_eq!(err, HsmError::PctValidationEccGenKeyFailed);
            assert!(private.iter().all(|&b| b == 0xa5));
            assert!(public.iter().all(|&b| b == 0xa5));
            let root = alloc.dma_alloc(ROOT_LEN).unwrap();
            root.fill(0x5a);
            let err = pal
                .ecc_gen_keypair_from_root(
                    &io,
                    curve,
                    root,
                    HsmEccPct::KeyAgreement,
                    Some((private, public)),
                )
                .await
                .unwrap_err();
            assert_eq!(err, HsmError::PctValidationEccGenKeyFailed);
            assert!(private.iter().all(|&b| b == 0xa5));
            assert!(public.iter().all(|&b| b == 0xa5));
        })
        .await;
    }

    #[tokio::test]
    async fn imported_key_pct_failure_is_reported_in_use_mode() {
        let (pal, io) = pal_and_io();
        pal.ecc_pct_fail.set(true);
        for curve in [EccCurve::P256, EccCurve::P384, EccCurve::P521] {
            let (private, _) = pal.ecc.gen_keypair(curve).await.expect("generate key");
            let mut bytes = vec![0; private.to_bytes(None).expect("DER size")];
            private.to_bytes(Some(&mut bytes)).expect("export DER");
            pal.alloc_scoped_async(&io, async |alloc| {
                let der = alloc.dma_alloc(bytes.len()).expect("DER buffer");
                der.copy_from_slice(&bytes);
                let out = alloc.dma_alloc(72).expect("vault buffer");
                for pct in [HsmEccPct::SignVerify, HsmEccPct::KeyAgreement] {
                    let query_pct = if matches!(&pct, HsmEccPct::SignVerify) {
                        HsmEccPct::SignVerify
                    } else {
                        HsmEccPct::KeyAgreement
                    };
                    assert!(pal
                        .ecc_priv_der_to_vault(&io, der, query_pct, None)
                        .await
                        .is_ok());
                    assert_eq!(
                        pal.ecc_priv_der_to_vault(&io, der, pct, Some(out)).await,
                        Err(HsmError::PctValidationRsaUnwrapEccKeyFailed)
                    );
                }
                pal.ecc_priv_der_to_vault(&io, der, HsmEccPct::None, Some(out))
                    .await
                    .expect("explicit skip");
            })
            .await;
        }
    }
}
