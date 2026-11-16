// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std ECC driver — performs ECC operations via OpenSSL.
//!
//! Operates on [`tsra_crypto`] key handle types directly
//! (`EccPrivateKey`, `EccPublicKey`). The public API accepts
//! references and slices; owned copies for the worker thread
//! boundary are made internally via `Clone` (cheap — OpenSSL
//! key handles are reference-counted).
//!
//! ## Supported operations
//!
//! | Method | Operation | Input | Output |
//! |--------|-----------|-------|--------|
//! | [`gen_keypair`] | Key generation | `EccCurve` | `(EccPrivateKey, EccPublicKey)` |
//! | [`pub_coords`] | Serialize pub key | `&EccPublicKey`, `big_endian`, `&mut [u8]` out | `x ∥ y` bytes |
//! | [`ecc_sign`] | Raw EC sign | `&EccPrivateKey`, `&[u8]` hash | `Vec<u8>` (r∥s) |
//! | [`ecc_verify`] | Raw EC verify | `&EccPublicKey`, `&[u8]` hash, `&[u8]` sig | `bool` |
//! | [`ecdh_derive`] | ECDH agreement | `&EccPrivateKey`, `&EccPublicKey` | writes `&mut [u8]` |
//!
//! ## Thread model
//!
//! All methods clone handles and input slices into owned buffers,
//! then dispatch to the tokio [`WorkerPool`]. The Embassy executor
//! yields while the worker runs, then copies results back.
//!
//! On real Cortex-M7 hardware, these operations would be offloaded
//! to a PKA (Public Key Accelerator) engine via DMA.

use tsra_crypto::DeriveOp;
use tsra_crypto::EccAlgo;
use tsra_crypto::EccCurve;
use tsra_crypto::EccKeyOp;
use tsra_crypto::EccPrivateKey;
use tsra_crypto::EccPublicKey;
use tsra_crypto::EcdhAlgo;
use tsra_crypto::ExportableHsmKey;
use tsra_crypto::ExportableKey;
use tsra_crypto::PrivateKey;
use tsra_crypto::SignOp;
use tsra_crypto::VerifyOp;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::*;
use zeroize::Zeroizing;

use crate::worker::WorkerPool;

/// Std ECC driver — software ECC via OpenSSL with async worker dispatch.
///
/// The `_op` methods exchange keys, digests, signatures and secrets in
/// the PAL's operand byte order; the driver converts to and from the
/// big-endian components OpenSSL uses.
pub struct StdEcc {
    pool: WorkerPool,
    order: HsmByteOrder,
}

impl StdEcc {
    /// Create a new ECC driver backed by the given worker pool, using the
    /// PAL operand byte order `order`.
    pub fn new(pool: WorkerPool, order: HsmByteOrder) -> Self {
        Self { pool, order }
    }

    /// Generate an ECC key pair asynchronously, returning the
    /// `(EccPrivateKey, EccPublicKey)` handle pair.
    ///
    /// Serialization is a separate concern: turn the public-key handle
    /// into raw `x ∥ y` bytes (in a chosen byte order) with
    /// [`Self::pub_coords`], and the private-key handle into raw HSM
    /// scalar bytes with its `to_hsm_bytes`.
    pub async fn gen_keypair(&self, curve: EccCurve) -> HsmResult<(EccPrivateKey, EccPublicKey)> {
        self.pool
            .submit_with_result(async move {
                let priv_key =
                    EccPrivateKey::from_curve(curve).map_err(|_| HsmError::EccGenerateError)?;
                let pub_key = priv_key
                    .public_key()
                    .map_err(|_| HsmError::EccGetCoordinatesError)?;
                Ok((priv_key, pub_key))
            })
            .await
    }

    /// Serialize a public-key handle's coordinates to raw `x ∥ y` bytes
    /// in `order`.  The curve is taken from the handle.
    ///
    /// [`HsmByteOrder::Be`] yields the exact-width big-endian form used
    /// by internal consumers (cert generation, POTA hashing); the PAL
    /// operand order yields the DDI wire form.  Each coordinate occupies
    /// a `wire_coord_len(curve, order)` slot (P-521 is padded to 68 bytes
    /// on little-endian).
    ///
    /// `out.len()` must be `2 * wire_coord_len(curve, order)`.
    pub async fn pub_coords(
        &self,
        pub_key: &EccPublicKey,
        order: HsmByteOrder,
        out: &mut [u8],
    ) -> HsmResult<()> {
        let curve = pub_key.curve();
        let coord_len = priv_key_len(curve);
        let wire_coord = wire_coord_len(curve, order);
        if out.len() != wire_coord * 2 {
            return Err(HsmError::EccGetCoordinatesError);
        }

        // Read the big-endian coordinates on the worker pool.
        let pub_key = pub_key.clone();
        let (x_be, y_be) = self
            .pool
            .submit_with_result(async move {
                let mut x_be = [0u8; 66];
                let mut y_be = [0u8; 66];
                pub_key
                    .coord(Some((&mut x_be[..coord_len], &mut y_be[..coord_len])))
                    .map_err(|_| HsmError::EccGetCoordinatesError)?;
                Ok::<_, HsmError>((x_be, y_be))
            })
            .await?;

        write_pair(order, curve, &x_be[..coord_len], &y_be[..coord_len], out)
    }

    /// Raw EC sign over a pre-computed hash digest.
    ///
    /// Clones the private key handle (cheap, ref-counted), copies the
    /// hash to an owned buffer, and dispatches to the worker pool.
    ///
    /// # Parameters
    /// - `priv_key` — The signing key handle.
    /// - `hash` — Pre-computed hash digest (e.g., SHA-256 output).
    ///
    /// # Returns
    /// The raw `r ∥ s` signature as a `Vec<u8>`. Length is
    /// `2 × curve.point_size()` (64 for P-256, 96 for P-384, 132 for P-521).
    ///
    /// # Errors
    /// Returns [`HsmError::EccSignFailed`] if the OpenSSL sign operation fails.
    pub async fn ecc_sign(&self, priv_key: &EccPrivateKey, hash: &[u8]) -> HsmResult<Vec<u8>> {
        let key = priv_key.clone();
        let hash_owned = hash.to_vec();
        self.pool
            .submit_with_result(async move {
                let sig_len = EccKeyOp::curve(&key).point_size() * 2;
                let mut sig = vec![0u8; sig_len];
                let mut algo = EccAlgo::default();
                algo.sign(&key, &hash_owned, Some(&mut sig))
                    .map_err(|_| HsmError::EccSignFailed)?;
                Ok(sig)
            })
            .await
    }

    /// Sign an operand-order digest with an [`EccPrivateKey`] handle and
    /// write the operand-order signature (`r || s`, each in a
    /// `wire_coord_len` slot) into `sig_out`.
    ///
    /// `sig_out.len()` must be `wire_sig_len(curve, order)`.
    /// `hash.len()` must not exceed SHA-512 (64 bytes); longer inputs are
    /// rejected rather than silently truncated.
    pub async fn ecc_sign_op(
        &self,
        priv_key: &EccPrivateKey,
        hash: &[u8],
        sig_out: &mut [u8],
    ) -> HsmResult<()> {
        let curve = EccKeyOp::curve(priv_key);
        let coord_len = priv_key_len(curve);
        if sig_out.len() != wire_coord_len(curve, self.order) * 2 {
            return Err(HsmError::EccSignFailed);
        }
        if hash.len() > 64 {
            return Err(HsmError::InvalidArg);
        }

        let mut hash_be = [0u8; 64];
        byte_order::int_copy_to_be(self.order, &mut hash_be[..hash.len()], hash)?;

        let sig_be = self.ecc_sign(priv_key, &hash_be[..hash.len()]).await?;
        if sig_be.len() < coord_len * 2 {
            return Err(HsmError::EccSignFailed);
        }
        let (r_be, s_be) = sig_be.split_at(coord_len);
        write_pair(self.order, curve, r_be, &s_be[..coord_len], sig_out)
    }

    /// Raw EC verify a signature over a pre-computed hash digest.
    ///
    /// Returns `true` if the signature is valid, `false` otherwise.
    pub async fn ecc_verify(
        &self,
        pub_key: &EccPublicKey,
        hash: &[u8],
        signature: &[u8],
    ) -> HsmResult<bool> {
        let key = pub_key.clone();
        let hash_owned = hash.to_vec();
        let sig_owned = signature.to_vec();
        self.pool
            .submit_with_result(async move {
                let mut algo = EccAlgo::default();
                algo.verify(&key, &hash_owned, &sig_owned)
                    .map_err(|_| HsmError::EccVerifyFailed)
            })
            .await
    }

    /// Verify an operand-order signature using a public key supplied as
    /// operand-order `x || y` coordinates.  The driver constructs the
    /// OpenSSL pub-key handle and converts byte order (plus P-521
    /// per-coordinate de-padding on little-endian) internally.
    ///
    /// `hash` is the operand-order digest, symmetric with
    /// [`Self::ecc_sign_op`].
    ///
    /// `pub_op` and `sig_op` must each be at least
    /// `2 * wire_coord_len(curve, order)` bytes.
    pub async fn ecc_verify_op(
        &self,
        curve: EccCurve,
        pub_op: &[u8],
        hash: &[u8],
        sig_op: &[u8],
    ) -> HsmResult<bool> {
        let coord_len = priv_key_len(curve);
        let (x_be, y_be) = read_pair(self.order, curve, pub_op)?;
        let key = EccPublicKey::from_coordinates(curve, &x_be[..coord_len], &y_be[..coord_len])
            .map_err(|_| HsmError::InvalidArg)?;

        let (r_be, s_be) = read_pair(self.order, curve, sig_op)?;
        let sig_len = coord_len * 2;
        let mut sig_be = [0u8; 132];
        sig_be[..coord_len].copy_from_slice(&r_be[..coord_len]);
        sig_be[coord_len..sig_len].copy_from_slice(&s_be[..coord_len]);

        // The PAL trait allows a `hash` buffer larger than the curve digest;
        // verify only the leading curve-digest bytes (matching the uno PAL,
        // which feeds the PKA exactly `hash_size(curve)`).
        let digest_len = ecc_digest_len(curve);
        let digest = hash.get(..digest_len).ok_or(HsmError::InvalidArg)?;
        let mut hash_be = [0u8; 64];
        byte_order::int_copy_to_be(self.order, &mut hash_be[..digest_len], digest)?;

        self.ecc_verify(&key, &hash_be[..digest_len], &sig_be[..sig_len])
            .await
    }

    /// ECDH key agreement — derives a shared secret into `secret`.
    ///
    /// Clones both key handles, dispatches ECDH computation to the worker
    /// pool, and copies the raw shared secret (x-coordinate of the
    /// shared point) into `secret`.
    ///
    /// # Parameters
    /// - `priv_key` — The local private key handle.
    /// - `pub_key` — The remote party's public key handle.
    /// - `secret` — Output buffer. Must be ≥ `curve.point_size()` bytes
    ///   (32 for P-256, 48 for P-384, 66 for P-521).
    ///
    /// # Errors
    /// - [`HsmError::EccDeriveError`] — ECDH computation, secret export,
    ///   or output buffer too small.
    pub async fn ecdh_derive(
        &self,
        priv_key: &EccPrivateKey,
        pub_key: &EccPublicKey,
        secret: &mut [u8],
    ) -> HsmResult<()> {
        let pk = priv_key.clone();
        let pubk = pub_key.clone();
        let result: HsmResult<Vec<u8>> = self
            .pool
            .submit_with_result(async move {
                let derived_len = EccKeyOp::curve(&pk).point_size();
                let ecdh = EcdhAlgo::new(&pubk);
                let derived = ecdh
                    .derive(&pk, derived_len)
                    .map_err(|_| HsmError::EccDeriveError)?;
                derived.to_vec().map_err(|_| HsmError::EccDeriveError)
            })
            .await;
        let bytes = result?;
        if secret.len() < bytes.len() {
            return Err(HsmError::EccDeriveError);
        }
        secret[..bytes.len()].copy_from_slice(&bytes);
        Ok(())
    }

    /// ECDH key agreement using a public key supplied as operand-order
    /// `x || y` coordinates.  The driver constructs the OpenSSL pub-key
    /// handle internally, including stripping P-521 per-coordinate
    /// padding on little-endian.
    ///
    /// `pub_op` must be at least `2 * wire_coord_len(curve, order)` bytes.
    /// The shared secret is written to the head of `secret_out` in
    /// operand order; the DDI handler converts to the consumer's byte
    /// order (e.g. to big-endian before an openssl-matching HKDF).
    pub async fn ecdh_derive_op(
        &self,
        priv_key: &EccPrivateKey,
        curve: EccCurve,
        pub_op: &[u8],
        secret_out: &mut [u8],
    ) -> HsmResult<()> {
        let coord_len = priv_key_len(curve);
        let (x_be, y_be) = read_pair(self.order, curve, pub_op)?;

        // Peer-key validation (FIPS 186-5 / SP 800-56A) and peer-key
        // construction are OpenSSL/CNG operations, so run them on the worker
        // pool per this driver's thread model rather than blocking the executor.
        // Mirrors the HW PKA point validation the Uno driver performs: reject
        // any affine coordinate outside `[1, p-1]`
        // (`EccPublicKeyValidationFailed`) and points that are not on the curve
        // (`EccPointValidationFailed`).
        let pubk = self
            .pool
            .submit_with_result(async move {
                let x = &x_be[..coord_len];
                let y = &y_be[..coord_len];
                if !curve.coordinate_in_range(x) || !curve.coordinate_in_range(y) {
                    return Err(HsmError::EccPublicKeyValidationFailed);
                }
                if !EccPublicKey::is_on_curve(curve, x, y)
                    .map_err(|_| HsmError::EccPointValidationFailed)?
                {
                    return Err(HsmError::EccPointValidationFailed);
                }
                EccPublicKey::from_coordinates(curve, x, y).map_err(|_| HsmError::InvalidArg)
            })
            .await?;

        self.ecdh_derive(priv_key, &pubk, secret_out).await?;

        // OpenSSL derives the secret big-endian; convert exactly `coord_len`
        // bytes so a larger (wire-padded) caller buffer keeps its trailing
        // padding.
        let secret = secret_out
            .get_mut(..coord_len)
            .ok_or(HsmError::EccDeriveError)?;
        byte_order::int_from_be(self.order, secret);
        Ok(())
    }

    /// Derive the public key from a vault-format private scalar (see
    /// [`import_priv`]; `pub = priv · G`) and serialize it as
    /// operand-order `x || y`.
    ///
    /// All OpenSSL work — key reconstruction (which computes
    /// `Q = d · G`), public-point extraction, and coordinate readout —
    /// runs on the worker pool.
    ///
    /// `priv_vault.len()` must be `wire_coord_len(curve, order)` and
    /// `out.len()` twice that.
    pub async fn pub_from_priv_op(
        &self,
        curve: EccCurve,
        priv_vault: &[u8],
        out: &mut [u8],
    ) -> HsmResult<()> {
        let coord_len = priv_key_len(curve);
        let wire_coord = wire_coord_len(curve, self.order);
        if priv_vault.len() != wire_coord || out.len() != wire_coord * 2 {
            return Err(HsmError::InvalidArg);
        }

        // `Zeroizing` scrubs this transient heap copy of the private
        // scalar when the worker closure drops it, so the plaintext key
        // bytes don't linger in freed process heap memory.
        let priv_owned = Zeroizing::new(priv_vault.to_vec());
        let (x_be, y_be) = self
            .pool
            .submit_with_result(async move {
                let pk = import_priv(&priv_owned)?;
                let pub_key = pk
                    .public_key()
                    .map_err(|_| HsmError::EccGetCoordinatesError)?;
                let mut x_be = [0u8; 66];
                let mut y_be = [0u8; 66];
                pub_key
                    .coord(Some((&mut x_be[..coord_len], &mut y_be[..coord_len])))
                    .map_err(|_| HsmError::EccGetCoordinatesError)?;
                Ok::<_, HsmError>((x_be, y_be))
            })
            .await?;

        write_pair(
            self.order,
            curve,
            &x_be[..coord_len],
            &y_be[..coord_len],
            out,
        )
    }
}

/// Import a vault-format ECC private key: the big-endian scalar, left
/// zero-padded to the PAL's `wire_coord_len` (P-521 is 68 bytes on
/// little-endian PALs and 66 on big-endian ones).
///
/// # Errors
/// [`HsmError::InvalidArg`] if the length or scalar is invalid.
pub fn import_priv(vault: &[u8]) -> HsmResult<EccPrivateKey> {
    let key = if vault.len() == priv_key_len(EccCurve::P521) {
        EccPrivateKey::from_scalar(EccCurve::P521, vault)
    } else {
        EccPrivateKey::from_hsm_bytes(vault)
    };
    key.map_err(|_| HsmError::InvalidArg)
}

/// Export `pk` in vault format (see [`import_priv`]) filling all of
/// `out`, which must be `wire_coord_len` for the key's curve.
///
/// # Errors
/// [`HsmError::EccExportError`] if `out` cannot hold the scalar.
pub fn export_priv(pk: &EccPrivateKey, out: &mut [u8]) -> HsmResult<()> {
    let mut full = Zeroizing::new([0u8; 68]);
    let n = pk
        .to_hsm_bytes(&mut full[..])
        .map_err(|_| HsmError::EccExportError)?;
    let skip = n.checked_sub(out.len()).ok_or(HsmError::EccExportError)?;
    let (pad, scalar) = full[..n].split_at(skip);
    if pad.iter().any(|&b| b != 0) {
        return Err(HsmError::EccExportError);
    }
    out.copy_from_slice(scalar);
    Ok(())
}

/// Lay the exact-width big-endian components `a_be`, `b_be` out in
/// `order` as two `wire_coord_len` slots filling `out`, zeroing padding.
fn write_pair(
    order: HsmByteOrder,
    curve: EccCurve,
    a_be: &[u8],
    b_be: &[u8],
    out: &mut [u8],
) -> HsmResult<()> {
    let coord_len = priv_key_len(curve);
    let wire_coord = wire_coord_len(curve, order);
    if out.len() != wire_coord * 2 {
        return Err(HsmError::InvalidArg);
    }
    out.fill(0);
    let (a, b) = out.split_at_mut(wire_coord);
    byte_order::int_copy_from_be(order, &mut a[..coord_len], a_be)?;
    byte_order::int_copy_from_be(order, &mut b[..coord_len], b_be)
}

/// Read the two operand-order components at the head of `wire` into
/// exact-width big-endian scratch.
fn read_pair(order: HsmByteOrder, curve: EccCurve, wire: &[u8]) -> HsmResult<([u8; 66], [u8; 66])> {
    let coord_len = priv_key_len(curve);
    let wire_coord = wire_coord_len(curve, order);
    let wire = wire.get(..wire_coord * 2).ok_or(HsmError::InvalidArg)?;
    let (a, b) = wire.split_at(wire_coord);
    let mut a_be = [0u8; 66];
    let mut b_be = [0u8; 66];
    byte_order::int_copy_to_be(order, &mut a_be[..coord_len], &a[..coord_len])?;
    byte_order::int_copy_to_be(order, &mut b_be[..coord_len], &b[..coord_len])?;
    Ok((a_be, b_be))
}

/// Raw private-key (and per-coordinate) length in bytes for the
/// given curve.  Mirrors `HsmEccCurve::priv_key_len` but defined
/// in driver-local terms so the driver doesn't depend on the
/// PAL-trait crate's curve enum.
fn priv_key_len(curve: EccCurve) -> usize {
    match curve {
        EccCurve::P256 => 32,
        EccCurve::P384 => 48,
        EccCurve::P521 => 66,
    }
}

/// ECDSA digest length for the curve's standard hash (SHA-256/384/512).
fn ecc_digest_len(curve: EccCurve) -> usize {
    match curve {
        EccCurve::P256 => 32,
        EccCurve::P384 => 48,
        EccCurve::P521 => 64,
    }
}

/// Per-coordinate operand slot length: exact on big-endian PALs; on
/// little-endian PALs padded to 32-bit words (P-521: 66 → 68).
fn wire_coord_len(curve: EccCurve, order: HsmByteOrder) -> usize {
    match curve {
        EccCurve::P256 => 32,
        EccCurve::P384 => 48,
        EccCurve::P521 if order.is_be() => 66,
        EccCurve::P521 => 68,
    }
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdEcc {
        make_driver_with(HsmByteOrder::Le)
    }

    fn make_driver_with(order: HsmByteOrder) -> StdEcc {
        StdEcc::new(WorkerPool::new(Handle::current()), order)
    }

    // ── Key generation ──────────────────────────────────────────

    #[tokio::test]
    async fn gen_keypair_p256() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        assert_eq!(EccKeyOp::curve(&priv_key), EccCurve::P256);
        assert_eq!(pub_key.curve(), EccCurve::P256);
    }

    #[tokio::test]
    async fn gen_keypair_p384() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        assert_eq!(EccKeyOp::curve(&priv_key), EccCurve::P384);
        assert_eq!(pub_key.curve(), EccCurve::P384);
    }

    #[tokio::test]
    async fn gen_keypair_p521() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        assert_eq!(EccKeyOp::curve(&priv_key), EccCurve::P521);
        assert_eq!(pub_key.curve(), EccCurve::P521);
    }

    // ── Public-key coordinate serialization ─────────────────────

    #[tokio::test]
    async fn pub_coords_le_is_byte_reverse_of_be() {
        let driver = make_driver();
        let (_priv_key, pub_key) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        let mut be = [0u8; 96];
        let mut le = [0u8; 96];
        driver
            .pub_coords(&pub_key, HsmByteOrder::Be, &mut be)
            .await
            .expect("be coords");
        driver
            .pub_coords(&pub_key, HsmByteOrder::Le, &mut le)
            .await
            .expect("le coords");
        // Each 48-byte coordinate in LE is the byte-reverse of BE.
        let mut expected = [0u8; 96];
        for (d, s) in expected[..48].iter_mut().zip(be[..48].iter().rev()) {
            *d = *s;
        }
        for (d, s) in expected[48..].iter_mut().zip(be[48..].iter().rev()) {
            *d = *s;
        }
        assert_eq!(le, expected);
    }

    // ── Public-key derivation from private scalar ───────────────

    async fn pub_from_priv_roundtrip(
        order: HsmByteOrder,
        curve: EccCurve,
        priv_len: usize,
        pub_len: usize,
    ) {
        let driver = make_driver_with(order);
        let (priv_key, pub_key) = driver.gen_keypair(curve).await.expect("keygen");

        // Export the private scalar in the vault format the mask /
        // unmask pipeline round-trips.
        let mut priv_vault = [0u8; 68];
        export_priv(&priv_key, &mut priv_vault[..priv_len]).expect("export");
        let reimported = import_priv(&priv_vault[..priv_len]).expect("import");
        assert_eq!(EccKeyOp::curve(&reimported), curve);

        // Derive the public key from the private scalar.
        let mut derived = [0u8; 136];
        driver
            .pub_from_priv_op(curve, &priv_vault[..priv_len], &mut derived[..pub_len])
            .await
            .expect("pub from priv");

        // It must equal the generated public key in operand order.
        let mut expected = [0u8; 136];
        driver
            .pub_coords(&pub_key, order, &mut expected[..pub_len])
            .await
            .expect("pub coords");

        assert_eq!(derived[..pub_len], expected[..pub_len]);
    }

    #[tokio::test]
    async fn pub_from_priv_matches_gen_p256() {
        pub_from_priv_roundtrip(HsmByteOrder::Le, EccCurve::P256, 32, 64).await;
    }

    #[tokio::test]
    async fn pub_from_priv_matches_gen_p384() {
        pub_from_priv_roundtrip(HsmByteOrder::Le, EccCurve::P384, 48, 96).await;
    }

    #[tokio::test]
    async fn pub_from_priv_matches_gen_p521() {
        pub_from_priv_roundtrip(HsmByteOrder::Le, EccCurve::P521, 68, 136).await;
    }

    #[tokio::test]
    async fn pub_from_priv_matches_gen_p521_be() {
        pub_from_priv_roundtrip(HsmByteOrder::Be, EccCurve::P521, 66, 132).await;
    }

    /// Operand-order sign/verify round-trips in both orders, and a
    /// big-endian signature is the per-component reverse of a
    /// little-endian one over the reversed digest.
    async fn sign_verify_op_roundtrip(order: HsmByteOrder, curve: EccCurve, sig_len: usize) {
        let driver = make_driver_with(order);
        let (priv_key, pub_key) = driver.gen_keypair(curve).await.expect("keygen");
        let mut pub_op = [0u8; 136];
        driver
            .pub_coords(&pub_key, order, &mut pub_op[..sig_len])
            .await
            .expect("pub coords");
        let digest_len = ecc_digest_len(curve);
        let hash: Vec<u8> = (1..=digest_len as u8).collect();
        let mut sig = [0u8; 136];
        driver
            .ecc_sign_op(&priv_key, &hash, &mut sig[..sig_len])
            .await
            .expect("sign");
        assert!(driver
            .ecc_verify_op(curve, &pub_op[..sig_len], &hash, &sig[..sig_len])
            .await
            .expect("verify"));
        let mut wrong = hash.clone();
        wrong[0] ^= 1;
        assert!(!driver
            .ecc_verify_op(curve, &pub_op[..sig_len], &wrong, &sig[..sig_len])
            .await
            .expect("verify wrong"));
    }

    #[tokio::test]
    async fn sign_verify_op_both_orders() {
        for order in [HsmByteOrder::Le, HsmByteOrder::Be] {
            sign_verify_op_roundtrip(order, EccCurve::P256, 64).await;
            sign_verify_op_roundtrip(order, EccCurve::P384, 96).await;
        }
        sign_verify_op_roundtrip(HsmByteOrder::Le, EccCurve::P521, 136).await;
        sign_verify_op_roundtrip(HsmByteOrder::Be, EccCurve::P521, 132).await;
    }

    /// ECDH secrets agree across orders: the big-endian secret is the
    /// byte reverse of the little-endian one.
    #[tokio::test]
    async fn ecdh_op_secret_order() {
        let le = make_driver_with(HsmByteOrder::Le);
        let be = make_driver_with(HsmByteOrder::Be);
        let (priv_a, _) = le.gen_keypair(EccCurve::P521).await.expect("keygen a");
        let (_, pub_b) = le.gen_keypair(EccCurve::P521).await.expect("keygen b");
        let mut pub_le = [0u8; 136];
        let mut pub_be = [0u8; 132];
        le.pub_coords(&pub_b, HsmByteOrder::Le, &mut pub_le)
            .await
            .expect("le coords");
        be.pub_coords(&pub_b, HsmByteOrder::Be, &mut pub_be)
            .await
            .expect("be coords");
        let mut s_le = [0u8; 66];
        let mut s_be = [0u8; 66];
        le.ecdh_derive_op(&priv_a, EccCurve::P521, &pub_le, &mut s_le)
            .await
            .expect("le ecdh");
        be.ecdh_derive_op(&priv_a, EccCurve::P521, &pub_be, &mut s_be)
            .await
            .expect("be ecdh");
        s_le.reverse();
        assert_eq!(s_le, s_be);
    }

    #[tokio::test]
    async fn pub_from_priv_rejects_wrong_out_len() {
        let driver = make_driver();
        let priv_hsm = [1u8; 48];
        let mut out = [0u8; 64]; // wrong: P-384 needs 96
        let err = driver
            .pub_from_priv_op(EccCurve::P384, &priv_hsm, &mut out)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn sign_verify_p256() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        let hash = [0xABu8; 32];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert_eq!(sig.len(), 64);
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p384() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        let hash = [0xCDu8; 48];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert_eq!(sig.len(), 96);
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    #[tokio::test]
    async fn sign_verify_p521() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        let hash = [0xEFu8; 64];
        let sig = driver.ecc_sign(&priv_key, &hash).await.unwrap();
        assert_eq!(sig.len(), 132);
        assert!(driver.ecc_verify(&pub_key, &hash, &sig).await.unwrap());
    }

    // ── Verify with wrong hash ──────────────────────────────────

    #[tokio::test]
    async fn verify_wrong_hash_p256() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        let sig = driver.ecc_sign(&priv_key, &[0xAAu8; 32]).await.unwrap();
        assert!(!driver
            .ecc_verify(&pub_key, &[0xBBu8; 32], &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_wrong_hash_p384() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        let sig = driver.ecc_sign(&priv_key, &[0xAAu8; 48]).await.unwrap();
        assert!(!driver
            .ecc_verify(&pub_key, &[0xBBu8; 48], &sig)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn verify_wrong_hash_p521() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        let sig = driver.ecc_sign(&priv_key, &[0xAAu8; 64]).await.unwrap();
        assert!(!driver
            .ecc_verify(&pub_key, &[0xBBu8; 64], &sig)
            .await
            .unwrap());
    }

    // ── ECDH shared secret ──────────────────────────────────────

    #[tokio::test]
    async fn ecdh_p256() {
        let driver = make_driver();
        let (priv_a, pub_a) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        let (priv_b, pub_b) = driver.gen_keypair(EccCurve::P256).await.unwrap();
        let mut secret_ab = [0u8; 32];
        let mut secret_ba = [0u8; 32];
        driver
            .ecdh_derive(&priv_a, &pub_b, &mut secret_ab)
            .await
            .unwrap();
        driver
            .ecdh_derive(&priv_b, &pub_a, &mut secret_ba)
            .await
            .unwrap();
        assert_eq!(secret_ab, secret_ba);
        assert_ne!(secret_ab, [0u8; 32]);
    }

    #[tokio::test]
    async fn ecdh_p384() {
        let driver = make_driver();
        let (priv_a, pub_a) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        let (priv_b, pub_b) = driver.gen_keypair(EccCurve::P384).await.unwrap();
        let mut secret_ab = [0u8; 48];
        let mut secret_ba = [0u8; 48];
        driver
            .ecdh_derive(&priv_a, &pub_b, &mut secret_ab)
            .await
            .unwrap();
        driver
            .ecdh_derive(&priv_b, &pub_a, &mut secret_ba)
            .await
            .unwrap();
        assert_eq!(secret_ab, secret_ba);
        assert_ne!(secret_ab, [0u8; 48]);
    }

    #[tokio::test]
    async fn ecdh_p521() {
        let driver = make_driver();
        let (priv_a, pub_a) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        let (priv_b, pub_b) = driver.gen_keypair(EccCurve::P521).await.unwrap();
        let mut secret_ab = [0u8; 66];
        let mut secret_ba = [0u8; 66];
        driver
            .ecdh_derive(&priv_a, &pub_b, &mut secret_ab)
            .await
            .unwrap();
        driver
            .ecdh_derive(&priv_b, &pub_a, &mut secret_ba)
            .await
            .unwrap();
        assert_eq!(secret_ab, secret_ba);
        assert_ne!(secret_ab, [0u8; 66]);
    }
}
