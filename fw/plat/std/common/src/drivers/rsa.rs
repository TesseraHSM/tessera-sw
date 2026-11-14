// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std RSA driver — performs RSA operations via OpenSSL.
//!
//! Operates on [`tsra_crypto`] key handle types directly
//! (`RsaPrivateKey`, `RsaPublicKey`). The public API accepts
//! references and slices; owned copies for the worker thread
//! boundary are made internally via `Clone` (cheap — OpenSSL
//! key handles are reference-counted).
//!
//! ## Supported key sizes
//!
//! | Key size (bits) | Modulus bytes | Use case |
//! |-----------------|--------------|----------|
//! | 2048            | 256          | Minimum recommended for current use |
//! | 3072            | 384          | Enhanced security for long-term protection |
//! | 4096            | 512          | Maximum security for critical applications |
//!
//! ## Supported operations
//!
//! | Method | Operation | Input | Output |
//! |--------|-----------|-------|--------|
//! | [`gen_keypair`] | Key generation | key size in bits | `(RsaPrivateKey, RsaPublicKey)` |
//! | [`mod_exp_priv`] | Private-key modular exponentiation (`y^d mod n`) | `&RsaPrivateKey`, `&[u8]` | writes `&mut [u8]` |
//! | [`mod_exp_pub`] | Public-key modular exponentiation (`x^e mod n`) | `&RsaPublicKey`, `&[u8]` | writes `&mut [u8]` |
//!
//! ## Modular exponentiation
//!
//! RSA signing and decryption are expressed as private-key modular
//! exponentiation (`mod_exp_priv`: `x = y^d mod n`), while encryption
//! and verification use public-key modular exponentiation (`mod_exp_pub`:
//! `y = x^e mod n`). This matches the hardware PKA register model where
//! the engine performs a single `base^exp mod n` operation regardless of
//! the higher-level use case.
//!
//! Both operations use raw RSA (no padding) via
//! [`RsaEncryptAlgo::with_no_padding()`]. Input buffers must be exactly
//! the modulus size in bytes.
//!
//! ## Thread model
//!
//! All methods clone handles and input slices into owned buffers,
//! then dispatch to the tokio [`WorkerPool`]. The Embassy executor
//! yields while the worker runs, then copies results back.
//!
//! On real Cortex-M7 hardware, these operations would be offloaded
//! to a PKA (Public Key Accelerator) engine via DMA.

use tsra_crypto::DecryptOp;
use tsra_crypto::EncryptOp;
use tsra_crypto::HashAlgo;
use tsra_crypto::KeyGenerationOp;
use tsra_crypto::PrivateKey;
use tsra_crypto::RsaEncryptAlgo;
use tsra_crypto::RsaKeyOp;
use tsra_crypto::RsaPrivateKey;
use tsra_crypto::RsaPublicKey;
use tsra_crypto::RsaSignAlgo;
use tsra_crypto::Verifier;
use tsra_fw_hsm_byte_order as byte_order;
use tsra_fw_hsm_pal_traits::*;

use crate::worker::WorkerPool;

/// Fixed width (bytes) of the public exponent `e` in the raw wire
/// public-key encoding (`n || e`).
pub const RSA_PUB_EXP_WIRE_LEN: usize = 4;

/// Serialize an RSA public-key handle into the raw wire form `n || e`
/// in operand order `order` — the modulus followed by a fixed 4-byte
/// exponent, the raw layout the host's `DdiDerPublicKey` post-decode
/// turns into DER.
///
/// OpenSSL produces big-endian components; each is written straight
/// into `out` and converted in place (a no-op on big-endian PALs).
///
/// Follows the query/alloc/use convention: pass `out = None` to query
/// the wire length (`n_len + RSA_PUB_EXP_WIRE_LEN`) the caller must
/// allocate, then `out = Some(buf)` to serialize.  Returns the wire
/// length in both modes.
pub fn rsa_pub_wire(
    pubk: &RsaPublicKey,
    order: HsmByteOrder,
    out: Option<&mut [u8]>,
) -> HsmResult<usize> {
    let n_len = pubk.n(None).map_err(|_| HsmError::RsaGenerateError)?;
    let wire_len = n_len + RSA_PUB_EXP_WIRE_LEN;
    // Query mode: report the buffer size the caller must allocate.
    let Some(out) = out else {
        return Ok(wire_len);
    };
    let out = out
        .get_mut(..wire_len)
        .ok_or(HsmError::RsaInvalidKeyLength)?;
    let (n_out, e_out) = out.split_at_mut(n_len);
    pubk.n(Some(n_out))
        .map_err(|_| HsmError::RsaGenerateError)?;
    byte_order::int_from_be(order, n_out);
    // Exponent: right-align big-endian in the fixed wire field, then
    // convert the whole field.
    let e_len = pubk.e(None).map_err(|_| HsmError::RsaGenerateError)?;
    let e_at = RSA_PUB_EXP_WIRE_LEN
        .checked_sub(e_len)
        .ok_or(HsmError::RsaInvalidKeyLength)?;
    e_out.fill(0);
    pubk.e(Some(&mut e_out[e_at..]))
        .map_err(|_| HsmError::RsaGenerateError)?;
    byte_order::int_from_be(order, e_out);
    Ok(wire_len)
}

/// Std RSA driver — software RSA via OpenSSL with async worker dispatch.
///
/// Operands are exchanged in the PAL operand byte order; the driver
/// converts to and from the big-endian values OpenSSL uses.
///
/// Created once during PAL initialization and shared across all IO tasks.
pub struct StdRsa {
    pool: WorkerPool,
    order: HsmByteOrder,
}

impl StdRsa {
    /// Create a new RSA driver backed by the given worker pool, using the
    /// PAL operand byte order `order`.
    pub fn new(pool: WorkerPool, order: HsmByteOrder) -> Self {
        Self { pool, order }
    }

    /// Generate an RSA key pair asynchronously.
    ///
    /// Converts `key_size_bits` to bytes and delegates to
    /// [`RsaPrivateKey::generate`] on the worker pool.
    ///
    /// # Parameters
    /// - `key_size_bits` — RSA modulus size in bits (2048, 3072, or 4096).
    ///
    /// # Returns
    /// The `(RsaPrivateKey, RsaPublicKey)` handle pair.
    ///
    /// # Errors
    /// - [`HsmError::RsaGenerateError`] — key generation or public key
    ///   extraction failed.
    pub async fn gen_keypair(
        &self,
        key_size_bits: usize,
    ) -> HsmResult<(RsaPrivateKey, RsaPublicKey)> {
        let size_bytes = key_size_bits / 8;
        self.pool
            .submit_with_result(async move {
                let priv_key =
                    RsaPrivateKey::generate(size_bytes).map_err(|_| HsmError::RsaGenerateError)?;
                let pub_key = priv_key
                    .public_key()
                    .map_err(|_| HsmError::RsaGenerateError)?;
                Ok((priv_key, pub_key))
            })
            .await
    }

    /// Private-key modular exponentiation: `x = y^d mod n`.
    ///
    /// Uses raw RSA (no padding) via [`RsaEncryptAlgo::with_no_padding()`]
    /// and [`DecryptOp::decrypt`] — the "decrypt" operation corresponds to
    /// the private-key exponentiation `y^d mod n`.
    ///
    /// Clones the private key handle (cheap, ref-counted), copies the
    /// input to an owned buffer, and dispatches to the worker pool.
    ///
    /// # Parameters
    /// - `priv_key` — The RSA private key handle.
    /// - `y` — Input data, exactly the key size in bytes; its value must
    ///   satisfy `1 < y < n-1` (FIPS / NIST ACVP).
    /// - `x` — Output buffer for the result. Must be exactly the key
    ///   size in bytes.
    ///
    /// # Errors
    /// - [`HsmError::InvalidArg`] — `y` is outside the required range
    ///   `1 < y < n-1`, or its length disagrees with the modulus.
    /// - [`HsmError::RsaDecryptFailed`] — the modular exponentiation failed.
    pub async fn mod_exp_priv(
        &self,
        priv_key: &RsaPrivateKey,
        y: &[u8],
        x: &mut [u8],
    ) -> HsmResult<()> {
        let result = self.mod_exp_priv_result(priv_key, y, x.len()).await?;
        byte_order::int_copy_from_be(self.order, x, &result)
    }

    /// Replace an operand-order input block with the private-key result.
    pub async fn mod_exp_priv_in_place(
        &self,
        priv_key: &RsaPrivateKey,
        y_x: &mut [u8],
    ) -> HsmResult<()> {
        let result = self.mod_exp_priv_result(priv_key, y_x, y_x.len()).await?;
        byte_order::int_copy_from_be(self.order, y_x, &result)
    }

    async fn mod_exp_priv_result(
        &self,
        priv_key: &RsaPrivateKey,
        y: &[u8],
        out_len: usize,
    ) -> HsmResult<Vec<u8>> {
        // Operands are in PAL order; OpenSSL is big-endian.
        let mut y_be = y.to_vec();
        byte_order::int_to_be(self.order, &mut y_be);

        // FIPS / NIST ACVP: the input value `m` must satisfy `1 < m < n-1`.
        // Reject out-of-range inputs with `InvalidArg` before the
        // exponentiation.  The check lives at the driver level so every
        // backend enforces it — real PKA hardware compares against the
        // modulus natively; here it is a software byte compare.
        reject_out_of_range_mod_exp_input(priv_key, &y_be)?;

        let key = priv_key.clone();
        self.pool
            .submit_with_result(async move {
                let mut algo = RsaEncryptAlgo::with_no_padding();
                let mut buf = vec![0u8; out_len];
                algo.decrypt(&key, &y_be, Some(&mut buf))
                    .map_err(|_| HsmError::RsaDecryptFailed)?;
                Ok::<_, HsmError>(buf)
            })
            .await
    }

    /// Public-key modular exponentiation: `y = x^e mod n`.
    ///
    /// Uses raw RSA (no padding) via [`RsaEncryptAlgo::with_no_padding()`]
    /// and [`EncryptOp::encrypt`] — the "encrypt" operation corresponds to
    /// the public-key exponentiation `x^e mod n`.
    ///
    /// Clones the public key handle (cheap, ref-counted), copies the
    /// input to an owned buffer, and dispatches to the worker pool.
    ///
    /// # Parameters
    /// - `pub_key` — The RSA public key handle.
    /// - `x_input` — Input data. Must be exactly the key size in bytes.
    /// - `y` — Output buffer for the result. Must be exactly the key
    ///   size in bytes.
    ///
    /// # Errors
    /// - [`HsmError::RsaEncryptFailed`] — the modular exponentiation failed.
    pub async fn mod_exp_pub(
        &self,
        pub_key: &RsaPublicKey,
        x_input: &[u8],
        y: &mut [u8],
    ) -> HsmResult<()> {
        let key = pub_key.clone();
        // Operands are in PAL order; OpenSSL is big-endian.
        let mut x_be = x_input.to_vec();
        byte_order::int_to_be(self.order, &mut x_be);
        let out_len = y.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let mut algo = RsaEncryptAlgo::with_no_padding();
                let mut buf = vec![0u8; out_len];
                algo.encrypt(&key, &x_be, Some(&mut buf))
                    .map_err(|_| HsmError::RsaEncryptFailed)?;
                Ok::<_, HsmError>(buf)
            })
            .await?;

        // `result` is big-endian; emit the operand-order form.
        byte_order::int_copy_from_be(self.order, y, &result)
    }

    /// Verify a digest using an operand-order `n || e(4)` key and signature.
    /// The digest is a standard byte string. `salt_len` selects PSS when
    /// present, and PKCS#1 v1.5 otherwise.
    pub async fn verify(
        &self,
        key_size: HsmRsaKey,
        hash: HashAlgo,
        pub_key: &[u8],
        digest: &[u8],
        signature: &[u8],
        salt_len: Option<usize>,
    ) -> HsmResult<bool> {
        let k = key_size.modulus_len();
        let max_salt = k
            .checked_sub(hash.size())
            .and_then(|len| len.checked_sub(2))
            .ok_or(HsmError::InvalidArg)?;
        if pub_key.len() != k + RSA_PUB_EXP_WIRE_LEN
            || signature.len() != k
            || digest.len() != hash.size()
            || salt_len.is_some_and(|len| len > max_salt)
        {
            return Err(HsmError::InvalidArg);
        }
        let mut public = pub_key.to_vec();
        byte_order::int_to_be(self.order, &mut public[..k]);
        byte_order::int_to_be(self.order, &mut public[k..]);
        let mut signature = signature.to_vec();
        byte_order::int_to_be(self.order, &mut signature);
        let digest = digest.to_vec();
        self.pool
            .submit_with_result(async move {
                let key = <RsaPublicKey as tsra_crypto::ImportableHsmKey>::from_hsm_bytes(&public)
                    .map_err(|_| HsmError::InvalidArg)?;
                let mut algorithm = match salt_len {
                    Some(len) => RsaSignAlgo::with_pss_padding(hash, len),
                    None => RsaSignAlgo::with_pkcs1_padding(hash),
                };
                Verifier::verify(&mut algorithm, &key, &digest, &signature)
                    .map_err(|_| HsmError::RsaEncryptFailed)
            })
            .await
    }

    /// RSA-OAEP decrypt (EME-OAEP, RFC 8017 §7.1.2).
    ///
    /// `ciphertext` is the operand-order RSA block; OpenSSL expects the
    /// standard big-endian byte string, so the block is converted here in
    /// the driver, mirroring [`rsa_pub_wire`].
    ///
    /// # Parameters
    /// - `priv_key` — the RSA private key handle.
    /// - `hash` — OAEP hash (label hash + MGF1).
    /// - `label` — optional OAEP label (`None` for the empty label).
    /// - `ciphertext` — operand-order RSA ciphertext (modulus-sized).
    /// - `output` — plaintext destination; must hold the recovered
    ///   message (`<= modulus_len`).
    ///
    /// # Returns
    /// - `Ok(len)` — recovered plaintext length; `output[..len]` valid.
    ///
    /// # Errors
    /// - [`HsmError::RsaDecryptFailed`] — OAEP unpadding detected
    ///   tampering, wrong key, or a label mismatch.
    pub async fn oaep_decrypt(
        &self,
        priv_key: &RsaPrivateKey,
        hash: HashAlgo,
        label: Option<Vec<u8>>,
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> HsmResult<usize> {
        let key = priv_key.clone();
        let mut ct_be = ciphertext.to_vec();
        byte_order::int_to_be(self.order, &mut ct_be);
        // OpenSSL sizes the decrypt output from a query that returns an
        // upper bound (up to the modulus size), so the scratch buffer
        // must be modulus-sized even though the recovered OAEP plaintext
        // is smaller.  `ct_be.len()` is the modulus length.
        let scratch_len = ct_be.len();
        let caller_len = output.len();

        let result = self
            .pool
            .submit_with_result(async move {
                let mut algo = RsaEncryptAlgo::with_oaep_padding(hash, label.as_deref());
                let mut buf = vec![0u8; scratch_len];
                let written = algo
                    .decrypt(&key, &ct_be, Some(&mut buf))
                    .map_err(|_| HsmError::RsaDecryptFailed)?;
                buf.truncate(written);
                Ok::<_, HsmError>(buf)
            })
            .await?;

        if result.len() > caller_len {
            return Err(HsmError::RsaInvalidKeyLength);
        }
        output[..result.len()].copy_from_slice(&result);
        Ok(result.len())
    }
}

/// Reject an RSA modular-exponentiation input outside the FIPS / NIST
/// ACVP range `1 < m < n - 1`, where `n` is the private key's modulus.
///
/// `m_be` is the big-endian, modulus-length input value.  The modulus
/// is recovered from the key's derived public key (uniform for CRT and
/// non-CRT keys).  Returns [`HsmError::InvalidArg`] when the input is out
/// of range or its length disagrees with the modulus.
fn reject_out_of_range_mod_exp_input(priv_key: &RsaPrivateKey, m_be: &[u8]) -> HsmResult<()> {
    /// Largest supported modulus (RSA-4096) in bytes.
    const MAX_MODULUS_LEN: usize = 512;

    let pubk = priv_key
        .public_key()
        .map_err(|_| HsmError::RsaDecryptFailed)?;
    let n_len = pubk.n(None).map_err(|_| HsmError::RsaDecryptFailed)?;
    if n_len > MAX_MODULUS_LEN || n_len != m_be.len() {
        return Err(HsmError::InvalidArg);
    }
    let mut n_be = [0u8; MAX_MODULUS_LEN];
    pubk.n(Some(&mut n_be[..n_len]))
        .map_err(|_| HsmError::RsaDecryptFailed)?;

    if mod_exp_input_in_range(&n_be[..n_len], m_be) {
        Ok(())
    } else {
        Err(HsmError::InvalidArg)
    }
}

/// Byte-wise check that the big-endian value `m` satisfies
/// `1 < m < n - 1`, where `n` is the big-endian modulus of equal length.
///
/// Mirrors the reference firmware's NIST-ACVP input validation: computes
/// `n - m` byte by byte from the least-significant end and requires no
/// final borrow (`m <= n`) and a difference of at least 2, plus `m > 1`.
fn mod_exp_input_in_range(n: &[u8], m: &[u8]) -> bool {
    let Some((&m_low, m_high)) = m.split_last() else {
        return false;
    };
    if n.len() != m.len() {
        return false;
    }
    let m_gt_one = m_low > 1 || m_high.iter().any(|&b| b != 0);

    let mut borrow = false;
    let mut diff_high_nonzero = false;
    let mut diff_low = 0u8;
    for (i, (&nb, &mb)) in n.iter().zip(m).enumerate().rev() {
        let (d, b1) = nb.overflowing_sub(mb);
        let (d, b2) = d.overflowing_sub(u8::from(borrow));
        borrow = b1 || b2;
        if i == n.len() - 1 {
            diff_low = d;
        } else {
            diff_high_nonzero |= d != 0;
        }
    }
    m_gt_one && !borrow && (diff_high_nonzero || diff_low > 1)
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Handle;

    use super::*;

    fn make_driver() -> StdRsa {
        StdRsa::new(WorkerPool::new(Handle::current()), HsmByteOrder::Le)
    }

    /// Build a small test message of exactly `key_size_bytes` bytes:
    /// all zeros except the last byte is `0x02`. This is a small
    /// integer (numerically < modulus) that is safe for raw RSA.
    fn small_test_message(key_size_bytes: usize) -> Vec<u8> {
        let mut msg = vec![0u8; key_size_bytes];
        msg[key_size_bytes - 1] = 0x02;
        msg
    }

    /// Edge cases for the `1 < m < n - 1` input-range check (all values
    /// big-endian).
    #[test]
    fn mod_exp_input_range_check() {
        // n = 0x0100FF (65791); valid m is 2..=65789 (1 < m < n-1).
        let n = [0x01, 0x00, 0xFF];
        assert!(!mod_exp_input_in_range(&n, &[0x00, 0x00, 0x00]), "m = 0");
        assert!(!mod_exp_input_in_range(&n, &[0x00, 0x00, 0x01]), "m = 1");
        assert!(mod_exp_input_in_range(&n, &[0x00, 0x00, 0x02]), "m = 2");
        assert!(mod_exp_input_in_range(&n, &[0x01, 0x00, 0xFD]), "m = n-2");
        assert!(!mod_exp_input_in_range(&n, &[0x01, 0x00, 0xFE]), "m = n-1");
        assert!(!mod_exp_input_in_range(&n, &[0x01, 0x00, 0xFF]), "m = n");
        assert!(!mod_exp_input_in_range(&n, &[0x01, 0x01, 0x00]), "m = n+1");

        // Borrow pattern: n = 0x010000, so n-1 = 0x00FFFF.
        let n2 = [0x01, 0x00, 0x00];
        assert!(!mod_exp_input_in_range(&n2, &[0x00, 0xFF, 0xFF]), "m = n-1");
        assert!(mod_exp_input_in_range(&n2, &[0x00, 0xFF, 0xFE]), "m = n-2");

        // Length mismatch and empty inputs are rejected.
        assert!(!mod_exp_input_in_range(&n, &[0x00, 0x02]));
        assert!(!mod_exp_input_in_range(&[], &[]));
    }

    // ── Key generation ──────────────────────────────────────────

    #[tokio::test]
    async fn verify_rejects_oversized_pss_hash() {
        let driver = make_driver();
        assert_eq!(
            driver
                .verify(
                    HsmRsaKey::Rsa2048Pub,
                    HashAlgo::shake256(std::num::NonZeroUsize::new(300).expect("nonzero length")),
                    &[0; 260],
                    &[0; 300],
                    &[0; 256],
                    Some(0)
                )
                .await,
            Err(HsmError::InvalidArg)
        );
    }

    #[tokio::test]
    async fn gen_keypair_2048() {
        let driver = make_driver();
        let (_priv_key, _pub_key) = driver.gen_keypair(2048).await.unwrap();
    }

    #[tokio::test]
    async fn gen_keypair_3072() {
        let driver = make_driver();
        let (_priv_key, _pub_key) = driver.gen_keypair(3072).await.unwrap();
    }

    #[tokio::test]
    async fn gen_keypair_4096() {
        let driver = make_driver();
        let (_priv_key, _pub_key) = driver.gen_keypair(4096).await.unwrap();
    }

    // ── Mod_exp roundtrip (encrypt with pub → decrypt with priv) ─

    async fn mod_exp_roundtrip(key_size_bits: usize) {
        let driver = make_driver();
        let key_size_bytes = key_size_bits / 8;
        let (priv_key, pub_key) = driver.gen_keypair(key_size_bits).await.unwrap();

        let plaintext = small_test_message(key_size_bytes);

        // Encrypt: y = plaintext^e mod n
        let mut ciphertext = vec![0u8; key_size_bytes];
        driver
            .mod_exp_pub(&pub_key, &plaintext, &mut ciphertext)
            .await
            .unwrap();
        assert_ne!(ciphertext, plaintext);

        // Decrypt: x = ciphertext^d mod n
        let mut decrypted = vec![0u8; key_size_bytes];
        driver
            .mod_exp_priv(&priv_key, &ciphertext, &mut decrypted)
            .await
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn mod_exp_roundtrip_2048() {
        mod_exp_roundtrip(2048).await;
    }

    #[tokio::test]
    async fn mod_exp_roundtrip_3072() {
        mod_exp_roundtrip(3072).await;
    }

    #[tokio::test]
    async fn mod_exp_roundtrip_4096() {
        mod_exp_roundtrip(4096).await;
    }

    /// End-to-end driver check: `mod_exp_priv` recovers the modulus from
    /// the OpenSSL key and rejects out-of-range wire inputs with
    /// `InvalidArg`.  `m = 0` and `m = 1` (little-endian, byte 0 is the
    /// LSB) are out of the `1 < m < n-1` range; a valid `m = 2` succeeds.
    #[tokio::test]
    async fn mod_exp_priv_rejects_out_of_range_inputs() {
        let driver = make_driver();
        let key_size_bytes = 256; // RSA-2048
        let (priv_key, _pub_key) = driver.gen_keypair(2048).await.unwrap();
        let mut out = vec![0u8; key_size_bytes];

        let m_zero = vec![0u8; key_size_bytes];
        assert!(matches!(
            driver.mod_exp_priv(&priv_key, &m_zero, &mut out).await,
            Err(HsmError::InvalidArg)
        ));

        let mut m_one = vec![0u8; key_size_bytes];
        m_one[0] = 1;
        assert!(matches!(
            driver.mod_exp_priv(&priv_key, &m_one, &mut out).await,
            Err(HsmError::InvalidArg)
        ));

        let mut m_two = vec![0u8; key_size_bytes];
        m_two[0] = 2;
        driver
            .mod_exp_priv(&priv_key, &m_two, &mut out)
            .await
            .unwrap();
    }

    // ── Identity test: pub(priv(m)) == m ─────────────────────────

    #[tokio::test]
    async fn mod_exp_priv_pub_identity_2048() {
        let driver = make_driver();
        let key_size_bytes = 256;
        let (priv_key, pub_key) = driver.gen_keypair(2048).await.unwrap();

        let plaintext = small_test_message(key_size_bytes);

        // priv(m) = m^d mod n
        let mut intermediate = vec![0u8; key_size_bytes];
        driver
            .mod_exp_priv(&priv_key, &plaintext, &mut intermediate)
            .await
            .unwrap();

        // pub(priv(m)) = (m^d)^e mod n == m
        let mut recovered = vec![0u8; key_size_bytes];
        driver
            .mod_exp_pub(&pub_key, &intermediate, &mut recovered)
            .await
            .unwrap();
        assert_eq!(recovered, plaintext);
    }

    // ── Wire byte-order contract (little-endian operands) ────────
    //
    // The round-trip / identity tests above reverse symmetrically, so
    // they pass even if the LE<->BE flips are wrong (or absent). These
    // tests pin the *absolute* wire byte order by comparing the driver
    // against a direct OpenSSL no-padding operation: on the wire the
    // operands are little-endian, while OpenSSL is big-endian. A
    // non-palindrome input (`m_be != reverse(m_be)`) makes the two byte
    // orders distinguishable.

    /// Build a non-palindrome big-endian test integer `< n` (leading
    /// byte `0x01`), so reversing it yields a genuinely different value.
    fn nonpalindrome_be(key_size_bytes: usize) -> Vec<u8> {
        let mut m = vec![0u8; key_size_bytes];
        m[0] = 0x01;
        m[1] = 0x23;
        m[key_size_bytes - 1] = 0x02;
        m
    }

    /// `mod_exp_pub` must consume a little-endian `x` and emit a
    /// little-endian `y`, i.e. `y == reverse(m_be^e mod n)`, verified
    /// against a direct big-endian OpenSSL no-padding public op.
    #[tokio::test]
    async fn mod_exp_pub_wire_le_matches_openssl() {
        let driver = make_driver();
        let key_size_bytes = 256;
        let (_priv_key, pub_key) = driver.gen_keypair(2048).await.unwrap();

        let m_be = nonpalindrome_be(key_size_bytes);

        // Independent reference: raw RSA public op in big-endian.
        let mut ref_be = vec![0u8; key_size_bytes];
        {
            let mut algo = RsaEncryptAlgo::with_no_padding();
            let written = algo.encrypt(&pub_key, &m_be, Some(&mut ref_be)).unwrap();
            assert_eq!(written, key_size_bytes);
        }
        let mut expected_le = ref_be.clone();
        expected_le.reverse();

        // Driver consumes little-endian `x` and emits little-endian `y`.
        let mut m_le = m_be.clone();
        m_le.reverse();
        let mut y_le = vec![0u8; key_size_bytes];
        driver
            .mod_exp_pub(&pub_key, &m_le, &mut y_le)
            .await
            .unwrap();

        assert_eq!(y_le, expected_le);
        // Guard: the output must be little-endian, not the big-endian
        // OpenSSL form (would be equal only if the output flip were missing).
        assert_ne!(y_le, ref_be);
    }

    /// `mod_exp_priv` must consume a little-endian `y` and emit a
    /// little-endian `x`, i.e. `x == reverse(m_be^d mod n)`, verified
    /// against a direct big-endian OpenSSL no-padding private op.
    #[tokio::test]
    async fn mod_exp_priv_wire_le_matches_openssl() {
        let driver = make_driver();
        let key_size_bytes = 256;
        let (priv_key, _pub_key) = driver.gen_keypair(2048).await.unwrap();

        let m_be = nonpalindrome_be(key_size_bytes);

        // Independent reference: raw RSA private op in big-endian.
        let mut ref_be = vec![0u8; key_size_bytes];
        {
            let mut algo = RsaEncryptAlgo::with_no_padding();
            algo.decrypt(&priv_key, &m_be, Some(&mut ref_be)).unwrap();
        }
        let mut expected_le = ref_be.clone();
        expected_le.reverse();

        // Driver consumes little-endian `y` and emits little-endian `x`.
        let mut m_le = m_be.clone();
        m_le.reverse();
        let mut x_le = vec![0u8; key_size_bytes];
        driver
            .mod_exp_priv(&priv_key, &m_le, &mut x_le)
            .await
            .unwrap();

        assert_eq!(x_le, expected_le);
        assert_ne!(x_le, ref_be);
    }

    // ── OAEP decrypt (wire-LE ciphertext → recovered plaintext) ──

    #[tokio::test]
    async fn oaep_decrypt_2048_roundtrip() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(2048).await.unwrap();

        // A representative 32-byte KEK (AES-256).
        let plaintext = b"a 32-byte AES-256 KEK for unwrap";
        assert_eq!(plaintext.len(), 32);

        // Encrypt with OAEP — OpenSSL emits a big-endian ciphertext.
        let mut ct_be = vec![0u8; 256];
        {
            let mut algo = RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None);
            let written = algo.encrypt(&pub_key, plaintext, Some(&mut ct_be)).unwrap();
            assert_eq!(written, 256);
        }

        // The wire carries the RSA block little-endian; reverse it so the
        // driver's LE->BE flip restores the original before OpenSSL.
        let mut ct_le = ct_be.clone();
        ct_le.reverse();

        let mut out = vec![0u8; 256];
        let len = driver
            .oaep_decrypt(&priv_key, HashAlgo::sha256(), None, &ct_le, &mut out)
            .await
            .unwrap();
        assert_eq!(&out[..len], plaintext);
    }

    #[tokio::test]
    async fn oaep_decrypt_2048_tamper_fails() {
        let driver = make_driver();
        let (priv_key, pub_key) = driver.gen_keypair(2048).await.unwrap();

        let mut ct_be = vec![0u8; 256];
        {
            let mut algo = RsaEncryptAlgo::with_oaep_padding(HashAlgo::sha256(), None);
            algo.encrypt(&pub_key, b"secret", Some(&mut ct_be)).unwrap();
        }
        let mut ct_le = ct_be.clone();
        ct_le.reverse();
        ct_le[0] ^= 0xff; // corrupt the ciphertext

        let mut out = vec![0u8; 256];
        let res = driver
            .oaep_decrypt(&priv_key, HashAlgo::sha256(), None, &ct_le, &mut out)
            .await;
        assert!(res.is_err());
    }
}
