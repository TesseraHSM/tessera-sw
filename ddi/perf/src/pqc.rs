// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ML-DSA and ML-KEM: device keys, inputs made on the host, and checks of
//! device responses, as the TBOR PQC command tests do them.
//!
//! The host reference is `tsra_crypto`'s pure-Rust ML-DSA and ML-KEM,
//! independent of the firmware's implementation. ML-DSA is checked end to
//! end: device signatures must verify on the host, and the device must
//! accept host signatures. ML-KEM shared secrets leave the device masked
//! under a key the host cannot derive, so KEM results can only be checked
//! for shape: lengths and the masked blob's AEAD envelope.

use rand::RngExt;
use tsra_crypto::EncapsulateOp;
use tsra_crypto::ExportableKey;
use tsra_crypto::ImportableKey;
use tsra_crypto::MlDsaAlgo;
use tsra_crypto::MlDsaPrivateKey;
use tsra_crypto::MlDsaPublicKey;
use tsra_crypto::MlDsaVariant;
use tsra_crypto::MlKemAlgo;
use tsra_crypto::MlKemPrivateKey;
use tsra_crypto::MlKemPublicKey;
use tsra_crypto::MlKemVariant;
use tsra_crypto::PrivateKey;
use tsra_crypto::Rng;
use tsra_crypto::Signer;
use tsra_crypto::Verifier;
use tsra_crypto::MLDSA_SEED_LEN;
use tsra_crypto::MLKEM_SEED_LEN;
use tsra_crypto::MLKEM_SHARED_SECRET_LEN;
use tsra_ddi_tbor_test_harness::pqc::MlDsaParams;
use tsra_ddi_tbor_test_harness::pqc::MlKemParams;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_types::TborMlDsaGenerateKeyReq;
use tsra_ddi_tbor_types::TborMlKemGenerateKeyReq;
use tsra_ddi_tbor_types::MASKED_MLKEM_SHARED_SECRET_MAX_LEN;
use tsra_ddi_tbor_types::MLDSA_MU_LEN;
use zeroize::Zeroizing;

use crate::setup::par_map;
use crate::setup::SCOPE_LOCAL;

/// Host-DMA page size: a response reaches the host as a PRP pair of 4 KiB
/// pages.
const HOST_PAGE: usize = 4096;

/// A device-generated ML-DSA key.
pub(crate) struct MlDsaKey {
    pub(crate) masked: Vec<u8>,
    /// For checking the device's signatures on the host.
    pub(crate) public: MlDsaPublicKey,
}

/// A host-generated ML-DSA key and its signatures in [`MlDsaSigned`].
pub(crate) struct MlDsaSigner {
    /// Encoded public key, as `MlDsaVerify` takes it.
    pub(crate) pub_key: Vec<u8>,
    /// Its signatures, in pair order: key `k` of `n` signs pairs `k`,
    /// `k + n`, `k + 2n`, ...
    sigs: Vec<Vec<u8>>,
}

/// `MlDsaVerify` inputs, made once on the host and shared by all threads:
/// [`Self::pairs`] signatures, pair `i` signing `μ` `i % mus` with key
/// `i % keys`. So every key and every `μ` is used, at a cost linear in
/// their number.
pub(crate) struct MlDsaSigned {
    /// Random message representatives, which is what the commands take.
    mus: Vec<Vec<u8>>,
    keys: Vec<MlDsaSigner>,
}

impl MlDsaSigned {
    /// The number of signed pairs: `max(keys, mus)`.
    pub(crate) fn pairs(&self) -> usize {
        self.keys.len().max(self.mus.len())
    }

    /// Pair `i`: `(public key, μ, signature)`.
    pub(crate) fn pair(&self, i: usize) -> (&[u8], &[u8], &[u8]) {
        let n = self.keys.len();
        let key = &self.keys[i % n];
        (
            &key.pub_key,
            &self.mus[i % self.mus.len()],
            &key.sigs[i / n],
        )
    }
}

/// A device-generated ML-KEM key and its ciphertexts in [`MlKemCts`].
pub(crate) struct MlKemKey {
    masked: Vec<u8>,
    /// Host encapsulations to the key's public key, in pair order as for
    /// [`MlDsaSigner::sigs`].
    cts: Vec<Vec<u8>>,
}

/// `MlKemDecapsulate` inputs, shared by all threads: [`Self::pairs`] host
/// ciphertexts, ciphertext `i` to key `i % keys`.
pub(crate) struct MlKemCts {
    keys: Vec<MlKemKey>,
    pairs: usize,
}

impl MlKemCts {
    pub(crate) fn pairs(&self) -> usize {
        self.pairs
    }

    /// Pair `i`: `(masked key, ciphertext)`.
    pub(crate) fn pair(&self, i: usize) -> (&[u8], &[u8]) {
        let n = self.keys.len();
        let key = &self.keys[i % n];
        (&key.masked, &key.cts[i / n])
    }
}

/// `MlDsaGenerateKey` for `p`, masked under the local scope.
pub(crate) fn mldsa_keygen_req(session_id: u16, p: &MlDsaParams) -> TborMlDsaGenerateKeyReq {
    TborMlDsaGenerateKeyReq {
        session_id,
        scope: SCOPE_LOCAL,
        key_kind: p.key_kind,
    }
}

/// `MlKemGenerateKey` for `p`, masked under the local scope.
pub(crate) fn mlkem_keygen_req(session_id: u16, p: &MlKemParams) -> TborMlKemGenerateKeyReq {
    TborMlKemGenerateKeyReq {
        session_id,
        scope: SCOPE_LOCAL,
        key_kind: p.key_kind,
    }
}

/// Generate `n` ML-DSA keys for `p` on the device.
pub(crate) fn device_mldsa_keys(
    ctx: &TestCtx,
    session_id: u16,
    p: &MlDsaParams,
    n: usize,
) -> Result<Vec<MlDsaKey>, String> {
    par_map(n, |_| {
        let resp = ctx
            .tbor(&mldsa_keygen_req(session_id, p))
            .map_err(|e| format!("MlDsaGenerateKey({}): {e:?}", p.name))?;
        let public = check_mldsa_key(p, &resp.pub_key, &resp.masked_key)?;
        Ok(MlDsaKey {
            masked: resp.masked_key,
            public,
        })
    })
}

/// Generate `keys` ML-DSA keys for `p` on the host and sign `mus` random
/// message representatives with them, as [`MlDsaSigned`] pairs them.
pub(crate) fn host_mldsa_signed(
    p: &MlDsaParams,
    keys: usize,
    mus: usize,
) -> Result<MlDsaSigned, String> {
    let variant = MlDsaVariant::from_pub_key_len(p.pub_key_len)
        .ok_or_else(|| format!("no host {}", p.name))?;
    let pairs = keys.max(mus);
    let mus = (0..mus)
        .map(|_| Rng::rand_vec(MLDSA_MU_LEN))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("host ML-DSA mu: {e:?}"))?;
    let keys = par_map(keys, |k| {
        let mine = (k..pairs).step_by(keys).map(|i| &mus[i % mus.len()]);
        host_mldsa_signer(p, variant, mine)
    })?;
    Ok(MlDsaSigned { mus, keys })
}

/// Generate one ML-DSA key on the host and sign each of `mus`.
fn host_mldsa_signer<'m>(
    p: &MlDsaParams,
    variant: MlDsaVariant,
    mus: impl Iterator<Item = &'m Vec<u8>>,
) -> Result<MlDsaSigner, String> {
    let mut seed = Zeroizing::new([0u8; MLDSA_SEED_LEN]);
    rand::rng().fill(&mut seed[..]);
    let key = MlDsaPrivateKey::from_seed(variant, &seed[..])
        .map_err(|e| format!("host {} keygen: {e:?}", p.name))?;
    let pub_key = key
        .public_key()
        .and_then(|k| k.to_vec())
        .map_err(|e| format!("host {} public key: {e:?}", p.name))?;
    let mut algo = MlDsaAlgo::external_mu();
    let sigs = mus
        .map(|m| {
            let mut sig = vec![0u8; p.sig_len];
            let len = Signer::sign(&mut algo, &key, m, Some(&mut sig))
                .map_err(|e| format!("host {} sign: {e:?}", p.name))?;
            sig.truncate(len);
            Ok(sig)
        })
        .collect::<Result<_, String>>()?;
    Ok(MlDsaSigner { pub_key, sigs })
}

/// Generate `n` ML-KEM key pairs for `p` on the host; returns their
/// encapsulation keys.
pub(crate) fn host_mlkem_pub_keys(p: &MlKemParams, n: usize) -> Result<Vec<Vec<u8>>, String> {
    let variant = MlKemVariant::from_pub_key_len(p.pub_key_len)
        .ok_or_else(|| format!("no host {}", p.name))?;
    par_map(n, |_| {
        let mut seed = Zeroizing::new([0u8; MLKEM_SEED_LEN]);
        rand::rng().fill(&mut seed[..]);
        MlKemPrivateKey::from_seed(variant, &seed[..])
            .and_then(|k| k.public_key())
            .and_then(|k| k.to_vec())
            .map_err(|e| format!("host {} keygen: {e:?}", p.name))
    })
}

/// Generate `keys` ML-KEM keys for `p` on the device, and on the host
/// `max(keys, messages)` ciphertexts to them, as [`MlKemCts`] pairs them.
pub(crate) fn device_mlkem_keys(
    ctx: &TestCtx,
    session_id: u16,
    p: &MlKemParams,
    keys: usize,
    messages: usize,
) -> Result<MlKemCts, String> {
    let pairs = keys.max(messages);
    let keys = par_map(keys, |k| {
        let resp = ctx
            .tbor(&mlkem_keygen_req(session_id, p))
            .map_err(|e| format!("MlKemGenerateKey({}): {e:?}", p.name))?;
        let public = check_mlkem_key(p, &resp.pub_key, &resp.masked_key)?;
        let cts = (k..pairs)
            .step_by(keys)
            .map(|_| host_encapsulate(p, &public))
            .collect::<Result<_, String>>()?;
        Ok(MlKemKey {
            masked: resp.masked_key,
            cts,
        })
    })?;
    Ok(MlKemCts { keys, pairs })
}

/// Encapsulate to `public` on the host; returns the ciphertext. The shared
/// secret is dropped: the device returns its own masked, so there is
/// nothing to compare it with.
pub(crate) fn host_encapsulate(
    p: &MlKemParams,
    public: &MlKemPublicKey,
) -> Result<Vec<u8>, String> {
    let mut ct = vec![0u8; p.ciphertext_len];
    let mut secret = Zeroizing::new([0u8; MLKEM_SHARED_SECRET_LEN]);
    MlKemAlgo::new()
        .encapsulate(public, Some(&mut ct), Some(&mut secret[..]))
        .map_err(|e| format!("host {} encapsulate: {e:?}", p.name))?;
    Ok(ct)
}

/// Check an `MlDsaGenerateKey` response for `p`; returns its public key.
pub(crate) fn check_mldsa_key(
    p: &MlDsaParams,
    pub_key: &[u8],
    masked: &[u8],
) -> Result<MlDsaPublicKey, String> {
    check_len(pub_key, p.pub_key_len, "ML-DSA public key")?;
    check_nonzero(pub_key, "ML-DSA public key")?;
    check_masked(masked, p.masked_key_len, "masked ML-DSA key")?;
    MlDsaPublicKey::from_bytes(pub_key).map_err(|e| format!("ML-DSA public key: {e:?}"))
}

/// Check an `MlKemGenerateKey` response for `p`; returns its encapsulation
/// key.
pub(crate) fn check_mlkem_key(
    p: &MlKemParams,
    pub_key: &[u8],
    masked: &[u8],
) -> Result<MlKemPublicKey, String> {
    check_len(pub_key, p.pub_key_len, "ML-KEM public key")?;
    check_nonzero(pub_key, "ML-KEM public key")?;
    check_masked(masked, p.masked_key_len, "masked ML-KEM key")?;
    MlKemPublicKey::from_bytes(pub_key).map_err(|e| format!("ML-KEM public key: {e:?}"))
}

/// Verify a device ML-DSA signature over `mu` on the host.
pub(crate) fn check_mldsa_sig(
    p: &MlDsaParams,
    public: &MlDsaPublicKey,
    mu: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    check_len(sig, p.sig_len, "ML-DSA signature")?;
    check_page_tail(sig, "ML-DSA signature")?;
    let mut algo = MlDsaAlgo::external_mu();
    let ok = Verifier::verify(&mut algo, public, mu, sig)
        .map_err(|e| format!("host ML-DSA verify: {e:?}"))?;
    if ok {
        Ok(())
    } else {
        Err("ML-DSA signature does not verify".into())
    }
}

/// Check an ML-KEM ciphertext's shape for `p`.
pub(crate) fn check_mlkem_ct(p: &MlKemParams, ct: &[u8]) -> Result<(), String> {
    check_len(ct, p.ciphertext_len, "ML-KEM ciphertext")?;
    check_nonzero(ct, "ML-KEM ciphertext")
}

/// Check a masked ML-KEM shared secret. It is masked under a key the host
/// cannot derive, so only its shape can be checked.
pub(crate) fn check_masked_secret(blob: &[u8]) -> Result<(), String> {
    check_masked(
        blob,
        MASKED_MLKEM_SHARED_SECRET_MAX_LEN,
        "masked shared secret",
    )
}

/// Check a masked blob: `len` bytes of AEAD envelope.
fn check_masked(blob: &[u8], len: usize, what: &str) -> Result<(), String> {
    check_len(blob, len, what)?;
    if !blob.starts_with(b"AEAD") {
        return Err(format!("{what} is not an AEAD envelope"));
    }
    check_page_tail(blob, what)
}

fn check_len(field: &[u8], len: usize, what: &str) -> Result<(), String> {
    if field.len() == len {
        Ok(())
    } else {
        Err(format!("{what} is {} bytes, expected {len}", field.len()))
    }
}

fn check_nonzero(field: &[u8], what: &str) -> Result<(), String> {
    if field.iter().any(|&b| b != 0) {
        Ok(())
    } else {
        Err(format!("{what} is all zeroes"))
    }
}

/// Fail if `field` crosses the 4 KiB host-DMA page and is all zeroes past
/// it: the mark of a response truncated at the first PRP page (see the TBOR
/// test harness's `assert_not_truncated_at_page`).
fn check_page_tail(field: &[u8], what: &str) -> Result<(), String> {
    match field.get(HOST_PAGE..) {
        Some(tail) if !tail.is_empty() && tail.iter().all(|&b| b == 0) => Err(format!(
            "{what} is all zeroes past the 4 KiB host-DMA page (truncated at the first PRP page?)"
        )),
        _ => Ok(()),
    }
}
