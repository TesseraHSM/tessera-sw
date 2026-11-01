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

use crate::setup::SCOPE_LOCAL;

/// Length of the messages ML-DSA operations sign and verify.
pub(crate) const MLDSA_MSG_LEN: usize = 64;

/// Host-DMA page size: a response reaches the host as a PRP pair of 4 KiB
/// pages.
const HOST_PAGE: usize = 4096;

/// A device-generated ML-DSA key.
pub(crate) struct MlDsaKey {
    pub(crate) masked: Vec<u8>,
    /// For checking the device's signatures on the host.
    pub(crate) public: MlDsaPublicKey,
}

/// A host-generated ML-DSA key and its signature over each shared message.
pub(crate) struct MlDsaSigner {
    /// Encoded public key, as `MlDsaVerify` takes it.
    pub(crate) pub_key: Vec<u8>,
    /// `sigs[m]` signs message `m` of [`MlDsaSigned::messages`].
    pub(crate) sigs: Vec<Vec<u8>>,
}

/// `MlDsaVerify` inputs, made once on the host and shared by all threads.
pub(crate) struct MlDsaSigned {
    pub(crate) messages: Vec<[u8; MLDSA_MSG_LEN]>,
    pub(crate) keys: Vec<MlDsaSigner>,
}

/// A device-generated ML-KEM key with host ciphertexts for it, shared by
/// all threads.
pub(crate) struct MlKemKey {
    pub(crate) masked: Vec<u8>,
    /// Host encapsulations to the key's public key.
    pub(crate) cts: Vec<Vec<u8>>,
}

/// `N` random bytes.
pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rng().fill(&mut bytes[..]);
    bytes
}

/// `f(i)` for each `i` in `0..n`, in order, spread over the host's cores:
/// the host PQC work behind the shared input pools is the bulk of setup.
fn par_map<T: Send>(
    n: usize,
    f: impl Fn(usize) -> Result<T, String> + Sync,
) -> Result<Vec<T>, String> {
    let threads = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, n.max(1));
    let per = n.div_ceil(threads).max(1);
    let f = &f;
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..n)
            .step_by(per)
            .map(|start| {
                s.spawn(move || {
                    (start..n.min(start + per))
                        .map(f)
                        .collect::<Result<Vec<T>, String>>()
                })
            })
            .collect();
        let mut out = Vec::with_capacity(n);
        for h in handles {
            let chunk = h
                .join()
                .unwrap_or_else(|_| Err("host PQC thread panicked".into()))?;
            out.extend(chunk);
        }
        Ok(out)
    })
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
    (0..n)
        .map(|_| {
            let resp = ctx
                .tbor(&mldsa_keygen_req(session_id, p))
                .map_err(|e| format!("MlDsaGenerateKey({}): {e:?}", p.name))?;
            let public = check_mldsa_key(p, &resp.pub_key, &resp.masked_key)?;
            Ok(MlDsaKey {
                masked: resp.masked_key,
                public,
            })
        })
        .collect()
}

/// Generate `keys` ML-DSA keys for `p` on the host, each signing the same
/// `messages` random messages.
pub(crate) fn host_mldsa_signed(
    p: &MlDsaParams,
    keys: usize,
    messages: usize,
) -> Result<MlDsaSigned, String> {
    let variant = MlDsaVariant::from_pub_key_len(p.pub_key_len)
        .ok_or_else(|| format!("no host {}", p.name))?;
    let messages: Vec<[u8; MLDSA_MSG_LEN]> = (0..messages).map(|_| random()).collect();
    let keys = par_map(keys, |_| host_mldsa_signer(p, variant, &messages))?;
    Ok(MlDsaSigned { messages, keys })
}

/// Generate one ML-DSA key on the host and sign each of `messages`.
fn host_mldsa_signer(
    p: &MlDsaParams,
    variant: MlDsaVariant,
    messages: &[[u8; MLDSA_MSG_LEN]],
) -> Result<MlDsaSigner, String> {
    let key = MlDsaPrivateKey::from_seed(variant, &random::<MLDSA_SEED_LEN>())
        .map_err(|e| format!("host {} keygen: {e:?}", p.name))?;
    let pub_key = key
        .public_key()
        .and_then(|k| k.to_vec())
        .map_err(|e| format!("host {} public key: {e:?}", p.name))?;
    let mut algo = MlDsaAlgo::new(&[]).map_err(|e| format!("host {}: {e:?}", p.name))?;
    let sigs = messages
        .iter()
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
    (0..n)
        .map(|_| {
            MlKemPrivateKey::from_seed(variant, &random::<MLKEM_SEED_LEN>())
                .and_then(|k| k.public_key())
                .and_then(|k| k.to_vec())
                .map_err(|e| format!("host {} keygen: {e:?}", p.name))
        })
        .collect()
}

/// Generate `keys` ML-KEM keys for `p` on the device, and encapsulate to
/// each `messages` times on the host.
pub(crate) fn device_mlkem_keys(
    ctx: &TestCtx,
    session_id: u16,
    p: &MlKemParams,
    keys: usize,
    messages: usize,
) -> Result<Vec<MlKemKey>, String> {
    let generated = (0..keys)
        .map(|_| {
            let resp = ctx
                .tbor(&mlkem_keygen_req(session_id, p))
                .map_err(|e| format!("MlKemGenerateKey({}): {e:?}", p.name))?;
            let public = check_mlkem_key(p, &resp.pub_key, &resp.masked_key)?;
            Ok((resp.masked_key, public))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let cts = par_map(generated.len(), |k| {
        (0..messages)
            .map(|_| host_encapsulate(p, &generated[k].1))
            .collect::<Result<Vec<_>, String>>()
    })?;
    Ok(generated
        .into_iter()
        .zip(cts)
        .map(|((masked, _), cts)| MlKemKey { masked, cts })
        .collect())
}

/// Encapsulate to `public` on the host; returns the ciphertext. The shared
/// secret is dropped: the device returns its own masked, so there is
/// nothing to compare it with.
pub(crate) fn host_encapsulate(
    p: &MlKemParams,
    public: &MlKemPublicKey,
) -> Result<Vec<u8>, String> {
    let mut ct = vec![0u8; p.ciphertext_len];
    let mut secret = [0u8; MLKEM_SHARED_SECRET_LEN];
    MlKemAlgo::new()
        .encapsulate(public, Some(&mut ct), Some(&mut secret))
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

/// Verify a device ML-DSA signature over `message` on the host (empty
/// context, as the device signs with).
pub(crate) fn check_mldsa_sig(
    p: &MlDsaParams,
    public: &MlDsaPublicKey,
    message: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    check_len(sig, p.sig_len, "ML-DSA signature")?;
    check_page_tail(sig, "ML-DSA signature")?;
    let mut algo = MlDsaAlgo::new(&[]).map_err(|e| format!("host ML-DSA: {e:?}"))?;
    let ok = Verifier::verify(&mut algo, public, message, sig)
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
