// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM AES keys for the engine's AES-CBC and AES-256-GCM ciphers (see
//! [`tsra_ossl_engine_core::cipher_method`]).
//!
//! `TSRA_CTRL_SET_KEY_URI` names a masked AES key blob
//! (`tsra://<path>;type=<aes|aes-gcm>[;bits=<n>]`, e.g. one [`generate_key`]
//! or, for `type=aes`, an HKDF derive wrote). It is unmasked into the HSM for
//! that cipher context (and its copies) and deleted when the last of them is
//! cleaned up or the key is replaced; the blob itself, the persistent form, is
//! never modified. The key must match the cipher's mode and size exactly.

use std::sync::Arc;

use tsra_api::HsmAesCbcAlgo;
use tsra_api::HsmAesGcmAlgo;
use tsra_api::HsmAesGcmKey;
use tsra_api::HsmAesGcmKeyGenAlgo;
use tsra_api::HsmAesGcmKeyUnmaskAlgo;
use tsra_api::HsmAesKey;
use tsra_api::HsmAesKeyGenAlgo;
use tsra_api::HsmAesKeyUnmaskAlgo;
use tsra_api::HsmAesXtsKeyGenAlgo;
use tsra_api::HsmDecryptOp;
use tsra_api::HsmEncryptOp;
use tsra_api::HsmError;
use tsra_api::HsmKeyClass;
use tsra_api::HsmKeyCommonProps;
use tsra_api::HsmKeyDeleteOp;
use tsra_api::HsmKeyGenOp;
use tsra_api::HsmKeyKind;
use tsra_api::HsmKeyManager;
use tsra_api::HsmKeyProps;
use tsra_api::HsmKeyPropsBuilder;
use tsra_api::HsmKeyUnmaskOp;
use tsra_api::HsmSession;
use tsra_ossl_engine_core::cipher_method::AES_BLOCK;
use tsra_ossl_engine_core::cipher_method::AesCbcKey;
use tsra_ossl_engine_core::cipher_method::AesGcmKey;
use tsra_ossl_engine_core::cipher_method::AesKeyLoader;
use tsra_ossl_engine_core::cipher_method::GCM_IV_LEN;
use tsra_ossl_engine_core::cipher_method::GCM_TAG_LEN;
use tsra_ossl_engine_core::engine::Engine;
use tsra_ossl_engine_core::error::EngineError;
use tsra_ossl_engine_core::error::EngineResult;
use zeroize::Zeroizing;

use crate::context::delete_hsm_key;
use crate::engine_impl::engine_data_slot;
use crate::uri::AesKind;
use crate::uri::KeyType;

/// Sizes of the HSM's plain AES keys (`type=aes`), in bits.
pub(crate) const AES_KEY_BITS: [u32; 3] = [128, 192, 256];
/// Size of a generated `type=aes` key without `bits=`, as in the provider.
const DEFAULT_AES_KEY_BITS: u32 = 256;
/// The only AES-GCM key size, in bits.
const AES_GCM_KEY_BITS: u32 = 256;
/// The only AES-XTS key size (a pair of AES-256 keys), in bits.
const AES_XTS_KEY_BITS: u32 = 512;

/// Marker type carrying the engine's AES key loading (see [`AesKeyLoader`]).
pub(crate) struct TsraAes;

impl AesKeyLoader for TsraAes {
    fn load_cbc_key(engine: &Engine, uri: &str, key_bits: u32) -> EngineResult<Arc<dyn AesCbcKey>> {
        let algo = HsmAesKeyUnmaskAlgo::default();
        let key = unmask_cipher_key(engine, uri, AesKind::Cbc, key_bits, algo)?;
        Ok(Arc::new(CipherKey::new(key)))
    }

    fn load_gcm_key(engine: &Engine, uri: &str, key_bits: u32) -> EngineResult<Arc<dyn AesGcmKey>> {
        let algo = HsmAesGcmKeyUnmaskAlgo::default();
        let key = unmask_cipher_key(engine, uri, AesKind::Gcm, key_bits, algo)?;
        Ok(Arc::new(CipherKey::new(key)))
    }
}

/// Unmask, with `algo`, the `kind` key `uri` names for a cipher of
/// `key_bits`. The URI's type and `bits=` are checked before the HSM is
/// touched; a key of another size is deleted again.
fn unmask_cipher_key<A>(
    engine: &Engine,
    uri: &str,
    kind: AesKind,
    key_bits: u32,
    mut algo: A,
) -> EngineResult<A::Key>
where
    A: HsmKeyUnmaskOp<Session = HsmSession, Error = HsmError>,
    A::Key: HsmKeyCommonProps + HsmKeyDeleteOp,
{
    let parsed = crate::uri::parse(uri)?;
    if parsed.key_type != KeyType::Aes(kind) {
        return Err(EngineError::Other(format!(
            "the key URI type does not fit this cipher (AES-CBC takes type=aes, \
             AES-GCM type=aes-gcm): {uri}"
        )));
    }
    if let Some(bits) = parsed.bits
        && bits != key_bits
    {
        return Err(EngineError::Other(format!(
            "the key URI says {bits} bits, but the cipher needs {key_bits}"
        )));
    }
    let slot = engine_data_slot()?;
    let data = slot
        .get(engine)
        .ok_or(EngineError::NullParam("engine_data"))?;
    // First caller may be the cipher (idempotent open).
    data.open_hsm_from_env()?;
    let masked = crate::keyload::read_masked_key(&parsed.masked_key_path)?;
    let key = data.with_session(|session| {
        HsmKeyManager::unmask_key(session, &mut algo, &masked)
            .map_err(|e| EngineError::wrap("AES key unmask", e))
    })?;
    let bits = key.bits();
    if bits != key_bits {
        delete_hsm_key(key, "size-mismatched AES key");
        return Err(EngineError::Other(format!(
            "the AES key is {bits} bits, but the cipher needs {key_bits}"
        )));
    }
    Ok(key)
}

/// The `GENERATE_KEY` ctrl command: generate the AES key `uri` names
/// (`tsra://<file>;type=<aes|aes-gcm|aes-xts>[;bits=<n>]`) in the HSM and
/// write its masked blob to the file, replacing any file there. The HSM key is
/// deleted again: the blob is its persistent form.
pub(crate) fn generate_key(engine: &Engine, uri: &str) -> EngineResult<()> {
    let parsed = crate::uri::parse(uri)?;
    let KeyType::Aes(kind) = parsed.key_type else {
        return Err(EngineError::Other(format!(
            "GENERATE_KEY makes AES keys only: {uri}"
        )));
    };
    let props = keygen_props(kind, parsed.bits)?;
    let slot = engine_data_slot()?;
    let data = slot
        .get(engine)
        .ok_or(EngineError::NullParam("engine_data"))?;
    // The command may be the first HSM touch (idempotent open).
    data.open_hsm_from_env()?;
    let masked = data.with_session(|session| match kind {
        AesKind::Cbc => generate_masked(session, HsmAesKeyGenAlgo::default(), props),
        AesKind::Gcm => generate_masked(session, HsmAesGcmKeyGenAlgo::default(), props),
        AesKind::Xts => generate_masked(session, HsmAesXtsKeyGenAlgo::default(), props),
    })?;
    crate::keygen::write_masked_blob(&parsed.masked_key_path, &masked)
}

/// Props of a new `kind` key of `bits` bits: 256 by default for `type=aes`,
/// the only size for the other kinds.
fn keygen_props(kind: AesKind, bits: Option<u32>) -> EngineResult<HsmKeyProps> {
    let (key_kind, sizes, default): (HsmKeyKind, &[u32], u32) = match kind {
        AesKind::Cbc => (HsmKeyKind::Aes, &AES_KEY_BITS, DEFAULT_AES_KEY_BITS),
        AesKind::Gcm => (HsmKeyKind::AesGcm, &[AES_GCM_KEY_BITS], AES_GCM_KEY_BITS),
        AesKind::Xts => (HsmKeyKind::AesXts, &[AES_XTS_KEY_BITS], AES_XTS_KEY_BITS),
    };
    let bits = bits.unwrap_or(default);
    if !sizes.contains(&bits) {
        return Err(EngineError::Other(format!(
            "unsupported key size {bits} for this AES key type; supported: {sizes:?}"
        )));
    }
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(key_kind)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .map_err(|e| EngineError::wrap("build AES key props", e))
}

/// Generate a key with `algo` and `props` and return its masked blob. The key
/// is deleted from the HSM again, also when the export fails.
fn generate_masked<A>(
    session: &HsmSession,
    mut algo: A,
    props: HsmKeyProps,
) -> EngineResult<Zeroizing<Vec<u8>>>
where
    A: HsmKeyGenOp<Session = HsmSession, Error = HsmError>,
    A::Key: HsmKeyCommonProps + HsmKeyDeleteOp,
{
    let key = HsmKeyManager::generate_key(session, &mut algo, props)
        .map_err(|e| EngineError::wrap("generate AES key", e))?;
    let masked = key.masked_key_vec();
    delete_hsm_key(key, "generated AES key");
    masked
        .map(Zeroizing::new)
        .map_err(|e| EngineError::wrap("export masked AES key", e))
}

/// An unmasked HSM key attached to cipher contexts, deleted from the HSM
/// when dropped.
pub(crate) struct CipherKey<K: HsmKeyDeleteOp>(
    /// Always `Some` until dropped (the `Option` lets drop move it out).
    Option<K>,
);

impl<K: HsmKeyDeleteOp> CipherKey<K> {
    /// Takes ownership of `key`; dropping the result deletes it from the HSM.
    pub(crate) fn new(key: K) -> Self {
        Self(Some(key))
    }

    /// The SDK key, for the HSM calls.
    fn key(&self) -> EngineResult<&K> {
        self.0.as_ref().ok_or(EngineError::NullParam("AES key"))
    }
}

impl<K: HsmKeyDeleteOp> Drop for CipherKey<K> {
    fn drop(&mut self) {
        if let Some(key) = self.0.take() {
            delete_hsm_key(key, "cipher AES key");
        }
    }
}

impl AesCbcKey for CipherKey<HsmAesKey> {
    fn cbc(
        &self,
        encrypt: bool,
        iv: &mut [u8; AES_BLOCK],
        input: &[u8],
        output: &mut [u8],
    ) -> EngineResult<()> {
        let key = self.key()?;
        // Raw CBC: the EVP layer pads and buffers; the algo chains the IV.
        // `input` is at most one device request (HSM_CBC_REQUEST), so the SDK
        // sends it as one, and a retried request restarts from `iv`.
        let mut algo = HsmAesCbcAlgo::with_no_padding(iv.to_vec())
            .map_err(|e| EngineError::wrap("AES-CBC IV", e))?;
        let written = if encrypt {
            HsmEncryptOp::encrypt(&mut algo, key, input, Some(output))
        } else {
            HsmDecryptOp::decrypt(&mut algo, key, input, Some(output))
        }
        .map_err(|e| EngineError::wrap("AES-CBC", e))?;
        if written != input.len() {
            return Err(EngineError::Other(format!(
                "AES-CBC produced {written} of {} bytes",
                input.len()
            )));
        }
        iv.copy_from_slice(algo.iv());
        Ok(())
    }
}

impl AesGcmKey for CipherKey<HsmAesGcmKey> {
    fn encrypt(
        &self,
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> EngineResult<[u8; GCM_TAG_LEN]> {
        let mut algo = HsmAesGcmAlgo::new_for_encryption(iv.to_vec(), gcm_aad(aad))
            .map_err(|e| EngineError::wrap("AES-GCM IV", e))?;
        let written = HsmEncryptOp::encrypt(&mut algo, self.key()?, input, Some(output))
            .map_err(|e| EngineError::wrap("AES-GCM encrypt", e))?;
        check_gcm_len(written, input.len())?;
        algo.tag()
            .copied()
            .ok_or(EngineError::Other("AES-GCM produced no tag".into()))
    }

    fn decrypt(
        &self,
        iv: &[u8; GCM_IV_LEN],
        aad: &[u8],
        tag: &[u8; GCM_TAG_LEN],
        input: &[u8],
        output: &mut [u8],
    ) -> EngineResult<()> {
        let mut algo = HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), tag.to_vec(), gcm_aad(aad))
            .map_err(|e| EngineError::wrap("AES-GCM IV or tag", e))?;
        let written = HsmDecryptOp::decrypt(&mut algo, self.key()?, input, Some(output))
            .map_err(|e| EngineError::wrap("AES-GCM decrypt", e))?;
        check_gcm_len(written, input.len())
    }
}

/// The SDK's form of `aad`: `None` when empty.
fn gcm_aad(aad: &[u8]) -> Option<Vec<u8>> {
    (!aad.is_empty()).then(|| aad.to_vec())
}

/// Fails unless the SDK wrote all `expected` bytes.
fn check_gcm_len(written: usize, expected: usize) -> EngineResult<()> {
    if written != expected {
        return Err(EngineError::Other(format!(
            "AES-GCM produced {written} of {expected} bytes"
        )));
    }
    Ok(())
}
