// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HSM HMAC keys for the engine's HMAC method (see
//! [`tsra_ossl_engine_core::hmac_method`]). `ENGINE_load_private_key` with a
//! `tsra://<masked-key-file>;type=hmac` URI returns an `EVP_PKEY_HMAC` whose
//! MACs run on the HSM through `EVP_DigestSign*`, with the digest of the key's
//! kind (SHA-256, SHA-384 or SHA-512).
//!
//! The `EVP_PKEY` keeps the masked key, not an HSM key: each MAC unmasks it and
//! deletes it again, as the provider does per MAC context. 1.1.1 does not tell
//! the engine when the `EVP_PKEY` is freed, so a key held across MACs would
//! never be released.

use std::ffi::c_int;

use tsra_api::HsmHmacAlgo;
use tsra_api::HsmHmacKey;
use tsra_api::HsmHmacKeyUnmaskAlgo;
use tsra_api::HsmKeyCommonProps;
use tsra_api::HsmKeyKind;
use tsra_api::HsmKeyManager;
use tsra_api::HsmSigner;
use tsra_ossl_engine_core::engine::Engine;
use tsra_ossl_engine_core::error::EngineError;
use tsra_ossl_engine_core::error::EngineResult;
use tsra_ossl_engine_core::ffi;
use tsra_ossl_engine_core::hmac_method::HmacKey;
use zeroize::Zeroizing;

use crate::context::EngineData;
use crate::context::delete_hsm_key;
use crate::engine_impl::engine_data_slot;

/// A masked HMAC key with the digest and MAC length of its kind.
struct TsraHmacKey {
    masked: Zeroizing<Vec<u8>>,
    md_nid: c_int,
    mac_len: usize,
}

impl HmacKey for TsraHmacKey {
    fn md_nid(&self) -> c_int {
        self.md_nid
    }

    fn mac_len(&self) -> usize {
        self.mac_len
    }

    fn sign(&self, engine: &Engine, message: &[u8]) -> EngineResult<Vec<u8>> {
        let slot = engine_data_slot()?;
        let data = slot
            .get(engine)
            .ok_or(EngineError::NullParam("engine_data"))?;
        let key = unmask(data, &self.masked)?;
        let mac = HsmSigner::sign_vec(&mut HsmHmacAlgo::new(), &key, message)
            .map_err(|e| EngineError::wrap("HMAC sign", e));
        delete_hsm_key(key, "HMAC key");
        mac
    }
}

/// Unmask the HMAC key in `masked` into the HSM.
fn unmask(data: &EngineData, masked: &[u8]) -> EngineResult<HsmHmacKey> {
    data.with_session(|session| {
        HsmKeyManager::unmask_key(session, &mut HsmHmacKeyUnmaskAlgo::default(), masked)
            .map_err(|e| EngineError::wrap("HMAC key unmask", e))
    })
}

/// Digest NID and MAC length of an HMAC key kind.
fn digest_of(kind: HsmKeyKind) -> EngineResult<(c_int, usize)> {
    match kind {
        HsmKeyKind::HmacSha256 => Ok((ffi::NID_sha256 as c_int, 32)),
        HsmKeyKind::HmacSha384 => Ok((ffi::NID_sha384 as c_int, 48)),
        HsmKeyKind::HmacSha512 => Ok((ffi::NID_sha512 as c_int, 64)),
        other => Err(EngineError::Other(format!(
            "not an HMAC key kind: {other:?}"
        ))),
    }
}

/// Check that `masked` holds an HMAC key and return it as an engine-bound
/// `EVP_PKEY_HMAC` (see the module docs).
pub(crate) fn load_hmac(
    engine: &Engine,
    data: &EngineData,
    masked: &[u8],
) -> EngineResult<*mut ffi::EVP_PKEY> {
    let key = unmask(data, masked)?;
    let kind = key.kind();
    delete_hsm_key(key, "HMAC key");
    let (md_nid, mac_len) = digest_of(kind)?;
    tsra_ossl_engine_core::hmac_method::new_hmac_pkey(
        engine,
        Box::new(TsraHmacKey {
            masked: Zeroizing::new(masked.to_vec()),
            md_nid,
            mac_len,
        }),
    )
}
