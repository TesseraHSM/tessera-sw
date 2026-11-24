// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pairwise consistency tests for generated ML-DSA and ML-KEM keys.

use tsra_fw_hsm_pal_traits::*;

use crate::ct_eq;
use crate::scratch;
use crate::scratch_zeroed;
use crate::wipe;

/// Sign a fixed message and verify it with the generated public key.
pub async fn mldsa_pct<P: HsmMlDsa>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    param: HsmMlDsaParamSet,
    sk: &HsmDmaBuf,
    pk: &HsmDmaBuf,
) -> HsmResult<bool> {
    let message = scratch(alloc, b"ML-DSA PCT".len())?;
    message.copy_from_slice(b"ML-DSA PCT");
    let msg = HsmMlDsaMsg::new(HsmMlDsaMsgType::Pure, 0, message)?;
    let sig = scratch_zeroed(alloc, param.sig_len())?;
    pal.mldsa_sign(
        io,
        param,
        HsmMlDsaPrivKey::Expanded(sk),
        HsmMlDsaHedge::Deterministic,
        msg,
        Some(sig),
    )
    .await?;
    pal.mldsa_verify(io, param, HsmMlDsaPubKey::Encoded(pk), msg, sig)
        .await
}

/// Encapsulate and require decapsulation to recover the same shared secret.
pub async fn mlkem_pct<P: HsmMlKem>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    param: HsmMlKemParamSet,
    sk: &HsmDmaBuf,
    pk: &HsmDmaBuf,
) -> HsmResult<bool> {
    let ct = scratch_zeroed(alloc, param.ct_len())?;
    let shared = scratch_zeroed(alloc, MLKEM_SHARED_SECRET_LEN)?;
    let recovered = scratch(alloc, MLKEM_SHARED_SECRET_LEN)?;
    recovered.fill(0xff);
    let result = async {
        pal.mlkem_encaps(io, param, HsmMlKemPubKey::Encoded(pk), Some((ct, shared)))
            .await?;
        pal.mlkem_decaps(
            io,
            param,
            HsmMlKemPrivKey::Expanded(sk),
            ct,
            Some(recovered),
        )
        .await?;
        Ok(ct_eq(shared, recovered))
    }
    .await;
    wipe(shared);
    wipe(recovered);
    result
}
