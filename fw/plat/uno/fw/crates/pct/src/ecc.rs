// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECC pairwise consistency tests.
//!
//! - **Sign/verify:** Hash a fixed message, sign the digest with the private
//!   key, and verify the signature with the public key.
//! - **Key agreement:** Run ECDH in both directions against a fixed test key
//!   pair, as SP 800-56A allows: the key under test with the test public key,
//!   and the test private key with the public key under test. Both must give
//!   the same shared secret. Only the X coordinate is compared. A public key
//!   under test that fails validation fails the test.

use tsra_fw_hsm_pal_traits::HsmDigestForm;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmEcc;
use tsra_fw_hsm_pal_traits::HsmEccCurve;
use tsra_fw_hsm_pal_traits::HsmEccPct;
use tsra_fw_hsm_pal_traits::HsmEcdsaNonce;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmHash;
use tsra_fw_hsm_pal_traits::HsmHashAlgo;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmScopedAlloc;

use crate::vectors;

/// Byte that fills the sign/verify test message.
const MESSAGE_BYTE: u8 = 100;

/// Length of the sign/verify test message: the widest ECC operand.
const MESSAGE_LEN: usize = 68;

/// PCT operations whose backend needs additional workspace.
pub enum EccPctOperation<'a> {
    Verify {
        hash: HsmHashAlgo,
        public: &'a HsmDmaBuf,
        input: &'a HsmDmaBuf,
        valid: &'a mut bool,
    },
    Derive {
        private: &'a HsmDmaBuf,
        public: &'a HsmDmaBuf,
        secret: &'a mut HsmDmaBuf,
    },
}

/// PCT-owned storage, excluding the backend's verification/ECDH workspace.
pub fn ecc_pct_workspace_len<P: HsmEcc>(curve: HsmEccCurve, pct: &HsmEccPct) -> usize {
    let coord = curve.wire_coord_len(P::ECC_COORD_PAD);
    match pct {
        HsmEccPct::None => 0,
        HsmEccPct::SignVerify => {
            MESSAGE_LEN + curve.ecdsa_verify_input_len(digest_algo(curve), P::ECC_COORD_PAD)
        }
        HsmEccPct::KeyAgreement => 7 * coord,
    }
}

/// Runs the ECC pairwise consistency test that `pct` selects.
///
/// `priv_key` and `pub_key` use the PAL's wire format: little-endian, with
/// each P-521 value padded to 68 bytes. Scratch buffers come from `alloc`.
///
/// # Returns
///
/// - `Ok(true)` — the key pair passed, or `pct` is [`HsmEccPct::None`].
/// - `Ok(false)` — the key pair is inconsistent. For the key-agreement test,
///   that includes a public key under test that fails validation.
/// - `Err(_)` — an allocation or PAL operation failed, so the test didn't
///   finish.
pub async fn ecc_pct<P: HsmEcc + HsmHash>(
    pal: &P,
    io: &P::Io,
    alloc: &impl HsmScopedAlloc,
    curve: HsmEccCurve,
    pct: &HsmEccPct,
    priv_key: &HsmDmaBuf,
    pub_key: &HsmDmaBuf,
) -> HsmResult<bool> {
    let len = ecc_pct_workspace_len::<P>(curve, pct);
    if len == 0 {
        return Ok(true);
    }
    let workspace = crate::scratch(alloc, len)?;
    ecc_pct_in_workspace(
        pal,
        io,
        curve,
        pct,
        priv_key,
        pub_key,
        workspace,
        async |operation, _: &mut HsmDmaBuf| match operation {
            EccPctOperation::Verify {
                hash,
                public,
                input,
                valid,
            } => {
                *valid = pal.ecc_verify(io, curve, hash, public, input).await?;
                Ok(())
            }
            EccPctOperation::Derive {
                private,
                public,
                secret,
            } => pal
                .ecdh_derive(io, curve, private, public, Some(secret))
                .await
                .map(|_| ()),
        },
    )
    .await
}

/// Run a PCT using caller-owned storage and workspace-aware backend operations.
///
/// The workspace begins with [`ecc_pct_workspace_len`] bytes for the test;
/// the remainder is passed to `operation` and reused between backend calls.
/// A verification operation must set `valid` to its boolean verification result.
#[allow(clippy::too_many_arguments)]
pub async fn ecc_pct_in_workspace<P, F>(
    pal: &P,
    io: &P::Io,
    curve: HsmEccCurve,
    pct: &HsmEccPct,
    priv_key: &HsmDmaBuf,
    pub_key: &HsmDmaBuf,
    workspace: &mut HsmDmaBuf,
    mut operation: F,
) -> HsmResult<bool>
where
    P: HsmEcc + HsmHash,
    F: for<'a> AsyncFnMut(EccPctOperation<'a>, &'a mut HsmDmaBuf) -> HsmResult<()>,
{
    let len = ecc_pct_workspace_len::<P>(curve, pct);
    if workspace.len() < len {
        return Err(HsmError::NotEnoughSpace);
    }
    let (scratch, backend) = workspace.split_at_mut(len);
    match pct {
        HsmEccPct::None => Ok(true),
        HsmEccPct::SignVerify => {
            sign_verify(
                pal,
                io,
                curve,
                priv_key,
                pub_key,
                scratch,
                backend,
                &mut operation,
            )
            .await
        }
        HsmEccPct::KeyAgreement => {
            key_agreement(
                curve,
                curve.wire_coord_len(P::ECC_COORD_PAD),
                priv_key,
                pub_key,
                scratch,
                backend,
                &mut operation,
            )
            .await
        }
    }
}

/// Returns the hash that the sign/verify PCT uses for each curve.
fn digest_algo(curve: HsmEccCurve) -> HsmHashAlgo {
    match curve {
        HsmEccCurve::P256 => HsmHashAlgo::Sha256,
        HsmEccCurve::P384 => HsmHashAlgo::Sha384,
        HsmEccCurve::P521 => HsmHashAlgo::Sha512,
    }
}

#[allow(clippy::too_many_arguments)]
async fn sign_verify<P, F>(
    pal: &P,
    io: &P::Io,
    curve: HsmEccCurve,
    priv_key: &HsmDmaBuf,
    pub_key: &HsmDmaBuf,
    scratch: &mut HsmDmaBuf,
    backend: &mut HsmDmaBuf,
    operation: &mut F,
) -> HsmResult<bool>
where
    P: HsmEcc + HsmHash,
    F: for<'a> AsyncFnMut(EccPctOperation<'a>, &'a mut HsmDmaBuf) -> HsmResult<()>,
{
    let algo = digest_algo(curve);
    let (message, input) = scratch.split_at_mut(MESSAGE_LEN);
    message.fill(MESSAGE_BYTE);

    // Sign `k ‖ digest` in place, leaving `r ‖ s` in the first two lanes,
    // then hash again into the digest lane after them to form the verify
    // input `r ‖ s ‖ digest`.
    let coord = curve.wire_coord_len(P::ECC_COORD_PAD);
    let sign_len = curve.ecdsa_sign_input_len(algo, P::ECC_COORD_PAD);
    input.fill(0);
    hash_into_lane(pal, io, algo, message, &mut input[coord..sign_len]).await?;
    pal.ecc_sign_in_place(
        io,
        curve,
        algo,
        priv_key,
        HsmEcdsaNonce::Generated,
        &mut input[..sign_len],
    )
    .await?;
    hash_into_lane(pal, io, algo, message, &mut input[2 * coord..]).await?;

    let mut valid = false;
    operation(
        EccPctOperation::Verify {
            hash: algo,
            public: pub_key,
            input,
            valid: &mut valid,
        },
        backend,
    )
    .await?;
    Ok(valid)
}

/// Hashes `message` into the start of a zero-filled digest lane, in the
/// operand form that ECDSA consumes.
async fn hash_into_lane<P: HsmHash>(
    pal: &P,
    io: &P::Io,
    algo: HsmHashAlgo,
    message: &HsmDmaBuf,
    lane: &mut HsmDmaBuf,
) -> HsmResult<()> {
    lane.fill(0);
    pal.hash(
        io,
        algo,
        message,
        HsmDigestForm::Operand,
        Some(&mut lane[..algo.digest_len()]),
    )
    .await
    .map(|_| ())
}

async fn key_agreement<F>(
    curve: HsmEccCurve,
    coord: usize,
    priv_key: &HsmDmaBuf,
    pub_key: &HsmDmaBuf,
    scratch: &mut HsmDmaBuf,
    backend: &mut HsmDmaBuf,
    operation: &mut F,
) -> HsmResult<bool>
where
    F: for<'a> AsyncFnMut(EccPctOperation<'a>, &'a mut HsmDmaBuf) -> HsmResult<()>,
{
    let test = vectors::ecdh_test_pair(curve);

    let (test_priv, scratch) = scratch.split_at_mut(coord);
    test_private_key_into(curve, test_priv);
    let (test_pub, scratch) = scratch.split_at_mut(2 * coord);
    test_pub.fill(0);
    vectors::be_to_le(test.qx, &mut test_pub[..test.qx.len()]);
    vectors::be_to_le(test.qy, &mut test_pub[coord..coord + test.qy.len()]);

    // The PKA may write the whole shared point, so each output holds X and
    // Y. The two outputs start different, so they can only match if both
    // derivations write them.
    let (from_key, from_test_key) = scratch.split_at_mut(2 * coord);
    from_key.fill(0);
    from_test_key.fill(0xFF);

    // Both derivations share one await point, which keeps the compiled
    // code small. Only the second uses the public key under test, so only
    // its validation errors mean the key pair is inconsistent: they fail the
    // test, as a mismatched secret does. The first uses the fixed test
    // public key, so any error from it is returned.
    let derived: HsmResult<bool> = async {
        for (d, q, out, under_test) in [
            (priv_key, &*test_pub, &mut *from_key, false),
            (&*test_priv, pub_key, &mut *from_test_key, true),
        ] {
            match operation(
                EccPctOperation::Derive {
                    private: d,
                    public: q,
                    secret: out,
                },
                backend,
            )
            .await
            {
                Err(
                    HsmError::EccPublicKeyValidationFailed | HsmError::EccPointValidationFailed,
                ) if under_test => {
                    return Ok(false);
                }
                result => result?,
            }
        }
        Ok(true)
    }
    .await;

    let secret_len = curve.secret_len();
    let consistent = matches!(derived, Ok(true))
        && crate::ct_eq(&from_key[..secret_len], &from_test_key[..secret_len]);
    crate::wipe(from_key);
    crate::wipe(from_test_key);
    derived.map(|_| consistent)
}

/// Builds the fixed test private key for `curve` in the Uno PAL's vault
/// format: the scalar little-endian, zero-padded to the curve's wire
/// coordinate length.
///
/// The test vectors hold only the raw scalar, so the key is built directly
/// instead of through the PAL's DER conversion.
fn test_private_key_into(curve: HsmEccCurve, test_priv: &mut HsmDmaBuf) {
    let d = vectors::ecdh_test_pair(curve).d;
    test_priv.fill(0);
    vectors::be_to_le(d, &mut test_priv[..d.len()]);
}
