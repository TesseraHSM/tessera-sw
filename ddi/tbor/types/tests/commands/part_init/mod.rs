// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `PartInit` command.
//!
//! `PartInit` is mainline-supported on both `emu` and hardware. Tests
//! run on both backends by default.
//!
//! Cross-test isolation comes from [`TestCtx::new`] (factory-reset +
//! process-global lock held for the ctx's lifetime, see
//! [`tsra_ddi_tbor_test_harness::fixture`]) so each test starts from a pristine
//! `Enabled` partition with the canonical default PSKs.
//!
//! Submodules group tests by what is being exercised:
//! * [`success_path`] — the full `OpenSession → PskChange → PartInit`
//!   flow, plus the cold-restart determinism test.
//! * [`fw_rejects`] — dispatcher/handler gates that reject **before**
//!   any partition-state mutation (default PSK, role, malformed
//!   policy).
//! * [`crypto_rejects`] — `mach_seed_envelope` AEAD-GCM tag and
//!   AAD-binding rejects.
//!
//! PartInit-specific helpers (`open_co_with`, the wire-correct
//! `known_good_part_policy`/`part_policy_with_pota`/`mach_seed` fixtures)
//! live in this module. Shared role-session bootstrap helpers and
//! rotated PSKs live in [`tsra_ddi_tbor_test_harness::fixture`].

use tsra_ddi_tbor_test_harness::x509_fixture::spki_thumbprint;
use tsra_ddi_tbor_test_harness::SessionHandshake;
use tsra_ddi_tbor_test_harness::SessionOpenInitOptions;
use tsra_ddi_tbor_test_harness::TestCtx;
use tsra_ddi_tbor_test_harness::TestPolicy;
use tsra_ddi_tbor_test_harness::CO_PSK_ID as CO;
use tsra_ddi_tbor_types::PolicyKey;
use tsra_ddi_tbor_types::SessionType;
use tsra_ddi_tbor_types::MACH_SEED_LEN;
use tsra_ddi_tbor_types::POLICY_THUMBPRINT_LEN;
use tsra_ddi_tbor_types::PSK_LEN;

mod crypto_rejects;
mod fw_rejects;
mod sd_config;
mod success_path;

/// Filler POTA thumbprint for tests that never walk a PTA chain.
pub(crate) const FILLER_POTA_THUMBPRINT: [u8; POLICY_THUMBPRINT_LEN] =
    [0x10; POLICY_THUMBPRINT_LEN];

/// Filler SATA thumbprint for tests that never verify a sealing key.
pub(crate) const FILLER_SATA_THUMBPRINT: [u8; POLICY_THUMBPRINT_LEN] =
    [0x20; POLICY_THUMBPRINT_LEN];

/// Build a canonical CBOR `PartPolicy` document that passes
/// `tsra_fw_hsm_core::ddi::tbor::policy::from_bytes`: filler POTA and
/// SATA thumbprints, no SAPOTA / backing partition, flags clear and a
/// 64-byte `info`.
pub(crate) fn known_good_part_policy() -> Vec<u8> {
    known_good_test_policy().encode()
}

/// The [`TestPolicy`] behind [`known_good_part_policy`], for tests that
/// tweak individual fields before encoding.
pub(crate) fn known_good_test_policy() -> TestPolicy {
    TestPolicy::new(FILLER_POTA_THUMBPRINT, FILLER_SATA_THUMBPRINT).with_info(&[0xAB; 64])
}

/// Like [`known_good_part_policy`] but anchored to a caller-supplied
/// **real** `POTAPubKey` (raw P-384 `X ‖ Y`, 96 bytes) via its SPKI
/// thumbprint, so `PartFinal` can validate a PTA certificate chain
/// rooted in it.
pub(crate) fn part_policy_with_pota(pota_raw: &[u8; 96]) -> Vec<u8> {
    let mut p = known_good_test_policy();
    p.pota_spki_thumbprint = spki_thumbprint(pota_raw);
    p.encode()
}

/// Return `policy` with the first byte of its `info` value flipped: still
/// a canonical policy with the same anchors, but a different hash.
/// `policy` must carry the 64-byte `info` of [`known_good_test_policy`].
pub(crate) fn perturb_policy_info(policy: &[u8]) -> Vec<u8> {
    const INFO_ENTRY_HEAD: [u8; 3] = [PolicyKey::Info as u8, 0x58, 64];
    let pos = policy
        .windows(INFO_ENTRY_HEAD.len())
        .position(|w| w == INFO_ENTRY_HEAD)
        .expect("policy carries the 64-byte fixture info");
    let mut out = policy.to_vec();
    out[pos + INFO_ENTRY_HEAD.len()] ^= 0xFF;
    out
}

pub(crate) fn mach_seed() -> [u8; MACH_SEED_LEN] {
    let mut v = [0u8; MACH_SEED_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    v
}

/// Seal an AEAD-GCM envelope under `param_key` with a caller-controlled
/// AAD and plaintext. Used by `crypto_rejects` to build envelopes the
/// canonical `encrypt_mach_seed_envelope` helper can't produce (wrong
/// AAD length, wrong plaintext length, mismatched session id, etc.).
/// Mirrors the `build_envelope` helper in `commands/psk_change.rs`.
pub(super) fn build_envelope(
    param_key: &tsra_crypto::AesKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    use tsra_crypto::aead_envelope;
    use tsra_crypto::aead_envelope::AeadAlg;
    use tsra_crypto::Rng;

    let iv = Rng::rand_vec(AeadAlg::AesGcm256.iv_len()).expect("rng iv");
    let total = aead_envelope::seal(AeadAlg::AesGcm256, param_key, &iv, aad, plaintext, None)
        .expect("aead size");
    let mut out = vec![0u8; total];
    let n = aead_envelope::seal(
        AeadAlg::AesGcm256,
        param_key,
        &iv,
        aad,
        plaintext,
        Some(&mut out),
    )
    .expect("aead seal");
    out.truncate(n);
    out
}

/// Open a CO session under the supplied PSK (bypassing the partition
/// default).
pub(super) fn open_co_with(ctx: &TestCtx, psk: &[u8; PSK_LEN]) -> SessionHandshake {
    let opts = SessionOpenInitOptions::new(CO, SessionType::Authenticated).with_psk(psk);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("session_open_init under PSK");
    ctx.session_open_finish(pending)
        .expect("session_open_finish under PSK")
}
