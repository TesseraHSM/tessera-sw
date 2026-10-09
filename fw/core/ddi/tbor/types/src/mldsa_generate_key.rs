// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `MlDsaGenerateKey` wire schema.
//!
//! `MlDsaGenerateKey` is (temporarily) an out-of-session command that generates a fresh
//! ML-DSA (FIPS 204) keypair for the requested PQC key kind and returns
//! the private key as a **masked** blob plus the wire public key.  The
//! private key is **not** stored on the device: the caller holds the
//! masked blob and passes it back to [`MlDsaSign`](crate::mldsa_sign)
//! (unmask-on-use).  This is the TBOR analogue of MBOR
//! `MldsaGenerateKey`, but without a vault `private_key_id`.
//!
//! Inputs:
//!
//! * `scope` — the [`KeyScope`] whose masking key wraps the private key.
//! * `key_kind` — the [`MlDsaKeyKind`] selecting ML-DSA-44 / -65 / -87.
//!   The TBOR wire ships **seed-only** private keys, so `masked_key`
//!   always carries the compact 32-byte `xi` seed.
//!
//! Outputs:
//!
//! * `masked_key` — the ML-DSA seed, masked (AEAD-GCM-256) under the
//!   scope's masking key.
//! * `pub_key` — the ML-DSA public key bytes.
//!
//! # TEMPORARY: out-of-session bring-up
//!
//! **This command is wired as `no_session` purely to unblock hardware
//! bring-up and MUST be reverted to `in_session` before any PR.**  TBOR
//! session establishment currently fails on real silicon
//! (`SessionOpenInit` -> `TborDecodeError`), which blocks every
//! in-session command, while the `no_session` path is proven working
//! there by `ApiRev`.  Running out of session means the request carries
//! no `session_id` and the private key is masked under a hardcoded
//! development key rather than a partition masking key, so there is
//! **no authentication, no authorization and no key protection**.
//! Not fit to ship.

use open_enum::open_enum;
use tsra_fw_ddi_tbor_api::tbor;

use crate::key_props::KeyScope;

/// TBOR opcode for `MlDsaGenerateKey`.
pub const TBOR_OP_MLDSA_GENERATE_KEY: u8 = 0x26;

/// Maximum masked ML-DSA private-key envelope length.
///
/// The TBOR wire ships **seed-only** ML-DSA private keys (see
/// [`MlDsaKeyKind`]), so the masked plaintext is always the 32-byte `xi`
/// seed: `header(8) ‖ iv(12) ‖ aad(192) ‖ pt(32) ‖ tag(16)` = 260 bytes.
/// The 228-byte constant part is the AEAD-GCM-256 masked-envelope
/// overhead.
///
/// If an expanded (`Private`) kind is ever added to [`MlDsaKeyKind`], the
/// worst-case plaintext becomes the 4896-byte ML-DSA-87 secret key and
/// this constant — together with the `max_len` literals on
/// [`TborMlDsaGenerateKeyResp::masked_key`] and
/// [`TborMlDsaSignReq`](crate::mldsa_sign::TborMlDsaSignReq)`::masked_key`
/// — must be raised to `4896 + 228 = 5124`.
///
/// Pinned into the `#[tbor(buffer, max_len = 260)]` literal on
/// [`TborMlDsaGenerateKeyResp::masked_key`].
pub const MASKED_MLDSA_KEY_MAX_LEN: usize = 8 + 12 + 192 + 32 + 4896 + 16;

/// Maximum ML-DSA public-key length: 2592 bytes for ML-DSA-87.  Pinned
/// into the `#[tbor(buffer, max_len = 2592)]` literal on
/// [`TborMlDsaGenerateKeyResp::pub_key`].
pub const MLDSA_PUB_KEY_MAX_LEN: usize = 2592;

/// ML-DSA signature maximum length: 4627 bytes for ML-DSA-87.  Shared by
/// `MlDsaSign` / `MlDsaVerify` and pinned into their signature buffers.
pub const MLDSA_SIGNATURE_MAX_LEN: usize = 4627;

/// Maximum ML-DSA context-string length: 255 bytes.
///
/// FIPS 204 defines `ML-DSA.Sign(sk, M, ctx)` and
/// `ML-DSA.Verify(pk, M, sigma, ctx)` over a caller-chosen context string
/// with `0 <= |ctx| <= 255`.  The bound is a hard specification limit, not
/// a wire-budget choice: the signed message representative embeds `|ctx|`
/// as a single byte of the domain separator, so a longer context string
/// is not representable.  An empty `ctx` is the FIPS 204 default and
/// reproduces the pre-context behaviour.
///
/// Shared by `MlDsaSign` / `MlDsaVerify` and pinned into the
/// `#[tbor(buffer, max_len = 255)]` literals on their `ctx` fields.
pub const MLDSA_CTX_MAX_LEN: usize = 255;

/// Maximum message length accepted by the TBOR ML-DSA sign and verify
/// schemas.
///
/// The binding constraint is the worst-case `MlDsaVerify` request — the
/// largest PQC frame — and the limit is the **host encoder's staging
/// budget**, not TBOR's 8191-byte `MAX_DATA_SIZE`.  The encoder stages
/// the data section at offset 132 (`header(4) + 32 TOC entries * 4`; see
/// `stage_base()` in `ddi/tbor/codec/src/encode.rs`) inside an 8192-byte
/// transport buffer (`REQ_BUF_LEN` in `ddi/nix/src/dev.rs` and
/// `ddi/win/src/dev.rs`):
///
/// ```text
///   transport buffer  =  8192
///   stage offset      =  -132   header(4) + 32 * 4 TOC bytes
///   pub_key           = -2592   ML-DSA-87
///   signature         = -4627   ML-DSA-87
///   ctx               =  -255   MLDSA_CTX_MAX_LEN
///   message budget    =   586
/// ```
///
/// `MlDsaSign` shares the same cap: sign and verify are inverse
/// operations over pure ML-DSA, so a message that can be signed must also
/// be verifiable.  `MlDsaSign` on its own would allow
/// `8192 - 132 - 164 - 255 = 7641` bytes.
///
/// The cap is therefore dictated entirely by `MlDsaVerify`.  If
/// `MlDsaVerify` is ever removed as a command, raising the cap is a
/// deliberate **one-constant change**: nothing else in the schema derives
/// from it, and the `max_len` literals on the `message` fields are
/// mechanically pinned to this constant by `const _: () = assert!(...)`
/// checks that fail the build if they drift.
pub const MLDSA_MESSAGE_MAX_LEN: usize = 586;

/// ML-DSA key-kind selector on the TBOR wire — a wire-side mirror of the
/// ML-DSA subset of the firmware
/// [`HsmVaultKeyKind`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind) enum.
///
/// The 1-byte discriminants MUST stay byte-identical to `HsmVaultKeyKind`
/// so the two convert losslessly.  A kind encodes both the parameter set
/// and the private-key representation, following the existing vault
/// taxonomy where each algorithm/variant/format pair is its own kind (the
/// same way fixed- and variable-length HMAC keys are distinct kinds).
///
/// **Seed-only on the wire.**  This enum deliberately exposes only the
/// three `Seed` kinds (44–46): a seed kind stores the 32-byte generation
/// seed `xi` and is re-expanded on each use.  The matching expanded
/// (`Private`) kinds `MlDsa44Private = 47` … `MlDsa87Private = 49` do
/// exist in `HsmVaultKeyKind` and remain fully supported by the vault;
/// they are simply not offered on the TBOR wire yet.  Adding them later
/// is a purely additive change to this enum — but it also requires
/// raising the `masked_key` `max_len` literals (and
/// [`MASKED_MLDSA_KEY_MAX_LEN`]) from 164 to 5028, because an expanded
/// ML-DSA-87 secret key is 4896 bytes instead of a 32-byte seed.
///
/// Kept as an [`open_enum`] so an unrecognized discriminant round-trips as
/// `MlDsaKeyKind(x)` and is rejected on-device rather than failing to
/// decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaKeyKind {
    /// ML-DSA-44 compact seed (`xi`, 32 B).
    MlDsa44Seed = 46,
    /// ML-DSA-65 compact seed (`xi`, 32 B).
    MlDsa65Seed = 47,
    /// ML-DSA-87 compact seed (`xi`, 32 B).
    MlDsa87Seed = 48,
}

/// `MlDsaGenerateKey` request schema.
#[tbor(opcode = 0x26)]
pub struct TborMlDsaGenerateKeyReq {
    /// CO/CU session id this request is bound to.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Requested key scope (masks the private key), 1-byte [`KeyScope`].
    #[tbor(U8)]
    pub scope: KeyScope,

    /// Requested ML-DSA private key kind, 1-byte [`MlDsaKeyKind`].  The kind
    /// encodes the parameter set; the wire is seed-only today.
    #[tbor(U8)]
    pub key_kind: MlDsaKeyKind,
}

/// `MlDsaGenerateKey` response schema.
///
/// `masked_key` is `#[tbor(mutable)]` so the handler can reserve the slot
/// and mask the private key straight into it (`decode_mut`) — no scratch
/// copy of the masked blob.
#[tbor(response)]
pub struct TborMlDsaGenerateKeyResp<'a> {
    /// The generated ML-DSA private key, masked (AEAD-GCM-256) under the
    /// scope's masking key.  Always 164 B: the wire is seed-only, so the
    /// plaintext is the 32-byte `xi` seed.  See
    /// [`MASKED_MLDSA_KEY_MAX_LEN`].
    #[tbor(buffer, max_len = 5156, mutable)]
    pub masked_key: &'a [u8],

    /// The ML-DSA public key.  Up to 2592 B for ML-DSA-87.
    ///
    /// `mutable` so the handler can reserve the slot and have the fastpath
    /// core write the key straight into it. The alternative — a temporary
    /// buffer copied in afterwards — costs another 2592 B of the per-IO DMA
    /// heap, which ML-DSA-87 no longer has to spare now that the masked
    /// blob carries the expanded secret key.
    #[tbor(buffer, max_len = 2592, mutable)]
    pub pub_key: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_seed_kind() {
        let mut buf = [0u8; 256];
        let frame = TborMlDsaGenerateKeyReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(1))
            .unwrap()
            .scope(KeyScope::Local)
            .unwrap()
            .key_kind(MlDsaKeyKind::MlDsa65Seed)
            .unwrap()
            .finish();

        assert_eq!(frame.scope(), KeyScope::Local);
        assert_eq!(frame.key_kind(), MlDsaKeyKind::MlDsa65Seed);
    }

    #[test]
    fn request_round_trips_every_seed_kind() {
        for kind in [
            MlDsaKeyKind::MlDsa44Seed,
            MlDsaKeyKind::MlDsa65Seed,
            MlDsaKeyKind::MlDsa87Seed,
        ] {
            let mut buf = [0u8; 256];
            let frame = TborMlDsaGenerateKeyReq::encode(&mut buf)
                .unwrap()
                .session_id(SessionId(1))
                .unwrap()
                .scope(KeyScope::Local)
                .unwrap()
                .key_kind(kind)
                .unwrap()
                .finish();

            assert_eq!(frame.key_kind(), kind);
        }
    }

    #[test]
    fn seed_kind_discriminants_are_contiguous_from_46() {
        assert_eq!(MlDsaKeyKind::MlDsa44Seed, MlDsaKeyKind(46));
        assert_eq!(MlDsaKeyKind::MlDsa65Seed, MlDsaKeyKind(47));
        assert_eq!(MlDsaKeyKind::MlDsa87Seed, MlDsaKeyKind(48));
    }

    #[test]
    fn response_round_trips_masked_and_pub() {
        let mut buf = [0u8; 8192];
        let masked = [0xABu8; MASKED_MLDSA_KEY_MAX_LEN];
        let pub_key = [0xCDu8; MLDSA_PUB_KEY_MAX_LEN];
        let frame = TborMlDsaGenerateKeyResp::encode(&mut buf, 0, true)
            .unwrap()
            .masked_key(&masked)
            .unwrap()
            .pub_key(&pub_key)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_key(), &masked[..]);
        assert_eq!(frame.pub_key(), &pub_key[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        const _: () = assert!(5156 == MASKED_MLDSA_KEY_MAX_LEN);
        const _: () = assert!(2592 == MLDSA_PUB_KEY_MAX_LEN);
        const _: () = assert!(4627 == MLDSA_SIGNATURE_MAX_LEN);
        const _: () = assert!(255 == MLDSA_CTX_MAX_LEN);
        const _: () = assert!(586 == MLDSA_MESSAGE_MAX_LEN);
        assert_eq!(MASKED_MLDSA_KEY_MAX_LEN, 5156);
    }

    /// The message cap is the residue of the worst-case `MlDsaVerify`
    /// request against the host encoder's 8192-byte staging budget.
    #[test]
    fn message_cap_is_the_mldsa_verify_staging_residue() {
        const TRANSPORT_BUF_LEN: usize = 8192;
        const STAGE_OFFSET: usize = 132;

        assert_eq!(
            TRANSPORT_BUF_LEN
                - STAGE_OFFSET
                - MLDSA_PUB_KEY_MAX_LEN
                - MLDSA_SIGNATURE_MAX_LEN
                - MLDSA_CTX_MAX_LEN,
            MLDSA_MESSAGE_MAX_LEN,
        );
    }
}
