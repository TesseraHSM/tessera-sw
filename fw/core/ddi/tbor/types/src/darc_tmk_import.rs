// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcTmkImport` wire schema.
//!
//! `DarcTmkImport` is an in-session command that imports a DARC Transfer
//! Masking Key (TMK) that was HPKE-sealed off-device to a DARC
//! key-exchange key (see [`DarcKexKeyGen`](crate::darc_kex_key_gen)) and
//! re-masks it locally under the partition's security-domain masking key
//! (SDMK) so the caller can persist and later re-import it.
//!
//! It mirrors `SdRestoreRemoteBackup`'s open front-end: the 32-byte TMK
//! plaintext is recovered by HPKE-Auth-opening `sealed_tmk` with the
//! receiver's masked DARC key-exchange private key, authenticated by the
//! sender public key recovered from a POTA-anchored certificate chain.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `masked_kex_key` — the **receiver's** masked DARC key-exchange key
//!   (from [`DarcKexKeyGen`](crate::darc_kex_key_gen)), exactly
//!   [`MASKED_KEX_KEY_LEN`] (280 B).  Unmasked on-device to recover the
//!   receiver's private HPKE key (`RcvrPriv`) that opens the sealed TMK;
//!   never a vault handle.  Its masked-key kind must be
//!   [`DarcKex`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind::DarcKex).
//! * `policy` — the unified [`PartPolicy`] whose `POTAPubKey` anchors the
//!   `remote_cert_chain`.  Length pinned to [`PART_POLICY_LEN`] (584 B);
//!   its SHA-384 digest must equal the partition's bound `policy_hash`.
//! * `sealed_tmk` — the HPKE-Auth seal of the 32-byte TMK, exactly
//!   [`SEALED_TMK_LEN`] (145 B): `enc(97) ‖ ct(TMK 32 + GCM tag 16)`.
//! * `remote_cert_chain` — a packed list of [`CertDescriptor`] entries
//!   `(index, length)` referencing where each DER certificate of the
//!   sender chain is carried **out of band** as an SGL Data Block.  The
//!   chain must be POTA-anchored; its terminal (leaf) certificate carries
//!   the sender public key that sealed `sealed_tmk`.
//!
//! Output:
//!
//! * `masked_tmk` — the imported TMK, re-masked (AEAD-GCM-256) under the
//!   partition SDMK, as a fixed [`MASKED_TMK_LEN`] (264 B) envelope.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::darc_kex_key_gen::MASKED_KEX_KEY_LEN;
use crate::evidence::CertDescriptor;
pub use crate::policy::PART_POLICY_LEN;

/// TBOR opcode for `DarcTmkImport`.
pub const TBOR_OP_DARC_TMK_IMPORT: u8 = 0x21;

/// Plaintext length of a DARC Transfer Masking Key (TMK): a 256-bit
/// symmetric key.
pub const TMK_LEN: usize = 32;

/// Exact on-the-wire length of `sealed_tmk`: the HPKE-Auth seal of the
/// TMK, `enc(97) ‖ ct(TMK 32 + GCM tag 16 = 48)` = 145 B, where `enc` is
/// the P-384 SEC1-uncompressed encapsulated key (`0x04 ‖ X ‖ Y`).
pub const SEALED_TMK_LEN: usize = (1 + 2 * 48) + (TMK_LEN + 16);

/// Exact on-the-wire length of the `masked_tmk` output envelope.
///
/// The envelope is fully deterministic: an AES-256-GCM `MaskedKey`
/// envelope around the 32-byte TMK plaintext —
/// `header(8) + iv(16) + MaskedKeyMetadata aad(192) + ct(32) + tag(16)`
/// = 264 B.
pub const MASKED_TMK_LEN: usize = 8 + 16 + 192 + TMK_LEN + 16;

// `masked_kex_key` is a masked DARC key-exchange key; the derive needs an
// integer literal on the field, so the length is spelled out as `280` and
// pinned against the canonical `MASKED_KEX_KEY_LEN` here.
const _: () = assert!(MASKED_KEX_KEY_LEN == 280);

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `484` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 584);

// `sealed_tmk` is an HPKE-Auth seal; the derive needs an integer literal
// on the field, so the length is spelled out as `145` and pinned against
// `SEALED_TMK_LEN` here.
const _: () = assert!(SEALED_TMK_LEN == 145);

// `masked_tmk` is a masked TMK envelope; the derive needs an integer
// literal on the field, so the length is spelled out as `264` and pinned
// against `MASKED_TMK_LEN` here.
const _: () = assert!(MASKED_TMK_LEN == 264);

// Pin the `remote_cert_chain` `#[tbor(min_len/max_len)]` literals to their
// descriptor-size constants (the derive requires integer literals): a
// single descriptor (`min_len`) and `MAX_CERTS` descriptors (`max_len`).
const _: () = assert!(crate::evidence::CERT_DESCRIPTOR_LEN == 3);
const _: () = assert!(crate::evidence::CERT_DESCRIPTORS_MAX_LEN == 6);

/// `DarcTmkImport` request schema.
///
/// Imports a DARC Transfer Masking Key sealed off-device to a DARC
/// key-exchange key and re-masks it under the partition SDMK.
#[tbor(opcode = 0x21, pair = TborDarcTmkImportResp)]
pub struct TborDarcTmkImportReq<'a> {
    /// CO/CU session id this request is bound to.  Typed
    /// [`SessionId`](tsra_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The receiver's masked DARC key-exchange key (from
    /// `DarcKexKeyGen`), exactly [`MASKED_KEX_KEY_LEN`] (280 B).  Unmasked
    /// on-device to recover the receiver's private HPKE key (`RcvrPriv`).
    #[tbor(buffer, len = 280)]
    pub masked_kex_key: &'a [u8],

    /// Caller-asserted unified [`PartPolicy`] whose `POTAPubKey` anchors
    /// `remote_cert_chain`.  Length pinned to [`PART_POLICY_LEN`] (584 B).
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 584)]
    pub policy: &'a [u8],

    /// HPKE-Auth seal of the 32-byte TMK.  Always exactly
    /// [`SEALED_TMK_LEN`] (145 B): `enc(97) ‖ ct(48)`.
    #[tbor(buffer, len = 145)]
    pub sealed_tmk: &'a [u8],

    /// Packed list of [`CertDescriptor`] entries `(index, length)` for the
    /// sender certificate chain carried out of band.  Decoded as a
    /// zero-copy typed slice; because [`CertDescriptor`] is `Unaligned`
    /// (alignment 1) the `&[CertDescriptor]` cast is sound at any offset.
    ///
    /// `min_len`/`max_len` are a coarse wire-size guard bounding the byte
    /// length to `[CERT_DESCRIPTOR_LEN, CERT_DESCRIPTORS_MAX_LEN]` =
    /// `[3, 6]`; a wire length that is not a whole-descriptor multiple
    /// decodes as an **empty** slice, which the handler rejects.
    #[tbor(buffer, min_len = 3, max_len = 6)]
    pub remote_cert_chain: &'a [CertDescriptor],
}

/// `DarcTmkImport` response schema.
///
/// Carries the imported TMK re-masked under the partition SDMK.
#[tbor(response, pair = TborDarcTmkImportReq)]
pub struct TborDarcTmkImportResp<'a> {
    /// The imported TMK, masked (AEAD-GCM-256) under the partition SDMK.
    /// Always exactly [`MASKED_TMK_LEN`] (264 B).
    #[tbor(buffer, len = 264)]
    pub masked_tmk: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;
    use crate::tbor_int::U16;

    #[test]
    fn request_round_trips_fields() {
        let masked_kex = [0u8; MASKED_KEX_KEY_LEN];
        let policy = [0u8; PART_POLICY_LEN];
        let sealed = [0xABu8; SEALED_TMK_LEN];
        let descs = [
            CertDescriptor {
                index: 0,
                length: U16::new(32),
            },
            CertDescriptor {
                index: 1,
                length: U16::new(64),
            },
        ];

        let mut buf = [0u8; 2048];
        let frame = TborDarcTmkImportReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .masked_kex_key(&masked_kex)
            .unwrap()
            .policy(&policy)
            .unwrap()
            .sealed_tmk(&sealed)
            .unwrap()
            .remote_cert_chain(&descs)
            .unwrap()
            .finish();

        assert_eq!(frame.masked_kex_key().len(), MASKED_KEX_KEY_LEN);
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
        assert_eq!(frame.sealed_tmk().len(), SEALED_TMK_LEN);
        // The typed-slice buffer getter returns the packed descriptor
        // bytes (3 B each), mirroring `PartFinal`'s `cert_descriptors`.
        assert_eq!(
            frame.remote_cert_chain().len(),
            descs.len() * crate::evidence::CERT_DESCRIPTOR_LEN,
        );
    }

    #[test]
    fn response_round_trips_masked_tmk() {
        let masked = [0xCDu8; MASKED_TMK_LEN];
        let mut buf = [0u8; 512];
        let frame = TborDarcTmkImportResp::encode(&mut buf, 0, true)
            .unwrap()
            .masked_tmk(&masked)
            .unwrap()
            .finish();
        assert_eq!(frame.masked_tmk(), &masked[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        // The `#[tbor(... len = N)]` attributes must remain numeric
        // literals; pin them against the exported consts.
        const _: () = assert!(280 == MASKED_KEX_KEY_LEN);
        const _: () = assert!(584 == PART_POLICY_LEN);
        const _: () = assert!(145 == SEALED_TMK_LEN);
        const _: () = assert!(264 == MASKED_TMK_LEN);
        assert_eq!(TMK_LEN, 32);
    }
}
