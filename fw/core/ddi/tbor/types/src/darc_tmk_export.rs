// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `DarcTmkExport` wire schema.
//!
//! `DarcTmkExport` is an in-session command that seals a locally-masked
//! DARC Transfer Masking Key (TMK) to a remote **target** so the target
//! can import it with [`DarcTmkImport`](crate::darc_tmk_import).  It is
//! the source-side mirror of `DarcTmkImport`: where import *opens* a
//! `sealed_tmk` and *re-masks* it, export *unmasks* a local `masked_tmk`
//! and *seals* it.
//!
//! It mirrors `SdCreateRemoteBackup`'s seal front-end, but the receiver
//! is identified by a single **DATA-anchored** certificate chain (the
//! export-side mirror of the `POTAPubKey`-anchored sender chain that
//! `DarcTmkImport` verifies).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher.
//! * `masked_sender_key` — the **source's** masked DARC key-exchange key
//!   (from [`DarcKexKeyGen`](crate::darc_kex_key_gen)), exactly
//!   [`MASKED_KEX_KEY_LEN`] (276 B).  Unmasked on-device to recover the
//!   HPKE **sender** private key (`SndrPriv`) that authenticates the
//!   seal.  Its masked-key kind must be
//!   [`DarcKex`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind::DarcKex).
//! * `masked_tmk` — the locally-masked TMK envelope (from
//!   [`DarcTmkGen`](crate::darc_tmk_gen) or `DarcTmkImport`), exactly
//!   [`MASKED_TMK_LEN`] (260 B).  Unmasked on-device to recover the
//!   32-byte TMK plaintext; its kind must be
//!   [`DarcTmk`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind::DarcTmk).
//! * `policy` — the unified [`PartPolicy`] whose `DATAPubKey` anchors the
//!   `target_cert_chain`.  Length pinned to [`PART_POLICY_LEN`] (584 B);
//!   its SHA-384 digest must equal the partition's bound `policy_hash`.
//! * `target_cert_chain` — a packed list of [`CertDescriptor`] entries
//!   `(index, length)` referencing where each DER certificate of the
//!   target chain is carried **out of band** as an SGL Data Block.  The
//!   chain must be DATA-anchored; its terminal (leaf) certificate carries
//!   the target's HPKE **receiver** public key (`RcvrPub`).
//!
//! Output:
//!
//! * `sealed_tmk` — the HPKE-Auth seal of the 32-byte TMK, exactly
//!   [`SEALED_TMK_LEN`] (145 B): `enc(97) ‖ ct(TMK 32 + GCM tag 16)`.
//!   Byte-for-byte what `DarcTmkImport` consumes.

use tsra_fw_ddi_tbor_api::tbor;

pub use crate::darc_kex_key_gen::MASKED_KEX_KEY_LEN;
pub use crate::darc_tmk_import::MASKED_TMK_LEN;
pub use crate::darc_tmk_import::SEALED_TMK_LEN;
pub use crate::darc_tmk_import::TMK_LEN;
use crate::evidence::CertDescriptor;
pub use crate::policy::PART_POLICY_LEN;

/// TBOR opcode for `DarcTmkExport`.
pub const TBOR_OP_DARC_TMK_EXPORT: u8 = 0x24;

// `masked_sender_key` is a masked DARC key-exchange key; the derive needs
// an integer literal on the field, so the length is spelled out as `276`
// and pinned against the canonical `MASKED_KEX_KEY_LEN` here.
const _: () = assert!(MASKED_KEX_KEY_LEN == 276);

// `masked_tmk` is a masked TMK envelope; the derive needs an integer
// literal on the field, so the length is spelled out as `260` and pinned
// against `MASKED_TMK_LEN` here.
const _: () = assert!(MASKED_TMK_LEN == 260);

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `584` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 584);

// `sealed_tmk` is an HPKE-Auth seal; the derive needs an integer literal
// on the field, so the length is spelled out as `145` and pinned against
// `SEALED_TMK_LEN` here.
const _: () = assert!(SEALED_TMK_LEN == 145);

// Pin the `target_cert_chain` `#[tbor(min_len/max_len)]` literals to their
// descriptor-size constants (the derive requires integer literals): a
// single descriptor (`min_len`) and `MAX_CERTS` descriptors (`max_len`).
const _: () = assert!(crate::evidence::CERT_DESCRIPTOR_LEN == 3);
const _: () = assert!(crate::evidence::CERT_DESCRIPTORS_MAX_LEN == 6);

/// `DarcTmkExport` request schema.
///
/// Unmasks a local TMK and HPKE-Auth-seals it to a DATA-authenticated
/// target for off-device transfer.
#[tbor(opcode = 0x24)]
pub struct TborDarcTmkExportReq<'a> {
    /// CO session id this request is bound to.  Typed
    /// [`SessionId`](tsra_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// The source's masked DARC key-exchange key (from `DarcKexKeyGen`),
    /// exactly [`MASKED_KEX_KEY_LEN`] (276 B).  Unmasked on-device to
    /// recover the HPKE sender private key (`SndrPriv`).
    #[tbor(buffer, len = 276)]
    pub masked_sender_key: &'a [u8],

    /// The locally-masked TMK envelope (from `DarcTmkGen` /
    /// `DarcTmkImport`), exactly [`MASKED_TMK_LEN`] (260 B).  Unmasked
    /// on-device to recover the 32-byte TMK plaintext.
    #[tbor(buffer, len = 260)]
    pub masked_tmk: &'a [u8],

    /// Caller-asserted unified [`PartPolicy`] whose `DATAPubKey` anchors
    /// `target_cert_chain`.  Length pinned to [`PART_POLICY_LEN`] (584 B).
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 584)]
    pub policy: &'a [u8],

    /// Packed list of [`CertDescriptor`] entries `(index, length)` for the
    /// target certificate chain carried out of band.  Decoded as a
    /// zero-copy typed slice; because [`CertDescriptor`] is `Unaligned`
    /// (alignment 1) the `&[CertDescriptor]` cast is sound at any offset.
    ///
    /// `min_len`/`max_len` are a coarse wire-size guard bounding the byte
    /// length to `[CERT_DESCRIPTOR_LEN, CERT_DESCRIPTORS_MAX_LEN]` =
    /// `[3, 6]`; a wire length that is not a whole-descriptor multiple
    /// decodes as an **empty** slice, which the handler rejects.
    #[tbor(buffer, min_len = 3, max_len = 6)]
    pub target_cert_chain: &'a [CertDescriptor],
}

/// `DarcTmkExport` response schema.
///
/// Carries the HPKE-Auth-sealed TMK for the target to import.
#[tbor(response)]
pub struct TborDarcTmkExportResp<'a> {
    /// The HPKE-Auth seal of the 32-byte TMK.  Always exactly
    /// [`SEALED_TMK_LEN`] (145 B): `enc(97) ‖ ct(48)`.
    #[tbor(buffer, len = 145)]
    pub sealed_tmk: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use tsra_fw_ddi_tbor_api::SessionId;

    use super::*;
    use crate::tbor_int::U16;

    #[test]
    fn request_round_trips_fields() {
        let masked_sender = [0u8; MASKED_KEX_KEY_LEN];
        let masked_tmk = [0u8; MASKED_TMK_LEN];
        let policy = [0u8; PART_POLICY_LEN];
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
        let frame = TborDarcTmkExportReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .masked_sender_key(&masked_sender)
            .unwrap()
            .masked_tmk(&masked_tmk)
            .unwrap()
            .policy(&policy)
            .unwrap()
            .target_cert_chain(&descs)
            .unwrap()
            .finish();

        assert_eq!(frame.masked_sender_key().len(), MASKED_KEX_KEY_LEN);
        assert_eq!(frame.masked_tmk().len(), MASKED_TMK_LEN);
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
        assert_eq!(
            frame.target_cert_chain().len(),
            descs.len() * crate::evidence::CERT_DESCRIPTOR_LEN,
        );
    }

    #[test]
    fn response_round_trips_sealed_tmk() {
        let sealed = [0xCDu8; SEALED_TMK_LEN];
        let mut buf = [0u8; 512];
        let frame = TborDarcTmkExportResp::encode(&mut buf, 0, true)
            .unwrap()
            .sealed_tmk(&sealed)
            .unwrap()
            .finish();
        assert_eq!(frame.sealed_tmk(), &sealed[..]);
    }

    #[test]
    fn lengths_match_pinned_values() {
        // The `#[tbor(... len = N)]` attributes must remain numeric
        // literals; pin them against the exported consts.
        const _: () = assert!(276 == MASKED_KEX_KEY_LEN);
        const _: () = assert!(260 == MASKED_TMK_LEN);
        const _: () = assert!(584 == PART_POLICY_LEN);
        const _: () = assert!(145 == SEALED_TMK_LEN);
        assert_eq!(TMK_LEN, 32);
    }
}
