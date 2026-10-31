// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR DDI command dispatch.
//!
//! TBOR commands are addressed by a single `u8` opcode carried in the
//! TBOR request header. Each handler decodes its typed request via
//! [`tsra_fw_ddi_tbor::TborRequest::decode`] (or the generated
//! `XxxReq::decode` shortcut) and encodes its response via the matching
//! `XxxResp::encode` typestate builder.
//!
//! ## Async, PAL-aware shape
//!
//! Native exchange handlers fill shared storage and return a response length.
//! Every handler returns a compact response length in the shared allocation.
//! Completion validates that prefix; IO teardown performs final scrubbing.
//! Error encoding initializes only the published response prefix.

pub(crate) mod aes_encrypt_decrypt;
pub(crate) mod aes_generate_key;
pub(crate) mod api_rev;
pub(crate) mod concat_kdf_derive;
pub(crate) mod darc_kex_key_gen;
pub(crate) mod darc_key_unwrap;
pub(crate) mod darc_key_wrap;
pub(crate) mod darc_tmk;
pub(crate) mod darc_tmk_export;
pub(crate) mod darc_tmk_gen;
pub(crate) mod darc_tmk_import;
pub(crate) mod ecc_generate_key;
pub(crate) mod ecc_sign;
pub(crate) mod ecdh_derive;
pub(crate) mod from_pal;
pub(crate) mod get_cert;
pub(crate) mod get_cert_chain_info;
pub(crate) mod get_unwrapping_key;
pub(crate) mod hash;
pub(crate) mod hkdf_derive;
pub(crate) mod hmac;
pub(crate) mod hmac_generate_key;
pub(crate) mod key_report;
pub(crate) mod mldsa_generate_key;
pub(crate) mod mldsa_sign;
pub(crate) mod mldsa_verify;
pub(crate) mod mlkem_decapsulate;
pub(crate) mod mlkem_encapsulate;
pub(crate) mod mlkem_generate_key;
pub(crate) mod part_final;
pub mod part_info;
pub mod part_init;
pub mod policy;
pub(crate) mod psk_change;
pub(crate) mod pta;
pub(crate) mod rsa_mod_exp;
pub(crate) mod sd_backup;
pub(crate) mod sd_create_peer_backup;
pub(crate) mod sd_create_remote_backup;
pub(crate) mod sd_reseal_remote_backup;
pub(crate) mod sd_restore_local_backup;
pub(crate) mod sd_restore_peer_backup;
pub(crate) mod sd_restore_remote_backup;
pub(crate) mod sd_sealing_key_gen;
pub(crate) mod session_close;
pub(crate) mod session_open_finish;
pub(crate) mod session_open_init;
pub(crate) mod unwrap_key;

use tsra_fw_ddi_tbor::RequestView;
use tsra_fw_ddi_tbor::ResponseEncoder;
use tsra_fw_ddi_tbor::TocEntry;
use tsra_fw_ddi_tbor::PROTOCOL_VERSION;
use tsra_fw_hsm_oob::OobPtr;
use tsra_fw_hsm_pal_traits::HsmCmdBuf;
use tsra_fw_hsm_pal_traits::HsmDmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionRole;
use tsra_fw_hsm_pal_traits::HsmSessionState;
use tsra_fw_hsm_pal_traits::SESSION_MASKING_KEY_LEN;
use tsra_fw_hsm_undo::UndoLog;

use super::*;
use crate::part_state;

/// TBOR opcodes recognised by the firmware dispatcher.
///
/// The wire opcode is a single byte. Constants kept here (rather than in
/// the host-side `tsra_ddi_tbor_types` crate) so that firmware can be
/// built `no_std` without host-side feature flags.
pub(crate) mod opcode {
    /// `ApiRev` — bootstrap TBOR command. Reports the firmware's
    /// supported TBOR wire-protocol version range.
    pub(crate) const API_REV: u8 = 0x01;

    /// `SessionOpenInit` — Phase 1 of the session-establishment
    /// handshake.  Client sends `(psk_id, pk_init, seed,
    /// bmk_session?)`; HSM responds with `(session_id, pk_resp,
    /// mac_resp)`.  The optional `bmk_session` selects the resume
    /// variant (preserves `masking_key` continuity from a prior
    /// session); fresh keys are always derived from the HPKE
    /// handshake, so every promoted session has forward secrecy.
    pub(crate) const SESSION_OPEN_INIT: u8 = 0x03;

    /// `SessionOpenFinish` — Phase 2 of the session-establishment
    /// handshake.  Client sends `(session_id, mac_fin)`; on success
    /// the slot transitions Pending → Active and the response carries
    /// a fresh `bmk_session` envelope the host may persist for a
    /// future resume.
    pub(crate) const SESSION_OPEN_FINISH: u8 = 0x04;

    /// `SessionClose` — destroys an Active or Pending session slot.
    pub(crate) const SESSION_CLOSE: u8 = 0x05;

    /// `PskChange` — rotate the CO or CU partition PSK to a
    /// new value supplied encrypted inside an AEAD-GCM envelope wrapped
    /// under the active session's `param_key`.  See
    /// [`super::psk_change`] for the authorization matrix and
    /// AAD layout.
    pub(crate) const PSK_CHANGE: u8 = 0x06;

    /// `PartInit` — bind PTA, policy, and POTA thumbprint.
    pub(crate) const PART_INIT: u8 = 0x07;

    /// `PartFinal` — finalize the partition (FinalizePart + ConfigPartSD):
    /// derive partition local masking keys and generate or restore the
    /// `local_mk` backup.  See [`super::part_final`].
    pub(crate) const PART_FINAL: u8 = 0x08;

    /// `PartInfo` — out-of-session info command reporting device kind /
    /// FIPS status plus the bound partition's lifecycle and identity
    /// (state, generation, owner/manufacturer SVN, PID, identity public
    /// key).  TBOR analogue of MBOR `GetDeviceInfo` + the TSRA
    /// `GetPartID` primitive.
    pub(crate) const PART_INFO: u8 = 0x02;

    /// `SdSealingKeyGen` — generate a security-domain sealing key (a
    /// P-384 ECC keypair for ECDH) under the active session's partition;
    /// return the private half **masked** under the requested scope's
    /// masking key (nothing is persisted on-device) plus the public key.
    /// See [`super::sd_sealing_key_gen`].
    pub(crate) const SD_SEALING_KEY_GEN: u8 = 0x09;

    /// `SdCreateRemoteBackup` — create a security-domain remote backup:
    /// a fresh BKS3 HPKE-Auth-sealed to the receiver's SD sealing public
    /// key (from its `KeyReport`, carried out of band) and authenticated
    /// by the sender's masked SD sealing key.  See
    /// [`super::sd_create_remote_backup`].
    pub(crate) const SD_CREATE_REMOTE_BACKUP: u8 = 0x0A;

    /// `SdResealRemoteBackup` — reseal a security-domain remote backup from a
    /// source recipient to a destination recipient: HPKE-Auth-open the
    /// source backup with the masked receiver key, then HPKE-Auth-seal the
    /// recovered BKS3 to the destination receiver.  See
    /// [`super::sd_reseal_remote_backup`].
    pub(crate) const SD_RESEAL_REMOTE_BACKUP: u8 = 0x0B;

    /// `SdRestoreRemoteBackup` — restore a security domain from a remote
    /// backup: HPKE-Auth-open `src_remote_backup` with the masked receiver
    /// key (authenticated by the sender's attested key), recover SDMK from
    /// `prev_sd_mk_backup`, and re-provision the SD.  See
    /// [`super::sd_restore_remote_backup`].
    pub(crate) const SD_RESTORE_REMOTE_BACKUP: u8 = 0x0C;

    /// `SdRestoreLocalBackup` — restore a security domain from its
    /// device-local backups: unmask `pok_local_backup` (BKS3 under
    /// `PartLocalMK`) and `sd_mk_backup` (SDMK under the derived SDBMK),
    /// re-mask both at the current SVN, and re-provision the SD.  See
    /// [`super::sd_restore_local_backup`].
    pub(crate) const SD_RESTORE_LOCAL_BACKUP: u8 = 0x0D;

    /// `SdCreatePeerBackup` — create a peer-transferable backup of a
    /// security domain: recover BKS3 from the caller's `pok_local_backup`
    /// (under `PartLocalMK`) and HPKE-Auth-seal it to a destination peer
    /// named by `dst_evidence`, authenticated by the sender's masked SD
    /// sealing key.  Gated by the SD policy's `allow_peer_cloning`.  See
    /// [`super::sd_create_peer_backup`].
    pub(crate) const SD_CREATE_PEER_BACKUP: u8 = 0x0E;

    /// `SdRestorePeerBackup` — restore a security domain from a peer backup:
    /// HPKE-Auth-open `pok_peer_backup` with the masked receiver key
    /// (authenticated by the sender peer's attested key), recover SDMK from
    /// `prev_sd_mk_backup`, and re-provision the SD.  Gated by the SD
    /// policy's `allow_peer_cloning`.  See [`super::sd_restore_peer_backup`].
    pub(crate) const SD_RESTORE_PEER_BACKUP: u8 = 0x0F;

    /// `KeyReport` — attest a masked key: unmask it, derive its public
    /// component on-device, and return a PID-signed COSE_Sign1
    /// key-attestation report over it.  See [`super::key_report`].
    ///
    /// `0x0A..=0x0F` are reserved by the Security-Domain backup schema
    /// family, so `KeyReport` takes the next free opcode, `0x10`.
    pub(crate) const KEY_REPORT: u8 = 0x10;

    /// `HmacGenerateKey` — generate a fresh random HMAC key of the
    /// requested SHA variant under the active session's partition; return
    /// it **masked** under the requested scope's masking key (nothing is
    /// persisted on-device).  See [`super::hmac_generate_key`].
    pub(crate) const HMAC_GENERATE_KEY: u8 = 0x11;

    /// `Hmac` — compute an HMAC tag over a host-supplied message using a
    /// caller-held masked HMAC key (unmasked on-device for the operation,
    /// then discarded).  See [`super::hmac`].
    pub(crate) const HMAC: u8 = 0x12;

    /// `GetUnwrappingKey` — return the partition's RSA-2048 unwrapping
    /// public key, which the host uses to RSA-AES key-wrap a payload for a
    /// future `UnwrapKey` import.  See [`super::get_unwrapping_key`].
    pub(crate) const GET_UNWRAPPING_KEY: u8 = 0x13;

    /// `UnwrapKey` — RSA-AES-unwrap a host-supplied wrapped key
    /// (AES / RSA / ECC / HMAC) with the partition unwrapping key and
    /// return it masked under the requested scope's masking key (plus the
    /// re-derived public key for RSA / ECC).  See [`super::unwrap_key`].
    pub(crate) const UNWRAP_KEY: u8 = 0x14;

    /// `AesGenerateKey` — generate a fresh random AES key (128 / 192 /
    /// 256) under the active session's partition; return it **masked**
    /// under the requested scope's masking key (nothing is persisted
    /// on-device).  See [`super::aes_generate_key`].
    pub(crate) const AES_GENERATE_KEY: u8 = 0x15;

    /// `AesEncryptDecrypt` — AES-CBC encrypt or decrypt a host-supplied
    /// message using a caller-held masked AES key (unmasked on-device for
    /// the operation, then discarded).  See [`super::aes_encrypt_decrypt`].
    pub(crate) const AES_ENCRYPT_DECRYPT: u8 = 0x16;

    /// `EccGenerateKey` — generate a fresh ECC keypair on the requested
    /// NIST curve and return the private key masked under the requested
    /// scope's masking key plus the wire public key (nothing is persisted
    /// on-device).  See [`super::ecc_generate_key`].
    pub(crate) const ECC_GENERATE_KEY: u8 = 0x17;

    /// `EccSign` — produce a raw ECDSA `r ‖ s` signature over a
    /// host-supplied pre-computed digest using a caller-held masked ECC
    /// private key (unmasked on-device).  See [`super::ecc_sign`].
    pub(crate) const ECC_SIGN: u8 = 0x18;

    /// `EcdhDerive` — derive an ECDH shared secret from a caller-held
    /// masked local ECC private key and a host-supplied peer public key,
    /// and return the secret masked under the requested scope's masking
    /// key.  See [`super::ecdh_derive`].
    pub(crate) const ECDH_DERIVE: u8 = 0x19;

    /// `RsaModExp` — perform the RSA private-key primitive `x = y^d mod n`
    /// using a caller-held masked RSA private key (imported via
    /// `UnwrapKey`; unmasked on-device).  The raw modular exponentiation
    /// underlying RSA decrypt / sign.  See [`super::rsa_mod_exp`].
    pub(crate) const RSA_MOD_EXP: u8 = 0x1A;

    /// `Hash` — compute a SHA-256 / 384 / 512 digest of a
    /// host-supplied message.  A pure hashing utility with no key or
    /// partition state.  See [`super::hash`].
    pub(crate) const HASH: u8 = 0x1B;

    /// `HkdfDerive` — derive key material (AES / HMAC) from a caller-held
    /// masked ECDH shared secret via HKDF (RFC 5869), and return the
    /// derived key masked under the requested scope's masking key.  See
    /// [`super::hkdf_derive`].
    pub(crate) const HKDF_DERIVE: u8 = 0x1C;

    /// `ConcatKdfDerive` — derive key material (AES / HMAC) from a
    /// caller-held masked ECDH shared secret via a single-step
    /// concatenation KDF (ANSI X9.63 or NIST SP 800-56A one-step), and
    /// return the derived key masked under the requested scope's masking
    /// key.  See [`super::concat_kdf_derive`].
    pub(crate) const CONCAT_KDF_DERIVE: u8 = 0x1D;

    /// `GetCertChainInfo` — out-of-session info command reporting the
    /// number of certificates and the leaf-certificate SHA-256 thumbprint
    /// for the caller's partition at a chain slot.  TBOR analogue of MBOR
    /// `GetCertChainInfo`.  See [`super::get_cert_chain_info`].
    pub(crate) const GET_CERT_CHAIN_INFO: u8 = 0x1E;

    /// `GetCertificate` — out-of-session command returning a single
    /// DER-encoded X.509 certificate from the caller's partition at a
    /// `(slot_id, cert_id)`.  TBOR analogue of MBOR `GetCertificate`.  See
    /// [`super::get_cert`].
    pub(crate) const GET_CERTIFICATE: u8 = 0x1F;

    /// `DarcKexKeyGen` — generate a DARC key-exchange key (a P-384 ECC
    /// keypair for ECDH) under the active session's partition; return the
    /// private half **masked** under the requested scope's masking key
    /// (nothing is persisted on-device) plus the public key.  Modelled on
    /// [`SD_SEALING_KEY_GEN`] but tagged with the distinct
    /// [`HsmVaultKeyKind::DarcKex`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind::DarcKex)
    /// key kind.  See [`super::darc_kex_key_gen`].
    pub(crate) const DARC_KEX_KEY_GEN: u8 = 0x20;

    /// `DarcTmkImport` — import a DARC Transfer Masking Key (TMK) that was
    /// HPKE-sealed off-device to a [`DARC_KEX_KEY_GEN`] key-exchange key,
    /// authenticated by a POTA-anchored sender certificate chain, and
    /// return it **masked** under the partition security-domain masking
    /// key (SDMK).  Nothing is persisted on-device.  Modelled on
    /// [`SD_RESTORE_REMOTE_BACKUP`]'s open front-end; tagged with the
    /// distinct
    /// [`HsmVaultKeyKind::DarcTmk`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind::DarcTmk)
    /// key kind.  See [`super::darc_tmk_import`].
    pub(crate) const DARC_TMK_IMPORT: u8 = 0x21;

    /// `DarcKeyUnwrap` — import an externally-generated **EC private key**
    /// encoded as an EC2 `COSE_Key` and AES-KWP-wrapped under a DARC
    /// Transfer Masking Key (TMK, see [`DARC_TMK_IMPORT`]), returning it
    /// **masked** under the caller-chosen partition scope (`Ephemeral` /
    /// `Local`).  Nothing is persisted on-device.  See
    /// [`super::darc_key_unwrap`].
    pub(crate) const DARC_KEY_UNWRAP: u8 = 0x22;

    /// `DarcTmkGen` — originate a fresh DARC Transfer Masking Key
    /// (TMK), a random 256-bit symmetric secret, and return it **masked**
    /// under the partition security-domain masking key (SDMK).  Nothing
    /// is persisted on-device.  The source-side counterpart of
    /// [`DARC_TMK_IMPORT`]; both emit the identical masked envelope (same
    /// [`HsmVaultKeyKind::DarcTmk`](tsra_fw_hsm_pal_traits::HsmVaultKeyKind::DarcTmk)
    /// kind) so a created and an imported TMK are interchangeable.  See
    /// [`super::darc_tmk_gen`].
    pub(crate) const DARC_TMK_GEN: u8 = 0x23;

    /// `DarcTmkExport` — seal a locally-masked DARC Transfer Masking Key
    /// (TMK, see [`DARC_TMK_GEN`] / [`DARC_TMK_IMPORT`]) to a remote
    /// **target**, producing a 145-byte `sealed_tmk` byte-compatible with
    /// what [`DARC_TMK_IMPORT`] consumes.  The target is authenticated by
    /// a certificate chain anchored to the policy `DATAPubKey` (the
    /// export-side mirror of the `POTAPubKey`-anchored sender chain
    /// [`DARC_TMK_IMPORT`] verifies).  Nothing is persisted on-device.
    /// See [`super::darc_tmk_export`].
    pub(crate) const DARC_TMK_EXPORT: u8 = 0x24;

    /// `DarcKeyWrap` — export a locally-masked EC private key by
    /// re-encoding it as an EC2 `COSE_Key` and AES-KWP-wrapping it under a
    /// DARC Transfer Masking Key (TMK, see [`DARC_TMK_GEN`] /
    /// [`DARC_TMK_IMPORT`]), producing a `wrapped_key` byte-compatible
    /// with what [`DARC_KEY_UNWRAP`] consumes.  The source-side mirror of
    /// [`DARC_KEY_UNWRAP`].  Nothing is persisted on-device.  See
    /// [`super::darc_key_wrap`].
    pub(crate) const DARC_KEY_WRAP: u8 = 0x25;
    /// `MlDsaGenerateKey` — generate an ML-DSA (FIPS 204) keypair and
    /// return the private half **masked**, plus the public key.
    ///
    /// TEMPORARY: currently dispatched out of session for hardware
    /// bring-up, and served by a stub that decodes and rejects rather
    /// than generating a key.  See [`super::mldsa_generate_key`].
    pub(crate) const MLDSA_GENERATE_KEY: u8 = 0x26;

    /// `MlDsaSign` — sign a message with a caller-held masked ML-DSA key.
    ///
    /// TEMPORARY: dispatched out of session for hardware bring-up, like
    /// `MLDSA_GENERATE_KEY`.  See [`super::mldsa_sign`].
    pub(crate) const MLDSA_SIGN: u8 = 0x27;

    /// `MlDsaVerify` — verify a signature under a supplied public key.
    ///
    /// TEMPORARY: dispatched out of session for hardware bring-up, like the
    /// other PQC opcodes.  See [`super::mldsa_verify`].
    pub(crate) const MLDSA_VERIFY: u8 = 0x28;

    /// `MlKemGenerateKey` — generate an ML-KEM key pair and return the
    /// decapsulation key **masked**, plus the encapsulation key.
    ///
    /// TEMPORARY: dispatched out of session for hardware bring-up, like the
    /// other PQC opcodes.  See [`super::mlkem_generate_key`].
    pub(crate) const MLKEM_GENERATE_KEY: u8 = 0x29;

    /// `MlKemEncapsulate` — encapsulate to an ML-KEM public key, returning
    /// the ciphertext and the shared secret **masked**.
    ///
    /// TEMPORARY: dispatched out of session for hardware bring-up, like the
    /// other PQC opcodes.  See [`super::mlkem_encapsulate`].
    pub(crate) const MLKEM_ENCAPSULATE: u8 = 0x2A;

    /// `MlKemDecapsulate` — decapsulate a ciphertext with a caller-held
    /// masked ML-KEM key, returning the shared secret **masked**.
    ///
    /// TEMPORARY: dispatched out of session for hardware bring-up, like the
    /// other PQC opcodes.  See [`super::mlkem_decapsulate`].
    pub(crate) const MLKEM_DECAPSULATE: u8 = 0x2B;
}

/// Validate that `sess_id` belongs to an active Crypto-Officer session.
fn validate_crypto_officer_active_session<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    sess_id: HsmSessId,
) -> HsmResult<()> {
    if sess_id.role() != HsmSessionRole::CryptoOfficer {
        return Err(HsmError::InvalidPermissions);
    }

    if !matches!(pal.session_state(io, sess_id), HsmSessionState::Active) {
        return Err(HsmError::SessionNotFound);
    }

    Ok(())
}

/// Validate that `sess_id` belongs to an active session of any role
/// (Crypto-Officer or Crypto-User).
///
/// Used by the general crypto commands (`HmacGenerateKey`, `Hmac`) which
/// — unlike the security-domain administrative commands — are available
/// to both CO and CU sessions.  The default-PSK gate (applied by the
/// dispatcher) still requires the calling role's PSK to be rotated.
fn validate_active_session<P: HsmPal>(pal: &P, io: &P::Io, sess_id: HsmSessId) -> HsmResult<()> {
    if !matches!(pal.session_state(io, sess_id), HsmSessionState::Active) {
        return Err(HsmError::SessionNotFound);
    }
    Ok(())
}

/// Resolve the vault id of the masking key associated with `scope`.
fn masking_key_id_for_scope<P: HsmPal>(
    pal: &P,
    io: &P::Io,
    scope: HsmKeyScope,
) -> HsmResult<HsmKeyId> {
    // Every provisioned scope's masking-key id is stored in an
    // `AbsentUntilSet` partition property that is only written once the
    // partition (`PartFinal`) or security domain (`CreateSD`) is
    // finalized.  Before then the read returns `PartPropNotFound`; remap
    // it to the documented `UnsupportedKeyScope` ("the requested scope
    // has no masking key yet") so clients never observe a leaked
    // `PartPropNotFound`.  Genuine read faults still propagate.
    let remap_absent = |r: HsmResult<HsmKeyId>| match r {
        Err(HsmError::PartPropNotFound) => Err(HsmError::UnsupportedKeyScope),
        other => other,
    };
    match scope {
        HsmKeyScope::Ephemeral => remap_absent(part_state::part_ephemeral_mk_key_id(pal, io)),
        HsmKeyScope::Local => remap_absent(part_state::part_local_mk_key_id(pal, io)),
        // Resolve the SecurityDomain masking key (`SDMK`) by `SD_MK_KEY_ID`
        // presence — the single source of truth.  A request that observes a
        // partially-written commit (the `SD_INITIALIZED` claim is set but
        // `SD_MK_KEY_ID` is not yet written, or a rollback is in flight)
        // gets the documented `UnsupportedKeyScope` rather than a leaked
        // `PartPropNotFound`; genuine read faults still propagate.
        HsmKeyScope::SecurityDomain => remap_absent(part_state::part_sd_mk_key_id(pal, io)),
        _ => Err(HsmError::UnsupportedKeyScope),
    }
}

/// Resolve the 32-byte AES-256-GCM masking key material for `scope`,
/// returning a borrow of the on-device key.
///
/// `Session` scope resolves to the per-session masking key
/// ([`HsmSessionManager::session_masking_key`](tsra_fw_hsm_pal_traits::HsmSessionManager::session_masking_key));
/// every other scope resolves via [`masking_key_id_for_scope`] and reads
/// the vault key.  All scopes yield a 32-byte key suitable for the
/// `key_masking::aead` (AES-GCM-256) masked-key system.
///
/// # Platform note
///
/// `Session`-scope masking is currently available only on the std/emu PAL.
/// The Uno (hardware) PAL does not yet provision the per-session masking
/// key and returns [`HsmError::UnsupportedCmd`] from
/// `session_masking_key`, so `scope = Session` on masked-key commands
/// (`UnwrapKey`, `Ecc*`, KDF, …) fails on Uno until session-key masking is
/// implemented.  Callers targeting hardware should use a persisted scope
/// (`Local` / `SecurityDomain`) provisioned by `PartFinal` / the SD
/// lifecycle.
fn resolve_masking_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    scope: HsmKeyScope,
    sess_id: HsmSessId,
) -> HsmResult<&'p HsmDmaBuf> {
    match scope {
        HsmKeyScope::Session => {
            // The std PAL's `session_masking_key` may return an 80-byte
            // legacy MBOR `Session` blob key or the 32-byte TBOR `SessionEx`
            // key.  The TBOR masked-key system is AES-256-GCM and requires
            // exactly `SESSION_MASKING_KEY_LEN` (32) bytes, so reject a
            // legacy-length key up front rather than letting AEAD masking
            // fail deeper with a less specific error.
            let key = pal.session_masking_key(io, sess_id)?;
            if key.len() != SESSION_MASKING_KEY_LEN {
                return Err(HsmError::UnsupportedKeyScope);
            }
            Ok(key)
        }
        _ => {
            let mk_key_id = masking_key_id_for_scope(pal, io, scope)?;
            pal.vault_key(io, mk_key_id)
        }
    }
}

/// Dispatch a parsed TBOR request to its handler.
///
/// All handlers return a response length in the exchange. On failure (unknown
/// opcode, default-PSK gate, etc.) returns the typed [`HsmError`];
/// per-handler decoding errors are also reported as `Err(...)`.  The
/// caller is responsible for translating a returned error into a TBOR
/// error response via [`encode_tbor_err`].
///
/// ## Default-PSK gate
///
/// Before invoking an in-session handler, the dispatcher checks
/// whether the calling role's partition PSK is still the well-known
/// public default (see
/// [`DEFAULT_PSK_CO`](tsra_fw_hsm_pal_traits::DEFAULT_PSK_CO) /
/// [`DEFAULT_PSK_CU`](tsra_fw_hsm_pal_traits::DEFAULT_PSK_CU)).  If
/// so, only commands listed in [`allowed_with_default_psk`] are
/// permitted; anything else returns
/// [`HsmError::DefaultPskMustRotate`].  Out-of-session commands
/// (`ApiRev`, `SessionOpenInit`, `SessionOpenFinish`) are never
/// gated — the client must always be able to bring up a session in
/// order to issue [`psk_change`] in the first place.
/// Outcome of dispatching a single TBOR command.
///
/// Mirrors the MBOR [`DispatchResult`](crate::ddi::mbor::DispatchResult):
/// carries the encoded response plus, for the session-lifecycle opcodes,
/// the slot id the IO layer places in the CQE. Only `SessionOpenInit`
/// needs it: the slot is allocated inside the handler, so the IO layer
/// has no other way to learn it. `SessionClose` is not threaded here —
/// the dispatcher cross-checks the body `session_id` against the SQE
/// one for every close/in-session opcode, so the IO layer can just use
/// the SQE value (exactly as `handle_mbor_op` uses `hdr.sess_id`).
pub(crate) struct DispatchResult {
    /// Encoded response prefix in the exchange allocation.
    pub(crate) response_len: usize,
    /// Slot id for the CQE; set only by `SessionOpenInit`.
    pub(crate) session_id: Option<u16>,
}

/// Capacity selected after header parsing, before any handler scratch allocation.
pub(crate) fn exchange_capacity(opcode: u8, request_len: usize, host_capacity: usize) -> usize {
    use tsra_fw_ddi_tbor_types as types;

    let output = match opcode {
        opcode::API_REV => types::TborApiRevResp::MAX_ENCODED_SIZE,
        opcode::SESSION_OPEN_INIT => types::TborSessionOpenInitResp::MAX_ENCODED_SIZE,
        opcode::SESSION_OPEN_FINISH => types::TborSessionOpenFinishResp::MAX_ENCODED_SIZE,
        opcode::SESSION_CLOSE => types::TborSessionCloseResp::MAX_ENCODED_SIZE,
        opcode::PSK_CHANGE => types::TborPskChangeResp::MAX_ENCODED_SIZE,
        opcode::PART_INIT => types::TborPartInitResp::MAX_ENCODED_SIZE,
        opcode::PART_FINAL => types::TborPartFinalResp::MAX_ENCODED_SIZE,
        opcode::PART_INFO => types::TborPartInfoResp::MAX_ENCODED_SIZE,
        opcode::SD_SEALING_KEY_GEN => types::TborSdSealingKeyGenResp::MAX_ENCODED_SIZE,
        opcode::SD_CREATE_REMOTE_BACKUP => types::TborSdCreateRemoteBackupResp::MAX_ENCODED_SIZE,
        opcode::SD_RESEAL_REMOTE_BACKUP => types::TborSdResealRemoteBackupResp::MAX_ENCODED_SIZE,
        opcode::SD_RESTORE_REMOTE_BACKUP => types::TborSdRestoreRemoteBackupResp::MAX_ENCODED_SIZE,
        opcode::SD_RESTORE_LOCAL_BACKUP => types::TborSdRestoreLocalBackupResp::MAX_ENCODED_SIZE,
        opcode::SD_CREATE_PEER_BACKUP => types::TborSdCreatePeerBackupResp::MAX_ENCODED_SIZE,
        opcode::SD_RESTORE_PEER_BACKUP => types::TborSdRestorePeerBackupResp::MAX_ENCODED_SIZE,
        opcode::KEY_REPORT => types::TborKeyReportResp::MAX_ENCODED_SIZE,
        opcode::HMAC_GENERATE_KEY => types::TborHmacGenerateKeyResp::MAX_ENCODED_SIZE,
        opcode::HMAC => types::TborHmacResp::MAX_ENCODED_SIZE,
        opcode::GET_UNWRAPPING_KEY => types::TborGetUnwrappingKeyResp::MAX_ENCODED_SIZE,
        opcode::UNWRAP_KEY => types::TborUnwrapKeyResp::MAX_ENCODED_SIZE,
        opcode::AES_GENERATE_KEY => types::TborAesGenerateKeyResp::MAX_ENCODED_SIZE,
        opcode::ECC_GENERATE_KEY => types::TborEccGenerateKeyResp::MAX_ENCODED_SIZE,
        opcode::ECDH_DERIVE => types::TborEcdhDeriveResp::MAX_ENCODED_SIZE,
        opcode::RSA_MOD_EXP => types::TborRsaModExpResp::MAX_ENCODED_SIZE,
        opcode::HASH => types::TborHashResp::MAX_ENCODED_SIZE,
        opcode::HKDF_DERIVE => types::TborHkdfDeriveResp::MAX_ENCODED_SIZE,
        opcode::CONCAT_KDF_DERIVE => types::TborConcatKdfDeriveResp::MAX_ENCODED_SIZE,
        opcode::GET_CERT_CHAIN_INFO => types::TborGetCertChainInfoResp::MAX_ENCODED_SIZE,
        opcode::GET_CERTIFICATE => types::TborGetCertResp::MAX_ENCODED_SIZE,
        opcode::DARC_KEX_KEY_GEN => types::TborDarcKexKeyGenResp::MAX_ENCODED_SIZE,
        opcode::DARC_TMK_IMPORT => types::TborDarcTmkImportResp::MAX_ENCODED_SIZE,
        opcode::DARC_KEY_UNWRAP => types::TborDarcKeyUnwrapResp::MAX_ENCODED_SIZE,
        opcode::DARC_TMK_GEN => types::TborDarcTmkGenResp::MAX_ENCODED_SIZE,
        opcode::DARC_TMK_EXPORT => types::TborDarcTmkExportResp::MAX_ENCODED_SIZE,
        opcode::DARC_KEY_WRAP => types::TborDarcKeyWrapResp::MAX_ENCODED_SIZE,
        opcode::MLDSA_GENERATE_KEY => types::TborMlDsaGenerateKeyResp::MAX_ENCODED_SIZE,
        opcode::MLDSA_SIGN => types::TborMlDsaSignResp::MAX_ENCODED_SIZE,
        opcode::MLDSA_VERIFY => types::TborMlDsaVerifyResp::MAX_ENCODED_SIZE,
        opcode::MLKEM_GENERATE_KEY => types::TborMlKemGenerateKeyResp::MAX_ENCODED_SIZE,
        opcode::MLKEM_ENCAPSULATE => types::TborMlKemEncapsulateResp::MAX_ENCODED_SIZE,
        opcode::MLKEM_DECAPSULATE => types::TborMlKemDecapsulateResp::MAX_ENCODED_SIZE,
        // These handlers reclaim response space within every valid request.
        opcode::AES_ENCRYPT_DECRYPT | opcode::ECC_SIGN => request_len,
        _ if !is_known_opcode(opcode) => host_capacity,
        _ => tsra_fw_ddi_tbor::RESP_HEADER_LEN + 4,
    };
    request_len.max(output).next_multiple_of(4)
}

/// Dispatch takes the full request context (PAL, IO, buffers, opcode,
/// session ids, OOB pointer and undo log) because every handler is
/// invoked from here; bundling them into a struct would only move the
/// same fields behind one more indirection.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch<'p, P: HsmPal>(
    pal: &'p P,
    io: &P::Io,
    cmd_buf: &mut HsmCmdBuf<'_>,
    opcode: u8,
    sqe_session_id: u16,
    body_sess_id: Option<HsmSessId>,
    oob: Option<OobPtr>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<DispatchResult> {
    // Reject unknown opcodes with the canonical error *before*
    // applying any gating logic so the gate cannot leak existence of
    // unsupported opcodes through a different error code.
    //
    // A platform may claim an opcode the core does not implement — this
    // is how test-only commands are added without appearing in the core
    // opcode table. The hook runs only after `is_known_opcode` has
    // failed, so it can never shadow a real command, and it sees the
    // request untouched because nothing has been parsed yet.
    //
    // It runs ahead of the gating below, but not ahead of
    // `handle_tbor_op`'s `validate_tbor_session_flags`: an unknown
    // opcode is classified `SessionCtrl::NoSession`, so a custom TBOR
    // command must arrive with sessionless SQE flags or it is rejected
    // before reaching here.
    if !is_known_opcode(opcode) {
        let outcome = pal.tbor_dispatch(io, opcode, cmd_buf).await;
        let len = cmd_buf.finish_response(outcome)?;
        return Ok(DispatchResult {
            response_len: len,
            session_id: None,
        });
    }

    // Pre-dispatch gating work (session-id cross-check, default-PSK
    // gate).  Only out-of-session opcodes that need neither check skip
    // the re-parse entirely — the caller's `RequestView::parse` in
    // `handle_tbor_op` already validated the header and TOC structure.
    {
        let needs_cross_check = needs_session_id_cross_check(opcode);
        let needs_psk_gate = is_in_session(opcode) && !allowed_with_default_psk(opcode);

        if needs_cross_check || needs_psk_gate {
            // `handle_tbor_op` already parsed the frame to read the
            // opcode and took the body `session_id` from that same
            // parse, so both checks below reuse it. Deriving it here
            // meant a second `RequestView::parse` plus a full TOC scan
            // per check -- two scans per request, since neither check
            // shared the other's result.
            let sess_id = body_sess_id.ok_or(HsmError::DdiDecodeFailed)?;

            // SQE/body session-id cross-check: for every opcode whose
            // `SessionCtrl` requires `id_valid = true` (close +
            // in-session), the SQE-carried `session_id` MUST match the
            // inline body `session_id` TOC entry.
            if needs_cross_check && u16::from(sess_id) != sqe_session_id {
                return Err(HsmError::InvalidArg);
            }

            // Default-PSK gate: applies only to in-session commands
            // that are not on the allow-list.
            if needs_psk_gate {
                let psk_id = psk_id_for_role(sess_id.role());
                if crate::part_state::part_psk_is_default(pal, io, psk_id)? {
                    return Err(HsmError::DefaultPskMustRotate);
                }
            }
        }
    }

    let mut session_id: Option<u16> = None;

    let resp = match opcode {
        opcode::API_REV => api_rev::handle(cmd_buf),
        opcode::HASH => hash::handle(pal, io, cmd_buf).await,
        opcode::AES_ENCRYPT_DECRYPT => aes_encrypt_decrypt::handle(pal, io, cmd_buf).await,
        opcode::ECC_SIGN => ecc_sign::handle(pal, io, cmd_buf).await,
        opcode::SESSION_OPEN_INIT => {
            session_open_init::handle(pal, io, cmd_buf, undo, &mut session_id).await
        }
        opcode::SESSION_OPEN_FINISH => session_open_finish::handle(pal, io, cmd_buf, undo).await,
        opcode::SESSION_CLOSE => session_close::handle(pal, io, cmd_buf).await,
        opcode::PSK_CHANGE => psk_change::handle(pal, io, cmd_buf, undo).await,
        opcode::PART_INIT => part_init::handle(pal, io, cmd_buf, undo).await,
        opcode::PART_FINAL => part_final::handle(pal, io, cmd_buf, oob, undo).await,
        opcode::PART_INFO => part_info::handle(pal, io, cmd_buf),
        opcode::SD_SEALING_KEY_GEN => sd_sealing_key_gen::handle(pal, io, cmd_buf).await,
        opcode::SD_CREATE_REMOTE_BACKUP => {
            sd_create_remote_backup::handle(pal, io, cmd_buf, oob, undo).await
        }
        opcode::SD_RESEAL_REMOTE_BACKUP => {
            sd_reseal_remote_backup::handle(pal, io, cmd_buf, oob).await
        }
        opcode::SD_RESTORE_REMOTE_BACKUP => {
            sd_restore_remote_backup::handle(pal, io, cmd_buf, oob, undo).await
        }
        opcode::SD_RESTORE_LOCAL_BACKUP => {
            sd_restore_local_backup::handle(pal, io, cmd_buf, undo).await
        }
        opcode::SD_CREATE_PEER_BACKUP => sd_create_peer_backup::handle(pal, io, cmd_buf, oob).await,
        opcode::SD_RESTORE_PEER_BACKUP => {
            sd_restore_peer_backup::handle(pal, io, cmd_buf, oob, undo).await
        }
        opcode::KEY_REPORT => key_report::handle(pal, io, cmd_buf).await,
        opcode::HMAC_GENERATE_KEY => hmac_generate_key::handle(pal, io, cmd_buf).await,
        opcode::HMAC => hmac::handle(pal, io, cmd_buf).await,
        opcode::GET_UNWRAPPING_KEY => get_unwrapping_key::handle(pal, io, cmd_buf).await,
        opcode::UNWRAP_KEY => unwrap_key::handle(pal, io, cmd_buf, undo).await,
        opcode::AES_GENERATE_KEY => aes_generate_key::handle(pal, io, cmd_buf).await,
        opcode::ECC_GENERATE_KEY => ecc_generate_key::handle(pal, io, cmd_buf).await,
        opcode::ECDH_DERIVE => ecdh_derive::handle(pal, io, cmd_buf).await,
        opcode::RSA_MOD_EXP => rsa_mod_exp::handle(pal, io, cmd_buf).await,
        opcode::HKDF_DERIVE => hkdf_derive::handle(pal, io, cmd_buf).await,
        opcode::CONCAT_KDF_DERIVE => concat_kdf_derive::handle(pal, io, cmd_buf).await,
        opcode::GET_CERT_CHAIN_INFO => get_cert_chain_info::handle(pal, io, cmd_buf).await,
        opcode::GET_CERTIFICATE => get_cert::handle(pal, io, cmd_buf).await,
        opcode::DARC_KEX_KEY_GEN => darc_kex_key_gen::handle(pal, io, cmd_buf).await,
        opcode::DARC_TMK_IMPORT => darc_tmk_import::handle(pal, io, cmd_buf, oob).await,
        opcode::DARC_KEY_UNWRAP => darc_key_unwrap::handle(pal, io, cmd_buf).await,
        opcode::DARC_TMK_GEN => darc_tmk_gen::handle(pal, io, cmd_buf).await,
        opcode::DARC_TMK_EXPORT => darc_tmk_export::handle(pal, io, cmd_buf, oob).await,
        opcode::DARC_KEY_WRAP => darc_key_wrap::handle(pal, io, cmd_buf).await,
        opcode::MLDSA_GENERATE_KEY => mldsa_generate_key::handle(pal, io, cmd_buf).await,
        opcode::MLDSA_SIGN => mldsa_sign::handle(pal, io, cmd_buf).await,
        opcode::MLDSA_VERIFY => mldsa_verify::handle(pal, io, cmd_buf).await,
        opcode::MLKEM_GENERATE_KEY => mlkem_generate_key::handle(pal, io, cmd_buf).await,
        opcode::MLKEM_ENCAPSULATE => mlkem_encapsulate::handle(pal, io, cmd_buf).await,
        opcode::MLKEM_DECAPSULATE => mlkem_decapsulate::handle(pal, io, cmd_buf).await,
        _ => Err(HsmError::UnsupportedCmd),
    };
    let response_len = cmd_buf.finish_response(resp)?;
    Ok(DispatchResult {
        response_len,
        session_id,
    })
}

/// Returns `true` iff `opcode` is one of the opcodes wired into
/// [`dispatch`].  Kept in sync with the `match` arm by construction —
/// add a new opcode to the dispatcher AND this classifier in the same
/// change.
fn is_known_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        opcode::API_REV
            | opcode::SESSION_OPEN_INIT
            | opcode::SESSION_OPEN_FINISH
            | opcode::SESSION_CLOSE
            | opcode::PSK_CHANGE
            | opcode::PART_INIT
            | opcode::PART_FINAL
            | opcode::PART_INFO
            | opcode::SD_SEALING_KEY_GEN
            | opcode::SD_CREATE_REMOTE_BACKUP
            | opcode::SD_RESEAL_REMOTE_BACKUP
            | opcode::SD_RESTORE_REMOTE_BACKUP
            | opcode::SD_RESTORE_LOCAL_BACKUP
            | opcode::SD_CREATE_PEER_BACKUP
            | opcode::SD_RESTORE_PEER_BACKUP
            | opcode::KEY_REPORT
            | opcode::HMAC_GENERATE_KEY
            | opcode::HMAC
            | opcode::GET_UNWRAPPING_KEY
            | opcode::UNWRAP_KEY
            | opcode::AES_GENERATE_KEY
            | opcode::AES_ENCRYPT_DECRYPT
            | opcode::ECC_GENERATE_KEY
            | opcode::ECC_SIGN
            | opcode::ECDH_DERIVE
            | opcode::RSA_MOD_EXP
            | opcode::HASH
            | opcode::HKDF_DERIVE
            | opcode::CONCAT_KDF_DERIVE
            | opcode::GET_CERT_CHAIN_INFO
            | opcode::GET_CERTIFICATE
            | opcode::DARC_KEX_KEY_GEN
            | opcode::DARC_TMK_IMPORT
            | opcode::DARC_KEY_UNWRAP
            | opcode::DARC_TMK_GEN
            | opcode::DARC_TMK_EXPORT
            | opcode::DARC_KEY_WRAP
            | opcode::MLDSA_GENERATE_KEY
            | opcode::MLDSA_SIGN
            | opcode::MLDSA_VERIFY
            | opcode::MLKEM_GENERATE_KEY
            | opcode::MLKEM_ENCAPSULATE
            | opcode::MLKEM_DECAPSULATE
    )
}

/// Returns `true` iff `opcode` is an in-session command (i.e. requires
/// an Active session slot to operate on, identified by an inline
/// `session_id` TOC field).
///
/// Out-of-session opcodes (`ApiRev`) and session-establishment
/// opcodes (`SessionOpenInit`, `SessionOpenFinish`) return `false` —
/// they either need no session at all or they bring a Pending slot to
/// life, and the default-PSK gate would have nothing meaningful to
/// check for them.
///
/// New opcodes are in-session by default: anyone adding an opcode
/// must explicitly add it here and choose whether it bypasses the
/// default-PSK gate via [`allowed_with_default_psk`].
fn is_in_session(opcode: u8) -> bool {
    match opcode {
        opcode::API_REV
        | opcode::SESSION_OPEN_INIT
        | opcode::SESSION_OPEN_FINISH
        | opcode::PART_INFO
        | opcode::GET_CERT_CHAIN_INFO
        | opcode::GET_CERTIFICATE => false,
        opcode::SESSION_CLOSE
        | opcode::PSK_CHANGE
        | opcode::PART_INIT
        | opcode::PART_FINAL
        | opcode::SD_SEALING_KEY_GEN
        | opcode::SD_CREATE_REMOTE_BACKUP
        | opcode::SD_RESEAL_REMOTE_BACKUP
        | opcode::SD_RESTORE_REMOTE_BACKUP
        | opcode::SD_RESTORE_LOCAL_BACKUP
        | opcode::SD_CREATE_PEER_BACKUP
        | opcode::SD_RESTORE_PEER_BACKUP
        | opcode::KEY_REPORT
        | opcode::HMAC_GENERATE_KEY
        | opcode::HMAC
        | opcode::GET_UNWRAPPING_KEY
        | opcode::UNWRAP_KEY
        | opcode::AES_GENERATE_KEY
        | opcode::AES_ENCRYPT_DECRYPT
        | opcode::ECC_GENERATE_KEY
        | opcode::ECC_SIGN
        | opcode::ECDH_DERIVE
        | opcode::RSA_MOD_EXP
        | opcode::HASH
        | opcode::HKDF_DERIVE
        | opcode::CONCAT_KDF_DERIVE
        | opcode::DARC_KEX_KEY_GEN
        | opcode::DARC_TMK_IMPORT
        | opcode::DARC_KEY_UNWRAP
        | opcode::DARC_TMK_GEN
        | opcode::DARC_TMK_EXPORT
        | opcode::DARC_KEY_WRAP => true,
        // Default-deny: any future opcode is treated as in-session
        // until classified, so the default-PSK gate applies to it.
        _ => true,
    }
}

/// Returns `true` iff `opcode` carries an inline body `session_id`
/// TOC entry that the dispatcher should cross-check against the SQE
/// `session_id` field.
///
/// Equivalent to "the opcode's [`SessionCtrl`] requires
/// `id_valid = true`" (see
/// [`SessionCtrl::from_tbor_opcode`](crate::op::SessionCtrl::from_tbor_opcode)):
/// `SessionOpenFinish`, `SessionClose`, and `PskChange` all carry
/// the targeted slot id both in the SQE header and in the body's
/// `SessionId` TOC entry, and the two MUST agree.
///
/// Out-of-session opcodes (`ApiRev`, `SessionOpenInit`) carry no
/// body `session_id` and are not cross-checked here;
/// `validate_tbor_session_flags` already rejects them if the SQE
/// `id_valid` bit is set.
///
/// Default-deny for unknown opcodes: a new TBOR opcode is assumed to
/// be session-bearing until explicitly classified, so any future
/// addition that is *not* session-bearing must opt out here in the
/// same change that wires it into `dispatch`.
fn needs_session_id_cross_check(opcode: u8) -> bool {
    match opcode {
        opcode::API_REV
        | opcode::SESSION_OPEN_INIT
        | opcode::PART_INFO
        | opcode::GET_CERT_CHAIN_INFO
        | opcode::GET_CERTIFICATE => false,
        opcode::SESSION_OPEN_FINISH
        | opcode::SESSION_CLOSE
        | opcode::PSK_CHANGE
        | opcode::PART_INIT
        | opcode::PART_FINAL
        | opcode::SD_SEALING_KEY_GEN
        | opcode::SD_CREATE_REMOTE_BACKUP
        | opcode::SD_RESEAL_REMOTE_BACKUP
        | opcode::SD_RESTORE_REMOTE_BACKUP
        | opcode::SD_RESTORE_LOCAL_BACKUP
        | opcode::SD_CREATE_PEER_BACKUP
        | opcode::SD_RESTORE_PEER_BACKUP
        | opcode::KEY_REPORT
        | opcode::HMAC_GENERATE_KEY
        | opcode::HMAC
        | opcode::GET_UNWRAPPING_KEY
        | opcode::UNWRAP_KEY
        | opcode::AES_GENERATE_KEY
        | opcode::AES_ENCRYPT_DECRYPT
        | opcode::ECC_GENERATE_KEY
        | opcode::ECC_SIGN
        | opcode::ECDH_DERIVE
        | opcode::RSA_MOD_EXP
        | opcode::HASH
        | opcode::HKDF_DERIVE
        | opcode::CONCAT_KDF_DERIVE
        | opcode::DARC_KEX_KEY_GEN
        | opcode::DARC_TMK_IMPORT
        | opcode::DARC_KEY_UNWRAP
        | opcode::DARC_TMK_GEN
        | opcode::DARC_TMK_EXPORT
        | opcode::DARC_KEY_WRAP => true,
        _ => true,
    }
}

/// Returns `true` iff `opcode` is permitted while the calling role's
/// partition PSK is still the public default.
///
/// **Allow-list, not block-list:** any opcode not explicitly listed
/// here is rejected with [`HsmError::DefaultPskMustRotate`] on a
/// default-PSK partition.  This keeps the gate safe-by-default —
/// adding a new in-session command does NOT silently expose it via
/// the public default PSK.
///
/// The two members are the minimum needed for the bootstrap flow:
/// `PskChange` rotates the PSK; `SessionClose` lets the client tear
/// the bootstrap session down cleanly.
fn allowed_with_default_psk(opcode: u8) -> bool {
    matches!(opcode, opcode::PSK_CHANGE | opcode::SESSION_CLOSE)
}

/// Maps a session role to the partition PSK slot id it authenticates
/// against: CO sessions → slot 0, CU sessions → slot 1.  Matches the
/// convention used by [`psk_change`] and the session-establishment
/// handlers.
fn psk_id_for_role(role: HsmSessionRole) -> u8 {
    match role {
        HsmSessionRole::CryptoOfficer => 0,
        HsmSessionRole::CryptoUser => 1,
    }
}

/// Extracts the inline `session_id` TOC entry from an in-session
/// request.  Every in-session schema declares exactly one
/// `#[tbor(session_id)]` field, so the request is required to carry
/// **exactly one** `TocEntry::SessionId`.  A missing or duplicate
/// `SessionId` entry is a protocol-malformed request and returns
/// [`HsmError::DdiDecodeFailed`].
/// Whether the dispatcher's in-session gating will need the body
/// `session_id` for this opcode.
///
/// Lets `handle_tbor_op` skip the TOC scan for out-of-session commands,
/// which have no id to find and no gate to satisfy. Must stay in step
/// with the `needs_cross_check || needs_psk_gate` condition in
/// [`dispatch`].
pub(crate) fn needs_body_session_id(opcode: u8) -> bool {
    needs_session_id_cross_check(opcode)
        || (is_in_session(opcode) && !allowed_with_default_psk(opcode))
}

/// Body `session_id` if the frame carries exactly one, else `None`.
///
/// Used by `handle_tbor_op` to take the id from the parse it already
/// performs for the opcode, so the dispatcher's gating does not have to
/// re-parse and re-scan. Returning `None` for absent-or-duplicate keeps
/// the rejection where it was: the dispatcher still fails a request that
/// needs an id and has not got exactly one.
pub(crate) fn peek_session_id(view: &RequestView<'_>) -> Option<HsmSessId> {
    extract_session_id(view).ok()
}

fn extract_session_id(view: &RequestView<'_>) -> HsmResult<HsmSessId> {
    let mut found: Option<u16> = None;
    for entry in view.toc_iter() {
        if let TocEntry::SessionId(id) = entry {
            if found.is_some() {
                return Err(HsmError::DdiDecodeFailed);
            }
            found = Some(id);
        }
    }
    found.map(HsmSessId::from).ok_or(HsmError::DdiDecodeFailed)
}

/// Encode a TBOR error response: header with `status = err.0` and a
/// single `none` placeholder TOC entry (the wire format requires
/// `toc_count >= 1`).
///
/// `opcode` is included only in trace context — TBOR responses do not
/// carry the opcode (it's implicit from the request/response pairing).
pub(crate) fn encode_tbor_err(_opcode: u8, err: HsmError, out: &mut [u8]) -> HsmResult<usize> {
    let bytes = ResponseEncoder::new(out, PROTOCOL_VERSION, err.0, false)
        .none()?
        .finish()?;
    Ok(bytes.len())
}

/// Replace the response prefix with a fully initialized TBOR error frame.
pub(crate) fn encode_exchange_err(
    opcode: u8,
    err: HsmError,
    cmd_buf: &mut HsmCmdBuf<'_>,
) -> HsmResult<usize> {
    encode_tbor_err(opcode, err, cmd_buf.buffer_mut())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use tsra_fw_core_crypto_key_masking::aead::mask;
    use tsra_fw_core_crypto_key_masking::aead::AeadAlg;
    use tsra_fw_core_crypto_key_masking::aead::MaskParams;
    use tsra_fw_ddi_tbor_types::AesOp;
    use tsra_fw_ddi_tbor_types::HashAlgo;
    use tsra_fw_ddi_tbor_types::RsaOp;
    use tsra_fw_ddi_tbor_types::TborAesEncryptDecryptReq;
    use tsra_fw_ddi_tbor_types::TborAesEncryptDecryptResp;
    use tsra_fw_ddi_tbor_types::TborEccSignReq;
    use tsra_fw_ddi_tbor_types::TborEccSignResp;
    use tsra_fw_ddi_tbor_types::TborHashReq;
    use tsra_fw_ddi_tbor_types::TborHashResp;
    use tsra_fw_ddi_tbor_types::TborRsaModExpReq;
    use tsra_fw_ddi_tbor_types::TborRsaModExpResp;
    use tsra_fw_ddi_tbor_types::AES_IV_LEN;
    use tsra_fw_ddi_tbor_types::AES_MSG_MAX_LEN;
    use tsra_fw_ddi_tbor_types::HASH_MSG_MAX_LEN;
    use tsra_fw_ddi_tbor_types::MASKED_AES_KEY_MAX_LEN;
    use tsra_fw_ddi_tbor_types::MASKED_ECC_KEY_MAX_LEN;
    use tsra_fw_ddi_tbor_types::RSA_MASKED_KEY_MAX_LEN;
    use tsra_fw_hsm_pal_std::HsmIoRequest;
    use tsra_fw_hsm_pal_std::HsmPartId;
    use tsra_fw_hsm_pal_std::StdHsmIo;
    use tsra_fw_hsm_pal_std::StdHsmPal;

    use super::*;

    #[allow(unsafe_code)]
    fn dma(bytes: &mut [u8]) -> &mut HsmDmaBuf {
        // SAFETY: host tests use ordinary slice accesses, not a DMA engine.
        unsafe { HsmDmaBuf::from_raw_mut(bytes) }
    }

    async fn crypto_fixture() -> (StdHsmPal, StdHsmIo, HsmSessId) {
        let (tx, rx) = async_channel::bounded(1);
        let pal = StdHsmPal::new(rx, tokio::runtime::Handle::current());
        pal.part_alloc_internal(0, 1).await.unwrap();
        pal.part_enable_internal(0).await.unwrap();
        let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
        tx.send(HsmIoRequest {
            pid: HsmPartId::from(0u8),
            qid: 0,
            qidx: 0,
            sqe: [0; tsra_fw_hsm_io::SQE_DWORDS],
            tx: reply_tx,
        })
        .await
        .unwrap();
        let io = pal.poll_io().await.unwrap();
        let sess_id = pal
            .session_create_pending(&io, HsmSessionRole::CryptoUser, dma(&mut []))
            .await
            .unwrap();
        pal.session_promote(
            &io,
            sess_id,
            &[0; 8],
            dma(&mut [1; 32]),
            dma(&mut [2; 32]),
            None,
            None,
        )
        .await
        .unwrap();
        (pal, io, sess_id)
    }

    #[tokio::test]
    async fn cbc_mask_initializes_padding_in_reused_dma_storage() {
        use tsra_fw_core_crypto_key_masking::cbc;

        use crate::ddi::mbor::from_pal;
        use crate::ddi::mbor::masking;

        let (pal, io, _) = crypto_fixture().await;
        let mut key = [0x17; 80];
        let plaintext = [0x5C; 17];
        for plaintext_len in [1, 16, 17] {
            for label_len in 0..4 {
                let metadata = masking::masked_metadata(
                    &pal,
                    from_pal::vault_kind_ddi(HsmVaultKeyKind::Aes256).unwrap(),
                    HsmVaultKeyAttrs::new(),
                    &b"test"[..label_len],
                    plaintext_len as u16,
                )
                .unwrap();
                let mut storage = [0xA5; 512];
                let len = cbc::mask(
                    &pal,
                    &io,
                    dma(&mut key),
                    &plaintext[..plaintext_len],
                    &metadata,
                    Some(dma(&mut storage)),
                )
                .await
                .unwrap();
                assert!(storage[len..].iter().all(|&b| b == 0xA5));
                let layout = cbc::unmask(&pal, &io, dma(&mut key), dma(&mut storage[..len]))
                    .await
                    .unwrap();
                let start = layout.plaintext_offset;
                assert_eq!(
                    &storage[start..start + plaintext_len],
                    &plaintext[..plaintext_len]
                );
                assert!(
                    storage[start + plaintext_len..start + layout.plaintext_max_len]
                        .iter()
                        .all(|&b| b == 0)
                );
                assert!(storage[layout.metadata_offset + layout.metadata_len..start]
                    .iter()
                    .all(|&b| b == 0));
            }
        }
        pal.drop_io(io).await.unwrap();
    }

    #[tokio::test]
    async fn gcm_envelope_interoperates_with_host_using_iv16() {
        use tsra_crypto::aead_envelope as host_envelope;
        use tsra_crypto::ImportableKey;
        use tsra_fw_core_crypto_aead_envelope as fw_envelope;

        let (pal, io, _) = crypto_fixture().await;
        let mut key = [0x17; 32];
        let host_key = tsra_crypto::AesKey::from_bytes(&key).unwrap();
        let mut iv = [0x24; 16];
        let mut aad = [0x33; 32];
        for plaintext_len in [0, 1, 16, 17, 32] {
            let mut plaintext = vec![0x5c; plaintext_len];
            let mut blob = vec![0; AeadAlg::AesGcm256.envelope_len(plaintext_len, aad.len())];
            fw_envelope::seal(
                &pal,
                &io,
                AeadAlg::AesGcm256,
                dma(&mut key),
                dma(&mut iv),
                dma(&mut aad),
                dma(&mut plaintext),
                Some(dma(&mut blob)),
            )
            .await
            .unwrap();
            assert_eq!(blob[4], 0x03);
            assert_eq!(&blob[20..24], &[0, 0, 0, 1]);
            assert_eq!(
                host_envelope::open(&host_key, &mut blob).unwrap().payload,
                plaintext
            );

            host_envelope::seal(
                host_envelope::AeadAlg::AesGcm256,
                &host_key,
                &iv,
                &aad,
                &plaintext,
                Some(&mut blob),
            )
            .unwrap();
            blob[20..24].fill(0xff);
            let opened = fw_envelope::open(&pal, &io, dma(&mut key), dma(&mut blob))
                .await
                .unwrap();
            assert_eq!(opened.payload, plaintext.as_slice());
            assert_eq!(&opened.iv[12..], &[0xff; 4]);
        }
        pal.drop_io(io).await.unwrap();
    }

    #[tokio::test]
    async fn gcm_mask_zero_pads_and_recovers_exact_key_length() {
        use tsra_fw_core_crypto_key_masking::aead;

        let (pal, io, _) = crypto_fixture().await;
        let mut key = [0x17; 32];
        for plaintext_len in (0..=32).chain([66, 68]) {
            for in_place in [false, true] {
                pal.alloc_scoped_async(&io, async |alloc| {
                    let params = MaskParams {
                        key_kind: HsmVaultKeyKind::Aes256,
                        key_attrs: HsmVaultKeyAttrs::new(),
                        svn: 1,
                        owner_seed_id: 2,
                        key_label: alloc.dma_alloc(0)?,
                    };
                    let mut plaintext = vec![0x5c; plaintext_len];
                    if let Some(last) = plaintext.last_mut() {
                        *last = 0;
                    }
                    let mut storage = [0xa5; 512];
                    let alg = AeadAlg::AesGcm256;
                    let expected_len = 232 + plaintext_len.next_multiple_of(16);
                    assert_eq!(
                        mask(
                            &pal,
                            &io,
                            alloc,
                            alg,
                            dma(&mut key),
                            &params,
                            dma(&mut plaintext),
                            None
                        )
                        .await?,
                        expected_len,
                    );
                    let len = if in_place {
                        let at = aead::payload_offset(alg);
                        storage[at..at + plaintext_len].copy_from_slice(&plaintext);
                        aead::mask_in_place(
                            &pal,
                            &io,
                            alloc,
                            alg,
                            dma(&mut key),
                            &params,
                            plaintext_len,
                            dma(&mut storage),
                        )
                        .await?
                    } else {
                        mask(
                            &pal,
                            &io,
                            alloc,
                            alg,
                            dma(&mut key),
                            &params,
                            dma(&mut plaintext),
                            Some(dma(&mut storage)),
                        )
                        .await?
                    };
                    assert_eq!(len, expected_len);
                    assert!(storage[len..].iter().all(|&b| b == 0xa5));
                    assert_eq!(storage[4], AeadAlg::AesGcm256.as_u8());
                    let metadata = aead::peek_metadata(dma(&mut storage[..len]))?;
                    assert_eq!(metadata.version.get(), 1);
                    assert_eq!(
                        metadata.data_pad_len as usize,
                        (16 - plaintext_len % 16) % 16
                    );
                    let view =
                        aead::unmask(&pal, &io, dma(&mut key), dma(&mut storage[..len])).await?;
                    assert_eq!(view.target_key, plaintext.as_slice());
                    assert_eq!(
                        view.target_key.as_ptr() as usize,
                        storage.as_ptr() as usize + aead::payload_offset(alg)
                    );
                    Ok::<(), HsmError>(())
                })
                .await
                .unwrap();
            }
        }
        pal.drop_io(io).await.unwrap();
    }

    #[tokio::test]
    async fn gcm_unmask_rejects_authenticated_invalid_padding_and_removed_algorithm() {
        use tsra_fw_core_crypto_aead_envelope::HEADER_LEN;
        use tsra_fw_core_crypto_key_masking::aead;

        let (pal, io, _) = crypto_fixture().await;
        let mut key = [0x17; 32];
        for (plaintext_len, count, corrupt_tail, version) in [
            (1, 15, true, 1u16),
            (1, 16, false, 1),
            (0, 1, false, 1),
            (1, 15, false, 2),
        ] {
            pal.alloc_scoped_async(&io, async |alloc| {
                let params = MaskParams {
                    key_kind: HsmVaultKeyKind::Aes256,
                    key_attrs: HsmVaultKeyAttrs::new(),
                    svn: 1,
                    owner_seed_id: 2,
                    key_label: alloc.dma_alloc(0)?,
                };
                let mut plaintext = vec![0x5c; plaintext_len];
                let mut storage = [0xa5; 512];
                let len = mask(
                    &pal,
                    &io,
                    alloc,
                    AeadAlg::AesGcm256,
                    dma(&mut key),
                    &params,
                    dma(&mut plaintext),
                    Some(dma(&mut storage)),
                )
                .await?;
                assert!(matches!(
                    aead::peek_scope(dma(&mut storage[..len + 1])),
                    Err(HsmError::MaskedKeyDecodeFailed),
                ));
                assert!(matches!(
                    aead::peek_metadata(dma(&mut storage[..len + 1])),
                    Err(HsmError::MaskedKeyDecodeFailed),
                ));
                assert!(matches!(
                    aead::unmask(&pal, &io, dma(&mut key), dma(&mut storage[..len + 1])).await,
                    Err(HsmError::MaskedKeyDecodeFailed),
                ));
                pal.key_unmask_in_place(
                    &io,
                    dma(&mut key),
                    192,
                    dma(&mut storage[HEADER_LEN..len]),
                )
                .await?;
                storage[28..30].copy_from_slice(&version.to_le_bytes());
                storage[24 + 154] = count;
                if corrupt_tail {
                    storage[len - 17] = 1;
                }
                pal.key_mask_in_place(&io, dma(&mut key), 192, dma(&mut storage[HEADER_LEN..len]))
                    .await?;
                assert!(matches!(
                    aead::unmask(&pal, &io, dma(&mut key), dma(&mut storage[..len])).await,
                    Err(HsmError::MaskedKeyDecodeFailed),
                ));
                storage[4] = 0x04;
                assert!(aead::peek_metadata(dma(&mut storage[..len])).is_err());
                Ok::<(), HsmError>(())
            })
            .await
            .unwrap();
        }
        pal.drop_io(io).await.unwrap();
    }

    async fn masked_test_key(
        pal: &StdHsmPal,
        io: &StdHsmIo,
        sess_id: HsmSessId,
        kind: HsmVaultKeyKind,
        attrs: HsmVaultKeyAttrs,
        key: &mut [u8],
        out: &mut [u8],
    ) -> usize {
        pal.alloc_scoped_async(io, async |alloc| {
            let params = MaskParams {
                key_kind: kind,
                key_attrs: attrs.with_scope(HsmKeyScope::Session),
                svn: 0,
                owner_seed_id: 0,
                key_label: alloc.dma_alloc(0)?,
            };
            mask(
                pal,
                io,
                alloc,
                AeadAlg::AesGcm256,
                pal.session_masking_key(io, sess_id)?,
                &params,
                dma(key),
                Some(dma(out)),
            )
            .await
        })
        .await
        .unwrap()
    }

    async fn bounded_exchange(
        pal: &StdHsmPal,
        io: &StdHsmIo,
        request: &[u8],
        host_capacity: usize,
    ) -> HsmResult<Vec<u8>> {
        pal.alloc_scoped_async(io, async |_scope| {
            // Mirror the real IO allocation order within the PAL's 16 KiB heap.
            let undo_buf = pal.dma_alloc(io, tsra_fw_hsm_undo::UNDO_LOG_SIZE)?;
            let undo_address = undo_buf.as_ptr() as usize;
            let mut undo = UndoLog::new(undo_buf);
            let mut allocation = pal.dma_alloc_exchange(io, request.len().next_multiple_of(4))?;
            let address = allocation.as_ptr();
            allocation.buffer_mut()[..request.len()].copy_from_slice(request);
            let (opcode, body_session) = {
                let view =
                    tsra_fw_ddi_tbor::RequestView::parse(&allocation.buffer_mut()[..request.len()])?;
                (view.opcode(), peek_session_id(&view))
            };
            let capacity = exchange_capacity(opcode, request.len(), host_capacity);
            pal.dma_grow(io, &mut allocation, capacity)?;
            assert_eq!(allocation.as_ptr(), address);
            assert_eq!(address as usize, undo_address + tsra_fw_hsm_undo::UNDO_LOG_SIZE);
            let mut cmd_buf =
                HsmCmdBuf::new(allocation.buffer_mut(), request.len(), host_capacity)?;
            let started = std::time::Instant::now();
            let result = dispatch(
                pal,
                io,
                &mut cmd_buf,
                opcode,
                body_session.map(u16::from).unwrap_or(0),
                body_session,
                None,
                &mut undo,
            )
            .await;
            assert!(undo.is_empty());
            match result {
                Ok(out) => {
                    let response = cmd_buf.response(out.response_len)?;
                    assert_eq!(response.as_ptr(), address);
                    let response = response.to_vec();
                    let retained = pal.dma_alloc(io, 0)?.as_ptr() as usize - undo_address;
                    let workspace = match opcode {
                        opcode::MLKEM_ENCAPSULATE | opcode::MLKEM_DECAPSULATE => 32,
                        _ => 0,
                    };
                    assert_eq!(retained, tsra_fw_hsm_undo::UNDO_LOG_SIZE + capacity + workspace);
                    println!(
                        "TBOR {opcode:#04x}: request={} response={} exchange={capacity} retained_dma={retained} elapsed_us={}",
                        request.len(), response.len(), started.elapsed().as_micros()
                    );
                    Ok(response)
                }
                Err(error) => {
                    let len = encode_exchange_err(opcode, error, &mut cmd_buf)?;
                    assert_eq!(len, 12);
                    assert_eq!(
                        tsra_fw_ddi_tbor::ResponseView::parse(cmd_buf.response(len)?)?.status(),
                        error.0
                    );
                    Err(error)
                }
            }
        })
        .await
    }

    fn request_with_payload_gap(
        request: &[u8],
        toc_count: usize,
        buffer_slots: &[usize],
    ) -> Vec<u8> {
        use tsra_fw_ddi_tbor::toc::*;
        use tsra_fw_ddi_tbor::REQ_HEADER_LEN;

        let gap = 4;
        let data_start = REQ_HEADER_LEN + toc_count * 4;
        let mut shifted = request.to_vec();
        shifted.resize(request.len() + gap, 0);
        shifted.copy_within(data_start..request.len(), data_start + gap);
        shifted[data_start..data_start + gap].fill(0);
        for &slot in buffer_slots {
            let word = read_toc_word(&shifted, REQ_HEADER_LEN, slot);
            let word = build_toc_offset_len(
                raw_toc_entry_type(word),
                raw_toc_length(word),
                raw_toc_offset(word) + gap,
            );
            write_toc_word(&mut shifted, REQ_HEADER_LEN, slot, word);
        }
        shifted
    }

    #[tokio::test]
    async fn maximum_mldsa_exchanges_fit_dma_heap_and_reject_failed_outputs() {
        use tsra_fw_ddi_tbor_types as types;

        let (pal, io, sess_id) = crypto_fixture().await;
        crate::part_state::part_set_psk(&pal, &io, 1, dma(&mut [3; 32])).unwrap();
        let mut request = [0; 8192];
        let message = vec![0x42; types::MLDSA_MESSAGE_MAX_LEN];
        let mut ctx = vec![0x24; types::MLDSA_CTX_MAX_LEN];
        for kind in [
            types::MlDsaKeyKind::MlDsa44Seed,
            types::MlDsaKeyKind::MlDsa65Seed,
            types::MlDsaKeyKind::MlDsa87Seed,
        ] {
            let req = types::TborMlDsaGenerateKeyReq::encode(&mut request)
                .unwrap()
                .session_id(u16::from(sess_id).into())
                .unwrap()
                .scope(types::KeyScope(HsmKeyScope::Session.0))
                .unwrap()
                .key_kind(kind)
                .unwrap()
                .finish();
            // Bound the test future's stack usage independently of the DMA heap.
            let mut key = Box::pin(bounded_exchange(&pal, &io, req.as_bytes(), 8192))
                .await
                .unwrap();
            let key = types::TborMlDsaGenerateKeyResp::decode(dma(&mut key)).unwrap();
            let masked_key = key.masked_key().to_vec();
            let public_key = key.pub_key().to_vec();
            let req = types::TborMlDsaSignReq::encode(&mut request)
                .unwrap()
                .session_id(u16::from(sess_id).into())
                .unwrap()
                .masked_key(&masked_key)
                .unwrap()
                .message(&message)
                .unwrap()
                .ctx(&ctx)
                .unwrap()
                .finish();
            let mut signature = Box::pin(bounded_exchange(&pal, &io, req.as_bytes(), 8192))
                .await
                .unwrap();
            assert_eq!(
                Box::pin(bounded_exchange(&pal, &io, req.as_bytes(), 12)).await,
                Err(HsmError::TborBufferTooSmall)
            );
            let mut noncanonical = request_with_payload_gap(
                req.as_bytes(),
                types::TborMlDsaSignReq::TOC_COUNT,
                &[1, 2, 3],
            );
            types::TborMlDsaSignReq::decode(dma(&mut noncanonical)).unwrap();
            assert_eq!(
                Box::pin(bounded_exchange(&pal, &io, &noncanonical, 8192)).await,
                Err(HsmError::InvalidArg)
            );
            let signature = types::TborMlDsaSignResp::decode(dma(&mut signature))
                .unwrap()
                .signature()
                .to_vec();
            for valid in [true, false] {
                if !valid {
                    ctx[0] ^= 1;
                }
                let req = types::TborMlDsaVerifyReq::encode(&mut request)
                    .unwrap()
                    .session_id(u16::from(sess_id).into())
                    .unwrap()
                    .pub_key(&public_key)
                    .unwrap()
                    .message(&message)
                    .unwrap()
                    .ctx(&ctx)
                    .unwrap()
                    .signature(&signature)
                    .unwrap()
                    .finish();
                let result = Box::pin(bounded_exchange(&pal, &io, req.as_bytes(), 8192)).await;
                if valid {
                    result.unwrap();
                    if kind == types::MlDsaKeyKind::MlDsa87Seed {
                        assert_eq!(req.len(), 8088);
                    }
                } else {
                    assert_eq!(result, Err(HsmError::MlDsaVerifyFailed));
                    ctx[0] ^= 1;
                }
            }
        }
    }

    #[tokio::test]
    async fn maximum_mlkem_exchanges_fit_dma_heap_and_preserve_shared_secrets() {
        use tsra_fw_ddi_tbor_types as types;

        let (pal, io, sess_id) = crypto_fixture().await;
        crate::part_state::part_set_psk(&pal, &io, 1, dma(&mut [3; 32])).unwrap();
        let mut request = [0; 8192];
        for kind in [
            types::MlKemKeyKind::MlKem512Seed,
            types::MlKemKeyKind::MlKem768Seed,
            types::MlKemKeyKind::MlKem1024Seed,
        ] {
            let req = types::TborMlKemGenerateKeyReq::encode(&mut request)
                .unwrap()
                .session_id(u16::from(sess_id).into())
                .unwrap()
                .scope(types::KeyScope(HsmKeyScope::Session.0))
                .unwrap()
                .key_kind(kind)
                .unwrap()
                .finish();
            let mut key = bounded_exchange(&pal, &io, req.as_bytes(), 8192)
                .await
                .unwrap();
            let key = types::TborMlKemGenerateKeyResp::decode(dma(&mut key)).unwrap();
            let mut masked_key = key.masked_key().to_vec();
            let public_key = key.pub_key().to_vec();
            let req = types::TborMlKemEncapsulateReq::encode(&mut request)
                .unwrap()
                .session_id(u16::from(sess_id).into())
                .unwrap()
                .scope(types::KeyScope(HsmKeyScope::Session.0))
                .unwrap()
                .pub_key(&public_key)
                .unwrap()
                .finish();
            let mut encapsulated = bounded_exchange(&pal, &io, req.as_bytes(), 8192)
                .await
                .unwrap();
            let mut noncanonical = request_with_payload_gap(
                req.as_bytes(),
                types::TborMlKemEncapsulateReq::TOC_COUNT,
                &[2],
            );
            types::TborMlKemEncapsulateReq::decode(dma(&mut noncanonical)).unwrap();
            assert_eq!(
                Box::pin(bounded_exchange(&pal, &io, &noncanonical, 8192)).await,
                Err(HsmError::InvalidArg)
            );
            let encapsulated =
                types::TborMlKemEncapsulateResp::decode(dma(&mut encapsulated)).unwrap();
            let ciphertext = encapsulated.ciphertext().to_vec();
            let mut shared_secret = encapsulated.masked_shared_secret().to_vec();
            for valid in [true, false] {
                if !valid {
                    *masked_key.last_mut().unwrap() ^= 1;
                }
                let req = types::TborMlKemDecapsulateReq::encode(&mut request)
                    .unwrap()
                    .session_id(u16::from(sess_id).into())
                    .unwrap()
                    .scope(types::KeyScope(HsmKeyScope::Session.0))
                    .unwrap()
                    .masked_key(&masked_key)
                    .unwrap()
                    .ciphertext(&ciphertext)
                    .unwrap()
                    .finish();
                let result = bounded_exchange(&pal, &io, req.as_bytes(), 8192).await;
                if valid {
                    let mut decapsulated = result.unwrap();
                    let decapsulated =
                        types::TborMlKemDecapsulateResp::decode(dma(&mut decapsulated)).unwrap();
                    let mut recovered = decapsulated.masked_shared_secret().to_vec();
                    let masking_key = pal.session_masking_key(&io, sess_id).unwrap();
                    let left = tsra_fw_core_crypto_key_masking::aead::unmask(
                        &pal,
                        &io,
                        masking_key,
                        dma(&mut shared_secret),
                    )
                    .await
                    .unwrap();
                    let right = tsra_fw_core_crypto_key_masking::aead::unmask(
                        &pal,
                        &io,
                        masking_key,
                        dma(&mut recovered),
                    )
                    .await
                    .unwrap();
                    assert!(left.target_key == right.target_key);
                } else {
                    assert!(result.is_err());
                }
            }
        }
    }

    #[tokio::test]
    async fn malformed_requests_for_every_command_leave_sessions_and_undo_intact() {
        let (pal, io, sess_id) = crypto_fixture().await;
        crate::part_state::part_set_psk(&pal, &io, 1, dma(&mut [3; 32])).unwrap();
        let mut tested = 0;
        for opcode in 0..=u8::MAX {
            if !is_known_opcode(opcode) || matches!(opcode, opcode::API_REV | opcode::PART_INFO) {
                continue;
            }
            let mut request = [0; 136];
            let mut encoder =
                tsra_fw_ddi_tbor::RequestEncoder::new(&mut request, PROTOCOL_VERSION, opcode);
            for _ in 0..32 {
                encoder = encoder.none().unwrap();
            }
            let request = encoder.finish().unwrap();
            pal.alloc_scoped_async(&io, async |_scope| {
                let mut undo =
                    UndoLog::new(pal.dma_alloc(&io, tsra_fw_hsm_undo::UNDO_LOG_SIZE).unwrap());
                let capacity = exchange_capacity(opcode, request.len(), 8192);
                let mut allocation = pal.dma_alloc_exchange(&io, capacity).unwrap();
                allocation.buffer_mut()[..request.len()].copy_from_slice(request);
                let mut cmd_buf =
                    HsmCmdBuf::new(allocation.buffer_mut(), request.len(), 8192).unwrap();
                let result = dispatch(
                    &pal,
                    &io,
                    &mut cmd_buf,
                    opcode,
                    u16::from(sess_id),
                    Some(sess_id),
                    None,
                    &mut undo,
                )
                .await;
                let error = match result {
                    Ok(_) => panic!("opcode {opcode:#04x} accepted missing required fields"),
                    Err(error) => error,
                };
                let len = encode_exchange_err(opcode, error, &mut cmd_buf).unwrap();
                assert_eq!(len, 12);
                assert!(undo.is_empty());
                assert!(matches!(
                    pal.session_state(&io, sess_id),
                    HsmSessionState::Active
                ));
            })
            .await;
            tested += 1;
        }
        assert_eq!(tested, 41);
    }

    #[tokio::test]
    async fn exchange_hash_reclaims_input_and_grows_for_empty_messages() {
        let (pal, io, sess_id) = crypto_fixture().await;
        for size in [0, 3, HASH_MSG_MAX_LEN] {
            let mut storage = [0xA5; 2100];
            let address = storage.as_ptr();
            let request_len = TborHashReq::encode(&mut storage)
                .unwrap()
                .session_id(u16::from(sess_id).into())
                .unwrap()
                .algo(HashAlgo::Sha512)
                .unwrap()
                .msg(&vec![0x42; size])
                .unwrap()
                .finish()
                .len();
            let capacity = exchange_capacity(opcode::HASH, request_len, 84);
            let mut cmd_buf =
                HsmCmdBuf::new(dma(&mut storage[..capacity]), request_len, 84).unwrap();
            let outcome = hash::handle(&pal, &io, &mut cmd_buf).await;
            let len = cmd_buf.finish_response(outcome).unwrap();
            let response = cmd_buf.response(len).unwrap();
            assert_eq!(response.as_ptr(), address);
            let frame = TborHashResp::decode(response).unwrap();
            assert_eq!(frame.digest().len(), HsmHashAlgo::Sha512.digest_len());
            assert_eq!(len, 20 + frame.digest().len());
        }
    }

    #[tokio::test]
    async fn exchange_aes_preserves_message_and_iv_addresses() {
        let (pal, io, sess_id) = crypto_fixture().await;
        let mut masked = [0; MASKED_AES_KEY_MAX_LEN];
        let masked_len = masked_test_key(
            &pal,
            &io,
            sess_id,
            HsmVaultKeyKind::Aes256,
            HsmVaultKeyAttrs::new()
                .with_encrypt(true)
                .with_decrypt(true),
            &mut [0x11; 32],
            &mut masked,
        )
        .await;
        let mut message = vec![0x5A; AES_MSG_MAX_LEN];
        for op in [AesOp::Encrypt, AesOp::Decrypt] {
            let mut storage = [0xA5; 1400];
            let request = TborAesEncryptDecryptReq::encode(&mut storage)
                .unwrap()
                .session_id(u16::from(sess_id).into())
                .unwrap()
                .op(op)
                .unwrap()
                .msg(&message)
                .unwrap()
                .iv(&[0x22; AES_IV_LEN])
                .unwrap()
                .masked_key(&masked[..masked_len])
                .unwrap()
                .finish();
            let request_len = request.len();
            let msg_address = request.msg().as_ptr();
            let iv_address = request.iv().as_ptr();
            let mut cmd_buf =
                HsmCmdBuf::new(dma(&mut storage), request_len, 28 + message.len() + 16).unwrap();
            let outcome = aes_encrypt_decrypt::handle(&pal, &io, &mut cmd_buf).await;
            let len = cmd_buf.finish_response(outcome).unwrap();
            let response =
                TborAesEncryptDecryptResp::decode(cmd_buf.response(len).unwrap()).unwrap();
            assert_eq!(response.msg().as_ptr(), msg_address);
            assert_eq!(response.iv().as_ptr(), iv_address);
            assert_eq!(len, 28 + message.len() + AES_IV_LEN);
            if op == AesOp::Encrypt {
                assert_ne!(response.msg(), &message[..]);
                message.copy_from_slice(response.msg());
            } else {
                assert!(response.msg().iter().all(|&b| b == 0x5A));
            }
        }
    }

    #[tokio::test]
    async fn exchange_aes_rejects_gaps_and_invalid_permissions() {
        let (pal, io, sess_id) = crypto_fixture().await;
        let mut masked = [0; MASKED_AES_KEY_MAX_LEN];
        let masked_len = masked_test_key(
            &pal,
            &io,
            sess_id,
            HsmVaultKeyKind::Aes256,
            HsmVaultKeyAttrs::new(),
            &mut [0x11; 32],
            &mut masked,
        )
        .await;
        for (gap, expected) in [(0, HsmError::InvalidPermissions), (4, HsmError::InvalidArg)] {
            let mut storage = [0xA5; 400];
            let request_len = TborAesEncryptDecryptReq::encode(&mut storage)
                .unwrap()
                .session_id(u16::from(sess_id).into())
                .unwrap()
                .op(AesOp::Encrypt)
                .unwrap()
                .msg(&[0x5A; 32])
                .unwrap()
                .iv(&[0x22; AES_IV_LEN])
                .unwrap()
                .masked_key(&masked[..masked_len])
                .unwrap()
                .finish()
                .len();
            if gap != 0 {
                use tsra_fw_ddi_tbor::toc::*;

                storage.copy_within(28..request_len, 28 + gap);
                for index in 2..5 {
                    let word = read_toc_word(&storage, 8, index);
                    let shifted = build_toc_offset_len(
                        raw_toc_entry_type(word),
                        raw_toc_length(word),
                        raw_toc_offset(word) + gap,
                    );
                    write_toc_word(&mut storage, 8, index, shifted);
                }
            }
            let mut cmd_buf = HsmCmdBuf::new(dma(&mut storage), request_len + gap, 80).unwrap();
            let outcome = aes_encrypt_decrypt::handle(&pal, &io, &mut cmd_buf).await;
            assert_eq!(cmd_buf.finish_response(outcome), Err(expected));
        }
    }

    #[tokio::test]
    async fn exchange_ecc_sign_reuses_metadata_and_enforces_permissions() {
        for (curve, kind) in [
            (HsmEccCurve::P256, HsmVaultKeyKind::Ecc256Private),
            (HsmEccCurve::P384, HsmVaultKeyKind::Ecc384Private),
            (HsmEccCurve::P521, HsmVaultKeyKind::Ecc521Private),
        ] {
            for permitted in [true, false] {
                let (pal, io, sess_id) = crypto_fixture().await;
                let mut key = vec![0; curve.wire_coord_len()];
                key[curve.wire_coord_len() - 1] = 1;
                let mut masked = [0; MASKED_ECC_KEY_MAX_LEN];
                let masked_len = masked_test_key(
                    &pal,
                    &io,
                    sess_id,
                    kind,
                    HsmVaultKeyAttrs::new().with_sign(permitted),
                    &mut key,
                    &mut masked,
                )
                .await;
                let mut storage = [0xA5; 400];
                let address = storage.as_ptr();
                let request_len = TborEccSignReq::encode(&mut storage)
                    .unwrap()
                    .session_id(u16::from(sess_id).into())
                    .unwrap()
                    .masked_key(&masked[..masked_len])
                    .unwrap()
                    .digest(&vec![0x42; curve.ecdsa_digest_len()])
                    .unwrap()
                    .finish()
                    .len();
                let mut cmd_buf =
                    HsmCmdBuf::new(dma(&mut storage), request_len, 20 + curve.wire_sig_len())
                        .unwrap();
                let outcome = ecc_sign::handle(&pal, &io, &mut cmd_buf).await;
                let result = cmd_buf.finish_response(outcome);
                if permitted {
                    let len = result.unwrap();
                    let response = cmd_buf.response(len).unwrap();
                    assert_eq!(response.as_ptr(), address);
                    let frame = TborEccSignResp::decode(response).unwrap();
                    assert_eq!(frame.signature().len(), curve.wire_sig_len());
                    assert_eq!(len, 20 + curve.wire_sig_len());
                } else {
                    assert_eq!(result, Err(HsmError::InvalidPermissions));
                }
            }
        }
    }

    #[test]
    fn exchange_api_rev_reuses_the_request_allocation() {
        let mut storage = [0xA5; 16];
        let address = storage.as_ptr();
        let len = tsra_fw_ddi_tbor_types::TborApiRevReq::encode(&mut storage)
            .unwrap()
            .finish()
            .len();
        let mut cmd_buf = HsmCmdBuf::new(dma(&mut storage), len, 16).unwrap();
        let len = api_rev::handle(&mut cmd_buf).unwrap();
        let bytes = cmd_buf.response(len).unwrap();
        assert_eq!(bytes.as_ptr(), address);
        let response = tsra_fw_ddi_tbor_types::TborApiRevResp::decode(bytes).unwrap();
        assert_eq!(response.min_ver(), PROTOCOL_VERSION);
        assert_eq!(response.max_ver(), PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn exchange_rsa_overwrites_input_and_rejects_invalid_requests() {
        let (pal, io, sess_id) = crypto_fixture().await;
        let mut private_key = [0; 2 * 256 + 4];
        pal.rsa_gen_keypair(
            &io,
            HsmRsaKey::Rsa2048Priv,
            dma(&mut private_key),
            dma(&mut [0; 512]),
            HsmRsaPct::None,
        )
        .await
        .unwrap();
        let mut y = [0; 256];
        y[0] = 2;
        let mut expected = [0; 256];
        pal.mod_exp_priv(
            &io,
            HsmRsaKey::Rsa2048Priv,
            dma(&mut private_key),
            dma(&mut y),
            dma(&mut expected),
        )
        .await
        .unwrap();
        for (permitted, input, gap, host_capacity) in [
            (true, 2, 0, 280),
            (false, 2, 0, 280),
            (true, 1, 0, 280),
            (true, 2, 4, 280),
            (true, 2, 0, 12),
        ] {
            let mut masked = [0; RSA_MASKED_KEY_MAX_LEN];
            let masked_len = masked_test_key(
                &pal,
                &io,
                sess_id,
                HsmVaultKeyKind::Rsa2kPrivate,
                HsmVaultKeyAttrs::new().with_sign(permitted),
                &mut private_key,
                &mut masked,
            )
            .await;
            y[0] = input;
            let mut storage = [0xA5; 1400];
            let address = storage.as_ptr();
            let request_len = TborRsaModExpReq::encode(&mut storage)
                .unwrap()
                .session_id(u16::from(sess_id).into())
                .unwrap()
                .y(&y)
                .unwrap()
                .masked_key(&masked[..masked_len])
                .unwrap()
                .op_type(RsaOp::Sign)
                .unwrap()
                .finish()
                .len();
            if gap != 0 {
                use tsra_fw_ddi_tbor::toc::*;

                let data_start = tsra_fw_ddi_tbor::REQ_HEADER_LEN + TborRsaModExpReq::TOC_COUNT * 4;
                storage.copy_within(data_start..request_len, data_start + gap);
                for index in 1..=2 {
                    let word = read_toc_word(&storage, 8, index);
                    let shifted = build_toc_offset_len(
                        raw_toc_entry_type(word),
                        raw_toc_length(word),
                        raw_toc_offset(word) + gap,
                    );
                    write_toc_word(&mut storage, 8, index, shifted);
                }
            }
            let mut cmd_buf =
                HsmCmdBuf::new(dma(&mut storage), request_len + gap, host_capacity).unwrap();
            let request = TborRsaModExpReq::decode(cmd_buf.request()).unwrap();
            let y_address = request.y().as_ptr();
            assert!(request.masked_key().as_ptr() as usize >= y_address as usize + y.len());
            let outcome = rsa_mod_exp::handle(&pal, &io, &mut cmd_buf).await;
            let result = cmd_buf.finish_response(outcome);
            if permitted && input == 2 && gap == 0 && host_capacity == 280 {
                let response = cmd_buf.response(result.unwrap()).unwrap();
                assert_eq!(response.as_ptr(), address);
                let frame = TborRsaModExpResp::decode(response).unwrap();
                assert_eq!(frame.x().as_ptr(), y_address);
                assert_eq!(frame.x(), &expected[..]);
            } else {
                let error = if !permitted {
                    HsmError::InvalidPermissions
                } else if host_capacity == 12 {
                    HsmError::TborBufferTooSmall
                } else {
                    HsmError::InvalidArg
                };
                assert_eq!(result, Err(error));
            }
        }
    }

    #[test]
    fn response_completion_validates_without_modifying_storage() {
        for (host_capacity, outcome, expected) in [
            (16, Ok(16), Ok(16)),
            (
                16,
                Err(HsmError::InvalidPermissions),
                Err(HsmError::InvalidPermissions),
            ),
            (16, Ok(0), Err(HsmError::TborBufferTooSmall)),
            (16, Ok(17), Err(HsmError::TborBufferTooSmall)),
            (128, Ok(65), Err(HsmError::TborBufferTooSmall)),
        ] {
            let mut storage = [0xA5; 64];
            let cmd_buf = HsmCmdBuf::new(dma(&mut storage), 48, host_capacity).unwrap();
            assert_eq!(cmd_buf.finish_response(outcome), expected);
            assert!(storage.iter().all(|&b| b == 0xA5));
        }
    }

    #[tokio::test]
    async fn dispatch_finishes_shared_responses_and_preserves_undo_storage() {
        let (pal, io, _) = crypto_fixture().await;
        for host_capacity in [12, 16] {
            let mut storage = [0xA5; 32];
            let address = storage.as_ptr();
            let request_len = tsra_fw_ddi_tbor_types::TborApiRevReq::encode(&mut storage)
                .unwrap()
                .finish()
                .len();
            let mut undo_storage = [0xAC; 128];
            let mut undo = UndoLog::new(dma(&mut undo_storage));
            let mut cmd_buf =
                HsmCmdBuf::new(dma(&mut storage), request_len, host_capacity).unwrap();
            let result = dispatch(
                &pal,
                &io,
                &mut cmd_buf,
                opcode::API_REV,
                0,
                None,
                None,
                &mut undo,
            )
            .await;
            if host_capacity == 16 {
                let response = cmd_buf.response(result.unwrap().response_len).unwrap();
                assert_eq!(response.as_ptr(), address);
                assert_eq!(response.len(), 16);
            } else {
                assert!(matches!(result, Err(HsmError::TborBufferTooSmall)));
            }
            assert!(cmd_buf.buffer_mut()[16..].iter().all(|&b| b == 0xA5));
            assert!(undo.is_empty());
            assert!(undo_storage.iter().all(|&b| b == 0xAC));
        }
    }

    #[test]
    fn exchange_error_initializes_only_its_prefix_without_touching_undo_storage() {
        let mut storage = [[0xA5; 64], [0x5A; 64]];
        for storage in &mut storage {
            let fill = storage[0];
            let (undo, buffer) = storage.split_at_mut(32);
            let address = buffer.as_ptr();
            let mut cmd_buf = HsmCmdBuf::new(dma(buffer), 16, 12).unwrap();
            let len =
                encode_exchange_err(opcode::API_REV, HsmError::InvalidArg, &mut cmd_buf).unwrap();
            let bytes = cmd_buf.response(len).unwrap();
            assert_eq!(bytes.as_ptr(), address);
            assert_eq!(len, 12);
            let response = tsra_fw_ddi_tbor::ResponseView::parse(bytes).unwrap();
            assert_eq!(response.status(), HsmError::InvalidArg.0);
            assert_eq!(response.toc_count(), 1);
            assert!(cmd_buf.buffer_mut()[len..].iter().all(|&b| b == fill));
            assert!(undo.iter().all(|&b| b == fill));
        }
        assert_eq!(storage[0][32..44], storage[1][32..44]);
    }

    /// Synthetic opcode used to exercise the "future in-session
    /// command that is NOT on the allow-list" branch of the gate.
    /// Picked from the unallocated opcode space so it cannot collide
    /// with a real handler.
    const SYNTHETIC_FUTURE_OPCODE: u8 = 0xFE;

    #[test]
    fn known_opcodes_match_dispatch_arms() {
        for op in [
            opcode::API_REV,
            opcode::SESSION_OPEN_INIT,
            opcode::SESSION_OPEN_FINISH,
            opcode::SESSION_CLOSE,
            opcode::PSK_CHANGE,
            opcode::PART_INIT,
            opcode::PART_INFO,
            opcode::PART_FINAL,
            opcode::SD_SEALING_KEY_GEN,
            opcode::SD_CREATE_REMOTE_BACKUP,
            opcode::SD_RESEAL_REMOTE_BACKUP,
            opcode::KEY_REPORT,
        ] {
            assert!(is_known_opcode(op), "{op:#04x} should be known");
        }
        assert!(!is_known_opcode(0x00));
        assert!(!is_known_opcode(0xFF));
    }

    #[test]
    fn out_of_session_opcodes_are_not_in_session() {
        for op in [
            opcode::API_REV,
            opcode::SESSION_OPEN_INIT,
            opcode::SESSION_OPEN_FINISH,
        ] {
            assert!(!is_in_session(op), "{op:#04x} must be out-of-session");
        }
    }

    #[test]
    fn close_and_psk_change_are_in_session() {
        assert!(is_in_session(opcode::SESSION_CLOSE));
        assert!(is_in_session(opcode::PSK_CHANGE));
    }

    #[test]
    fn sd_sealing_key_gen_is_in_session() {
        assert!(is_in_session(opcode::SD_SEALING_KEY_GEN));
    }

    #[test]
    fn darc_kex_key_gen_is_in_session() {
        assert!(is_in_session(opcode::DARC_KEX_KEY_GEN));
        assert!(needs_session_id_cross_check(opcode::DARC_KEX_KEY_GEN));
        assert!(is_known_opcode(opcode::DARC_KEX_KEY_GEN));
    }

    #[test]
    fn darc_tmk_import_is_in_session() {
        assert!(is_in_session(opcode::DARC_TMK_IMPORT));
        assert!(needs_session_id_cross_check(opcode::DARC_TMK_IMPORT));
        assert!(is_known_opcode(opcode::DARC_TMK_IMPORT));
    }

    #[test]
    fn darc_key_unwrap_is_in_session() {
        assert!(is_in_session(opcode::DARC_KEY_UNWRAP));
        assert!(needs_session_id_cross_check(opcode::DARC_KEY_UNWRAP));
        assert!(is_known_opcode(opcode::DARC_KEY_UNWRAP));
    }

    #[test]
    fn darc_tmk_gen_is_in_session() {
        assert!(is_in_session(opcode::DARC_TMK_GEN));
        assert!(needs_session_id_cross_check(opcode::DARC_TMK_GEN));
        assert!(is_known_opcode(opcode::DARC_TMK_GEN));
    }

    #[test]
    fn darc_tmk_export_is_in_session() {
        assert!(is_in_session(opcode::DARC_TMK_EXPORT));
        assert!(needs_session_id_cross_check(opcode::DARC_TMK_EXPORT));
        assert!(is_known_opcode(opcode::DARC_TMK_EXPORT));
    }

    #[test]
    fn darc_key_wrap_is_in_session() {
        assert!(is_in_session(opcode::DARC_KEY_WRAP));
        assert!(needs_session_id_cross_check(opcode::DARC_KEY_WRAP));
        assert!(is_known_opcode(opcode::DARC_KEY_WRAP));
    }

    #[test]
    fn key_report_is_in_session() {
        assert!(is_in_session(opcode::KEY_REPORT));
    }

    #[test]
    fn unknown_opcode_defaults_to_in_session() {
        // Default-deny: an unknown future opcode is treated as
        // in-session so the default-PSK gate applies to it until it
        // is explicitly classified.
        assert!(is_in_session(SYNTHETIC_FUTURE_OPCODE));
    }

    #[test]
    fn allow_list_is_exactly_psk_change_and_session_close() {
        assert!(allowed_with_default_psk(opcode::PSK_CHANGE));
        assert!(allowed_with_default_psk(opcode::SESSION_CLOSE));
        // Everything else — known or unknown — is NOT allowed.
        for op in [
            opcode::API_REV,
            opcode::SESSION_OPEN_INIT,
            opcode::SESSION_OPEN_FINISH,
            opcode::SD_SEALING_KEY_GEN,
            SYNTHETIC_FUTURE_OPCODE,
            0x00,
            0xFF,
        ] {
            assert!(
                !allowed_with_default_psk(op),
                "{op:#04x} must NOT bypass the default-PSK gate",
            );
        }
    }

    #[test]
    fn psk_id_maps_role_to_slot() {
        assert_eq!(psk_id_for_role(HsmSessionRole::CryptoOfficer), 0);
        assert_eq!(psk_id_for_role(HsmSessionRole::CryptoUser), 1);
    }

    #[test]
    fn future_in_session_opcode_is_gated() {
        // Composite property the dispatcher relies on: a future
        // unknown-but-classified-as-in-session opcode is NOT on the
        // allow-list, so the gate would apply.  This is the
        // safe-by-default contract of `is_in_session` +
        // `allowed_with_default_psk`.
        assert!(is_in_session(SYNTHETIC_FUTURE_OPCODE));
        assert!(!allowed_with_default_psk(SYNTHETIC_FUTURE_OPCODE));
    }
}
