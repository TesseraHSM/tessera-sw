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
//! The dispatcher signature mirrors
//! [`crate::ddi::mbor::dispatch`]: it is `async fn dispatch<P:
//! HsmPal>(pal, io, view, opcode) -> HsmResult<&'p DmaBuf>` so handlers
//! can perform vault, crypto, and session-manager work.  Each handler
//! allocates its output buffer via
//! [`HsmAlloc::dma_alloc_var`](tsra_fw_hsm_pal_traits::HsmAlloc::dma_alloc_var)
//! and returns the resulting `&DmaBuf` slice (lifetime tied to the
//! per-IO allocator scope).

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
#[cfg(feature = "tbor-test-cmds")]
pub(crate) mod test_aes_gcm;
pub(crate) mod unwrap_key;

use tsra_fw_ddi_tbor::RequestView;
use tsra_fw_ddi_tbor::ResponseEncoder;
use tsra_fw_ddi_tbor::TocEntry;
use tsra_fw_ddi_tbor::PROTOCOL_VERSION;
use tsra_fw_hsm_oob::OobPtr;
use tsra_fw_hsm_pal_traits::DmaBuf;
use tsra_fw_hsm_pal_traits::HsmError;
use tsra_fw_hsm_pal_traits::HsmIo;
use tsra_fw_hsm_pal_traits::HsmKeyId;
use tsra_fw_hsm_pal_traits::HsmPal;
use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_hsm_pal_traits::HsmSessId;
use tsra_fw_hsm_pal_traits::HsmSessionState;
use tsra_fw_hsm_pal_traits::SessionRole;
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

    /// `TestAesGcm` — test-only AES-256-GCM under a raw request key, out
    /// of session. Compiled only with `tbor-test-cmds`. See
    /// [`super::test_aes_gcm`].
    #[cfg(feature = "tbor-test-cmds")]
    pub(crate) const TEST_AES_GCM: u8 = 0xF0;
}

/// Validate that `sess_id` belongs to an active Crypto-Officer session.
fn validate_crypto_officer_active_session<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    sess_id: HsmSessId,
) -> HsmResult<()> {
    if sess_id.role() != SessionRole::CryptoOfficer {
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
fn validate_active_session<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
    sess_id: HsmSessId,
) -> HsmResult<()> {
    if !matches!(pal.session_state(io, sess_id), HsmSessionState::Active) {
        return Err(HsmError::SessionNotFound);
    }
    Ok(())
}

/// Resolve the vault id of the masking key associated with `scope`.
fn masking_key_id_for_scope<P: HsmPal>(
    pal: &P,
    io: &impl HsmIo,
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
    io: &impl HsmIo,
    scope: HsmKeyScope,
    sess_id: HsmSessId,
) -> HsmResult<&'p DmaBuf> {
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
/// On success returns a `&DmaBuf` view of the encoded response (lifetime
/// bound to the per-IO allocator).  On dispatch-level failure (unknown
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
pub(crate) struct DispatchResult<'p> {
    /// Encoded response slice (borrows `pal`'s per-IO allocator).
    pub(crate) resp: &'p DmaBuf,
    /// Slot id for the CQE; set only by `SessionOpenInit`.
    pub(crate) session_id: Option<u16>,
}

/// Dispatch takes the full request context (PAL, IO, buffers, opcode,
/// session ids, OOB pointer and undo log) because every handler is
/// invoked from here; bundling them into a struct would only move the
/// same fields behind one more indirection.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &mut DmaBuf,
    opcode: u8,
    sqe_session_id: u16,
    body_sess_id: Option<HsmSessId>,
    oob: Option<OobPtr>,
    undo: &mut UndoLog<'p>,
) -> HsmResult<DispatchResult<'p>> {
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
        let resp = pal.tbor_dispatch(io, opcode, req_buf).await?;
        return Ok(DispatchResult {
            resp,
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

    // `SessionOpenInit` reports its freshly allocated slot here; the other
    // arms are untouched so the response type stays `&DmaBuf`.
    let mut session_id: Option<u16> = None;

    let resp = match opcode {
        opcode::API_REV => api_rev::handle(pal, io, req_buf),
        opcode::SESSION_OPEN_INIT => {
            session_open_init::handle(pal, io, req_buf, undo, &mut session_id).await
        }
        opcode::SESSION_OPEN_FINISH => session_open_finish::handle(pal, io, req_buf, undo).await,
        opcode::SESSION_CLOSE => session_close::handle(pal, io, req_buf).await,
        opcode::PSK_CHANGE => psk_change::handle(pal, io, req_buf, undo).await,
        opcode::PART_INIT => part_init::handle(pal, io, req_buf, undo).await,
        opcode::PART_FINAL => part_final::handle(pal, io, req_buf, oob, undo).await,
        opcode::PART_INFO => part_info::handle(pal, io, req_buf),
        opcode::SD_SEALING_KEY_GEN => sd_sealing_key_gen::handle(pal, io, req_buf).await,
        opcode::SD_CREATE_REMOTE_BACKUP => {
            sd_create_remote_backup::handle(pal, io, req_buf, oob, undo).await
        }
        opcode::SD_RESEAL_REMOTE_BACKUP => {
            sd_reseal_remote_backup::handle(pal, io, req_buf, oob).await
        }
        opcode::SD_RESTORE_REMOTE_BACKUP => {
            sd_restore_remote_backup::handle(pal, io, req_buf, oob, undo).await
        }
        opcode::SD_RESTORE_LOCAL_BACKUP => {
            sd_restore_local_backup::handle(pal, io, req_buf, undo).await
        }
        opcode::SD_CREATE_PEER_BACKUP => sd_create_peer_backup::handle(pal, io, req_buf, oob).await,
        opcode::SD_RESTORE_PEER_BACKUP => {
            sd_restore_peer_backup::handle(pal, io, req_buf, oob, undo).await
        }
        opcode::KEY_REPORT => key_report::handle(pal, io, req_buf).await,
        opcode::HMAC_GENERATE_KEY => hmac_generate_key::handle(pal, io, req_buf).await,
        opcode::HMAC => hmac::handle(pal, io, req_buf).await,
        opcode::GET_UNWRAPPING_KEY => get_unwrapping_key::handle(pal, io, req_buf).await,
        opcode::UNWRAP_KEY => unwrap_key::handle(pal, io, req_buf, undo).await,
        opcode::AES_GENERATE_KEY => aes_generate_key::handle(pal, io, req_buf).await,
        opcode::AES_ENCRYPT_DECRYPT => aes_encrypt_decrypt::handle(pal, io, req_buf).await,
        opcode::ECC_GENERATE_KEY => ecc_generate_key::handle(pal, io, req_buf).await,
        opcode::ECC_SIGN => ecc_sign::handle(pal, io, req_buf).await,
        opcode::ECDH_DERIVE => ecdh_derive::handle(pal, io, req_buf).await,
        opcode::RSA_MOD_EXP => rsa_mod_exp::handle(pal, io, req_buf).await,
        opcode::HASH => hash::handle(pal, io, req_buf).await,
        opcode::HKDF_DERIVE => hkdf_derive::handle(pal, io, req_buf).await,
        opcode::CONCAT_KDF_DERIVE => concat_kdf_derive::handle(pal, io, req_buf).await,
        opcode::GET_CERT_CHAIN_INFO => get_cert_chain_info::handle(pal, io, req_buf).await,
        opcode::GET_CERTIFICATE => get_cert::handle(pal, io, req_buf).await,
        opcode::DARC_KEX_KEY_GEN => darc_kex_key_gen::handle(pal, io, req_buf).await,
        opcode::DARC_TMK_IMPORT => darc_tmk_import::handle(pal, io, req_buf, oob).await,
        opcode::DARC_KEY_UNWRAP => darc_key_unwrap::handle(pal, io, req_buf).await,
        opcode::DARC_TMK_GEN => darc_tmk_gen::handle(pal, io, req_buf).await,
        opcode::DARC_TMK_EXPORT => darc_tmk_export::handle(pal, io, req_buf, oob).await,
        opcode::DARC_KEY_WRAP => darc_key_wrap::handle(pal, io, req_buf).await,
        opcode::MLDSA_GENERATE_KEY => mldsa_generate_key::handle(pal, io, req_buf).await,
        opcode::MLDSA_SIGN => mldsa_sign::handle(pal, io, req_buf).await,
        opcode::MLDSA_VERIFY => mldsa_verify::handle(pal, io, req_buf).await,
        opcode::MLKEM_GENERATE_KEY => mlkem_generate_key::handle(pal, io, req_buf).await,
        opcode::MLKEM_ENCAPSULATE => mlkem_encapsulate::handle(pal, io, req_buf).await,
        opcode::MLKEM_DECAPSULATE => mlkem_decapsulate::handle(pal, io, req_buf).await,
        #[cfg(feature = "tbor-test-cmds")]
        opcode::TEST_AES_GCM => test_aes_gcm::handle(pal, io, req_buf).await,
        _ => Err(HsmError::UnsupportedCmd),
    }?;

    Ok(DispatchResult { resp, session_id })
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
    ) || is_test_opcode(opcode)
}

/// Returns `true` for the test-only opcodes compiled in with
/// `tbor-test-cmds`.
fn is_test_opcode(opcode: u8) -> bool {
    match opcode {
        #[cfg(feature = "tbor-test-cmds")]
        opcode::TEST_AES_GCM => true,
        _ => false,
    }
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
        // The test-only opcodes run out of session.
        #[cfg(feature = "tbor-test-cmds")]
        opcode::TEST_AES_GCM => false,
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
        // The test-only opcodes carry no session id.
        #[cfg(feature = "tbor-test-cmds")]
        opcode::TEST_AES_GCM => false,
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
fn psk_id_for_role(role: SessionRole) -> u8 {
    match role {
        SessionRole::CryptoOfficer => 0,
        SessionRole::CryptoUser => 1,
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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

    #[cfg(feature = "tbor-test-cmds")]
    #[test]
    fn test_aes_gcm_is_known_and_out_of_session() {
        assert!(is_known_opcode(opcode::TEST_AES_GCM));
        assert!(!is_in_session(opcode::TEST_AES_GCM));
        assert!(!needs_session_id_cross_check(opcode::TEST_AES_GCM));
    }

    #[cfg(not(feature = "tbor-test-cmds"))]
    #[test]
    fn test_opcodes_unknown_without_feature() {
        assert!(!is_known_opcode(0xF0));
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
        assert_eq!(psk_id_for_role(SessionRole::CryptoOfficer), 0);
        assert_eq!(psk_id_for_role(SessionRole::CryptoUser), 1);
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
