// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <tsra_api.h>

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

// Pinned TBOR masked-blob wire lengths, mirroring the host / firmware
// `tsra_ddi_tbor_types` constants (which are not exposed in the C
// header). Each masked blob is an AEAD-GCM-256 envelope:
// `header(8) + iv(16) + MaskedKeyMetadata aad(192) + padded plaintext + tag(16)`.
inline constexpr uint32_t kMaskedSealingKeyLen = 280; ///< sealing priv scalar (48 B)
inline constexpr uint32_t kMaskedSdLen = 280;         ///< masked BKS3 (48 B)
inline constexpr uint32_t kPokLocalBackupLen = 280;   ///< device-local BKS3 backup (48 B)
inline constexpr uint32_t kSdMkBackupLen = 264;       ///< masked SDMK / local_mk (32 B)
/// Remote partition-owner-key backup: an HPKE-Auth seal (`enc(97) + ct(64)`).
inline constexpr uint32_t kPokRemoteBackupLen = 161;

// Security-domain provisioning helper for the sealing round-trip test.
//
// `SdSealingKeyGen` needs a partition in the `Initialized` state on a CO
// session, reached via the full provisioning flow (rotate CO PSK ->
// `PartInit` -> POTA-anchored PTA chain -> `PartFinal`) — the same sequence
// a real C consumer performs, except the consumer brings its own PKI chain.
//
// The chain is built with the platform host crypto (OpenSSL on Linux,
// BCrypt on Windows), no HSM session. Excluded from the mock backend; runs
// on the emu and hardware backends.
#if !defined(TSRA_FEATURE_MOCK)

/// Provision a freshly-reset partition's security domain and return a live,
/// provisioned Crypto-Officer session handle (`Initialized` state):
/// open CO under the default PSK, rotate it, reopen, `PartInit`, build a
/// POTA-anchored root -> PTA chain from the CSR, then `PartFinal`.
///
/// Records a gtest failure and returns 0 on error. The caller owns the
/// returned handle and must close it with `tsra_sess_close`.
///
/// @param part_handle An opened, factory-reset partition handle.
/// @return A provisioned CO session handle, or 0 on failure.
tsra_handle provision_sd_co_session(tsra_handle part_handle);

/// Opaque host CA key (defined in `sd_provision.cpp`). Exposed only as a
/// `std::shared_ptr` handle so a caller can keep the SATA anchor alive
/// across the evidence-building step without seeing the definition.
class CaKey;

/// A provisioned backing-partition security-domain context: the live CO
/// session plus the exact policy image, partition-identity public key, and
/// SATA anchor key that the create-backup call and its evidence depend on.
struct SdBackingContext
{
    /// Provisioned CO session handle (`Initialized`); 0 on failure.
    tsra_handle session = 0;
    /// Exact 484-byte backing-partition policy image.
    std::vector<uint8_t> policy;
    /// Raw P-384 partition-identity public key (`X ‖ Y`, 96 B).
    std::vector<uint8_t> pid_pub;
    /// SATA anchor key that roots the partition-owner evidence chain.
    std::shared_ptr<CaKey> sata_key;
    /// POTA anchor key that roots the CSR -> PTA chain. Retained so a
    /// restore target can re-provision under the same policy.
    std::shared_ptr<CaKey> pota_key;
    /// Device-local master-key (`local_mk`) backup emitted by `PartFinal`.
    std::vector<uint8_t> local_mk_backup;
};

/// Provision `part_handle` with a backing-partition policy that names this
/// partition (via its `PartInfo` PID / raw public key) as the backup
/// backing partition, anchored to a freshly-generated internal SATA key.
///
/// Records a gtest failure and returns a default `SdBackingContext`
/// (`session == 0`) on error. The caller owns `session` and must close it
/// with `tsra_sess_close`. `allow_peer_cloning` sets that policy flag
/// (default `true`); clear it to exercise the peer-cloning policy gate.
SdBackingContext provision_sd_backing_co_session(
    tsra_handle part_handle,
    bool allow_peer_cloning = true
);

/// Re-provision `part_handle` — the same physical backing partition after a
/// simulated reboot (`tsra_part_reset`) — as a restore target, reusing
/// `prev`'s policy and SATA/POTA anchors and supplying
/// `prev.local_mk_backup` to `PartFinal` for device-local master-key
/// continuity. This reproduces the receiver (device-2) side of a restore
/// round trip.
///
/// Records a gtest failure and returns a default `SdBackingContext`
/// (`session == 0`) on error. The caller owns `session` and must close it
/// with `tsra_sess_close`.
SdBackingContext provision_sd_restore_target(tsra_handle part_handle, const SdBackingContext &prev);

/// A minted SD sealing key: its masked private-key blob and a COSE_Sign1
/// `KeyReport` attesting it.
struct SealingKeyMaterial
{
    /// Masked sealing-key blob (280 B).
    std::vector<uint8_t> masked;
    /// Raw P-384 sealing-key public key (`X ‖ Y`, 96 B): the recipient
    /// public key (`RcvrPub`) the remote backup is sealed to.
    std::vector<uint8_t> pub;
    /// COSE_Sign1 `KeyReport` DER bytes.
    std::vector<uint8_t> report;
};

/// Mint an SD sealing key on `session` and return its 280-byte masked blob
/// plus a `KeyReport` built over 128 zero report-data bytes. Records a
/// gtest failure and returns empty vectors on error.
SealingKeyMaterial sealing_key_and_report(tsra_handle session);

/// Owns the DER bytes and `tsra_buffer` arrays backing one party's SD
/// attestation evidence and exposes a wired-up `tsra_sd_evidence` that
/// points into them. The holder must outlive the create-backup call.
///
/// Copies are forbidden (the internal `tsra_buffer` / `tsra_sd_evidence`
/// pointers are self-referential); moves re-point them at the moved-to
/// storage.
class SdEvidenceHolder
{
  public:
    SdEvidenceHolder() = default;
    SdEvidenceHolder(const SdEvidenceHolder &) = delete;
    SdEvidenceHolder &operator=(const SdEvidenceHolder &) = delete;
    SdEvidenceHolder(SdEvidenceHolder &&other) noexcept
    {
        *this = std::move(other);
    }
    SdEvidenceHolder &operator=(SdEvidenceHolder &&other) noexcept
    {
        mfgr_root_ = std::move(other.mfgr_root_);
        mfgr_leaf_ = std::move(other.mfgr_leaf_);
        owner_root_ = std::move(other.owner_root_);
        owner_leaf_ = std::move(other.owner_leaf_);
        po_root_ = std::move(other.po_root_);
        po_leaf_ = std::move(other.po_leaf_);
        rcvr_root_ = std::move(other.rcvr_root_);
        rcvr_leaf_ = std::move(other.rcvr_leaf_);
        report_ = std::move(other.report_);
        wire();
        return *this;
    }

    /// The wired-up evidence view; valid for this holder's lifetime.
    const tsra_sd_evidence &get() const
    {
        return ev_;
    }

    /// The receiver key certificate chain (spec `RcvrCertChain`); anchored
    /// to the policy SATA key, its leaf certifies `RcvrPub`. Valid for this
    /// holder's lifetime.
    const tsra_sd_cert_chain &receiver_chain() const
    {
        return rcvr_chain_;
    }

  private:
    friend SdEvidenceHolder build_receiver_evidence(
        const SdBackingContext &ctx,
        const std::vector<uint8_t> &rcvr_pub,
        const std::vector<uint8_t> &report
    );

    /// Re-point the `tsra_buffer` arrays and `tsra_sd_evidence` at the
    /// currently-held vectors. Called after population and every move.
    void wire();

    std::vector<uint8_t> mfgr_root_;
    std::vector<uint8_t> mfgr_leaf_;
    std::vector<uint8_t> owner_root_;
    std::vector<uint8_t> owner_leaf_;
    std::vector<uint8_t> po_root_;
    std::vector<uint8_t> po_leaf_;
    std::vector<uint8_t> rcvr_root_;
    std::vector<uint8_t> rcvr_leaf_;
    std::vector<uint8_t> report_;
    tsra_buffer mfgr_bufs_[2]{};
    tsra_buffer owner_bufs_[2]{};
    tsra_buffer po_bufs_[2]{};
    tsra_buffer rcvr_bufs_[2]{};
    tsra_buffer report_buf_{};
    tsra_sd_evidence ev_{};
    tsra_sd_cert_chain rcvr_chain_{};
};

/// Build the receiver's three-chain SD attestation evidence and the
/// receiver key certificate chain for a security-domain backup. The
/// manufacturer and owner chains are rooted at fresh CAs and the
/// partition-owner chain at `ctx.sata_key`; every evidence leaf certifies
/// `ctx.pid_pub` (the report signer). The receiver key certificate chain
/// (spec `RcvrCertChain`) is rooted at the same `ctx.sata_key`, and its
/// leaf certifies `rcvr_pub` — the receiver sealing key `RcvrPub` the
/// remote backup is sealed to, and the key the report attests. Records a
/// gtest failure and returns an empty holder on error.
SdEvidenceHolder build_receiver_evidence(
    const SdBackingContext &ctx,
    const std::vector<uint8_t> &rcvr_pub,
    const std::vector<uint8_t> &report
);

// ── DARC key-transfer provisioning ───────────────────────────────────────────

/// A partition whose security domain is initialized and whose bound policy
/// carries **both** a DATA anchor (validating `tsra_darc_tmk_export`
/// target chains) and a POTA anchor (validating `tsra_darc_tmk_import`
/// sender chains), plus the host CA keys backing those anchors. The C mirror
/// of the Rust `darc_sd_initialized_session` fixture.
struct DarcReadyContext
{
    /// Provisioned CO security-domain (V2) session; 0 on failure.
    tsra_handle session = 0;
    /// Exact 584-byte policy image bound at `PartInit` (DATA slot present).
    std::vector<uint8_t> policy;
    /// Policy DATA CA — anchors the `tsra_darc_tmk_export` target chain.
    std::shared_ptr<CaKey> data_key;
    /// Policy POTA CA — anchors the `tsra_darc_tmk_import` sender chain.
    std::shared_ptr<CaKey> pota_key;
};

/// Provision a freshly-reset partition for the DARC key-transfer commands:
/// rotate the CO PSK, bind a DATA+POTA-anchored 584-byte policy at
/// `PartInit`, finalize with a POTA-anchored PTA chain, then self-initialize
/// the security domain (self `SdCreateRemoteBackup`) so a Security-Domain
/// Master Key exists. Returns a live CO session plus the DATA/POTA anchor
/// keys and the exact bound policy.
///
/// Records a gtest failure and returns a default context (`session == 0`) on
/// error. The caller owns `session` and must close it with
/// `tsra_sess_close`.
///
/// @param part_handle An opened, factory-reset partition handle.
DarcReadyContext provision_darc_session(tsra_handle part_handle);

/// Generate a standalone host CA key (for negative tests that anchor a chain
/// to an unrelated root). Returns nullptr and records a gtest failure on
/// error.
std::shared_ptr<CaKey> darc_generate_ca();

/// Owns the DER bytes and `tsra_buffer` array backing a two-cert
/// (`root -> leaf`) DARC certificate chain and exposes a wired-up
/// `tsra_darc_cert_chain` pointing into them. The holder must outlive any
/// call it is passed to.
///
/// Copies are forbidden (the internal pointers are self-referential); moves
/// re-point them at the moved-to storage.
class DarcCertChainHolder
{
  public:
    DarcCertChainHolder() = default;
    DarcCertChainHolder(const DarcCertChainHolder &) = delete;
    DarcCertChainHolder &operator=(const DarcCertChainHolder &) = delete;
    DarcCertChainHolder(DarcCertChainHolder &&other) noexcept
    {
        *this = std::move(other);
    }
    DarcCertChainHolder &operator=(DarcCertChainHolder &&other) noexcept
    {
        root_ = std::move(other.root_);
        leaf_ = std::move(other.leaf_);
        wire();
        return *this;
    }

    /// The wired-up chain view; valid for this holder's lifetime.
    const tsra_darc_cert_chain &get() const
    {
        return chain_;
    }

  private:
    friend DarcCertChainHolder darc_make_chain(
        const std::shared_ptr<CaKey> &ca,
        const std::vector<uint8_t> &leaf_pub_raw
    );

    /// Re-point the `tsra_buffer` array and `tsra_darc_cert_chain` at the
    /// currently-held DER vectors. Called after population and every move.
    void wire();

    std::vector<uint8_t> root_;
    std::vector<uint8_t> leaf_;
    tsra_buffer bufs_[2]{};
    tsra_darc_cert_chain chain_{};
};

/// Build a `root -> leaf` DER certificate chain: a self-signed root CA
/// (`ca`) certifying an end-entity leaf carrying `leaf_pub_raw` (raw P-384
/// `X ‖ Y`, big-endian, 96 B). Anchor to the policy DATA/POTA CA to pass the
/// on-device anchor check, or to an unrelated CA to fail it. Records a gtest
/// failure and returns an empty holder on error.
DarcCertChainHolder darc_make_chain(
    const std::shared_ptr<CaKey> &ca,
    const std::vector<uint8_t> &leaf_pub_raw
);

#endif // !defined(TSRA_FEATURE_MOCK)
