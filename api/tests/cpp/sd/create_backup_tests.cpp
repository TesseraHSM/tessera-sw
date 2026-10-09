// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// api-level `SdCreateRemoteBackup` round trip against the emulator.
//
// Provisions a partition whose policy names itself as the backup backing
// partition (`provision_sd_backing_co_session`), mints an SD sealing key,
// attests it via the masked-blob `KeyReport`, builds the receiver's
// three-chain attestation evidence, then calls
// `tsra_sd_create_remote_backup` and validates the three returned
// backups. This is a self-backup (sender == receiver): the partition seals
// to its own attested identity key.
//
// The whole file needs the two-phase TBOR HPKE handshake and a fully
// provisioned partition, which the mock backend does not implement, so it is
// excluded from the mock lane and runs on the emu and hardware backends.
#if !defined(TSRA_FEATURE_MOCK)

#include <array>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <tsra_api.h>
#include <vector>

#include "handle/part_list_handle.hpp"
#include "utils/sd_provision.hpp"
#include "utils/utils.hpp"

namespace
{
// Run the create-backup call, sizing the three output buffers via the
// probe/fill convention. The FFI validates each output buffer in sequence
// and reports the first that is too small, so a single len=0 probe only
// sizes the first buffer; loop until every buffer is large enough. Buffer
// validation runs before the domain is created, so a too-small buffer never
// consumes the one-shot command. Returns the final status and sizes the
// caller vectors to the bytes written on success.
tsra_status create_backup_fill(
    tsra_handle session,
    const tsra_sd_create_remote_backup_params *params,
    std::vector<uint8_t> &remote,
    std::vector<uint8_t> &local,
    std::vector<uint8_t> &mk
)
{
    tsra_buffer remote_buf{ nullptr, 0 };
    tsra_buffer local_buf{ nullptr, 0 };
    tsra_buffer mk_buf{ nullptr, 0 };
    tsra_status err = TSRA_STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        err = tsra_sd_create_remote_backup(session, params, &remote_buf, &local_buf, &mk_buf);
        if (err != TSRA_STATUS_BUFFER_TOO_SMALL)
        {
            break;
        }
        if (remote_buf.len > remote.size())
        {
            remote.resize(remote_buf.len);
        }
        if (local_buf.len > local.size())
        {
            local.resize(local_buf.len);
        }
        if (mk_buf.len > mk.size())
        {
            mk.resize(mk_buf.len);
        }
        remote_buf = { remote.data(), static_cast<uint32_t>(remote.size()) };
        local_buf = { local.data(), static_cast<uint32_t>(local.size()) };
        mk_buf = { mk.data(), static_cast<uint32_t>(mk.size()) };
    }
    if (err == TSRA_STATUS_SUCCESS)
    {
        remote.resize(remote_buf.len);
        local.resize(local_buf.len);
        mk.resize(mk_buf.len);
    }
    return err;
}
} // namespace

/// Test fixture for security-domain create-remote-backup
/// (`tsra_sd_create_remote_backup`).
class tsra_sd_create_backup_test : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Open and factory-reset a partition into a clean state. Records a
    // gtest failure and returns 0 on error; the returned handle must be
    // closed by the caller.
    static tsra_handle open_reset_partition(std::vector<tsra_char> &path)
    {
        tsra_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        tsra_handle part_handle = 0;
        auto err = tsra_part_open(&path_str, &part_handle, session_ex_test_api_rev());
        if (err != TSRA_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "tsra_part_open failed: " << err;
            return 0;
        }

        err = tsra_part_reset(part_handle);
        if (err != TSRA_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "tsra_part_reset failed: " << err;
            tsra_part_close(part_handle);
            return 0;
        }

        return part_handle;
    }

    // Open a Crypto-Officer security-domain session on an already-open
    // partition handle. Records a gtest failure and returns 0 on error;
    // the returned handle must be closed by the caller.
    static tsra_handle open_sd_session(tsra_handle part_handle)
    {
        tsra_handle sess_handle = 0;
        tsra_session_psk psk{ 0, nullptr };
        auto err =
            tsra_sess_ex_open(part_handle, &psk, TSRA_SESSION_EX_TYPE_AUTHENTICATED, &sess_handle);
        if (err != TSRA_STATUS_SUCCESS || sess_handle == 0)
        {
            ADD_FAILURE() << "tsra_sess_ex_open failed: " << err;
            return 0;
        }
        return sess_handle;
    }
};

// Happy path: creating a security domain on a partition that names itself
// as the backing partition returns three non-zero backups of the pinned
// wire lengths.
TEST_F(tsra_sd_create_backup_test, create_backup_roundtrip)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        SdBackingContext ctx = provision_sd_backing_co_session(part_handle);
        if (ctx.session == 0)
        {
            return; // provisioning recorded its own failure
        }
        auto sess_guard = scope_guard::make_scope_exit([&ctx] { tsra_sess_close(ctx.session); });

        SealingKeyMaterial sealing = sealing_key_and_report(ctx.session);
        ASSERT_EQ(sealing.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(sealing.report.empty());

        SdEvidenceHolder evidence = build_receiver_evidence(ctx, sealing.pub, sealing.report);

        tsra_buffer masked_buf{ sealing.masked.data(),
                                static_cast<uint32_t>(sealing.masked.size()) };
        tsra_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        tsra_sd_create_remote_backup_params params{
            &policy_buf,
            &masked_buf,
            evidence.receiver_chain(),
            &evidence.get(),
        };

        std::vector<uint8_t> pok_remote;
        std::vector<uint8_t> pok_local;
        std::vector<uint8_t> sd_mk;
        auto err = create_backup_fill(ctx.session, &params, pok_remote, pok_local, sd_mk);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        // Remote backup: HPKE-Auth seal of BKS3, 161 B, non-zero.
        ASSERT_EQ(pok_remote.size(), kPokRemoteBackupLen);
        ASSERT_TRUE(any_nonzero(pok_remote)) << "pok_remote_backup must not be all-zero";

        // Local backup: BKS3 masked under the partition-local key, 276 B,
        // non-zero.
        ASSERT_EQ(pok_local.size(), kPokLocalBackupLen);
        ASSERT_TRUE(any_nonzero(pok_local)) << "pok_local_backup must not be all-zero";

        // Masking-key backup: SDMK masked under the derived SDBMK, 260 B,
        // non-zero.
        ASSERT_EQ(sd_mk.size(), kSdMkBackupLen);
        ASSERT_TRUE(any_nonzero(sd_mk)) << "sd_mk_backup must not be all-zero";
    });
}

// Flag-clear / FFI allow-empty path: when the policy does not set
// `require_trusted_sa_key`, the receiver attestation evidence is optional.
// Supplying only the mandatory receiver certificate chain together with a
// fully-empty `tsra_sd_evidence` (zero-length cert chains and a null
// report) must still create the security domain. This drives the C decode
// (`SdEvidence::try_from_optional` / `unpack_cert_chain_allow_empty`) that
// the host-level Rust test `sd_create_remote_backup_roundtrip_empty_evidence`
// cannot reach because it calls the session method directly.
TEST_F(tsra_sd_create_backup_test, create_backup_empty_evidence_ffi)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        // Default backing policy leaves `require_trusted_sa_key` clear, so
        // the firmware ignores attestation evidence entirely.
        SdBackingContext ctx = provision_sd_backing_co_session(part_handle);
        if (ctx.session == 0)
        {
            return; // provisioning recorded its own failure
        }
        auto sess_guard = scope_guard::make_scope_exit([&ctx] { tsra_sess_close(ctx.session); });

        SealingKeyMaterial sealing = sealing_key_and_report(ctx.session);
        ASSERT_EQ(sealing.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(sealing.report.empty());

        // Build the holder only to mint the mandatory receiver certificate
        // chain (SATA-anchored, leaf = `RcvrPub`); its three attestation
        // chains and report are deliberately left unused.
        SdEvidenceHolder evidence = build_receiver_evidence(ctx, sealing.pub, sealing.report);

        // Fully-empty evidence: zero-initialization yields
        // {certs=nullptr, len=0} for every chain and report=nullptr, which
        // the FFI decodes through the allow-empty path.
        tsra_sd_evidence empty_evidence{};

        tsra_buffer masked_buf{ sealing.masked.data(),
                                static_cast<uint32_t>(sealing.masked.size()) };
        tsra_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        tsra_sd_create_remote_backup_params params{
            &policy_buf,
            &masked_buf,
            evidence.receiver_chain(),
            &empty_evidence,
        };

        std::vector<uint8_t> pok_remote;
        std::vector<uint8_t> pok_local;
        std::vector<uint8_t> sd_mk;
        auto err = create_backup_fill(ctx.session, &params, pok_remote, pok_local, sd_mk);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS);

        ASSERT_EQ(pok_remote.size(), kPokRemoteBackupLen);
        ASSERT_TRUE(any_nonzero(pok_remote)) << "pok_remote_backup must not be all-zero";
        ASSERT_EQ(pok_local.size(), kPokLocalBackupLen);
        ASSERT_TRUE(any_nonzero(pok_local)) << "pok_local_backup must not be all-zero";
        ASSERT_EQ(sd_mk.size(), kSdMkBackupLen);
        ASSERT_TRUE(any_nonzero(sd_mk)) << "sd_mk_backup must not be all-zero";
    });
}

// One-shot: creating a security domain is a once-per-partition operation,
// so a second create on the now-initialized partition is rejected by the
// firmware with `SD_ALREADY_INITIALIZED`.
TEST_F(tsra_sd_create_backup_test, create_backup_is_one_shot)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        SdBackingContext ctx = provision_sd_backing_co_session(part_handle);
        if (ctx.session == 0)
        {
            return;
        }
        auto sess_guard = scope_guard::make_scope_exit([&ctx] { tsra_sess_close(ctx.session); });

        SealingKeyMaterial sealing = sealing_key_and_report(ctx.session);
        ASSERT_EQ(sealing.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(sealing.report.empty());

        SdEvidenceHolder evidence = build_receiver_evidence(ctx, sealing.pub, sealing.report);

        tsra_buffer masked_buf{ sealing.masked.data(),
                                static_cast<uint32_t>(sealing.masked.size()) };
        tsra_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        tsra_sd_create_remote_backup_params params{
            &policy_buf,
            &masked_buf,
            evidence.receiver_chain(),
            &evidence.get(),
        };

        // First create succeeds and sizes the output vectors.
        std::vector<uint8_t> pok_remote;
        std::vector<uint8_t> pok_local;
        std::vector<uint8_t> sd_mk;
        ASSERT_EQ(
            create_backup_fill(ctx.session, &params, pok_remote, pok_local, sd_mk),
            TSRA_STATUS_SUCCESS
        );

        // A second create on the same (now initialized) partition must
        // fail. The buffers are already large enough, so the request clears
        // validation and reaches the firmware's one-shot guard.
        tsra_buffer remote_buf{ pok_remote.data(), static_cast<uint32_t>(pok_remote.size()) };
        tsra_buffer local_buf{ pok_local.data(), static_cast<uint32_t>(pok_local.size()) };
        tsra_buffer mk_buf{ sd_mk.data(), static_cast<uint32_t>(sd_mk.size()) };
        auto second =
            tsra_sd_create_remote_backup(ctx.session, &params, &remote_buf, &local_buf, &mk_buf);
        ASSERT_EQ(second, TSRA_STATUS_SD_ALREADY_INITIALIZED);
    });
}

// A NULL params pointer is rejected with `INVALID_ARGUMENT` after the
// session resolves and before the domain is created.
TEST_F(tsra_sd_create_backup_test, create_backup_null_params)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        tsra_handle sess_handle = open_sd_session(part_handle);
        if (sess_handle == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&sess_handle] { tsra_sess_close(sess_handle); });

        tsra_buffer out{ nullptr, 0 };
        auto err = tsra_sd_create_remote_backup(sess_handle, nullptr, &out, &out, &out);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

// Aliasing: passing the same `tsra_buffer` for two of the three output
// pointers is rejected with `INVALID_ARGUMENT` (it would otherwise form two
// aliasing `&mut` references at the FFI boundary), before the domain is
// created.
TEST_F(tsra_sd_create_backup_test, create_backup_rejects_aliased_output_buffers)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        SdBackingContext ctx = provision_sd_backing_co_session(part_handle);
        if (ctx.session == 0)
        {
            return;
        }
        auto sess_guard = scope_guard::make_scope_exit([&ctx] { tsra_sess_close(ctx.session); });

        SealingKeyMaterial sealing = sealing_key_and_report(ctx.session);
        ASSERT_EQ(sealing.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(sealing.report.empty());

        SdEvidenceHolder evidence = build_receiver_evidence(ctx, sealing.pub, sealing.report);

        tsra_buffer masked_buf{ sealing.masked.data(),
                                static_cast<uint32_t>(sealing.masked.size()) };
        tsra_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        tsra_sd_create_remote_backup_params params{
            &policy_buf,
            &masked_buf,
            evidence.receiver_chain(),
            &evidence.get(),
        };

        // Pass the same output buffer for the remote and local backups.
        std::vector<uint8_t> shared(kPokLocalBackupLen);
        tsra_buffer shared_buf{ shared.data(), static_cast<uint32_t>(shared.size()) };
        std::vector<uint8_t> mk(kSdMkBackupLen);
        tsra_buffer mk_buf{ mk.data(), static_cast<uint32_t>(mk.size()) };
        auto err =
            tsra_sd_create_remote_backup(ctx.session, &params, &shared_buf, &shared_buf, &mk_buf);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

#endif // !defined(TSRA_FEATURE_MOCK)
