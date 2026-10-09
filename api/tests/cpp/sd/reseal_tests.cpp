// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// api-level `SdResealRemoteBackup` round trip against the emulator.
//
// Self-reseal on one partition: mint receiver / sender / destination SD
// sealing keys, use `tsra_sd_create_remote_backup` to produce a
// real source backup (BKS3 sealed to the receiver by the sender), then
// reseal it to the destination via
// `tsra_sd_reseal_remote_backup`. A successful reseal is itself
// the correctness check: the HPKE open only succeeds if the receiver key
// and the attested sender key match those that sealed the source.
//
// Like the create-backup tests, this needs the two-phase TBOR HPKE
// handshake and a fully provisioned partition, which the mock backend does
// not implement, so it is excluded from the mock lane and runs on the emu
// and hardware backends.
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
// Create a real source backup: a fresh BKS3 sealed to the receiver's
// attested public key (`receiver_report`) by `masked_sender`. Returns the
// 161-byte remote backup, or an empty vector on failure (recording a gtest
// failure). Sizes the three output buffers via the probe/fill convention.
std::vector<uint8_t> create_source_backup(
    SdBackingContext &ctx,
    std::vector<uint8_t> &masked_sender,
    const std::vector<uint8_t> &receiver_pub,
    const std::vector<uint8_t> &receiver_report
)
{
    SdEvidenceHolder receiver = build_receiver_evidence(ctx, receiver_pub, receiver_report);

    tsra_buffer masked_buf{ masked_sender.data(), static_cast<uint32_t>(masked_sender.size()) };
    tsra_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
    tsra_sd_create_remote_backup_params params{
        &policy_buf,
        &masked_buf,
        receiver.receiver_chain(),
        &receiver.get(),
    };

    std::vector<uint8_t> remote;
    std::vector<uint8_t> local;
    std::vector<uint8_t> mk;
    tsra_buffer remote_buf{ nullptr, 0 };
    tsra_buffer local_buf{ nullptr, 0 };
    tsra_buffer mk_buf{ nullptr, 0 };
    tsra_status err = TSRA_STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        err = tsra_sd_create_remote_backup(ctx.session, &params, &remote_buf, &local_buf, &mk_buf);
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
    if (err != TSRA_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "create source backup failed: " << err;
        return {};
    }
    remote.resize(remote_buf.len);
    return remote;
}

// Run the reseal call, sizing the single output buffer via the probe/fill
// convention. The FFI validates the output buffer before resealing, so a
// too-small buffer never performs the reseal. Returns the final status and
// sizes `dst` to the bytes written on success.
tsra_status reseal_fill(
    tsra_handle session,
    const tsra_sd_reseal_remote_backup_params *params,
    std::vector<uint8_t> &dst
)
{
    tsra_buffer dst_buf{ nullptr, 0 };
    tsra_status err = TSRA_STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        err = tsra_sd_reseal_remote_backup(session, params, &dst_buf);
        if (err != TSRA_STATUS_BUFFER_TOO_SMALL)
        {
            break;
        }
        if (dst_buf.len > dst.size())
        {
            dst.resize(dst_buf.len);
        }
        dst_buf = { dst.data(), static_cast<uint32_t>(dst.size()) };
    }
    if (err == TSRA_STATUS_SUCCESS)
    {
        dst.resize(dst_buf.len);
    }
    return err;
}
} // namespace

/// Test fixture for security-domain reseal-remote-backup
/// (`tsra_sd_reseal_remote_backup`).
class tsra_sd_reseal_backup_test : public ::testing::Test
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
};

// Happy path: resealing a real source backup yields a fresh 161-byte,
// non-zero backup distinct from the source ciphertext.
TEST_F(tsra_sd_reseal_backup_test, reseal_backup_roundtrip)
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

        // Receiver (unseals the source), sender (sealed the source), and
        // destination (the reseal target) SD sealing keys, each attested.
        SealingKeyMaterial rcvr = sealing_key_and_report(ctx.session);
        SealingKeyMaterial sndr = sealing_key_and_report(ctx.session);
        SealingKeyMaterial dst = sealing_key_and_report(ctx.session);
        ASSERT_EQ(rcvr.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(rcvr.report.empty());
        ASSERT_FALSE(sndr.report.empty());
        ASSERT_FALSE(dst.report.empty());

        std::vector<uint8_t> src_backup =
            create_source_backup(ctx, sndr.masked, rcvr.pub, rcvr.report);
        ASSERT_EQ(src_backup.size(), kPokRemoteBackupLen);

        // Reseal: open with the receiver key (auth = sender), reseal to the
        // destination receiver.
        SdEvidenceHolder src_ev = build_receiver_evidence(ctx, sndr.pub, sndr.report);
        SdEvidenceHolder dst_ev = build_receiver_evidence(ctx, dst.pub, dst.report);

        tsra_buffer masked_buf{ rcvr.masked.data(), static_cast<uint32_t>(rcvr.masked.size()) };
        tsra_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        tsra_buffer src_buf{ src_backup.data(), static_cast<uint32_t>(src_backup.size()) };
        tsra_sd_reseal_remote_backup_params params{
            &policy_buf, &masked_buf, &src_ev.get(), &dst_ev.get(), &src_buf,
        };

        std::vector<uint8_t> dst_backup;
        ASSERT_EQ(reseal_fill(ctx.session, &params, dst_backup), TSRA_STATUS_SUCCESS);

        // A successful HPKE open -> seal yields a 161-byte, non-zero backup.
        ASSERT_EQ(dst_backup.size(), kPokRemoteBackupLen);
        ASSERT_TRUE(any_nonzero(dst_backup)) << "dst_remote_backup must not be all-zero";
        // The resealed backup is a fresh HPKE encapsulation, not the source.
        ASSERT_NE(dst_backup, src_backup)
            << "reseal must produce a fresh encapsulation, not echo the source";

        tsra_sd_evidence src_without_owner = src_ev.get();
        tsra_sd_evidence dst_without_owner = dst_ev.get();
        src_without_owner.owner_cert_chain = { nullptr, 0 };
        dst_without_owner.owner_cert_chain = { nullptr, 0 };
        params.src_evidence = &src_without_owner;
        params.dest_evidence = &dst_without_owner;
        ASSERT_EQ(reseal_fill(ctx.session, &params, dst_backup), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(dst_backup.size(), kPokRemoteBackupLen);

        src_without_owner.mfgr_cert_chain = { nullptr, 0 };
        ASSERT_EQ(reseal_fill(ctx.session, &params, dst_backup), TSRA_STATUS_INVALID_ARGUMENT);
        src_without_owner.mfgr_cert_chain = src_ev.get().mfgr_cert_chain;
        dst_without_owner.part_owner_cert_chain = { nullptr, 0 };
        ASSERT_EQ(reseal_fill(ctx.session, &params, dst_backup), TSRA_STATUS_INVALID_ARGUMENT);
    });
}

// Re-randomization: two reseals of the same source produce distinct
// ciphertexts (a fresh HPKE ephemeral each call).
TEST_F(tsra_sd_reseal_backup_test, reseal_backup_rerandomizes)
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

        SealingKeyMaterial rcvr = sealing_key_and_report(ctx.session);
        SealingKeyMaterial sndr = sealing_key_and_report(ctx.session);
        SealingKeyMaterial dst = sealing_key_and_report(ctx.session);
        ASSERT_FALSE(rcvr.report.empty());
        ASSERT_FALSE(sndr.report.empty());
        ASSERT_FALSE(dst.report.empty());

        std::vector<uint8_t> src_backup =
            create_source_backup(ctx, sndr.masked, rcvr.pub, rcvr.report);
        ASSERT_EQ(src_backup.size(), kPokRemoteBackupLen);

        SdEvidenceHolder src_ev = build_receiver_evidence(ctx, sndr.pub, sndr.report);
        SdEvidenceHolder dst_ev = build_receiver_evidence(ctx, dst.pub, dst.report);

        tsra_buffer masked_buf{ rcvr.masked.data(), static_cast<uint32_t>(rcvr.masked.size()) };
        tsra_buffer policy_buf{ ctx.policy.data(), static_cast<uint32_t>(ctx.policy.size()) };
        tsra_buffer src_buf{ src_backup.data(), static_cast<uint32_t>(src_backup.size()) };
        tsra_sd_reseal_remote_backup_params params{
            &policy_buf, &masked_buf, &src_ev.get(), &dst_ev.get(), &src_buf,
        };

        std::vector<uint8_t> first;
        std::vector<uint8_t> second;
        ASSERT_EQ(reseal_fill(ctx.session, &params, first), TSRA_STATUS_SUCCESS);
        ASSERT_EQ(reseal_fill(ctx.session, &params, second), TSRA_STATUS_SUCCESS);
        ASSERT_NE(first, second) << "each reseal must re-randomize the HPKE encapsulation";
    });
}

// A NULL params pointer is rejected with `INVALID_ARGUMENT` after the
// session resolves and before the reseal is performed.
TEST_F(tsra_sd_reseal_backup_test, reseal_backup_null_params)
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

        tsra_buffer out{ nullptr, 0 };
        auto err = tsra_sd_reseal_remote_backup(ctx.session, nullptr, &out);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

#endif // !defined(TSRA_FEATURE_MOCK)
