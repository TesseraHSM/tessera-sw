// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// api-level `SdRestoreLocalBackup` round trip against the emulator.
//
// Self-backup "reboot" flow on one physical partition: device 1 provisions a
// backing partition, creates the security domain (capturing its device-local
// `pok_local_backup` / `sd_mk_backup` and the `local_mk_backup` from
// `PartFinal`); the same partition is factory-reset (a simulated reboot) and
// re-provisioned as a restore target — reusing the policy and SATA/POTA
// anchors and supplying the captured `local_mk_backup` so `PartLocalMK` is
// restored — and the security domain is restored from the device-local
// backups via `tsra_sd_restore_local_backup`. Unlike the
// remote/peer restores, this carries no attestation evidence.
//
// Like the create/reseal/restore tests this needs the two-phase TBOR HPKE
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
// Create the security domain, capturing the 276-byte device-local backup and
// the 260-byte masking-key backup that RestoreLocalBackup consumes. Sizes the
// three output buffers via the probe/fill convention. Records a gtest failure
// and returns false on error.
bool create_sd_capture(
    tsra_handle session,
    std::vector<uint8_t> &masked,
    const tsra_sd_cert_chain &receiver_chain,

    const tsra_sd_evidence &receiver,
    const std::vector<uint8_t> &policy,
    std::vector<uint8_t> &out_local,
    std::vector<uint8_t> &out_mk
)
{
    tsra_buffer masked_buf{ masked.data(), static_cast<uint32_t>(masked.size()) };
    tsra_buffer policy_buf{ const_cast<uint8_t *>(policy.data()),
                            static_cast<uint32_t>(policy.size()) };
    tsra_sd_create_remote_backup_params params{
        &policy_buf,
        &masked_buf,
        receiver_chain,
        &receiver,
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
        err = tsra_sd_create_remote_backup(session, &params, &remote_buf, &local_buf, &mk_buf);
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
        ADD_FAILURE() << "create remote backup failed: " << err;
        return false;
    }
    local.resize(local_buf.len);
    mk.resize(mk_buf.len);
    out_local = std::move(local);
    out_mk = std::move(mk);
    return true;
}

// Run the restore-local call, sizing both output buffers via the probe/fill
// convention. The FFI validates the output buffers before restoring, so a
// too-small buffer never performs the restore. Returns the final status and,
// on success, sizes `pok_local` / `sd_mk` to the bytes written.
tsra_status restore_local_fill(
    tsra_handle session,
    const tsra_sd_restore_local_backup_params *params,
    std::vector<uint8_t> &pok_local,
    std::vector<uint8_t> &sd_mk
)
{
    tsra_buffer pok_buf{ nullptr, 0 };
    tsra_buffer mk_buf{ nullptr, 0 };
    tsra_status err = TSRA_STATUS_BUFFER_TOO_SMALL;
    for (int attempt = 0; attempt < 4; ++attempt)
    {
        err = tsra_sd_restore_local_backup(session, params, &pok_buf, &mk_buf);
        if (err != TSRA_STATUS_BUFFER_TOO_SMALL)
        {
            break;
        }
        if (pok_buf.len > pok_local.size())
        {
            pok_local.resize(pok_buf.len);
        }
        if (mk_buf.len > sd_mk.size())
        {
            sd_mk.resize(mk_buf.len);
        }
        pok_buf = { pok_local.data(), static_cast<uint32_t>(pok_local.size()) };
        mk_buf = { sd_mk.data(), static_cast<uint32_t>(sd_mk.size()) };
    }
    if (err == TSRA_STATUS_SUCCESS)
    {
        pok_local.resize(pok_buf.len);
        sd_mk.resize(mk_buf.len);
    }
    return err;
}
} // namespace

/// Test fixture for security-domain restore-local-backup
/// (`tsra_sd_restore_local_backup`).
class tsra_sd_restore_local_backup_test : public ::testing::Test
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

// Happy path: create the security domain on one incarnation, then restore it
// from its device-local backups on a rebooted (factory-reset,
// re-provisioned) incarnation of the same partition; the restore returns
// non-zero refreshed device-local backups of the pinned lengths.
TEST_F(tsra_sd_restore_local_backup_test, restore_local_backup_roundtrip)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        // Device 1: provision and create the SD, capturing the device-local
        // backups the local restore consumes.
        SdBackingContext dev1 = provision_sd_backing_co_session(part_handle);
        if (dev1.session == 0)
        {
            return; // provisioning recorded its own failure
        }
        // Safety net for an early ASSERT exit; the happy path closes the
        // session explicitly before the reboot (zeroing the handle), which
        // makes this guard a no-op.
        auto dev1_guard = scope_guard::make_scope_exit([&dev1] {
            if (dev1.session != 0)
            {
                tsra_sess_close(dev1.session);
            }
        });

        SealingKeyMaterial key = sealing_key_and_report(dev1.session);
        ASSERT_EQ(key.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(key.report.empty());

        SdEvidenceHolder evidence = build_receiver_evidence(dev1, key.pub, key.report);

        std::vector<uint8_t> local_backup;
        std::vector<uint8_t> sd_mk_backup;
        ASSERT_TRUE(create_sd_capture(
            dev1.session,
            key.masked,
            evidence.receiver_chain(),
            evidence.get(),
            dev1.policy,
            local_backup,
            sd_mk_backup
        ));
        ASSERT_EQ(local_backup.size(), kMaskedSdLen);
        ASSERT_EQ(sd_mk_backup.size(), kSdMkBackupLen);

        // Close device 1's session before the reboot.
        tsra_sess_close(dev1.session);
        dev1.session = 0;

        // Device 2 (reboot): factory-reset the same partition and
        // re-provision it as a restore target, reusing device 1's policy
        // and anchors and its captured local_mk backup.
        auto err = tsra_part_reset(part_handle);
        ASSERT_EQ(err, TSRA_STATUS_SUCCESS) << "reboot reset failed";
        SdBackingContext dev2 = provision_sd_restore_target(part_handle, dev1);
        if (dev2.session == 0)
        {
            return; // provisioning recorded its own failure
        }
        auto sess_guard = scope_guard::make_scope_exit([&dev2] { tsra_sess_close(dev2.session); });

        // Restore the security domain from device 1's device-local backups.
        tsra_buffer local_buf{ local_backup.data(), static_cast<uint32_t>(local_backup.size()) };
        tsra_buffer mk_in_buf{ sd_mk_backup.data(), static_cast<uint32_t>(sd_mk_backup.size()) };
        tsra_sd_restore_local_backup_params params{
            &local_buf,
            &mk_in_buf,
        };

        std::vector<uint8_t> pok_local;
        std::vector<uint8_t> sd_mk;
        ASSERT_EQ(restore_local_fill(dev2.session, &params, pok_local, sd_mk), TSRA_STATUS_SUCCESS);

        // Refreshed device-local backups: 276-byte local pok backup and
        // 260-byte masking-key backup, both non-zero.
        ASSERT_EQ(pok_local.size(), kMaskedSdLen);
        ASSERT_TRUE(any_nonzero(pok_local)) << "pok_local_backup must not be all-zero";
        ASSERT_EQ(sd_mk.size(), kSdMkBackupLen);
        ASSERT_TRUE(any_nonzero(sd_mk)) << "sd_mk_backup must not be all-zero";
    });
}

// A NULL params pointer is rejected with `INVALID_ARGUMENT` after the
// session resolves and before the restore is performed.
TEST_F(tsra_sd_restore_local_backup_test, restore_local_backup_null_params)
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

        tsra_buffer pok_local{ nullptr, 0 };
        tsra_buffer sd_mk{ nullptr, 0 };
        auto err = tsra_sd_restore_local_backup(ctx.session, nullptr, &pok_local, &sd_mk);
        ASSERT_EQ(err, TSRA_STATUS_INVALID_ARGUMENT);
    });
}

// One-shot: an incarnation that just created its security domain is already
// SD-initialized, so a local restore on that same incarnation is rejected by
// the firmware's one-shot gate.
TEST_F(tsra_sd_restore_local_backup_test, restore_local_backup_is_one_shot)
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

        SealingKeyMaterial key = sealing_key_and_report(ctx.session);
        ASSERT_EQ(key.masked.size(), kMaskedSealingKeyLen);
        ASSERT_FALSE(key.report.empty());
        SdEvidenceHolder evidence = build_receiver_evidence(ctx, key.pub, key.report);

        // Create the SD (initializing this incarnation), capturing the
        // device-local backups the restore would consume.
        std::vector<uint8_t> local_backup;
        std::vector<uint8_t> sd_mk_backup;
        ASSERT_TRUE(create_sd_capture(
            ctx.session,
            key.masked,
            evidence.receiver_chain(),
            evidence.get(),
            ctx.policy,
            local_backup,
            sd_mk_backup
        ));

        // Restore on the same already-initialized incarnation is rejected.
        tsra_buffer local_buf{ local_backup.data(), static_cast<uint32_t>(local_backup.size()) };
        tsra_buffer mk_in_buf{ sd_mk_backup.data(), static_cast<uint32_t>(sd_mk_backup.size()) };
        tsra_sd_restore_local_backup_params params{
            &local_buf,
            &mk_in_buf,
        };
        std::vector<uint8_t> pok_local;
        std::vector<uint8_t> sd_mk;
        ASSERT_EQ(
            restore_local_fill(ctx.session, &params, pok_local, sd_mk),
            TSRA_STATUS_SD_ALREADY_INITIALIZED
        );
    });
}

#endif // !defined(TSRA_FEATURE_MOCK)
