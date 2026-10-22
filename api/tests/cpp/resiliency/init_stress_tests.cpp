// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file init_stress_tests.cpp
///
/// Resiliency stress tests for partition initialization and partition-level
/// operations (cert_chain, init_part) under continuous resets.
///

#include <scope_guard.hpp>

#include "resiliency/resiliency_stress_helpers.hpp"

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class init_resiliency_stress : public resiliency_stress_base
{
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A single worker thread repeatedly calls cert_chain while a dedicated
/// thread fires resets. Every cert_chain call must eventually succeed.
///
TEST_F(init_resiliency_stress, cert_chain_under_reset)
{
    part_list_.for_each_part([&](std::vector<tsra_char> &path) {
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { tsra_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { tsra_sess_close(r.session); });

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { tsra_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    // Two-call pattern: query size, then fetch.
                    tsra_part_prop prop = { TSRA_PART_PROP_ID_MANUFACTURER_CERT_CHAIN, nullptr, 0 };
                    auto err = tsra_part_get_prop(r.part, &prop);
                    if (err != TSRA_STATUS_BUFFER_TOO_SMALL)
                    {
                        ADD_FAILURE() << "cert_chain size query " << i << " got " << err;
                        continue;
                    }

                    std::vector<tsra_char> buf(prop.len);
                    prop.val = buf.data();
                    err = tsra_part_get_prop(r.part, &prop);
                    if (err != TSRA_STATUS_SUCCESS)
                    {
                        ADD_FAILURE() << "cert_chain fetch " << i << " got " << err;
                        continue;
                    }
                    ++ok;
                    std::this_thread::sleep_for(WORKER_SLEEP);
                }
                return ok;
            },
            STRESS_OPS
        );
    });
}

/// A single worker thread repeatedly calls init() with resiliency enabled
/// while a dedicated thread fires resets. At most five transient
/// DDI_CMD_FAILURE errors are tolerated.
///
TEST_F(init_resiliency_stress, init_part_under_reset)
{
    part_list_.for_each_part([&](std::vector<tsra_char> &path) {
        // Initial baseline init.
        auto r = init_partition_with_resiliency(path);
        ASSERT_NE(r.part, 0u);
        auto part_guard = scope_guard::make_scope_exit([&] { tsra_part_close(r.part); });
        auto sess_guard = scope_guard::make_scope_exit([&] { tsra_sess_close(r.session); });

        // The PID public key is stable across resets. Prepare POTA before
        // starting resets so its public-key query cannot race with them.
        PartInitConfig init_config{};
        make_part_init_config(r.part, init_config);
        if (init_config.backup_config.source == TSRA_OWNER_BACKUP_KEY_SOURCE_CALLER)
        {
            // init_bk3 is one-shot across resets; re-init must reuse MOBK.
            init_config.mobk_cache = query_mobk_property(r.part);
            ASSERT_FALSE(init_config.mobk_cache.empty()) << "Baseline init must provide MOBK";
            init_config.obk_buf = { init_config.mobk_cache.data(),
                                   static_cast<uint32_t>(init_config.mobk_cache.size()) };
            init_config.backup_config.owner_backup_key = nullptr;
            init_config.backup_config.masked_owner_backup_key = &init_config.obk_buf;
        }

        auto reset_h = open_reset_handle(path);
        auto reset_guard = scope_guard::make_scope_exit([&] { tsra_part_close(reset_h); });

        run_under_reset(
            reset_h,
            [&]() -> uint32_t {
                uint32_t ok = 0;
                for (uint32_t i = 0; i < STRESS_OPS; ++i)
                {
                    tsra_credentials creds{};
                    std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
                    std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

                    tsra_resiliency_config res_config{};
                    make_resiliency_config_in(*r.resiliency_ctx, res_config);

                    auto err = tsra_part_init(
                        r.part,
                        &creds,
                        nullptr,
                        nullptr,
                        &init_config.backup_config,
                        &init_config.pota_endorsement,
                        &res_config
                    );
                    if (err != TSRA_STATUS_SUCCESS)
                    {
                        EXPECT_EQ(err, TSRA_STATUS_DDI_CMD_FAILURE)
                            << "init iteration " << i << " failed with unexpected status";
                        // DDI_CMD_FAILURE (-8) is a known transient error when
                        // a reset races with the DDI call. Tolerated by the
                        // max_allowed_fails parameter below.
                        continue;
                    }
                    ++ok;
                }
                return ok;
            },
            STRESS_OPS,
            5 // allow up to 5 transient DDI_CMD_FAILURE errors
        );
    });
}
