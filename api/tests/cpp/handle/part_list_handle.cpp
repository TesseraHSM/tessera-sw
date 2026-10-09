// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "part_list_handle.hpp"
#include "../utils/utils.hpp"
#include "part_handle.hpp"
#include "session_handle.hpp"

#include <scope_guard.hpp>

namespace
{
constexpr size_t TEST_CO_PSK_LEN = 32;
constexpr uint8_t TEST_CO_PSK_FILL = 0xA5;
} // namespace
void PartitionListHandle::for_each_session(const std::function<void(tsra_handle)> &func) const
{
#if SESSION_EX_TESTS
    for_each_part([&](std::vector<tsra_char> &path) {
        tsra_str path_str{ path.data(), static_cast<uint32_t>(path.size()) };
        tsra_handle part_handle = 0;
        auto err = tsra_part_open(&path_str, &part_handle, session_ex_test_api_rev());
        if (err != TSRA_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to open session_ex test partition. Error: " + std::to_string(err)
            );
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

#if defined(TSRA_FEATURE_EMU)
        err = tsra_part_reset(part_handle);
        if (err != TSRA_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to reset session_ex test partition. Error: " + std::to_string(err)
            );
        }
#endif

        std::vector<uint8_t> rotated_psk(TEST_CO_PSK_LEN, TEST_CO_PSK_FILL);
        tsra_buffer rotated_psk_buf{ rotated_psk.data(),
                                     static_cast<uint32_t>(rotated_psk.size()) };
#if defined(TSRA_FEATURE_EMU)
        tsra_session_psk psk{ 0, nullptr };
#else
        tsra_session_psk psk{ 0, &rotated_psk_buf };
#endif
        tsra_handle session_handle = 0;
        err = tsra_sess_ex_open(
            part_handle,
            &psk,
            TSRA_SESSION_EX_TYPE_AUTHENTICATED,
            &session_handle
        );
        if (err != TSRA_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to call tsra_sess_ex_open for a test. Error: " + std::to_string(err)
            );
        }
        auto session_guard =
            scope_guard::make_scope_exit([&session_handle] { tsra_sess_close(session_handle); });

#if defined(TSRA_FEATURE_EMU)
        err = tsra_sess_ex_psk_change(session_handle, &rotated_psk_buf);
        if (err != TSRA_STATUS_SUCCESS)
        {
            throw std::runtime_error(
                "Failed to rotate session_ex test CO PSK. Error: " + std::to_string(err)
            );
        }
#endif

        func(session_handle);
    });
#else
    for_each_part([&](std::vector<tsra_char> &path) {
        auto partition = PartitionHandle(path);
        auto session = SessionHandle(partition.get());
        func(session.get());
    });
#endif
}