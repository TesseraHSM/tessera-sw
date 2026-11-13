// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>
#include <stdexcept>
#include <string>
#include <tsra_api.h>
#include <utility>
#include <vector>

inline constexpr uint32_t kReportDataSize = 128;
inline constexpr uint32_t kShortReportDataSize = kReportDataSize / 2;
inline constexpr uint32_t kValidReportDataSize = kReportDataSize;

/// Returns the value of `key` in `TSRA_TEST_ARGS` (`;`-separated
/// `key=value` pairs, whitespace-trimmed), or an empty string when unset.
/// The SDK validates the full variable; this only extracts one key.
inline std::string test_arg(const std::string &key)
{
    std::string args;
#ifdef _WIN32
    char *raw = nullptr;
    size_t len = 0;
    if (_dupenv_s(&raw, &len, "TSRA_TEST_ARGS") == 0 && raw != nullptr)
    {
        args = raw;
    }
    free(raw);
#else
    if (const char *raw = std::getenv("TSRA_TEST_ARGS"))
    {
        args = raw;
    }
#endif
    const auto trim = [](const std::string &s) {
        const auto begin = s.find_first_not_of(" \t");
        const auto end = s.find_last_not_of(" \t");
        return begin == std::string::npos ? std::string() : s.substr(begin, end - begin + 1);
    };
    size_t start = 0;
    while (start <= args.size())
    {
        auto end = args.find(';', start);
        if (end == std::string::npos)
        {
            end = args.size();
        }
        const auto pair = args.substr(start, end - start);
        const auto eq = pair.find('=');
        if (eq != std::string::npos && trim(pair.substr(0, eq)) == key)
        {
            return trim(pair.substr(eq + 1));
        }
        start = end + 1;
    }
    return {};
}

/// Returns the `api_rev` selected in `TSRA_TEST_ARGS` as `(major, minor)`.
/// An unset `api_rev` selects revision 1.1. `api_rev` is written as
/// `MAJOR_MINOR` (e.g. `1_1`); other values throw, matching the Rust parser.
inline std::pair<uint32_t, uint32_t> selected_api_rev()
{
    const auto value = test_arg("api_rev");
    if (value.empty())
    {
        return { 1, 1 };
    }
    const auto invalid = [&value]() {
        return std::invalid_argument("TSRA_TEST_ARGS api_rev must be `MAJOR_MINOR`, got " + value);
    };
    const auto sep = value.find('_');
    if (sep == std::string::npos)
    {
        throw invalid();
    }
    const auto parse_part = [&invalid](const std::string &part) {
        if (part.empty() || part.size() > 10 ||
            part.find_first_not_of("0123456789") != std::string::npos)
        {
            throw invalid();
        }
        const auto parsed = std::stoull(part);
        if (parsed > UINT32_MAX)
        {
            throw invalid();
        }
        return static_cast<uint32_t>(parsed);
    };
    return { parse_part(value.substr(0, sep)), parse_part(value.substr(sep + 1)) };
}

/// Returns `true` when the selected `api_rev` is at least `major.minor`.
/// Revisions from 1.1 run the `open_session_ex` tests.
inline bool api_rev_at_least(uint32_t major, uint32_t minor)
{
    return selected_api_rev() >= std::make_pair(major, minor);
}

/// Returns `true` when the selected `api_rev` is at most `major.minor`.
/// Legacy `open_session` and partition `init` tests run only up to 1.1;
/// 2.0 devices accept only `open_session_ex`.
inline bool api_rev_at_most(uint32_t major, uint32_t minor)
{
    return selected_api_rev() <= std::make_pair(major, minor);
}

/// Returns the standard test API revision: 1.0, or 2.0 when that is
/// selected (2.0 devices accept only 2.0).
inline tsra_api_rev test_api_rev()
{
    return api_rev_at_least(2, 0) ? tsra_api_rev{ 2, 0 } : tsra_api_rev{ 1, 0 };
}

/// Returns the API revision used by `open_session_ex` test fixtures: 1.1,
/// or 2.0 when that is selected.
inline tsra_api_rev session_ex_test_api_rev()
{
    return api_rev_at_least(2, 0) ? tsra_api_rev{ 2, 0 } : tsra_api_rev{ 1, 1 };
}

/// Returns the system temporary directory (`/tmp` on Linux, `%TEMP%` on Windows).
/// Fails the current test if the temp directory cannot be determined.
inline std::filesystem::path get_test_tmp_dir()
{
    std::error_code ec;
    auto dir = std::filesystem::temp_directory_path(ec);
    if (ec)
    {
        ADD_FAILURE() << "get_test_tmp_dir: unable to determine temp directory: " << ec.message();
        return {};
    }
    return dir;
}

/// Returns true if any byte in `bytes` is non-zero (i.e. not all-zero).
inline bool any_nonzero(const std::vector<uint8_t> &bytes)
{
    for (uint8_t b : bytes)
    {
        if (b != 0)
        {
            return true;
        }
    }
    return false;
}
