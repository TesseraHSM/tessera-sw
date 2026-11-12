// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// LeakGate: every way a key-backed operation can end gives its device
/// resources back.
///
/// Each termination path (completion, an error that terminates, a session
/// close, ...) runs many times; then a fresh operation must still succeed,
/// once in the same login and once after a logout and login. It never asserts
/// a device capacity: a path that leaks a device key fills any finite key table
/// once it has run often enough, and the fresh operation then fails.

#include <functional>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/module.hpp"

/// One way to end an operation: `run` starts an operation and ends it that
/// way, ASSERTing on anything unexpected.
struct TerminationPath
{
    std::string name;
    std::function<void()> run;
};

/// Rounds per path: far more device keys than any key table we know holds.
constexpr int kLeakGateRounds = 512;

/// Run the gate on session `s`; `fresh` starts and completes one new
/// operation. ASSERTs, so call it as ASSERT_NO_FATAL_FAILURE(leak_gate(...)).
inline void leak_gate(
    CK_SESSION_HANDLE s,
    const std::vector<TerminationPath> &paths,
    const std::function<CK_RV()> &fresh
)
{
    for (const TerminationPath &path : paths)
    {
        SCOPED_TRACE(path.name);
        for (int i = 0; i < kLeakGateRounds; i++)
        {
            ASSERT_NO_FATAL_FAILURE(path.run()) << "round " << i;
        }
        ASSERT_CKR_OK(fresh()) << "a fresh operation after " << kLeakGateRounds << " rounds";
    }
    ASSERT_CKR_OK(p11()->C_Logout(s));
    ASSERT_CKR_OK(login_user(s));
    ASSERT_CKR_OK(fresh()) << "a fresh operation after a logout and login";
}
