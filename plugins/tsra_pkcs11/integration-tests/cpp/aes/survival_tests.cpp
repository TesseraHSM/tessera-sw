// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file survival_tests.cpp
///
/// Keys outlive the events PKCS#11 says they outlive, proven by use: a
/// SurvivingKey (utils/surviving_key.hpp) encrypts the same message to the
/// same ciphertext before and after each event. Every event below also ends
/// the device session: no other session keeps the login open (ctest runs each
/// case in a process of its own), and a case that closes the session checks
/// that the next one starts logged out. Each case covers a private token key
/// of every family.

#include <array>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <utility>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"
#include "utils/store_dir.hpp"
#include "utils/surviving_key.hpp"

namespace
{

/// The cipher of each key family, and the label of its token key.
constexpr std::array<std::pair<CK_MECHANISM_TYPE, const char *>, 3> kFamilies = { {
    { CKM_AES_CBC, "survival-cbc" },
    { CKM_AES_GCM, "survival-gcm" },
    { CKM_AES_XTS, "survival-xts" },
} };

/// A private token key of every family, each with the c0 it gave when made.
class TokenKeys
{
  public:
    /// Generate and record the keys through the logged-in session `s`.
    /// ASSERTs, so call it as ASSERT_NO_FATAL_FAILURE(keys.make(s)).
    void make(CK_SESSION_HANDLE s)
    {
        for (auto [mech, label] : kFamilies)
        {
            CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
            ASSERT_CKR_OK(gen_family_key(s, mech, CK_TRUE, CK_TRUE, label, &key));
            handles_.push_back(key);
            survivors_.push_back(std::make_unique<SurvivingKey>(s, key, mech));
            ASSERT_NO_FATAL_FAILURE(survivors_.back()->record());
        }
    }

    /// Look the keys up again by label through `s`: after C_Initialize the
    /// module may hand out other handles. ASSERTs.
    void find(CK_SESSION_HANDLE s)
    {
        for (size_t i = 0; i < handles_.size(); i++)
        {
            const char *label = kFamilies[i].second;
            CK_ATTRIBUTE by_label = { CKA_LABEL,
                                      const_cast<char *>(label),
                                      static_cast<CK_ULONG>(std::strlen(label)) };
            ASSERT_CKR_OK(p11()->C_FindObjectsInit(s, &by_label, 1));
            CK_OBJECT_HANDLE found[2] = {};
            CK_ULONG n = 0;
            ASSERT_CKR_OK(p11()->C_FindObjects(s, found, 2, &n));
            ASSERT_CKR_OK(p11()->C_FindObjectsFinal(s));
            ASSERT_EQ(1u, n) << label;
            handles_[i] = found[0];
        }
    }

    /// Every key still gives its c0 through session `s` after `event`.
    /// ASSERTs.
    void check(CK_SESSION_HANDLE s, const char *event)
    {
        for (size_t i = 0; i < survivors_.size(); i++)
        {
            SCOPED_TRACE(kFamilies[i].second);
            survivors_[i]->rebind(s, handles_[i]);
            ASSERT_NO_FATAL_FAILURE(survivors_[i]->check(event));
        }
    }

    /// Token objects outlive the test: destroy them through `s`.
    void destroy(CK_SESSION_HANDLE s)
    {
        for (CK_OBJECT_HANDLE h : handles_)
        {
            (void)p11()->C_DestroyObject(s, h);
        }
        handles_.clear();
    }

  private:
    std::vector<CK_OBJECT_HANDLE> handles_;
    std::vector<std::unique_ptr<SurvivingKey>> survivors_;
};

/// Open a session in place of the one the event closed, show that the event
/// ended the login and with it the device session, and log in again.
/// ASSERTs, so call it as ASSERT_NO_FATAL_FAILURE(reopen(&s_)).
void reopen(CK_SESSION_HANDLE *s)
{
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, s)
    );
    CK_SESSION_INFO info{};
    ASSERT_CKR_OK(p11()->C_GetSessionInfo(*s, &info));
    ASSERT_EQ(static_cast<CK_STATE>(CKS_RW_PUBLIC_SESSION), info.state) << "the login ended";
    ASSERT_CKR_OK(login_user(*s));
}

} // namespace

class key_survival : public UserSession
{
  protected:
    void TearDown() override
    {
        if (s_ != 0)
        {
            keys_.destroy(s_);
        }
        UserSession::TearDown();
    }

    TokenKeys keys_;
};

/// The file store keeps token objects across C_Finalize, which the memory
/// store does not, so this one runs on a store of its own.
class key_survival_persist : public StoreDirFixture
{
  protected:
    TokenKeys keys_;
};

TEST_F(key_survival, every_key_family_gives_c0_again_when_nothing_happened)
{
    // The positive control for every survival case: with no event in between,
    // the check passes for each key family.
    CK_OBJECT_HANDLE cbc = 0;
    CK_OBJECT_HANDLE gcm = 0;
    CK_OBJECT_HANDLE xts = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "survival-cbc", &cbc));
    ASSERT_CKR_OK(gen_gcm_key(s_, "survival-gcm", &gcm));
    ASSERT_CKR_OK(gen_xts_key(s_, "survival-xts", &xts));
    for (auto [key, mech] : { std::pair{ cbc, CKM_AES_CBC },
                              std::pair{ gcm, CKM_AES_GCM },
                              std::pair{ xts, CKM_AES_XTS } })
    {
        SCOPED_TRACE(mech);
        SurvivingKey survivor(s_, key, mech);
        ASSERT_NO_FATAL_FAILURE(survivor.record());
        ASSERT_NO_FATAL_FAILURE(survivor.check("nothing"));
    }
}

TEST_F(key_survival, after_logout_login)
{
    ASSERT_NO_FATAL_FAILURE(keys_.make(s_));
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    ASSERT_CKR_OK(login_user(s_));
    ASSERT_NO_FATAL_FAILURE(keys_.check(s_, "a logout and login"));
}

TEST_F(key_survival, after_last_session_close)
{
    ASSERT_NO_FATAL_FAILURE(keys_.make(s_));
    ASSERT_CKR_OK(p11()->C_CloseSession(s_));
    s_ = 0;
    ASSERT_NO_FATAL_FAILURE(reopen(&s_));
    ASSERT_NO_FATAL_FAILURE(keys_.check(s_, "closing the last session"));
}

TEST_F(key_survival, after_close_all_sessions)
{
    ASSERT_NO_FATAL_FAILURE(keys_.make(s_));
    ASSERT_CKR_OK(p11()->C_CloseAllSessions(kSlot));
    s_ = 0;
    ASSERT_NO_FATAL_FAILURE(reopen(&s_));
    ASSERT_NO_FATAL_FAILURE(keys_.check(s_, "C_CloseAllSessions"));
}

TEST_F(key_survival_persist, after_finalize_initialize)
{
    ASSERT_NO_FATAL_FAILURE(keys_.make(s_));
    ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
    s_ = 0;
    ASSERT_CKR_OK(p11()->C_Initialize(nullptr));
    ASSERT_NO_FATAL_FAILURE(reopen(&s_));
    ASSERT_NO_FATAL_FAILURE(keys_.find(s_));
    ASSERT_NO_FATAL_FAILURE(keys_.check(s_, "C_Finalize and C_Initialize"));
}
