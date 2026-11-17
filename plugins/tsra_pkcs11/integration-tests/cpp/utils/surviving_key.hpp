// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// SurvivingKey: proof that a key is still the same key after a lifecycle
/// event. record() encrypts a fixed message under fixed parameters and keeps
/// the ciphertext c0; check() encrypts it again and expects CKR_OK and c0.
/// Presence of the object proves nothing here: the key has to work, and give
/// the same answer. The caller names the cipher of the key's family
/// (CKM_AES_CBC for a plain AES key, CKM_AES_GCM or CKM_AES_XTS); the store
/// backend is whatever the module runs on, so one case covers both the memory
/// store and the file store (TSRA_PKCS11_PERSIST=1).

#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"

class SurvivingKey
{
  public:
    SurvivingKey(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE key, CK_MECHANISM_TYPE mech)
        : s_(s), key_(key), plain_(pattern(32))
    {
        std::memset(iv_, 0x5A, sizeof(iv_));
        gcm_.pIv = iv_;
        gcm_.ulIvLen = kGcmIv;
        gcm_.ulIvBits = kGcmIv * 8;
        gcm_.ulTagBits = kGcmTagBits;
        switch (mech)
        {
        case CKM_AES_GCM:
            mech_ = { CKM_AES_GCM, &gcm_, sizeof(gcm_) };
            break;
        case CKM_AES_XTS:
            std::memset(iv_ + 1, 0, sizeof(iv_) - 1); /* a small sector number */
            mech_ = { CKM_AES_XTS, iv_, sizeof(iv_) };
            break;
        default:
            mech_ = { CKM_AES_CBC, iv_, sizeof(iv_) };
            break;
        }
    }
    SurvivingKey(const SurvivingKey &) = delete; /* mech_ points into this object */
    SurvivingKey &operator=(const SurvivingKey &) = delete;

    /// Encrypt the message and keep the result as c0. ASSERTs, so call it as
    /// ASSERT_NO_FATAL_FAILURE(k.record()).
    void record()
    {
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain_, c0_));
        ASSERT_FALSE(c0_.empty());
    }

    /// Check through session `s` and key handle `key` from now on: an event
    /// that closes the session or re-initializes the module hands out new ones.
    void rebind(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE key)
    {
        s_ = s;
        key_ = key;
    }

    /// The key still encrypts the message to c0 after `event`. ASSERTs, so call
    /// it as ASSERT_NO_FATAL_FAILURE(k.check("...")).
    void check(const char *event)
    {
        std::vector<CK_BYTE> c;
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech_, key_, plain_, c))
            << "the key is not usable after " << event;
        ASSERT_EQ(c0_, c) << "the key is not the same key after " << event;
    }

  private:
    static constexpr CK_ULONG kGcmIv = 12;
    static constexpr CK_ULONG kGcmTagBits = 128;

    CK_SESSION_HANDLE s_;
    CK_OBJECT_HANDLE key_;
    std::vector<CK_BYTE> plain_;
    std::vector<CK_BYTE> c0_;
    CK_BYTE iv_[kAesBlock];
    CK_GCM_PARAMS gcm_{};
    CK_MECHANISM mech_{};
};
