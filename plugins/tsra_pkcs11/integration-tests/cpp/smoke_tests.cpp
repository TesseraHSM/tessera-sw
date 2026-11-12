// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file smoke_tests.cpp
///
/// The module loads, identifies itself, exposes a token on slot 0 with honest
/// token information (no random-number generator, real session counts) and
/// advertises exactly the mechanisms it implements, each of which an init
/// call accepts. If the .so is missing or its init fails, ModuleEnvironment
/// already throws before any of these.

#include <gtest/gtest.h>
#include <vector>

#include "tsra_pkcs11_template.h"
#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"

class smoke : public PublicSession
{
};

class smoke_login : public UserSession
{
};

TEST_F(smoke, module_reports_cryptoki_3_1)
{
    CK_INFO info{};
    ASSERT_CKR_OK(p11()->C_GetInfo(&info));
    EXPECT_EQ(3, info.cryptokiVersion.major);
    EXPECT_EQ(1, info.cryptokiVersion.minor);
}

TEST_F(smoke, slot_zero_has_a_login_required_token)
{
    CK_ULONG count = 0;
    ASSERT_CKR_OK(p11()->C_GetSlotList(CK_TRUE, nullptr, &count));
    ASSERT_GE(count, 1u);

    CK_TOKEN_INFO tinfo{};
    ASSERT_CKR_OK(p11()->C_GetTokenInfo(kSlot, &tinfo));
    EXPECT_NE(0u, tinfo.flags & CKF_LOGIN_REQUIRED)
        << "every key-backed call needs the device session behind C_Login";
}

TEST_F(smoke, aes_mechanisms_are_advertised)
{
    CK_ULONG count = 0;
    ASSERT_CKR_OK(p11()->C_GetMechanismList(kSlot, nullptr, &count));
    std::vector<CK_MECHANISM_TYPE> mechs(count);
    ASSERT_CKR_OK(p11()->C_GetMechanismList(kSlot, mechs.data(), &count));

    auto has = [&](CK_MECHANISM_TYPE m) {
        for (CK_MECHANISM_TYPE x : mechs)
        {
            if (x == m)
            {
                return true;
            }
        }
        return false;
    };
    EXPECT_TRUE(has(CKM_AES_KEY_GEN));
    EXPECT_TRUE(has(CKM_AES_CBC));
    EXPECT_TRUE(has(CKM_AES_CBC_PAD));
    EXPECT_TRUE(has(CKM_AES_GCM));
    EXPECT_TRUE(has(CKM_AES_XTS));
    EXPECT_TRUE(has(CKM_AES_XTS_KEY_GEN));

    CK_MECHANISM_INFO minfo{};
    ASSERT_CKR_OK(p11()->C_GetMechanismInfo(kSlot, CKM_AES_KEY_GEN, &minfo));
    EXPECT_NE(0u, minfo.flags & CKF_GENERATE);
    ASSERT_CKR_OK(p11()->C_GetMechanismInfo(kSlot, CKM_AES_CBC_PAD, &minfo));
    EXPECT_NE(0u, minfo.flags & CKF_ENCRYPT);
    EXPECT_NE(0u, minfo.flags & CKF_DECRYPT);

    // The key sizes are the device's: GCM keys only at 256 bits, XTS keys only
    // as two 256-bit halves (reported in bytes, like the AES rows).
    ASSERT_CKR_OK(p11()->C_GetMechanismInfo(kSlot, CKM_AES_GCM, &minfo));
    EXPECT_EQ(32u, minfo.ulMinKeySize);
    EXPECT_EQ(32u, minfo.ulMaxKeySize);
    EXPECT_NE(0u, minfo.flags & CKF_ENCRYPT);
    ASSERT_CKR_OK(p11()->C_GetMechanismInfo(kSlot, CKM_AES_XTS_KEY_GEN, &minfo));
    EXPECT_EQ(64u, minfo.ulMinKeySize);
    EXPECT_EQ(64u, minfo.ulMaxKeySize);
    EXPECT_NE(0u, minfo.flags & CKF_GENERATE);
}

TEST_F(smoke, unimplemented_entry_point_reports_not_supported)
{
    CK_UTF8CHAR pin[] = "1234";
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_SetPIN(s_, pin, 4, pin, 4));
}

TEST_F(smoke, session_info_reflects_open_public_session)
{
    CK_SESSION_INFO sinfo{};
    ASSERT_CKR_OK(p11()->C_GetSessionInfo(s_, &sinfo));
    EXPECT_EQ(kSlot, sinfo.slotID);
    EXPECT_EQ(static_cast<CK_STATE>(CKS_RW_PUBLIC_SESSION), sinfo.state);
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_GetSessionInfo(kInvalidSession, &sinfo));
}

TEST_F(smoke, token_reports_no_rng_and_real_session_counts)
{
    CK_TOKEN_INFO before{};
    ASSERT_CKR_OK(p11()->C_GetTokenInfo(kSlot, &before));
    EXPECT_EQ(0u, before.flags & CKF_RNG) << "the device offers no random-number generator";
    EXPECT_NE(CK_EFFECTIVELY_INFINITE, before.ulMaxSessionCount);
    EXPECT_NE(CK_UNAVAILABLE_INFORMATION, before.ulMaxSessionCount);
    EXPECT_EQ(before.ulMaxSessionCount, before.ulMaxRwSessionCount);
    EXPECT_GE(before.ulSessionCount, 1u) << "the fixture's own session";
    EXPECT_GE(before.ulRwSessionCount, 1u);

    CK_SESSION_HANDLE ro = 0, rw = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &rw)
    );
    CK_TOKEN_INFO during{};
    ASSERT_CKR_OK(p11()->C_GetTokenInfo(kSlot, &during));
    EXPECT_EQ(before.ulSessionCount + 2, during.ulSessionCount);
    EXPECT_EQ(before.ulRwSessionCount + 1, during.ulRwSessionCount);

    ASSERT_CKR_OK(p11()->C_CloseSession(ro));
    ASSERT_CKR_OK(p11()->C_CloseSession(rw));
    CK_TOKEN_INFO after{};
    ASSERT_CKR_OK(p11()->C_GetTokenInfo(kSlot, &after));
    EXPECT_EQ(before.ulSessionCount, after.ulSessionCount);
    EXPECT_EQ(before.ulRwSessionCount, after.ulRwSessionCount);
}

TEST_F(smoke, random_number_functions_report_no_rng)
{
    CK_BYTE buf[16] = { 0 };
    EXPECT_CKR(CKR_RANDOM_NO_RNG, p11()->C_GenerateRandom(s_, buf, sizeof(buf)));
    EXPECT_CKR(CKR_RANDOM_NO_RNG, p11()->C_SeedRandom(s_, buf, sizeof(buf)));
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_GenerateRandom(kInvalidSession, buf, sizeof(buf))
    );
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_SeedRandom(kInvalidSession, buf, sizeof(buf)));
}

TEST_F(smoke_login, every_advertised_mechanism_has_an_init_path)
{
    CK_ULONG count = 0;
    ASSERT_CKR_OK(p11()->C_GetMechanismList(kSlot, nullptr, &count));
    std::vector<CK_MECHANISM_TYPE> mechs(count);
    ASSERT_CKR_OK(p11()->C_GetMechanismList(kSlot, mechs.data(), &count));

    CK_OBJECT_HANDLE cbc = 0, gcm = 0, xts = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "init-cbc", &cbc));
    ASSERT_CKR_OK(gen_gcm_key(s_, "init-gcm", &gcm));
    ASSERT_CKR_OK(gen_xts_key(s_, "init-xts", &xts));
    CK_BYTE iv[kAesBlock] = { 0 };
    CK_GCM_PARAMS gcm_params{};
    gcm_params.pIv = iv;
    gcm_params.ulIvLen = AES_GCM_IV_LEN;
    gcm_params.ulIvBits = AES_GCM_IV_LEN * 8;
    gcm_params.ulTagBits = AES_GCM_TAG_LEN * 8;

    const CK_FLAGS driven = CKF_DIGEST | CKF_GENERATE | CKF_ENCRYPT | CKF_DECRYPT;
    for (CK_MECHANISM_TYPE m : mechs)
    {
        SCOPED_TRACE(::testing::Message() << "mechanism 0x" << std::hex << m);
        CK_MECHANISM_INFO info{};
        ASSERT_CKR_OK(p11()->C_GetMechanismInfo(kSlot, m, &info));
        EXPECT_EQ(0u, info.flags & ~driven) << "an entry point this test does not drive";

        CK_MECHANISM mech = { m, nullptr, 0 };
        if ((info.flags & CKF_DIGEST) != 0)
        {
            EXPECT_CKR_OK(p11()->C_DigestInit(s_, &mech));
            EXPECT_CKR_OK(p11()->C_DigestInit(s_, nullptr));
        }
        if ((info.flags & CKF_GENERATE) != 0)
        {
            CK_ULONG len = info.ulMaxKeySize;
            CK_ATTRIBUTE tmpl[] = { { CKA_VALUE_LEN, &len, sizeof(len) } };
            CK_OBJECT_HANDLE key = 0;
            EXPECT_CKR_OK(p11()->C_GenerateKey(s_, &mech, tmpl, 1, &key));
        }
        if ((info.flags & (CKF_ENCRYPT | CKF_DECRYPT)) != 0)
        {
            CK_OBJECT_HANDLE key = 0;
            switch (m)
            {
            case CKM_AES_CBC:
            case CKM_AES_CBC_PAD:
                mech = { m, iv, sizeof(iv) };
                key = cbc;
                break;
            case CKM_AES_GCM:
                mech = { m, &gcm_params, sizeof(gcm_params) };
                key = gcm;
                break;
            case CKM_AES_XTS:
                mech = { m, iv, sizeof(iv) };
                key = xts;
                break;
            default:
                ADD_FAILURE() << "no key and parameter for this cipher mechanism";
                continue;
            }
            EXPECT_CKR_OK(p11()->C_EncryptInit(s_, &mech, key));
            EXPECT_CKR_OK(p11()->C_EncryptInit(s_, nullptr, key));
            EXPECT_CKR_OK(p11()->C_DecryptInit(s_, &mech, key));
            EXPECT_CKR_OK(p11()->C_DecryptInit(s_, nullptr, key));
        }
    }
}
