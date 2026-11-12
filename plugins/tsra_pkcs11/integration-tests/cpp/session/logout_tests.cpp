// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file logout_tests.cpp
///
/// What C_Logout does to objects: it destroys the private session objects of
/// every session of the token, and leaves public session objects and token
/// objects alone. A surviving public key still works after the next login. It
/// also ends a search, whose handles were collected while logged in.

#include <cstring>
#include <gtest/gtest.h>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"
#include "utils/surviving_key.hpp"

namespace
{

/// C_CreateObject of a CKO_DATA object. It carries no CKA_VALUE: the file
/// store refuses a private token object with a plaintext value.
CK_RV create_data(
    CK_SESSION_HANDLE s,
    CK_BBOOL token,
    CK_BBOOL priv,
    const char *label,
    CK_OBJECT_HANDLE *out
)
{
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_TOKEN, &token, sizeof(token) },
        { CKA_PRIVATE, &priv, sizeof(priv) },
        { CKA_LABEL, const_cast<char *>(label), static_cast<CK_ULONG>(std::strlen(label)) },
    };
    return p11()->C_CreateObject(s, tmpl, sizeof(tmpl) / sizeof(tmpl[0]), out);
}

/// Whether `obj` is a valid handle for session `s`.
CK_RV probe(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE obj)
{
    CK_OBJECT_CLASS cls = 0;
    return get_attr(s, obj, CKA_CLASS, &cls);
}

} // namespace

class logout : public UserSession
{
};

TEST_F(logout, private_session_object_handle_invalid_after_relogin)
{
    CK_SESSION_HANDLE sibling = 0;
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &sibling)
    );
    CK_OBJECT_HANDLE key = 0;
    CK_OBJECT_HANDLE data = 0;
    CK_OBJECT_HANDLE sibling_key = 0;
    ASSERT_CKR_OK(gen_family_key(s_, CKM_AES_CBC, CK_FALSE, CK_TRUE, "private-session", &key));
    ASSERT_CKR_OK(create_data(s_, CK_FALSE, CK_TRUE, "private-session", &data));
    ASSERT_CKR_OK(
        gen_family_key(sibling, CKM_AES_CBC, CK_FALSE, CK_TRUE, "private-session", &sibling_key)
    );
    // The positive control: the same objects as token objects stay.
    CK_OBJECT_HANDLE token_key = 0;
    CK_OBJECT_HANDLE token_data = 0;
    ASSERT_CKR_OK(gen_family_key(s_, CKM_AES_CBC, CK_TRUE, CK_TRUE, "private-token", &token_key));
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, CK_TRUE, "private-token", &token_data));

    ASSERT_CKR_OK(p11()->C_Logout(s_));
    ASSERT_CKR_OK(login_user(s_));

    // Gone, not merely hidden until the login: the sibling session's too.
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, probe(s_, key));
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, probe(s_, data));
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, probe(sibling, sibling_key));
    CK_BYTE iv[kAesBlock] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_EncryptInit(s_, &cbc, key));
    const char label[] = "private-session";
    CK_ATTRIBUTE by_label = { CKA_LABEL, const_cast<char *>(label), sizeof(label) - 1 };
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, &by_label, 1));
    CK_OBJECT_HANDLE found[4] = {};
    CK_ULONG n = 0;
    ASSERT_CKR_OK(p11()->C_FindObjects(s_, found, 4, &n));
    ASSERT_CKR_OK(p11()->C_FindObjectsFinal(s_));
    EXPECT_EQ(0u, n) << "a search does not find them either";

    EXPECT_CKR_OK(probe(s_, token_key));
    EXPECT_CKR_OK(probe(s_, token_data));
    // Leave the token store as we found it.
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, token_key));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, token_data));
    EXPECT_CKR_OK(p11()->C_CloseSession(sibling));
}

TEST_F(logout, public_session_object_survives_logout)
{
    CK_OBJECT_HANDLE key = 0;
    CK_OBJECT_HANDLE data = 0;
    ASSERT_CKR_OK(gen_family_key(s_, CKM_AES_CBC, CK_FALSE, CK_FALSE, "public-session", &key));
    ASSERT_CKR_OK(create_data(s_, CK_FALSE, CK_FALSE, "public-session", &data));
    SurvivingKey survivor(s_, key, CKM_AES_CBC);
    ASSERT_NO_FATAL_FAILURE(survivor.record());

    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR_OK(probe(s_, key)) << "public objects stay visible while logged out";
    EXPECT_CKR_OK(probe(s_, data));

    ASSERT_CKR_OK(login_user(s_));
    EXPECT_CKR_OK(probe(s_, data));
    ASSERT_NO_FATAL_FAILURE(survivor.check("a logout and login"));
}

TEST_F(logout, ends_an_active_search)
{
    CK_OBJECT_HANDLE data = 0;
    ASSERT_CKR_OK(create_data(s_, CK_TRUE, CK_TRUE, "private-search", &data));
    const char label[] = "private-search";
    CK_ATTRIBUTE by_label = { CKA_LABEL, const_cast<char *>(label), sizeof(label) - 1 };
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, &by_label, 1));

    ASSERT_CKR_OK(p11()->C_Logout(s_));
    CK_OBJECT_HANDLE found[4] = {};
    CK_ULONG n = 0;
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_FindObjects(s_, found, 4, &n));
    EXPECT_EQ(0u, n) << "the private token object stays hidden while logged out";

    ASSERT_CKR_OK(login_user(s_));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, data));
}
