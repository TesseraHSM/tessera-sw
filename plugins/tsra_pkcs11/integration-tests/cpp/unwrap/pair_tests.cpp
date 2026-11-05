// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file pair_tests.cpp
///
/// C_GenerateKeyPair with CKM_RSA_PKCS_KEY_PAIR_GEN: the partition's one RSA
/// unwrapping key as a public and a private object, the exact template that
/// asks for it, the refusal of every other RSA template, and how the objects
/// relate to the device key (the same key on every call, kept when the objects
/// go, and checked again at every unwrap).

#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"
#include "utils/store_dir.hpp"
#include "utils/subprocess.hpp"
#include "utils/unwrap_helpers.hpp"

class unwrapping_pair : public UserSession
{
};

TEST_F(unwrapping_pair, is_the_partition_key_with_its_public_parts)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub, &priv));

    std::vector<CK_BYTE> n;
    std::vector<CK_BYTE> e;
    ASSERT_CKR_OK(get_bytes(s_, pub, CKA_MODULUS, n));
    ASSERT_CKR_OK(get_bytes(s_, pub, CKA_PUBLIC_EXPONENT, e));
    EXPECT_EQ(kUnwrapKeyBits / 8, n.size());
    EXPECT_NE(0, n[0]) << "no leading zero";
    EXPECT_EQ(std::vector<CK_BYTE>({ 0x01, 0x00, 0x01 }), e);
    std::vector<CK_BYTE> priv_n;
    std::vector<CK_BYTE> priv_e;
    ASSERT_CKR_OK(get_bytes(s_, priv, CKA_MODULUS, priv_n));
    ASSERT_CKR_OK(get_bytes(s_, priv, CKA_PUBLIC_EXPONENT, priv_e));
    EXPECT_EQ(n, priv_n);
    EXPECT_EQ(e, priv_e);

    std::vector<CK_BYTE> id;
    std::vector<CK_BYTE> priv_id;
    ASSERT_CKR_OK(get_bytes(s_, pub, CKA_ID, id));
    ASSERT_CKR_OK(get_bytes(s_, priv, CKA_ID, priv_id));
    EXPECT_EQ(20u, id.size()) << "the SHA-1 of the modulus";
    EXPECT_EQ(id, priv_id);

    struct
    {
        CK_OBJECT_HANDLE obj;
        CK_ATTRIBUTE_TYPE type;
        CK_BBOOL want;
    } flags[] = {
        { pub, CKA_WRAP, CK_TRUE },
        { pub, CKA_ENCRYPT, CK_FALSE },
        { pub, CKA_VERIFY, CK_FALSE },
        { pub, CKA_PRIVATE, CK_FALSE },
        { pub, CKA_LOCAL, CK_TRUE },
        { priv, CKA_UNWRAP, CK_TRUE },
        { priv, CKA_DECRYPT, CK_FALSE },
        { priv, CKA_SIGN, CK_FALSE },
        { priv, CKA_PRIVATE, CK_TRUE },
        { priv, CKA_SENSITIVE, CK_TRUE },
        { priv, CKA_EXTRACTABLE, CK_FALSE },
        { priv, CKA_ALWAYS_SENSITIVE, CK_TRUE },
        { priv, CKA_NEVER_EXTRACTABLE, CK_TRUE },
        { priv, CKA_LOCAL, CK_TRUE },
    };
    for (const auto &f : flags)
    {
        SCOPED_TRACE("attribute 0x" + std::to_string(f.type));
        CK_BBOOL got = CK_FALSE;
        ASSERT_CKR_OK(get_attr(s_, f.obj, f.type, &got));
        EXPECT_EQ(f.want, got);
    }
    for (CK_OBJECT_HANDLE obj : { pub, priv })
    {
        CK_ULONG bits = 0;
        CK_KEY_TYPE kt = 0;
        CK_MECHANISM_TYPE kgm = 0;
        std::vector<CK_MECHANISM_TYPE> allowed;
        EXPECT_CKR_OK(get_attr(s_, obj, CKA_KEY_TYPE, &kt));
        EXPECT_EQ(CKK_RSA, kt);
        EXPECT_CKR_OK(get_attr(s_, obj, CKA_KEY_GEN_MECHANISM, &kgm));
        EXPECT_EQ(CKM_RSA_PKCS_KEY_PAIR_GEN, kgm);
        ASSERT_CKR_OK(get_allowed_mechs(s_, obj, allowed));
        EXPECT_EQ(std::vector<CK_MECHANISM_TYPE>({ CKM_RSA_AES_KEY_WRAP }), allowed);
        if (obj == pub)
        {
            EXPECT_CKR_OK(get_attr(s_, obj, CKA_MODULUS_BITS, &bits));
            EXPECT_EQ(kUnwrapKeyBits, bits);
        }
    }
    CK_BYTE secret[512];
    CK_ATTRIBUTE d = { CKA_PRIVATE_EXPONENT, secret, sizeof(secret) };
    EXPECT_NE(Ckr{ CKR_OK }, Ckr{ p11()->C_GetAttributeValue(s_, priv, &d, 1) })
        << "the private exponent never leaves the device";
}

TEST_F(unwrapping_pair, every_call_returns_the_same_key)
{
    std::vector<CK_BYTE> first;
    for (int i = 0; i < 3; i++)
    {
        CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
        ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub, &priv));
        std::vector<CK_BYTE> n;
        ASSERT_CKR_OK(get_bytes(s_, pub, CKA_MODULUS, n));
        if (i == 0)
        {
            first = n;
        }
        EXPECT_EQ(first, n) << "call " << i;
        // The device key stays when its objects go.
        ASSERT_CKR_OK(p11()->C_DestroyObject(s_, pub));
        ASSERT_CKR_OK(p11()->C_DestroyObject(s_, priv));
    }
}

TEST_F(unwrapping_pair, is_findable_by_modulus)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub, &priv));
    std::vector<CK_BYTE> n;
    ASSERT_CKR_OK(get_bytes(s_, pub, CKA_MODULUS, n));

    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE match[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_MODULUS, n.data(), static_cast<CK_ULONG>(n.size()) },
    };
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, match, 2));
    CK_OBJECT_HANDLE found[4] = {};
    CK_ULONG count = 0;
    ASSERT_CKR_OK(p11()->C_FindObjects(s_, found, 4, &count));
    ASSERT_CKR_OK(p11()->C_FindObjectsFinal(s_));
    ASSERT_EQ(1u, count);
    EXPECT_EQ(priv, found[0]);
}

TEST_F(unwrapping_pair, any_other_rsa_template_is_refused)
{
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0 };
    CK_ULONG bits = kUnwrapKeyBits;
    CK_ULONG small = 1024;
    CK_ULONG big = 4096;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_BYTE e3[] = { 0x03 };
    CK_BYTE e65537[] = { 0x00, 0x01, 0x00, 0x01 };
    CK_BYTE modulus[kUnwrapKeyBits / 8] = { 0x80 };
    CK_MECHANISM_TYPE oaep = CKM_RSA_PKCS_OAEP;
    CK_ATTRIBUTE bits_ok = { CKA_MODULUS_BITS, &bits, sizeof(bits) };
    CK_ATTRIBUTE wrap = { CKA_WRAP, &yes, sizeof(yes) };
    CK_ATTRIBUTE unwrap = { CKA_UNWRAP, &yes, sizeof(yes) };

    struct Case
    {
        const char *what;
        std::vector<CK_ATTRIBUTE> pub;
        std::vector<CK_ATTRIBUTE> priv;
        CK_RV want;
    } cases[] = {
        { "1024 bits",
          { { CKA_MODULUS_BITS, &small, sizeof(small) }, wrap },
          { unwrap },
          CKR_TEMPLATE_INCONSISTENT },
        { "4096 bits",
          { { CKA_MODULUS_BITS, &big, sizeof(big) }, wrap },
          { unwrap },
          CKR_TEMPLATE_INCONSISTENT },
        { "no modulus size", { wrap }, { unwrap }, CKR_TEMPLATE_INCOMPLETE },
        { "a signing key",
          { bits_ok, { CKA_VERIFY, &yes, sizeof(yes) } },
          { { CKA_SIGN, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "an encryption key",
          { bits_ok, { CKA_ENCRYPT, &yes, sizeof(yes) } },
          { { CKA_DECRYPT, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "decrypt besides unwrap",
          { bits_ok, wrap },
          { unwrap, { CKA_DECRYPT, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "no usage", { bits_ok }, {}, CKR_TEMPLATE_INCONSISTENT },
        { "unwrap FALSE",
          { bits_ok, wrap },
          { { CKA_UNWRAP, &no, sizeof(no) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "extractable",
          { bits_ok, wrap },
          { unwrap, { CKA_EXTRACTABLE, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "not sensitive",
          { bits_ok, wrap },
          { unwrap, { CKA_SENSITIVE, &no, sizeof(no) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "a modulus",
          { bits_ok, wrap, { CKA_MODULUS, modulus, sizeof(modulus) } },
          { unwrap },
          CKR_TEMPLATE_INCONSISTENT },
        { "exponent 3",
          { bits_ok, wrap, { CKA_PUBLIC_EXPONENT, e3, sizeof(e3) } },
          { unwrap },
          CKR_TEMPLATE_INCONSISTENT },
        { "another mechanism",
          { bits_ok, wrap },
          { unwrap, { CKA_ALLOWED_MECHANISMS, &oaep, sizeof(oaep) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "exponent 65537 with a leading zero",
          { bits_ok, wrap, { CKA_PUBLIC_EXPONENT, e65537, sizeof(e65537) } },
          { unwrap },
          CKR_OK },
    };
    for (Case &c : cases)
    {
        SCOPED_TRACE(c.what);
        CK_ULONG before = count_objects(s_);
        CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
        EXPECT_CKR(
            c.want,
            p11()->C_GenerateKeyPair(
                s_,
                &mech,
                c.pub.data(),
                static_cast<CK_ULONG>(c.pub.size()),
                c.priv.data(),
                static_cast<CK_ULONG>(c.priv.size()),
                &pub,
                &priv
            )
        );
        EXPECT_EQ(before + ((c.want == CKR_OK) ? 2 : 0), count_objects(s_));
    }
}

TEST_F(unwrapping_pair, mechanism_session_and_login_rules)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_ULONG bits = kUnwrapKeyBits;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE pub_tmpl[] = { { CKA_MODULUS_BITS, &bits, sizeof(bits) },
                                { CKA_WRAP, &yes, sizeof(yes) } };
    CK_ATTRIBUTE priv_tmpl[] = { { CKA_UNWRAP, &yes, sizeof(yes) } };

    CK_MECHANISM dsa = { CKM_DSA_KEY_PAIR_GEN, nullptr, 0 };
    EXPECT_CKR(
        CKR_MECHANISM_INVALID,
        p11()->C_GenerateKeyPair(s_, &dsa, pub_tmpl, 2, priv_tmpl, 1, &pub, &priv)
    );
    CK_BYTE param = 0;
    CK_MECHANISM with_param = { CKM_RSA_PKCS_KEY_PAIR_GEN, &param, sizeof(param) };
    EXPECT_CKR(
        CKR_MECHANISM_PARAM_INVALID,
        p11()->C_GenerateKeyPair(s_, &with_param, pub_tmpl, 2, priv_tmpl, 1, &pub, &priv)
    );
    ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub, &priv, CK_TRUE));
    ASSERT_CKR_OK(p11()->C_DestroyObject(s_, pub));
    ASSERT_CKR_OK(p11()->C_DestroyObject(s_, priv));

    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    EXPECT_CKR(CKR_SESSION_READ_ONLY, gen_unwrapping_pair(ro, &pub, &priv, CK_TRUE));
    ASSERT_CKR_OK(gen_unwrapping_pair(ro, &pub, &priv)) << "session objects need no R/W session";
    ASSERT_CKR_OK(p11()->C_CloseSession(ro));

    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR(CKR_USER_NOT_LOGGED_IN, gen_unwrapping_pair(s_, &pub, &priv));
}

/// A token pair on the file store: it outlives C_Finalize, and works after it
/// as long as the partition keeps its unwrapping key.
class unwrapping_pair_persist : public StoreDirFixture
{
};

/// The second process: it runs on the parent's store (SubprocessModule passes
/// the environment), so it is a plain logged-in session.
class unwrapping_pair_child : public UserSession
{
};

TEST_F(unwrapping_pair_persist, token_pair_survives_finalize_initialize)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub, &priv, CK_TRUE));
    std::vector<CK_BYTE> n;
    ASSERT_CKR_OK(get_bytes(s_, pub, CKA_MODULUS, n));

    ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
    ASSERT_CKR_OK(p11()->C_Initialize(nullptr));
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &s_)
    );
    ASSERT_CKR_OK(login_user(s_));
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE match[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_MODULUS, n.data(), static_cast<CK_ULONG>(n.size()) },
    };
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, match, 2));
    CK_ULONG count = 0;
    ASSERT_CKR_OK(p11()->C_FindObjects(s_, &priv, 1, &count));
    ASSERT_CKR_OK(p11()->C_FindObjectsFinal(s_));
    ASSERT_EQ(1u, count);

    host::Pkey key = host::rsa_public(n, { 0x01, 0x00, 0x01 });
    RsaAesMechanism m;
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    EXPECT_CKR_OK(unwrap_key(
        s_,
        priv,
        &m.mech,
        host::rsa_aes_key_wrap(key.get(), "SHA256", host::Bytes(32, 0x11)),
        CKM_AES_CBC,
        &aes
    ));
}

TEST_F(unwrapping_pair_persist, another_partitions_pair_is_refused_at_unwrap)
{
    MOCK_ONLY("the mock gives every process a partition, and an unwrapping key, of its own");
    SubprocessModule::Result child =
        SubprocessModule::run("unwrapping_pair_child.makes_a_token_pair", store_env());
    ASSERT_EQ(0, child.exit_code);
    ASSERT_EQ("1", child.values["ran"]);

    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE match = { CKA_CLASS, &cls, sizeof(cls) };
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, &match, 1));
    CK_OBJECT_HANDLE theirs = CK_INVALID_HANDLE;
    CK_ULONG count = 0;
    ASSERT_CKR_OK(p11()->C_FindObjects(s_, &theirs, 1, &count));
    ASSERT_CKR_OK(p11()->C_FindObjectsFinal(s_));
    ASSERT_EQ(1u, count);

    std::vector<CK_BYTE> n;
    ASSERT_CKR_OK(get_bytes(s_, theirs, CKA_MODULUS, n));
    host::Pkey key = host::rsa_public(n, { 0x01, 0x00, 0x01 });
    RsaAesMechanism m;
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    EXPECT_CKR(
        CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        unwrap_key(
            s_,
            theirs,
            &m.mech,
            host::rsa_aes_key_wrap(key.get(), "SHA256", host::Bytes(32, 0x22)),
            CKM_AES_CBC,
            &aes
        )
    );
}

TEST_F(unwrapping_pair_child, makes_a_token_pair)
{
    SUBPROCESS_ONLY();
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub, &priv, CK_TRUE));
}
