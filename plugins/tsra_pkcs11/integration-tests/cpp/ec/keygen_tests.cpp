// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file keygen_tests.cpp
///
/// C_GenerateKeyPair with CKM_EC_KEY_PAIR_GEN through the module ABI: the
/// login gate and argument/mechanism/session precedence, the template
/// verdicts as a caller sees them (the full CK_RV matrix is unit-tested in
/// tests/ec_template_test.c; here a representative row per verdict proves the
/// wiring), the SIGN-or-DERIVE rule, the attributes both halves carry, a
/// CKA_EC_POINT the host accepts as a point on the curve, the sizing of the
/// EC attributes, visibility while logged out, and that generation gives its
/// device resources back.

#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/ec_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/leak_gate.hpp"
#include "utils/module.hpp"

namespace
{

CK_MECHANISM g_ec_keygen = { CKM_EC_KEY_PAIR_GEN, nullptr, 0 };
CK_BBOOL g_true = CK_TRUE;
CK_BBOOL g_false = CK_FALSE;

/// C_GenerateKeyPair for a P-256 signing pair with `pub_extra` and
/// `priv_extra` (each may be nullptr) added to its templates.
CK_RV gen_with(CK_SESSION_HANDLE s, const CK_ATTRIBUTE *pub_extra, const CK_ATTRIBUTE *priv_extra)
{
    std::vector<CK_BYTE> params = ec_curves()[0].params;
    CK_ATTRIBUTE pub[] = { { CKA_EC_PARAMS, params.data(), params.size() }, {} };
    CK_ATTRIBUTE priv[] = { { CKA_SIGN, &g_true, sizeof(g_true) }, {} };
    if (pub_extra != nullptr)
    {
        pub[1] = *pub_extra;
    }
    if (priv_extra != nullptr)
    {
        priv[1] = *priv_extra;
    }
    CK_OBJECT_HANDLE hpub = 0;
    CK_OBJECT_HANDLE hpriv = 0;
    return p11()->C_GenerateKeyPair(
        s,
        &g_ec_keygen,
        pub,
        (pub_extra != nullptr) ? 2 : 1,
        priv,
        (priv_extra != nullptr) ? 2 : 1,
        &hpub,
        &hpriv
    );
}

} // namespace

// ---------------------------------------------------------------------------
// Logged out
// ---------------------------------------------------------------------------

class ec_keygen_public : public PublicSession
{
};

TEST_F(ec_keygen_public, requires_login)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    EXPECT_CKR(CKR_USER_NOT_LOGGED_IN, gen_p256(s_, &pub, &priv));
}

TEST_F(ec_keygen_public, malformed_request_is_reported_before_login_state)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    CK_ATTRIBUTE t[] = { { CKA_SIGN, &g_true, sizeof(g_true) } };
    EXPECT_CKR(
        CKR_ARGUMENTS_BAD,
        p11()->C_GenerateKeyPair(s_, &g_ec_keygen, t, 1, t, 1, nullptr, &priv)
    );
    EXPECT_CKR(
        CKR_ARGUMENTS_BAD,
        p11()->C_GenerateKeyPair(s_, &g_ec_keygen, t, 1, t, 1, &pub, nullptr)
    );
    EXPECT_CKR(
        CKR_ARGUMENTS_BAD,
        p11()->C_GenerateKeyPair(s_, &g_ec_keygen, nullptr, 1, t, 1, &pub, &priv)
    );
    EXPECT_CKR(
        CKR_ARGUMENTS_BAD,
        p11()->C_GenerateKeyPair(s_, &g_ec_keygen, t, 1, nullptr, 1, &pub, &priv)
    );
    CK_MECHANISM dsa = { CKM_DSA_KEY_PAIR_GEN, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_GenerateKeyPair(s_, &dsa, t, 1, t, 1, &pub, &priv));
    CK_BYTE param = 0;
    CK_MECHANISM with_param = { CKM_EC_KEY_PAIR_GEN, &param, 1 };
    EXPECT_CKR(
        CKR_MECHANISM_PARAM_INVALID,
        p11()->C_GenerateKeyPair(s_, &with_param, t, 1, t, 1, &pub, &priv)
    );
}

// ---------------------------------------------------------------------------
// Logged in
// ---------------------------------------------------------------------------

class ec_keygen : public UserSession
{
};

TEST_F(ec_keygen, session_handle_is_checked_first)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_GenerateKeyPair(kInvalidSession, nullptr, nullptr, 3, nullptr, 3, nullptr, nullptr)
    );
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, gen_p256(kInvalidSession, &pub, &priv));
}

TEST_F(ec_keygen, every_curve_gives_a_point_on_the_curve)
{
    for (const EcCurve &c : ec_curves())
    {
        SCOPED_TRACE(c.name);
        CK_OBJECT_HANDLE pub = 0;
        CK_OBJECT_HANDLE priv = 0;
        ASSERT_CKR_OK(gen_ec_pair(s_, c, true, CK_FALSE, CK_TRUE, "curve", &pub, &priv));
        std::vector<CK_BYTE> der;
        ASSERT_CKR_OK(get_bytes(s_, pub, CKA_EC_POINT, der));
        size_t point_len = 1 + (2 * c.coord);
        // A DER OCTET STRING around the uncompressed point: 67, 99 or 136 bytes.
        EXPECT_EQ(point_len + ((point_len < 0x80) ? 2 : 3), der.size());
        std::vector<CK_BYTE> point = ec_point(s_, pub);
        ASSERT_EQ(point_len, point.size());
        EXPECT_EQ(0x04, point[0]) << "uncompressed";
        EXPECT_NO_THROW(host::ec_public(c.name, point)) << "the point is on the curve";

        for (CK_OBJECT_HANDLE h : { pub, priv })
        {
            std::vector<CK_BYTE> params;
            ASSERT_CKR_OK(get_bytes(s_, h, CKA_EC_PARAMS, params));
            EXPECT_EQ(c.params, params);
        }
    }
}

TEST_F(ec_keygen, two_pairs_have_different_points)
{
    CK_OBJECT_HANDLE pub1 = 0, priv1 = 0, pub2 = 0, priv2 = 0;
    ASSERT_CKR_OK(gen_p256(s_, &pub1, &priv1));
    ASSERT_CKR_OK(gen_p256(s_, &pub2, &priv2));
    EXPECT_NE(ec_point(s_, pub1), ec_point(s_, pub2));
}

TEST_F(ec_keygen, the_pair_carries_its_attributes)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    ASSERT_CKR_OK(gen_p256(s_, &pub, &priv));

    CK_OBJECT_CLASS cls = 0;
    CK_KEY_TYPE kt = 0;
    CK_MECHANISM_TYPE kgm = 0;
    ASSERT_CKR_OK(get_attr(s_, pub, CKA_CLASS, &cls));
    EXPECT_EQ(static_cast<CK_OBJECT_CLASS>(CKO_PUBLIC_KEY), cls);
    ASSERT_CKR_OK(get_attr(s_, priv, CKA_CLASS, &cls));
    EXPECT_EQ(static_cast<CK_OBJECT_CLASS>(CKO_PRIVATE_KEY), cls);
    for (CK_OBJECT_HANDLE h : { pub, priv })
    {
        ASSERT_CKR_OK(get_attr(s_, h, CKA_KEY_TYPE, &kt));
        EXPECT_EQ(static_cast<CK_KEY_TYPE>(CKK_EC), kt);
        ASSERT_CKR_OK(get_attr(s_, h, CKA_KEY_GEN_MECHANISM, &kgm));
        EXPECT_EQ(static_cast<CK_MECHANISM_TYPE>(CKM_EC_KEY_PAIR_GEN), kgm);
    }

    struct Flag
    {
        CK_OBJECT_HANDLE h;
        CK_ATTRIBUTE_TYPE type;
        CK_BBOOL want;
    };
    for (Flag f : { Flag{ pub, CKA_VERIFY, CK_TRUE },
                    Flag{ pub, CKA_DERIVE, CK_FALSE },
                    Flag{ pub, CKA_PRIVATE, CK_FALSE },
                    Flag{ pub, CKA_LOCAL, CK_TRUE },
                    Flag{ priv, CKA_SIGN, CK_TRUE },
                    Flag{ priv, CKA_DERIVE, CK_FALSE },
                    Flag{ priv, CKA_PRIVATE, CK_TRUE },
                    Flag{ priv, CKA_LOCAL, CK_TRUE },
                    Flag{ priv, CKA_SENSITIVE, CK_TRUE },
                    Flag{ priv, CKA_ALWAYS_SENSITIVE, CK_TRUE },
                    Flag{ priv, CKA_EXTRACTABLE, CK_FALSE },
                    Flag{ priv, CKA_NEVER_EXTRACTABLE, CK_TRUE } })
    {
        CK_BBOOL v = 0x55;
        ASSERT_CKR_OK(get_attr(s_, f.h, f.type, &v)) << "attribute 0x" << std::hex << f.type;
        EXPECT_EQ(f.want, v) << "attribute 0x" << std::hex << f.type;
    }

    // The private value never leaves the device, and the public key has none.
    CK_BYTE raw[80];
    std::memset(raw, 0xEE, sizeof(raw));
    CK_ATTRIBUTE value = { CKA_VALUE, raw, sizeof(raw) };
    EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, p11()->C_GetAttributeValue(s_, priv, &value, 1));
    EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, value.ulValueLen);
    EXPECT_EQ(0xEE, raw[0]) << "the buffer must not have been written";
    std::vector<CK_BYTE> none;
    EXPECT_CKR(CKR_ATTRIBUTE_TYPE_INVALID, get_bytes(s_, priv, CKA_EC_POINT, none));
}

TEST_F(ec_keygen, ec_attributes_follow_the_sizing_rules)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    ASSERT_CKR_OK(gen_ec_pair(s_, ec_curves()[2], true, CK_FALSE, CK_TRUE, "sizing", &pub, &priv));
    for (CK_ATTRIBUTE_TYPE type : { CKA_EC_POINT, CKA_EC_PARAMS })
    {
        SCOPED_TRACE(type);
        CK_ATTRIBUTE a = { type, nullptr, 0 };
        ASSERT_CKR_OK(p11()->C_GetAttributeValue(s_, pub, &a, 1));
        CK_ULONG need = a.ulValueLen;
        ASSERT_GT(need, 1u);
        std::vector<CK_BYTE> buf(need + 8, 0xEE);

        a = { type, buf.data(), 0 };
        EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_GetAttributeValue(s_, pub, &a, 1));
        EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, a.ulValueLen);
        a = { type, buf.data(), need - 1 };
        EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_GetAttributeValue(s_, pub, &a, 1));
        EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, a.ulValueLen);
        a = { type, buf.data(), need };
        EXPECT_CKR_OK(p11()->C_GetAttributeValue(s_, pub, &a, 1));
        EXPECT_EQ(need, a.ulValueLen);
        a = { type, buf.data(), need + 8 };
        EXPECT_CKR_OK(p11()->C_GetAttributeValue(s_, pub, &a, 1));
        EXPECT_EQ(need, a.ulValueLen) << "a larger buffer reports the exact length";
    }
}

TEST_F(ec_keygen, sign_and_derive_together_or_neither_is_refused)
{
    // The device makes a signing or a deriving key, never both.
    CK_ATTRIBUTE derive = { CKA_DERIVE, &g_true, sizeof(g_true) };
    EXPECT_CKR(CKR_TEMPLATE_INCONSISTENT, gen_with(s_, nullptr, &derive));

    std::vector<CK_BYTE> params = ec_curves()[0].params;
    CK_ATTRIBUTE pub[] = { { CKA_EC_PARAMS, params.data(), params.size() } };
    CK_ATTRIBUTE label[] = { { CKA_LABEL, const_cast<char *>("neither"), 7 } };
    CK_OBJECT_HANDLE hpub = 0;
    CK_OBJECT_HANDLE hpriv = 0;
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        p11()->C_GenerateKeyPair(s_, &g_ec_keygen, pub, 1, label, 1, &hpub, &hpriv)
    );
}

TEST_F(ec_keygen, a_deriving_pair_derives_and_cannot_sign)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    ASSERT_CKR_OK(gen_ec_pair(s_, ec_curves()[1], false, CK_FALSE, CK_TRUE, "derive", &pub, &priv));
    CK_BBOOL sign = 0x55, derive = 0x55, verify = 0x55;
    ASSERT_CKR_OK(get_attr(s_, priv, CKA_SIGN, &sign));
    ASSERT_CKR_OK(get_attr(s_, priv, CKA_DERIVE, &derive));
    ASSERT_CKR_OK(get_attr(s_, pub, CKA_VERIFY, &verify));
    EXPECT_EQ(CK_FALSE, sign);
    EXPECT_EQ(CK_TRUE, derive);
    EXPECT_EQ(CK_FALSE, verify);
    CK_MECHANISM ecdsa = { CKM_ECDSA_SHA384, nullptr, 0 };
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_SignInit(s_, &ecdsa, priv));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_VerifyInit(s_, &ecdsa, pub));
}

TEST_F(ec_keygen, template_verdicts_reach_the_caller)
{
    CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
    CK_KEY_TYPE rsa = CKK_RSA;
    CK_BYTE point[65] = { 0x04 };
    CK_ULONG wide = 1;
    CK_ATTRIBUTE secret_class = { CKA_CLASS, &secret, sizeof(secret) };
    CK_ATTRIBUTE rsa_type = { CKA_KEY_TYPE, &rsa, sizeof(rsa) };
    CK_ATTRIBUTE ec_point_attr = { CKA_EC_POINT, point, sizeof(point) };
    CK_ATTRIBUTE not_sensitive = { CKA_SENSITIVE, &g_false, sizeof(g_false) };
    CK_ATTRIBUTE extractable = { CKA_EXTRACTABLE, &g_true, sizeof(g_true) };
    CK_ATTRIBUTE local = { CKA_LOCAL, &g_true, sizeof(g_true) };
    CK_ATTRIBUTE wide_token = { CKA_TOKEN, &wide, sizeof(wide) };
    CK_ATTRIBUTE label = { CKA_LABEL, const_cast<char *>("ok"), 2 };
    EXPECT_CKR(CKR_TEMPLATE_INCONSISTENT, gen_with(s_, &secret_class, nullptr));
    EXPECT_CKR(CKR_TEMPLATE_INCONSISTENT, gen_with(s_, nullptr, &rsa_type));
    EXPECT_CKR(CKR_TEMPLATE_INCONSISTENT, gen_with(s_, &ec_point_attr, nullptr));
    EXPECT_CKR(CKR_TEMPLATE_INCONSISTENT, gen_with(s_, nullptr, &not_sensitive));
    EXPECT_CKR(CKR_TEMPLATE_INCONSISTENT, gen_with(s_, nullptr, &extractable));
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, gen_with(s_, nullptr, &local));
    EXPECT_CKR(CKR_ATTRIBUTE_VALUE_INVALID, gen_with(s_, &wide_token, nullptr));
    EXPECT_CKR_OK(gen_with(s_, &label, &label));
}

TEST_F(ec_keygen, curve_parameters_are_judged)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    CK_ATTRIBUTE sign[] = { { CKA_SIGN, &g_true, sizeof(g_true) } };
    CK_BYTE secp256k1[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a };
    CK_ATTRIBUTE k1[] = { { CKA_EC_PARAMS, secp256k1, sizeof(secp256k1) } };
    EXPECT_CKR(
        CKR_CURVE_NOT_SUPPORTED,
        p11()->C_GenerateKeyPair(s_, &g_ec_keygen, k1, 1, sign, 1, &pub, &priv)
    );
    CK_ATTRIBUTE truncated[] = { { CKA_EC_PARAMS, secp256k1, 4 } };
    EXPECT_CKR(
        CKR_ATTRIBUTE_VALUE_INVALID,
        p11()->C_GenerateKeyPair(s_, &g_ec_keygen, truncated, 1, sign, 1, &pub, &priv)
    );
    EXPECT_CKR(
        CKR_TEMPLATE_INCOMPLETE,
        p11()->C_GenerateKeyPair(s_, &g_ec_keygen, nullptr, 0, sign, 1, &pub, &priv)
    );
}

TEST_F(ec_keygen, token_pair_needs_a_read_write_session)
{
    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    EXPECT_CKR(
        CKR_SESSION_READ_ONLY,
        gen_ec_pair(ro, ec_curves()[0], true, CK_TRUE, CK_TRUE, "ro", &pub, &priv)
    );
    EXPECT_CKR_OK(gen_ec_pair(ro, ec_curves()[0], true, CK_FALSE, CK_TRUE, "ro", &pub, &priv))
        << "session objects need no read/write session";
    EXPECT_CKR_OK(p11()->C_CloseSession(ro));
}

TEST_F(ec_keygen, the_public_key_is_visible_while_logged_out)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    ASSERT_CKR_OK(gen_ec_pair(s_, ec_curves()[0], true, CK_TRUE, CK_TRUE, "visible", &pub, &priv));
    std::vector<CK_BYTE> point = ec_point(s_, pub);
    ASSERT_FALSE(point.empty());
    ASSERT_CKR_OK(p11()->C_Logout(s_));

    EXPECT_EQ(point, ec_point(s_, pub)) << "a public token key is readable while logged out";
    CK_KEY_TYPE kt = 0;
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, get_attr(s_, priv, CKA_KEY_TYPE, &kt))
        << "the private key is not visible";

    ASSERT_CKR_OK(login_user(s_));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, pub));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, priv));
}

TEST_F(ec_keygen, generation_gives_its_device_keys_back)
{
    // Each generation holds two device keys until it has read back the
    // masked blob. A refusal after the device made the pair (a record over
    // the file store's limit) must give them back as well.
    std::string huge(300 * 1024, 'x');
    std::vector<TerminationPath> paths = {
        { "generate and destroy",
          [&] {
              CK_OBJECT_HANDLE pub = 0;
              CK_OBJECT_HANDLE priv = 0;
              ASSERT_CKR_OK(gen_p256(s_, &pub, &priv));
              ASSERT_CKR_OK(p11()->C_DestroyObject(s_, pub));
              ASSERT_CKR_OK(p11()->C_DestroyObject(s_, priv));
          } },
        { "a token pair over the record limit",
          [&] {
              CK_OBJECT_HANDLE pub = 0;
              CK_OBJECT_HANDLE priv = 0;
              CK_RV rv = gen_ec_pair(
                  s_,
                  ec_curves()[0],
                  true,
                  CK_TRUE,
                  CK_TRUE,
                  huge.c_str(),
                  &pub,
                  &priv
              );
              if (rv == CKR_OK) /* the memory store has no record limit */
              {
                  ASSERT_CKR_OK(p11()->C_DestroyObject(s_, pub));
                  ASSERT_CKR_OK(p11()->C_DestroyObject(s_, priv));
              }
              else
              {
                  ASSERT_CKR(CKR_DEVICE_MEMORY, rv);
              }
          } },
    };
    auto fresh = [&] {
        CK_OBJECT_HANDLE pub = 0;
        CK_OBJECT_HANDLE priv = 0;
        CK_RV rv = gen_p256(s_, &pub, &priv);
        std::vector<CK_BYTE> sig;
        return (rv == CKR_OK) ? sign_oneshot(s_, CKM_ECDSA_SHA256, priv, { 'a' }, sig) : rv;
    };
    ASSERT_NO_FATAL_FAILURE(leak_gate(s_, paths, fresh));
}
