// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file sign_tests.cpp
///
/// C_Sign* and C_Verify* with the ECDSA mechanisms through the module ABI.
/// ECDSA signatures are randomised, so no known answer exists: the host
/// oracle (utils/host_crypto.hpp) verifies every token signature against the
/// key's CKA_EC_POINT, and the token's own verification is checked against
/// token signatures and their corruptions. Also: the raw ECDSA length rule,
/// multi-part against one-shot, init precedence and usage enforcement, the
/// sizing and lifetime rules of the operation, key survival, and that every
/// way an operation ends gives its device keys back.

#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/ec_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/leak_gate.hpp"
#include "utils/module.hpp"
#include "utils/store_dir.hpp"
#include "utils/surviving_key.hpp"

namespace
{

/// The hashing ECDSA mechanisms (multi-part capable).
constexpr CK_MECHANISM_TYPE kHashed[] = { CKM_ECDSA_SHA1,
                                          CKM_ECDSA_SHA256,
                                          CKM_ECDSA_SHA384,
                                          CKM_ECDSA_SHA512 };

/// The hash lengths CKM_ECDSA takes.
constexpr size_t kRawLengths[] = { 20, 32, 48, 64 };

} // namespace

/// A logged-in session with a fresh signing pair on P-256.
class ec_sign : public UserSession
{
  protected:
    void SetUp() override
    {
        UserSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_CKR_OK(gen_p256(s_, &pub_, &priv_));
        point_ = ec_point(s_, pub_);
        ASSERT_FALSE(point_.empty());
        host_ = host::ec_public("P-256", point_);
    }

    /// Whether the host accepts `sig` over `msg` for the pair's public key.
    bool host_verifies(
        CK_MECHANISM_TYPE mech,
        const std::vector<CK_BYTE> &msg,
        const std::vector<CK_BYTE> &sig
    )
    {
        return host::ecdsa_verify(host_.get(), ecdsa_md(mech), msg, sig);
    }

    CK_OBJECT_HANDLE pub_ = 0;
    CK_OBJECT_HANDLE priv_ = 0;
    std::vector<CK_BYTE> point_;
    host::Pkey host_;
    std::vector<CK_BYTE> msg_ = pattern(100);
};

TEST_F(ec_sign, every_curve_and_hash_signs_what_the_host_verifies)
{
    for (const EcCurve &c : ec_curves())
    {
        SCOPED_TRACE(c.name);
        CK_OBJECT_HANDLE pub = 0;
        CK_OBJECT_HANDLE priv = 0;
        ASSERT_CKR_OK(gen_ec_pair(s_, c, true, CK_FALSE, CK_TRUE, "curves", &pub, &priv));
        host::Pkey key = host::ec_public(c.name, ec_point(s_, pub));
        for (CK_MECHANISM_TYPE mech : kHashed)
        {
            SCOPED_TRACE(ecdsa_md(mech));
            std::vector<CK_BYTE> sig;
            ASSERT_CKR_OK(sign_oneshot(s_, mech, priv, msg_, sig));
            EXPECT_EQ(2 * c.coord, sig.size()) << "r || s";
            EXPECT_TRUE(host::ecdsa_verify(key.get(), ecdsa_md(mech), msg_, sig));
            EXPECT_CKR_OK(verify_oneshot(s_, mech, pub, msg_, sig)) << "the token agrees";
        }
        for (size_t len : kRawLengths)
        {
            SCOPED_TRACE(len);
            std::vector<CK_BYTE> hash = pattern(len);
            std::vector<CK_BYTE> sig;
            ASSERT_CKR_OK(sign_oneshot(s_, CKM_ECDSA, priv, hash, sig));
            // The host, like the device, truncates a hash longer than the order.
            EXPECT_TRUE(host::ecdsa_verify(key.get(), nullptr, hash, sig));
            EXPECT_CKR_OK(verify_oneshot(s_, CKM_ECDSA, pub, hash, sig));
        }
    }
}

TEST_F(ec_sign, signatures_differ_but_both_verify)
{
    std::vector<CK_BYTE> a, b;
    ASSERT_CKR_OK(sign_oneshot(s_, CKM_ECDSA_SHA256, priv_, msg_, a));
    ASSERT_CKR_OK(sign_oneshot(s_, CKM_ECDSA_SHA256, priv_, msg_, b));
    EXPECT_NE(a, b) << "ECDSA draws a fresh nonce";
    EXPECT_TRUE(host_verifies(CKM_ECDSA_SHA256, msg_, a));
    EXPECT_TRUE(host_verifies(CKM_ECDSA_SHA256, msg_, b));
}

TEST_F(ec_sign, multi_part_matches_one_shot)
{
    for (CK_MECHANISM_TYPE mech : kHashed)
    {
        SCOPED_TRACE(ecdsa_md(mech));
        for (size_t chunk : { 1, 7, 64, 100 })
        {
            std::vector<CK_BYTE> sig;
            ASSERT_CKR_OK(sign_multipart(s_, mech, priv_, msg_, chunk, sig)) << "chunk " << chunk;
            EXPECT_TRUE(host_verifies(mech, msg_, sig)) << "chunk " << chunk;
            EXPECT_CKR_OK(verify_multipart(s_, mech, pub_, msg_, chunk, sig)) << "chunk " << chunk;
        }
        std::vector<CK_BYTE> one;
        ASSERT_CKR_OK(sign_oneshot(s_, mech, priv_, msg_, one));
        EXPECT_CKR_OK(verify_multipart(s_, mech, pub_, msg_, 13, one))
            << "a one-shot signature verifies in parts";
    }
}

TEST_F(ec_sign, the_empty_message_signs_both_ways)
{
    std::vector<CK_BYTE> empty;
    std::vector<CK_BYTE> sig;
    ASSERT_CKR_OK(sign_multipart(s_, CKM_ECDSA_SHA256, priv_, empty, 1, sig)) << "zero parts";
    EXPECT_TRUE(host_verifies(CKM_ECDSA_SHA256, empty, sig));
    ASSERT_CKR_OK(sign_oneshot(s_, CKM_ECDSA_SHA256, priv_, empty, sig));
    EXPECT_TRUE(host_verifies(CKM_ECDSA_SHA256, empty, sig));
    EXPECT_CKR_OK(verify_multipart(s_, CKM_ECDSA_SHA256, pub_, empty, 1, sig));
}

TEST_F(ec_sign, verification_refuses_what_it_must)
{
    std::vector<CK_BYTE> sig;
    ASSERT_CKR_OK(sign_oneshot(s_, CKM_ECDSA_SHA256, priv_, msg_, sig));
    ASSERT_CKR_OK(verify_oneshot(s_, CKM_ECDSA_SHA256, pub_, msg_, sig));

    std::vector<CK_BYTE> flipped = sig;
    flipped[5] ^= 0x01;
    EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, CKM_ECDSA_SHA256, pub_, msg_, flipped));
    EXPECT_CKR(
        CKR_SIGNATURE_INVALID,
        verify_multipart(s_, CKM_ECDSA_SHA256, pub_, msg_, 9, flipped)
    );
    std::vector<CK_BYTE> other_msg = msg_;
    other_msg[0] ^= 0x80;
    EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, CKM_ECDSA_SHA256, pub_, other_msg, sig));
    EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, CKM_ECDSA_SHA384, pub_, msg_, sig))
        << "another hash";
    // r and s of zero, and of all ones (above the group order), are values
    // no signature has.
    std::vector<CK_BYTE> zeros(sig.size(), 0);
    EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, CKM_ECDSA_SHA256, pub_, msg_, zeros));
    EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_multipart(s_, CKM_ECDSA_SHA256, pub_, msg_, 9, zeros));
    std::vector<CK_BYTE> ones(sig.size(), 0xFF);
    EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, CKM_ECDSA_SHA256, pub_, msg_, ones));

    std::vector<CK_BYTE> truncated(sig.begin(), sig.end() - 1);
    EXPECT_CKR(
        CKR_SIGNATURE_LEN_RANGE,
        verify_oneshot(s_, CKM_ECDSA_SHA256, pub_, msg_, truncated)
    );
    std::vector<CK_BYTE> longer = sig;
    longer.push_back(0);
    EXPECT_CKR(CKR_SIGNATURE_LEN_RANGE, verify_oneshot(s_, CKM_ECDSA_SHA256, pub_, msg_, longer));
    EXPECT_CKR(
        CKR_SIGNATURE_LEN_RANGE,
        verify_multipart(s_, CKM_ECDSA_SHA256, pub_, msg_, 9, longer)
    );

    CK_OBJECT_HANDLE pub2 = 0;
    CK_OBJECT_HANDLE priv2 = 0;
    ASSERT_CKR_OK(gen_p256(s_, &pub2, &priv2));
    EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, CKM_ECDSA_SHA256, pub2, msg_, sig))
        << "another key's public half";

    // The host oracle refuses the same corruptions: it is not a rubber stamp.
    EXPECT_FALSE(host_verifies(CKM_ECDSA_SHA256, msg_, flipped));
    EXPECT_FALSE(host_verifies(CKM_ECDSA_SHA256, other_msg, sig));
}

TEST_F(ec_sign, raw_ecdsa_takes_only_the_known_hash_lengths)
{
    CK_MECHANISM raw = { CKM_ECDSA, nullptr, 0 };
    for (size_t len : { 0, 16, 28, 31, 33, 65 })
    {
        SCOPED_TRACE(len);
        std::vector<CK_BYTE> hash = pattern(len);
        CK_ULONG need = 0;
        ASSERT_CKR_OK(p11()->C_SignInit(s_, &raw, priv_));
        EXPECT_CKR(
            CKR_DATA_LEN_RANGE,
            p11()->C_Sign(s_, hash.data(), static_cast<CK_ULONG>(len), nullptr, &need)
        );
        EXPECT_CKR(
            CKR_OPERATION_NOT_INITIALIZED,
            p11()->C_Sign(s_, hash.data(), 32, nullptr, &need)
        ) << "the refusal ended the operation";
        std::vector<CK_BYTE> sig(64);
        ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &raw, pub_));
        EXPECT_CKR(
            CKR_DATA_LEN_RANGE,
            p11()->C_Verify(s_, hash.data(), static_cast<CK_ULONG>(len), sig.data(), 64)
        );
    }
}

TEST_F(ec_sign, raw_ecdsa_is_one_shot_only)
{
    CK_MECHANISM raw = { CKM_ECDSA, nullptr, 0 };
    std::vector<CK_BYTE> hash = pattern(32);
    CK_BYTE sig[64];
    CK_ULONG len = sizeof(sig);
    ASSERT_CKR_OK(p11()->C_SignInit(s_, &raw, priv_));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_SignUpdate(s_, hash.data(), 32));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Sign(s_, hash.data(), 32, sig, &len));
    ASSERT_CKR_OK(p11()->C_SignInit(s_, &raw, priv_));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_SignFinal(s_, sig, &len));
    ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &raw, pub_));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_VerifyUpdate(s_, hash.data(), 32));
    ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &raw, pub_));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_VerifyFinal(s_, sig, sizeof(sig)));
}

TEST_F(ec_sign, sizing_follows_the_two_call_rules)
{
    CK_MECHANISM m = { CKM_ECDSA_SHA256, nullptr, 0 };
    std::vector<CK_BYTE> buf(80, 0xEE);
    ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, priv_));
    CK_ULONG len = 0;
    ASSERT_CKR_OK(p11()->C_Sign(s_, msg_.data(), 100, nullptr, &len));
    EXPECT_EQ(64u, len) << "a NULL buffer learns the length";
    len = 0;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Sign(s_, msg_.data(), 100, buf.data(), &len));
    EXPECT_EQ(64u, len);
    len = 63;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Sign(s_, msg_.data(), 100, buf.data(), &len));
    EXPECT_EQ(64u, len);
    EXPECT_EQ(0xEE, buf[0]) << "nothing written";
    len = 80;
    ASSERT_CKR_OK(p11()->C_Sign(s_, msg_.data(), 100, buf.data(), &len))
        << "the operation survived";
    EXPECT_EQ(64u, len) << "a larger buffer gets the exact length";
    EXPECT_EQ(0xEE, buf[64]) << "nothing past the signature";
    buf.resize(64);
    EXPECT_TRUE(host_verifies(CKM_ECDSA_SHA256, msg_, buf));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Sign(s_, msg_.data(), 100, buf.data(), &len))
        << "success ended it";

    // The same rules on the final call.
    buf.assign(64, 0);
    ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, priv_));
    ASSERT_CKR_OK(p11()->C_SignUpdate(s_, msg_.data(), 100));
    len = 0;
    ASSERT_CKR_OK(p11()->C_SignFinal(s_, nullptr, &len));
    EXPECT_EQ(64u, len);
    len = 10;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_SignFinal(s_, buf.data(), &len));
    len = 64;
    ASSERT_CKR_OK(p11()->C_SignFinal(s_, buf.data(), &len));
    EXPECT_TRUE(host_verifies(CKM_ECDSA_SHA256, msg_, buf));
}

TEST_F(ec_sign, one_shot_and_multi_part_do_not_mix)
{
    CK_MECHANISM m = { CKM_ECDSA_SHA256, nullptr, 0 };
    CK_BYTE sig[64];
    CK_ULONG len = sizeof(sig);
    ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, priv_));
    ASSERT_CKR_OK(p11()->C_SignUpdate(s_, msg_.data(), 10));
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_Sign(s_, msg_.data(), 10, sig, &len));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_SignFinal(s_, sig, &len)) << "terminated";

    ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, priv_));
    ASSERT_CKR_OK(p11()->C_Sign(s_, msg_.data(), 10, nullptr, &len));
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_SignUpdate(s_, msg_.data(), 10));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Sign(s_, msg_.data(), 10, sig, &len));

    ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &m, pub_));
    ASSERT_CKR_OK(p11()->C_VerifyUpdate(s_, msg_.data(), 10));
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_Verify(s_, msg_.data(), 10, sig, 64));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_VerifyFinal(s_, sig, 64));
}

TEST_F(ec_sign, init_precedence_and_usage)
{
    CK_MECHANISM m = { CKM_ECDSA_SHA256, nullptr, 0 };
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, p11()->C_SignInit(kInvalidSession, &m, priv_));
    CK_MECHANISM des = { CKM_DES3_CBC, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_SignInit(s_, &des, priv_));
    CK_MECHANISM sha224 = { CKM_ECDSA_SHA224, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_SignInit(s_, &sha224, priv_));
    CK_BYTE param = 0;
    CK_MECHANISM with_param = { CKM_ECDSA_SHA256, &param, 1 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_VerifyInit(s_, &with_param, pub_));

    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_SignInit(s_, &m, kInvalidObject));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_SignInit(s_, &m, pub_))
        << "a public key does not sign";
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_VerifyInit(s_, &m, priv_))
        << "a private key does not verify";
    CK_OBJECT_HANDLE aes = 0;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "aes", &aes));
    EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_SignInit(s_, &m, aes));
    CK_MECHANISM cbc = { CKM_AES_CBC, msg_.data(), 16 };
    EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_EncryptInit(s_, &cbc, priv_))
        << "an EC key does not encrypt";

    // A public key made with C_CreateObject has no device key behind it.
    CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
    CK_KEY_TYPE kt = CKK_EC;
    std::vector<CK_BYTE> params = ec_curves()[0].params;
    CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &cls, sizeof(cls) },
                            { CKA_KEY_TYPE, &kt, sizeof(kt) },
                            { CKA_EC_PARAMS, params.data(), params.size() } };
    CK_OBJECT_HANDLE created = 0;
    ASSERT_CKR_OK(p11()->C_CreateObject(s_, tmpl, 3, &created));
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_VerifyInit(s_, &m, created));

    // CKA_VERIFY cleared on the public key, and an allowed-mechanism list.
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE off = { CKA_VERIFY, &no, sizeof(no) };
    ASSERT_CKR_OK(p11()->C_SetAttributeValue(s_, pub_, &off, 1));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_VerifyInit(s_, &m, pub_));

    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    CK_MECHANISM_TYPE only384 = CKM_ECDSA_SHA384;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE pub_tmpl[] = { { CKA_EC_PARAMS, params.data(), params.size() } };
    CK_ATTRIBUTE priv_tmpl[] = { { CKA_SIGN, &yes, sizeof(yes) },
                                 { CKA_ALLOWED_MECHANISMS, &only384, sizeof(only384) } };
    CK_MECHANISM keygen = { CKM_EC_KEY_PAIR_GEN, nullptr, 0 };
    ASSERT_CKR_OK(p11()->C_GenerateKeyPair(s_, &keygen, pub_tmpl, 1, priv_tmpl, 2, &pub, &priv));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_SignInit(s_, &m, priv));
    CK_MECHANISM m384 = { CKM_ECDSA_SHA384, nullptr, 0 };
    EXPECT_CKR_OK(p11()->C_SignInit(s_, &m384, priv));
    EXPECT_CKR(CKR_OPERATION_ACTIVE, p11()->C_VerifyInit(s_, &m384, pub))
        << "one operation at a time";
}

TEST_F(ec_sign, cancels_and_logout_end_the_operation)
{
    CK_MECHANISM m = { CKM_ECDSA_SHA256, nullptr, 0 };
    CK_BYTE sig[64];
    CK_ULONG len = sizeof(sig);
    ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, priv_));
    EXPECT_CKR_OK(p11()->C_SignInit(s_, nullptr, priv_));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Sign(s_, msg_.data(), 10, sig, &len));

    ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &m, pub_));
    EXPECT_CKR_OK(p11_3()->C_SessionCancel(s_, CKF_VERIFY));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_VerifyFinal(s_, sig, 64));

    ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, priv_));
    ASSERT_CKR_OK(p11()->C_SignUpdate(s_, msg_.data(), 10));
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_SignFinal(s_, sig, &len))
        << "the logout released the operation and its device keys";
    ASSERT_CKR_OK(login_user(s_));
}

TEST_F(ec_sign, every_way_an_operation_ends_gives_its_device_keys_back)
{
    CK_MECHANISM m = { CKM_ECDSA_SHA256, nullptr, 0 };
    CK_MECHANISM raw = { CKM_ECDSA, nullptr, 0 };
    std::vector<CK_BYTE> sig;
    ASSERT_CKR_OK(sign_oneshot(s_, CKM_ECDSA_SHA256, priv_, msg_, sig));
    CK_ULONG len = 0;
    std::vector<TerminationPath> paths = {
        { "one-shot sign",
          [&] { ASSERT_CKR_OK(sign_oneshot(s_, CKM_ECDSA_SHA256, priv_, msg_, sig)); } },
        { "multi-part verify",
          [&] { ASSERT_CKR_OK(verify_multipart(s_, CKM_ECDSA_SHA256, pub_, msg_, 50, sig)); } },
        { "probe, then bad arguments",
          [&] {
              ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, priv_));
              ASSERT_CKR_OK(p11()->C_Sign(s_, msg_.data(), 10, nullptr, &len));
              ASSERT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Sign(s_, msg_.data(), 10, nullptr, nullptr));
          } },
        { "raw length refused",
          [&] {
              ASSERT_CKR_OK(p11()->C_SignInit(s_, &raw, priv_));
              ASSERT_CKR(CKR_DATA_LEN_RANGE, p11()->C_Sign(s_, msg_.data(), 28, nullptr, &len));
          } },
        { "update then cancel",
          [&] {
              ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, priv_));
              ASSERT_CKR_OK(p11()->C_SignUpdate(s_, msg_.data(), 10));
              ASSERT_CKR_OK(p11()->C_SignInit(s_, nullptr, priv_));
          } },
        { "invalid signature",
          [&] {
              std::vector<CK_BYTE> bad(sig.size(), 0x01);
              ASSERT_CKR(
                  CKR_SIGNATURE_INVALID,
                  verify_oneshot(s_, CKM_ECDSA_SHA256, pub_, msg_, bad)
              );
          } },
        { "session close",
          [&] {
              CK_SESSION_HANDLE other = 0;
              ASSERT_CKR_OK(
                  p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &other)
              );
              ASSERT_CKR_OK(p11()->C_SignInit(other, &m, priv_));
              ASSERT_CKR_OK(p11()->C_SignUpdate(other, msg_.data(), 10));
              ASSERT_CKR_OK(p11()->C_CloseSession(other));
          } },
    };
    // The fresh operation runs on a pair that is not private, which outlives
    // the gate's logout and must still be the same key after it.
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    ASSERT_CKR_OK(
        gen_ec_pair(s_, ec_curves()[0], true, CK_FALSE, CK_FALSE, "leak-gate", &pub, &priv)
    );
    SurvivingKey survivor(s_, priv, "P-256", ec_point(s_, pub));
    ASSERT_NO_FATAL_FAILURE(survivor.record());
    std::vector<CK_BYTE> fresh_sig;
    auto fresh = [&] { return sign_oneshot(s_, CKM_ECDSA_SHA256, priv, msg_, fresh_sig); };
    ASSERT_NO_FATAL_FAILURE(leak_gate(s_, paths, fresh));
    ASSERT_NO_FATAL_FAILURE(survivor.check("the leak gate"));
}

// ---------------------------------------------------------------------------
// Key survival (see aes/survival_tests.cpp for the events)
// ---------------------------------------------------------------------------

class ec_survival : public UserSession
{
};

TEST_F(ec_survival, a_token_key_signs_for_its_point_after_logout_login)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    ASSERT_CKR_OK(
        gen_ec_pair(s_, ec_curves()[1], true, CK_TRUE, CK_TRUE, "ec-survival", &pub, &priv)
    );
    SurvivingKey survivor(s_, priv, "P-384", ec_point(s_, pub));
    ASSERT_NO_FATAL_FAILURE(survivor.record());
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    ASSERT_CKR_OK(login_user(s_));
    ASSERT_NO_FATAL_FAILURE(survivor.check("a logout and login"));
    ASSERT_CKR_OK(p11()->C_CloseAllSessions(kSlot));
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &s_)
    );
    ASSERT_CKR_OK(login_user(s_));
    survivor.rebind(s_, priv);
    ASSERT_NO_FATAL_FAILURE(survivor.check("C_CloseAllSessions"));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, pub));
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, priv));
}

class ec_survival_persist : public StoreDirFixture
{
};

TEST_F(ec_survival_persist, a_token_key_signs_for_its_point_after_finalize_initialize)
{
    CK_OBJECT_HANDLE pub = 0;
    CK_OBJECT_HANDLE priv = 0;
    ASSERT_CKR_OK(gen_ec_pair(s_, ec_curves()[2], true, CK_TRUE, CK_TRUE, "ec-persist", &pub, &priv)
    );
    std::vector<CK_BYTE> point = ec_point(s_, pub);
    SurvivingKey survivor(s_, priv, "P-521", point);
    ASSERT_NO_FATAL_FAILURE(survivor.record());
    ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
    s_ = 0;
    ASSERT_CKR_OK(p11()->C_Initialize(nullptr));
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &s_)
    );
    ASSERT_CKR_OK(login_user(s_));

    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE find[] = { { CKA_CLASS, &cls, sizeof(cls) },
                            { CKA_LABEL, const_cast<char *>("ec-persist"), 10 } };
    CK_OBJECT_HANDLE found[2] = {};
    CK_ULONG n = 0;
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s_, find, 2));
    ASSERT_CKR_OK(p11()->C_FindObjects(s_, found, 2, &n));
    ASSERT_CKR_OK(p11()->C_FindObjectsFinal(s_));
    ASSERT_EQ(1u, n);
    survivor.rebind(s_, found[0]);
    ASSERT_NO_FATAL_FAILURE(survivor.check("C_Finalize and C_Initialize"));
}
