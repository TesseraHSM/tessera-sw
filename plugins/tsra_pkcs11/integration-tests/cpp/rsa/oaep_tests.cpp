// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file oaep_tests.cpp
///
/// C_Encrypt and C_Decrypt with CKM_RSA_PKCS_OAEP through the module ABI, on
/// keys unwrapped from the host: the host encrypts and the token decrypts and
/// the other way round, on every size and OAEP hash, with and without a
/// label; the parameter rules; the length rules; one
/// CKR_ENCRYPTED_DATA_INVALID with the caller's buffer untouched for every bad
/// ciphertext; the sizing rules; the refused multi-part calls; the usage and
/// key rules; the Project Wycheproof decryption vectors; and that every way an
/// operation ends gives its device keys back. The parameter matrix is in
/// tests/rsa_params_test.c.

#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/leak_gate.hpp"
#include "utils/module.hpp"
#include "utils/rsa_helpers.hpp"
#include "wycheproof/rsa_oaep.inc"

namespace
{

/// The bytes OAEP adds to twice the hash length (RFC 8017 section 7.1.1).
constexpr size_t kOaepFixed = 2;

/// The longest message OAEP encrypts under a key of `bits` with `hash`.
size_t max_msg(size_t bits, CK_MECHANISM_TYPE hash)
{
    return (bits / 8) - (2 * host::digest(hash_name(hash), {}).size()) - kOaepFixed;
}

/// A byte no result has, to see what a call wrote.
constexpr CK_BYTE kUntouched = 0xEE;

/// The hash mechanism of an OpenSSL digest name.
CK_MECHANISM_TYPE hash_of(const std::string &md)
{
    return (md == "SHA384") ? CKM_SHA384 : (md == "SHA512") ? CKM_SHA512 : CKM_SHA256;
}

} // namespace

/// A logged-in session with an RSA-2048 decrypting pair unwrapped from the host.
class rsa_oaep : public PrivateUnwrapSession
{
  protected:
    void SetUp() override
    {
        PrivateUnwrapSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_NO_FATAL_FAILURE(unwrap_pair(host_rsa(2048), CKK_RSA, CKA_DECRYPT, &pair_));
    }

    UnwrappedPair pair_;
};

TEST_F(rsa_oaep, the_host_and_the_token_decrypt_each_other)
{
    for (size_t bits : kRsaSizes)
    {
        SCOPED_TRACE(bits);
        EVP_PKEY *key = host_rsa(bits);
        UnwrappedPair pair;
        ASSERT_NO_FATAL_FAILURE(unwrap_pair(key, CKK_RSA, CKA_DECRYPT, &pair));
        for (CK_MECHANISM_TYPE hash : { CKM_SHA256, CKM_SHA384, CKM_SHA512 })
        {
            for (const host::Bytes &label : { host::Bytes(), host::Bytes{ 'l', 'a', 'b' } })
            {
                SCOPED_TRACE(std::string(hash_name(hash)) + (label.empty() ? "" : " labelled"));
                OaepMechanism m(hash, label);
                std::vector<CK_BYTE> msg = pattern(max_msg(bits, hash));
                host::Bytes ct = host::rsa_oaep_encrypt(key, hash_name(hash), msg, label);
                std::vector<CK_BYTE> back;
                ASSERT_CKR_OK(crypt_oneshot(s_, false, &m.mech, pair.priv, ct, back));
                EXPECT_EQ(msg, back) << "the token decrypts the host's ciphertext";
                std::vector<CK_BYTE> token_ct;
                ASSERT_CKR_OK(crypt_oneshot(s_, true, &m.mech, pair.pub, msg, token_ct));
                EXPECT_EQ(bits / 8, token_ct.size()) << "a ciphertext is one modulus long";
                EXPECT_EQ(msg, host::rsa_oaep_decrypt(key, hash_name(hash), token_ct, label))
                    << "the host decrypts the token's ciphertext";
            }
        }
    }
}

TEST_F(rsa_oaep, an_empty_message_and_an_empty_label)
{
    OaepMechanism m;
    std::vector<CK_BYTE> ct;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &m.mech, pair_.pub, {}, ct));
    std::vector<CK_BYTE> back(4, kUntouched);
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &m.mech, pair_.priv, ct, back));
    EXPECT_TRUE(back.empty());
    // A label pointer with a length of 0 is no label.
    CK_BYTE unused = 0;
    m.params.pSourceData = &unused;
    m.params.ulSourceDataLen = 0;
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &m.mech, pair_.priv, ct, back)) << "an empty label";
}

TEST_F(rsa_oaep, parameter_rules)
{
    struct Case
    {
        const char *what;
        void (*edit)(OaepMechanism &);
        CK_RV want;
    } cases[] = {
        { "SHA-1",
          [](OaepMechanism &o) {
              o.params.hashAlg = CKM_SHA_1;
              o.params.mgf = CKG_MGF1_SHA1;
          },
          CKR_MECHANISM_PARAM_INVALID },
        { "SHA-224",
          [](OaepMechanism &o) {
              o.params.hashAlg = CKM_SHA224;
              o.params.mgf = CKG_MGF1_SHA224;
          },
          CKR_MECHANISM_PARAM_INVALID },
        { "MGF1 with another hash",
          [](OaepMechanism &o) { o.params.mgf = CKG_MGF1_SHA384; },
          CKR_MECHANISM_PARAM_INVALID },
        { "no source", [](OaepMechanism &o) { o.params.source = 0; }, CKR_MECHANISM_PARAM_INVALID },
        { "a NULL label with a length",
          [](OaepMechanism &o) { o.params.ulSourceDataLen = 4; },
          CKR_MECHANISM_PARAM_INVALID },
        { "no parameter",
          [](OaepMechanism &o) {
              o.mech.pParameter = nullptr;
              o.mech.ulParameterLen = 0;
          },
          CKR_MECHANISM_PARAM_INVALID },
        { "a short parameter",
          [](OaepMechanism &o) { o.mech.ulParameterLen = sizeof(o.params) - 1; },
          CKR_MECHANISM_PARAM_INVALID },
        { "the control", [](OaepMechanism &) {}, CKR_OK },
    };
    for (const Case &c : cases)
    {
        SCOPED_TRACE(c.what);
        OaepMechanism m;
        c.edit(m);
        EXPECT_CKR(c.want, p11()->C_EncryptInit(s_, &m.mech, pair_.pub))
            << "SHA-2 OAEP with MGF1 of the same hash only";
        EXPECT_CKR_OK(p11()->C_EncryptInit(s_, nullptr, pair_.pub));
        EXPECT_CKR(c.want, p11()->C_DecryptInit(s_, &m.mech, pair_.priv));
        EXPECT_CKR_OK(p11()->C_DecryptInit(s_, nullptr, pair_.priv));
    }
    CK_MECHANISM v15 = { CKM_RSA_PKCS, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_DecryptInit(s_, &v15, pair_.priv))
        << "no PKCS#1 v1.5 decryption: it would be a padding oracle";
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_EncryptInit(s_, &v15, pair_.pub));
}

TEST_F(rsa_oaep, length_rules)
{
    for (CK_MECHANISM_TYPE hash : { CKM_SHA256, CKM_SHA512 })
    {
        SCOPED_TRACE(hash_name(hash));
        OaepMechanism m(hash);
        std::vector<CK_BYTE> out;
        std::vector<CK_BYTE> longest = pattern(max_msg(2048, hash));
        EXPECT_CKR_OK(crypt_oneshot(s_, true, &m.mech, pair_.pub, longest, out));
        std::vector<CK_BYTE> too_long = pattern(longest.size() + 1);
        EXPECT_CKR(CKR_DATA_LEN_RANGE, crypt_oneshot(s_, true, &m.mech, pair_.pub, too_long, out))
            << "a message is at most k - 2hLen - 2 bytes";
        for (size_t len : { size_t{ 0 }, size_t{ 255 }, size_t{ 257 }, size_t{ 512 } })
        {
            EXPECT_CKR(
                CKR_ENCRYPTED_DATA_LEN_RANGE,
                crypt_oneshot(s_, false, &m.mech, pair_.priv, pattern(len), out)
            ) << "a ciphertext of "
              << len << " bytes is not one modulus long";
        }
    }
}

TEST_F(rsa_oaep, a_bad_ciphertext_is_one_error_and_leaves_the_buffer_untouched)
{
    host::Bytes label = { 'r', 'i', 'g', 'h', 't' };
    host::Bytes ct = host::rsa_oaep_encrypt(host_rsa(2048), "SHA256", pattern(32), label);
    host::Bytes flipped = ct;
    flipped[100] ^= 0x01;
    host::Bytes zeros(ct.size(), 0);
    host::Bytes above(ct.size(), 0xFF);
    host::Bytes other_hash = host::rsa_oaep_encrypt(host_rsa(2048), "SHA384", pattern(32), label);
    struct
    {
        const char *what;
        const host::Bytes &ct;
        host::Bytes label;
    } cases[] = {
        { "a flipped byte", flipped, label },
        { "the wrong label", ct, host::Bytes{ 'w', 'r', 'o', 'n', 'g' } },
        { "no label", ct, host::Bytes() },
        { "another OAEP hash", other_hash, label },
        { "all zeros", zeros, label },
        { "above the modulus", above, label },
    };
    for (const auto &c : cases)
    {
        SCOPED_TRACE(c.what);
        OaepMechanism m(CKM_SHA256, c.label);
        ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &m.mech, pair_.priv));
        std::vector<CK_BYTE> out(256, kUntouched);
        CK_ULONG len = static_cast<CK_ULONG>(out.size());
        EXPECT_CKR(
            CKR_ENCRYPTED_DATA_INVALID,
            p11()->C_Decrypt(
                s_,
                const_cast<CK_BYTE_PTR>(c.ct.data()),
                static_cast<CK_ULONG>(c.ct.size()),
                out.data(),
                &len
            )
        ) << "one code for every failure: no padding oracle";
        EXPECT_EQ(std::vector<CK_BYTE>(256, kUntouched), out)
            << "not even the raw RSA block reaches the caller";
        EXPECT_CKR(
            CKR_OPERATION_NOT_INITIALIZED,
            p11()->C_Decrypt(s_, out.data(), 256, out.data(), &len)
        ) << "the failure ended the operation";
    }
    OaepMechanism m(CKM_SHA256, label);
    std::vector<CK_BYTE> back;
    ASSERT_CKR_OK(crypt_oneshot(s_, false, &m.mech, pair_.priv, ct, back)) << "the control";
    EXPECT_EQ(pattern(32), back);
}

TEST_F(rsa_oaep, sizing_follows_the_two_call_rules)
{
    OaepMechanism m;
    std::vector<CK_BYTE> msg = pattern(20);
    std::vector<CK_BYTE> buf(300, kUntouched);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &m.mech, pair_.pub));
    CK_ULONG len = 0;
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, msg.data(), 20, nullptr, &len));
    EXPECT_EQ(256u, len) << "a ciphertext is one modulus long";
    len = 255;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Encrypt(s_, msg.data(), 20, buf.data(), &len));
    EXPECT_EQ(256u, len);
    EXPECT_EQ(kUntouched, buf[0]) << "nothing written";
    len = 300;
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, msg.data(), 20, buf.data(), &len))
        << "the operation survived";
    EXPECT_EQ(256u, len) << "a larger buffer gets the exact length";
    EXPECT_EQ(kUntouched, buf[256]);
    std::vector<CK_BYTE> ct(buf.begin(), buf.begin() + 256);

    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &m.mech, pair_.priv));
    len = 0;
    ASSERT_CKR_OK(p11()->C_Decrypt(s_, ct.data(), 256, nullptr, &len));
    EXPECT_EQ(max_msg(2048, CKM_SHA256), len) << "a probe learns the longest message";
    std::fill(buf.begin(), buf.end(), kUntouched);
    len = 19;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Decrypt(s_, ct.data(), 256, buf.data(), &len));
    EXPECT_EQ(20u, len) << "a short buffer learns the exact length";
    EXPECT_EQ(std::vector<CK_BYTE>(300, kUntouched), buf) << "nothing written";
    len = 20;
    ASSERT_CKR_OK(p11()->C_Decrypt(s_, ct.data(), 256, buf.data(), &len))
        << "the operation survived";
    EXPECT_EQ(20u, len);
    EXPECT_EQ(msg, std::vector<CK_BYTE>(buf.begin(), buf.begin() + 20));
    EXPECT_EQ(kUntouched, buf[20]);
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_Decrypt(s_, ct.data(), 256, buf.data(), &len)
    ) << "success ended it";
}

TEST_F(rsa_oaep, input_and_output_may_share_a_buffer)
{
    OaepMechanism m;
    std::vector<CK_BYTE> buf = pattern(256);
    std::vector<CK_BYTE> msg(buf.begin(), buf.begin() + 40);
    CK_ULONG len = 256;
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &m.mech, pair_.pub));
    ASSERT_CKR_OK(p11()->C_Encrypt(s_, buf.data(), 40, buf.data(), &len));
    ASSERT_EQ(256u, len);
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &m.mech, pair_.priv));
    ASSERT_CKR_OK(p11()->C_Decrypt(s_, buf.data(), 256, buf.data(), &len));
    ASSERT_EQ(40u, len);
    EXPECT_EQ(msg, std::vector<CK_BYTE>(buf.begin(), buf.begin() + 40));
}

TEST_F(rsa_oaep, oaep_is_one_shot_only)
{
    OaepMechanism m;
    CK_BYTE in[16] = {};
    CK_BYTE out[256];
    CK_ULONG len = sizeof(out);
    ASSERT_CKR_OK(p11()->C_EncryptInit(s_, &m.mech, pair_.pub));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_EncryptUpdate(s_, in, 16, out, &len))
        << "the SDK has no OAEP stream";
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Encrypt(s_, in, 16, out, &len))
        << "the refusal ended the operation";
    ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &m.mech, pair_.priv));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_DecryptFinal(s_, out, &len));
}

TEST_F(rsa_oaep, usage_and_key_rules)
{
    OaepMechanism m;
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_DecryptInit(s_, &m.mech, pair_.pub))
        << "a public key does not decrypt";
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_EncryptInit(s_, &m.mech, pair_.priv))
        << "a private key does not encrypt";
    UnwrappedPair sign;
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(host_rsa(2048), CKK_RSA, CKA_SIGN, &sign));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_DecryptInit(s_, &m.mech, sign.priv))
        << "a signing key does not decrypt";
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_EncryptInit(s_, &m.mech, sign.pub));
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "aes", &aes));
    EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_EncryptInit(s_, &m.mech, aes));
    CK_BYTE iv[kAesBlock] = {};
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
    EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_EncryptInit(s_, &cbc, pair_.pub))
        << "an RSA key does not run AES";
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_DecryptInit(s_, &m.mech, priv_))
        << "the unwrapping key does not decrypt: its usage is judged first";
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_EncryptInit(s_, &m.mech, pub_));
}

TEST_F(rsa_oaep, wycheproof_vectors)
{
    ASSERT_FALSE(std::empty(vectors::kWycheproofRsaOaep));
    const char *loaded = nullptr;
    UnwrappedPair pair;
    size_t valid = 0;
    size_t refused = 0;
    for (const vectors::WycheproofOaep &v : vectors::kWycheproofRsaOaep)
    {
        SCOPED_TRACE(std::string(v.md) + " tcId " + std::to_string(v.tc_id));
        if (v.pkcs8 != loaded)
        {
            host::Pkey key = host::private_key(vectors::hex(v.pkcs8));
            ASSERT_NO_FATAL_FAILURE(unwrap_pair(key.get(), CKK_RSA, CKA_DECRYPT, &pair));
            loaded = v.pkcs8;
        }
        CK_ULONG bits = 0;
        ASSERT_CKR_OK(get_attr(s_, pair.pub, CKA_MODULUS_BITS, &bits));
        OaepMechanism m(hash_of(v.md), vectors::hex(v.label));
        host::Bytes ct = vectors::hex(v.ct);
        std::vector<CK_BYTE> out;
        CK_RV rv = crypt_oneshot(s_, false, &m.mech, pair.priv, ct, out);
        if (v.valid)
        {
            EXPECT_CKR_OK(rv);
            EXPECT_EQ(vectors::hex(v.msg), out);
            valid += (rv == CKR_OK) ? 1 : 0;
            continue;
        }
        CK_RV want =
            (ct.size() == (bits / 8)) ? CKR_ENCRYPTED_DATA_INVALID : CKR_ENCRYPTED_DATA_LEN_RANGE;
        EXPECT_CKR(want, rv) << "an invalid vector does not decrypt";
        refused += (rv == want) ? 1 : 0;
    }
    EXPECT_NE(0u, valid);
    EXPECT_NE(0u, refused);
}

TEST_F(rsa_oaep, every_way_an_operation_ends_gives_its_device_keys_back)
{
    OaepMechanism m;
    std::vector<CK_BYTE> ct;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &m.mech, pair_.pub, pattern(16), ct));
    std::vector<CK_BYTE> bad = ct;
    bad[7] ^= 0x01;
    std::vector<CK_BYTE> out;
    CK_ULONG len = 0;
    std::vector<TerminationPath> paths = {
        { "one-shot decrypt",
          [&] { ASSERT_CKR_OK(crypt_oneshot(s_, false, &m.mech, pair_.priv, ct, out)); } },
        { "a bad ciphertext",
          [&] {
              ASSERT_CKR(
                  CKR_ENCRYPTED_DATA_INVALID,
                  crypt_oneshot(s_, false, &m.mech, pair_.priv, bad, out)
              );
          } },
        { "probe, then a refused update",
          [&] {
              ASSERT_CKR_OK(p11()->C_DecryptInit(s_, &m.mech, pair_.priv));
              ASSERT_CKR_OK(p11()->C_Decrypt(s_, ct.data(), 256, nullptr, &len));
              ASSERT_CKR(
                  CKR_OPERATION_ACTIVE,
                  p11()->C_DecryptUpdate(s_, ct.data(), 256, nullptr, &len)
              );
          } },
    };
    PrivateTemplate t(CKK_RSA, CKA_DECRYPT, CK_FALSE, "leak-gate", CK_FALSE);
    CK_OBJECT_HANDLE fresh_key = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(unwrap_with_template(s_, priv_, blob_of(host_rsa(2048)), t.attrs, &fresh_key));
    std::vector<CK_BYTE> fresh_out;
    auto fresh = [&] { return crypt_oneshot(s_, false, &m.mech, fresh_key, ct, fresh_out); };
    ASSERT_NO_FATAL_FAILURE(leak_gate(s_, paths, fresh));
    EXPECT_EQ(pattern(16), fresh_out) << "still the same key";
}
