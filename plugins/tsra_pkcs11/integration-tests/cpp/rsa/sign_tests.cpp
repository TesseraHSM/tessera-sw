// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file sign_tests.cpp
///
/// C_Sign* and C_Verify* with the RSA mechanisms through the module ABI, on
/// keys unwrapped from the host. PKCS#1 v1.5 signatures are deterministic, so
/// they match host OpenSSL and the NIST vectors bit for bit; PSS signatures
/// are randomised, so the host verifies the token's and the token the host's,
/// with every salt length the key allows. Also: the pre-hashed CKM_RSA_PKCS_PSS
/// and its input length, the PSS parameter rules, multi-part against one-shot,
/// sizing, the refusals of a verification, the usage and key rules, and that
/// every way an operation ends gives its device keys back. The parameter
/// matrix is in tests/rsa_params_test.c.

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/ec_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/leak_gate.hpp"
#include "utils/module.hpp"
#include "utils/rsa_helpers.hpp"
#include "vectors/rsa_pkcs1_nist.inc"
#include "vectors/rsa_pss_nist.inc"

namespace
{

/// A PKCS#1 v1.5 mechanism and its hash.
struct Pkcs1
{
    CK_MECHANISM_TYPE mech;
    CK_MECHANISM_TYPE hash;
};

constexpr Pkcs1 kPkcs1[] = {
    { CKM_SHA1_RSA_PKCS, CKM_SHA_1 },
    { CKM_SHA256_RSA_PKCS, CKM_SHA256 },
    { CKM_SHA384_RSA_PKCS, CKM_SHA384 },
    { CKM_SHA512_RSA_PKCS, CKM_SHA512 },
};

constexpr Pkcs1 kPss[] = {
    { CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1 },
    { CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256 },
    { CKM_SHA384_RSA_PKCS_PSS, CKM_SHA384 },
    { CKM_SHA512_RSA_PKCS_PSS, CKM_SHA512 },
};

/// The bytes PSS and OAEP add to the hash lengths: the trailer and the
/// separator (RFC 8017).
constexpr CK_ULONG kPadFixed = 2;

/// The longest PSS salt a key of `bits` takes with a hash of `h_len` bytes.
CK_ULONG max_salt(size_t bits, size_t h_len)
{
    return ((bits - 1 + 7) / 8) - h_len - kPadFixed;
}

/// One-shot sign or verify with a mechanism that carries parameters.
CK_RV sign_with(
    CK_SESSION_HANDLE s,
    CK_MECHANISM *m,
    CK_OBJECT_HANDLE key,
    const std::vector<CK_BYTE> &in,
    std::vector<CK_BYTE> &sig
)
{
    CK_RV rv = p11()->C_SignInit(s, m, key);
    CK_ULONG need = 0;
    if (rv == CKR_OK)
    {
        rv = p11()->C_Sign(
            s,
            const_cast<CK_BYTE_PTR>(in.data()),
            static_cast<CK_ULONG>(in.size()),
            nullptr,
            &need
        );
    }
    if (rv != CKR_OK)
    {
        return rv;
    }
    sig.assign(need, 0);
    rv = p11()->C_Sign(
        s,
        const_cast<CK_BYTE_PTR>(in.data()),
        static_cast<CK_ULONG>(in.size()),
        sig.data(),
        &need
    );
    sig.resize((rv == CKR_OK) ? need : 0);
    return rv;
}

CK_RV verify_with(
    CK_SESSION_HANDLE s,
    CK_MECHANISM *m,
    CK_OBJECT_HANDLE key,
    const std::vector<CK_BYTE> &in,
    const std::vector<CK_BYTE> &sig
)
{
    CK_RV rv = p11()->C_VerifyInit(s, m, key);
    if (rv != CKR_OK)
    {
        return rv;
    }
    return p11()->C_Verify(
        s,
        const_cast<CK_BYTE_PTR>(in.data()),
        static_cast<CK_ULONG>(in.size()),
        const_cast<CK_BYTE_PTR>(sig.data()),
        static_cast<CK_ULONG>(sig.size())
    );
}

/// The hash length of a hash mechanism.
size_t h_len(CK_MECHANISM_TYPE hash)
{
    return host::digest(hash_name(hash), {}).size();
}

} // namespace

/// A logged-in session with an RSA-2048 signing pair unwrapped from the host.
class rsa_sign : public PrivateUnwrapSession
{
  protected:
    void SetUp() override
    {
        PrivateUnwrapSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_NO_FATAL_FAILURE(unwrap_pair(host_rsa(2048), CKK_RSA, CKA_SIGN, &pair_));
    }

    UnwrappedPair pair_;
    std::vector<CK_BYTE> msg_ = pattern(100);
};

TEST_F(rsa_sign, pkcs1_signatures_match_the_nist_vectors)
{
    ASSERT_FALSE(std::empty(vectors::kRsaPkcs1Nist));
    const vectors::RsaKey *loaded = nullptr;
    UnwrappedPair pair;
    host::Pkey key;
    for (const vectors::RsaSigVector &v : vectors::kRsaPkcs1Nist)
    {
        SCOPED_TRACE(std::string(v.md) + " " + std::string(v.sig).substr(0, 16));
        if (v.key != loaded)
        {
            key = host::private_key(vectors::hex(v.key->pkcs8));
            ASSERT_NO_FATAL_FAILURE(unwrap_pair(key.get(), CKK_RSA, CKA_SIGN, &pair));
            loaded = v.key;
        }
        CK_MECHANISM_TYPE mech = (std::string(v.md) == "SHA384")   ? CKM_SHA384_RSA_PKCS
                                 : (std::string(v.md) == "SHA512") ? CKM_SHA512_RSA_PKCS
                                                                   : CKM_SHA256_RSA_PKCS;
        std::vector<CK_BYTE> sig;
        ASSERT_CKR_OK(sign_oneshot(s_, mech, pair.priv, vectors::hex(v.msg), sig));
        EXPECT_EQ(vectors::hex(v.sig), sig) << "PKCS#1 v1.5 is deterministic";
        EXPECT_CKR_OK(verify_oneshot(s_, mech, pair.pub, vectors::hex(v.msg), sig));
    }
}

TEST_F(rsa_sign, the_nist_pss_signatures_verify)
{
    ASSERT_FALSE(std::empty(vectors::kRsaPssNist));
    host::Pkey key = host::private_key(vectors::hex(vectors::kRsaPssKey0.pkcs8));
    UnwrappedPair pair;
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(key.get(), CKK_RSA, CKA_SIGN, &pair));
    for (const vectors::RsaSigVector &v : vectors::kRsaPssNist)
    {
        SCOPED_TRACE(v.md);
        CK_MECHANISM_TYPE hash = (std::string(v.md) == "SHA384") ? CKM_SHA384 : CKM_SHA256;
        CK_MECHANISM_TYPE mech =
            (hash == CKM_SHA384) ? CKM_SHA384_RSA_PKCS_PSS : CKM_SHA256_RSA_PKCS_PSS;
        PssMechanism m(mech, hash, h_len(hash));
        EXPECT_CKR_OK(verify_with(s_, &m.mech, pair.pub, vectors::hex(v.msg), vectors::hex(v.sig)));
        std::vector<CK_BYTE> wrong = vectors::hex(v.sig);
        wrong[wrong.size() / 2] ^= 0x01;
        EXPECT_CKR(
            CKR_SIGNATURE_INVALID,
            verify_with(s_, &m.mech, pair.pub, vectors::hex(v.msg), wrong)
        );
    }
}

TEST_F(rsa_sign, every_size_and_hash_agrees_with_the_host)
{
    for (size_t bits : kRsaSizes)
    {
        SCOPED_TRACE(bits);
        EVP_PKEY *key = host_rsa(bits);
        UnwrappedPair pair;
        ASSERT_NO_FATAL_FAILURE(unwrap_pair(key, CKK_RSA, CKA_SIGN, &pair));
        for (const Pkcs1 &p : kPkcs1)
        {
            SCOPED_TRACE(hash_name(p.hash));
            std::vector<CK_BYTE> sig;
            ASSERT_CKR_OK(sign_oneshot(s_, p.mech, pair.priv, msg_, sig));
            EXPECT_EQ(bits / 8, sig.size()) << "a signature is one modulus long";
            EXPECT_EQ(host::rsa_sign(key, hash_name(p.hash), RSA_PKCS1_PADDING, msg_), sig)
                << "bit-exact against the host";
            EXPECT_CKR_OK(verify_oneshot(s_, p.mech, pair.pub, msg_, sig));
        }
        for (const Pkcs1 &p : kPss)
        {
            SCOPED_TRACE(hash_name(p.hash));
            int salt = static_cast<int>(h_len(p.hash));
            PssMechanism m(p.mech, p.hash, static_cast<CK_ULONG>(salt));
            std::vector<CK_BYTE> sig;
            ASSERT_CKR_OK(sign_with(s_, &m.mech, pair.priv, msg_, sig));
            EXPECT_TRUE(
                host::rsa_verify(key, hash_name(p.hash), RSA_PKCS1_PSS_PADDING, msg_, sig, salt)
            ) << "the host verifies the token's PSS signature";
            std::vector<CK_BYTE> host_sig =
                host::rsa_sign(key, hash_name(p.hash), RSA_PKCS1_PSS_PADDING, msg_, salt);
            EXPECT_CKR_OK(verify_with(s_, &m.mech, pair.pub, msg_, host_sig))
                << "the token verifies the host's";
        }
    }
}

TEST_F(rsa_sign, pss_takes_every_salt_the_key_allows)
{
    EVP_PKEY *key = host_rsa(2048);
    for (const Pkcs1 &p : kPss)
    {
        SCOPED_TRACE(hash_name(p.hash));
        CK_ULONG longest = max_salt(2048, h_len(p.hash));
        for (CK_ULONG salt : { CK_ULONG{ 0 }, CK_ULONG{ 1 }, longest })
        {
            SCOPED_TRACE(salt);
            PssMechanism m(p.mech, p.hash, salt);
            std::vector<CK_BYTE> sig;
            ASSERT_CKR_OK(sign_with(s_, &m.mech, pair_.priv, msg_, sig));
            EXPECT_TRUE(host::rsa_verify(
                key,
                hash_name(p.hash),
                RSA_PKCS1_PSS_PADDING,
                msg_,
                sig,
                static_cast<int>(salt)
            ));
            EXPECT_CKR_OK(verify_with(s_, &m.mech, pair_.pub, msg_, sig));
        }
        PssMechanism too_long(p.mech, p.hash, longest + 1);
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_SignInit(s_, &too_long.mech, pair_.priv))
            << "sLen <= emLen - hLen - 2";
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_VerifyInit(s_, &too_long.mech, pair_.pub));
        PssMechanism fits(p.mech, p.hash, longest);
        EXPECT_CKR_OK(p11()->C_SignInit(s_, &fits.mech, pair_.priv))
            << "the refused init left no operation";
        EXPECT_CKR_OK(p11()->C_SignInit(s_, nullptr, pair_.priv));
    }
}

TEST_F(rsa_sign, pre_hashed_pss_signs_one_hash)
{
    EVP_PKEY *key = host_rsa(2048);
    for (CK_MECHANISM_TYPE hash : { CKM_SHA_1, CKM_SHA256, CKM_SHA384, CKM_SHA512 })
    {
        SCOPED_TRACE(hash_name(hash));
        int salt = static_cast<int>(h_len(hash));
        PssMechanism m(CKM_RSA_PKCS_PSS, hash, static_cast<CK_ULONG>(salt));
        host::Bytes dgst = host::digest(hash_name(hash), msg_);
        std::vector<CK_BYTE> sig;
        ASSERT_CKR_OK(sign_with(s_, &m.mech, pair_.priv, dgst, sig));
        EXPECT_TRUE(host::rsa_pss_verify_digest(key, hash_name(hash), dgst, sig, salt));
        EXPECT_TRUE(host::rsa_verify(key, hash_name(hash), RSA_PKCS1_PSS_PADDING, msg_, sig, salt))
            << "the same signature as the hashing mechanism makes";
        EXPECT_CKR_OK(verify_with(
            s_,
            &m.mech,
            pair_.pub,
            dgst,
            host::rsa_pss_sign_digest(key, hash_name(hash), dgst, salt)
        ));

        host::Bytes longer = dgst;
        longer.push_back(0);
        EXPECT_CKR(CKR_DATA_LEN_RANGE, sign_with(s_, &m.mech, pair_.priv, longer, sig))
            << "the input is exactly one hash of hashAlg";
        EXPECT_CKR(
            CKR_DATA_LEN_RANGE,
            sign_with(s_, &m.mech, pair_.priv, host::Bytes(dgst.begin(), dgst.end() - 1), sig)
        );
        EXPECT_CKR(CKR_DATA_LEN_RANGE, verify_with(s_, &m.mech, pair_.pub, longer, sig));
    }
    PssMechanism m(CKM_RSA_PKCS_PSS, CKM_SHA256, 32);
    CK_BYTE sig[256];
    CK_ULONG len = sizeof(sig);
    ASSERT_CKR_OK(p11()->C_SignInit(s_, &m.mech, pair_.priv));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_SignUpdate(s_, msg_.data(), 32))
        << "the SDK streams no caller-made hash";
    ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &m.mech, pair_.pub));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_VerifyFinal(s_, sig, len));
}

TEST_F(rsa_sign, mechanism_and_parameter_rules)
{
    struct Case
    {
        const char *what;
        CK_MECHANISM mech;
        CK_RV want;
    };
    CK_RSA_PKCS_PSS_PARAMS ok = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_RSA_PKCS_PSS_PARAMS other_hash = { CKM_SHA384, CKG_MGF1_SHA384, 32 };
    CK_RSA_PKCS_PSS_PARAMS other_mgf = { CKM_SHA256, CKG_MGF1_SHA384, 32 };
    CK_RSA_PKCS_PSS_PARAMS sha224 = { CKM_SHA224, CKG_MGF1_SHA224, 28 };
    std::vector<Case> cases = {
        { "PSS without parameters",
          { CKM_SHA256_RSA_PKCS_PSS, nullptr, 0 },
          CKR_MECHANISM_PARAM_INVALID },
        { "a short PSS parameter",
          { CKM_SHA256_RSA_PKCS_PSS, &ok, sizeof(ok) - 1 },
          CKR_MECHANISM_PARAM_INVALID },
        { "another hash than the mechanism's",
          { CKM_SHA256_RSA_PKCS_PSS, &other_hash, sizeof(other_hash) },
          CKR_MECHANISM_PARAM_INVALID },
        { "MGF1 with another hash",
          { CKM_SHA256_RSA_PKCS_PSS, &other_mgf, sizeof(other_mgf) },
          CKR_MECHANISM_PARAM_INVALID },
        { "a pre-hashed SHA-224",
          { CKM_RSA_PKCS_PSS, &sha224, sizeof(sha224) },
          CKR_MECHANISM_PARAM_INVALID },
        { "a pre-hashed MGF1 with another hash",
          { CKM_RSA_PKCS_PSS, &other_mgf, sizeof(other_mgf) },
          CKR_MECHANISM_PARAM_INVALID },
        { "PKCS#1 v1.5 with a parameter",
          { CKM_SHA256_RSA_PKCS, &ok, sizeof(ok) },
          CKR_MECHANISM_PARAM_INVALID },
        { "CKM_RSA_PKCS", { CKM_RSA_PKCS, nullptr, 0 }, CKR_MECHANISM_INVALID },
        { "CKM_SHA224_RSA_PKCS", { CKM_SHA224_RSA_PKCS, nullptr, 0 }, CKR_MECHANISM_INVALID },
        { "CKM_RSA_X_509", { CKM_RSA_X_509, nullptr, 0 }, CKR_MECHANISM_INVALID },
        { "the control", { CKM_SHA256_RSA_PKCS_PSS, &ok, sizeof(ok) }, CKR_OK },
    };
    for (Case &c : cases)
    {
        SCOPED_TRACE(c.what);
        EXPECT_CKR(c.want, p11()->C_SignInit(s_, &c.mech, pair_.priv))
            << "PSS parameters as the mechanism names them";
        EXPECT_CKR_OK(p11()->C_SignInit(s_, nullptr, pair_.priv));
        EXPECT_CKR(c.want, p11()->C_VerifyInit(s_, &c.mech, pair_.pub));
        EXPECT_CKR_OK(p11()->C_VerifyInit(s_, nullptr, pair_.pub));
    }
}

TEST_F(rsa_sign, multi_part_matches_one_shot)
{
    for (const Pkcs1 &p : kPkcs1)
    {
        SCOPED_TRACE(hash_name(p.hash));
        std::vector<CK_BYTE> one;
        ASSERT_CKR_OK(sign_oneshot(s_, p.mech, pair_.priv, msg_, one));
        for (size_t chunk : { 1, 7, 64, 100 })
        {
            std::vector<CK_BYTE> parts;
            ASSERT_CKR_OK(sign_multipart(s_, p.mech, pair_.priv, msg_, chunk, parts));
            EXPECT_EQ(one, parts) << "chunk " << chunk;
            EXPECT_CKR_OK(verify_multipart(s_, p.mech, pair_.pub, msg_, chunk, one));
        }
    }
    EVP_PKEY *key = host_rsa(2048);
    for (const Pkcs1 &p : kPss)
    {
        SCOPED_TRACE(hash_name(p.hash));
        int salt = static_cast<int>(h_len(p.hash));
        PssMechanism m(p.mech, p.hash, static_cast<CK_ULONG>(salt));
        CK_BYTE sig[256];
        CK_ULONG len = sizeof(sig);
        ASSERT_CKR_OK(p11()->C_SignInit(s_, &m.mech, pair_.priv));
        ASSERT_CKR_OK(p11()->C_SignUpdate(s_, msg_.data(), 40));
        ASSERT_CKR_OK(p11()->C_SignUpdate(s_, msg_.data() + 40, 60));
        ASSERT_CKR_OK(p11()->C_SignFinal(s_, sig, &len));
        std::vector<CK_BYTE> parts(sig, sig + len);
        EXPECT_TRUE(
            host::rsa_verify(key, hash_name(p.hash), RSA_PKCS1_PSS_PADDING, msg_, parts, salt)
        );
        ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &m.mech, pair_.pub));
        ASSERT_CKR_OK(p11()->C_VerifyUpdate(s_, msg_.data(), 13));
        ASSERT_CKR_OK(p11()->C_VerifyUpdate(s_, msg_.data() + 13, 87));
        EXPECT_CKR_OK(p11()->C_VerifyFinal(s_, sig, len));
    }
}

TEST_F(rsa_sign, sizing_follows_the_two_call_rules)
{
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, nullptr, 0 };
    std::vector<CK_BYTE> buf(300, 0xEE);
    ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, pair_.priv));
    CK_ULONG len = 0;
    ASSERT_CKR_OK(p11()->C_Sign(s_, msg_.data(), 100, nullptr, &len));
    EXPECT_EQ(256u, len) << "a NULL buffer learns the modulus length";
    len = 255;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Sign(s_, msg_.data(), 100, buf.data(), &len));
    EXPECT_EQ(256u, len);
    EXPECT_EQ(0xEE, buf[0]) << "nothing written";
    len = 300;
    ASSERT_CKR_OK(p11()->C_Sign(s_, msg_.data(), 100, buf.data(), &len))
        << "the operation survived";
    EXPECT_EQ(256u, len) << "a larger buffer gets the exact length";
    EXPECT_EQ(0xEE, buf[256]) << "nothing past the signature";
    buf.resize(256);
    EXPECT_EQ(host::rsa_sign(host_rsa(2048), "SHA256", RSA_PKCS1_PADDING, msg_), buf);

    ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, pair_.priv));
    ASSERT_CKR_OK(p11()->C_SignUpdate(s_, msg_.data(), 100));
    len = 0;
    ASSERT_CKR_OK(p11()->C_SignFinal(s_, nullptr, &len));
    EXPECT_EQ(256u, len);
    len = 10;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_SignFinal(s_, buf.data(), &len));
    len = 256;
    ASSERT_CKR_OK(p11()->C_SignFinal(s_, buf.data(), &len));
}

TEST_F(rsa_sign, verification_refuses_what_it_must)
{
    PssMechanism pss(CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, 32);
    std::vector<CK_BYTE> sig;
    ASSERT_CKR_OK(sign_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.priv, msg_, sig));
    ASSERT_CKR_OK(verify_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, sig));
    std::vector<CK_BYTE> flipped = sig;
    flipped[5] ^= 0x01;
    EXPECT_CKR(
        CKR_SIGNATURE_INVALID,
        verify_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, flipped)
    );
    EXPECT_CKR(
        CKR_SIGNATURE_INVALID,
        verify_multipart(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, 9, flipped)
    );
    std::vector<CK_BYTE> other = msg_;
    other[0] ^= 0x80;
    EXPECT_CKR(
        CKR_SIGNATURE_INVALID,
        verify_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.pub, other, sig)
    );
    EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, CKM_SHA384_RSA_PKCS, pair_.pub, msg_, sig))
        << "another hash";
    std::vector<CK_BYTE> ones(sig.size(), 0xFF);
    EXPECT_CKR(
        CKR_SIGNATURE_INVALID,
        verify_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, ones)
    ) << "a value above the modulus";
    std::vector<CK_BYTE> shorter(sig.begin(), sig.end() - 1);
    EXPECT_CKR(
        CKR_SIGNATURE_LEN_RANGE,
        verify_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, shorter)
    );
    std::vector<CK_BYTE> longer = sig;
    longer.push_back(0);
    EXPECT_CKR(
        CKR_SIGNATURE_LEN_RANGE,
        verify_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, longer)
    );
    EXPECT_CKR(
        CKR_SIGNATURE_LEN_RANGE,
        verify_multipart(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, 9, longer)
    );

    std::vector<CK_BYTE> pss_sig;
    ASSERT_CKR_OK(sign_with(s_, &pss.mech, pair_.priv, msg_, pss_sig));
    PssMechanism other_salt(CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, 20);
    EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_with(s_, &other_salt.mech, pair_.pub, msg_, pss_sig))
        << "PSS verifies with the salt length it was made with";
    EXPECT_CKR(
        CKR_SIGNATURE_INVALID,
        verify_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, pss_sig)
    ) << "a PSS signature is no PKCS#1 v1.5 one";

    UnwrappedPair other_key;
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(host_rsa(3072), CKK_RSA, CKA_SIGN, &other_key));
    EXPECT_CKR(
        CKR_SIGNATURE_LEN_RANGE,
        verify_oneshot(s_, CKM_SHA256_RSA_PKCS, other_key.pub, msg_, sig)
    ) << "another key's length";
    EXPECT_FALSE(host::rsa_verify(host_rsa(2048), "SHA256", RSA_PKCS1_PADDING, msg_, flipped))
        << "the host refuses the same corruption: it is no rubber stamp";
}

TEST_F(rsa_sign, usage_and_key_rules)
{
    CK_MECHANISM m = { CKM_SHA256_RSA_PKCS, nullptr, 0 };
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_SignInit(s_, &m, pair_.pub))
        << "a public key does not sign";
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_VerifyInit(s_, &m, pair_.priv))
        << "a private key does not verify";
    UnwrappedPair decrypt;
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(host_rsa(2048), CKK_RSA, CKA_DECRYPT, &decrypt));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_SignInit(s_, &m, decrypt.priv))
        << "a decrypting key does not sign";
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_VerifyInit(s_, &m, decrypt.pub));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_SignInit(s_, &m, priv_))
        << "the unwrapping key does not sign: its usage is judged first";
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_VerifyInit(s_, &m, pub_));
    CK_MECHANISM ecdsa = { CKM_ECDSA_SHA256, nullptr, 0 };
    EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_SignInit(s_, &ecdsa, pair_.priv));
    CK_OBJECT_HANDLE ec_pub = 0;
    CK_OBJECT_HANDLE ec_priv = 0;
    ASSERT_CKR_OK(gen_p256(s_, &ec_pub, &ec_priv));
    EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_SignInit(s_, &m, ec_priv));

    // A public key made with C_CreateObject has no device key behind it, even
    // with the modulus and the exponent of an unwrapped one.
    std::vector<CK_BYTE> n;
    std::vector<CK_BYTE> e;
    ASSERT_CKR_OK(get_bytes(s_, pair_.pub, CKA_MODULUS, n));
    ASSERT_CKR_OK(get_bytes(s_, pair_.pub, CKA_PUBLIC_EXPONENT, e));
    CK_OBJECT_CLASS cls = CKO_PUBLIC_KEY;
    CK_KEY_TYPE kt = CKK_RSA;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = { { CKA_CLASS, &cls, sizeof(cls) },
                            { CKA_KEY_TYPE, &kt, sizeof(kt) },
                            { CKA_VERIFY, &yes, sizeof(yes) },
                            { CKA_MODULUS, n.data(), n.size() },
                            { CKA_PUBLIC_EXPONENT, e.data(), e.size() } };
    CK_OBJECT_HANDLE created = 0;
    ASSERT_CKR_OK(p11()->C_CreateObject(s_, tmpl, 5, &created));
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID, p11()->C_VerifyInit(s_, &m, created))
        << "the SDK verifies only with a device key";

    // An allowed-mechanism list.
    CK_OBJECT_CLASS priv_cls = CKO_PRIVATE_KEY;
    CK_MECHANISM_TYPE only_pss = CKM_SHA256_RSA_PKCS_PSS;
    std::vector<CK_ATTRIBUTE> limited = {
        { CKA_CLASS, &priv_cls, sizeof(priv_cls) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_SIGN, &yes, sizeof(yes) },
        { CKA_ALLOWED_MECHANISMS, &only_pss, sizeof(only_pss) },
    };
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(unwrap_with_template(s_, priv_, blob_of(host_rsa(2048)), limited, &key));
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_SignInit(s_, &m, key));
    PssMechanism pss(CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, 32);
    EXPECT_CKR_OK(p11()->C_SignInit(s_, &pss.mech, key));
}

TEST_F(rsa_sign, every_way_an_operation_ends_gives_its_device_keys_back)
{
    // The paths that run RSA code; the key-independent ones (cancel, session
    // close, bad arguments) are in ec/sign_tests.cpp.
    PssMechanism too_long(CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256, 223);
    std::vector<CK_BYTE> sig;
    ASSERT_CKR_OK(sign_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.priv, msg_, sig));
    std::vector<TerminationPath> paths = {
        { "one-shot sign",
          [&] { ASSERT_CKR_OK(sign_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.priv, msg_, sig)); } },
        { "multi-part verify",
          [&] {
              ASSERT_CKR_OK(verify_multipart(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, 50, sig));
          } },
        { "a salt the key refuses",
          [&] {
              ASSERT_CKR(
                  CKR_MECHANISM_PARAM_INVALID,
                  p11()->C_SignInit(s_, &too_long.mech, pair_.priv)
              );
          } },
        { "invalid signature",
          [&] {
              std::vector<CK_BYTE> bad(sig.size(), 0x01);
              ASSERT_CKR(
                  CKR_SIGNATURE_INVALID,
                  verify_oneshot(s_, CKM_SHA256_RSA_PKCS, pair_.pub, msg_, bad)
              );
          } },
    };
    // The fresh operation runs on a pair that is not private, which outlives
    // the gate's logout.
    PrivateTemplate t(CKK_RSA, CKA_SIGN, CK_FALSE, "leak-gate", CK_FALSE);
    CK_OBJECT_HANDLE fresh_key = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(unwrap_with_template(s_, priv_, blob_of(host_rsa(2048)), t.attrs, &fresh_key));
    std::vector<CK_BYTE> fresh_sig;
    auto fresh = [&] { return sign_oneshot(s_, CKM_SHA256_RSA_PKCS, fresh_key, msg_, fresh_sig); };
    ASSERT_NO_FATAL_FAILURE(leak_gate(s_, paths, fresh));
    EXPECT_EQ(sig, fresh_sig) << "still the same key";
}
