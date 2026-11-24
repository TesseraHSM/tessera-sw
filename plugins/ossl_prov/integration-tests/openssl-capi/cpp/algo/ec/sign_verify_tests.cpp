// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file sign_verify_tests.cpp
///
/// Round-trip sign / verify tests that use **session-based** EC keys via the
/// OpenSSL EVP API.  Session keys are ephemeral (never written to disk) and
/// therefore cannot be tested through the OpenSSL command-line tool.

#include <cstring>
#include <gtest/gtest.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string>
#include <vector>

#include "utils/keygen_helpers.hpp"
#include "utils/ossl_helpers.hpp"
#include "utils/provider_ctx.hpp"

// ---------------------------------------------------------------------------
// Test parameters
// ---------------------------------------------------------------------------

struct EcSessionTestCase
{
    const char *curve;  // "P-256", "P-384", "P-521"
    const char *digest; // "SHA256", "SHA384", "SHA512"
    const char *label;  // Human-readable label for SCOPED_TRACE
};

static const EcSessionTestCase kTestCases[] = {
    { "P-256", "SHA256", "P-256 / SHA-256" },
    { "P-384", "SHA384", "P-384 / SHA-384" },
    { "P-521", "SHA512", "P-521 / SHA-512" },
};

// ---------------------------------------------------------------------------
// Test fixture
// ---------------------------------------------------------------------------

class ec_sign_verify : public ::testing::Test
{
  protected:
    ProviderCtx prov_;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Generate a session key for each curve and produce a signature.
TEST_F(ec_sign_verify, sign_all_curves)
{
    for (const auto &tc : kTestCases)
    {
        SCOPED_TRACE(tc.label);

        auto pkey = generate_ec_session_key(prov_.libctx(), tc.curve);
        ASSERT_NE(pkey, nullptr) << "keygen failed for " << tc.curve;

        const std::string message = std::string("sign test data for ") + tc.label;
        const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
        const size_t msg_len = message.size();

        EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
        ASSERT_NE(sign_ctx, nullptr);

        ASSERT_EQ(
            EVP_DigestSignInit_ex(
                sign_ctx.get(),
                nullptr,
                tc.digest,
                prov_.libctx(),
                ProviderCtx::propquery(),
                pkey.get(),
                nullptr
            ),
            1
        ) << "DigestSignInit failed";

        size_t sig_len = 0;
        ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
        ASSERT_GT(sig_len, 0u);

        std::vector<unsigned char> signature(sig_len);
        ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1)
            << "DigestSign failed";
        signature.resize(sig_len);

        EXPECT_GT(signature.size(), 0u) << "Signature should be non-empty";
    }
}

/// Sign then verify round-trip for each curve.
TEST_F(ec_sign_verify, verify_all_curves)
{
    for (const auto &tc : kTestCases)
    {
        SCOPED_TRACE(tc.label);

        auto pkey = generate_ec_session_key(prov_.libctx(), tc.curve);
        ASSERT_NE(pkey, nullptr) << "keygen failed for " << tc.curve;

        const std::string message = std::string("round-trip test data for ") + tc.label;
        const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
        const size_t msg_len = message.size();

        // Sign
        EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
        ASSERT_NE(sign_ctx, nullptr);

        ASSERT_EQ(
            EVP_DigestSignInit_ex(
                sign_ctx.get(),
                nullptr,
                tc.digest,
                prov_.libctx(),
                ProviderCtx::propquery(),
                pkey.get(),
                nullptr
            ),
            1
        ) << "DigestSignInit failed";

        size_t sig_len = 0;
        ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
        ASSERT_GT(sig_len, 0u);

        std::vector<unsigned char> signature(sig_len);
        ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1)
            << "DigestSign failed";
        signature.resize(sig_len);

        // Verify
        EvpMdCtxPtr verify_ctx(EVP_MD_CTX_new());
        ASSERT_NE(verify_ctx, nullptr);

        ASSERT_EQ(
            EVP_DigestVerifyInit_ex(
                verify_ctx.get(),
                nullptr,
                tc.digest,
                prov_.libctx(),
                ProviderCtx::propquery(),
                pkey.get(),
                nullptr
            ),
            1
        ) << "DigestVerifyInit failed";

        EXPECT_EQ(
            EVP_DigestVerify(
                verify_ctx.get(),
                signature.data(),
                signature.size(),
                msg_ptr,
                msg_len
            ),
            1
        ) << "DigestVerify failed — signature did not verify";
    }
}

/// Tampered data must NOT verify.
TEST_F(ec_sign_verify, verify_rejects_tampered_data)
{
    for (const auto &tc : kTestCases)
    {
        SCOPED_TRACE(tc.label);

        auto pkey = generate_ec_session_key(prov_.libctx(), tc.curve);
        ASSERT_NE(pkey, nullptr) << "keygen failed for " << tc.curve;

        const std::string message = std::string("tamper test data for ") + tc.label;
        const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
        const size_t msg_len = message.size();

        // Sign
        EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
        ASSERT_NE(sign_ctx, nullptr);

        ASSERT_EQ(
            EVP_DigestSignInit_ex(
                sign_ctx.get(),
                nullptr,
                tc.digest,
                prov_.libctx(),
                ProviderCtx::propquery(),
                pkey.get(),
                nullptr
            ),
            1
        ) << "DigestSignInit failed";

        size_t sig_len = 0;
        ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
        std::vector<unsigned char> signature(sig_len);
        ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1);
        signature.resize(sig_len);

        // Tamper with the data
        std::string tampered = message;
        tampered[0] ^= 0xFF;
        const auto *tampered_ptr = reinterpret_cast<const unsigned char *>(tampered.data());

        // Verify must fail
        EvpMdCtxPtr verify_ctx(EVP_MD_CTX_new());
        ASSERT_NE(verify_ctx, nullptr);
        ASSERT_EQ(
            EVP_DigestVerifyInit_ex(
                verify_ctx.get(),
                nullptr,
                tc.digest,
                prov_.libctx(),
                ProviderCtx::propquery(),
                pkey.get(),
                nullptr
            ),
            1
        );

        EXPECT_NE(
            EVP_DigestVerify(
                verify_ctx.get(),
                signature.data(),
                signature.size(),
                tampered_ptr,
                tampered.size()
            ),
            1
        ) << "DigestVerify should fail with tampered data";
    }
}

/// Signing with one session key and verifying with a different session key
/// must fail.
TEST_F(ec_sign_verify, verify_fails_with_wrong_key)
{
    auto key_a = generate_ec_session_key(prov_.libctx(), "P-256");
    auto key_b = generate_ec_session_key(prov_.libctx(), "P-256");
    ASSERT_NE(key_a, nullptr);
    ASSERT_NE(key_b, nullptr);

    const std::string message = "cross-key verification must fail";
    const auto *msg_ptr = reinterpret_cast<const unsigned char *>(message.data());
    const size_t msg_len = message.size();

    // Sign with key_a
    EvpMdCtxPtr sign_ctx(EVP_MD_CTX_new());
    ASSERT_NE(sign_ctx, nullptr);
    ASSERT_EQ(
        EVP_DigestSignInit_ex(
            sign_ctx.get(),
            nullptr,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            key_a.get(),
            nullptr
        ),
        1
    );

    size_t sig_len = 0;
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), nullptr, &sig_len, msg_ptr, msg_len), 1);
    std::vector<unsigned char> signature(sig_len);
    ASSERT_EQ(EVP_DigestSign(sign_ctx.get(), signature.data(), &sig_len, msg_ptr, msg_len), 1);
    signature.resize(sig_len);

    // Verify with key_b — must fail
    EvpMdCtxPtr verify_ctx(EVP_MD_CTX_new());
    ASSERT_NE(verify_ctx, nullptr);
    ASSERT_EQ(
        EVP_DigestVerifyInit_ex(
            verify_ctx.get(),
            nullptr,
            "SHA256",
            prov_.libctx(),
            ProviderCtx::propquery(),
            key_b.get(),
            nullptr
        ),
        1
    );

    EXPECT_NE(
        EVP_DigestVerify(verify_ctx.get(), signature.data(), signature.size(), msg_ptr, msg_len),
        1
    ) << "Verification with wrong key should fail";
}

/// Verification accepts only the DER encoding of a signature: the same r and s
/// with a trailing byte or a non-minimal length fail, through EVP_PKEY_verify()
/// and EVP_DigestVerify*().
TEST_F(ec_sign_verify, verify_rejects_non_canonical_signature)
{
    for (const auto &tc : kTestCases)
    {
        SCOPED_TRACE(tc.label);
        auto key = generate_ec_session_key(prov_.libctx(), tc.curve);
        ASSERT_NE(key, nullptr);
        const unsigned char message[] = "strict DER signature";
        EvpMdCtxPtr sign(EVP_MD_CTX_new());
        ASSERT_NE(sign, nullptr);
        ASSERT_EQ(
            EVP_DigestSignInit_ex(
                sign.get(),
                nullptr,
                tc.digest,
                prov_.libctx(),
                "provider=tsra",
                key.get(),
                nullptr
            ),
            1
        );
        size_t len = 0;
        ASSERT_EQ(EVP_DigestSign(sign.get(), nullptr, &len, message, sizeof(message)), 1);
        std::vector<unsigned char> signature(len);
        ASSERT_EQ(EVP_DigestSign(sign.get(), signature.data(), &len, message, sizeof(message)), 1);
        signature.resize(len);
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_len = 0;
        EvpMdPtr md(EVP_MD_fetch(prov_.libctx(), tc.digest, "provider=default"));
        ASSERT_NE(md, nullptr);
        ASSERT_EQ(EVP_Digest(message, sizeof(message), digest, &digest_len, md.get(), nullptr), 1);

        std::vector<unsigned char> suffixed(signature);
        suffixed.push_back(0);
        // Same r and s under a non-minimal (BER) outer length.
        std::vector<unsigned char> ber(signature);
        ASSERT_GT(ber.size(), 2u);
        if (ber[1] < 0x80)
        {
            ber.insert(ber.begin() + 1, 0x81);
        }
        else
        {
            ASSERT_EQ(ber[1], 0x81);
            ber[1] = 0x82;
            ber.insert(ber.begin() + 2, 0x00);
        }
        struct Candidate
        {
            const char *name;
            const std::vector<unsigned char> &bytes;
            int expected;
        };
        const Candidate candidates[] = {
            { "DER", signature, 1 },
            { "trailing byte", suffixed, 0 },
            { "BER length", ber, 0 },
        };

        for (const Candidate &candidate : candidates)
        {
            SCOPED_TRACE(candidate.name);
            EvpPkeyCtxPtr pctx(
                EVP_PKEY_CTX_new_from_pkey(prov_.libctx(), key.get(), "provider=tsra")
            );
            ASSERT_NE(pctx, nullptr);
            ASSERT_EQ(EVP_PKEY_verify_init(pctx.get()), 1);
            EXPECT_EQ(
                EVP_PKEY_verify(
                    pctx.get(),
                    candidate.bytes.data(),
                    candidate.bytes.size(),
                    digest,
                    digest_len
                ),
                candidate.expected
            );
            EvpMdCtxPtr streaming(EVP_MD_CTX_new());
            ASSERT_NE(streaming, nullptr);
            ASSERT_EQ(
                EVP_DigestVerifyInit_ex(
                    streaming.get(),
                    nullptr,
                    tc.digest,
                    prov_.libctx(),
                    "provider=tsra",
                    key.get(),
                    nullptr
                ),
                1
            );
            ASSERT_EQ(EVP_DigestVerifyUpdate(streaming.get(), message, sizeof(message)), 1);
            EXPECT_EQ(
                EVP_DigestVerifyFinal(
                    streaming.get(),
                    candidate.bytes.data(),
                    candidate.bytes.size()
                ),
                candidate.expected
            );
        }
    }
}
