// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file relation_tests.cpp
///
/// Relations between AES outputs that every correct implementation satisfies,
/// checked without knowing the key: CBC chaining and the IV XOR, CBC-PAD as
/// CBC over PKCS#7-padded input, and GCM as a keystream XOR. A round trip
/// only proves that decryption undoes encryption; these tie the outputs to
/// the mode definitions until keys can be imported for known-answer tests.

#include <algorithm>
#include <cstring>
#include <gtest/gtest.h>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"

namespace
{

constexpr CK_ULONG kGcmIv = 12;
constexpr CK_ULONG kGcmTag = 16;

} // namespace

class aes_relations : public UserSession
{
  protected:
    void SetUp() override
    {
        UserSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "relations", &key_));
        std::memset(iv_, 0xC3, sizeof(iv_));
    }

    /// One-shot encryption of `in` with `mech` (CKM_AES_CBC or CKM_AES_CBC_PAD)
    /// under `iv`. ASSERTs, so call it as ASSERT_NO_FATAL_FAILURE(...).
    void cbc(
        CK_MECHANISM_TYPE mech,
        const CK_BYTE *iv,
        const std::vector<CK_BYTE> &in,
        std::vector<CK_BYTE> &out
    )
    {
        CK_MECHANISM m = { mech, const_cast<CK_BYTE *>(iv), kAesBlock };
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &m, key_, in, out));
    }

    CK_OBJECT_HANDLE key_ = 0;
    CK_BYTE iv_[kAesBlock];
};

TEST_F(aes_relations, cbc_chains_each_block_through_the_previous_ciphertext)
{
    // C[i] = E(P[i] xor C[i-1]): block i alone under the IV C[i-1] gives C[i].
    const size_t blocks = 3;
    std::vector<CK_BYTE> plain = pattern(blocks * kAesBlock), whole;
    ASSERT_NO_FATAL_FAILURE(cbc(CKM_AES_CBC, iv_, plain, whole));
    ASSERT_EQ(plain.size(), whole.size());
    for (size_t i = 1; i < blocks; i++)
    {
        SCOPED_TRACE(i);
        std::vector<CK_BYTE> block(
            plain.begin() + i * kAesBlock,
            plain.begin() + (i + 1) * kAesBlock
        );
        std::vector<CK_BYTE> alone;
        ASSERT_NO_FATAL_FAILURE(cbc(CKM_AES_CBC, &whole[(i - 1) * kAesBlock], block, alone));
        EXPECT_TRUE(std::equal(alone.begin(), alone.end(), whole.begin() + i * kAesBlock));
    }
}

TEST_F(aes_relations, cbc_xors_the_iv_into_the_first_block)
{
    // E(P xor IV) is the same for (P, IV) and (P xor IV xor IV2, IV2).
    std::vector<CK_BYTE> plain = pattern(kAesBlock), moved(kAesBlock);
    CK_BYTE iv2[kAesBlock];
    std::memset(iv2, 0x3C, sizeof(iv2));
    for (size_t i = 0; i < kAesBlock; i++)
    {
        moved[i] = plain[i] ^ iv_[i] ^ iv2[i];
    }
    std::vector<CK_BYTE> a, b;
    ASSERT_NO_FATAL_FAILURE(cbc(CKM_AES_CBC, iv_, plain, a));
    ASSERT_NO_FATAL_FAILURE(cbc(CKM_AES_CBC, iv2, moved, b));
    EXPECT_EQ(a, b);
}

TEST_F(aes_relations, cbc_pad_is_cbc_over_pkcs7_padded_input)
{
    for (size_t n : { 0, 1, 15, 16, 17, 33 })
    {
        SCOPED_TRACE(n);
        std::vector<CK_BYTE> plain = pattern(n);
        std::vector<CK_BYTE> padded = plain;
        size_t pad = kAesBlock - (n % kAesBlock);
        padded.insert(padded.end(), pad, static_cast<CK_BYTE>(pad));
        std::vector<CK_BYTE> a, b;
        ASSERT_NO_FATAL_FAILURE(cbc(CKM_AES_CBC_PAD, iv_, plain, a));
        ASSERT_NO_FATAL_FAILURE(cbc(CKM_AES_CBC, iv_, padded, b));
        EXPECT_EQ(b, a);
    }
}

TEST_F(aes_relations, gcm_encrypts_by_xor_with_a_keystream)
{
    // Same key, IV and AAD: C = P xor S, and the keystream S is the encryption
    // of zeros. The tag still depends on the plaintext.
    CK_OBJECT_HANDLE gcm = 0;
    ASSERT_CKR_OK(gen_gcm_key(s_, "relations-gcm", &gcm));
    CK_GCM_PARAMS params = {};
    params.pIv = iv_;
    params.ulIvLen = kGcmIv;
    params.ulIvBits = kGcmIv * 8;
    params.ulTagBits = kGcmTag * 8;
    CK_MECHANISM mech = { CKM_AES_GCM, &params, sizeof(params) };

    const size_t n = 37; // not a block multiple
    std::vector<CK_BYTE> plain = pattern(n), stream, ct;
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech, gcm, std::vector<CK_BYTE>(n, 0), stream));
    ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech, gcm, plain, ct));
    ASSERT_EQ(n + kGcmTag, stream.size());
    ASSERT_EQ(n + kGcmTag, ct.size());
    for (size_t i = 0; i < n; i++)
    {
        ASSERT_EQ(plain[i] ^ stream[i], ct[i]) << "byte " << i;
    }
    EXPECT_FALSE(std::equal(ct.begin() + n, ct.end(), stream.begin() + n));
}
