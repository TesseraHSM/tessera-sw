// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file kat_tests.cpp
///
/// Known-answer tests of the token's AES keys. Keys cannot be imported in
/// clear, so every case wraps a published key on the host and unwraps it into
/// the token (CKM_RSA_AES_KEY_WRAP), then checks the token's results bit for
/// bit: NIST CAVP AES-CBC and AES-XTS, and the Project Wycheproof sets for
/// AES-CBC with PKCS#7 padding, AES-GCM (the shapes the device takes) and AES
/// key wrap with padding, the last one as the inner layer of the unwrap
/// itself. Valid vectors must give the published answer, invalid ones must be
/// refused. Multi-part operations are checked at awkward part sizes.

#include <algorithm>
#include <climits>
#include <cstring>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/module.hpp"
#include "utils/unwrap_helpers.hpp"
#include "vectors/aes_cbc_nist.inc"
#include "vectors/aes_xts_nist.inc"
#include "wycheproof/aes_cbc_pkcs5.inc"
#include "wycheproof/aes_gcm.inc"
#include "wycheproof/aes_kwp.inc"

using vectors::hex;

namespace
{

/// Part sizes for the multi-part checks: below, at and around one block.
constexpr size_t kParts[] = { 1, 15, 16, 17, 33 };
/// The one GCM tag length the device produces.
constexpr CK_ULONG kGcmTagBits = 128;

} // namespace

class unwrap_kat : public UnwrapSession
{
  protected:
    /// The token key for `key` of `family`, unwrapped once per case.
    CK_OBJECT_HANDLE key_for(const host::Bytes &key, CK_MECHANISM_TYPE family)
    {
        auto it = keys_.find({ family, key });
        if (it != keys_.end())
        {
            return it->second;
        }
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        unwrap_known(key, family, &obj);
        keys_[{ family, key }] = obj;
        return obj;
    }

    std::map<std::pair<CK_MECHANISM_TYPE, host::Bytes>, CK_OBJECT_HANDLE> keys_;
};

TEST_F(unwrap_kat, aes_cbc_nist)
{
    for (const auto &v : vectors::kAesCbcNist)
    {
        SCOPED_TRACE(std::string("key ") + v.key + " pt " + v.pt);
        CK_OBJECT_HANDLE key = key_for(hex(v.key), CKM_AES_CBC);
        ASSERT_FALSE(HasFatalFailure());
        host::Bytes iv = hex(v.iv);
        CK_MECHANISM mech = { CKM_AES_CBC, iv.data(), static_cast<CK_ULONG>(iv.size()) };
        std::vector<CK_BYTE> out;
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech, key, hex(v.pt), out));
        EXPECT_EQ(hex(v.ct), out);
        ASSERT_CKR_OK(crypt_oneshot(s_, false, &mech, key, hex(v.ct), out));
        EXPECT_EQ(hex(v.pt), out);
    }
}

TEST_F(unwrap_kat, aes_xts_nist)
{
    for (const auto &v : vectors::kAesXtsNist)
    {
        SCOPED_TRACE(std::string("key ") + v.key + " tweak " + v.iv);
        CK_OBJECT_HANDLE key = key_for(hex(v.key), CKM_AES_XTS);
        ASSERT_FALSE(HasFatalFailure());
        host::Bytes tweak = hex(v.iv);
        CK_MECHANISM mech = { CKM_AES_XTS, tweak.data(), static_cast<CK_ULONG>(tweak.size()) };
        std::vector<CK_BYTE> out;
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech, key, hex(v.pt), out));
        EXPECT_EQ(hex(v.ct), out);
        ASSERT_CKR_OK(crypt_oneshot(s_, false, &mech, key, hex(v.ct), out));
        EXPECT_EQ(hex(v.pt), out);
    }
}

TEST_F(unwrap_kat, aes_cbc_pkcs5_wycheproof)
{
    for (const auto &v : vectors::kWycheproofAesCbcPkcs5)
    {
        SCOPED_TRACE("tcId " + std::to_string(v.tc_id));
        CK_OBJECT_HANDLE key = key_for(hex(v.key), CKM_AES_CBC);
        ASSERT_FALSE(HasFatalFailure());
        host::Bytes iv = hex(v.iv);
        CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv.data(), static_cast<CK_ULONG>(iv.size()) };
        std::vector<CK_BYTE> out;
        CK_RV rv = crypt_oneshot(s_, false, &mech, key, hex(v.ct), out);
        if (v.valid)
        {
            ASSERT_CKR_OK(rv);
            EXPECT_EQ(hex(v.msg), out);
            ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech, key, hex(v.msg), out));
            EXPECT_EQ(hex(v.ct), out);
        }
        else
        {
            // No ciphertext at all is a length error, a bad padding block not.
            EXPECT_CKR(
                (v.ct[0] == '\0') ? CKR_ENCRYPTED_DATA_LEN_RANGE : CKR_ENCRYPTED_DATA_INVALID,
                rv
            );
            EXPECT_TRUE(out.empty());
        }
    }
}

TEST_F(unwrap_kat, aes_gcm_wycheproof)
{
    for (const auto &v : vectors::kWycheproofAesGcm)
    {
        SCOPED_TRACE("tcId " + std::to_string(v.tc_id));
        CK_OBJECT_HANDLE key = key_for(hex(v.key), CKM_AES_GCM);
        ASSERT_FALSE(HasFatalFailure());
        host::Bytes iv = hex(v.iv);
        host::Bytes aad = hex(v.aad);
        CK_GCM_PARAMS gcm = { iv.data(),
                              static_cast<CK_ULONG>(iv.size()),
                              static_cast<CK_ULONG>(iv.size() * CHAR_BIT),
                              aad.data(),
                              static_cast<CK_ULONG>(aad.size()),
                              kGcmTagBits };
        CK_MECHANISM mech = { CKM_AES_GCM, &gcm, sizeof(gcm) };
        host::Bytes sealed = hex(v.ct);
        host::Bytes tag = hex(v.tag);
        sealed.insert(sealed.end(), tag.begin(), tag.end());
        std::vector<CK_BYTE> out;
        CK_RV rv = crypt_oneshot(s_, false, &mech, key, sealed, out);
        if (v.valid)
        {
            ASSERT_CKR_OK(rv);
            EXPECT_EQ(hex(v.msg), out);
            ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech, key, hex(v.msg), out));
            EXPECT_EQ(sealed, out);
        }
        else
        {
            // A failed tag check is the generic device failure (README).
            EXPECT_CKR(CKR_FUNCTION_FAILED, rv);
            EXPECT_TRUE(out.empty());
        }
    }
}

TEST_F(unwrap_kat, aes_kwp_wycheproof_inside_the_unwrap)
{
    // The inner layer of a CKM_RSA_AES_KEY_WRAP blob is RFC 5649 under the
    // KEK the OAEP block carries, so each vector's KEK and wrap make a blob.
    // A valid wrap of an AES key length must unwrap to that key; any other
    // must be refused without an object, by length when no AES key fits it.
    for (const auto &v : vectors::kWycheproofAesKwp)
    {
        SCOPED_TRACE("tcId " + std::to_string(v.tc_id));
        host::Bytes kek = hex(v.key);
        host::Bytes msg = hex(v.msg);
        host::Bytes ct = hex(v.ct);
        RsaAesMechanism m(CKM_SHA256, kek.size() * CHAR_BIT);
        host::Bytes blob = host::rsa_oaep_encrypt(host_pub_.get(), "SHA256", kek, host::Bytes());
        blob.insert(blob.end(), ct.begin(), ct.end());
        bool aes_len = (msg.size() == 16) || (msg.size() == 24) || (msg.size() == 32);
        bool fits = (ct.size() == 24) || (ct.size() == 32) || (ct.size() == 40);
        CK_ULONG before = count_objects(s_);
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        CK_RV rv = unwrap_key(s_, priv_, &m.mech, blob, CKM_AES_CBC, &obj);
        if (v.valid && aes_len)
        {
            ASSERT_CKR_OK(rv);
            CK_BYTE iv[kAesBlock] = {};
            CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
            std::vector<CK_BYTE> out;
            ASSERT_CKR_OK(crypt_oneshot(s_, true, &cbc, obj, pattern(32), out));
            EXPECT_EQ(
                host::aes_cbc_encrypt(msg, host::Bytes(kAesBlock, 0), pattern(32), false),
                out
            );
            ASSERT_CKR_OK(p11()->C_DestroyObject(s_, obj));
        }
        else
        {
            EXPECT_CKR(fits ? CKR_WRAPPED_KEY_INVALID : CKR_WRAPPED_KEY_LEN_RANGE, rv);
            EXPECT_EQ(before, count_objects(s_));
        }
    }
}

TEST_F(unwrap_kat, multipart_parts_give_the_known_answers)
{
    // CBC: the longest NIST AES-256 vector. CBC-PAD: the host oracle.
    const auto &nist = *std::max_element(
        std::begin(vectors::kAesCbcNist),
        std::end(vectors::kAesCbcNist),
        [](const auto &a, const auto &b) {
            return (std::strlen(a.key) < std::strlen(b.key)) ||
                   ((std::strlen(a.key) == std::strlen(b.key)) &&
                    (std::strlen(a.pt) < std::strlen(b.pt)));
        }
    );
    host::Bytes cbc_key = hex(nist.key);
    host::Bytes iv = hex(nist.iv);
    CK_OBJECT_HANDLE cbc = key_for(cbc_key, CKM_AES_CBC);
    ASSERT_FALSE(HasFatalFailure());
    CK_MECHANISM raw = { CKM_AES_CBC, iv.data(), static_cast<CK_ULONG>(iv.size()) };
    CK_MECHANISM pad = { CKM_AES_CBC_PAD, iv.data(), static_cast<CK_ULONG>(iv.size()) };
    std::vector<CK_BYTE> plain = pattern(100);
    host::Bytes padded = host::aes_cbc_encrypt(cbc_key, iv, plain, true);

    // XTS: a 48-byte NIST vector. GCM: the longest Wycheproof vector.
    const auto &xts = *std::find_if(
        std::begin(vectors::kAesXtsNist),
        std::end(vectors::kAesXtsNist),
        [](const auto &v) { return std::strlen(v.pt) == 96; }
    );
    host::Bytes tweak = hex(xts.iv);
    CK_OBJECT_HANDLE xts_key = key_for(hex(xts.key), CKM_AES_XTS);
    ASSERT_FALSE(HasFatalFailure());
    CK_MECHANISM xts_mech = { CKM_AES_XTS, tweak.data(), static_cast<CK_ULONG>(tweak.size()) };
    const auto &gv = *std::max_element(
        std::begin(vectors::kWycheproofAesGcm),
        std::end(vectors::kWycheproofAesGcm),
        [](const auto &a, const auto &b) {
            return (!a.valid && b.valid) ||
                   ((a.valid == b.valid) && (std::strlen(a.msg) < std::strlen(b.msg)));
        }
    );
    host::Bytes gcm_iv = hex(gv.iv);
    host::Bytes aad = hex(gv.aad);
    CK_GCM_PARAMS gcm = { gcm_iv.data(),
                          static_cast<CK_ULONG>(gcm_iv.size()),
                          static_cast<CK_ULONG>(gcm_iv.size() * CHAR_BIT),
                          aad.data(),
                          static_cast<CK_ULONG>(aad.size()),
                          kGcmTagBits };
    CK_MECHANISM gcm_mech = { CKM_AES_GCM, &gcm, sizeof(gcm) };
    CK_OBJECT_HANDLE gcm_key = key_for(hex(gv.key), CKM_AES_GCM);
    ASSERT_FALSE(HasFatalFailure());
    host::Bytes sealed = hex(gv.ct);
    host::Bytes tag = hex(gv.tag);
    sealed.insert(sealed.end(), tag.begin(), tag.end());

    struct
    {
        const char *what;
        CK_MECHANISM *mech;
        CK_OBJECT_HANDLE key;
        host::Bytes plain;
        host::Bytes cipher;
    } cases[] = {
        { "CBC", &raw, cbc, hex(nist.pt), hex(nist.ct) },
        { "CBC-PAD", &pad, cbc, plain, padded },
        { "XTS", &xts_mech, xts_key, hex(xts.pt), hex(xts.ct) },
        { "GCM", &gcm_mech, gcm_key, hex(gv.msg), sealed },
    };
    for (const auto &c : cases)
    {
        for (size_t part : kParts)
        {
            SCOPED_TRACE(std::string(c.what) + " in parts of " + std::to_string(part));
            std::vector<CK_BYTE> out;
            ASSERT_CKR_OK(crypt_multipart(s_, true, c.mech, c.key, c.plain, part, out));
            EXPECT_EQ(c.cipher, out);
            ASSERT_CKR_OK(crypt_multipart(s_, false, c.mech, c.key, c.cipher, part, out));
            EXPECT_EQ(c.plain, out);
        }
    }
}
