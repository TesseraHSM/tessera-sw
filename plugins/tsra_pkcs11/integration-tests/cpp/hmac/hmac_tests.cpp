// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file hmac_tests.cpp
///
/// C_Sign* and C_Verify* with CKM_SHA256_HMAC, CKM_SHA384_HMAC and
/// CKM_SHA512_HMAC through the module ABI. HMAC keys come only from HKDF, so
/// each hash has a known chain: a NIST CAVP ECDH vector gives the base key's
/// private scalar (unwrapped into the token), the peer point and the shared
/// secret, HKDF on the host over that secret in the device's byte order (see
/// device_ikm) gives the key's value, and every tag must equal host HMAC
/// bit for bit. One curve per hash: P-256 with SHA-256, P-384 with SHA-384,
/// P-521 with SHA-512. Also: every split of a multi-part message, the
/// 1024-byte message limit, the refusals of a verification (which compares
/// in the module, in constant time), sizing, the key type and usage rules, a
/// token key across a relogin, and that every way an operation ends gives its
/// device key back. The constant-time compare is unit-tested in
/// tests/wipe_test.c, the sign mechanism table in tests/ec_template_test.c.

#include <algorithm>
#include <climits>
#include <gtest/gtest.h>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_key.h"
#include "tsra_pkcs11_template.h"
#include "utils/aes_helpers.hpp"
#include "utils/derive_helpers.hpp"
#include "utils/ec_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/leak_gate.hpp"
#include "utils/module.hpp"
#include "utils/rsa_helpers.hpp"
#include "vectors/ecdh_nist.inc"

namespace
{

CK_OBJECT_CLASS g_secret_class = CKO_SECRET_KEY;
CK_KEY_TYPE g_generic = CKK_GENERIC_SECRET;
CK_BBOOL g_yes = CK_TRUE;
CK_BBOOL g_no = CK_FALSE;

/// The HKDF salt and info of the chains.
const host::Bytes kSalt = { 's', 'a', 'l', 't' };
const host::Bytes kInfo = { 'h', 'm', 'a', 'c' };

/// The message most cases tag, longer than any hash block, and the shorter
/// messages of the known-answer case.
constexpr size_t kMsgLen = 300;
constexpr size_t kShortMsg = 1;
constexpr size_t kMidMsg = 100;

/// Part sizes: one that divides no block, and SHA-256's block.
constexpr size_t kOddPart = 7;
constexpr size_t kBlockPart = 64;

/// What the sizing case fills its buffer with, to see what was written.
constexpr CK_BYTE kFill = 0xEE;

/// One hash: its HKDF PRF and HMAC, its key type, its tag length, and the
/// curve of the NIST vector its chain starts from.
struct Chain
{
    const char *md;
    CK_MECHANISM_TYPE prf;
    CK_MECHANISM_TYPE mech;
    CK_KEY_TYPE key_type;
    size_t tag_len;
    const char *curve;
};

const Chain kChains[] = {
    { "SHA256",
      CKM_SHA256,
      CKM_SHA256_HMAC,
      CKK_SHA256_HMAC,
      TSRA_PKCS11_SHA256_DIGEST_LEN,
      "P-256" },
    { "SHA384",
      CKM_SHA384,
      CKM_SHA384_HMAC,
      CKK_SHA384_HMAC,
      TSRA_PKCS11_SHA384_DIGEST_LEN,
      "P-384" },
    { "SHA512",
      CKM_SHA512,
      CKM_SHA512_HMAC,
      CKK_SHA512_HMAC,
      TSRA_PKCS11_SHA512_DIGEST_LEN,
      "P-521" },
};

/// The first NIST ECDH vector on `curve`.
const vectors::EcdhVector &nist_vector(std::string_view curve)
{
    for (const vectors::EcdhVector &v : vectors::kEcdhNist)
    {
        if (curve == v.curve)
        {
            return v;
        }
    }
    throw std::runtime_error("no NIST ECDH vector for " + std::string(curve));
}

/// Feed `msg` to an initialised sign (`sign`) or verify operation in parts of
/// the sizes in `parts`, empty parts included, then finish it: a sign probes
/// the length and fills `tag`, a verify checks `tag`. The parts must cover
/// `msg`.
CK_RV run_parts(
    CK_SESSION_HANDLE s,
    bool sign,
    const host::Bytes &msg,
    const std::vector<size_t> &parts,
    std::vector<CK_BYTE> &tag
)
{
    size_t off = 0;
    CK_RV rv = CKR_OK;
    for (size_t n : parts)
    {
        CK_BYTE_PTR p = const_cast<CK_BYTE_PTR>(msg.data()) + off;
        rv = sign ? p11()->C_SignUpdate(s, p, static_cast<CK_ULONG>(n))
                  : p11()->C_VerifyUpdate(s, p, static_cast<CK_ULONG>(n));
        if (rv != CKR_OK)
        {
            return rv;
        }
        off += n;
    }
    if (off != msg.size())
    {
        return CKR_GENERAL_ERROR; /* a test bug: the parts miss bytes */
    }
    if (!sign)
    {
        return p11()->C_VerifyFinal(s, tag.data(), static_cast<CK_ULONG>(tag.size()));
    }
    CK_ULONG need = 0;
    rv = p11()->C_SignFinal(s, nullptr, &need);
    if (rv != CKR_OK)
    {
        return rv;
    }
    tag.assign(need, 0);
    rv = p11()->C_SignFinal(s, tag.data(), &need);
    tag.resize((rv == CKR_OK) ? need : 0);
    return rv;
}

/// Multi-part sign of `msg` in `parts`.
CK_RV sign_parts(
    CK_SESSION_HANDLE s,
    CK_MECHANISM_TYPE mech,
    CK_OBJECT_HANDLE key,
    const host::Bytes &msg,
    const std::vector<size_t> &parts,
    std::vector<CK_BYTE> &tag
)
{
    CK_MECHANISM m = { mech, nullptr, 0 };
    CK_RV rv = p11()->C_SignInit(s, &m, key);
    return (rv == CKR_OK) ? run_parts(s, true, msg, parts, tag) : rv;
}

/// Multi-part verify of `tag` over `msg` in `parts`.
CK_RV verify_parts(
    CK_SESSION_HANDLE s,
    CK_MECHANISM_TYPE mech,
    CK_OBJECT_HANDLE key,
    const host::Bytes &msg,
    const std::vector<size_t> &parts,
    std::vector<CK_BYTE> tag
)
{
    CK_MECHANISM m = { mech, nullptr, 0 };
    CK_RV rv = p11()->C_VerifyInit(s, &m, key);
    return (rv == CKR_OK) ? run_parts(s, false, msg, parts, tag) : rv;
}

/// Parts of `chunk` bytes covering `n` bytes.
std::vector<size_t> chunks(size_t n, size_t chunk)
{
    std::vector<size_t> out;
    for (size_t off = 0; off < n; off += chunk)
    {
        out.push_back(std::min(chunk, n - off));
    }
    return out;
}

/// The ways to split a message of `n` bytes, each with its name.
std::vector<std::pair<std::string, std::vector<size_t>>> splits(size_t n)
{
    return {
        { "one part", { n } },
        { "byte by byte", chunks(n, 1) },
        { "parts of kOddPart bytes", chunks(n, kOddPart) },
        { "parts of kBlockPart bytes", chunks(n, kBlockPart) },
        { "empty parts first, between and last", { 0, n / 3, 0, 0, n - (n / 3), 0 } },
    };
}

/// A copy of `tag` with bit `bit` of byte `at` flipped.
std::vector<CK_BYTE> flipped(std::vector<CK_BYTE> tag, size_t at, unsigned bit)
{
    tag[at] ^= static_cast<CK_BYTE>(1u << bit);
    return tag;
}

} // namespace

/// A logged-in session that derives HMAC keys over the known chains. Each
/// chain's base key and ECDH secret are made on first use in a test.
class hmac : public PrivateUnwrapSession
{
  protected:
    /// The ECDH secret of chain `c`: its base key is the NIST scalar
    /// unwrapped into the token, its peer the NIST point. ASSERTs.
    void chain_secret(const Chain &c, CK_OBJECT_HANDLE *secret)
    {
        CK_OBJECT_HANDLE &cached = secrets_[c.key_type];
        if (cached == CK_INVALID_HANDLE)
        {
            const vectors::EcdhVector &v = nist_vector(c.curve);
            host::Pkey k = host::ec_private(v.curve, vectors::hex(v.priv));
            UnwrappedPair base;
            ASSERT_NO_FATAL_FAILURE(unwrap_pair(k.get(), CKK_EC, CKA_DERIVE, &base));
            host::Bytes peer = vectors::hex(v.pub);
            EcdhMechanism m(peer); /* points into `peer` */
            CK_ATTRIBUTE tmpl[] = {
                { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
                { CKA_KEY_TYPE, &g_generic, sizeof(g_generic) },
            };
            ASSERT_CKR_OK(p11()->C_DeriveKey(s_, &m.mech, base.priv, tmpl, std::size(tmpl), &cached)
            );
            bases_[c.key_type] = base;
        }
        *secret = cached;
    }

    /// The HMAC key of chain `c` from HKDF with `info` and the template's
    /// extra attributes, and its value as the host computes it. ASSERTs.
    void chain_key(
        const Chain &c,
        CK_OBJECT_HANDLE *key,
        host::Bytes *value,
        const host::Bytes &info = kInfo,
        const std::vector<CK_ATTRIBUTE> &extra = {}
    )
    {
        CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
        ASSERT_NO_FATAL_FAILURE(chain_secret(c, &secret));
        CK_KEY_TYPE kt = c.key_type;
        std::vector<CK_ATTRIBUTE> tmpl = {
            { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
            { CKA_KEY_TYPE, &kt, sizeof(kt) },
        };
        tmpl.insert(tmpl.end(), extra.begin(), extra.end());
        HkdfMechanism h(c.prf, kSalt, info);
        ASSERT_CKR_OK(p11()->C_DeriveKey(
            s_,
            &h.mech,
            secret,
            tmpl.data(),
            static_cast<CK_ULONG>(tmpl.size()),
            key
        ));
        const vectors::EcdhVector &v = nist_vector(c.curve);
        *value = host::hkdf(c.md, device_ikm(vectors::hex(v.shared)), kSalt, info, c.tag_len);
        ASSERT_EQ(c.tag_len, value->size());
    }

    std::map<CK_KEY_TYPE, CK_OBJECT_HANDLE> secrets_;
    std::map<CK_KEY_TYPE, UnwrappedPair> bases_;
};

// ---------------------------------------------------------------------------
// Tags against the host
// ---------------------------------------------------------------------------

TEST_F(hmac, tags_match_the_host_over_a_known_chain_in_device_byte_order)
{
    for (const Chain &c : kChains)
    {
        SCOPED_TRACE(std::string(c.md) + " on " + c.curve);
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        host::Bytes value;
        ASSERT_NO_FATAL_FAILURE(chain_key(c, &key, &value));
        for (size_t len : { size_t{ 0 }, kShortMsg, kMidMsg, size_t{ HMAC_MAX_DATA_LEN } })
        {
            SCOPED_TRACE(std::to_string(len) + " bytes");
            host::Bytes msg = pattern(len);
            std::vector<CK_BYTE> tag;
            ASSERT_CKR_OK(sign_oneshot(s_, c.mech, key, msg, tag));
            host::Bytes want = host::hmac(c.md, value, msg);
            ASSERT_FALSE(want.empty());
            EXPECT_EQ(want, tag) << "HMAC under HKDF over the known secret, as on the host";
            EXPECT_CKR_OK(verify_oneshot(s_, c.mech, key, msg, want)) << "the host's tag verifies";
        }
    }
}

TEST_F(hmac, multi_part_matches_the_host_for_every_split)
{
    host::Bytes msg = pattern(kMsgLen);
    for (const Chain &c : kChains)
    {
        SCOPED_TRACE(c.md);
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        host::Bytes value;
        ASSERT_NO_FATAL_FAILURE(chain_key(c, &key, &value));
        host::Bytes want = host::hmac(c.md, value, msg);
        for (const auto &split : splits(msg.size()))
        {
            SCOPED_TRACE(split.first);
            std::vector<CK_BYTE> tag;
            ASSERT_CKR_OK(sign_parts(s_, c.mech, key, msg, split.second, tag));
            EXPECT_EQ(want, tag) << "the parts tag as the whole message";
            EXPECT_CKR_OK(verify_parts(s_, c.mech, key, msg, split.second, want))
                << "the host's tag verifies in the same parts";
        }
        // The empty message with no part at all, and with one empty part.
        host::Bytes empty;
        host::Bytes want_empty = host::hmac(c.md, value, empty);
        for (const std::vector<size_t> &parts : { std::vector<size_t>{}, std::vector<size_t>{ 0 } })
        {
            SCOPED_TRACE(std::to_string(parts.size()) + " parts of the empty message");
            std::vector<CK_BYTE> tag;
            ASSERT_CKR_OK(sign_parts(s_, c.mech, key, empty, parts, tag));
            EXPECT_EQ(want_empty, tag) << "the empty message tags as on the host";
            EXPECT_CKR_OK(verify_parts(s_, c.mech, key, empty, parts, want_empty))
                << "and verifies";
        }
    }
}

// ---------------------------------------------------------------------------
// The message limit
// ---------------------------------------------------------------------------

TEST_F(hmac, a_message_over_1024_bytes_is_data_len_range_and_ends_the_operation)
{
    host::Bytes full = pattern(HMAC_MAX_DATA_LEN);
    host::Bytes over = pattern(HMAC_MAX_DATA_LEN + 1);
    for (const Chain &c : kChains)
    {
        SCOPED_TRACE(c.md);
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        host::Bytes value;
        ASSERT_NO_FATAL_FAILURE(chain_key(c, &key, &value));
        CK_MECHANISM m = { c.mech, nullptr, 0 };
        std::vector<CK_BYTE> tag(c.tag_len);
        CK_ULONG len = static_cast<CK_ULONG>(tag.size());

        // Positive controls: exactly the limit, one-shot and in parts.
        std::vector<CK_BYTE> got;
        ASSERT_CKR_OK(sign_oneshot(s_, c.mech, key, full, got));
        EXPECT_EQ(host::hmac(c.md, value, full), got) << "1024 bytes are taken in one call";
        ASSERT_CKR_OK(sign_parts(s_, c.mech, key, full, { HMAC_MAX_DATA_LEN - 1, 0, 1, 0 }, got))
            << "an empty part after the limit is reached is still taken";
        EXPECT_EQ(host::hmac(c.md, value, full), got) << "1024 bytes are taken in parts";

        // One-shot, the sizing call included.
        ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, key));
        EXPECT_CKR(
            CKR_DATA_LEN_RANGE,
            p11()->C_Sign(s_, over.data(), static_cast<CK_ULONG>(over.size()), nullptr, &len)
        ) << "the device command holds at most 1024 bytes";
        EXPECT_CKR(
            CKR_OPERATION_NOT_INITIALIZED,
            p11()->C_Sign(s_, full.data(), static_cast<CK_ULONG>(full.size()), tag.data(), &len)
        ) << "the refusal ended the operation";
        ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &m, key));
        EXPECT_CKR(
            CKR_DATA_LEN_RANGE,
            p11()->C_Verify(
                s_,
                over.data(),
                static_cast<CK_ULONG>(over.size()),
                tag.data(),
                static_cast<CK_ULONG>(tag.size())
            )
        ) << "a verification holds the same limit";
        EXPECT_CKR(
            CKR_OPERATION_NOT_INITIALIZED,
            p11()->C_VerifyFinal(s_, tag.data(), static_cast<CK_ULONG>(tag.size()))
        ) << "the refusal ended the operation";

        // Multi-part: the part that crosses the limit, and one that alone exceeds it.
        for (bool sign : { true, false })
        {
            SCOPED_TRACE(sign ? "sign" : "verify");
            for (const std::vector<size_t> &parts :
                 { std::vector<size_t>{ HMAC_MAX_DATA_LEN - 1, 2 },
                   std::vector<size_t>{ HMAC_MAX_DATA_LEN, 1 },
                   std::vector<size_t>{ HMAC_MAX_DATA_LEN + 1 } })
            {
                ASSERT_CKR_OK(
                    sign ? p11()->C_SignInit(s_, &m, key) : p11()->C_VerifyInit(s_, &m, key)
                );
                CK_RV rv = CKR_OK;
                size_t off = 0;
                for (size_t n : parts)
                {
                    CK_ULONG part = static_cast<CK_ULONG>(n);
                    rv = sign ? p11()->C_SignUpdate(s_, over.data() + off, part)
                              : p11()->C_VerifyUpdate(s_, over.data() + off, part);
                    off += n;
                    if (rv != CKR_OK)
                    {
                        break;
                    }
                }
                EXPECT_CKR(CKR_DATA_LEN_RANGE, rv) << "the parts add up to over 1024 bytes";
                EXPECT_EQ(over.size(), off) << "the last part is the refused one";
                EXPECT_CKR(
                    CKR_OPERATION_NOT_INITIALIZED,
                    sign ? p11()->C_SignFinal(s_, tag.data(), &len)
                         : p11()->C_VerifyFinal(s_, tag.data(), static_cast<CK_ULONG>(tag.size()))
                ) << "the refusal ended the operation";
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

TEST_F(hmac, a_wrong_tag_is_signature_invalid_and_a_wrong_length_signature_len_range)
{
    host::Bytes msg = pattern(kMsgLen);
    const std::vector<size_t> parts = { kMsgLen / 2, kMsgLen - (kMsgLen / 2) };
    for (const Chain &c : kChains)
    {
        SCOPED_TRACE(c.md);
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        host::Bytes value;
        ASSERT_NO_FATAL_FAILURE(chain_key(c, &key, &value));
        std::vector<CK_BYTE> tag = host::hmac(c.md, value, msg);
        ASSERT_CKR_OK(verify_oneshot(s_, c.mech, key, msg, tag));
        ASSERT_CKR_OK(verify_parts(s_, c.mech, key, msg, parts, tag));

        for (size_t at : { size_t{ 0 }, c.tag_len / 2, c.tag_len - 1 })
        {
            for (unsigned bit : { 0u, static_cast<unsigned>(CHAR_BIT - 1) })
            {
                SCOPED_TRACE("byte " + std::to_string(at) + ", bit " + std::to_string(bit));
                std::vector<CK_BYTE> bad = flipped(tag, at, bit);
                EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, c.mech, key, msg, bad))
                    << "a tag with one bit flipped";
                EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_parts(s_, c.mech, key, msg, parts, bad))
                    << "a tag with one bit flipped, in parts";
            }
        }
        host::Bytes other_msg = msg;
        other_msg[0] ^= 1;
        EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, c.mech, key, other_msg, tag))
            << "another message";

        // The tag of another key of the same type, from the same secret.
        CK_OBJECT_HANDLE other = CK_INVALID_HANDLE;
        host::Bytes other_value;
        ASSERT_NO_FATAL_FAILURE(chain_key(c, &other, &other_value, { 'o', 't', 'h', 'e', 'r' }));
        std::vector<CK_BYTE> other_tag;
        ASSERT_CKR_OK(sign_oneshot(s_, c.mech, other, msg, other_tag));
        ASSERT_EQ(host::hmac(c.md, other_value, msg), other_tag);
        ASSERT_NE(tag, other_tag);
        EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, c.mech, key, msg, other_tag))
            << "another key's tag";
        EXPECT_CKR(CKR_SIGNATURE_INVALID, verify_parts(s_, c.mech, key, msg, parts, other_tag))
            << "another key's tag, in parts";

        // A tag of the wrong length is a length error, also another hash's length.
        std::vector<CK_BYTE> shorter(tag.begin(), tag.end() - 1);
        std::vector<CK_BYTE> longer = tag;
        longer.push_back(0);
        size_t other_len = (c.tag_len == TSRA_PKCS11_SHA512_DIGEST_LEN)
                               ? TSRA_PKCS11_SHA256_DIGEST_LEN
                               : TSRA_PKCS11_SHA512_DIGEST_LEN;
        for (const std::vector<CK_BYTE> &t : { shorter, longer, std::vector<CK_BYTE>(other_len) })
        {
            SCOPED_TRACE(std::to_string(t.size()) + " bytes");
            EXPECT_CKR(CKR_SIGNATURE_LEN_RANGE, verify_oneshot(s_, c.mech, key, msg, t))
                << "an HMAC tag is as long as the hash";
            EXPECT_CKR(CKR_SIGNATURE_LEN_RANGE, verify_parts(s_, c.mech, key, msg, parts, t))
                << "an HMAC tag is as long as the hash, in parts";
        }
        CK_MECHANISM m = { c.mech, nullptr, 0 };
        ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &m, key));
        EXPECT_CKR(
            CKR_SIGNATURE_LEN_RANGE,
            p11()->C_Verify(s_, msg.data(), static_cast<CK_ULONG>(msg.size()), nullptr, 0)
        ) << "no tag at all";
        EXPECT_CKR(
            CKR_OPERATION_NOT_INITIALIZED,
            p11()->C_Verify(
                s_,
                msg.data(),
                static_cast<CK_ULONG>(msg.size()),
                tag.data(),
                static_cast<CK_ULONG>(tag.size())
            )
        ) << "a refused verification ended the operation";
    }
}

TEST_F(hmac, sizing_follows_the_two_call_rules)
{
    host::Bytes msg = pattern(kMsgLen);
    for (const Chain &c : kChains)
    {
        SCOPED_TRACE(c.md);
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        host::Bytes value;
        ASSERT_NO_FATAL_FAILURE(chain_key(c, &key, &value));
        CK_MECHANISM m = { c.mech, nullptr, 0 };
        std::vector<CK_BYTE> buf(c.tag_len + 1, kFill);
        ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, key));
        CK_ULONG len = 0;
        ASSERT_CKR_OK(p11()->C_Sign(s_, msg.data(), kMsgLen, nullptr, &len));
        EXPECT_EQ(c.tag_len, len) << "a NULL buffer learns the hash length";
        len = c.tag_len - 1;
        EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_Sign(s_, msg.data(), kMsgLen, buf.data(), &len))
            << "a buffer one byte short";
        EXPECT_EQ(c.tag_len, len) << "the short buffer learns the length";
        EXPECT_EQ(kFill, buf[0]) << "nothing written";
        len = static_cast<CK_ULONG>(buf.size());
        ASSERT_CKR_OK(p11()->C_Sign(s_, msg.data(), kMsgLen, buf.data(), &len))
            << "the operation survived";
        EXPECT_EQ(c.tag_len, len) << "a larger buffer gets the exact length";
        EXPECT_EQ(kFill, buf[c.tag_len]) << "nothing past the tag";
        buf.resize(c.tag_len);
        EXPECT_EQ(host::hmac(c.md, value, msg), buf) << "the tag is the host's";
        EXPECT_CKR(
            CKR_OPERATION_NOT_INITIALIZED,
            p11()->C_Sign(s_, msg.data(), kMsgLen, buf.data(), &len)
        ) << "success ended it";

        // The same rules on the final call.
        ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, key));
        ASSERT_CKR_OK(p11()->C_SignUpdate(s_, msg.data(), kMsgLen));
        len = 0;
        ASSERT_CKR_OK(p11()->C_SignFinal(s_, nullptr, &len));
        EXPECT_EQ(c.tag_len, len) << "a NULL buffer learns the hash length on the final call";
        len = 1;
        EXPECT_CKR(CKR_BUFFER_TOO_SMALL, p11()->C_SignFinal(s_, buf.data(), &len))
            << "a short buffer on the final call";
        EXPECT_EQ(c.tag_len, len) << "the short buffer learns the length";
        ASSERT_CKR_OK(p11()->C_SignFinal(s_, buf.data(), &len));
        EXPECT_EQ(host::hmac(c.md, value, msg), buf) << "the final call's tag is the host's";
    }
}

// ---------------------------------------------------------------------------
// Key rules
// ---------------------------------------------------------------------------

TEST_F(hmac, mechanism_and_key_type_must_match)
{
    std::map<CK_KEY_TYPE, CK_OBJECT_HANDLE> keys;
    for (const Chain &c : kChains)
    {
        host::Bytes value;
        ASSERT_NO_FATAL_FAILURE(chain_key(c, &keys[c.key_type], &value));
    }
    for (const Chain &c : kChains)
    {
        CK_MECHANISM m = { c.mech, nullptr, 0 };
        for (const Chain &k : kChains)
        {
            SCOPED_TRACE(std::string(c.md) + " on a key of " + k.md);
            CK_RV want = (k.key_type == c.key_type) ? CKR_OK : CKR_KEY_TYPE_INCONSISTENT;
            EXPECT_CKR(want, p11()->C_SignInit(s_, &m, keys[k.key_type]))
                << "an HMAC key serves the mechanism of its hash only";
            abandon_operations(s_);
            EXPECT_CKR(want, p11()->C_VerifyInit(s_, &m, keys[k.key_type]))
                << "an HMAC key verifies with the mechanism of its hash only";
            abandon_operations(s_);
        }
    }

    // No other key type takes an HMAC mechanism.
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(chain_secret(kChains[0], &secret));
    const UnwrappedPair &ec = bases_[kChains[0].key_type];
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_aes_key(s_, AES256_KEY_BYTES, CK_TRUE, CK_TRUE, "aes", &aes));
    UnwrappedPair rsa;
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(host_rsa(kRsaSizes[0]), CKK_RSA, CKA_SIGN, &rsa));
    CK_MECHANISM m = { CKM_SHA256_HMAC, nullptr, 0 };
    for (const auto &other : std::vector<std::pair<const char *, CK_OBJECT_HANDLE>>{
             { "the ECDH secret, a CKK_GENERIC_SECRET", secret },
             { "an AES key", aes },
             { "an EC private key", ec.priv },
             { "an EC public key", ec.pub },
             { "an RSA private key", rsa.priv },
             { "an RSA public key", rsa.pub } })
    {
        SCOPED_TRACE(other.first);
        EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_SignInit(s_, &m, other.second))
            << "HMAC runs on an HMAC key only";
        EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_VerifyInit(s_, &m, other.second))
            << "HMAC verifies with an HMAC key only";
    }

    // Nor does an HMAC key take another sign mechanism.
    CK_OBJECT_HANDLE key = keys[CKK_SHA256_HMAC];
    for (CK_MECHANISM_TYPE mech : { CKM_ECDSA_SHA256, CKM_SHA256_RSA_PKCS })
    {
        CK_MECHANISM other = { mech, nullptr, 0 };
        EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, p11()->C_SignInit(s_, &other, key))
            << "an HMAC key takes no other sign mechanism";
    }

    // The HMAC mechanisms the device lacks, and a parameter.
    for (CK_MECHANISM_TYPE mech : { CKM_SHA_1_HMAC, CKM_SHA224_HMAC, CKM_SHA256_HMAC_GENERAL })
    {
        CK_MECHANISM other = { mech, nullptr, 0 };
        EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_SignInit(s_, &other, key))
            << "the device has no SHA-1, SHA-224 or truncated HMAC";
    }
    CK_ULONG param = TSRA_PKCS11_SHA256_DIGEST_LEN;
    CK_MECHANISM with_param = { CKM_SHA256_HMAC, &param, sizeof(param) };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, p11()->C_SignInit(s_, &with_param, key))
        << "CKM_SHA256_HMAC takes no parameter";
}

TEST_F(hmac, usage_flags_are_enforced)
{
    const Chain &c = kChains[0];
    host::Bytes msg = pattern(kMsgLen);
    CK_MECHANISM m = { c.mech, nullptr, 0 };

    CK_OBJECT_HANDLE verify_only = CK_INVALID_HANDLE;
    host::Bytes value;
    ASSERT_NO_FATAL_FAILURE(
        chain_key(c, &verify_only, &value, kInfo, { { CKA_SIGN, &g_no, sizeof(g_no) } })
    );
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_SignInit(s_, &m, verify_only))
        << "CKA_SIGN FALSE";
    EXPECT_CKR_OK(verify_oneshot(s_, c.mech, verify_only, msg, host::hmac(c.md, value, msg)))
        << "it verifies, though the device signs to check the tag";

    CK_OBJECT_HANDLE sign_only = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(
        chain_key(c, &sign_only, &value, kInfo, { { CKA_VERIFY, &g_no, sizeof(g_no) } })
    );
    EXPECT_CKR(CKR_KEY_FUNCTION_NOT_PERMITTED, p11()->C_VerifyInit(s_, &m, sign_only))
        << "CKA_VERIFY FALSE";
    std::vector<CK_BYTE> tag;
    EXPECT_CKR_OK(sign_oneshot(s_, c.mech, sign_only, msg, tag))
        << "CKA_VERIFY FALSE leaves signing";
    EXPECT_EQ(host::hmac(c.md, value, msg), tag) << "the sign-only key tags as on the host";

    // The only allowed-mechanism list an HMAC key can carry is its own
    // mechanism, so no key that lacks it exists to be refused at the init.
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(chain_secret(c, &secret));
    CK_KEY_TYPE kt = c.key_type;
    CK_MECHANISM_TYPE other = CKM_SHA384_HMAC;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_ALLOWED_MECHANISMS, &other, sizeof(other) },
    };
    HkdfMechanism h(c.prf, kSalt, kInfo);
    CK_OBJECT_HANDLE refused = CK_INVALID_HANDLE;
    EXPECT_CKR(
        CKR_TEMPLATE_INCONSISTENT,
        p11()->C_DeriveKey(s_, &h.mech, secret, tmpl, std::size(tmpl), &refused)
    ) << "a list without the key's own mechanism";
    EXPECT_EQ(CK_INVALID_HANDLE, refused) << "no object is left";
}

TEST_F(hmac, a_token_key_tags_alike_after_a_relogin)
{
    const Chain &c = kChains[1];
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    host::Bytes value;
    ASSERT_NO_FATAL_FAILURE(
        chain_key(c, &key, &value, kInfo, { { CKA_TOKEN, &g_yes, sizeof(g_yes) } })
    );
    host::Bytes msg = pattern(kMsgLen);
    host::Bytes want = host::hmac(c.md, value, msg);
    std::vector<CK_BYTE> tag;
    ASSERT_CKR_OK(sign_oneshot(s_, c.mech, key, msg, tag));
    EXPECT_EQ(want, tag) << "the token key tags as on the host";
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    ASSERT_CKR_OK(login_user(s_));
    tag.clear();
    EXPECT_CKR_OK(sign_oneshot(s_, c.mech, key, msg, tag)) << "the token key outlives the login";
    EXPECT_EQ(want, tag) << "the same tag after the relogin";
    EXPECT_CKR_OK(verify_oneshot(s_, c.mech, key, msg, want)) << "and the host's tag verifies";
    EXPECT_CKR_OK(p11()->C_DestroyObject(s_, key)) << "a token object is destroyed again";
}

// ---------------------------------------------------------------------------
// Device resources
// ---------------------------------------------------------------------------

TEST_F(hmac, every_way_an_operation_ends_gives_its_device_key_back)
{
    const Chain &c = kChains[0];
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    host::Bytes value;
    ASSERT_NO_FATAL_FAILURE(chain_key(c, &key, &value));
    host::Bytes msg = pattern(kMsgLen);
    host::Bytes over = pattern(HMAC_MAX_DATA_LEN + 1);
    std::vector<CK_BYTE> want = host::hmac(c.md, value, msg);
    std::vector<CK_BYTE> bad = flipped(want, 0, 0);
    CK_MECHANISM m = { c.mech, nullptr, 0 };
    CK_ULONG len = 0;
    std::vector<CK_BYTE> tag;
    std::vector<TerminationPath> paths = {
        { "one-shot sign", [&] { ASSERT_CKR_OK(sign_oneshot(s_, c.mech, key, msg, tag)); } },
        { "multi-part verify",
          [&] { ASSERT_CKR_OK(verify_parts(s_, c.mech, key, msg, { 1, kMsgLen - 1 }, want)); } },
        { "invalid tag, one-shot",
          [&] { ASSERT_CKR(CKR_SIGNATURE_INVALID, verify_oneshot(s_, c.mech, key, msg, bad)); } },
        { "invalid tag, multi-part",
          [&] {
              ASSERT_CKR(
                  CKR_SIGNATURE_INVALID,
                  verify_parts(s_, c.mech, key, msg, { kMsgLen }, bad)
              );
          } },
        { "message over the limit",
          [&] {
              ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, key));
              ASSERT_CKR(
                  CKR_DATA_LEN_RANGE,
                  p11()->C_Sign(s_, over.data(), static_cast<CK_ULONG>(over.size()), nullptr, &len)
              );
          } },
        { "part over the limit",
          [&] {
              ASSERT_CKR_OK(p11()->C_VerifyInit(s_, &m, key));
              ASSERT_CKR_OK(p11()->C_VerifyUpdate(s_, over.data(), HMAC_MAX_DATA_LEN));
              ASSERT_CKR(CKR_DATA_LEN_RANGE, p11()->C_VerifyUpdate(s_, over.data(), 1));
          } },
        { "update then cancel",
          [&] {
              ASSERT_CKR_OK(p11()->C_SignInit(s_, &m, key));
              ASSERT_CKR_OK(p11()->C_SignUpdate(s_, msg.data(), kMsgLen));
              ASSERT_CKR_OK(p11()->C_SignInit(s_, nullptr, key));
          } },
        { "session close",
          [&] {
              CK_SESSION_HANDLE other = 0;
              ASSERT_CKR_OK(
                  p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &other)
              );
              ASSERT_CKR_OK(p11()->C_VerifyInit(other, &m, key));
              ASSERT_CKR_OK(p11()->C_VerifyUpdate(other, msg.data(), kMsgLen));
              ASSERT_CKR_OK(p11()->C_CloseSession(other));
          } },
    };
    // The fresh operation runs on a key that is not private, which outlives
    // the gate's logout, and must still give the host's tag after it.
    CK_OBJECT_HANDLE survivor = CK_INVALID_HANDLE;
    host::Bytes survivor_value;
    ASSERT_NO_FATAL_FAILURE(
        chain_key(c, &survivor, &survivor_value, kInfo, { { CKA_PRIVATE, &g_no, sizeof(g_no) } })
    );
    std::vector<CK_BYTE> fresh_tag;
    auto fresh = [&] {
        CK_RV rv = sign_oneshot(s_, c.mech, survivor, msg, fresh_tag);
        return ((rv == CKR_OK) && (fresh_tag != host::hmac(c.md, survivor_value, msg)))
                   ? CKR_GENERAL_ERROR
                   : rv;
    };
    ASSERT_NO_FATAL_FAILURE(leak_gate(s_, paths, fresh));
}
