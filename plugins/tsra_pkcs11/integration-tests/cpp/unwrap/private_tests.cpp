// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file private_tests.cpp
///
/// C_UnwrapKey with CKM_RSA_AES_KEY_WRAP into RSA and EC private keys: a host
/// key of every RSA size and every curve unwraps, and the companion public key
/// the unwrap leaves is found by CKA_ID and carries the host key's public
/// values; the attributes both objects get; one row per template verdict with
/// no object left; the blob lengths of no key; one CKR_WRAPPED_KEY_INVALID and
/// no object for every bad blob; the usage flags that stay as unwrapped;
/// survival across a relogin; and that the file store never sees the private
/// key; and the leak gate. The full verdict matrix and the length windows are
/// in tests/unwrap_params_test.c, the RSA operations in rsa/, ECDH on unwrapped
/// keys in derive/derive_tests.cpp.

#include <cstring>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/aes_helpers.hpp"
#include "utils/ec_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/leak_gate.hpp"
#include "utils/module.hpp"
#include "utils/rsa_helpers.hpp"
#include "utils/store_dir.hpp"
#include "utils/unwrap_helpers.hpp"

namespace
{

/// The SHA-1 of `v`, what CKA_ID is by default.
host::Bytes sha1(const host::Bytes &v)
{
    return host::digest("SHA1", v);
}

/// The CK_BBOOL attribute `type` of `obj`; ASSERTs that it reads.
void expect_bool(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type, CK_BBOOL want)
{
    CK_BBOOL got = CK_FALSE;
    ASSERT_CKR_OK(get_attr(s, obj, type, &got)) << "attribute 0x" << std::hex << type;
    EXPECT_EQ(want, got) << "attribute 0x" << std::hex << type;
}

} // namespace

class private_unwrap : public PrivateUnwrapSession
{
};

TEST_F(private_unwrap, every_rsa_size_unwraps_with_its_companion)
{
    for (size_t bits : kRsaSizes)
    {
        SCOPED_TRACE(bits);
        EVP_PKEY *key = host_rsa(bits);
        UnwrappedPair pair;
        ASSERT_NO_FATAL_FAILURE(unwrap_pair(key, CKK_RSA, CKA_SIGN, &pair));
        host::Bytes n = host::bn_param(key, OSSL_PKEY_PARAM_RSA_N);
        host::Bytes e = host::bn_param(key, OSSL_PKEY_PARAM_RSA_E);
        for (CK_OBJECT_HANDLE obj : { pair.priv, pair.pub })
        {
            std::vector<CK_BYTE> got;
            ASSERT_CKR_OK(get_bytes(s_, obj, CKA_MODULUS, got));
            EXPECT_EQ(n, got) << "the host key's modulus";
            ASSERT_CKR_OK(get_bytes(s_, obj, CKA_PUBLIC_EXPONENT, got));
            EXPECT_EQ(e, got) << "the host key's exponent";
            ASSERT_CKR_OK(get_bytes(s_, obj, CKA_ID, got));
            EXPECT_EQ(sha1(n), got) << "CKA_ID is the SHA-1 of the modulus on both";
        }
        CK_ULONG mod_bits = 0;
        ASSERT_CKR_OK(get_attr(s_, pair.pub, CKA_MODULUS_BITS, &mod_bits));
        EXPECT_EQ(bits, mod_bits);
        std::vector<CK_BYTE> msg = pattern(100);
        std::vector<CK_BYTE> sig;
        ASSERT_CKR_OK(sign_oneshot(s_, CKM_SHA256_RSA_PKCS, pair.priv, msg, sig));
        EXPECT_EQ(host::rsa_sign(key, "SHA256", RSA_PKCS1_PADDING, msg), sig)
            << "the token holds the host's key";
        EXPECT_CKR_OK(verify_oneshot(s_, CKM_SHA256_RSA_PKCS, pair.pub, msg, sig))
            << "the companion verifies";
    }
}

TEST_F(private_unwrap, every_curve_unwraps_with_its_companion)
{
    for (const EcCurve &c : ec_curves())
    {
        SCOPED_TRACE(c.name);
        host::Pkey key = host::ec_generate(c.name);
        UnwrappedPair pair;
        ASSERT_NO_FATAL_FAILURE(unwrap_pair(key.get(), CKK_EC, CKA_SIGN, &pair));
        host::Bytes point = host::ec_point(key.get());
        EXPECT_EQ(point, ec_point(s_, pair.pub)) << "the host key's point";
        for (CK_OBJECT_HANDLE obj : { pair.priv, pair.pub })
        {
            std::vector<CK_BYTE> got;
            ASSERT_CKR_OK(get_bytes(s_, obj, CKA_EC_PARAMS, got));
            EXPECT_EQ(c.params, got);
            ASSERT_CKR_OK(get_bytes(s_, obj, CKA_ID, got));
            EXPECT_EQ(sha1(point), got) << "CKA_ID is the SHA-1 of the point on both";
        }
        std::vector<CK_BYTE> got;
        EXPECT_CKR(CKR_ATTRIBUTE_TYPE_INVALID, get_bytes(s_, pair.priv, CKA_EC_POINT, got))
            << "PKCS#11 defines the point on the public key only";
        std::vector<CK_BYTE> msg = pattern(64);
        std::vector<CK_BYTE> sig;
        ASSERT_CKR_OK(sign_oneshot(s_, CKM_ECDSA_SHA384, pair.priv, msg, sig));
        EXPECT_TRUE(host::ecdsa_verify(key.get(), "SHA384", msg, sig))
            << "the host verifies the token's signature with its own key";
        EXPECT_CKR_OK(verify_oneshot(s_, CKM_ECDSA_SHA384, pair.pub, msg, sig));
    }
}

TEST_F(private_unwrap, both_objects_carry_the_attributes_of_an_imported_key)
{
    UnwrappedPair pair;
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(host_rsa(2048), CKK_RSA, CKA_DECRYPT, &pair));
    for (const auto &f : std::vector<std::pair<CK_ATTRIBUTE_TYPE, CK_BBOOL>>{
             { CKA_PRIVATE, CK_TRUE },
             { CKA_SENSITIVE, CK_TRUE },
             { CKA_EXTRACTABLE, CK_FALSE },
             { CKA_ALWAYS_SENSITIVE, CK_FALSE },
             { CKA_NEVER_EXTRACTABLE, CK_FALSE },
             { CKA_LOCAL, CK_FALSE },
             { CKA_DECRYPT, CK_TRUE },
             { CKA_SIGN, CK_FALSE },
             { CKA_UNWRAP, CK_FALSE },
         })
    {
        ASSERT_NO_FATAL_FAILURE(expect_bool(s_, pair.priv, f.first, f.second));
    }
    for (const auto &f : std::vector<std::pair<CK_ATTRIBUTE_TYPE, CK_BBOOL>>{
             { CKA_PRIVATE, CK_FALSE },
             { CKA_LOCAL, CK_FALSE },
             { CKA_ENCRYPT, CK_TRUE },
             { CKA_VERIFY, CK_FALSE },
             { CKA_WRAP, CK_FALSE },
         })
    {
        ASSERT_NO_FATAL_FAILURE(expect_bool(s_, pair.pub, f.first, f.second));
    }
    CK_MECHANISM_TYPE kgm = 0;
    ASSERT_CKR_OK(get_attr(s_, pair.priv, CKA_KEY_GEN_MECHANISM, &kgm));
    EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, kgm) << "the key came from outside";
    for (CK_ATTRIBUTE_TYPE secret : { CKA_PRIVATE_EXPONENT,
                                      CKA_PRIME_1,
                                      CKA_PRIME_2,
                                      CKA_EXPONENT_1,
                                      CKA_EXPONENT_2,
                                      CKA_COEFFICIENT })
    {
        CK_BYTE buf[512];
        CK_ATTRIBUTE a = { secret, buf, sizeof(buf) };
        EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, p11()->C_GetAttributeValue(s_, pair.priv, &a, 1))
            << "a private component is sensitive: 0x" << std::hex << secret;
        EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, a.ulValueLen);
    }

    UnwrappedPair derive;
    host::Pkey ec = host::ec_generate("P-256");
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(ec.get(), CKK_EC, CKA_DERIVE, &derive));
    ASSERT_NO_FATAL_FAILURE(expect_bool(s_, derive.priv, CKA_DERIVE, CK_TRUE));
    ASSERT_NO_FATAL_FAILURE(expect_bool(s_, derive.priv, CKA_SIGN, CK_FALSE));
    ASSERT_NO_FATAL_FAILURE(expect_bool(s_, derive.pub, CKA_DERIVE, CK_TRUE))
        << "a deriving key's public half derives, as a generated pair's";
    ASSERT_NO_FATAL_FAILURE(expect_bool(s_, derive.pub, CKA_VERIFY, CK_FALSE));
}

TEST_F(private_unwrap, the_template_names_the_id_label_and_token_of_both)
{
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE kt = CKK_RSA;
    CK_BBOOL yes = CK_TRUE;
    CK_BYTE id[] = { 'k', 'e', 'y', '-', '1' };
    const char label[] = "named";
    std::vector<CK_ATTRIBUTE> tmpl = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_SIGN, &yes, sizeof(yes) },
        { CKA_ID, id, sizeof(id) },
        { CKA_LABEL, const_cast<char *>(label), sizeof(label) - 1 },
    };
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(unwrap_with_template(s_, priv_, blob_of(host_rsa(2048)), tmpl, &priv));
    std::vector<CK_OBJECT_HANDLE> found;
    ASSERT_NO_FATAL_FAILURE(
        find_by_id(s_, CKO_PUBLIC_KEY, std::vector<CK_BYTE>(id, id + sizeof(id)), label, &found)
    );
    ASSERT_EQ(1u, found.size()) << "the companion takes the template's CKA_ID and CKA_LABEL";
    ASSERT_NO_FATAL_FAILURE(expect_bool(s_, found[0], CKA_TOKEN, CK_FALSE));
    ASSERT_NO_FATAL_FAILURE(
        find_by_id(s_, CKO_PRIVATE_KEY, std::vector<CK_BYTE>(id, id + sizeof(id)), label, &found)
    );
    ASSERT_EQ(1u, found.size());
    EXPECT_EQ(priv, found[0]) << "C_UnwrapKey returns the private key";
}

TEST_F(private_unwrap, template_rules)
{
    host::Bytes rsa_blob = blob_of(host_rsa(2048));
    host::Pkey p384 = host::ec_generate("P-384");
    host::Bytes ec_blob = blob_of(p384.get());
    CK_OBJECT_CLASS cls_priv = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsa = CKK_RSA;
    CK_KEY_TYPE ec = CKK_EC;
    CK_KEY_TYPE aes = CKK_AES;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_BYTE modulus[256] = { 0x80 };
    CK_BYTE exponent[] = { 0x01, 0x00, 0x01 };
    std::vector<CK_BYTE> p256 = ec_curves()[0].params;
    std::vector<CK_BYTE> p384_params = ec_curves()[1].params;
    CK_ATTRIBUTE cls = { CKA_CLASS, &cls_priv, sizeof(cls_priv) };
    CK_ATTRIBUTE kt_rsa = { CKA_KEY_TYPE, &rsa, sizeof(rsa) };
    CK_ATTRIBUTE kt_ec = { CKA_KEY_TYPE, &ec, sizeof(ec) };
    CK_ATTRIBUTE sign = { CKA_SIGN, &yes, sizeof(yes) };
    struct Case
    {
        const char *what;
        const host::Bytes &blob;
        std::vector<CK_ATTRIBUTE> tmpl;
        CK_RV want;
        const char *rule;
    } cases[] = {
        { "no key type",
          rsa_blob,
          { cls, sign },
          CKR_TEMPLATE_INCOMPLETE,
          "CKA_KEY_TYPE is required" },
        { "no class",
          rsa_blob,
          { kt_rsa, sign },
          CKR_TEMPLATE_INCOMPLETE,
          "CKA_CLASS is required" },
        { "an AES key type",
          rsa_blob,
          { cls, { CKA_KEY_TYPE, &aes, sizeof(aes) }, sign },
          CKR_TEMPLATE_INCONSISTENT,
          "a private key is RSA or EC" },
        { "RSA signs and decrypts",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_DECRYPT, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT,
          "an RSA key signs or decrypts, not both" },
        { "RSA with no usage",
          rsa_blob,
          { cls, kt_rsa },
          CKR_TEMPLATE_INCONSISTENT,
          "an RSA key signs or decrypts" },
        { "RSA unwraps",
          rsa_blob,
          { cls, kt_rsa, { CKA_UNWRAP, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT,
          "the device refuses an RSA key that unwraps" },
        { "RSA signs and derives",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_DERIVE, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT,
          "one usage only" },
        { "EC signs and derives",
          ec_blob,
          { cls, kt_ec, sign, { CKA_DERIVE, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT,
          "an EC key signs or derives, not both" },
        { "EC decrypts",
          ec_blob,
          { cls, kt_ec, { CKA_DECRYPT, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT,
          "an EC key does not decrypt" },
        { "a modulus",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_MODULUS, modulus, sizeof(modulus) } },
          CKR_TEMPLATE_INCONSISTENT,
          "the blob carries the public values" },
        { "a public exponent",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent) } },
          CKR_TEMPLATE_INCONSISTENT,
          "the blob carries the public values" },
        { "a private exponent",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_PRIVATE_EXPONENT, modulus, sizeof(modulus) } },
          CKR_TEMPLATE_INCONSISTENT,
          "no key material in the template" },
        { "not sensitive",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_SENSITIVE, &no, sizeof(no) } },
          CKR_TEMPLATE_INCONSISTENT,
          "device keys exist only masked" },
        { "extractable",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_EXTRACTABLE, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT,
          "device keys exist only masked" },
        { "always authenticate",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_ALWAYS_AUTHENTICATE, &yes, sizeof(yes) } },
          CKR_ATTRIBUTE_VALUE_INVALID,
          "no context-specific login" },
        { "local",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_LOCAL, &yes, sizeof(yes) } },
          CKR_ATTRIBUTE_READ_ONLY,
          "the token sets CKA_LOCAL" },
        { "a public token key",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_TOKEN, &yes, sizeof(yes) }, { CKA_PRIVATE, &no, sizeof(no) } },
          CKR_TEMPLATE_INCONSISTENT,
          "a token private key is private" },
        { "a public session key",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_PRIVATE, &no, sizeof(no) } },
          CKR_OK,
          "a session private key may be public" },
        { "an RSA key with a curve",
          rsa_blob,
          { cls, kt_rsa, sign, { CKA_EC_PARAMS, p256.data(), p256.size() } },
          CKR_TEMPLATE_INCONSISTENT,
          "an RSA key has no curve" },
        { "another curve",
          ec_blob,
          { cls, kt_ec, sign, { CKA_EC_PARAMS, p256.data(), p256.size() } },
          CKR_TEMPLATE_INCONSISTENT,
          "the blob's length names P-384" },
        { "the blob's curve",
          ec_blob,
          { cls, kt_ec, sign, { CKA_EC_PARAMS, p384_params.data(), p384_params.size() } },
          CKR_OK,
          "CKA_EC_PARAMS may name the curve the blob has" },
        { "an RSA key in an EC blob",
          ec_blob,
          { cls, kt_rsa, sign },
          CKR_WRAPPED_KEY_LEN_RANGE,
          "an EC blob is too short for any RSA key" },
        { "an EC key in an RSA blob",
          rsa_blob,
          { cls, kt_ec, sign },
          CKR_WRAPPED_KEY_LEN_RANGE,
          "an RSA blob has no curve's length" },
    };
    for (Case &c : cases)
    {
        SCOPED_TRACE(c.what);
        CK_ULONG before = count_objects(s_);
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        EXPECT_CKR(c.want, unwrap_with_template(s_, priv_, c.blob, c.tmpl, &obj)) << c.rule;
        bool ok = (c.want == CKR_OK);
        EXPECT_EQ(ok, obj != CK_INVALID_HANDLE);
        EXPECT_EQ(before + (ok ? 2 : 0), count_objects(s_)) << "a pair or nothing";
    }
}

TEST_F(private_unwrap, a_blob_of_no_key_length_is_refused_without_the_device)
{
    PrivateTemplate rsa(CKK_RSA, CKA_SIGN, CK_FALSE, "len");
    PrivateTemplate ec(CKK_EC, CKA_SIGN, CK_FALSE, "len");
    host::Bytes good = blob_of(host_rsa(2048));
    host::Pkey p256 = host::ec_generate("P-256");
    host::Bytes ec_good = blob_of(p256.get());
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    for (const host::Bytes &b : { host::Bytes(good.begin(), good.end() - 1),
                                  host::Bytes(good.begin(), good.begin() + kOaepBlock),
                                  host::Bytes(good.begin(), good.begin() + kOaepBlock + 16),
                                  host::Bytes() })
    {
        EXPECT_CKR(CKR_WRAPPED_KEY_LEN_RANGE, unwrap_with_template(s_, priv_, b, rsa.attrs, &obj))
            << "an RSA blob of " << b.size() << " bytes";
    }
    host::Bytes longer = ec_good;
    longer.resize(ec_good.size() + 8, 0);
    EXPECT_CKR(CKR_WRAPPED_KEY_LEN_RANGE, unwrap_with_template(s_, priv_, longer, ec.attrs, &obj))
        << "an EC blob one semiblock too long";
    EXPECT_EQ(CK_INVALID_HANDLE, obj);
}

TEST_F(private_unwrap, a_bad_blob_is_one_error_and_no_object)
{
    EVP_PKEY *key = host_rsa(2048);
    host::Bytes pkcs8 = host::pkcs8(key);
    host::Bytes good = host::rsa_aes_key_wrap(host_pub_.get(), "SHA256", pkcs8);
    host::Bytes in_oaep = good;
    in_oaep[kOaepBlock / 2] ^= 0x01;
    host::Bytes in_kwp = good;
    in_kwp.back() ^= 0x01;
    host::Bytes sha384 = host::rsa_aes_key_wrap(host_pub_.get(), "SHA384", pkcs8);
    // A component off by one: the PKCS#8 still parses, the key is not
    // consistent, and the device refuses it on import.
    host::Bytes inconsistent = pkcs8;
    inconsistent[inconsistent.size() - 1] ^= 0x01;
    host::Bytes bad_key = host::rsa_aes_key_wrap(host_pub_.get(), "SHA256", inconsistent);
    // An EC key without its public point is as long as no curve's PKCS#8,
    // which the length rule refuses; one whose point is another key's is not.
    host::Pkey ec = host::ec_generate("P-256");
    host::Pkey other = host::ec_generate("P-256");
    host::Bytes ec_pkcs8 = host::pkcs8(ec.get());
    host::Bytes other_point = host::ec_point(other.get());
    std::copy(other_point.begin(), other_point.end(), ec_pkcs8.end() - other_point.size());
    host::Bytes foreign_point = host::rsa_aes_key_wrap(host_pub_.get(), "SHA256", ec_pkcs8);

    PrivateTemplate rsa(CKK_RSA, CKA_SIGN, CK_FALSE, "bad");
    PrivateTemplate ecdsa(CKK_EC, CKA_SIGN, CK_FALSE, "bad");
    struct
    {
        const char *what;
        const host::Bytes &blob;
        const std::vector<CK_ATTRIBUTE> &tmpl;
    } cases[] = {
        { "a byte of the OAEP block flipped", in_oaep, rsa.attrs },
        { "a byte of the key wrap flipped", in_kwp, rsa.attrs },
        { "OAEP with SHA-384, declared SHA-256", sha384, rsa.attrs },
        { "an inconsistent RSA key", bad_key, rsa.attrs },
        { "an EC key with another key's point", foreign_point, ecdsa.attrs },
    };
    for (const auto &c : cases)
    {
        SCOPED_TRACE(c.what);
        CK_ULONG before = count_objects(s_);
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        EXPECT_CKR(CKR_WRAPPED_KEY_INVALID, unwrap_with_template(s_, priv_, c.blob, c.tmpl, &obj))
            << "every SDK failure is one code: no decryption oracle";
        EXPECT_EQ(CK_INVALID_HANDLE, obj);
        EXPECT_EQ(before, count_objects(s_)) << "neither object stays";
    }
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    EXPECT_CKR_OK(unwrap_with_template(s_, priv_, good, rsa.attrs, &obj)) << "the good blob";
}

TEST_F(private_unwrap, usage_flags_stay_as_unwrapped)
{
    UnwrappedPair pair;
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(host_rsa(2048), CKK_RSA, CKA_SIGN, &pair));
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE off = { CKA_SIGN, &no, sizeof(no) };
    CK_ATTRIBUTE decrypt = { CKA_DECRYPT, &yes, sizeof(yes) };
    CK_ATTRIBUTE encrypt = { CKA_ENCRYPT, &yes, sizeof(yes) };
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, pair.priv, &off, 1))
        << "the device key keeps its use";
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, pair.priv, &decrypt, 1));
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, pair.pub, &encrypt, 1));
    const char label[] = "relabelled";
    CK_ATTRIBUTE relabel = { CKA_LABEL, const_cast<char *>(label), sizeof(label) - 1 };
    EXPECT_CKR_OK(p11()->C_SetAttributeValue(s_, pair.priv, &relabel, 1)) << "the control";
}

TEST_F(private_unwrap, a_token_pair_needs_a_read_write_session)
{
    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    PrivateTemplate t(CKK_RSA, CKA_SIGN, CK_TRUE, "ro");
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    EXPECT_CKR(
        CKR_SESSION_READ_ONLY,
        unwrap_with_template(ro, priv_, blob_of(host_rsa(2048)), t.attrs, &obj)
    );
    EXPECT_EQ(CK_INVALID_HANDLE, obj);
    PrivateTemplate session(CKK_RSA, CKA_SIGN, CK_FALSE, "ro");
    EXPECT_CKR_OK(unwrap_with_template(ro, priv_, blob_of(host_rsa(2048)), session.attrs, &obj))
        << "a session pair unwraps in a read-only session";
    ASSERT_CKR_OK(p11()->C_CloseSession(ro));
}

TEST_F(private_unwrap, unwrapped_token_pairs_survive_relogin)
{
    UnwrappedPair rsa;
    host::Pkey ec = host::ec_generate("P-521");
    UnwrappedPair ecdsa;
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(host_rsa(3072), CKK_RSA, CKA_SIGN, &rsa, CK_TRUE));
    ASSERT_NO_FATAL_FAILURE(unwrap_pair(ec.get(), CKK_EC, CKA_SIGN, &ecdsa, CK_TRUE));
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    ASSERT_CKR_OK(login_user(s_));
    std::vector<CK_BYTE> msg = pattern(33);
    std::vector<CK_BYTE> sig;
    ASSERT_CKR_OK(sign_oneshot(s_, CKM_SHA512_RSA_PKCS, rsa.priv, msg, sig));
    EXPECT_EQ(host::rsa_sign(host_rsa(3072), "SHA512", RSA_PKCS1_PADDING, msg), sig)
        << "the token key is still the host's after a relogin";
    std::vector<CK_BYTE> ec_sig;
    ASSERT_CKR_OK(sign_oneshot(s_, CKM_ECDSA_SHA256, ecdsa.priv, msg, ec_sig));
    EXPECT_TRUE(host::ecdsa_verify(ec.get(), "SHA256", msg, ec_sig));
    // Each object holds its own copy of the masked blob.
    ASSERT_CKR_OK(p11()->C_DestroyObject(s_, rsa.priv));
    EXPECT_CKR_OK(verify_oneshot(s_, CKM_SHA512_RSA_PKCS, rsa.pub, msg, sig))
        << "the companion outlives the private key";
    ASSERT_CKR_OK(p11()->C_DestroyObject(s_, rsa.pub));
    ASSERT_CKR_OK(p11()->C_DestroyObject(s_, ecdsa.priv));
    ASSERT_CKR_OK(p11()->C_DestroyObject(s_, ecdsa.pub));
}

TEST_F(private_unwrap, leak_gate)
{
    host::Pkey key = host::ec_generate("P-256");
    host::Bytes good = blob_of(key.get());
    host::Bytes bad = good;
    bad.back() ^= 0x01;
    PrivateTemplate t(CKK_EC, CKA_SIGN, CK_FALSE, "leak-gate");
    std::vector<TerminationPath> paths = {
        { "unwrap, then destroy both",
          [&]() {
              CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
              ASSERT_CKR_OK(unwrap_with_template(s_, priv_, good, t.attrs, &obj));
              std::vector<CK_BYTE> id;
              ASSERT_CKR_OK(get_bytes(s_, obj, CKA_ID, id));
              std::vector<CK_OBJECT_HANDLE> found;
              ASSERT_NO_FATAL_FAILURE(find_by_id(s_, CKO_PUBLIC_KEY, id, t.label, &found));
              ASSERT_EQ(1u, found.size());
              ASSERT_CKR_OK(p11()->C_DestroyObject(s_, found[0]));
              ASSERT_CKR_OK(p11()->C_DestroyObject(s_, obj));
          } },
        { "a refused blob",
          [&]() {
              CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
              ASSERT_CKR(
                  CKR_WRAPPED_KEY_INVALID,
                  unwrap_with_template(s_, priv_, bad, t.attrs, &obj)
              );
          } },
    };
    ASSERT_NO_FATAL_FAILURE(leak_gate(s_, paths, [&]() {
        CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE unwrapping = CK_INVALID_HANDLE;
        CK_RV rv = gen_unwrapping_pair(s_, &pub, &unwrapping);
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        return (rv == CKR_OK) ? unwrap_with_template(s_, unwrapping, good, t.attrs, &obj) : rv;
    }));
}

/// The file store holds an unwrapped private key only masked.
class private_unwrap_persist : public StoreDirFixture
{
};

TEST_F(private_unwrap_persist, the_store_never_sees_the_private_key)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub, &priv, CK_TRUE));
    std::vector<CK_BYTE> n;
    ASSERT_CKR_OK(get_bytes(s_, pub, CKA_MODULUS, n));
    host::Pkey host_pub = host::rsa_public(n, { 0x01, 0x00, 0x01 });
    EVP_PKEY *key = host_rsa(2048);
    host::Bytes blob = host::rsa_aes_key_wrap(host_pub.get(), "SHA256", host::pkcs8(key));
    PrivateTemplate t(CKK_RSA, CKA_SIGN, CK_TRUE, "persist");
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(unwrap_with_template(s_, priv, blob, t.attrs, &obj));
    EXPECT_TRUE(store_contains(host::bn_param(key, OSSL_PKEY_PARAM_RSA_N)))
        << "the public modulus is stored as it is";
    for (const char *secret :
         { OSSL_PKEY_PARAM_RSA_D, OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR2 })
    {
        host::Bytes v = host::bn_param(key, secret);
        ASSERT_FALSE(v.empty());
        EXPECT_FALSE(store_contains(v)) << secret;
        EXPECT_FALSE(store_contains(host::Bytes(v.begin(), v.begin() + 16)))
            << "part of " << secret;
    }
    EXPECT_FALSE(store_contains(host::Bytes(blob.begin() + kOaepBlock, blob.end())))
        << "its RFC 5649 wrap";
}
