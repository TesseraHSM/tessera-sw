// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file unwrap_tests.cpp
///
/// C_UnwrapKey with CKM_RSA_AES_KEY_WRAP: keys of every AES family from blobs
/// the host wraps, every OAEP hash and key-encryption key size, the attributes
/// an unwrapped key gets, the mechanism, template and unwrapping-key rules,
/// one uniform CKR_WRAPPED_KEY_INVALID and no object for every bad blob, the
/// refused C_WrapKey, survival across a relogin, the leak gate, and that the
/// file store never sees the key.

#include <climits>
#include <cstring>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <vector>

#include "tsra_pkcs11_template.h"
#include "utils/aes_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/leak_gate.hpp"
#include "utils/module.hpp"
#include "utils/store_dir.hpp"
#include "utils/surviving_key.hpp"
#include "utils/unwrap_helpers.hpp"

namespace
{

/// The key length of each family the module unwraps into.
size_t family_key_bytes(CK_MECHANISM_TYPE family)
{
    return (family == CKM_AES_XTS) ? AES_XTS_KEY_BYTES : AES256_KEY_BYTES;
}

} // namespace

class unwrap : public UnwrapSession
{
  protected:
    /// A blob of a fresh 32-byte AES key under OAEP-SHA-256 and an AES-256 KEK.
    host::Bytes blob_of(const host::Bytes &target)
    {
        return host::rsa_aes_key_wrap(host_pub_.get(), "SHA256", target);
    }

    /// C_UnwrapKey with `tmpl` and the default mechanism.
    CK_RV unwrap_with(
        const host::Bytes &blob,
        std::vector<CK_ATTRIBUTE> tmpl,
        CK_OBJECT_HANDLE *out
    )
    {
        RsaAesMechanism m;
        return p11()->C_UnwrapKey(
            s_,
            &m.mech,
            priv_,
            const_cast<CK_BYTE_PTR>(blob.data()),
            static_cast<CK_ULONG>(blob.size()),
            tmpl.data(),
            static_cast<CK_ULONG>(tmpl.size()),
            out
        );
    }
};

TEST_F(unwrap, every_family_unwraps_and_matches_the_host)
{
    for (CK_MECHANISM_TYPE family : { CKM_AES_CBC, CKM_AES_GCM, CKM_AES_XTS })
    {
        SCOPED_TRACE("family 0x" + std::to_string(family));
        host::Bytes key(family_key_bytes(family));
        for (size_t i = 0; i < key.size(); i++)
        {
            key[i] = static_cast<CK_BYTE>(0xA0 + i);
        }
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        ASSERT_NO_FATAL_FAILURE(unwrap_known(key, family, &obj));
        std::vector<CK_BYTE> plain = pattern(64);
        std::vector<CK_BYTE> ct;
        CK_BYTE iv[kAesBlock] = { 0x07 };
        if (family == CKM_AES_GCM)
        {
            CK_GCM_PARAMS gcm = { iv,
                                  AES_GCM_IV_LEN,
                                  AES_GCM_IV_LEN * CHAR_BIT,
                                  nullptr,
                                  0,
                                  AES_GCM_TAG_LEN * CHAR_BIT };
            CK_MECHANISM mech = { CKM_AES_GCM, &gcm, sizeof(gcm) };
            std::vector<CK_BYTE> back;
            ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech, obj, plain, ct));
            ASSERT_CKR_OK(crypt_oneshot(s_, false, &mech, obj, ct, back));
            EXPECT_EQ(plain, back);
            continue; /* the GCM known answers are in kat_tests.cpp */
        }
        CK_MECHANISM mech = { family, iv, sizeof(iv) };
        ASSERT_CKR_OK(crypt_oneshot(s_, true, &mech, obj, plain, ct));
        std::string name = (family == CKM_AES_XTS) ? "AES-256-XTS" : "AES-256-CBC";
        EXPECT_EQ(
            host::cipher(name, true, key, host::Bytes(iv, iv + sizeof(iv)), plain, false),
            ct
        );
    }
}

TEST_F(unwrap, every_oaep_hash_and_kek_size)
{
    for (CK_MECHANISM_TYPE hash : { CKM_SHA256, CKM_SHA384, CKM_SHA512 })
    {
        for (CK_ULONG kek_bits : { 128, 192, 256 })
        {
            SCOPED_TRACE(std::string(md_name(hash)) + " KEK " + std::to_string(kek_bits));
            RsaAesMechanism m(hash, kek_bits);
            host::Bytes kek(kek_bits / CHAR_BIT, 0x5C);
            host::Bytes key(16, static_cast<CK_BYTE>(kek_bits));
            host::Bytes blob = rsa_aes_wrap(host_pub_.get(), md_name(hash), kek, key);
            CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
            ASSERT_CKR_OK(unwrap_key(s_, priv_, &m.mech, blob, CKM_AES_CBC, &obj));
            CK_BYTE iv[kAesBlock] = {};
            CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
            std::vector<CK_BYTE> ct;
            ASSERT_CKR_OK(crypt_oneshot(s_, true, &cbc, obj, pattern(16), ct));
            EXPECT_EQ(
                host::aes_cbc_encrypt(key, host::Bytes(kAesBlock, 0), pattern(16), false),
                ct
            );
        }
    }
}

TEST_F(unwrap, an_unwrapped_key_is_sensitive_and_not_local)
{
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(unwrap_known(host::Bytes(24, 0x24), CKM_AES_CBC, &obj));
    struct
    {
        CK_ATTRIBUTE_TYPE type;
        CK_BBOOL want;
    } flags[] = {
        { CKA_SENSITIVE, CK_TRUE },
        { CKA_EXTRACTABLE, CK_FALSE },
        { CKA_ALWAYS_SENSITIVE, CK_FALSE },
        { CKA_NEVER_EXTRACTABLE, CK_FALSE },
        { CKA_LOCAL, CK_FALSE },
        { CKA_ENCRYPT, CK_TRUE },
        { CKA_DECRYPT, CK_TRUE },
    };
    for (const auto &f : flags)
    {
        CK_BBOOL got = CK_FALSE;
        ASSERT_CKR_OK(get_attr(s_, obj, f.type, &got)) << "attribute 0x" << std::hex << f.type;
        EXPECT_EQ(f.want, got) << "attribute 0x" << std::hex << f.type;
    }
    CK_ULONG len = 0;
    CK_MECHANISM_TYPE kgm = 0;
    ASSERT_CKR_OK(get_attr(s_, obj, CKA_VALUE_LEN, &len));
    EXPECT_EQ(24u, len) << "taken from the blob";
    ASSERT_CKR_OK(get_attr(s_, obj, CKA_KEY_GEN_MECHANISM, &kgm));
    EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, kgm);
    std::vector<CK_MECHANISM_TYPE> allowed;
    ASSERT_CKR_OK(get_allowed_mechs(s_, obj, allowed));
    EXPECT_EQ(std::vector<CK_MECHANISM_TYPE>({ CKM_AES_CBC, CKM_AES_CBC_PAD }), allowed);
    CK_BYTE value[32];
    CK_ATTRIBUTE v = { CKA_VALUE, value, sizeof(value) };
    EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, p11()->C_GetAttributeValue(s_, obj, &v, 1));
}

TEST_F(unwrap, template_rules)
{
    host::Bytes blob = blob_of(host::Bytes(16, 0x16));
    CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
    CK_OBJECT_CLASS private_key = CKO_PRIVATE_KEY;
    CK_KEY_TYPE aes = CKK_AES;
    CK_KEY_TYPE xts = CKK_AES_XTS;
    CK_KEY_TYPE ec = CKK_EC;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ULONG len16 = 16;
    CK_ULONG len32 = 32;
    CK_MECHANISM_TYPE gcm = CKM_AES_GCM;
    CK_BYTE value[16] = {};
    CK_ATTRIBUTE cls = { CKA_CLASS, &secret, sizeof(secret) };
    CK_ATTRIBUTE kt = { CKA_KEY_TYPE, &aes, sizeof(aes) };
    struct Case
    {
        const char *what;
        std::vector<CK_ATTRIBUTE> tmpl;
        CK_RV want;
    } cases[] = {
        { "no class", { kt }, CKR_TEMPLATE_INCOMPLETE },
        { "no key type", { cls }, CKR_TEMPLATE_INCOMPLETE },
        { "a private key",
          { { CKA_CLASS, &private_key, sizeof(private_key) }, kt },
          CKR_TEMPLATE_INCONSISTENT },
        { "an EC key", { cls, { CKA_KEY_TYPE, &ec, sizeof(ec) } }, CKR_TEMPLATE_INCONSISTENT },
        { "not sensitive",
          { cls, kt, { CKA_SENSITIVE, &no, sizeof(no) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "extractable",
          { cls, kt, { CKA_EXTRACTABLE, &yes, sizeof(yes) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "key material",
          { cls, kt, { CKA_VALUE, value, sizeof(value) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "local", { cls, kt, { CKA_LOCAL, &yes, sizeof(yes) } }, CKR_ATTRIBUTE_READ_ONLY },
        { "a length the blob does not have",
          { cls, kt, { CKA_VALUE_LEN, &len32, sizeof(len32) } },
          CKR_WRAPPED_KEY_LEN_RANGE },
        { "a GCM key of 16 bytes",
          { cls, kt, { CKA_ALLOWED_MECHANISMS, &gcm, sizeof(gcm) } },
          CKR_WRAPPED_KEY_LEN_RANGE },
        { "an XTS key of 16 bytes",
          { cls, { CKA_KEY_TYPE, &xts, sizeof(xts) } },
          CKR_WRAPPED_KEY_LEN_RANGE },
        { "the blob's length", { cls, kt, { CKA_VALUE_LEN, &len16, sizeof(len16) } }, CKR_OK },
    };
    for (Case &c : cases)
    {
        SCOPED_TRACE(c.what);
        CK_ULONG before = count_objects(s_);
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        EXPECT_CKR(c.want, unwrap_with(blob, c.tmpl, &obj));
        EXPECT_EQ(before + ((c.want == CKR_OK) ? 1 : 0), count_objects(s_));
    }
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    for (const host::Bytes &shorter : { host::Bytes(blob.begin(), blob.end() - 1),
                                        host::Bytes(blob.begin(), blob.begin() + kOaepBlock),
                                        host::Bytes() })
    {
        EXPECT_CKR(CKR_WRAPPED_KEY_LEN_RANGE, unwrap_with(shorter, { cls, kt }, &obj))
            << "a blob of " << shorter.size() << " bytes";
    }
    EXPECT_CKR(
        CKR_WRAPPED_KEY_LEN_RANGE,
        unwrap_with(
            blob_of(host::Bytes(64, 0x64)),
            { cls, { CKA_KEY_TYPE, &xts, sizeof(xts) } },
            &obj
        )
    ) << "an XTS key in one blob rather than the SDK's container";
}

TEST_F(unwrap, mechanism_rules)
{
    host::Bytes blob = blob_of(host::Bytes(16, 0x16));
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    auto run = [&](CK_MECHANISM *mech) {
        return unwrap_key(s_, priv_, mech, blob, CKM_AES_CBC, &obj);
    };

    CK_MECHANISM oaep = { CKM_RSA_PKCS_OAEP, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_INVALID, run(&oaep));
    CK_MECHANISM no_params = { CKM_RSA_AES_KEY_WRAP, nullptr, 0 };
    EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, run(&no_params));
    {
        RsaAesMechanism m;
        m.mech.ulParameterLen = sizeof(m.params) - 1;
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, run(&m.mech)) << "short parameter";
    }
    {
        RsaAesMechanism m(CKM_SHA256, 64);
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, run(&m.mech)) << "a 64-bit KEK";
    }
    {
        RsaAesMechanism m;
        m.params.pOAEPParams = nullptr;
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, run(&m.mech)) << "no OAEP parameters";
    }
    {
        RsaAesMechanism m(CKM_SHA_1);
        m.oaep.mgf = CKG_MGF1_SHA1;
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, run(&m.mech)) << "OAEP with SHA-1";
    }
    {
        RsaAesMechanism m;
        m.oaep.mgf = CKG_MGF1_SHA384;
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, run(&m.mech)) << "MGF1 with another hash";
    }
    {
        RsaAesMechanism m;
        CK_BYTE label[] = { 'l' };
        m.oaep.pSourceData = label;
        m.oaep.ulSourceDataLen = sizeof(label);
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, run(&m.mech)) << "a label";
    }
    {
        RsaAesMechanism m;
        m.oaep.source = 0;
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, run(&m.mech)) << "no source";
    }
}

TEST_F(unwrap, unwrapping_key_rules)
{
    host::Bytes blob = blob_of(host::Bytes(16, 0x16));
    RsaAesMechanism m;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    EXPECT_CKR(
        CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        unwrap_key(s_, kInvalidObject, &m.mech, blob, CKM_AES_CBC, &obj)
    );
    EXPECT_CKR(
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        unwrap_key(s_, pub_, &m.mech, blob, CKM_AES_CBC, &obj)
    );
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_aes_key(s_, 32, CK_TRUE, CK_TRUE, "not-an-unwrapping-key", &aes));
    EXPECT_CKR(
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        unwrap_key(s_, aes, &m.mech, blob, CKM_AES_CBC, &obj)
    );

    CK_BBOOL no = CK_FALSE;
    CK_ATTRIBUTE off = { CKA_UNWRAP, &no, sizeof(no) };
    ASSERT_CKR_OK(p11()->C_SetAttributeValue(s_, priv_, &off, 1));
    EXPECT_CKR(
        CKR_KEY_FUNCTION_NOT_PERMITTED,
        unwrap_key(s_, priv_, &m.mech, blob, CKM_AES_CBC, &obj)
    );

    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub, &priv));
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR(CKR_USER_NOT_LOGGED_IN, unwrap_key(s_, priv, &m.mech, blob, CKM_AES_CBC, &obj));
}

TEST_F(unwrap, a_bad_blob_is_one_error_and_no_object)
{
    host::Bytes key(32, 0x33);
    host::Bytes kek(32, 0x44);
    host::Bytes good = rsa_aes_wrap(host_pub_.get(), "SHA256", kek, key);
    host::Bytes in_oaep = good;
    in_oaep[kOaepBlock / 2] ^= 0x01;
    host::Bytes in_kwp = good;
    in_kwp.back() ^= 0x01;
    host::Bytes wrong_kek = host::rsa_oaep_encrypt(host_pub_.get(), "SHA256", kek, host::Bytes());
    host::Bytes other = host::aes_kwp_wrap(host::Bytes(32, 0x55), key);
    wrong_kek.insert(wrong_kek.end(), other.begin(), other.end());
    host::Bytes sha384 = rsa_aes_wrap(host_pub_.get(), "SHA384", kek, key);
    host::Bytes labelled = host::rsa_oaep_encrypt(host_pub_.get(), "SHA256", kek, { 'l' });
    host::Bytes wrapped = host::aes_kwp_wrap(kek, key);
    labelled.insert(labelled.end(), wrapped.begin(), wrapped.end());
    host::Bytes xts = rsa_aes_blob(host_pub_.get(), "SHA256", pattern(64), CKM_AES_XTS);
    host::Bytes xts_magic = xts;
    xts_magic[0] ^= 0x01;
    host::Bytes xts_half = xts;
    xts_half.back() ^= 0x01;

    struct
    {
        const char *what;
        const host::Bytes &blob;
        CK_MECHANISM_TYPE family;
    } cases[] = {
        { "a byte of the OAEP block flipped", in_oaep, CKM_AES_CBC },
        { "a byte of the key wrap flipped", in_kwp, CKM_AES_CBC },
        { "another KEK", wrong_kek, CKM_AES_CBC },
        { "OAEP with SHA-384, declared SHA-256", sha384, CKM_AES_CBC },
        { "an OAEP label", labelled, CKM_AES_CBC },
        { "an XTS container with a bad magic", xts_magic, CKM_AES_XTS },
        { "an XTS container with a bad second half", xts_half, CKM_AES_XTS },
    };
    RsaAesMechanism m;
    for (const auto &c : cases)
    {
        SCOPED_TRACE(c.what);
        CK_ULONG before = count_objects(s_);
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        EXPECT_CKR(CKR_WRAPPED_KEY_INVALID, unwrap_key(s_, priv_, &m.mech, c.blob, c.family, &obj));
        EXPECT_EQ(CK_INVALID_HANDLE, obj);
        EXPECT_EQ(before, count_objects(s_));
    }
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    EXPECT_CKR_OK(unwrap_key(s_, priv_, &m.mech, good, CKM_AES_CBC, &obj)) << "the good blob";
    EXPECT_CKR_OK(unwrap_key(s_, priv_, &m.mech, xts, CKM_AES_XTS, &obj)) << "the good container";
}

TEST_F(unwrap, an_xts_key_with_equal_halves_unwraps_but_does_not_encrypt)
{
    // Generation never makes such a key; the device refuses it at use, as
    // FIPS 140-3 asks of XTS (key 1 and key 2 must differ).
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(unwrap_known(host::Bytes(64, 0x64), CKM_AES_XTS, &key));
    CK_BYTE tweak[kAesBlock] = { 0x01 };
    CK_MECHANISM mech = { CKM_AES_XTS, tweak, sizeof(tweak) };
    std::vector<CK_BYTE> out;
    EXPECT_CKR(CKR_FUNCTION_FAILED, crypt_oneshot(s_, true, &mech, key, pattern(32), out));
}

TEST_F(unwrap, wrap_key_is_not_supported)
{
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(unwrap_known(host::Bytes(32, 0x66), CKM_AES_CBC, &aes));
    RsaAesMechanism m;
    CK_BYTE out[512];
    CK_ULONG len = sizeof(out);
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_WrapKey(s_, &m.mech, pub_, aes, out, &len));
    len = 0;
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_WrapKey(s_, &m.mech, pub_, aes, nullptr, &len));
}

TEST_F(unwrap, unwrapped_keys_survive_relogin)
{
    const CK_MECHANISM_TYPE families[] = { CKM_AES_CBC, CKM_AES_GCM, CKM_AES_XTS };
    CK_OBJECT_HANDLE keys[3] = {};
    std::vector<std::unique_ptr<SurvivingKey>> survivors;
    RsaAesMechanism m;
    for (size_t i = 0; i < 3; i++)
    {
        host::Bytes blob = rsa_aes_blob(
            host_pub_.get(),
            "SHA256",
            pattern(family_key_bytes(families[i])),
            families[i]
        );
        ASSERT_CKR_OK(unwrap_key(s_, priv_, &m.mech, blob, families[i], &keys[i], CK_TRUE));
        survivors.push_back(std::make_unique<SurvivingKey>(s_, keys[i], families[i]));
        ASSERT_NO_FATAL_FAILURE(survivors.back()->record());
    }
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    ASSERT_CKR_OK(login_user(s_));
    for (size_t i = 0; i < 3; i++)
    {
        SCOPED_TRACE("family 0x" + std::to_string(families[i]));
        ASSERT_NO_FATAL_FAILURE(survivors[i]->check("a logout and login"));
        ASSERT_CKR_OK(p11()->C_DestroyObject(s_, keys[i]));
    }
}

TEST_F(unwrap, leak_gate)
{
    host::Bytes good = blob_of(host::Bytes(32, 0x88));
    host::Bytes bad = good;
    bad.back() ^= 0x01;
    RsaAesMechanism m;
    std::vector<TerminationPath> paths = {
        { "unwrap, then destroy",
          [&]() {
              CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
              ASSERT_CKR_OK(unwrap_key(s_, priv_, &m.mech, good, CKM_AES_CBC, &obj));
              ASSERT_CKR_OK(p11()->C_DestroyObject(s_, obj));
          } },
        { "a refused blob",
          [&]() {
              CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
              ASSERT_CKR(
                  CKR_WRAPPED_KEY_INVALID,
                  unwrap_key(s_, priv_, &m.mech, bad, CKM_AES_CBC, &obj)
              );
          } },
    };
    ASSERT_NO_FATAL_FAILURE(leak_gate(s_, paths, [&]() {
        CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
        CK_RV rv = gen_unwrapping_pair(s_, &pub, &priv);
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        return (rv == CKR_OK) ? unwrap_key(s_, priv, &m.mech, good, CKM_AES_CBC, &obj) : rv;
    }));
}

/// The file store holds the unwrapped key only masked.
class unwrap_persist : public StoreDirFixture
{
};

TEST_F(unwrap_persist, the_store_never_sees_the_key)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub, &priv, CK_TRUE));
    std::vector<CK_BYTE> n;
    ASSERT_CKR_OK(get_bytes(s_, pub, CKA_MODULUS, n));
    EXPECT_TRUE(store_contains(n)) << "the public modulus is stored as it is";
    host::Pkey host_pub = host::rsa_public(n, { 0x01, 0x00, 0x01 });

    host::Bytes key(32);
    for (size_t i = 0; i < key.size(); i++)
    {
        key[i] = static_cast<CK_BYTE>(0xC0 ^ (i * 13));
    }
    RsaAesMechanism m;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    host::Bytes blob = host::rsa_aes_key_wrap(host_pub.get(), "SHA256", key);
    ASSERT_CKR_OK(unwrap_key(s_, priv, &m.mech, blob, CKM_AES_CBC, &obj, CK_TRUE));
    EXPECT_FALSE(store_contains(key)) << "the key itself";
    EXPECT_FALSE(store_contains(host::Bytes(key.begin(), key.begin() + 16))) << "half of it";
    EXPECT_FALSE(store_contains(host::Bytes(blob.begin() + kOaepBlock, blob.end())))
        << "its RFC 5649 wrap";
}
