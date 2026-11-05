// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// Helpers for the unwrap tests: the partition's RSA unwrapping key pair as
/// objects and as a host key, CK_RSA_AES_KEY_WRAP_PARAMS, and C_UnwrapKey into
/// a key of each AES family from a blob the host oracle wraps.
///
/// UnwrapSession is a UserSession that starts with the pair as session
/// objects and its public key on the host, so a case can wrap any key of its
/// choosing and unwrap it into the token: the only way known key material
/// reaches a key object, and so the way known-answer tests reach the token.

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "utils/host_crypto.hpp"
#include "utils/module.hpp"

/// The size of the partition's one RSA key.
constexpr CK_ULONG kUnwrapKeyBits = 2048;
/// The OAEP block that starts every CKM_RSA_AES_KEY_WRAP blob.
constexpr size_t kOaepBlock = kUnwrapKeyBits / 8;

/// C_GenerateKeyPair with the one template the token accepts: the
/// partition's unwrapping key as a public and a private object.
inline CK_RV gen_unwrapping_pair(
    CK_SESSION_HANDLE s,
    CK_OBJECT_HANDLE *pub,
    CK_OBJECT_HANDLE *priv,
    CK_BBOOL token = CK_FALSE
)
{
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0 };
    CK_ULONG bits = kUnwrapKeyBits;
    CK_BBOOL yes = CK_TRUE;
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_MODULUS_BITS, &bits, sizeof(bits) },
        { CKA_WRAP, &yes, sizeof(yes) },
        { CKA_TOKEN, &token, sizeof(token) },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_UNWRAP, &yes, sizeof(yes) },
        { CKA_TOKEN, &token, sizeof(token) },
    };
    return p11()->C_GenerateKeyPair(s, &mech, pub_tmpl, 3, priv_tmpl, 2, pub, priv);
}

/// The OpenSSL name of an OAEP hash mechanism.
inline const char *md_name(CK_MECHANISM_TYPE hash)
{
    switch (hash)
    {
    case CKM_SHA384:
        return "SHA384";
    case CKM_SHA512:
        return "SHA512";
    default:
        return "SHA256";
    }
}

/// A CKM_RSA_AES_KEY_WRAP blob of `target` under `key` with the given
/// key-encryption key: OAEP (md for OAEP and MGF1, no label), then RFC 5649.
/// host::rsa_aes_key_wrap does the same with a fresh AES-256 KEK.
inline host::Bytes rsa_aes_wrap(
    EVP_PKEY *key,
    const char *md,
    const host::Bytes &kek,
    const host::Bytes &target
)
{
    host::Bytes out = host::rsa_oaep_encrypt(key, md, kek, host::Bytes());
    host::Bytes wrapped = host::aes_kwp_wrap(kek, target);
    out.insert(out.end(), wrapped.begin(), wrapped.end());
    return out;
}

/// The blob C_UnwrapKey takes for `target` of the cipher `family`, wrapped with
/// fresh AES-256 KEKs and md for OAEP. An AES-XTS key travels in the SDK's
/// container: a 16-byte header ("TSRA-XTS", version 1, both lengths and two
/// reserved bytes, little-endian), then one blob per 32-byte half.
inline host::Bytes rsa_aes_blob(
    EVP_PKEY *key,
    const char *md,
    const host::Bytes &target,
    CK_MECHANISM_TYPE family
)
{
    if (family != CKM_AES_XTS)
    {
        return host::rsa_aes_key_wrap(key, md, target);
    }
    size_t half = target.size() / 2;
    host::Bytes key1 =
        host::rsa_aes_key_wrap(key, md, host::Bytes(target.begin(), target.begin() + half));
    host::Bytes key2 =
        host::rsa_aes_key_wrap(key, md, host::Bytes(target.begin() + half, target.end()));
    const char magic[] = "TSRA-XTS";
    host::Bytes out(magic, magic + sizeof(magic) - 1);
    for (size_t len : { size_t{ 1 }, key1.size(), key2.size(), size_t{ 0 } })
    {
        out.push_back(static_cast<CK_BYTE>(len & 0xFF));
        out.push_back(static_cast<CK_BYTE>(len >> 8));
    }
    out.insert(out.end(), key1.begin(), key1.end());
    out.insert(out.end(), key2.begin(), key2.end());
    return out;
}

/// A CKM_RSA_AES_KEY_WRAP mechanism; it points into itself, so it does not copy.
struct RsaAesMechanism
{
    explicit RsaAesMechanism(CK_MECHANISM_TYPE hash = CKM_SHA256, CK_ULONG kek_bits = 256)
    {
        oaep.hashAlg = hash;
        oaep.mgf = (hash == CKM_SHA384)   ? CKG_MGF1_SHA384
                   : (hash == CKM_SHA512) ? CKG_MGF1_SHA512
                                          : CKG_MGF1_SHA256;
        oaep.source = CKZ_DATA_SPECIFIED;
        params.ulAESKeyBits = kek_bits;
        params.pOAEPParams = &oaep;
        mech = { CKM_RSA_AES_KEY_WRAP, &params, sizeof(params) };
    }
    RsaAesMechanism(const RsaAesMechanism &) = delete;
    RsaAesMechanism &operator=(const RsaAesMechanism &) = delete;

    CK_RSA_PKCS_OAEP_PARAMS oaep{};
    CK_RSA_AES_KEY_WRAP_PARAMS params{};
    CK_MECHANISM mech{};
};

/// C_UnwrapKey of `blob` into a key for the cipher `family` (CKM_AES_CBC for a
/// plain AES key, CKM_AES_GCM or CKM_AES_XTS), public, without CKA_VALUE_LEN.
inline CK_RV unwrap_key(
    CK_SESSION_HANDLE s,
    CK_OBJECT_HANDLE unwrapping,
    CK_MECHANISM *mech,
    const host::Bytes &blob,
    CK_MECHANISM_TYPE family,
    CK_OBJECT_HANDLE *out,
    CK_BBOOL token = CK_FALSE
)
{
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    CK_KEY_TYPE kt = (family == CKM_AES_XTS) ? CKK_AES_XTS : CKK_AES;
    CK_BBOOL no = CK_FALSE;
    CK_MECHANISM_TYPE gcm = CKM_AES_GCM;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_KEY_TYPE, &kt, sizeof(kt) },
        { CKA_PRIVATE, &no, sizeof(no) },
        { CKA_TOKEN, &token, sizeof(token) },
        { CKA_ALLOWED_MECHANISMS, &gcm, sizeof(gcm) }, /* GCM keys only */
    };
    CK_ULONG n = (sizeof(tmpl) / sizeof(tmpl[0])) - ((family == CKM_AES_GCM) ? 0 : 1);
    return p11()->C_UnwrapKey(
        s,
        mech,
        unwrapping,
        const_cast<CK_BYTE_PTR>(blob.data()),
        static_cast<CK_ULONG>(blob.size()),
        tmpl,
        n,
        out
    );
}

/// The number of objects session `s` can see.
inline CK_ULONG count_objects(CK_SESSION_HANDLE s)
{
    CK_ULONG total = 0;
    if (p11()->C_FindObjectsInit(s, nullptr, 0) != CKR_OK)
    {
        return 0;
    }
    CK_OBJECT_HANDLE batch[64];
    CK_ULONG n = 0;
    while ((p11()->C_FindObjects(s, batch, 64, &n) == CKR_OK) && (n > 0))
    {
        total += n;
    }
    (void)p11()->C_FindObjectsFinal(s);
    return total;
}

/// A logged-in session holding the unwrapping key pair (session objects) and
/// its public key as a host key.
class UnwrapSession : public UserSession
{
  protected:
    void SetUp() override
    {
        UserSession::SetUp();
        if (HasFatalFailure())
        {
            return;
        }
        ASSERT_CKR_OK(gen_unwrapping_pair(s_, &pub_, &priv_));
        std::vector<CK_BYTE> n;
        std::vector<CK_BYTE> e;
        ASSERT_CKR_OK(get_bytes(s_, pub_, CKA_MODULUS, n));
        ASSERT_CKR_OK(get_bytes(s_, pub_, CKA_PUBLIC_EXPONENT, e));
        host_pub_ = host::rsa_public(n, e);
    }

    /// Wrap `target` on the host (rsa_aes_blob, OAEP-SHA-256) and unwrap it
    /// into a key of `family`. ASSERTs, so call it as
    /// ASSERT_NO_FATAL_FAILURE(unwrap_known(...)).
    void unwrap_known(const host::Bytes &target, CK_MECHANISM_TYPE family, CK_OBJECT_HANDLE *out)
    {
        RsaAesMechanism m;
        host::Bytes blob = rsa_aes_blob(host_pub_.get(), "SHA256", target, family);
        ASSERT_CKR_OK(unwrap_key(s_, priv_, &m.mech, blob, family, out));
    }

    CK_OBJECT_HANDLE pub_ = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv_ = CK_INVALID_HANDLE;
    host::Pkey host_pub_;
};
