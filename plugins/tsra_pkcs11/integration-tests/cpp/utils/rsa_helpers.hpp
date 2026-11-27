// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// Helpers for the tests of private keys unwrapped into the token, RSA and
/// EC: host RSA keys of each size, made once per process (RSA key generation
/// is slow); C_UnwrapKey of a host private key into a private key, and the
/// companion public key the unwrap leaves, found by CKA_ID; the PSS and OAEP
/// parameter blocks.
///
/// PrivateUnwrapSession is an UnwrapSession that unwraps host keys of its
/// choosing, the way RSA keys and existing EC keys reach the token.

#include <cstring>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <vector>

#include "utils/host_crypto.hpp"
#include "utils/module.hpp"
#include "utils/unwrap_helpers.hpp"

/// The RSA sizes the device unwraps.
constexpr size_t kRsaSizes[] = { 2048, 3072, 4096 };

/// A host RSA key of `bits`, made on first use and kept for the process.
inline EVP_PKEY *host_rsa(size_t bits)
{
    static std::map<size_t, host::Pkey> keys;
    host::Pkey &k = keys[bits];
    if (!k)
    {
        k = host::rsa_generate(bits);
    }
    return k.get();
}

/// The OpenSSL name of a hash mechanism (CKM_SHA_1 ... CKM_SHA512).
inline const char *hash_name(CK_MECHANISM_TYPE hash)
{
    switch (hash)
    {
    case CKM_SHA_1:
        return "SHA1";
    case CKM_SHA384:
        return "SHA384";
    case CKM_SHA512:
        return "SHA512";
    default:
        return "SHA256";
    }
}

/// The MGF1 of a hash mechanism.
inline CK_RSA_PKCS_MGF_TYPE mgf1_of(CK_MECHANISM_TYPE hash)
{
    switch (hash)
    {
    case CKM_SHA_1:
        return CKG_MGF1_SHA1;
    case CKM_SHA384:
        return CKG_MGF1_SHA384;
    case CKM_SHA512:
        return CKG_MGF1_SHA512;
    default:
        return CKG_MGF1_SHA256;
    }
}

/// A PSS mechanism with its parameters; it points into itself, so it does
/// not copy.
struct PssMechanism
{
    PssMechanism(CK_MECHANISM_TYPE m, CK_MECHANISM_TYPE hash, CK_ULONG salt)
    {
        params = { hash, mgf1_of(hash), salt };
        mech = { m, &params, sizeof(params) };
    }
    PssMechanism(const PssMechanism &) = delete;
    PssMechanism &operator=(const PssMechanism &) = delete;

    CK_RSA_PKCS_PSS_PARAMS params{};
    CK_MECHANISM mech{};
};

/// CKM_RSA_PKCS_OAEP with `hash` for OAEP and MGF1 and an optional label; it
/// points into itself, so it does not copy.
struct OaepMechanism
{
    explicit OaepMechanism(CK_MECHANISM_TYPE hash = CKM_SHA256, const host::Bytes &l = {})
        : label(l)
    {
        params = { hash,
                   mgf1_of(hash),
                   CKZ_DATA_SPECIFIED,
                   label.empty() ? nullptr : label.data(),
                   static_cast<CK_ULONG>(label.size()) };
        mech = { CKM_RSA_PKCS_OAEP, &params, sizeof(params) };
    }
    OaepMechanism(const OaepMechanism &) = delete;
    OaepMechanism &operator=(const OaepMechanism &) = delete;

    host::Bytes label;
    CK_RSA_PKCS_OAEP_PARAMS params{};
    CK_MECHANISM mech{};
};

/// A private key the token unwrapped and the companion public key it made.
struct UnwrappedPair
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
};

/// The handles of the objects of class `cls` whose CKA_ID is `id` and, if
/// given, whose CKA_LABEL is `label`. ASSERTs that the search works, so call
/// it through ASSERT_NO_FATAL_FAILURE.
inline void find_by_id(
    CK_SESSION_HANDLE s,
    CK_OBJECT_CLASS cls,
    const std::vector<CK_BYTE> &id,
    const std::string &label,
    std::vector<CK_OBJECT_HANDLE> *out
)
{
    std::vector<CK_ATTRIBUTE> tmpl = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_ID, const_cast<CK_BYTE *>(id.data()), id.size() },
    };
    if (!label.empty())
    {
        tmpl.push_back({ CKA_LABEL, const_cast<char *>(label.data()), label.size() });
    }
    out->clear();
    ASSERT_CKR_OK(p11()->C_FindObjectsInit(s, tmpl.data(), static_cast<CK_ULONG>(tmpl.size())));
    CK_OBJECT_HANDLE batch[16];
    CK_ULONG n = 0;
    CK_RV rv = CKR_OK;
    while (((rv = p11()->C_FindObjects(s, batch, 16, &n)) == CKR_OK) && (n > 0))
    {
        out->insert(out->end(), batch, batch + n);
    }
    ASSERT_CKR_OK(rv);
    ASSERT_CKR_OK(p11()->C_FindObjectsFinal(s));
}

/// The template of a private key of type `kt` whose one use is `usage`, with
/// CKA_TOKEN `token` and CKA_LABEL `label`; private unless `priv` says not.
/// The values live in the struct, so it does not copy.
struct PrivateTemplate
{
    PrivateTemplate(
        CK_KEY_TYPE type,
        CK_ATTRIBUTE_TYPE use,
        CK_BBOOL tok,
        const std::string &lab,
        CK_BBOOL private_key = CK_TRUE
    )
        : kt(type), token(tok), priv(private_key), label(lab)
    {
        attrs = {
            { CKA_CLASS, &cls, sizeof(cls) },     { CKA_KEY_TYPE, &kt, sizeof(kt) },
            { use, &yes, sizeof(yes) },           { CKA_TOKEN, &token, sizeof(token) },
            { CKA_PRIVATE, &priv, sizeof(priv) }, { CKA_LABEL, label.data(), label.size() },
        };
    }
    PrivateTemplate(const PrivateTemplate &) = delete;
    PrivateTemplate &operator=(const PrivateTemplate &) = delete;

    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE kt;
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL token;
    CK_BBOOL priv;
    std::string label;
    std::vector<CK_ATTRIBUTE> attrs;
};

/// C_UnwrapKey of `blob` with the OAEP-SHA-256 CKM_RSA_AES_KEY_WRAP and `tmpl`.
inline CK_RV unwrap_with_template(
    CK_SESSION_HANDLE s,
    CK_OBJECT_HANDLE unwrapping,
    const host::Bytes &blob,
    std::vector<CK_ATTRIBUTE> tmpl,
    CK_OBJECT_HANDLE *out
)
{
    RsaAesMechanism m;
    return p11()->C_UnwrapKey(
        s,
        &m.mech,
        unwrapping,
        const_cast<CK_BYTE_PTR>(blob.data()),
        static_cast<CK_ULONG>(blob.size()),
        tmpl.data(),
        static_cast<CK_ULONG>(tmpl.size()),
        out
    );
}

/// A logged-in session with the unwrapping key pair that unwraps host private
/// keys.
class PrivateUnwrapSession : public UnwrapSession
{
  protected:
    /// The blob of the host private key `key`, wrapped for this partition.
    host::Bytes blob_of(EVP_PKEY *key)
    {
        return host::rsa_aes_key_wrap(host_pub_.get(), "SHA256", host::pkcs8(key));
    }

    /// Unwrap the host key `key` into a private key of `kt` whose one use is
    /// `usage`, and find its companion by CKA_ID and a label of its own.
    /// ASSERTs, so call it through ASSERT_NO_FATAL_FAILURE.
    void unwrap_pair(
        EVP_PKEY *key,
        CK_KEY_TYPE kt,
        CK_ATTRIBUTE_TYPE usage,
        UnwrappedPair *pair,
        CK_BBOOL token = CK_FALSE
    )
    {
        std::string label = "unwrapped-" + std::to_string(++unwraps_);
        PrivateTemplate t(kt, usage, token, label);
        ASSERT_CKR_OK(unwrap_with_template(s_, priv_, blob_of(key), t.attrs, &pair->priv));
        std::vector<CK_BYTE> id;
        ASSERT_CKR_OK(get_bytes(s_, pair->priv, CKA_ID, id));
        std::vector<CK_OBJECT_HANDLE> found;
        ASSERT_NO_FATAL_FAILURE(find_by_id(s_, CKO_PUBLIC_KEY, id, label, &found));
        ASSERT_EQ(1u, found.size()) << "one companion public key";
        pair->pub = found[0];
    }

    int unwraps_ = 0;
};
