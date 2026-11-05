// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// Helpers for the EC tests: key-pair generation with the usual templates,
/// the public point, and the sign and verify calls with the two-call (probe,
/// then fill) discipline, one-shot and multi-part.

#include <algorithm>
#include <cstring>
#include <vector>

#include "utils/module.hpp"

/// One curve: its CKA_EC_PARAMS (the DER named-curve OID), its OpenSSL group
/// name, and the length of a coordinate, and so of r and of s.
struct EcCurve
{
    const char *name;
    std::vector<CK_BYTE> params;
    size_t coord;
};

/// The three curves the device generates keys on.
inline const std::vector<EcCurve> &ec_curves()
{
    static const std::vector<EcCurve> curves = {
        { "P-256", { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }, 32 },
        { "P-384", { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 }, 48 },
        { "P-521", { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 }, 66 },
    };
    return curves;
}

/// Generate an EC key pair on `curve` whose private key signs (`sign`) or
/// derives, with explicit CKA_TOKEN on both halves and CKA_PRIVATE `priv` on
/// the private key (the public key stays public). Both halves get `label`.
inline CK_RV gen_ec_pair(
    CK_SESSION_HANDLE s,
    const EcCurve &curve,
    bool sign,
    CK_BBOOL token,
    CK_BBOOL priv,
    const char *label,
    CK_OBJECT_HANDLE *pub,
    CK_OBJECT_HANDLE *prv
)
{
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, nullptr, 0 };
    CK_BBOOL yes = CK_TRUE;
    CK_ULONG label_len = static_cast<CK_ULONG>(std::strlen(label));
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_EC_PARAMS, const_cast<CK_BYTE *>(curve.params.data()), curve.params.size() },
        { CKA_TOKEN, &token, sizeof(token) },
        { CKA_LABEL, const_cast<char *>(label), label_len },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { static_cast<CK_ATTRIBUTE_TYPE>(sign ? CKA_SIGN : CKA_DERIVE), &yes, sizeof(yes) },
        { CKA_TOKEN, &token, sizeof(token) },
        { CKA_PRIVATE, &priv, sizeof(priv) },
        { CKA_LABEL, const_cast<char *>(label), label_len },
    };
    return p11()->C_GenerateKeyPair(s, &mech, pub_tmpl, 3, priv_tmpl, 4, pub, prv);
}

/// A P-256 signing pair of private session objects (the common case).
inline CK_RV gen_p256(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv)
{
    return gen_ec_pair(s, ec_curves()[0], true, CK_FALSE, CK_TRUE, "ec", pub, prv);
}

/// The uncompressed point inside a public key's CKA_EC_POINT, a DER OCTET
/// STRING; empty when the attribute is missing or not exactly that.
inline std::vector<CK_BYTE> ec_point(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE pub)
{
    std::vector<CK_BYTE> der;
    if ((get_bytes(s, pub, CKA_EC_POINT, der) != CKR_OK) || (der.size() < 2) || (der[0] != 0x04))
    {
        return {};
    }
    size_t header = (der[1] == 0x81) ? 3 : 2;
    size_t len = (header == 3) ? der[2] : der[1];
    if ((der.size() < header) || ((header + len) != der.size()))
    {
        return {};
    }
    return std::vector<CK_BYTE>(der.begin() + header, der.end());
}

/// One-shot sign: init, probe the length, then fill. `sig` is sized to the
/// bytes written.
inline CK_RV sign_oneshot(
    CK_SESSION_HANDLE s,
    CK_MECHANISM_TYPE mech,
    CK_OBJECT_HANDLE key,
    const std::vector<CK_BYTE> &in,
    std::vector<CK_BYTE> &sig
)
{
    CK_MECHANISM m = { mech, nullptr, 0 };
    CK_RV rv = p11()->C_SignInit(s, &m, key);
    if (rv != CKR_OK)
    {
        return rv;
    }
    CK_BYTE_PTR in_ptr = const_cast<CK_BYTE_PTR>(in.data());
    CK_ULONG need = 0;
    rv = p11()->C_Sign(s, in_ptr, static_cast<CK_ULONG>(in.size()), nullptr, &need);
    if (rv != CKR_OK)
    {
        return rv;
    }
    sig.assign(need, 0);
    CK_ULONG len = need;
    rv = p11()->C_Sign(s, in_ptr, static_cast<CK_ULONG>(in.size()), sig.data(), &len);
    sig.resize((rv == CKR_OK) ? len : 0);
    return rv;
}

/// Multi-part sign: init, `in` fed in parts of `chunk` bytes (none at all
/// for an empty message), then the final call, probed first.
inline CK_RV sign_multipart(
    CK_SESSION_HANDLE s,
    CK_MECHANISM_TYPE mech,
    CK_OBJECT_HANDLE key,
    const std::vector<CK_BYTE> &in,
    size_t chunk,
    std::vector<CK_BYTE> &sig
)
{
    CK_MECHANISM m = { mech, nullptr, 0 };
    CK_RV rv = p11()->C_SignInit(s, &m, key);
    for (size_t off = 0; (rv == CKR_OK) && (off < in.size()); off += chunk)
    {
        CK_ULONG n = static_cast<CK_ULONG>(std::min(chunk, in.size() - off));
        rv = p11()->C_SignUpdate(s, const_cast<CK_BYTE_PTR>(in.data()) + off, n);
    }
    CK_ULONG need = 0;
    if (rv == CKR_OK)
    {
        rv = p11()->C_SignFinal(s, nullptr, &need);
    }
    if (rv != CKR_OK)
    {
        return rv;
    }
    sig.assign(need, 0);
    CK_ULONG len = need;
    rv = p11()->C_SignFinal(s, sig.data(), &len);
    sig.resize((rv == CKR_OK) ? len : 0);
    return rv;
}

/// One-shot verify.
inline CK_RV verify_oneshot(
    CK_SESSION_HANDLE s,
    CK_MECHANISM_TYPE mech,
    CK_OBJECT_HANDLE key,
    const std::vector<CK_BYTE> &in,
    const std::vector<CK_BYTE> &sig
)
{
    CK_MECHANISM m = { mech, nullptr, 0 };
    CK_RV rv = p11()->C_VerifyInit(s, &m, key);
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

/// Multi-part verify in parts of `chunk` bytes.
inline CK_RV verify_multipart(
    CK_SESSION_HANDLE s,
    CK_MECHANISM_TYPE mech,
    CK_OBJECT_HANDLE key,
    const std::vector<CK_BYTE> &in,
    size_t chunk,
    const std::vector<CK_BYTE> &sig
)
{
    CK_MECHANISM m = { mech, nullptr, 0 };
    CK_RV rv = p11()->C_VerifyInit(s, &m, key);
    for (size_t off = 0; (rv == CKR_OK) && (off < in.size()); off += chunk)
    {
        CK_ULONG n = static_cast<CK_ULONG>(std::min(chunk, in.size() - off));
        rv = p11()->C_VerifyUpdate(s, const_cast<CK_BYTE_PTR>(in.data()) + off, n);
    }
    if (rv != CKR_OK)
    {
        return rv;
    }
    return p11()
        ->C_VerifyFinal(s, const_cast<CK_BYTE_PTR>(sig.data()), static_cast<CK_ULONG>(sig.size()));
}

/// The OpenSSL digest of a hashing ECDSA mechanism; nullptr for CKM_ECDSA.
inline const char *ecdsa_md(CK_MECHANISM_TYPE mech)
{
    switch (mech)
    {
    case CKM_ECDSA_SHA1:
        return "SHA1";
    case CKM_ECDSA_SHA256:
        return "SHA256";
    case CKM_ECDSA_SHA384:
        return "SHA384";
    case CKM_ECDSA_SHA512:
        return "SHA512";
    default:
        return nullptr;
    }
}
