// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// The host oracle: OpenSSL recomputes or checks on the host what the token
/// computes, so a test can judge a key-backed result without reading the key.
///
/// Everything runs in a private OSSL_LIB_CTX holding only the default provider.
/// The module and the SDK it loads share this process's libcrypto, and the
/// global context is theirs and the system openssl.cnf's (see build_pota in
/// tsra_pkcs11_hsm.c), so the oracle never depends on what either did to it.
/// Keys made here belong to the private context too. host_crypto_tests.cpp
/// checks every helper against published vectors.
///
/// A library failure throws std::runtime_error. An input the operation itself
/// rejects (bad padding, a signature that does not verify) returns an empty
/// optional or false.

#include <memory>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace host
{

using Bytes = std::vector<unsigned char>;

/// An uncompressed P-521 point, the longest EC point here.
constexpr size_t kMaxEcPoint = 1 + (2 * 66);
/// The CKM_RSA_AES_KEY_WRAP key-encryption key: AES-256.
constexpr size_t kRsaAesKekBytes = 32;

template <typename T, void (*Free)(T *)> struct Deleter
{
    void operator()(T *p) const
    {
        Free(p);
    }
};
/// An OpenSSL object freed with its own free function.
template <typename T, void (*Free)(T *)> using Owned = std::unique_ptr<T, Deleter<T, Free>>;
/// An owned key.
using Pkey = Owned<EVP_PKEY, EVP_PKEY_free>;

/// Throw with OpenSSL's last error; the error queue is shared with the module.
[[noreturn]] inline void fail(const char *what)
{
    char reason[256] = "";
    ERR_error_string_n(ERR_peek_last_error(), reason, sizeof(reason));
    ERR_clear_error();
    throw std::runtime_error(std::string("host_crypto: ") + what + ": " + reason);
}

/// The private library context. Never freed: freeing it at exit could run
/// after libcrypto's own exit-time cleanup.
inline OSSL_LIB_CTX *libctx()
{
    static OSSL_LIB_CTX *ctx = [] {
        OSSL_LIB_CTX *c = OSSL_LIB_CTX_new();
        if ((c == nullptr) || (OSSL_PROVIDER_load(c, "default") == nullptr))
        {
            fail("private OSSL_LIB_CTX with the default provider");
        }
        return c;
    }();
    return ctx;
}

/// An octet-string parameter; OpenSSL rejects a NULL buffer even at length 0.
inline OSSL_PARAM octets(const char *key, const Bytes &v)
{
    static unsigned char empty = 0;
    return OSSL_PARAM_construct_octet_string(
        key,
        v.empty() ? &empty : const_cast<unsigned char *>(v.data()),
        v.size()
    );
}

inline OSSL_PARAM utf8(const char *key, const char *v)
{
    return OSSL_PARAM_construct_utf8_string(key, const_cast<char *>(v), 0);
}

/// HMAC of msg under key with the digest md ("SHA256", ...).
inline Bytes hmac(const char *md, const Bytes &key, const Bytes &msg)
{
    Owned<EVP_MAC, EVP_MAC_free> mac(EVP_MAC_fetch(libctx(), "HMAC", nullptr));
    Owned<EVP_MAC_CTX, EVP_MAC_CTX_free> ctx(mac ? EVP_MAC_CTX_new(mac.get()) : nullptr);
    OSSL_PARAM params[] = { utf8(OSSL_MAC_PARAM_DIGEST, md), OSSL_PARAM_construct_end() };
    Bytes out(EVP_MAX_MD_SIZE);
    size_t len = 0;
    if (!ctx || (EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1) ||
        (EVP_MAC_update(ctx.get(), msg.data(), msg.size()) != 1) ||
        (EVP_MAC_final(ctx.get(), out.data(), &len, out.size()) != 1))
    {
        fail("HMAC");
    }
    out.resize(len);
    return out;
}

/// HKDF extract-and-expand (RFC 5869) with the digest md; an empty salt means
/// a salt of hash-length zeros.
inline Bytes hkdf(
    const char *md,
    const Bytes &ikm,
    const Bytes &salt,
    const Bytes &info,
    size_t len
)
{
    Owned<EVP_KDF, EVP_KDF_free> kdf(EVP_KDF_fetch(libctx(), "HKDF", nullptr));
    Owned<EVP_KDF_CTX, EVP_KDF_CTX_free> ctx(kdf ? EVP_KDF_CTX_new(kdf.get()) : nullptr);
    OSSL_PARAM params[] = {
        utf8(OSSL_KDF_PARAM_DIGEST, md),   octets(OSSL_KDF_PARAM_KEY, ikm),
        octets(OSSL_KDF_PARAM_SALT, salt), octets(OSSL_KDF_PARAM_INFO, info),
        OSSL_PARAM_construct_end(),
    };
    Bytes out(len);
    if (!ctx || (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1))
    {
        fail("HKDF");
    }
    return out;
}

/// Run the cipher `name` over `in` in one go; an empty optional when the
/// input is rejected (bad padding, a wrong unwrap check).
inline std::optional<Bytes> cipher(
    const std::string &name,
    bool encrypt,
    const Bytes &key,
    const Bytes &iv,
    const Bytes &in,
    bool pad
)
{
    Owned<EVP_CIPHER, EVP_CIPHER_free> c(EVP_CIPHER_fetch(libctx(), name.c_str(), nullptr));
    Owned<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free> ctx(EVP_CIPHER_CTX_new());
    if (!c || !ctx)
    {
        fail(name.c_str());
    }
    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if ((EVP_CipherInit_ex2(
             ctx.get(),
             c.get(),
             key.data(),
             iv.empty() ? nullptr : iv.data(),
             encrypt ? 1 : 0,
             nullptr
         ) != 1) ||
        (EVP_CIPHER_CTX_set_padding(ctx.get(), pad ? 1 : 0) != 1))
    {
        fail(name.c_str());
    }
    Bytes out(in.size() + (2 * EVP_MAX_BLOCK_LENGTH));
    int in_len = static_cast<int>(in.size());
    int n = 0;
    int last = 0;
    if ((EVP_CipherUpdate(ctx.get(), out.data(), &n, in.data(), in_len) != 1) ||
        (EVP_CipherFinal_ex(ctx.get(), out.data() + n, &last) != 1))
    {
        ERR_clear_error();
        return std::nullopt;
    }
    out.resize(static_cast<size_t>(n + last));
    return out;
}

/// AES-CBC encryption, with PKCS#7 padding when pad is set (CKM_AES_CBC_PAD).
inline Bytes aes_cbc_encrypt(const Bytes &key, const Bytes &iv, const Bytes &in, bool pad)
{
    std::string name = "AES-" + std::to_string(key.size() * 8) + "-CBC";
    std::optional<Bytes> out = cipher(name, true, key, iv, in, pad);
    if (!out)
    {
        fail("AES-CBC encrypt (unpadded input not a multiple of the block?)");
    }
    return *out;
}

/// AES-CBC decryption; empty when the padding (or the length) is wrong.
inline std::optional<Bytes> aes_cbc_decrypt(
    const Bytes &key,
    const Bytes &iv,
    const Bytes &in,
    bool pad
)
{
    return cipher("AES-" + std::to_string(key.size() * 8) + "-CBC", false, key, iv, in, pad);
}

/// AES key wrap with padding (RFC 5649) of `in` under the KEK.
inline Bytes aes_kwp_wrap(const Bytes &kek, const Bytes &in)
{
    std::string name = "AES-" + std::to_string(kek.size() * 8) + "-WRAP-PAD";
    std::optional<Bytes> out = cipher(name, true, kek, Bytes(), in, false);
    if (!out)
    {
        fail(name.c_str());
    }
    return *out;
}

/// A key of `type` built from parameters.
inline Pkey from_data(const char *type, int selection, OSSL_PARAM *params)
{
    Owned<EVP_PKEY_CTX, EVP_PKEY_CTX_free> ctx(EVP_PKEY_CTX_new_from_name(libctx(), type, nullptr));
    EVP_PKEY *key = nullptr;
    if (!ctx || (EVP_PKEY_fromdata_init(ctx.get()) != 1) ||
        (EVP_PKEY_fromdata(ctx.get(), &key, selection, params) != 1))
    {
        fail(type);
    }
    return Pkey(key);
}

/// A private key of any type from PKCS#8 DER.
inline Pkey private_key(const Bytes &pkcs8)
{
    const unsigned char *p = pkcs8.data();
    Pkey key(d2i_AutoPrivateKey_ex(nullptr, &p, static_cast<long>(pkcs8.size()), libctx(), nullptr)
    );
    if (!key)
    {
        fail("PKCS#8 private key");
    }
    return key;
}

/// The PKCS#8 DER encoding of a private key (what C_UnwrapKey imports).
inline Bytes pkcs8(EVP_PKEY *key)
{
    Owned<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free> p8(EVP_PKEY2PKCS8(key));
    unsigned char *der = nullptr;
    int len = p8 ? i2d_PKCS8_PRIV_KEY_INFO(p8.get(), &der) : -1;
    if (len <= 0)
    {
        fail("PKCS#8 encoding");
    }
    Bytes out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// An RSA public key from its big-endian modulus and public exponent
/// (CKA_MODULUS and CKA_PUBLIC_EXPONENT).
inline Pkey rsa_public(const Bytes &n, const Bytes &e)
{
    Owned<BIGNUM, BN_free> bn_n(BN_bin2bn(n.data(), static_cast<int>(n.size()), nullptr));
    Owned<BIGNUM, BN_free> bn_e(BN_bin2bn(e.data(), static_cast<int>(e.size()), nullptr));
    Owned<OSSL_PARAM_BLD, OSSL_PARAM_BLD_free> bld(OSSL_PARAM_BLD_new());
    if (!bn_n || !bn_e || !bld ||
        (OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, bn_n.get()) != 1) ||
        (OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, bn_e.get()) != 1))
    {
        fail("RSA public key parameters");
    }
    Owned<OSSL_PARAM, OSSL_PARAM_free> params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params)
    {
        fail("RSA public key parameters");
    }
    return from_data("RSA", EVP_PKEY_PUBLIC_KEY, params.get());
}

/// Sign msg hashed with md under PKCS#1 v1.5 (padding RSA_PKCS1_PADDING) or
/// PSS (RSA_PKCS1_PSS_PADDING: MGF1 with md, salt as long as the digest).
inline Bytes rsa_sign(EVP_PKEY *key, const char *md, int padding, const Bytes &msg)
{
    Owned<EVP_MD_CTX, EVP_MD_CTX_free> ctx(EVP_MD_CTX_new());
    EVP_PKEY_CTX *pctx = nullptr; /* owned by ctx */
    size_t len = 0;
    if (!ctx ||
        (EVP_DigestSignInit_ex(ctx.get(), &pctx, md, libctx(), nullptr, key, nullptr) != 1) ||
        (EVP_PKEY_CTX_set_rsa_padding(pctx, padding) != 1) ||
        ((padding == RSA_PKCS1_PSS_PADDING) &&
         (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1)) ||
        (EVP_DigestSign(ctx.get(), nullptr, &len, msg.data(), msg.size()) != 1))
    {
        fail("RSA sign");
    }
    Bytes sig(len);
    if (EVP_DigestSign(ctx.get(), sig.data(), &len, msg.data(), msg.size()) != 1)
    {
        fail("RSA sign");
    }
    sig.resize(len);
    return sig;
}

/// Verify an RSA signature made as rsa_sign() makes it.
inline bool rsa_verify(
    EVP_PKEY *key,
    const char *md,
    int padding,
    const Bytes &msg,
    const Bytes &sig
)
{
    Owned<EVP_MD_CTX, EVP_MD_CTX_free> ctx(EVP_MD_CTX_new());
    EVP_PKEY_CTX *pctx = nullptr; /* owned by ctx */
    if (!ctx ||
        (EVP_DigestVerifyInit_ex(ctx.get(), &pctx, md, libctx(), nullptr, key, nullptr) != 1) ||
        (EVP_PKEY_CTX_set_rsa_padding(pctx, padding) != 1) ||
        ((padding == RSA_PKCS1_PSS_PADDING) &&
         (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1)))
    {
        fail("RSA verify");
    }
    bool ok = EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), msg.data(), msg.size()) == 1;
    ERR_clear_error();
    return ok;
}

/// RSA-OAEP with md as the OAEP and the MGF1 hash (the only form the SDK takes)
/// and a label (empty for none); a rejected decryption input returns empty.
/// rsa_oaep_encrypt() and rsa_oaep_decrypt() below are the two directions.
inline std::optional<Bytes> rsa_oaep(
    EVP_PKEY *key,
    bool encrypt,
    const char *md,
    const Bytes &in,
    const Bytes &label
)
{
    Owned<EVP_PKEY_CTX, EVP_PKEY_CTX_free> ctx(EVP_PKEY_CTX_new_from_pkey(libctx(), key, nullptr));
    OSSL_PARAM params[] = {
        utf8(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_OAEP),
        utf8(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, md),
        utf8(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, md),
        octets(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, label),
        OSSL_PARAM_construct_end(),
    };
    auto init = encrypt ? EVP_PKEY_encrypt_init_ex : EVP_PKEY_decrypt_init_ex;
    auto op = encrypt ? EVP_PKEY_encrypt : EVP_PKEY_decrypt;
    size_t len = 0;
    if (!ctx || (init(ctx.get(), params) != 1) ||
        (op(ctx.get(), nullptr, &len, in.data(), in.size()) != 1))
    {
        fail("RSA-OAEP");
    }
    Bytes out(len);
    if (op(ctx.get(), out.data(), &len, in.data(), in.size()) != 1)
    {
        if (encrypt)
        {
            fail("RSA-OAEP encrypt");
        }
        ERR_clear_error();
        return std::nullopt;
    }
    out.resize(len);
    return out;
}

inline Bytes rsa_oaep_encrypt(EVP_PKEY *key, const char *md, const Bytes &msg, const Bytes &label)
{
    return *rsa_oaep(key, true, md, msg, label);
}

inline std::optional<Bytes> rsa_oaep_decrypt(
    EVP_PKEY *key,
    const char *md,
    const Bytes &ct,
    const Bytes &label
)
{
    return rsa_oaep(key, false, md, ct, label);
}

/// The CKM_RSA_AES_KEY_WRAP blob that C_UnwrapKey takes for `target` (a
/// secret key value or a PKCS#8 private key): a fresh AES-256 key encrypted
/// under the RSA public key with OAEP (md for OAEP and MGF1, no label),
/// followed by target wrapped under that AES key with RFC 5649.
inline Bytes rsa_aes_key_wrap(EVP_PKEY *key, const char *md, const Bytes &target)
{
    Bytes kek(kRsaAesKekBytes);
    if (RAND_bytes_ex(libctx(), kek.data(), kek.size(), 0) != 1)
    {
        fail("RAND_bytes_ex");
    }
    Bytes out = rsa_oaep_encrypt(key, md, kek, Bytes());
    Bytes wrapped = aes_kwp_wrap(kek, target);
    out.insert(out.end(), wrapped.begin(), wrapped.end());
    return out;
}

/// An EC public key from a curve ("P-256", "P-384", "P-521") and an
/// uncompressed point 0x04 || x || y (the octet string inside CKA_EC_POINT).
/// A point not on the curve throws.
inline Pkey ec_public(const char *curve, const Bytes &point)
{
    OSSL_PARAM params[] = {
        utf8(OSSL_PKEY_PARAM_GROUP_NAME, curve),
        octets(OSSL_PKEY_PARAM_PUB_KEY, point),
        OSSL_PARAM_construct_end(),
    };
    return from_data("EC", EVP_PKEY_PUBLIC_KEY, params);
}

/// The uncompressed point of an EC key.
inline Bytes ec_point(EVP_PKEY *key)
{
    Bytes out(kMaxEcPoint);
    size_t len = 0;
    if (EVP_PKEY_get_octet_string_param(
            key,
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
            out.data(),
            out.size(),
            &len
        ) != 1)
    {
        fail("EC point");
    }
    out.resize(len);
    return out;
}

/// An EC private key from a curve and its big-endian scalar, with the public
/// point computed from it (so pkcs8() carries both).
inline Pkey ec_private(const char *curve, const Bytes &scalar)
{
    Owned<EC_GROUP, EC_GROUP_free> group(
        EC_GROUP_new_by_curve_name_ex(libctx(), nullptr, EC_curve_nist2nid(curve))
    );
    Owned<BIGNUM, BN_free> d(BN_bin2bn(scalar.data(), static_cast<int>(scalar.size()), nullptr));
    Owned<EC_POINT, EC_POINT_free> pub(group ? EC_POINT_new(group.get()) : nullptr);
    if (!pub || !d ||
        (EC_POINT_mul(group.get(), pub.get(), d.get(), nullptr, nullptr, nullptr) != 1))
    {
        fail("EC public point");
    }
    Bytes point(kMaxEcPoint);
    size_t len = EC_POINT_point2oct(
        group.get(),
        pub.get(),
        POINT_CONVERSION_UNCOMPRESSED,
        point.data(),
        point.size(),
        nullptr
    );
    point.resize(len);
    Owned<OSSL_PARAM_BLD, OSSL_PARAM_BLD_free> bld(OSSL_PARAM_BLD_new());
    if ((len == 0) || !bld ||
        (OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, curve, 0) != 1) ||
        (OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, d.get()) != 1) ||
        (OSSL_PARAM_BLD_push_octet_string(
             bld.get(),
             OSSL_PKEY_PARAM_PUB_KEY,
             point.data(),
             point.size()
         ) != 1))
    {
        fail("EC private key parameters");
    }
    Owned<OSSL_PARAM, OSSL_PARAM_free> params(OSSL_PARAM_BLD_to_param(bld.get()));
    if (!params)
    {
        fail("EC private key parameters");
    }
    return from_data("EC", EVP_PKEY_KEYPAIR, params.get());
}

/// A fresh EC key pair on the curve.
inline Pkey ec_generate(const char *curve)
{
    Pkey key(EVP_PKEY_Q_keygen(libctx(), nullptr, "EC", curve));
    if (!key)
    {
        fail("EC key generation");
    }
    return key;
}

/// Verify a PKCS#11 ECDSA signature, r || s with each half as long as the
/// group order, over msg hashed with md (CKM_ECDSA_SHA256, ...) or over msg
/// as the digest itself when md is nullptr (CKM_ECDSA).
inline bool ecdsa_verify(EVP_PKEY *key, const char *md, const Bytes &msg, const Bytes &sig)
{
    size_t half = (static_cast<size_t>(EVP_PKEY_get_bits(key)) + 7) / 8;
    if (sig.size() != (2 * half))
    {
        return false;
    }
    Owned<ECDSA_SIG, ECDSA_SIG_free> es(ECDSA_SIG_new());
    BIGNUM *r = BN_bin2bn(sig.data(), static_cast<int>(half), nullptr);
    BIGNUM *s = BN_bin2bn(sig.data() + half, static_cast<int>(half), nullptr);
    if (!es || (r == nullptr) || (s == nullptr) || (ECDSA_SIG_set0(es.get(), r, s) != 1))
    {
        BN_free(r);
        BN_free(s);
        fail("ECDSA signature");
    }
    unsigned char *encoded = nullptr;
    int encoded_len = i2d_ECDSA_SIG(es.get(), &encoded);
    if (encoded_len <= 0)
    {
        fail("ECDSA signature encoding");
    }
    Bytes der(encoded, encoded + encoded_len);
    OPENSSL_free(encoded);
    int rc = 0;
    if (md != nullptr)
    {
        Owned<EVP_MD_CTX, EVP_MD_CTX_free> ctx(EVP_MD_CTX_new());
        if (!ctx ||
            (EVP_DigestVerifyInit_ex(ctx.get(), nullptr, md, libctx(), nullptr, key, nullptr) != 1))
        {
            fail("ECDSA verify");
        }
        rc = EVP_DigestVerify(ctx.get(), der.data(), der.size(), msg.data(), msg.size());
    }
    else
    {
        Owned<EVP_PKEY_CTX, EVP_PKEY_CTX_free> ctx(
            EVP_PKEY_CTX_new_from_pkey(libctx(), key, nullptr)
        );
        if (!ctx || (EVP_PKEY_verify_init(ctx.get()) != 1))
        {
            fail("ECDSA verify");
        }
        rc = EVP_PKEY_verify(ctx.get(), der.data(), der.size(), msg.data(), msg.size());
    }
    ERR_clear_error();
    return rc == 1;
}

/// The ECDH shared secret (the x-coordinate, as CKD_NULL derives it) of a
/// private key and a peer's uncompressed point on the same curve.
inline Bytes ecdh(EVP_PKEY *key, const Bytes &peer_point)
{
    char curve[64] = "";
    if (EVP_PKEY_get_utf8_string_param(
            key,
            OSSL_PKEY_PARAM_GROUP_NAME,
            curve,
            sizeof(curve),
            nullptr
        ) != 1)
    {
        fail("EC curve name");
    }
    Pkey peer = ec_public(curve, peer_point);
    Owned<EVP_PKEY_CTX, EVP_PKEY_CTX_free> ctx(EVP_PKEY_CTX_new_from_pkey(libctx(), key, nullptr));
    size_t len = 0;
    if (!ctx || (EVP_PKEY_derive_init(ctx.get()) != 1) ||
        (EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1) ||
        (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1))
    {
        fail("ECDH");
    }
    Bytes out(len);
    if (EVP_PKEY_derive(ctx.get(), out.data(), &len) != 1)
    {
        fail("ECDH");
    }
    out.resize(len);
    return out;
}

} // namespace host
