// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file derive_tests.cpp
///
/// C_DeriveKey with CKM_ECDH1_DERIVE and CKM_HKDF_DERIVE: the chain from a
/// token EC key and a host peer through the shared secret into an AES-CBC
/// key, recomputed bit-exact by the host oracle on every curve and over the
/// PRF hashes, salt forms, info lengths and key lengths (HKDF reads the secret
/// in the device's byte order, see device_ikm); HKDF into each HMAC
/// key type; the attributes derived keys get; one row per refusal with its
/// positive control and no object left; the checks that come first
/// (initialized, session, arguments, login); the base key rules; survival
/// across a relogin and the end of a session; the Wycheproof ECDH points the
/// token must refuse; the leak gate; and that the file store never sees a
/// derived value. The full verdict matrix is in tests/derive_params_test.c.

#include <cstring>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include "tsra_pkcs11_derive_params.h"
#include "tsra_pkcs11_digest.h"
#include "utils/aes_helpers.hpp"
#include "utils/ec_helpers.hpp"
#include "utils/host_crypto.hpp"
#include "utils/leak_gate.hpp"
#include "utils/module.hpp"
#include "utils/store_dir.hpp"
#include "utils/surviving_key.hpp"
#include "utils/unwrap_helpers.hpp"
#include "vectors/vectors.hpp"
#include "wycheproof/ecdh_ecpoint.inc"

namespace
{

CK_BBOOL g_yes = CK_TRUE;
CK_BBOOL g_no = CK_FALSE;
CK_OBJECT_CLASS g_secret_class = CKO_SECRET_KEY;
CK_KEY_TYPE g_generic = CKK_GENERIC_SECRET;
CK_KEY_TYPE g_aes = CKK_AES;

/// The salt and info of the chain test, and the block it encrypts.
const host::Bytes kSalt = { 's', 'a', 'l', 't' };
const host::Bytes kInfo = { 'i', 'n', 'f', 'o' };
constexpr CK_BYTE kIvByte = 0x3C;
/// The bytes of the longest salt.
constexpr CK_BYTE kSaltFill = 0x5A;
/// SEC 1: the first byte of a compressed point, plus the parity of y.
constexpr CK_BYTE kEcCompressed = 0x02;

/// The word the little-endian device (Uno and its simulator) pads ECC values
/// to (fw ECC_COORD_PAD of the Uno platforms).
constexpr size_t kDeviceWord = 4;

/// The HKDF input of an API 1.x device: the ECDH secret in the device's byte
/// order, least significant byte first and zero-padded to whole words (68
/// bytes for P-521), where SP 800-56A and RFC 5869 take the big-endian
/// x-coordinate `z` (a deviation in the README). The tests named
/// *_in_device_byte_order pin it. A firmware that hands HKDF the standard
/// secret turns them red; that is the signal to give the oracle `z` itself and
/// to drop the README deviation.
host::Bytes device_ikm(const host::Bytes &z)
{
    host::Bytes out(z.rbegin(), z.rend());
    out.resize(((out.size() + kDeviceWord - 1) / kDeviceWord) * kDeviceWord, 0);
    return out;
}

/// The OpenSSL name of an HKDF PRF.
const char *prf_name(CK_MECHANISM_TYPE prf)
{
    switch (prf)
    {
    case CKM_SHA384:
        return "SHA384";
    case CKM_SHA512:
        return "SHA512";
    default:
        return "SHA256";
    }
}

/// CK_ECDH1_DERIVE_PARAMS with CKD_NULL around a copy of `point` (raw or DER),
/// so a temporary argument is safe.
struct EcdhMechanism
{
    explicit EcdhMechanism(host::Bytes point)
        : point_bytes(std::move(point)), params{ CKD_NULL,
                                                 0,
                                                 nullptr,
                                                 static_cast<CK_ULONG>(point_bytes.size()),
                                                 point_bytes.data() },
          mech{ CKM_ECDH1_DERIVE, &params, sizeof(params) }
    {
    }
    EcdhMechanism(const EcdhMechanism &) = delete; /* params and mech point into this object */
    EcdhMechanism &operator=(const EcdhMechanism &) = delete;

    host::Bytes point_bytes; /* declared before params, which points into it */
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM mech;
};

/// CK_HKDF_PARAMS for extract and expand with `prf`, a salt of bytes (none
/// when `salt_null`) and `info`. It keeps copies of both, so temporary
/// arguments are safe.
struct HkdfMechanism
{
    HkdfMechanism(CK_MECHANISM_TYPE prf, host::Bytes salt, host::Bytes info, bool salt_null = false)
        : salt_bytes(std::move(salt)), info_bytes(std::move(info)),
          params{ CK_TRUE,
                  CK_TRUE,
                  prf,
                  salt_null ? CKF_HKDF_SALT_NULL : CKF_HKDF_SALT_DATA,
                  salt_null ? nullptr : salt_bytes.data(),
                  salt_null ? 0 : static_cast<CK_ULONG>(salt_bytes.size()),
                  CK_INVALID_HANDLE,
                  info_bytes.data(),
                  static_cast<CK_ULONG>(info_bytes.size()) },
          mech{ CKM_HKDF_DERIVE, &params, sizeof(params) }
    {
    }
    HkdfMechanism(const HkdfMechanism &) = delete; /* params and mech point into this object */
    HkdfMechanism &operator=(const HkdfMechanism &) = delete;

    /* Declared before params, which points into them. */
    host::Bytes salt_bytes;
    host::Bytes info_bytes;
    CK_HKDF_PARAMS params;
    CK_MECHANISM mech;
};

/// C_DeriveKey with `tmpl`.
CK_RV run_derive(
    CK_SESSION_HANDLE s,
    CK_MECHANISM *mech,
    CK_OBJECT_HANDLE base,
    std::vector<CK_ATTRIBUTE> tmpl,
    CK_OBJECT_HANDLE *out
)
{
    return p11()->C_DeriveKey(s, mech, base, tmpl.data(), static_cast<CK_ULONG>(tmpl.size()), out);
}

/// The template of the ECDH secret: a generic secret, a token object or not.
std::vector<CK_ATTRIBUTE> secret_template(CK_BBOOL *token)
{
    return {
        { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
        { CKA_KEY_TYPE, &g_generic, sizeof(g_generic) },
        { CKA_TOKEN, token, sizeof(*token) },
    };
}

/// The template of an AES key of *len bytes from HKDF.
std::vector<CK_ATTRIBUTE> aes_template(CK_ULONG *len, CK_BBOOL *token)
{
    return {
        { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
        { CKA_KEY_TYPE, &g_aes, sizeof(g_aes) },
        { CKA_VALUE_LEN, len, sizeof(*len) },
        { CKA_TOKEN, token, sizeof(*token) },
    };
}

/// The ECDH secret of the token key `priv` and the peer `point`.
CK_RV ecdh(
    CK_SESSION_HANDLE s,
    CK_OBJECT_HANDLE priv,
    const std::vector<CK_BYTE> &point,
    CK_OBJECT_HANDLE *secret,
    CK_BBOOL token = CK_FALSE
)
{
    EcdhMechanism m(point);
    return run_derive(s, &m.mech, priv, secret_template(&token), secret);
}

/// AES-CBC of a fixed message under `key` with a fixed IV, on the token.
std::vector<CK_BYTE> cbc_on_token(CK_SESSION_HANDLE s, CK_OBJECT_HANDLE key)
{
    CK_BYTE iv[kAesBlock];
    std::memset(iv, kIvByte, sizeof(iv));
    CK_MECHANISM cbc = { CKM_AES_CBC, iv, sizeof(iv) };
    std::vector<CK_BYTE> ct;
    CK_RV rv = crypt_oneshot(s, true, &cbc, key, pattern(2 * kAesBlock), ct);
    return (rv == CKR_OK) ? ct : std::vector<CK_BYTE>();
}

/// The same on the host with the key's value.
host::Bytes cbc_on_host(const host::Bytes &key)
{
    return host::aes_cbc_encrypt(
        key,
        host::Bytes(kAesBlock, kIvByte),
        pattern(2 * kAesBlock),
        false
    );
}

} // namespace

/// A logged-in session with a deriving EC pair on each curve, made on first
/// use, and a host key on the same curve as the peer.
class derive : public UserSession
{
  protected:
    /// A deriving pair on curve `c` (an index into ec_curves()): the private
    /// key and its uncompressed point. ASSERTs.
    void token_pair(
        size_t c,
        CK_OBJECT_HANDLE *priv,
        std::vector<CK_BYTE> *point,
        CK_BBOOL token = CK_FALSE,
        CK_OBJECT_HANDLE *pub = nullptr
    )
    {
        CK_OBJECT_HANDLE p = CK_INVALID_HANDLE;
        ASSERT_CKR_OK(gen_ec_pair(s_, ec_curves()[c], false, token, CK_TRUE, "derive", &p, priv));
        *point = ec_point(s_, p);
        ASSERT_FALSE(point->empty());
        if (pub != nullptr)
        {
            *pub = p;
        }
    }

    /// The P-256 secret of a fresh token pair and a fresh host key, and the
    /// value the host computes for it. ASSERTs.
    void p256_secret(
        CK_OBJECT_HANDLE *secret,
        host::Bytes *z,
        CK_BBOOL token = CK_FALSE,
        CK_OBJECT_HANDLE *pub = nullptr,
        CK_OBJECT_HANDLE *priv_out = nullptr
    )
    {
        CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
        std::vector<CK_BYTE> point;
        ASSERT_NO_FATAL_FAILURE(token_pair(0, &priv, &point, token, pub));
        if (priv_out != nullptr)
        {
            *priv_out = priv;
        }
        host::Pkey peer = host::ec_generate("P-256");
        ASSERT_CKR_OK(ecdh(s_, priv, host::ec_point(peer.get()), secret, token));
        *z = host::ecdh(peer.get(), point);
        ASSERT_FALSE(z->empty());
    }

    /// An AES key of `len` bytes from `secret` with HKDF and the chain's
    /// salt and info. ASSERTs.
    void aes_from(
        CK_OBJECT_HANDLE secret,
        CK_ULONG len,
        CK_OBJECT_HANDLE *key,
        CK_BBOOL token = CK_FALSE
    )
    {
        HkdfMechanism m(CKM_SHA256, kSalt, kInfo);
        ASSERT_CKR_OK(derive_key(&m.mech, secret, aes_template(&len, &token), key));
    }

    CK_RV derive_key(
        CK_MECHANISM *mech,
        CK_OBJECT_HANDLE base,
        std::vector<CK_ATTRIBUTE> tmpl,
        CK_OBJECT_HANDLE *out
    )
    {
        return run_derive(s_, mech, base, std::move(tmpl), out);
    }
};

// ---------------------------------------------------------------------------
// The chain against the host
// ---------------------------------------------------------------------------

TEST_F(derive, ecdh_then_hkdf_matches_the_host_on_every_curve_in_device_byte_order)
{
    for (size_t c = 0; c < ec_curves().size(); c++)
    {
        const EcCurve &curve = ec_curves()[c];
        SCOPED_TRACE(curve.name);
        CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
        std::vector<CK_BYTE> point;
        ASSERT_NO_FATAL_FAILURE(token_pair(c, &priv, &point));
        host::Pkey peer = host::ec_generate(curve.name);
        CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
        ASSERT_CKR_OK(ecdh(s_, priv, host::ec_point(peer.get()), &secret));
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        ASSERT_NO_FATAL_FAILURE(aes_from(secret, AES256_KEY_BYTES, &key));

        host::Bytes z = host::ecdh(peer.get(), point);
        ASSERT_EQ(curve.coord, z.size());
        host::Bytes k = host::hkdf("SHA256", device_ikm(z), kSalt, kInfo, AES256_KEY_BYTES);
        std::vector<CK_BYTE> ct = cbc_on_token(s_, key);
        ASSERT_FALSE(ct.empty());
        EXPECT_EQ(cbc_on_host(k), ct)
            << "the host's ECDH secret, HKDF over it in the device's byte order, AES-CBC";
        CK_ULONG len = 0;
        ASSERT_CKR_OK(get_attr(s_, secret, CKA_VALUE_LEN, &len));
        EXPECT_EQ(curve.coord, len) << "the secret is as long as the curve's coordinate";
    }
}

TEST_F(derive, the_peer_point_may_be_raw_or_in_der)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    std::vector<CK_BYTE> point;
    ASSERT_NO_FATAL_FAILURE(token_pair(2, &priv, &point));
    host::Pkey peer = host::ec_generate("P-521");
    host::Bytes raw = host::ec_point(peer.get());
    std::vector<CK_BYTE> der = { kDerOctetString, kDerLen1, static_cast<CK_BYTE>(raw.size()) };
    der.insert(der.end(), raw.begin(), raw.end());
    CK_OBJECT_HANDLE a = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE b = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(ecdh(s_, priv, raw, &a)) << "the raw point";
    ASSERT_CKR_OK(ecdh(s_, priv, der, &b)) << "the DER OCTET STRING, as CKA_EC_POINT holds it";
    CK_OBJECT_HANDLE ka = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE kb = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(aes_from(a, AES128_KEY_BYTES, &ka));
    ASSERT_NO_FATAL_FAILURE(aes_from(b, AES128_KEY_BYTES, &kb));
    std::vector<CK_BYTE> ca = cbc_on_token(s_, ka);
    ASSERT_FALSE(ca.empty());
    EXPECT_EQ(ca, cbc_on_token(s_, kb)) << "both forms give the same secret";
}

TEST_F(derive, hkdf_sweep_matches_the_host_in_device_byte_order)
{
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    host::Bytes z;
    ASSERT_NO_FATAL_FAILURE(p256_secret(&secret, &z));
    const host::Bytes full_salt(HKDF_MAX_SALT_LEN, kSaltFill);
    struct Salt
    {
        const char *what;
        host::Bytes bytes;
        bool null;
    } salts[] = {
        { "CKF_HKDF_SALT_NULL", {}, true },
        { "an empty salt", {}, false },
        { "a one-byte salt", { 0x01 }, false },
        { "a salt of HKDF_MAX_SALT_LEN bytes", full_salt, false },
    };
    const size_t info_lens[] = { 0, 1, HKDF_MAX_INFO_LEN - 1, HKDF_MAX_INFO_LEN };
    for (CK_MECHANISM_TYPE prf : { CKM_SHA256, CKM_SHA384, CKM_SHA512 })
    {
        for (const Salt &salt : salts)
        {
            for (size_t info_len : info_lens)
            {
                SCOPED_TRACE(
                    std::string(prf_name(prf)) + ", " + salt.what + ", info " +
                    std::to_string(info_len)
                );
                host::Bytes info(info_len);
                for (size_t i = 0; i < info.size(); i++)
                {
                    info[i] = static_cast<CK_BYTE>(i ^ prf);
                }
                HkdfMechanism m(prf, salt.bytes, info, salt.null);
                CK_ULONG len = AES256_KEY_BYTES;
                CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
                ASSERT_CKR_OK(derive_key(&m.mech, secret, aes_template(&len, &g_no), &key));
                host::Bytes k = host::hkdf(prf_name(prf), device_ikm(z), salt.bytes, info, len);
                std::vector<CK_BYTE> ct = cbc_on_token(s_, key);
                ASSERT_FALSE(ct.empty());
                EXPECT_EQ(cbc_on_host(k), ct) << "the token's HKDF equals RFC 5869 on the host";
                ASSERT_CKR_OK(p11()->C_DestroyObject(s_, key));
            }
        }
    }
}

TEST_F(derive, every_aes_length_matches_the_host_in_device_byte_order)
{
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    host::Bytes z;
    ASSERT_NO_FATAL_FAILURE(p256_secret(&secret, &z));
    for (CK_ULONG len : { AES128_KEY_BYTES, AES192_KEY_BYTES, AES256_KEY_BYTES })
    {
        SCOPED_TRACE(std::to_string(len) + " bytes");
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        ASSERT_NO_FATAL_FAILURE(aes_from(secret, len, &key));
        std::vector<CK_BYTE> ct = cbc_on_token(s_, key);
        ASSERT_FALSE(ct.empty());
        EXPECT_EQ(cbc_on_host(host::hkdf("SHA256", device_ikm(z), kSalt, kInfo, len)), ct)
            << "the key is HKDF's first CKA_VALUE_LEN bytes";
    }
}

// ---------------------------------------------------------------------------
// What derived keys are
// ---------------------------------------------------------------------------

TEST_F(derive, derived_keys_carry_their_attributes)
{
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    host::Bytes z;
    ASSERT_NO_FATAL_FAILURE(p256_secret(&secret, &z));
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(aes_from(secret, AES128_KEY_BYTES, &key));
    struct
    {
        CK_OBJECT_HANDLE obj;
        CK_ATTRIBUTE_TYPE type;
        CK_BBOOL want;
    } flags[] = {
        { secret, CKA_DERIVE, CK_TRUE },
        { secret, CKA_SENSITIVE, CK_TRUE },
        { secret, CKA_EXTRACTABLE, CK_FALSE },
        { secret, CKA_LOCAL, CK_FALSE },
        { secret, CKA_ALWAYS_SENSITIVE, CK_TRUE },
        { secret, CKA_NEVER_EXTRACTABLE, CK_TRUE },
        { secret, CKA_PRIVATE, CK_TRUE },
        { key, CKA_ENCRYPT, CK_TRUE },
        { key, CKA_DECRYPT, CK_TRUE },
        { key, CKA_SENSITIVE, CK_TRUE },
        { key, CKA_LOCAL, CK_FALSE },
        { key, CKA_ALWAYS_SENSITIVE, CK_TRUE },
        { key, CKA_NEVER_EXTRACTABLE, CK_TRUE },
    };
    for (const auto &f : flags)
    {
        CK_BBOOL got = CK_FALSE;
        ASSERT_CKR_OK(get_attr(s_, f.obj, f.type, &got)) << "attribute 0x" << std::hex << f.type;
        EXPECT_EQ(f.want, got) << "attribute 0x" << std::hex << f.type
                               << ": a derived key keeps the base key's protection";
    }
    CK_BBOOL sign = CK_FALSE;
    EXPECT_CKR(CKR_ATTRIBUTE_TYPE_INVALID, get_attr(s_, secret, CKA_SIGN, &sign))
        << "the secret states only the usage its device key has";
    CK_KEY_TYPE kt = 0;
    CK_MECHANISM_TYPE kgm = 0;
    ASSERT_CKR_OK(get_attr(s_, secret, CKA_KEY_TYPE, &kt));
    EXPECT_EQ(CKK_GENERIC_SECRET, kt);
    ASSERT_CKR_OK(get_attr(s_, key, CKA_KEY_GEN_MECHANISM, &kgm));
    EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, kgm) << "derived, not generated";
    std::vector<CK_MECHANISM_TYPE> allowed;
    ASSERT_CKR_OK(get_allowed_mechs(s_, secret, allowed));
    EXPECT_EQ(std::vector<CK_MECHANISM_TYPE>({ CKM_HKDF_DERIVE }), allowed);
    ASSERT_CKR_OK(get_allowed_mechs(s_, key, allowed));
    EXPECT_EQ(std::vector<CK_MECHANISM_TYPE>({ CKM_AES_CBC, CKM_AES_CBC_PAD }), allowed);
    CK_BYTE value[ECDH_SECRET_MAX_BYTES];
    CK_ATTRIBUTE v = { CKA_VALUE, value, sizeof(value) };
    EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, p11()->C_GetAttributeValue(s_, secret, &v, 1))
        << "the secret never reaches the host";
}

TEST_F(derive, hkdf_into_each_hmac_key_type)
{
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    host::Bytes z;
    ASSERT_NO_FATAL_FAILURE(p256_secret(&secret, &z));
    struct
    {
        CK_KEY_TYPE kt;
        CK_ULONG len;
        CK_MECHANISM_TYPE mech;
    } types[] = {
        { CKK_SHA256_HMAC, TSRA_PKCS11_SHA256_DIGEST_LEN, CKM_SHA256_HMAC },
        { CKK_SHA384_HMAC, TSRA_PKCS11_SHA384_DIGEST_LEN, CKM_SHA384_HMAC },
        { CKK_SHA512_HMAC, TSRA_PKCS11_SHA512_DIGEST_LEN, CKM_SHA512_HMAC },
    };
    for (auto &t : types)
    {
        SCOPED_TRACE("key type 0x" + std::to_string(t.kt));
        HkdfMechanism m(CKM_SHA512, kSalt, kInfo);
        std::vector<CK_ATTRIBUTE> tmpl = {
            { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
            { CKA_KEY_TYPE, &t.kt, sizeof(t.kt) },
        };
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        ASSERT_CKR_OK(derive_key(&m.mech, secret, tmpl, &key));
        ASSERT_NE(CK_INVALID_HANDLE, key);
        CK_KEY_TYPE kt = 0;
        CK_ULONG len = 0;
        CK_BBOOL sign = CK_FALSE;
        CK_BBOOL verify = CK_FALSE;
        ASSERT_CKR_OK(get_attr(s_, key, CKA_KEY_TYPE, &kt));
        ASSERT_CKR_OK(get_attr(s_, key, CKA_VALUE_LEN, &len));
        ASSERT_CKR_OK(get_attr(s_, key, CKA_SIGN, &sign));
        ASSERT_CKR_OK(get_attr(s_, key, CKA_VERIFY, &verify));
        EXPECT_EQ(t.kt, kt);
        EXPECT_EQ(t.len, len) << "an HMAC key is as long as its hash";
        EXPECT_EQ(CK_TRUE, sign);
        EXPECT_EQ(CK_TRUE, verify);
        std::vector<CK_MECHANISM_TYPE> allowed;
        ASSERT_CKR_OK(get_allowed_mechs(s_, key, allowed));
        EXPECT_EQ(std::vector<CK_MECHANISM_TYPE>({ t.mech }), allowed);
        CK_BYTE on = CK_TRUE;
        CK_ATTRIBUTE derive_on = { CKA_DERIVE, &on, sizeof(on) };
        EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, key, &derive_on, 1))
            << "an HMAC key's usage stays as derived";
    }
}

// ---------------------------------------------------------------------------
// The checks that come first
// ---------------------------------------------------------------------------

TEST_F(derive, needs_an_initialized_module)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    std::vector<CK_BYTE> point;
    ASSERT_NO_FATAL_FAILURE(token_pair(0, &priv, &point));
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
    CK_RV rv = ecdh(s_, priv, point, &obj);
    CK_RV rv_null = p11()->C_DeriveKey(kInvalidSession, nullptr, 0, nullptr, 1, nullptr);
    s_ = 0;
    ASSERT_CKR_OK(p11()->C_Initialize(nullptr));
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &s_)
    );
    ASSERT_CKR_OK(login_user(s_));
    EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, rv) << "a finalized module derives nothing";
    EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, rv_null) << "before the session and the arguments";
    EXPECT_EQ(CK_INVALID_HANDLE, obj);
}

TEST_F(derive, session_handle_is_checked_before_mechanism_and_arguments)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    std::vector<CK_BYTE> point;
    ASSERT_NO_FATAL_FAILURE(token_pair(0, &priv, &point));
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, ecdh(kInvalidSession, priv, point, &obj))
        << "an unknown session";
    EXPECT_CKR(
        CKR_SESSION_HANDLE_INVALID,
        p11()->C_DeriveKey(kInvalidSession, nullptr, priv, nullptr, 1, nullptr)
    ) << "before the arguments";
    EXPECT_EQ(CK_INVALID_HANDLE, obj);
}

TEST_F(derive, arguments_are_checked_before_mechanism)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    std::vector<CK_BYTE> point;
    ASSERT_NO_FATAL_FAILURE(token_pair(0, &priv, &point));
    EcdhMechanism m(point);
    CK_BBOOL token = CK_FALSE;
    std::vector<CK_ATTRIBUTE> tmpl = secret_template(&token);
    CK_ULONG n = static_cast<CK_ULONG>(tmpl.size());
    CK_OBJECT_HANDLE good = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(p11()->C_DeriveKey(s_, &m.mech, priv, tmpl.data(), n, &good))
        << "the call with every argument";
    CK_MECHANISM sha = { CKM_SHA256, nullptr, 0 };
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_ULONG before = count_objects(s_);
    ASSERT_NE(0u, before);
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_DeriveKey(s_, nullptr, priv, tmpl.data(), n, &obj))
        << "no mechanism";
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_DeriveKey(s_, &sha, priv, tmpl.data(), n, nullptr))
        << "no handle to return, before the mechanism";
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_DeriveKey(s_, &sha, priv, nullptr, n, &obj))
        << "no template with a count, before the mechanism";
    EXPECT_CKR(CKR_MECHANISM_INVALID, p11()->C_DeriveKey(s_, &sha, priv, tmpl.data(), n, &obj))
        << "then the mechanism";
    EXPECT_EQ(CK_INVALID_HANDLE, obj);
    EXPECT_EQ(before, count_objects(s_));
}

/// The same session, logged out.
class derive_public : public PublicSession
{
};

TEST_F(derive_public, needs_a_login_and_a_malformed_request_is_reported_first)
{
    std::vector<CK_BYTE> point(1 + (2 * ec_curves()[0].coord), kEcUncompressed);
    EcdhMechanism m(point);
    CK_BBOOL token = CK_FALSE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    EXPECT_CKR(
        CKR_USER_NOT_LOGGED_IN,
        run_derive(s_, &m.mech, kInvalidObject, secret_template(&token), &obj)
    ) << "unmasking the base key needs the login's device session";
    m.params.kdf = CKD_SHA256_KDF;
    EXPECT_CKR(
        CKR_MECHANISM_PARAM_INVALID,
        run_derive(s_, &m.mech, kInvalidObject, secret_template(&token), &obj)
    ) << "a malformed parameter before the login state";
    EXPECT_EQ(CK_INVALID_HANDLE, obj);
}

// ---------------------------------------------------------------------------
// Refusals, each after its positive control
// ---------------------------------------------------------------------------

TEST_F(derive, mechanism_and_parameter_rules)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    std::vector<CK_BYTE> point;
    ASSERT_NO_FATAL_FAILURE(token_pair(1, &priv, &point));
    host::Pkey peer = host::ec_generate("P-384");
    host::Bytes good = host::ec_point(peer.get());
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(ecdh(s_, priv, good, &secret)) << "the positive control";
    CK_ULONG before = count_objects(s_);

    host::Bytes compressed(good.begin(), good.begin() + 1 + ec_curves()[1].coord);
    compressed[0] = static_cast<CK_BYTE>(kEcCompressed | (good.back() & 1));
    host::Bytes off_curve = good;
    off_curve.back() ^= 0x01;
    host::Bytes p256_point = host::ec_point(host::ec_generate("P-256").get());
    struct
    {
        const char *what;
        host::Bytes point;
    } points[] = {
        { "a compressed point (the module takes uncompressed ones)", compressed },
        { "a point not on the curve (the SDK's check)", off_curve },
        { "a P-256 point on a P-384 key", p256_point },
        { "a byte short", host::Bytes(good.begin(), good.end() - 1) },
    };
    for (const auto &p : points)
    {
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, ecdh(s_, priv, p.point, &obj)) << p.what;
        EXPECT_EQ(CK_INVALID_HANDLE, obj) << p.what;
    }
    EcdhMechanism kdf(good);
    kdf.params.kdf = CKD_SHA256_KDF;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_BBOOL token = CK_FALSE;
    EXPECT_CKR(
        CKR_MECHANISM_PARAM_INVALID,
        derive_key(&kdf.mech, priv, secret_template(&token), &obj)
    ) << "only CKD_NULL: the SDK has no KDF here";

    CK_ULONG len = AES128_KEY_BYTES;
    HkdfMechanism ok(
        CKM_SHA256,
        host::Bytes(HKDF_MAX_SALT_LEN, 1),
        host::Bytes(HKDF_MAX_INFO_LEN, 2)
    );
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(derive_key(&ok.mech, secret, aes_template(&len, &g_no), &key))
        << "salt and info at their limits";
    ASSERT_CKR_OK(p11()->C_DestroyObject(s_, key));
    host::Bytes salt_over(HKDF_MAX_SALT_LEN + 1, 1);
    host::Bytes info_over(HKDF_MAX_INFO_LEN + 1, 2);
    HkdfMechanism sha1(CKM_SHA_1, kSalt, kInfo);
    HkdfMechanism long_salt(CKM_SHA256, salt_over, kInfo);
    HkdfMechanism long_info(CKM_SHA256, kSalt, info_over);
    HkdfMechanism salt_key(CKM_SHA256, kSalt, kInfo);
    salt_key.params.ulSaltType = CKF_HKDF_SALT_KEY;
    salt_key.params.hSaltKey = secret;
    HkdfMechanism expand_only(CKM_SHA256, kSalt, kInfo);
    expand_only.params.bExtract = CK_FALSE;
    struct
    {
        const char *what;
        CK_MECHANISM *mech;
    } hkdfs[] = {
        { "a SHA-1 PRF", &sha1.mech },
        { "a salt over HKDF_MAX_SALT_LEN", &long_salt.mech },
        { "info over HKDF_MAX_INFO_LEN", &long_info.mech },
        { "a salt from a key", &salt_key.mech },
        { "expand without extract", &expand_only.mech },
    };
    for (const auto &h : hkdfs)
    {
        key = CK_INVALID_HANDLE;
        EXPECT_CKR(
            CKR_MECHANISM_PARAM_INVALID,
            derive_key(h.mech, secret, aes_template(&len, &g_no), &key)
        ) << h.what;
        EXPECT_EQ(CK_INVALID_HANDLE, key) << h.what;
    }
    for (CK_MECHANISM_TYPE t : { CKM_ECDH1_COFACTOR_DERIVE, CKM_SP800_108_COUNTER_KDF })
    {
        CK_MECHANISM m = { t, nullptr, 0 };
        EXPECT_CKR(CKR_MECHANISM_INVALID, derive_key(&m, secret, aes_template(&len, &g_no), &key))
            << "mechanism 0x" << std::hex << t << " is not offered";
    }
    EXPECT_EQ(before, count_objects(s_)) << "no refusal leaves an object behind";
}

TEST_F(derive, template_rules)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    std::vector<CK_BYTE> point;
    ASSERT_NO_FATAL_FAILURE(token_pair(0, &priv, &point));
    host::Bytes peer = host::ec_point(host::ec_generate("P-256").get());
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(ecdh(s_, priv, peer, &secret)) << "the positive control";
    CK_ULONG before = count_objects(s_);
    EcdhMechanism e(peer);
    HkdfMechanism h(CKM_SHA256, kSalt, kInfo);
    CK_ULONG len16 = AES128_KEY_BYTES;
    CK_ULONG len32 = AES256_KEY_BYTES;
    CK_KEY_TYPE hmac = CKK_SHA256_HMAC;
    CK_MECHANISM_TYPE gcm = CKM_AES_GCM;
    CK_BYTE value[AES256_KEY_BYTES] = {};
    CK_ATTRIBUTE cls = { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) };
    CK_ATTRIBUTE gen = { CKA_KEY_TYPE, &g_generic, sizeof(g_generic) };
    CK_ATTRIBUTE aes = { CKA_KEY_TYPE, &g_aes, sizeof(g_aes) };
    struct Case
    {
        const char *what;
        CK_MECHANISM *mech;
        CK_OBJECT_HANDLE base;
        std::vector<CK_ATTRIBUTE> tmpl;
        CK_RV want;
    } cases[] = {
        { "ECDH: no key type", &e.mech, priv, { cls }, CKR_TEMPLATE_INCOMPLETE },
        { "ECDH: into an AES key", &e.mech, priv, { cls, aes }, CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: a truncated secret",
          &e.mech,
          priv,
          { cls, gen, { CKA_VALUE_LEN, &len16, sizeof(len16) } },
          CKR_ATTRIBUTE_VALUE_INVALID },
        { "ECDH: a secret that signs",
          &e.mech,
          priv,
          { cls, gen, { CKA_SIGN, &g_yes, sizeof(g_yes) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: a value",
          &e.mech,
          priv,
          { cls, gen, { CKA_VALUE, value, sizeof(value) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: not sensitive",
          &e.mech,
          priv,
          { cls, gen, { CKA_SENSITIVE, &g_no, sizeof(g_no) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: a public token secret",
          &e.mech,
          priv,
          { cls, gen, { CKA_TOKEN, &g_yes, sizeof(g_yes) }, { CKA_PRIVATE, &g_no, sizeof(g_no) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: into a generic secret", &h.mech, secret, { cls, gen }, CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: AES without CKA_VALUE_LEN",
          &h.mech,
          secret,
          { cls, aes },
          CKR_TEMPLATE_INCOMPLETE },
        { "HKDF: an AES-GCM key",
          &h.mech,
          secret,
          { cls,
            aes,
            { CKA_VALUE_LEN, &len32, sizeof(len32) },
            { CKA_ALLOWED_MECHANISMS, &gcm, sizeof(gcm) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: an HMAC key that encrypts",
          &h.mech,
          secret,
          { cls, { CKA_KEY_TYPE, &hmac, sizeof(hmac) }, { CKA_ENCRYPT, &g_yes, sizeof(g_yes) } },
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: an HMAC key of another length",
          &h.mech,
          secret,
          { cls, { CKA_KEY_TYPE, &hmac, sizeof(hmac) }, { CKA_VALUE_LEN, &len16, sizeof(len16) } },
          CKR_ATTRIBUTE_VALUE_INVALID },
    };
    for (const Case &c : cases)
    {
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        EXPECT_CKR(c.want, derive_key(c.mech, c.base, c.tmpl, &obj)) << c.what;
        EXPECT_EQ(CK_INVALID_HANDLE, obj) << c.what;
    }
    EXPECT_EQ(before, count_objects(s_)) << "no refusal leaves an object behind";

    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_RV rv_session = run_derive(ro, &h.mech, secret, aes_template(&len16, &g_no), &obj);
    CK_OBJECT_HANDLE tok = CK_INVALID_HANDLE;
    CK_RV rv_token = run_derive(ro, &h.mech, secret, aes_template(&len16, &g_yes), &tok);
    ASSERT_CKR_OK(p11()->C_CloseSession(ro));
    EXPECT_CKR_OK(rv_session) << "a session key from a read-only session";
    EXPECT_CKR(CKR_SESSION_READ_ONLY, rv_token) << "a token key needs a read/write session";
    EXPECT_EQ(CK_INVALID_HANDLE, tok);
}

TEST_F(derive, base_key_rules)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_ec_pair(s_, ec_curves()[0], false, CK_FALSE, CK_TRUE, "derive", &pub, &priv));
    std::vector<CK_BYTE> point = ec_point(s_, pub);
    ASSERT_FALSE(point.empty());
    host::Bytes peer = host::ec_point(host::ec_generate("P-256").get());
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(ecdh(s_, priv, peer, &secret)) << "the positive control";

    CK_OBJECT_HANDLE sign_pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE sign_priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_p256(s_, &sign_pub, &sign_priv));
    CK_OBJECT_HANDLE aes = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_aes_key(s_, AES128_KEY_BYTES, CK_TRUE, CK_TRUE, "aes", &aes));
    CK_OBJECT_HANDLE hmac = CK_INVALID_HANDLE;
    CK_KEY_TYPE hmac_type = CKK_SHA256_HMAC;
    HkdfMechanism h(CKM_SHA256, kSalt, kInfo);
    ASSERT_CKR_OK(derive_key(
        &h.mech,
        secret,
        { { CKA_CLASS, &g_secret_class, sizeof(g_secret_class) },
          { CKA_KEY_TYPE, &hmac_type, sizeof(hmac_type) } },
        &hmac
    ));
    /* A deriving pair whose private key names only ECDSA. */
    CK_MECHANISM keygen = { CKM_EC_KEY_PAIR_GEN, nullptr, 0 };
    CK_MECHANISM_TYPE ecdsa = CKM_ECDSA;
    std::vector<CK_BYTE> params = ec_curves()[0].params;
    CK_ATTRIBUTE pub_tmpl[] = { { CKA_EC_PARAMS, params.data(), params.size() } };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_DERIVE, &g_yes, sizeof(g_yes) },
        { CKA_ALLOWED_MECHANISMS, &ecdsa, sizeof(ecdsa) },
    };
    CK_OBJECT_HANDLE listed_pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE listed = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(
        p11()->C_GenerateKeyPair(s_, &keygen, pub_tmpl, 1, priv_tmpl, 2, &listed_pub, &listed)
    );
    CK_BYTE data_value[] = { 1, 2, 3 };
    CK_OBJECT_CLASS data_class = CKO_DATA;
    CK_ATTRIBUTE data_tmpl[] = {
        { CKA_CLASS, &data_class, sizeof(data_class) },
        { CKA_VALUE, data_value, sizeof(data_value) },
    };
    CK_OBJECT_HANDLE data = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(p11()->C_CreateObject(s_, data_tmpl, 2, &data));

    CK_ULONG before = count_objects(s_);
    CK_ULONG len = AES128_KEY_BYTES;
    EcdhMechanism e(peer);
    struct
    {
        const char *what;
        CK_MECHANISM *mech;
        CK_OBJECT_HANDLE base;
        CK_RV want;
    } cases[] = {
        { "ECDH from a signing key (CKA_DERIVE FALSE)",
          &e.mech,
          sign_priv,
          CKR_KEY_FUNCTION_NOT_PERMITTED },
        { "ECDH from the public key, which holds the pair's blob",
          &e.mech,
          pub,
          CKR_KEY_TYPE_INCONSISTENT },
        { "ECDH from a key whose list lacks it", &e.mech, listed, CKR_KEY_FUNCTION_NOT_PERMITTED },
        { "ECDH from an AES key", &e.mech, aes, CKR_KEY_TYPE_INCONSISTENT },
        { "ECDH from the secret", &e.mech, secret, CKR_KEY_TYPE_INCONSISTENT },
        { "HKDF from the EC private key", &h.mech, priv, CKR_KEY_TYPE_INCONSISTENT },
        { "HKDF from an HMAC key", &h.mech, hmac, CKR_KEY_TYPE_INCONSISTENT },
        { "HKDF from an AES key", &h.mech, aes, CKR_KEY_TYPE_INCONSISTENT },
        { "a data object", &h.mech, data, CKR_KEY_HANDLE_INVALID },
        { "no object", &h.mech, kInvalidObject, CKR_KEY_HANDLE_INVALID },
    };
    for (const auto &c : cases)
    {
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        EXPECT_CKR(c.want, derive_key(c.mech, c.base, aes_template(&len, &g_no), &obj)) << c.what;
        EXPECT_EQ(CK_INVALID_HANDLE, obj) << c.what;
    }
    EXPECT_EQ(before, count_objects(s_)) << "no refusal leaves an object behind";

    CK_ATTRIBUTE derive_off = { CKA_DERIVE, &g_no, sizeof(g_no) };
    EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, p11()->C_SetAttributeValue(s_, secret, &derive_off, 1))
        << "the secret's usage stays as derived";
}

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------

TEST_F(derive, derived_token_keys_survive_relogin)
{
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    host::Bytes z;
    ASSERT_NO_FATAL_FAILURE(p256_secret(&secret, &z, CK_TRUE, &pub, &priv));
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(aes_from(secret, AES256_KEY_BYTES, &key, CK_TRUE));
    SurvivingKey survivor(s_, key, CKM_AES_CBC);
    ASSERT_NO_FATAL_FAILURE(survivor.record());
    std::vector<CK_BYTE> before = cbc_on_token(s_, key);
    ASSERT_FALSE(before.empty());
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    ASSERT_CKR_OK(login_user(s_));
    ASSERT_NO_FATAL_FAILURE(survivor.check("a logout and login"));
    CK_OBJECT_HANDLE again = CK_INVALID_HANDLE;
    ASSERT_NO_FATAL_FAILURE(aes_from(secret, AES256_KEY_BYTES, &again));
    EXPECT_EQ(before, cbc_on_token(s_, again))
        << "the token secret still derives the same key after a relogin";
    for (CK_OBJECT_HANDLE h : { key, secret, pub, priv })
    {
        ASSERT_CKR_OK(p11()->C_DestroyObject(s_, h));
    }
}

TEST_F(derive, session_keys_die_with_their_session)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    std::vector<CK_BYTE> point;
    ASSERT_NO_FATAL_FAILURE(token_pair(0, &priv, &point));
    CK_SESSION_HANDLE other = 0;
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &other)
    );
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(ecdh(other, priv, host::ec_point(host::ec_generate("P-256").get()), &secret));
    CK_ULONG len = 0;
    ASSERT_CKR_OK(get_attr(s_, secret, CKA_VALUE_LEN, &len)) << "visible from the other session";
    ASSERT_CKR_OK(p11()->C_CloseSession(other));
    EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, get_attr(s_, secret, CKA_VALUE_LEN, &len))
        << "a session object dies with the session that derived it";
}

// ---------------------------------------------------------------------------
// Wycheproof
// ---------------------------------------------------------------------------

TEST_F(derive, wycheproof_points_the_token_must_refuse)
{
    ASSERT_FALSE(std::empty(vectors::kWycheproofEcdhPoints));
    std::vector<CK_OBJECT_HANDLE> privs(ec_curves().size(), CK_INVALID_HANDLE);
    std::vector<size_t> refused(ec_curves().size(), 0);
    std::vector<size_t> taken(ec_curves().size(), 0);
    for (const vectors::WycheproofEcPoint &v : vectors::kWycheproofEcdhPoints)
    {
        SCOPED_TRACE(std::string(v.curve) + " tcId " + std::to_string(v.tc_id));
        size_t c = 0;
        while ((c < ec_curves().size()) && (std::strcmp(ec_curves()[c].name, v.curve) != 0))
        {
            c++;
        }
        ASSERT_LT(c, ec_curves().size()) << "a curve the token has";
        if (privs[c] == CK_INVALID_HANDLE)
        {
            std::vector<CK_BYTE> point;
            ASSERT_NO_FATAL_FAILURE(token_pair(c, &privs[c], &point));
        }
        CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
        CK_RV rv = ecdh(s_, privs[c], vectors::hex(v.pub), &obj);
        if (v.valid)
        {
            EXPECT_CKR_OK(rv) << "a point on the curve is taken";
            taken[c] += (rv == CKR_OK) ? 1 : 0;
            (void)p11()->C_DestroyObject(s_, obj);
            continue;
        }
        EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID, rv) << "an invalid or compressed point is refused";
        EXPECT_EQ(CK_INVALID_HANDLE, obj);
        refused[c] += (rv == CKR_MECHANISM_PARAM_INVALID) ? 1 : 0;
    }
    for (size_t c = 0; c < ec_curves().size(); c++)
    {
        EXPECT_NE(0u, refused[c]) << ec_curves()[c].name << ": the set refuses something";
        EXPECT_NE(0u, taken[c]) << ec_curves()[c].name << ": its control is taken";
    }
}

// ---------------------------------------------------------------------------
// Device resources and the store
// ---------------------------------------------------------------------------

TEST_F(derive, leak_gate)
{
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    std::vector<CK_BYTE> point;
    ASSERT_NO_FATAL_FAILURE(token_pair(0, &priv, &point));
    host::Bytes peer = host::ec_point(host::ec_generate("P-256").get());
    host::Bytes off_curve = peer;
    off_curve.back() ^= 0x01;
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(ecdh(s_, priv, peer, &secret));
    CK_ULONG len = AES128_KEY_BYTES;
    std::vector<TerminationPath> paths = {
        { "ECDH, then destroy",
          [&]() {
              CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
              ASSERT_CKR_OK(ecdh(s_, priv, peer, &obj));
              ASSERT_CKR_OK(p11()->C_DestroyObject(s_, obj));
          } },
        { "ECDH refused by the device (a point off the curve)",
          [&]() {
              CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
              ASSERT_CKR(CKR_MECHANISM_PARAM_INVALID, ecdh(s_, priv, off_curve, &obj));
          } },
        { "HKDF, then destroy",
          [&]() {
              HkdfMechanism h(CKM_SHA384, kSalt, kInfo);
              CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
              ASSERT_CKR_OK(derive_key(&h.mech, secret, aes_template(&len, &g_no), &obj));
              ASSERT_CKR_OK(p11()->C_DestroyObject(s_, obj));
          } },
        { "HKDF refused after the base key read",
          [&]() {
              HkdfMechanism h(CKM_SHA384, kSalt, kInfo);
              CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
              ASSERT_CKR(
                  CKR_TEMPLATE_INCONSISTENT,
                  derive_key(&h.mech, secret, secret_template(&g_no), &obj)
              );
          } },
    };
    /* A fresh pair each time: the gate's logout ends the private session keys. */
    ASSERT_NO_FATAL_FAILURE(leak_gate(s_, paths, [&]() {
        CK_OBJECT_HANDLE p = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE k = CK_INVALID_HANDLE;
        CK_RV rv = gen_ec_pair(s_, ec_curves()[0], false, CK_FALSE, CK_TRUE, "fresh", &p, &k);
        CK_OBJECT_HANDLE fresh_secret = CK_INVALID_HANDLE;
        if (rv == CKR_OK)
        {
            rv = ecdh(s_, k, peer, &fresh_secret);
        }
        HkdfMechanism h(CKM_SHA256, kSalt, kInfo);
        CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
        return (rv == CKR_OK) ? derive_key(&h.mech, fresh_secret, aes_template(&len, &g_no), &key)
                              : rv;
    }));
}

/// The file store holds derived keys only masked.
class derive_persist : public StoreDirFixture
{
};

TEST_F(derive_persist, the_store_never_sees_a_derived_value)
{
    CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(gen_ec_pair(s_, ec_curves()[0], false, CK_TRUE, CK_TRUE, "derive", &pub, &priv));
    std::vector<CK_BYTE> point = ec_point(s_, pub);
    ASSERT_FALSE(point.empty());
    host::Pkey peer = host::ec_generate("P-256");
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(ecdh(s_, priv, host::ec_point(peer.get()), &secret, CK_TRUE));
    CK_ULONG len = AES256_KEY_BYTES;
    CK_BBOOL token = CK_TRUE;
    HkdfMechanism h(CKM_SHA256, kSalt, kInfo);
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    ASSERT_CKR_OK(run_derive(s_, &h.mech, secret, aes_template(&len, &token), &key));
    EXPECT_TRUE(store_contains(point)) << "the public point is stored as it is";
    host::Bytes z = host::ecdh(peer.get(), point);
    host::Bytes ikm = device_ikm(z);
    host::Bytes k = host::hkdf("SHA256", ikm, kSalt, kInfo, len);
    ASSERT_EQ(cbc_on_host(k), cbc_on_token(s_, key))
        << "k is the key, so its absence means something";
    EXPECT_FALSE(store_contains(z)) << "the shared secret";
    EXPECT_FALSE(store_contains(ikm)) << "the shared secret in the device's byte order";
    EXPECT_FALSE(store_contains(host::Bytes(z.begin(), z.begin() + (z.size() / 2))))
        << "half of it";
    EXPECT_FALSE(store_contains(k)) << "the derived AES key";
}
