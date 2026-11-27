// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the CKM_ECDH1_DERIVE and CKM_HKDF_DERIVE logic
 * (src/tsra_pkcs11_derive_params.c), the DER SubjectPublicKeyInfo it builds
 * (tsra_pkcs11_ec_spki_from_point) and the derived-key template builder
 * (tsra_pkcs11_derive_build_template). No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src derive_params_test.c \
 *       ../src/tsra_pkcs11_derive_params.c ../src/tsra_pkcs11_ec_template.c \
 *       ../src/tsra_pkcs11_template.c ../src/tsra_pkcs11_attr_types.c \
 *       -o derive_params_test && ./derive_params_test
 *
 * Covers the CK_ECDH1_DERIVE_PARAMS and CK_HKDF_PARAMS decoders (every
 * refusal with its positive control, salt and info at and over their limit,
 * misaligned blocks), the ECDH peer point in raw and DER form on every curve
 * against OpenSSL's encoding of its SubjectPublicKeyInfo, with compressed,
 * hybrid, short, long and non-minimal DER forms refused, the base key policy
 * against a fake object, every verdict of the derived-key template for the
 * generic secret, AES and HMAC targets, and the attributes a derived key is
 * stored with.
 */

#include "tsra_pkcs11_derive_params.h"
#include "tsra_pkcs11_digest.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int g_fail = 0;
static int g_checks = 0;

#define CHECK(cond, msg)                                                                           \
    do                                                                                             \
    {                                                                                              \
        g_checks++;                                                                                \
        if (cond)                                                                                  \
        {                                                                                          \
            printf("  ok   : %s\n", (msg));                                                        \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            printf("  FAIL : %s\n", (msg));                                                        \
            g_fail = 1;                                                                            \
        }                                                                                          \
    } while (0)

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define ATTR(t, v)                                                                                 \
    {                                                                                              \
        (t), (void *)&(v), sizeof(v)                                                               \
    }

static CK_BBOOL g_true = CK_TRUE;
static CK_BBOOL g_false = CK_FALSE;
static CK_OBJECT_CLASS g_secret = CKO_SECRET_KEY;
static CK_OBJECT_CLASS g_private = CKO_PRIVATE_KEY;
static CK_OBJECT_CLASS g_public = CKO_PUBLIC_KEY;
static CK_KEY_TYPE g_generic = CKK_GENERIC_SECRET;
static CK_KEY_TYPE g_aes = CKK_AES;
static CK_KEY_TYPE g_xts = CKK_AES_XTS;
static CK_KEY_TYPE g_ec = CKK_EC;
static CK_KEY_TYPE g_hmac256 = CKK_SHA256_HMAC;
static CK_KEY_TYPE g_hmac384 = CKK_SHA384_HMAC;
static CK_KEY_TYPE g_hmac512 = CKK_SHA512_HMAC;

/* The curve OIDs (CKA_EC_PARAMS), and secp256k1, which the device lacks. */
static CK_BYTE g_p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static CK_BYTE g_p384[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static CK_BYTE g_k256[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a };

/* What precedes the point in OpenSSL's DER SubjectPublicKeyInfo of a key on
 * each curve (i2d_PUBKEY of the NIST CAVP ECDH peers): the SEQUENCE, the
 * algorithm with its curve OID, and the BIT STRING header with its unused-bits
 * byte. */
static const CK_BYTE SPKI_P256[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
                                     0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                                     0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 };
static const CK_BYTE SPKI_P384[] = { 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
                                     0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
                                     0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00 };
static const CK_BYTE SPKI_P521[] = { 0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86,
                                     0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81,
                                     0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00 };

static const struct
{
    const char *name;
    tsra_pkcs11_ec_curve_t curve;
    const CK_BYTE *prefix;
    CK_ULONG prefix_len;
    CK_ULONG coord;
    CK_ULONG bits;
} CURVES[] = {
    { "P-256", TSRA_PKCS11_CURVE_P256, SPKI_P256, sizeof(SPKI_P256), 32, EC_P256_BITS },
    { "P-384", TSRA_PKCS11_CURVE_P384, SPKI_P384, sizeof(SPKI_P384), 48, EC_P384_BITS },
    { "P-521", TSRA_PKCS11_CURVE_P521, SPKI_P521, sizeof(SPKI_P521), 66, EC_P521_BITS },
};

/* SEC 1 point forms and the DER OCTET STRING around CKA_EC_POINT. */
#define PT_UNCOMPRESSED 0x04
#define PT_COMPRESSED_EVEN 0x02
#define PT_HYBRID 0x06
#define DER_OCTET 0x04
#define DER_BIT_STRING 0x03
#define DER_SHORT_MAX 0x7f
#define DER_LONG_FORM_ANY 0x80
#define DER_LONG1 0x81
#define DER_LONG2 0x82
/* A salt and an info length well within their limits. */
#define SOME_SALT_LEN 16
#define SOME_INFO_LEN 10
/* Room for any point with a DER header, and some. */
#define BUF_MAX 256

/* An uncompressed point on curve row `c`: 0x04, then filler. The decoder does
 * not check that it lies on the curve; the SDK does. */
static CK_ULONG make_point(size_t c, CK_BYTE *out)
{
    CK_ULONG n = 1 + (2 * CURVES[c].coord);
    out[0] = PT_UNCOMPRESSED;
    for (CK_ULONG i = 1; i < n; i++)
    {
        out[i] = (CK_BYTE)(i * 3);
    }
    return n;
}

/* ========================================================================= */
/* Mechanism parameters                                                      */
/* ========================================================================= */

static CK_RV ecdh(CK_ECDH1_DERIVE_PARAMS p, tsra_pkcs11_derive_params *out)
{
    CK_MECHANISM m = { CKM_ECDH1_DERIVE, &p, sizeof(p) };
    return tsra_pkcs11_derive_params_check(&m, out);
}

static void test_ecdh_params(void)
{
    printf("== derive_params_check: CKM_ECDH1_DERIVE ==\n");
    CK_BYTE point[BUF_MAX];
    CK_ULONG plen = make_point(0, point);
    CK_BYTE shared[1] = { 0 };
    tsra_pkcs11_derive_params out;
    CK_ECDH1_DERIVE_PARAMS good = { CKD_NULL, 0, NULL, plen, point };
    CHECK(
        (ecdh(good, &out) == CKR_OK) && (out.mech == CKM_ECDH1_DERIVE) &&
            (out.base_key_type == CKK_EC) && (out.public_data == point) && (out.public_len == plen),
        "CKD_NULL with a public point -> OK, the point passed on"
    );
    CK_MECHANISM m = { CKM_ECDH1_DERIVE, &good, sizeof(good) };
    CHECK(tsra_pkcs11_derive_params_check(NULL, &out) == CKR_ARGUMENTS_BAD, "NULL mechanism");
    CHECK(tsra_pkcs11_derive_params_check(&m, NULL) == CKR_ARGUMENTS_BAD, "NULL output");
    CK_MECHANISM other = { CKM_ECDH1_COFACTOR_DERIVE, &good, sizeof(good) };
    CHECK(
        tsra_pkcs11_derive_params_check(&other, &out) == CKR_MECHANISM_INVALID,
        "CKM_ECDH1_COFACTOR_DERIVE -> MECHANISM_INVALID"
    );
    CK_MECHANISM kbkdf = { CKM_SP800_108_COUNTER_KDF, NULL, 0 };
    CHECK(
        tsra_pkcs11_derive_params_check(&kbkdf, &out) == CKR_MECHANISM_INVALID,
        "CKM_SP800_108_COUNTER_KDF is not offered -> MECHANISM_INVALID"
    );
    CK_MECHANISM empty = { CKM_ECDH1_DERIVE, NULL, 0 };
    CHECK(
        (tsra_pkcs11_derive_params_check(&empty, &out) == CKR_MECHANISM_PARAM_INVALID) &&
            (out.mech == CKM_ECDH1_DERIVE) && (out.base_key_type == CKK_EC),
        "no parameter -> MECHANISM_PARAM_INVALID, the mechanism still named"
    );
    CK_MECHANISM short_block = { CKM_ECDH1_DERIVE, &good, sizeof(good) - 1 };
    CHECK(
        tsra_pkcs11_derive_params_check(&short_block, &out) == CKR_MECHANISM_PARAM_INVALID,
        "a short parameter block -> MECHANISM_PARAM_INVALID"
    );
    CK_ECDH1_DERIVE_PARAMS p = good;
    p.kdf = CKD_SHA256_KDF;
    CHECK(ecdh(p, &out) == CKR_MECHANISM_PARAM_INVALID, "a KDF other than CKD_NULL -> refused");
    p = good;
    p.ulSharedDataLen = 1;
    p.pSharedData = shared;
    CHECK(ecdh(p, &out) == CKR_MECHANISM_PARAM_INVALID, "shared data -> refused");
    p.ulSharedDataLen = 0;
    CHECK(ecdh(p, &out) == CKR_MECHANISM_PARAM_INVALID, "a shared data pointer -> refused");
    p = good;
    p.pPublicData = NULL;
    CHECK(ecdh(p, &out) == CKR_MECHANISM_PARAM_INVALID, "no public data -> refused");
    p = good;
    p.ulPublicDataLen = 0;
    CHECK(ecdh(p, &out) == CKR_MECHANISM_PARAM_INVALID, "empty public data -> refused");

    CK_BYTE raw[sizeof(good) + 1];
    memcpy(raw + 1, &good, sizeof(good));
    CK_MECHANISM odd = { CKM_ECDH1_DERIVE, raw + 1, sizeof(good) };
    CHECK(
        (tsra_pkcs11_derive_params_check(&odd, &out) == CKR_OK) && (out.public_len == plen),
        "a misaligned parameter block is read"
    );
}

static CK_HKDF_PARAMS hkdf_good(CK_BYTE *salt, CK_ULONG salt_len, CK_BYTE *info, CK_ULONG info_len)
{
    CK_HKDF_PARAMS p = { CK_TRUE,           CK_TRUE, CKM_SHA256, CKF_HKDF_SALT_DATA, salt, salt_len,
                         CK_INVALID_HANDLE, info,    info_len };
    return p;
}

static CK_RV hkdf(CK_HKDF_PARAMS p, tsra_pkcs11_derive_params *out)
{
    CK_MECHANISM m = { CKM_HKDF_DERIVE, &p, sizeof(p) };
    return tsra_pkcs11_derive_params_check(&m, out);
}

static void test_hkdf_params(void)
{
    printf("== derive_params_check: CKM_HKDF_DERIVE ==\n");
    static CK_BYTE salt[HKDF_MAX_SALT_LEN + 1];
    static CK_BYTE info[HKDF_MAX_INFO_LEN + 1];
    tsra_pkcs11_derive_params out;
    CHECK(
        (hkdf(hkdf_good(salt, SOME_SALT_LEN, info, SOME_INFO_LEN), &out) == CKR_OK) &&
            (out.mech == CKM_HKDF_DERIVE) && (out.base_key_type == CKK_GENERIC_SECRET) &&
            (out.prf == CKM_SHA256) && (out.salt == salt) && (out.salt_len == SOME_SALT_LEN) &&
            (out.info == info) && (out.info_len == SOME_INFO_LEN),
        "SHA-256, salt data and info -> OK, all passed on"
    );
    static const CK_MECHANISM_TYPE prfs[] = { CKM_SHA384, CKM_SHA512 };
    for (size_t i = 0; i < COUNT(prfs); i++)
    {
        CK_HKDF_PARAMS p = hkdf_good(salt, 1, info, 1);
        p.prfHashMechanism = prfs[i];
        CHECK((hkdf(p, &out) == CKR_OK) && (out.prf == prfs[i]), "SHA-384 and SHA-512 -> OK");
    }
    static const CK_MECHANISM_TYPE bad_prfs[] = { CKM_SHA_1, CKM_SHA224, CKM_SHA3_256, CKM_MD5 };
    for (size_t i = 0; i < COUNT(bad_prfs); i++)
    {
        CK_HKDF_PARAMS p = hkdf_good(salt, 1, info, 1);
        p.prfHashMechanism = bad_prfs[i];
        CHECK(
            hkdf(p, &out) == CKR_MECHANISM_PARAM_INVALID,
            "SHA-1, SHA-224, SHA3-256 and MD5 as the PRF -> refused"
        );
    }
    CK_HKDF_PARAMS p = hkdf_good(salt, 1, info, 1);
    p.bExtract = CK_FALSE;
    CHECK(hkdf(p, &out) == CKR_MECHANISM_PARAM_INVALID, "expand only -> refused");
    p = hkdf_good(salt, 1, info, 1);
    p.bExpand = CK_FALSE;
    CHECK(hkdf(p, &out) == CKR_MECHANISM_PARAM_INVALID, "extract only -> refused");

    p = hkdf_good(NULL, 0, NULL, 0);
    p.ulSaltType = CKF_HKDF_SALT_NULL;
    CHECK(
        (hkdf(p, &out) == CKR_OK) && (out.salt == NULL) && (out.info == NULL),
        "CKF_HKDF_SALT_NULL and no info -> OK, neither passed"
    );
    p.pSalt = salt; /* ignored without a length */
    CHECK(hkdf(p, &out) == CKR_OK, "CKF_HKDF_SALT_NULL ignores the salt pointer");
    p.ulSaltLen = 1;
    CHECK(hkdf(p, &out) == CKR_MECHANISM_PARAM_INVALID, "CKF_HKDF_SALT_NULL with a length");
    p = hkdf_good(salt, 1, info, 1);
    p.ulSaltType = CKF_HKDF_SALT_KEY;
    CHECK(hkdf(p, &out) == CKR_MECHANISM_PARAM_INVALID, "CKF_HKDF_SALT_KEY -> refused");
    p.ulSaltType = 0;
    CHECK(hkdf(p, &out) == CKR_MECHANISM_PARAM_INVALID, "no salt type -> refused");
    p.ulSaltType = CKF_HKDF_SALT_NULL | CKF_HKDF_SALT_DATA;
    CHECK(hkdf(p, &out) == CKR_MECHANISM_PARAM_INVALID, "two salt types -> refused");

    CHECK(
        (hkdf(hkdf_good(salt, 0, info, 0), &out) == CKR_OK) && (out.salt == NULL) &&
            (out.info == NULL),
        "an empty salt and info are passed as none"
    );
    CHECK(
        hkdf(hkdf_good(NULL, 1, info, 1), &out) == CKR_MECHANISM_PARAM_INVALID,
        "a NULL salt with a length -> refused"
    );
    CHECK(
        hkdf(hkdf_good(salt, 1, NULL, 1), &out) == CKR_MECHANISM_PARAM_INVALID,
        "a NULL info with a length -> refused"
    );
    CHECK(
        hkdf(hkdf_good(salt, HKDF_MAX_SALT_LEN, info, HKDF_MAX_INFO_LEN), &out) == CKR_OK,
        "salt and info at HKDF_MAX_SALT_LEN / HKDF_MAX_INFO_LEN -> OK"
    );
    CHECK(
        hkdf(hkdf_good(salt, HKDF_MAX_SALT_LEN + 1, info, 1), &out) == CKR_MECHANISM_PARAM_INVALID,
        "a salt one byte over -> refused"
    );
    CHECK(
        hkdf(hkdf_good(salt, 1, info, HKDF_MAX_INFO_LEN + 1), &out) == CKR_MECHANISM_PARAM_INVALID,
        "info one byte over -> refused"
    );

    CK_MECHANISM empty = { CKM_HKDF_DERIVE, NULL, 0 };
    CHECK(
        (tsra_pkcs11_derive_params_check(&empty, &out) == CKR_MECHANISM_PARAM_INVALID) &&
            (out.base_key_type == CKK_GENERIC_SECRET),
        "no parameter -> refused, the base key type still named"
    );
    CK_HKDF_PARAMS g = hkdf_good(salt, 1, info, 1);
    CK_MECHANISM wrong = { CKM_HKDF_DERIVE, &g, sizeof(g) + 1 };
    CHECK(
        tsra_pkcs11_derive_params_check(&wrong, &out) == CKR_MECHANISM_PARAM_INVALID,
        "a long parameter block -> refused"
    );
    CK_BYTE raw[sizeof(g) + 1];
    memcpy(raw + 1, &g, sizeof(g));
    CK_MECHANISM odd = { CKM_HKDF_DERIVE, raw + 1, sizeof(g) };
    CHECK(
        (tsra_pkcs11_derive_params_check(&odd, &out) == CKR_OK) && (out.salt == salt),
        "a misaligned parameter block is read"
    );
}

/* ========================================================================= */
/* The ECDH peer                                                             */
/* ========================================================================= */

static void test_peer(void)
{
    printf("== ecdh_peer_spki and ec_spki_from_point ==\n");
    CK_BYTE spki[EC_SPKI_DER_MAX];
    CK_ULONG len = 0;
    for (size_t c = 0; c < COUNT(CURVES); c++)
    {
        char msg[128];
        CK_BYTE point[BUF_MAX];
        CK_ULONG plen = make_point(c, point);
        tsra_pkcs11_ec_curve_t curve = CURVES[c].curve;

        len = sizeof(spki);
        bool ok = (tsra_pkcs11_ecdh_peer_spki(curve, point, plen, spki, &len) == CKR_OK) &&
                  (len == (CURVES[c].prefix_len + plen)) &&
                  (memcmp(spki, CURVES[c].prefix, CURVES[c].prefix_len) == 0) &&
                  (memcmp(spki + CURVES[c].prefix_len, point, plen) == 0);
        snprintf(msg, sizeof(msg), "%s: a raw point -> OpenSSL's SPKI", CURVES[c].name);
        CHECK(ok, msg);

        CK_BYTE der[BUF_MAX];
        CK_ULONG h = 0;
        der[h++] = DER_OCTET;
        if (plen > DER_SHORT_MAX)
        {
            der[h++] = DER_LONG1;
        }
        der[h++] = (CK_BYTE)plen;
        memcpy(der + h, point, plen);
        CK_BYTE spki2[EC_SPKI_DER_MAX];
        CK_ULONG len2 = sizeof(spki2);
        ok = (tsra_pkcs11_ecdh_peer_spki(curve, der, h + plen, spki2, &len2) == CKR_OK) &&
             (len2 == len) && (memcmp(spki, spki2, len) == 0);
        snprintf(msg, sizeof(msg), "%s: the DER form (CKA_EC_POINT) -> the same", CURVES[c].name);
        CHECK(ok, msg);

        CK_ULONG small = len - 1;
        ok = (tsra_pkcs11_ecdh_peer_spki(curve, point, plen, spki2, &small) == CKR_BUFFER_TOO_SMALL
             ) &&
             (small == len);
        snprintf(msg, sizeof(msg), "%s: a short buffer -> its length", CURVES[c].name);
        CHECK(ok, msg);

        /* Every refusal: compressed and hybrid points, the infinity byte,
         * a byte short or long, the DER form with another tag, length or
         * a non-minimal length. */
        CK_BYTE bad[BUF_MAX + 4];
        bool all = true;
        memcpy(bad, point, plen);
        bad[0] = PT_COMPRESSED_EVEN;
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, bad, 1 + CURVES[c].coord, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, bad, plen, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        bad[0] = PT_HYBRID;
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, bad, plen, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        bad[0] = 0;
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, bad, 1, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, point, plen - 1, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        memcpy(bad, point, plen);
        bad[plen] = 0;
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, bad, plen + 1, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        memcpy(bad, der, h + plen);
        bad[0] = DER_BIT_STRING;
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, bad, h + plen, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        memcpy(bad, der, h + plen);
        bad[h - 1] = (CK_BYTE)(plen - 1);
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, bad, h + plen, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        /* One length byte more than DER's minimal form. */
        CK_ULONG k = 0;
        bad[k++] = DER_OCTET;
        if (plen > DER_SHORT_MAX)
        {
            bad[k++] = DER_LONG2;
            bad[k++] = 0;
        }
        else
        {
            bad[k++] = DER_LONG1;
        }
        bad[k++] = (CK_BYTE)plen;
        memcpy(bad + k, point, plen);
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, bad, k + plen, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        /* The DER form of a compressed point. */
        memcpy(bad, der, h + plen);
        bad[h] = PT_COMPRESSED_EVEN;
        all = all && (tsra_pkcs11_ecdh_peer_spki(curve, bad, h + plen, spki2, &len2) ==
                      CKR_MECHANISM_PARAM_INVALID);
        snprintf(
            msg,
            sizeof(msg),
            "%s: compressed, hybrid, infinity, short, long, wrong tag, wrong or non-minimal "
            "length -> MECHANISM_PARAM_INVALID",
            CURVES[c].name
        );
        CHECK(all, msg);

        snprintf(msg, sizeof(msg), "%s: %lu bits", CURVES[c].name, (unsigned long)CURVES[c].bits);
        CHECK(tsra_pkcs11_ec_curve_bits(curve) == CURVES[c].bits, msg);
    }
    /* The P-521 point is 133 bytes: a length byte of 0x85 alone would be the
     * long-form marker, so DER needs 0x81 0x85. */
    CK_BYTE point[BUF_MAX];
    CK_ULONG plen = make_point(2, point);
    CK_BYTE der[BUF_MAX];
    der[0] = DER_OCTET;
    der[1] = (CK_BYTE)plen;
    memcpy(der + 2, point, plen);
    len = sizeof(spki);
    CHECK(
        tsra_pkcs11_ecdh_peer_spki(TSRA_PKCS11_CURVE_P521, der, 2 + plen, spki, &len) ==
            CKR_MECHANISM_PARAM_INVALID,
        "P-521: a short-form length of 133 -> refused"
    );
    /* Three header bytes as the P-521 point needs, but not 0x81 0x85. */
    static const CK_BYTE markers[] = { DER_LONG_FORM_ANY, DER_LONG2, 0 };
    bool all = true;
    for (size_t i = 0; i < COUNT(markers); i++)
    {
        der[1] = markers[i];
        der[2] = (CK_BYTE)plen;
        memcpy(der + 3, point, plen);
        len = sizeof(spki);
        all =
            all && (tsra_pkcs11_ecdh_peer_spki(TSRA_PKCS11_CURVE_P521, der, 3 + plen, spki, &len) ==
                    CKR_MECHANISM_PARAM_INVALID);
    }
    CHECK(all, "P-521: a second header byte of 0x80, 0x82 or 0 -> refused");
    CK_BYTE p256[BUF_MAX];
    CK_ULONG p256_len = make_point(0, p256);
    CHECK(
        tsra_pkcs11_ecdh_peer_spki(TSRA_PKCS11_CURVE_P384, p256, p256_len, spki, &len) ==
            CKR_MECHANISM_PARAM_INVALID,
        "a P-256 point on a P-384 base key -> refused"
    );
    CHECK(
        tsra_pkcs11_ecdh_peer_spki(TSRA_PKCS11_CURVE_P256, NULL, p256_len, spki, &len) ==
            CKR_MECHANISM_PARAM_INVALID,
        "no data -> MECHANISM_PARAM_INVALID"
    );
    CHECK(
        (tsra_pkcs11_ecdh_peer_spki(TSRA_PKCS11_CURVE_NONE, p256, p256_len, spki, &len) ==
         CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ecdh_peer_spki(TSRA_PKCS11_CURVE_P256, p256, p256_len, NULL, &len) ==
             CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ecdh_peer_spki(TSRA_PKCS11_CURVE_P256, p256, p256_len, spki, NULL) ==
             CKR_ARGUMENTS_BAD),
        "no curve or no output -> ARGUMENTS_BAD"
    );
    len = sizeof(spki);
    CHECK(
        (tsra_pkcs11_ec_spki_from_point(TSRA_PKCS11_CURVE_P256, NULL, p256_len, spki, &len) ==
         CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_spki_from_point(
                 TSRA_PKCS11_CURVE_P256,
                 p256,
                 p256_len - 1,
                 spki,
                 &len
             ) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_spki_from_point(TSRA_PKCS11_CURVE_NONE, p256, p256_len, spki, &len) ==
             CKR_ARGUMENTS_BAD),
        "ec_spki_from_point: no point, a wrong length or no curve -> ARGUMENTS_BAD"
    );
    CHECK(tsra_pkcs11_ec_curve_bits(TSRA_PKCS11_CURVE_NONE) == 0, "no curve: 0 bits");
    CHECK(
        (EC_SPKI_DER_MAX >=
         (sizeof(SPKI_P521) + 1 + (2 * tsra_pkcs11_ec_coord_len(TSRA_PKCS11_CURVE_P521)))) &&
            (EC_SPKI_DER_MAX <= ECDH_PEER_DER_MAX),
        "EC_SPKI_DER_MAX holds the P-521 key and fits the device command"
    );
    CHECK(
        (ECDH_SECRET_MIN_BYTES == tsra_pkcs11_ec_coord_len(TSRA_PKCS11_CURVE_P256)) &&
            (ECDH_SECRET_MAX_BYTES == tsra_pkcs11_ec_coord_len(TSRA_PKCS11_CURVE_P521)),
        "the ECDH secret lengths are the P-256 and P-521 coordinate lengths"
    );
}

/* ========================================================================= */
/* The base key                                                              */
/* ========================================================================= */

/* The base key: a fixed attribute set, or a forced read result. */
typedef struct
{
    const CK_ATTRIBUTE *attrs;
    CK_ULONG count;
    CK_RV fail; /* returned by every read when non-zero */
} fake_obj;

static CK_RV fake_read(void *ctx, CK_ATTRIBUTE *a)
{
    const fake_obj *o = (const fake_obj *)ctx;
    if (o->fail != CKR_OK)
    {
        return o->fail;
    }
    for (CK_ULONG i = 0; i < o->count; i++)
    {
        const CK_ATTRIBUTE *s = &o->attrs[i];
        if (s->type != a->type)
        {
            continue;
        }
        if (a->pValue == NULL)
        {
            a->ulValueLen = s->ulValueLen;
            return CKR_OK;
        }
        if (a->ulValueLen < s->ulValueLen)
        {
            a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
            return CKR_BUFFER_TOO_SMALL;
        }
        memcpy(a->pValue, s->pValue, s->ulValueLen);
        a->ulValueLen = s->ulValueLen;
        return CKR_OK;
    }
    a->ulValueLen = CK_UNAVAILABLE_INFORMATION;
    return CKR_ATTRIBUTE_TYPE_INVALID;
}

static CK_RV base_on(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *attrs,
    CK_ULONG n,
    tsra_pkcs11_derive_base *out
)
{
    fake_obj o = { attrs, n, CKR_OK };
    return tsra_pkcs11_derive_base_check(mech, fake_read, &o, out);
}

static void test_base(void)
{
    printf("== derive_base_check ==\n");
    static CK_MECHANISM_TYPE ecdh_only[] = { CKM_ECDH1_DERIVE };
    static CK_MECHANISM_TYPE ecdsa_only[] = { CKM_ECDSA_SHA256 };
    static CK_MECHANISM_TYPE hkdf_only[] = { CKM_HKDF_DERIVE };
    static CK_MECHANISM_TYPE too_many[KEYGEN_MAX_ALLOWED_MECHS + 1];
    for (size_t i = 0; i < COUNT(too_many); i++)
    {
        too_many[i] = CKM_ECDH1_DERIVE;
    }
    static CK_BYTE long_params[EC_PARAMS_DER_MAX + 1];
    static CK_BYTE wide_bool[2] = { 1, 1 };
    tsra_pkcs11_derive_base b;
    const CK_ATTRIBUTE ec[] = {
        ATTR(CKA_KEY_TYPE, g_ec),           ATTR(CKA_CLASS, g_private),
        ATTR(CKA_DERIVE, g_true),           ATTR(CKA_EC_PARAMS, g_p384),
        ATTR(CKA_ALWAYS_SENSITIVE, g_true), ATTR(CKA_NEVER_EXTRACTABLE, g_true),
    };
    CHECK(
        (base_on(CKM_ECDH1_DERIVE, ec, COUNT(ec), &b) == CKR_OK) &&
            (b.curve == TSRA_PKCS11_CURVE_P384) && (b.always_sensitive == CK_TRUE) &&
            (b.never_extractable == CK_TRUE),
        "ECDH: an EC private key with CKA_DERIVE -> OK, its curve and protection"
    );
    CHECK(
        (base_on(CKM_ECDH1_DERIVE, ec, 4, &b) == CKR_OK) && (b.always_sensitive == CK_FALSE) &&
            (b.never_extractable == CK_FALSE),
        "ECDH: no CKA_ALWAYS_SENSITIVE / CKA_NEVER_EXTRACTABLE reads as FALSE"
    );
    const CK_ATTRIBUTE ec_list[] = {
        ATTR(CKA_KEY_TYPE, g_ec),
        ATTR(CKA_CLASS, g_private),
        ATTR(CKA_DERIVE, g_true),
        ATTR(CKA_EC_PARAMS, g_p256),
        ATTR(CKA_ALLOWED_MECHANISMS, ecdh_only),
    };
    CHECK(
        (base_on(CKM_ECDH1_DERIVE, ec_list, COUNT(ec_list), &b) == CKR_OK) &&
            (b.curve == TSRA_PKCS11_CURVE_P256),
        "ECDH: CKA_ALLOWED_MECHANISMS naming it -> OK"
    );
    struct
    {
        const char *what;
        CK_ATTRIBUTE_TYPE type;
        CK_ATTRIBUTE value; /* replaces the attribute of that type; type 0: removed */
        CK_RV want;
    } rows[] = {
        { "an AES key -> KEY_TYPE_INCONSISTENT",
          CKA_KEY_TYPE,
          ATTR(CKA_KEY_TYPE, g_aes),
          CKR_KEY_TYPE_INCONSISTENT },
        { "no key type -> KEY_TYPE_INCONSISTENT",
          CKA_KEY_TYPE,
          { 0, NULL, 0 },
          CKR_KEY_TYPE_INCONSISTENT },
        { "a one-byte key type -> KEY_TYPE_INCONSISTENT",
          CKA_KEY_TYPE,
          ATTR(CKA_KEY_TYPE, g_true),
          CKR_KEY_TYPE_INCONSISTENT },
        { "the EC public key -> KEY_TYPE_INCONSISTENT",
          CKA_CLASS,
          ATTR(CKA_CLASS, g_public),
          CKR_KEY_TYPE_INCONSISTENT },
        { "no class -> KEY_TYPE_INCONSISTENT",
          CKA_CLASS,
          { 0, NULL, 0 },
          CKR_KEY_TYPE_INCONSISTENT },
        { "CKA_DERIVE FALSE -> KEY_FUNCTION_NOT_PERMITTED",
          CKA_DERIVE,
          ATTR(CKA_DERIVE, g_false),
          CKR_KEY_FUNCTION_NOT_PERMITTED },
        { "no CKA_DERIVE -> KEY_FUNCTION_NOT_PERMITTED",
          CKA_DERIVE,
          { 0, NULL, 0 },
          CKR_KEY_FUNCTION_NOT_PERMITTED },
        { "a two-byte CKA_DERIVE -> KEY_FUNCTION_NOT_PERMITTED",
          CKA_DERIVE,
          ATTR(CKA_DERIVE, wide_bool),
          CKR_KEY_FUNCTION_NOT_PERMITTED },
        { "CKA_ALLOWED_MECHANISMS without it -> KEY_FUNCTION_NOT_PERMITTED",
          CKA_ALLOWED_MECHANISMS,
          ATTR(CKA_ALLOWED_MECHANISMS, ecdsa_only),
          CKR_KEY_FUNCTION_NOT_PERMITTED },
        { "a list longer than any stored -> KEY_FUNCTION_NOT_PERMITTED",
          CKA_ALLOWED_MECHANISMS,
          ATTR(CKA_ALLOWED_MECHANISMS, too_many),
          CKR_KEY_FUNCTION_NOT_PERMITTED },
        { "no CKA_EC_PARAMS -> KEY_TYPE_INCONSISTENT",
          CKA_EC_PARAMS,
          { 0, NULL, 0 },
          CKR_KEY_TYPE_INCONSISTENT },
        { "secp256k1 -> KEY_TYPE_INCONSISTENT",
          CKA_EC_PARAMS,
          ATTR(CKA_EC_PARAMS, g_k256),
          CKR_KEY_TYPE_INCONSISTENT },
        { "an over-long CKA_EC_PARAMS -> KEY_TYPE_INCONSISTENT",
          CKA_EC_PARAMS,
          ATTR(CKA_EC_PARAMS, long_params),
          CKR_KEY_TYPE_INCONSISTENT },
    };
    for (size_t r = 0; r < COUNT(rows); r++)
    {
        CK_ATTRIBUTE attrs[COUNT(ec_list)];
        CK_ULONG n = 0;
        for (size_t i = 0; i < COUNT(ec_list); i++)
        {
            if (ec_list[i].type != rows[r].type)
            {
                attrs[n++] = ec_list[i];
            }
            else if (rows[r].value.pValue != NULL)
            {
                attrs[n++] = rows[r].value;
            }
        }
        char msg[128];
        snprintf(msg, sizeof(msg), "ECDH: %s", rows[r].what);
        CHECK(base_on(CKM_ECDH1_DERIVE, attrs, n, &b) == rows[r].want, msg);
    }

    const CK_ATTRIBUTE secret[] = {
        ATTR(CKA_KEY_TYPE, g_generic),      ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_DERIVE, g_true),           ATTR(CKA_ALLOWED_MECHANISMS, hkdf_only),
        ATTR(CKA_ALWAYS_SENSITIVE, g_true),
    };
    CHECK(
        (base_on(CKM_HKDF_DERIVE, secret, COUNT(secret), &b) == CKR_OK) &&
            (b.curve == TSRA_PKCS11_CURVE_NONE) && (b.always_sensitive == CK_TRUE) &&
            (b.never_extractable == CK_FALSE),
        "HKDF: the ECDH secret -> OK, no curve read"
    );
    CHECK(
        base_on(CKM_ECDH1_DERIVE, secret, COUNT(secret), &b) == CKR_KEY_TYPE_INCONSISTENT,
        "ECDH: the secret as base key -> KEY_TYPE_INCONSISTENT"
    );
    CHECK(
        base_on(CKM_HKDF_DERIVE, ec, COUNT(ec), &b) == CKR_KEY_TYPE_INCONSISTENT,
        "HKDF: an EC key as base key -> KEY_TYPE_INCONSISTENT"
    );
    const CK_ATTRIBUTE secret_ecdh[] = {
        ATTR(CKA_KEY_TYPE, g_generic),
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_DERIVE, g_true),
        ATTR(CKA_ALLOWED_MECHANISMS, ecdh_only),
    };
    CHECK(
        base_on(CKM_HKDF_DERIVE, secret_ecdh, COUNT(secret_ecdh), &b) ==
            CKR_KEY_FUNCTION_NOT_PERMITTED,
        "HKDF: a list without CKM_HKDF_DERIVE -> KEY_FUNCTION_NOT_PERMITTED"
    );
    const CK_ATTRIBUTE secret_private[] = {
        ATTR(CKA_KEY_TYPE, g_generic),
        ATTR(CKA_CLASS, g_private),
        ATTR(CKA_DERIVE, g_true),
    };
    CHECK(
        base_on(CKM_HKDF_DERIVE, secret_private, COUNT(secret_private), &b) ==
            CKR_KEY_TYPE_INCONSISTENT,
        "HKDF: not a secret key -> KEY_TYPE_INCONSISTENT"
    );

    fake_obj gone = { NULL, 0, CKR_OBJECT_HANDLE_INVALID };
    fake_obj locked = { NULL, 0, CKR_USER_NOT_LOGGED_IN };
    fake_obj broken = { NULL, 0, CKR_FUNCTION_FAILED };
    CHECK(
        (tsra_pkcs11_derive_base_check(CKM_ECDH1_DERIVE, fake_read, &gone, &b) ==
         CKR_OBJECT_HANDLE_INVALID) &&
            (tsra_pkcs11_derive_base_check(CKM_HKDF_DERIVE, fake_read, &locked, &b) ==
             CKR_USER_NOT_LOGGED_IN) &&
            (tsra_pkcs11_derive_base_check(CKM_HKDF_DERIVE, fake_read, &broken, &b) ==
             CKR_FUNCTION_FAILED),
        "a store failure is passed through, not taken as a verdict"
    );
    fake_obj o = { ec, COUNT(ec), CKR_OK };
    CHECK(
        (tsra_pkcs11_derive_base_check(CKM_ECDH1_DERIVE, NULL, &o, &b) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_derive_base_check(CKM_ECDH1_DERIVE, fake_read, &o, NULL) ==
             CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_derive_base_check(CKM_ECDSA, fake_read, &o, &b) == CKR_ARGUMENTS_BAD),
        "no reader, no output or another mechanism -> ARGUMENTS_BAD"
    );
}

/* ========================================================================= */
/* The derived key's template                                                */
/* ========================================================================= */

static CK_RV tmpl_check(
    CK_MECHANISM_TYPE mech,
    tsra_pkcs11_ec_curve_t curve,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG n,
    tsra_pkcs11_derive_target *out
)
{
    return tsra_pkcs11_derive_check_template(mech, curve, tmpl, n, out);
}

/* One template verdict: the mechanism, the curve and the attributes. */
typedef struct
{
    const char *what;
    CK_MECHANISM_TYPE mech;
    CK_ATTRIBUTE tmpl[6];
    CK_ULONG n;
    CK_RV want;
} tmpl_row;

static void test_template(void)
{
    printf("== derive_check_template ==\n");
    static tsra_pkcs11_derive_target t;
    static CK_ULONG len16 = AES128_KEY_BYTES;
    static CK_ULONG len24 = AES192_KEY_BYTES;
    static CK_ULONG len32 = AES256_KEY_BYTES;
    static CK_ULONG len48 = TSRA_PKCS11_SHA384_DIGEST_LEN;
    static CK_ULONG len64 = AES_XTS_KEY_BYTES;
    static CK_ULONG len66 = ECDH_SECRET_MAX_BYTES;
    static CK_MECHANISM_TYPE hkdf_m[] = { CKM_HKDF_DERIVE };
    static CK_MECHANISM_TYPE ecdh_m[] = { CKM_ECDH1_DERIVE };
    static CK_MECHANISM_TYPE gcm_m[] = { CKM_AES_GCM };
    static CK_MECHANISM_TYPE xts_m[] = { CKM_AES_XTS };
    static CK_MECHANISM_TYPE cbc_m[] = { CKM_AES_CBC };
    static CK_MECHANISM_TYPE h256_m[] = { CKM_SHA256_HMAC };
    static CK_MECHANISM_TYPE h384_m[] = { CKM_SHA384_HMAC };
    static CK_BYTE value[AES256_KEY_BYTES];
    static CK_ATTRIBUTE nested = { CKA_CLASS, &g_secret, sizeof(g_secret) };
    const CK_ATTRIBUTE cls = ATTR(CKA_CLASS, g_secret);
    const CK_ATTRIBUTE gen = ATTR(CKA_KEY_TYPE, g_generic);
    const CK_ATTRIBUTE aes = ATTR(CKA_KEY_TYPE, g_aes);
    const CK_ATTRIBUTE h256 = ATTR(CKA_KEY_TYPE, g_hmac256);

    /* ECDH positive controls, one per curve. */
    for (size_t c = 0; c < COUNT(CURVES); c++)
    {
        CK_ATTRIBUTE tmpl[] = { cls, gen };
        char msg[128];
        snprintf(
            msg,
            sizeof(msg),
            "ECDH %s: secret class and type -> the curve's length appended",
            CURVES[c].name
        );
        CHECK(
            (tmpl_check(CKM_ECDH1_DERIVE, CURVES[c].curve, tmpl, 2, &t) == CKR_OK) &&
                (t.value_len == CURVES[c].coord) && (t.count == 3) &&
                (t.tmpl[2].type == CKA_VALUE_LEN) && (t.tmpl[2].pValue == &t.value_len) &&
                (t.policy != NULL) && (t.policy->kind == TSRA_PKCS11_KIND_SHARED_SECRET) &&
                (t.policy->key_type == CKK_GENERIC_SECRET),
            msg
        );
    }
    tmpl_row rows[] = {
        { "ECDH: CKA_VALUE_LEN 32 on P-256 -> OK",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_VALUE_LEN, len32) },
          3,
          CKR_OK },
        { "ECDH: CKA_VALUE_LEN 16 (a truncation) -> ATTRIBUTE_VALUE_INVALID",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_VALUE_LEN, len16) },
          3,
          CKR_ATTRIBUTE_VALUE_INVALID },
        { "ECDH: CKA_VALUE_LEN 48 on P-256 -> ATTRIBUTE_VALUE_INVALID",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_VALUE_LEN, len48) },
          3,
          CKR_ATTRIBUTE_VALUE_INVALID },
        { "ECDH: no class -> TEMPLATE_INCOMPLETE",
          CKM_ECDH1_DERIVE,
          { gen },
          1,
          CKR_TEMPLATE_INCOMPLETE },
        { "ECDH: no key type -> TEMPLATE_INCOMPLETE",
          CKM_ECDH1_DERIVE,
          { cls },
          1,
          CKR_TEMPLATE_INCOMPLETE },
        { "ECDH: an AES key -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, aes },
          2,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: an HMAC key -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, h256 },
          2,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: a private key class -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { ATTR(CKA_CLASS, g_private), gen },
          2,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: CKA_VALUE -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_VALUE, value) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: CKA_SIGN TRUE -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_SIGN, g_true) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: CKA_ENCRYPT TRUE -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_ENCRYPT, g_true) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: CKA_SIGN TRUE before the key type -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { ATTR(CKA_SIGN, g_true), cls, gen },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: CKA_SIGN FALSE and CKA_DERIVE TRUE -> OK",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_SIGN, g_false), ATTR(CKA_DERIVE, g_true) },
          4,
          CKR_OK },
        { "ECDH: CKA_DERIVE FALSE -> OK (a key the caller limits)",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_DERIVE, g_false) },
          3,
          CKR_OK },
        { "ECDH: CKA_SENSITIVE FALSE -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_SENSITIVE, g_false) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: CKA_EXTRACTABLE TRUE -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_EXTRACTABLE, g_true) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: CKA_SENSITIVE TRUE and CKA_EXTRACTABLE FALSE -> OK",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_SENSITIVE, g_true), ATTR(CKA_EXTRACTABLE, g_false) },
          4,
          CKR_OK },
        { "ECDH: a public token key -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_TOKEN, g_true), ATTR(CKA_PRIVATE, g_false) },
          4,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: a public session key -> OK",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_TOKEN, g_false), ATTR(CKA_PRIVATE, g_false) },
          4,
          CKR_OK },
        { "ECDH: CKA_LOCAL -> ATTRIBUTE_READ_ONLY",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_LOCAL, g_false) },
          3,
          CKR_ATTRIBUTE_READ_ONLY },
        { "ECDH: CKA_ALLOWED_MECHANISMS { CKM_HKDF_DERIVE } -> OK",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_ALLOWED_MECHANISMS, hkdf_m) },
          3,
          CKR_OK },
        { "ECDH: CKA_ALLOWED_MECHANISMS { CKM_ECDH1_DERIVE } -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, gen, ATTR(CKA_ALLOWED_MECHANISMS, ecdh_m) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: an empty CKA_ALLOWED_MECHANISMS -> ATTRIBUTE_VALUE_INVALID",
          CKM_ECDH1_DERIVE,
          { cls, gen, { CKA_ALLOWED_MECHANISMS, hkdf_m, 0 } },
          3,
          CKR_ATTRIBUTE_VALUE_INVALID },
        { "ECDH: a repeated class -> TEMPLATE_INCONSISTENT",
          CKM_ECDH1_DERIVE,
          { cls, gen, cls },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "ECDH: CKA_DERIVE_TEMPLATE -> ATTRIBUTE_TYPE_INVALID",
          CKM_ECDH1_DERIVE,
          { cls, gen, { CKA_DERIVE_TEMPLATE, &nested, sizeof(nested) } },
          3,
          CKR_ATTRIBUTE_TYPE_INVALID },
        { "ECDH: a two-byte CK_BBOOL -> ATTRIBUTE_VALUE_INVALID",
          CKM_ECDH1_DERIVE,
          { cls, gen, { CKA_TOKEN, value, 2 } },
          3,
          CKR_ATTRIBUTE_VALUE_INVALID },

        { "HKDF: AES of 16 bytes -> OK",
          CKM_HKDF_DERIVE,
          { cls, aes, ATTR(CKA_VALUE_LEN, len16) },
          3,
          CKR_OK },
        { "HKDF: AES of 24 bytes -> OK",
          CKM_HKDF_DERIVE,
          { cls, aes, ATTR(CKA_VALUE_LEN, len24) },
          3,
          CKR_OK },
        { "HKDF: AES of 32 bytes with { CKM_AES_CBC } -> OK",
          CKM_HKDF_DERIVE,
          { cls, aes, ATTR(CKA_VALUE_LEN, len32), ATTR(CKA_ALLOWED_MECHANISMS, cbc_m) },
          4,
          CKR_OK },
        { "HKDF: AES without CKA_VALUE_LEN -> TEMPLATE_INCOMPLETE",
          CKM_HKDF_DERIVE,
          { cls, aes },
          2,
          CKR_TEMPLATE_INCOMPLETE },
        { "HKDF: AES of 64 bytes -> ATTRIBUTE_VALUE_INVALID",
          CKM_HKDF_DERIVE,
          { cls, aes, ATTR(CKA_VALUE_LEN, len64) },
          3,
          CKR_ATTRIBUTE_VALUE_INVALID },
        { "HKDF: AES without a class -> TEMPLATE_INCOMPLETE",
          CKM_HKDF_DERIVE,
          { aes, ATTR(CKA_VALUE_LEN, len16) },
          2,
          CKR_TEMPLATE_INCOMPLETE },
        { "HKDF: no key type -> TEMPLATE_INCOMPLETE",
          CKM_HKDF_DERIVE,
          { cls, ATTR(CKA_VALUE_LEN, len16) },
          2,
          CKR_TEMPLATE_INCOMPLETE },
        { "HKDF: an AES-GCM key -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, aes, ATTR(CKA_VALUE_LEN, len32), ATTR(CKA_ALLOWED_MECHANISMS, gcm_m) },
          4,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: an AES-GCM key without a length -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, aes, ATTR(CKA_ALLOWED_MECHANISMS, gcm_m) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: { CKM_AES_XTS } on CKK_AES -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, aes, ATTR(CKA_VALUE_LEN, len32), ATTR(CKA_ALLOWED_MECHANISMS, xts_m) },
          4,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: CKK_AES_XTS -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, ATTR(CKA_KEY_TYPE, g_xts), ATTR(CKA_VALUE_LEN, len64) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: AES with CKA_VALUE -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, aes, ATTR(CKA_VALUE_LEN, len16), ATTR(CKA_VALUE, value) },
          4,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: AES with CKA_SENSITIVE FALSE -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, aes, ATTR(CKA_VALUE_LEN, len16), ATTR(CKA_SENSITIVE, g_false) },
          4,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: a public token AES key -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls,
            aes,
            ATTR(CKA_VALUE_LEN, len16),
            ATTR(CKA_TOKEN, g_true),
            ATTR(CKA_PRIVATE, g_false) },
          5,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: a generic secret -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, gen },
          2,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: an EC key -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, ATTR(CKA_KEY_TYPE, g_ec) },
          2,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: HMAC-SHA256 with CKA_VALUE_LEN 32 -> OK",
          CKM_HKDF_DERIVE,
          { cls, h256, ATTR(CKA_VALUE_LEN, len32) },
          3,
          CKR_OK },
        { "HKDF: HMAC-SHA256 with CKA_VALUE_LEN 48 -> ATTRIBUTE_VALUE_INVALID",
          CKM_HKDF_DERIVE,
          { cls, h256, ATTR(CKA_VALUE_LEN, len48) },
          3,
          CKR_ATTRIBUTE_VALUE_INVALID },
        { "HKDF: HMAC-SHA512 with CKA_VALUE_LEN 66 -> ATTRIBUTE_VALUE_INVALID",
          CKM_HKDF_DERIVE,
          { cls, ATTR(CKA_KEY_TYPE, g_hmac512), ATTR(CKA_VALUE_LEN, len66) },
          3,
          CKR_ATTRIBUTE_VALUE_INVALID },
        { "HKDF: HMAC with CKA_SIGN FALSE and CKA_VERIFY TRUE -> OK",
          CKM_HKDF_DERIVE,
          { cls, h256, ATTR(CKA_SIGN, g_false), ATTR(CKA_VERIFY, g_true) },
          4,
          CKR_OK },
        { "HKDF: HMAC with CKA_ENCRYPT TRUE -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, h256, ATTR(CKA_ENCRYPT, g_true) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: HMAC with CKA_DERIVE TRUE -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, h256, ATTR(CKA_DERIVE, g_true) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: HMAC-SHA256 with { CKM_SHA256_HMAC } -> OK",
          CKM_HKDF_DERIVE,
          { cls, h256, ATTR(CKA_ALLOWED_MECHANISMS, h256_m) },
          3,
          CKR_OK },
        { "HKDF: HMAC-SHA256 with { CKM_SHA384_HMAC } -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, h256, ATTR(CKA_ALLOWED_MECHANISMS, h384_m) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
        { "HKDF: HMAC with CKA_EXTRACTABLE TRUE -> TEMPLATE_INCONSISTENT",
          CKM_HKDF_DERIVE,
          { cls, h256, ATTR(CKA_EXTRACTABLE, g_true) },
          3,
          CKR_TEMPLATE_INCONSISTENT },
    };
    for (size_t r = 0; r < COUNT(rows); r++)
    {
        CHECK(
            tmpl_check(rows[r].mech, TSRA_PKCS11_CURVE_P256, rows[r].tmpl, rows[r].n, &t) ==
                rows[r].want,
            rows[r].what
        );
    }

    /* The HMAC lengths and kinds. */
    static const struct
    {
        CK_KEY_TYPE *kt;
        CK_ULONG len;
        tsra_pkcs11_key_kind_t kind;
        CK_MECHANISM_TYPE mech;
    } hmacs[] = {
        { &g_hmac256,
          TSRA_PKCS11_SHA256_DIGEST_LEN,
          TSRA_PKCS11_KIND_HMAC_SHA256,
          CKM_SHA256_HMAC },
        { &g_hmac384,
          TSRA_PKCS11_SHA384_DIGEST_LEN,
          TSRA_PKCS11_KIND_HMAC_SHA384,
          CKM_SHA384_HMAC },
        { &g_hmac512,
          TSRA_PKCS11_SHA512_DIGEST_LEN,
          TSRA_PKCS11_KIND_HMAC_SHA512,
          CKM_SHA512_HMAC },
    };
    bool all = true;
    for (size_t h = 0; h < COUNT(hmacs); h++)
    {
        CK_ATTRIBUTE tmpl[] = { cls, { CKA_KEY_TYPE, hmacs[h].kt, sizeof(CK_KEY_TYPE) } };
        all = all && (tmpl_check(CKM_HKDF_DERIVE, TSRA_PKCS11_CURVE_NONE, tmpl, 2, &t) == CKR_OK) &&
              (t.value_len == hmacs[h].len) && (t.policy != NULL) &&
              (t.policy->kind == hmacs[h].kind) && (t.policy->mechs[0] == hmacs[h].mech) &&
              (t.count == 3);
    }
    CHECK(all, "HKDF: each HMAC key type -> its hash length appended, its kind and mechanism");
    CK_ATTRIBUTE aes_tmpl[] = { cls, aes, ATTR(CKA_VALUE_LEN, len24) };
    CHECK(
        (tmpl_check(CKM_HKDF_DERIVE, TSRA_PKCS11_CURVE_NONE, aes_tmpl, 3, &t) == CKR_OK) &&
            (t.value_len == len24) && (t.count == 3) && (t.policy != NULL) &&
            (t.policy->kind == TSRA_PKCS11_KIND_AES),
        "HKDF: an AES key keeps its template, the CBC kind"
    );
    CK_ATTRIBUTE token_tmpl[] = { cls, gen, ATTR(CKA_TOKEN, g_true) };
    CHECK(
        (tmpl_check(CKM_ECDH1_DERIVE, TSRA_PKCS11_CURVE_P256, token_tmpl, 3, &t) == CKR_OK) &&
            (t.token == CK_TRUE),
        "a token key, private by default -> OK, CKA_TOKEN reported"
    );

    /* A template packed into a byte buffer: the values are misaligned. */
    CK_BYTE raw[sizeof(CK_ULONG) * 3 + 1];
    memcpy(raw + 1, &g_secret, sizeof(g_secret));
    memcpy(raw + 1 + sizeof(CK_ULONG), &g_hmac384, sizeof(g_hmac384));
    memcpy(raw + 1 + (2 * sizeof(CK_ULONG)), &len48, sizeof(len48));
    CK_ATTRIBUTE packed[] = {
        { CKA_CLASS, raw + 1, sizeof(CK_ULONG) },
        { CKA_KEY_TYPE, raw + 1 + sizeof(CK_ULONG), sizeof(CK_ULONG) },
        { CKA_VALUE_LEN, raw + 1 + (2 * sizeof(CK_ULONG)), sizeof(CK_ULONG) },
    };
    CHECK(
        (tmpl_check(CKM_HKDF_DERIVE, TSRA_PKCS11_CURVE_NONE, packed, 3, &t) == CKR_OK) &&
            (t.value_len == len48),
        "a misaligned template is read"
    );

    CK_ATTRIBUTE ok_tmpl[] = { cls, gen };
    CHECK(
        (tmpl_check(CKM_ECDH1_DERIVE, TSRA_PKCS11_CURVE_P256, ok_tmpl, 2, NULL) == CKR_ARGUMENTS_BAD
        ) &&
            (tmpl_check(CKM_ECDH1_DERIVE, TSRA_PKCS11_CURVE_P256, NULL, 1, &t) == CKR_ARGUMENTS_BAD
            ) &&
            (tmpl_check(CKM_ECDH1_DERIVE, TSRA_PKCS11_CURVE_NONE, ok_tmpl, 2, &t) ==
             CKR_ARGUMENTS_BAD) &&
            (tmpl_check(CKM_ECDSA, TSRA_PKCS11_CURVE_P256, ok_tmpl, 2, &t) == CKR_ARGUMENTS_BAD) &&
            (tmpl_check(
                 CKM_ECDH1_DERIVE,
                 TSRA_PKCS11_CURVE_P256,
                 ok_tmpl,
                 TEMPLATE_MAX_ATTRS + 1,
                 &t
             ) == CKR_ARGUMENTS_BAD),
        "no output, a NULL template with a count, ECDH without a curve, another mechanism "
        "or too many attributes -> ARGUMENTS_BAD"
    );
}

/* ========================================================================= */
/* The stored template                                                       */
/* ========================================================================= */

/* Whether `full` holds `type` with exactly `len` bytes equal to `value`. */
static bool built_has(
    const CK_ATTRIBUTE *full,
    CK_ULONG n,
    CK_ATTRIBUTE_TYPE type,
    const void *value,
    CK_ULONG len
)
{
    for (CK_ULONG i = 0; i < n; i++)
    {
        if (full[i].type == type)
        {
            return (full[i].ulValueLen == len) && (memcmp(full[i].pValue, value, len) == 0);
        }
    }
    return false;
}

static bool built_lacks(const CK_ATTRIBUTE *full, CK_ULONG n, CK_ATTRIBUTE_TYPE type)
{
    for (CK_ULONG i = 0; i < n; i++)
    {
        if (full[i].type == type)
        {
            return false;
        }
    }
    return true;
}

static void test_build(void)
{
    printf("== derive_build_template ==\n");
    static tsra_pkcs11_derive_target t;
    CK_ATTRIBUTE full[TEMPLATE_MAX_ATTRS + 1 + KEYGEN_APPENDED_ATTRS];
    tsra_pkcs11_keygen_fill fill;
    CK_ULONG n = 0;
    CK_MECHANISM_TYPE kgm = CK_UNAVAILABLE_INFORMATION;
    CK_ULONG len32 = ECDH_SECRET_MIN_BYTES; /* the P-256 secret */

    CK_ATTRIBUTE gen[] = { ATTR(CKA_CLASS, g_secret), ATTR(CKA_KEY_TYPE, g_generic) };
    CHECK(
        tsra_pkcs11_derive_check_template(CKM_ECDH1_DERIVE, TSRA_PKCS11_CURVE_P256, gen, 2, &t) ==
            CKR_OK,
        "a generic secret template is accepted"
    );
    memset(&fill, 0xA5, sizeof(fill)); /* every field must be written by the builder */
    CK_MECHANISM_TYPE hkdf_m = CKM_HKDF_DERIVE;
    CHECK(
        (tsra_pkcs11_derive_build_template(
             t.policy,
             t.tmpl,
             t.count,
             CK_TRUE,
             CK_FALSE,
             &fill,
             full,
             &n
         ) == CKR_OK) &&
            (n <= (t.count + KEYGEN_APPENDED_ATTRS)) &&
            built_has(full, n, CKA_VALUE_LEN, &len32, sizeof(len32)) &&
            built_has(full, n, CKA_PRIVATE, &g_true, sizeof(g_true)) &&
            built_has(full, n, CKA_SENSITIVE, &g_true, sizeof(g_true)) &&
            built_has(full, n, CKA_EXTRACTABLE, &g_false, sizeof(g_false)) &&
            built_has(full, n, CKA_DERIVE, &g_true, sizeof(g_true)) &&
            built_lacks(full, n, CKA_ENCRYPT) && built_lacks(full, n, CKA_SIGN) &&
            built_has(full, n, CKA_ALLOWED_MECHANISMS, &hkdf_m, sizeof(hkdf_m)) &&
            built_has(full, n, CKA_LOCAL, &g_false, sizeof(g_false)) &&
            built_has(full, n, CKA_ALWAYS_SENSITIVE, &g_true, sizeof(g_true)) &&
            built_has(full, n, CKA_NEVER_EXTRACTABLE, &g_false, sizeof(g_false)) &&
            built_has(full, n, CKA_KEY_GEN_MECHANISM, &kgm, sizeof(kgm)),
        "generic secret: derives only, HKDF only, not local, the base key's protection"
    );
    CHECK(
        (tsra_pkcs11_derive_build_template(
             t.policy,
             t.tmpl,
             t.count,
             CK_FALSE,
             CK_TRUE,
             &fill,
             full,
             &n
         ) == CKR_OK) &&
            built_has(full, n, CKA_ALWAYS_SENSITIVE, &g_false, sizeof(g_false)) &&
            built_has(full, n, CKA_NEVER_EXTRACTABLE, &g_true, sizeof(g_true)),
        "the two flags follow the base key independently"
    );

    CK_ATTRIBUTE hm[] = { ATTR(CKA_CLASS, g_secret), ATTR(CKA_KEY_TYPE, g_hmac384) };
    CK_MECHANISM_TYPE h384_m = CKM_SHA384_HMAC;
    CK_ULONG len48 = TSRA_PKCS11_SHA384_DIGEST_LEN;
    CHECK(
        (tsra_pkcs11_derive_check_template(CKM_HKDF_DERIVE, TSRA_PKCS11_CURVE_NONE, hm, 2, &t) ==
         CKR_OK) &&
            (tsra_pkcs11_derive_build_template(
                 t.policy,
                 t.tmpl,
                 t.count,
                 CK_TRUE,
                 CK_TRUE,
                 &fill,
                 full,
                 &n
             ) == CKR_OK) &&
            built_has(full, n, CKA_KEY_TYPE, &g_hmac384, sizeof(g_hmac384)) &&
            built_has(full, n, CKA_VALUE_LEN, &len48, sizeof(len48)) &&
            built_has(full, n, CKA_SIGN, &g_true, sizeof(g_true)) &&
            built_has(full, n, CKA_VERIFY, &g_true, sizeof(g_true)) &&
            built_lacks(full, n, CKA_DERIVE) && built_lacks(full, n, CKA_ENCRYPT) &&
            built_has(full, n, CKA_ALLOWED_MECHANISMS, &h384_m, sizeof(h384_m)),
        "HMAC-SHA384: signs and verifies, CKM_SHA384_HMAC only"
    );
    CK_ATTRIBUTE limited[] = { ATTR(CKA_CLASS, g_secret),
                               ATTR(CKA_KEY_TYPE, g_hmac256),
                               ATTR(CKA_SIGN, g_false) };
    CHECK(
        (tsra_pkcs11_derive_check_template(
             CKM_HKDF_DERIVE,
             TSRA_PKCS11_CURVE_NONE,
             limited,
             3,
             &t
         ) == CKR_OK) &&
            (tsra_pkcs11_derive_build_template(
                 t.policy,
                 t.tmpl,
                 t.count,
                 CK_TRUE,
                 CK_TRUE,
                 &fill,
                 full,
                 &n
             ) == CKR_OK) &&
            built_has(full, n, CKA_SIGN, &g_false, sizeof(g_false)) &&
            built_has(full, n, CKA_VERIFY, &g_true, sizeof(g_true)),
        "a caller's FALSE usage is kept"
    );
    CHECK(
        tsra_pkcs11_derive_build_template(
            NULL,
            t.tmpl,
            t.count,
            CK_TRUE,
            CK_TRUE,
            &fill,
            full,
            &n
        ) == CKR_ARGUMENTS_BAD,
        "no policy -> ARGUMENTS_BAD"
    );
}

int main(void)
{
    test_ecdh_params();
    test_hkdf_params();
    test_peer();
    test_base();
    test_template();
    test_build();
    printf(
        g_fail ? "\nderive_params_test: FAILED (%d checks)\n"
               : "\nderive_params_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
