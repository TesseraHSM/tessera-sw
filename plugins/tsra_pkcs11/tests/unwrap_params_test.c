// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the CKM_RSA_AES_KEY_WRAP and unwrapping key pair logic
 * (src/tsra_pkcs11_unwrap_params.c). No device, no store, no module load:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src unwrap_params_test.c \
 *       ../src/tsra_pkcs11_unwrap_params.c ../src/tsra_pkcs11_unwrap_private.c \
 *       ../src/tsra_pkcs11_template.c ../src/tsra_pkcs11_ec_template.c \
 *       ../src/tsra_pkcs11_attr_types.c ../src/tsra_pkcs11_digest.c \
 *       -o unwrap_params_test && ./unwrap_params_test
 *
 * Covers the CK_RSA_AES_KEY_WRAP_PARAMS decoder (key-encryption key sizes,
 * the OAEP hash and MGF1 pairs, source and label, a misaligned block), the
 * unwrap template with its blob length rule for each key family (the XTS
 * container included), the unwrapping-key rule against a fake object, the
 * exact key pair template and its refusals, the templates stored for both
 * halves, the SubjectPublicKeyInfo walk on a real RSA-1024 key, on broken
 * encodings and on DER lengths around the short and long forms, and the
 * comparison of an object's modulus with the device key; for private-key
 * targets the blob length window of each RSA size and EC curve at its
 * edges, every template verdict and its order, and the two templates stored
 * for the private key and its companion public key, from RSA and EC public
 * key infos and from ones that are not the target's.
 */

#include "tsra_pkcs11_unwrap_params.h"
#include "tsra_pkcs11_unwrap_private.h"

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
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
static CK_KEY_TYPE g_aes = CKK_AES;
static CK_KEY_TYPE g_xts = CKK_AES_XTS;
static CK_KEY_TYPE g_rsa = CKK_RSA;
static CK_ULONG g_bits = RSA_UNWRAP_KEY_BITS;

/* The blob lengths of each key length: one OAEP block plus the RFC 5649 wrap,
 * and for XTS the SDK's container of two such blobs of 32-byte halves. */
#define BLOB(key) (RSA_UNWRAP_MODULUS_BYTES + AES_KWP_OVERHEAD + (key))
#define XTS_BLOB (AES_XTS_BLOB_HEADER + (2 * BLOB(32)))

/* A real RSA-1024 public key (DER SubjectPublicKeyInfo): long-form lengths,
 * a modulus with a leading zero octet, and the exponent 65537. */
static const CK_BYTE SPKI[] = {
    0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xd5,
    0x57, 0x59, 0x41, 0x05, 0x9f, 0xa7, 0x32, 0x9a, 0xde, 0x2e, 0xd3, 0x50, 0xd4, 0x66, 0xf6,
    0x9c, 0x88, 0x5d, 0x48, 0x91, 0xed, 0x42, 0xb8, 0xc2, 0x11, 0x7e, 0xdc, 0x5d, 0xb8, 0xaf,
    0xbe, 0x3f, 0x20, 0x86, 0x97, 0xe9, 0x56, 0x3d, 0x41, 0x52, 0xca, 0xa5, 0x5e, 0x80, 0x03,
    0x67, 0x6a, 0xde, 0x74, 0x88, 0x7d, 0xe8, 0x4f, 0x0f, 0x67, 0x8f, 0xee, 0x63, 0x45, 0xfc,
    0xa2, 0x24, 0x7f, 0xdd, 0x43, 0xee, 0x2f, 0x9a, 0xb4, 0xc6, 0xcb, 0x5c, 0x6c, 0xf0, 0xae,
    0x0e, 0x89, 0x0e, 0x72, 0x1f, 0x99, 0xf1, 0x9f, 0xde, 0xb2, 0xbc, 0x3b, 0xc0, 0x21, 0xf0,
    0x2f, 0x60, 0xc7, 0x56, 0x9d, 0xd3, 0x2c, 0x34, 0x12, 0xbf, 0xc3, 0xa1, 0x19, 0x25, 0x3c,
    0xf9, 0xc2, 0x1f, 0x08, 0x82, 0xae, 0x59, 0x02, 0xc8, 0x79, 0xb4, 0x11, 0xf8, 0x46, 0x79,
    0x3d, 0xd4, 0xed, 0xf5, 0x9e, 0x79, 0x4f, 0x02, 0x03, 0x01, 0x00, 0x01,
};
/* Where the modulus content starts after its leading zero, and its length. */
#define SPKI_N_OFFSET 29
#define SPKI_N_LEN 128

/* ========================================================================= */
/* CK_RSA_AES_KEY_WRAP_PARAMS                                                */
/* ========================================================================= */

static CK_RV params(CK_ULONG kek_bits, CK_MECHANISM_TYPE hash, CK_RSA_PKCS_MGF_TYPE mgf)
{
    CK_RSA_PKCS_OAEP_PARAMS oaep = { hash, mgf, CKZ_DATA_SPECIFIED, NULL, 0 };
    CK_RSA_AES_KEY_WRAP_PARAMS p = { kek_bits, &oaep };
    CK_MECHANISM m = { CKM_RSA_AES_KEY_WRAP, &p, sizeof(p) };
    tsra_pkcs11_rsa_aes_params out;
    return tsra_pkcs11_unwrap_params_check(&m, &out);
}

static void test_params(void)
{
    printf("== unwrap_params_check ==\n");
    CK_RSA_PKCS_OAEP_PARAMS oaep = { CKM_SHA384, CKG_MGF1_SHA384, CKZ_DATA_SPECIFIED, NULL, 0 };
    CK_RSA_AES_KEY_WRAP_PARAMS p = { 192, &oaep };
    CK_MECHANISM m = { CKM_RSA_AES_KEY_WRAP, &p, sizeof(p) };
    tsra_pkcs11_rsa_aes_params out;
    CHECK(
        (tsra_pkcs11_unwrap_params_check(&m, &out) == CKR_OK) && (out.hash == CKM_SHA384) &&
            (out.aes_key_bits == 192),
        "SHA-384 with a 192-bit KEK -> its hash and size"
    );
    CHECK(tsra_pkcs11_unwrap_params_check(NULL, &out) == CKR_ARGUMENTS_BAD, "NULL mechanism");
    CHECK(tsra_pkcs11_unwrap_params_check(&m, NULL) == CKR_ARGUMENTS_BAD, "NULL output");
    CK_MECHANISM oaep_mech = { CKM_RSA_PKCS_OAEP, &oaep, sizeof(oaep) };
    CHECK(
        tsra_pkcs11_unwrap_params_check(&oaep_mech, &out) == CKR_MECHANISM_INVALID,
        "another mechanism -> CKR_MECHANISM_INVALID"
    );
    CK_MECHANISM empty = { CKM_RSA_AES_KEY_WRAP, NULL, 0 };
    CHECK(
        tsra_pkcs11_unwrap_params_check(&empty, &out) == CKR_MECHANISM_PARAM_INVALID,
        "no parameter -> CKR_MECHANISM_PARAM_INVALID"
    );
    CK_MECHANISM short_block = { CKM_RSA_AES_KEY_WRAP, &p, sizeof(p) - 1 };
    CHECK(
        tsra_pkcs11_unwrap_params_check(&short_block, &out) == CKR_MECHANISM_PARAM_INVALID,
        "a short parameter -> CKR_MECHANISM_PARAM_INVALID"
    );
    p.pOAEPParams = NULL;
    CHECK(
        tsra_pkcs11_unwrap_params_check(&m, &out) == CKR_MECHANISM_PARAM_INVALID,
        "no OAEP parameters -> CKR_MECHANISM_PARAM_INVALID"
    );

    CHECK(params(128, CKM_SHA256, CKG_MGF1_SHA256) == CKR_OK, "KEK 128");
    CHECK(params(256, CKM_SHA512, CKG_MGF1_SHA512) == CKR_OK, "KEK 256 with SHA-512");
    const CK_ULONG bad_bits[] = { 0, 64, 127, 129, 384, 512 };
    for (size_t i = 0; i < COUNT(bad_bits); i++)
    {
        char msg[64];
        snprintf(msg, sizeof(msg), "KEK %lu -> CKR_MECHANISM_PARAM_INVALID", bad_bits[i]);
        CHECK(params(bad_bits[i], CKM_SHA256, CKG_MGF1_SHA256) == CKR_MECHANISM_PARAM_INVALID, msg);
    }
    CHECK(
        params(256, CKM_SHA_1, CKG_MGF1_SHA1) == CKR_MECHANISM_PARAM_INVALID,
        "SHA-1 -> CKR_MECHANISM_PARAM_INVALID (the SDK has no SHA-1 OAEP)"
    );
    CHECK(
        params(256, CKM_SHA224, CKG_MGF1_SHA224) == CKR_MECHANISM_PARAM_INVALID,
        "SHA-224 -> CKR_MECHANISM_PARAM_INVALID"
    );
    CHECK(
        params(256, CKM_SHA256, CKG_MGF1_SHA384) == CKR_MECHANISM_PARAM_INVALID,
        "MGF1 with another hash -> CKR_MECHANISM_PARAM_INVALID"
    );
    CHECK(
        params(256, CKM_SHA512, CKG_MGF1_SHA256) == CKR_MECHANISM_PARAM_INVALID,
        "SHA-512 with MGF1-SHA-256 -> CKR_MECHANISM_PARAM_INVALID"
    );

    oaep = (CK_RSA_PKCS_OAEP_PARAMS){ CKM_SHA256, CKG_MGF1_SHA256, 0, NULL, 0 };
    p.pOAEPParams = &oaep;
    CHECK(
        tsra_pkcs11_unwrap_params_check(&m, &out) == CKR_MECHANISM_PARAM_INVALID,
        "source 0 -> CKR_MECHANISM_PARAM_INVALID"
    );
    CK_BYTE label[] = { 'l' };
    oaep = (CK_RSA_PKCS_OAEP_PARAMS
    ){ CKM_SHA256, CKG_MGF1_SHA256, CKZ_DATA_SPECIFIED, label, sizeof(label) };
    CHECK(
        tsra_pkcs11_unwrap_params_check(&m, &out) == CKR_MECHANISM_PARAM_INVALID,
        "a label -> CKR_MECHANISM_PARAM_INVALID (the SDK drops it)"
    );
    oaep.ulSourceDataLen = 0;
    CHECK(tsra_pkcs11_unwrap_params_check(&m, &out) == CKR_OK, "a label pointer of length 0");

    /* A parameter block at an odd address (UBSan build). */
    CK_BYTE raw[sizeof(p) + 1];
    memcpy(raw + 1, &p, sizeof(p));
    CK_MECHANISM odd = { CKM_RSA_AES_KEY_WRAP, raw + 1, sizeof(p) };
    CHECK(
        (tsra_pkcs11_unwrap_params_check(&odd, &out) == CKR_OK) && (out.hash == CKM_SHA256),
        "a misaligned parameter block is read correctly"
    );
}

/* ========================================================================= */
/* Unwrap template and blob length                                           */
/* ========================================================================= */

static CK_RV target(
    const CK_ATTRIBUTE *t,
    CK_ULONG n,
    CK_ULONG blob,
    tsra_pkcs11_unwrap_target *out
)
{
    return tsra_pkcs11_unwrap_check_template(t, n, blob, out);
}

static void test_template(void)
{
    printf("== unwrap_check_template ==\n");
    static tsra_pkcs11_unwrap_target out; /* 1.6 KB; kept off the stack */
    CK_MECHANISM_TYPE gcm = CKM_AES_GCM;
    CK_ULONG len16 = 16;
    CK_ULONG len24 = 24;
    CK_ULONG len64 = 64;
    CK_ATTRIBUTE aes[] = { ATTR(CKA_CLASS, g_secret), ATTR(CKA_KEY_TYPE, g_aes) };
    CK_ATTRIBUTE gcm_t[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_aes),
        ATTR(CKA_ALLOWED_MECHANISMS, gcm),
    };
    CK_ATTRIBUTE xts[] = { ATTR(CKA_CLASS, g_secret), ATTR(CKA_KEY_TYPE, g_xts) };

    const CK_ULONG lens[] = { 16, 24, 32 };
    for (size_t i = 0; i < COUNT(lens); i++)
    {
        char msg[96];
        snprintf(
            msg,
            sizeof(msg),
            "a blob of %lu bytes -> an AES key of %lu",
            BLOB(lens[i]),
            lens[i]
        );
        CHECK(
            (target(aes, 2, BLOB(lens[i]), &out) == CKR_OK) && (out.value_len == lens[i]) &&
                (out.policy->kind == TSRA_PKCS11_KIND_AES) && (out.count == 3) &&
                (out.tmpl[2].type == CKA_VALUE_LEN) && (out.tmpl[2].pValue == &out.value_len) &&
                (out.tmpl[0].pValue == &g_secret),
            msg
        );
    }
    CHECK(
        (target(gcm_t, 3, BLOB(32), &out) == CKR_OK) &&
            (out.policy->kind == TSRA_PKCS11_KIND_AES_GCM) && (out.value_len == 32),
        "GCM family, 32-byte key"
    );
    CHECK(
        target(gcm_t, 3, BLOB(16), &out) == CKR_WRAPPED_KEY_LEN_RANGE,
        "GCM family, 16-byte key -> CKR_WRAPPED_KEY_LEN_RANGE"
    );
    CHECK(
        (target(xts, 2, XTS_BLOB, &out) == CKR_OK) &&
            (out.policy->kind == TSRA_PKCS11_KIND_AES_XTS) && (out.value_len == 64),
        "XTS in the SDK's container -> a 64-byte key"
    );
    CHECK(
        target(xts, 2, BLOB(64), &out) == CKR_WRAPPED_KEY_LEN_RANGE,
        "XTS in one blob -> CKR_WRAPPED_KEY_LEN_RANGE"
    );
    const CK_ULONG bad[] = {
        0, 1, RSA_UNWRAP_MODULUS_BYTES, BLOB(8), BLOB(15), BLOB(17), BLOB(64)
    };
    for (size_t i = 0; i < COUNT(bad); i++)
    {
        char msg[96];
        snprintf(msg, sizeof(msg), "AES, a blob of %lu bytes -> CKR_WRAPPED_KEY_LEN_RANGE", bad[i]);
        CHECK(target(aes, 2, bad[i], &out) == CKR_WRAPPED_KEY_LEN_RANGE, msg);
    }

    CK_ATTRIBUTE with_len[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_aes),
        ATTR(CKA_VALUE_LEN, len24),
        ATTR(CKA_TOKEN, g_true),
    };
    CHECK(
        (target(with_len, 4, BLOB(24), &out) == CKR_OK) && (out.count == 4) &&
            (out.value_len == 24) && (out.token == CK_TRUE),
        "a matching CKA_VALUE_LEN is kept, nothing appended, CKA_TOKEN read"
    );
    CHECK(
        target(with_len, 4, BLOB(16), &out) == CKR_WRAPPED_KEY_LEN_RANGE,
        "CKA_VALUE_LEN against a shorter blob -> CKR_WRAPPED_KEY_LEN_RANGE"
    );
    CK_ATTRIBUTE xts_len[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_xts),
        ATTR(CKA_VALUE_LEN, len64),
    };
    CHECK(target(xts_len, 3, XTS_BLOB, &out) == CKR_OK, "XTS with CKA_VALUE_LEN 64");
    CK_ATTRIBUTE xts_16[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_xts),
        ATTR(CKA_VALUE_LEN, len16),
    };
    CHECK(
        target(xts_16, 3, XTS_BLOB, &out) == CKR_ATTRIBUTE_VALUE_INVALID,
        "XTS with CKA_VALUE_LEN 16 -> the key-generation verdict"
    );

    CHECK(target(&aes[1], 1, BLOB(16), &out) == CKR_TEMPLATE_INCOMPLETE, "no class -> INCOMPLETE");
    CHECK(target(aes, 1, BLOB(16), &out) == CKR_TEMPLATE_INCOMPLETE, "no key type -> INCOMPLETE");
    CK_ATTRIBUTE priv[] = { ATTR(CKA_CLASS, g_private), ATTR(CKA_KEY_TYPE, g_aes) };
    CHECK(
        target(priv, 2, BLOB(16), &out) == CKR_TEMPLATE_INCONSISTENT,
        "a private key class -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE rsa[] = { ATTR(CKA_CLASS, g_secret), ATTR(CKA_KEY_TYPE, g_rsa) };
    CHECK(
        target(rsa, 2, BLOB(16), &out) == CKR_TEMPLATE_INCONSISTENT,
        "an RSA key type -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE open[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_aes),
        ATTR(CKA_SENSITIVE, g_false),
    };
    CHECK(
        target(open, 3, BLOB(16), &out) == CKR_TEMPLATE_INCONSISTENT,
        "not sensitive -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE public_session[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_aes),
        ATTR(CKA_PRIVATE, g_false),
    };
    CK_ATTRIBUTE public_token[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_aes),
        ATTR(CKA_PRIVATE, g_false),
        ATTR(CKA_TOKEN, g_true),
    };
    CHECK(
        (target(public_session, 3, BLOB(16), &out) == CKR_OK) &&
            (target(public_token, 4, BLOB(16), &out) == CKR_TEMPLATE_INCONSISTENT),
        "a token key must be private; a session one need not be"
    );
    CK_ATTRIBUTE local[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_aes),
        ATTR(CKA_LOCAL, g_false),
    };
    CHECK(
        target(local, 3, BLOB(16), &out) == CKR_ATTRIBUTE_READ_ONLY,
        "CKA_LOCAL -> CKR_ATTRIBUTE_READ_ONLY"
    );
    CK_ATTRIBUTE short_type[] = { ATTR(CKA_CLASS, g_secret), { CKA_KEY_TYPE, &g_aes, 1 } };
    CHECK(
        target(short_type, 2, BLOB(16), &out) == CKR_ATTRIBUTE_VALUE_INVALID,
        "a one-byte key type -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CHECK(target(NULL, 1, BLOB(16), &out) == CKR_ARGUMENTS_BAD, "NULL template with a count");
    CHECK(target(aes, TEMPLATE_MAX_ATTRS + 1, BLOB(16), &out) == CKR_ARGUMENTS_BAD, "over-long");
    CHECK(target(aes, 2, BLOB(16), NULL) == CKR_ARGUMENTS_BAD, "NULL output");
}

/* ========================================================================= */
/* The unwrapping key                                                        */
/* ========================================================================= */

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

static CK_RV key_check(const CK_ATTRIBUTE *attrs, CK_ULONG count, CK_RV fail)
{
    fake_obj o = { attrs, count, fail };
    return tsra_pkcs11_unwrapping_key_check(fake_read, &o);
}

static void test_unwrapping_key(void)
{
    printf("== unwrapping_key_check ==\n");
    CK_ULONG wide[2] = { CKO_PRIVATE_KEY, CKO_PRIVATE_KEY };
    CK_ATTRIBUTE good[] = {
        ATTR(CKA_CLASS, g_private),
        ATTR(CKA_KEY_TYPE, g_rsa),
        ATTR(CKA_UNWRAP, g_true),
    };
    CHECK(key_check(good, 3, CKR_OK) == CKR_OK, "an RSA private key with CKA_UNWRAP");
    CHECK(
        tsra_pkcs11_unwrapping_key_check(NULL, NULL) == CKR_ARGUMENTS_BAD,
        "NULL reader -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        key_check(good, 3, CKR_DEVICE_ERROR) == CKR_DEVICE_ERROR,
        "a store failure is passed through"
    );
    CK_ATTRIBUTE pub[] = {
        ATTR(CKA_CLASS, g_public),
        ATTR(CKA_KEY_TYPE, g_rsa),
        ATTR(CKA_UNWRAP, g_true),
    };
    CHECK(
        key_check(pub, 3, CKR_OK) == CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        "a public key -> CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"
    );
    CK_ATTRIBUTE secret[] = {
        ATTR(CKA_CLASS, g_secret),
        ATTR(CKA_KEY_TYPE, g_aes),
        ATTR(CKA_UNWRAP, g_true),
    };
    CHECK(
        key_check(secret, 3, CKR_OK) == CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        "an AES key with CKA_UNWRAP -> CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"
    );
    CK_ATTRIBUTE no_type[] = { ATTR(CKA_CLASS, g_private), ATTR(CKA_UNWRAP, g_true) };
    CHECK(
        key_check(no_type, 2, CKR_OK) == CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        "no key type -> CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"
    );
    CK_ATTRIBUTE wide_class[] = {
        ATTR(CKA_CLASS, wide),
        ATTR(CKA_KEY_TYPE, g_rsa),
        ATTR(CKA_UNWRAP, g_true),
    };
    CHECK(
        key_check(wide_class, 3, CKR_OK) == CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
        "a stored class of the wrong width -> CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"
    );
    CHECK(
        key_check(good, 2, CKR_OK) == CKR_KEY_FUNCTION_NOT_PERMITTED,
        "no CKA_UNWRAP -> CKR_KEY_FUNCTION_NOT_PERMITTED"
    );
    CK_ATTRIBUTE off[] = {
        ATTR(CKA_CLASS, g_private),
        ATTR(CKA_KEY_TYPE, g_rsa),
        ATTR(CKA_UNWRAP, g_false),
    };
    CHECK(
        key_check(off, 3, CKR_OK) == CKR_KEY_FUNCTION_NOT_PERMITTED,
        "CKA_UNWRAP FALSE -> CKR_KEY_FUNCTION_NOT_PERMITTED"
    );
    CK_ATTRIBUTE wide_flag[] = {
        ATTR(CKA_CLASS, g_private),
        ATTR(CKA_KEY_TYPE, g_rsa),
        ATTR(CKA_UNWRAP, wide),
    };
    CHECK(
        key_check(wide_flag, 3, CKR_OK) == CKR_KEY_FUNCTION_NOT_PERMITTED,
        "a stored CKA_UNWRAP of the wrong width -> CKR_KEY_FUNCTION_NOT_PERMITTED"
    );
}

/* ========================================================================= */
/* The unwrapping key pair request                                           */
/* ========================================================================= */

static CK_RV pair(const CK_ATTRIBUTE *pub, CK_ULONG npub, const CK_ATTRIBUTE *priv, CK_ULONG npriv)
{
    CK_BBOOL pt = CK_FALSE;
    CK_BBOOL kt = CK_FALSE;
    return tsra_pkcs11_unwrapping_pair_check(
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        pub,
        npub,
        priv,
        npriv,
        &pt,
        &kt
    );
}

static void test_pair_check(void)
{
    printf("== unwrapping_pair_check ==\n");
    CK_ATTRIBUTE pub[] = { ATTR(CKA_MODULUS_BITS, g_bits), ATTR(CKA_WRAP, g_true) };
    CK_ATTRIBUTE priv[] = { ATTR(CKA_UNWRAP, g_true) };
    CK_BBOOL pt = CK_TRUE;
    CK_BBOOL kt = CK_TRUE;
    CHECK(
        (tsra_pkcs11_unwrapping_pair_check(CKM_RSA_PKCS_KEY_PAIR_GEN, pub, 2, priv, 1, &pt, &kt) ==
         CKR_OK) &&
            !pt && !kt,
        "the exact template; session objects by default"
    );
    CK_ATTRIBUTE pub_tok[] = {
        ATTR(CKA_MODULUS_BITS, g_bits),
        ATTR(CKA_WRAP, g_true),
        ATTR(CKA_TOKEN, g_true),
    };
    CHECK(
        (tsra_pkcs11_unwrapping_pair_check(
             CKM_RSA_PKCS_KEY_PAIR_GEN,
             pub_tok,
             3,
             priv,
             1,
             &pt,
             &kt
         ) == CKR_OK) &&
            pt && !kt,
        "CKA_TOKEN per half"
    );
    CHECK(
        tsra_pkcs11_unwrapping_pair_check(CKM_EC_KEY_PAIR_GEN, pub, 2, priv, 1, &pt, &kt) ==
            CKR_MECHANISM_INVALID,
        "another mechanism -> CKR_MECHANISM_INVALID"
    );
    CHECK(
        tsra_pkcs11_unwrapping_pair_check(CKM_RSA_PKCS_KEY_PAIR_GEN, pub, 2, priv, 1, NULL, &kt) ==
            CKR_ARGUMENTS_BAD,
        "NULL token output -> CKR_ARGUMENTS_BAD"
    );
    CHECK(pair(NULL, 1, priv, 1) == CKR_ARGUMENTS_BAD, "NULL public template with a count");
    CHECK(pair(pub, 2, NULL, 1) == CKR_ARGUMENTS_BAD, "NULL private template with a count");
    CHECK(pair(pub, TEMPLATE_MAX_ATTRS + 1, priv, 1) == CKR_ARGUMENTS_BAD, "over-long template");

    /* Every usage other than wrap / unwrap, TRUE, in either half. */
    const CK_ATTRIBUTE_TYPE usages[] = { CKA_ENCRYPT,       CKA_DECRYPT, CKA_SIGN,
                                         CKA_SIGN_RECOVER,  CKA_VERIFY,  CKA_DERIVE,
                                         CKA_VERIFY_RECOVER };
    for (size_t i = 0; i < COUNT(usages); i++)
    {
        CK_ATTRIBUTE pub_u[] = { pub[0], pub[1], { usages[i], &g_true, sizeof(g_true) } };
        CK_ATTRIBUTE priv_u[] = { priv[0], { usages[i], &g_true, sizeof(g_true) } };
        CK_ATTRIBUTE pub_f[] = { pub[0], pub[1], { usages[i], &g_false, sizeof(g_false) } };
        char msg[96];
        snprintf(
            msg,
            sizeof(msg),
            "usage 0x%lx TRUE refused in both halves, FALSE accepted",
            usages[i]
        );
        CHECK(
            (pair(pub_u, 3, priv, 1) == CKR_TEMPLATE_INCONSISTENT) &&
                (pair(pub, 2, priv_u, 2) == CKR_TEMPLATE_INCONSISTENT) &&
                (pair(pub_f, 3, priv, 1) == CKR_OK),
            msg
        );
    }
    CK_ATTRIBUTE unwrap_in_pub[] = { pub[0], pub[1], ATTR(CKA_UNWRAP, g_true) };
    CK_ATTRIBUTE wrap_in_priv[] = { priv[0], ATTR(CKA_WRAP, g_true) };
    CHECK(
        (pair(unwrap_in_pub, 3, priv, 1) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(pub, 2, wrap_in_priv, 2) == CKR_TEMPLATE_INCONSISTENT),
        "the other half's usage -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE no_wrap[] = { pub[0] };
    CK_ATTRIBUTE wrap_false[] = { pub[0], ATTR(CKA_WRAP, g_false) };
    CHECK(
        (pair(no_wrap, 1, priv, 1) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(wrap_false, 2, priv, 1) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(pub, 2, NULL, 0) == CKR_TEMPLATE_INCONSISTENT),
        "no CKA_WRAP / CKA_UNWRAP TRUE -> CKR_TEMPLATE_INCONSISTENT"
    );
    CK_ATTRIBUTE no_bits[] = { pub[1] };
    CHECK(pair(no_bits, 1, priv, 1) == CKR_TEMPLATE_INCOMPLETE, "no modulus size -> INCOMPLETE");
    CK_ULONG sizes[] = { 1024, 2047, 3072, 4096 };
    for (size_t i = 0; i < COUNT(sizes); i++)
    {
        CK_ATTRIBUTE other[] = { ATTR(CKA_MODULUS_BITS, sizes[i]), pub[1] };
        char msg[64];
        snprintf(msg, sizeof(msg), "%lu bits -> CKR_TEMPLATE_INCONSISTENT", sizes[i]);
        CHECK(pair(other, 2, priv, 1) == CKR_TEMPLATE_INCONSISTENT, msg);
    }
    CK_ATTRIBUTE bits_in_priv[] = { priv[0], ATTR(CKA_MODULUS_BITS, g_bits) };
    CHECK(
        pair(pub, 2, bits_in_priv, 2) == CKR_TEMPLATE_INCONSISTENT,
        "a modulus size in the private template -> INCONSISTENT"
    );
    CK_BYTE n[4] = { 0x80, 1, 2, 3 };
    CK_BYTE e[3] = { 1, 0, 1 };
    CK_ATTRIBUTE with_n[] = { pub[0], pub[1], ATTR(CKA_MODULUS, n) };
    CK_ATTRIBUTE with_e[] = { pub[0], pub[1], ATTR(CKA_PUBLIC_EXPONENT, e) };
    CK_ATTRIBUTE e_in_priv[] = { priv[0], ATTR(CKA_PUBLIC_EXPONENT, e) };
    CHECK(pair(with_n, 3, priv, 1) == CKR_TEMPLATE_INCONSISTENT, "a modulus -> INCONSISTENT");
    CHECK(pair(with_e, 3, priv, 1) == CKR_OK, "a public exponent waits for the key");
    CHECK(
        pair(pub, 2, e_in_priv, 2) == CKR_TEMPLATE_INCONSISTENT,
        "a public exponent in the private template -> INCONSISTENT"
    );
    CK_ATTRIBUTE pub_cls[] = { pub[0], pub[1], ATTR(CKA_CLASS, g_private) };
    CK_ATTRIBUTE priv_cls[] = { priv[0], ATTR(CKA_CLASS, g_public) };
    CK_ATTRIBUTE good_cls[] = { priv[0], ATTR(CKA_CLASS, g_private), ATTR(CKA_KEY_TYPE, g_rsa) };
    CK_ATTRIBUTE aes_type[] = { priv[0], ATTR(CKA_KEY_TYPE, g_aes) };
    CHECK(
        (pair(pub_cls, 3, priv, 1) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(pub, 2, priv_cls, 2) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(pub, 2, good_cls, 3) == CKR_OK) &&
            (pair(pub, 2, aes_type, 2) == CKR_TEMPLATE_INCONSISTENT),
        "class and key type must be the half's"
    );
    CK_ATTRIBUTE extractable[] = { priv[0], ATTR(CKA_EXTRACTABLE, g_true) };
    CK_ATTRIBUTE open[] = { priv[0], ATTR(CKA_SENSITIVE, g_false) };
    CK_ATTRIBUTE closed[] = { priv[0],
                              ATTR(CKA_SENSITIVE, g_true),
                              ATTR(CKA_EXTRACTABLE, g_false) };
    CHECK(
        (pair(pub, 2, extractable, 2) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(pub, 2, open, 2) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(pub, 2, closed, 3) == CKR_OK),
        "the private key is sensitive and unextractable"
    );
    CK_ATTRIBUTE always_auth[] = { priv[0], ATTR(CKA_ALWAYS_AUTHENTICATE, g_true) };
    CK_ATTRIBUTE no_always_auth[] = { priv[0], ATTR(CKA_ALWAYS_AUTHENTICATE, g_false) };
    CHECK(
        (pair(pub, 2, always_auth, 2) == CKR_ATTRIBUTE_VALUE_INVALID) &&
            (pair(pub, 2, no_always_auth, 2) == CKR_OK),
        "CKA_ALWAYS_AUTHENTICATE TRUE -> CKR_ATTRIBUTE_VALUE_INVALID (no context-specific login)"
    );
    CK_ATTRIBUTE public_session[] = { priv[0], ATTR(CKA_PRIVATE, g_false) };
    CK_ATTRIBUTE public_token[] = { priv[0], ATTR(CKA_TOKEN, g_true), ATTR(CKA_PRIVATE, g_false) };
    CHECK(
        (pair(pub, 2, public_session, 2) == CKR_OK) &&
            (pair(pub, 2, public_token, 3) == CKR_TEMPLATE_INCONSISTENT),
        "a token private key must be private; a session one need not be"
    );
    CK_MECHANISM_TYPE wrap_mech = CKM_RSA_AES_KEY_WRAP;
    CK_MECHANISM_TYPE mixed[] = { CKM_RSA_AES_KEY_WRAP, CKM_RSA_PKCS_OAEP };
    CK_ATTRIBUTE allowed_ok[] = { priv[0], ATTR(CKA_ALLOWED_MECHANISMS, wrap_mech) };
    CK_ATTRIBUTE allowed_mixed[] = { priv[0], ATTR(CKA_ALLOWED_MECHANISMS, mixed) };
    CK_ATTRIBUTE allowed_empty[] = { priv[0], { CKA_ALLOWED_MECHANISMS, mixed, 0 } };
    CHECK(
        (pair(pub, 2, allowed_ok, 2) == CKR_OK) &&
            (pair(pub, 2, allowed_mixed, 2) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(pub, 2, allowed_empty, 2) == CKR_TEMPLATE_INCONSISTENT),
        "CKA_ALLOWED_MECHANISMS may name CKM_RSA_AES_KEY_WRAP only"
    );
    CK_ATTRIBUTE allowed_ragged[] = { priv[0],
                                      { CKA_ALLOWED_MECHANISMS, mixed, sizeof(wrap_mech) + 1 } };
    CHECK(
        pair(pub, 2, allowed_ragged, 2) == CKR_ATTRIBUTE_VALUE_INVALID,
        "a CKA_ALLOWED_MECHANISMS length that is not whole mechanism types is refused, not "
        "truncated"
    );
    CK_ATTRIBUTE dup[] = { priv[0], priv[0] };
    CK_BYTE d[4] = { 1, 2, 3, 4 };
    CK_ATTRIBUTE material[] = { priv[0], ATTR(CKA_PRIVATE_EXPONENT, d) };
    CK_ATTRIBUTE local[] = { priv[0], ATTR(CKA_LOCAL, g_true) };
    CK_ATTRIBUTE short_bool[] = { priv[0], { CKA_TOKEN, &g_bits, sizeof(g_bits) } };
    CK_ATTRIBUTE array[] = { priv[0], { CKA_UNWRAP_TEMPLATE, NULL, 0 } };
    CHECK(
        (pair(pub, 2, dup, 2) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(pub, 2, material, 2) == CKR_TEMPLATE_INCONSISTENT) &&
            (pair(pub, 2, local, 2) == CKR_ATTRIBUTE_READ_ONLY) &&
            (pair(pub, 2, short_bool, 2) == CKR_ATTRIBUTE_VALUE_INVALID) &&
            (pair(pub, 2, array, 2) == CKR_ATTRIBUTE_TYPE_INVALID),
        "duplicates, key material, token-set attributes, shapes and arrays"
    );
}

/* ========================================================================= */
/* The stored templates and the SubjectPublicKeyInfo walk                    */
/* ========================================================================= */

/* Whether `full` carries `type` with exactly `len` bytes equal to `v`. */
static bool has(
    const CK_ATTRIBUTE *full,
    CK_ULONG n,
    CK_ATTRIBUTE_TYPE type,
    const void *v,
    CK_ULONG len
)
{
    const CK_ATTRIBUTE *a = tsra_pkcs11_tmpl_find(full, n, type);
    return (a != NULL) && (a->ulValueLen == len) && (memcmp(a->pValue, v, len) == 0);
}

static void test_build(void)
{
    printf("== spki_rsa and unwrapping_half_build ==\n");
    tsra_pkcs11_rsa_public key;
    CHECK(
        tsra_pkcs11_spki_rsa(SPKI, sizeof(SPKI), &key) && (key.n == SPKI + SPKI_N_OFFSET) &&
            (key.n_len == SPKI_N_LEN) && (key.e_len == 3) && (key.e[0] == 1) && (key.e[2] == 1),
        "a real RSA-1024 SPKI -> its modulus without the zero octet and 65537"
    );
    CK_BYTE broken[sizeof(SPKI) + 1];
    memcpy(broken, SPKI, sizeof(SPKI));
    broken[sizeof(SPKI)] = 0;
    CHECK(!tsra_pkcs11_spki_rsa(broken, sizeof(SPKI) + 1, &key), "a trailing byte is refused");
    CHECK(!tsra_pkcs11_spki_rsa(SPKI, sizeof(SPKI) - 1, &key), "a truncated SPKI is refused");
    struct
    {
        size_t at;
        CK_BYTE value;
        const char *what;
    } edits[] = {
        { 0, 0x31, "a SET instead of the outer SEQUENCE" },
        { 1, 0x80, "an indefinite length" },
        { 1, 0x85, "five length octets" },
        { 15, 0x02, "another algorithm (rsaEncryption's last arc)" },
        { 21, 0x01, "unused bits in the key's BIT STRING" },
        { 28, 0x80, "a negative modulus" },
        { 25, 0x03, "a BIT STRING where the modulus INTEGER is" },
    };
    for (size_t i = 0; i < COUNT(edits); i++)
    {
        memcpy(broken, SPKI, sizeof(SPKI));
        broken[edits[i].at] = edits[i].value;
        char msg[96];
        snprintf(msg, sizeof(msg), "%s is refused", edits[i].what);
        CHECK(!tsra_pkcs11_spki_rsa(broken, sizeof(SPKI), &key), msg);
    }
    CHECK(!tsra_pkcs11_spki_rsa(NULL, 0, &key), "NULL DER is refused");

    CHECK(tsra_pkcs11_spki_rsa(SPKI, sizeof(SPKI), &key), "the key again");
    tsra_pkcs11_pair_fill fill;
    memset(&fill, 0xA5, sizeof(fill)); /* every field must be written by the builder */
    CK_ATTRIBUTE full[8 + UNWRAPPING_PAIR_APPENDED_ATTRS];
    CK_ULONG n = 0;
    CK_ATTRIBUTE priv[] = { ATTR(CKA_UNWRAP, g_true) };
    CK_BYTE id[TSRA_PKCS11_SHA1_DIGEST_LEN];
    tsra_pkcs11_digest_op_t *sha1 = NULL;
    (void)tsra_pkcs11_digest_op_new(CKM_SHA_1, &sha1);
    tsra_pkcs11_digest_op_update(sha1, key.n, key.n_len);
    tsra_pkcs11_digest_op_final(sha1, id);
    tsra_pkcs11_digest_op_free(sha1);
    CK_OBJECT_CLASS priv_cls = CKO_PRIVATE_KEY;
    CK_MECHANISM_TYPE kgm = CKM_RSA_PKCS_KEY_PAIR_GEN;
    CK_MECHANISM_TYPE wrap_mech = CKM_RSA_AES_KEY_WRAP;
    CHECK(
        (tsra_pkcs11_unwrapping_half_build(true, priv, 1, &key, &fill, full, &n) == CKR_OK) &&
            (n == 1 + UNWRAPPING_PAIR_APPENDED_ATTRS) && (full[0].pValue == &g_true),
        "private half: the caller's template first, every default appended"
    );
    CHECK(
        has(full, n, CKA_CLASS, &priv_cls, sizeof(priv_cls)) &&
            has(full, n, CKA_KEY_TYPE, &g_rsa, sizeof(g_rsa)) &&
            has(full, n, CKA_PRIVATE, &g_true, sizeof(g_true)) &&
            has(full, n, CKA_ID, id, sizeof(id)) && has(full, n, CKA_MODULUS, key.n, key.n_len) &&
            has(full, n, CKA_PUBLIC_EXPONENT, key.e, key.e_len) &&
            has(full, n, CKA_DECRYPT, &g_false, sizeof(g_false)) &&
            has(full, n, CKA_SIGN, &g_false, sizeof(g_false)) &&
            has(full, n, CKA_SIGN_RECOVER, &g_false, sizeof(g_false)) &&
            has(full, n, CKA_DERIVE, &g_false, sizeof(g_false)) &&
            has(full, n, CKA_ALLOWED_MECHANISMS, &wrap_mech, sizeof(wrap_mech)) &&
            has(full, n, CKA_SENSITIVE, &g_true, sizeof(g_true)) &&
            has(full, n, CKA_EXTRACTABLE, &g_false, sizeof(g_false)) &&
            has(full, n, CKA_ALWAYS_SENSITIVE, &g_true, sizeof(g_true)) &&
            has(full, n, CKA_NEVER_EXTRACTABLE, &g_true, sizeof(g_true)) &&
            has(full, n, CKA_LOCAL, &g_true, sizeof(g_true)) &&
            has(full, n, CKA_KEY_GEN_MECHANISM, &kgm, sizeof(kgm)),
        "private half: class, type, private, the SHA-1 ID, the public parts, usages, "
        "sensitivity and origin"
    );

    char label[] = "mine";
    CK_BYTE my_id[] = { 7 };
    CK_BYTE e_padded[] = { 0, 0, 1, 0, 1 };
    CK_ATTRIBUTE pub[] = {
        ATTR(CKA_MODULUS_BITS, g_bits), ATTR(CKA_WRAP, g_true),
        ATTR(CKA_LABEL, label),         ATTR(CKA_ID, my_id),
        ATTR(CKA_PRIVATE, g_true),      ATTR(CKA_PUBLIC_EXPONENT, e_padded),
    };
    CK_OBJECT_CLASS pub_cls = CKO_PUBLIC_KEY;
    CHECK(
        (tsra_pkcs11_unwrapping_half_build(false, pub, COUNT(pub), &key, &fill, full, &n) == CKR_OK
        ) && (n <= COUNT(pub) + UNWRAPPING_PAIR_APPENDED_ATTRS) &&
            has(full, n, CKA_CLASS, &pub_cls, sizeof(pub_cls)) &&
            has(full, n, CKA_ID, my_id, sizeof(my_id)) &&
            has(full, n, CKA_PRIVATE, &g_true, sizeof(g_true)) &&
            has(full, n, CKA_PUBLIC_EXPONENT, e_padded, sizeof(e_padded)) &&
            has(full, n, CKA_ENCRYPT, &g_false, sizeof(g_false)) &&
            has(full, n, CKA_VERIFY, &g_false, sizeof(g_false)) &&
            has(full, n, CKA_VERIFY_RECOVER, &g_false, sizeof(g_false)) &&
            has(full, n, CKA_MODULUS, key.n, key.n_len) &&
            (tsra_pkcs11_tmpl_find(full, n, CKA_SENSITIVE) == NULL),
        "public half: the caller's ID, CKA_PRIVATE and exponent win; no sensitivity"
    );
    CK_BYTE e3[] = { 3 };
    CK_ATTRIBUTE pub_e3[] = { ATTR(CKA_MODULUS_BITS, g_bits), ATTR(CKA_PUBLIC_EXPONENT, e3) };
    CHECK(
        tsra_pkcs11_unwrapping_half_build(false, pub_e3, 2, &key, &fill, full, &n) ==
            CKR_TEMPLATE_INCONSISTENT,
        "an exponent other than the key's -> CKR_TEMPLATE_INCONSISTENT"
    );
    CHECK(
        (tsra_pkcs11_unwrapping_half_build(true, NULL, 1, &key, &fill, full, &n) ==
         CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_unwrapping_half_build(true, priv, 1, NULL, &fill, full, &n) ==
             CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_unwrapping_half_build(true, priv, 1, &key, NULL, full, &n) ==
             CKR_ARGUMENTS_BAD),
        "NULL arguments -> CKR_ARGUMENTS_BAD"
    );
}

/* ========================================================================= */
/* DER lengths                                                               */
/* ========================================================================= */

/* What rsa_spki writes besides the fixed parts below. */
#define TAG_INTEGER 0x02
#define TAG_BIT_STRING 0x03
#define TAG_SEQUENCE 0x30
#define LONG_FORM 0x80
#define TLV_HEAD 2   /* the tag and the first length byte */
#define N_BYTE 0x5A  /* every modulus byte: positive, so no sign byte */
#define SPKI_MAX 320 /* an SPKI with a modulus of up to 256 bytes */

/* The AlgorithmIdentifier's parts: the tags its parameters are tested with,
 * and rsaEncryption, 1.2.840.113549.1.1.1 (RFC 3279), as a DER OID TLV. */
#define TAG_OCTET_STRING 0x04
#define TAG_NULL 0x05
#define TAG_OID 0x06
#define RSA_OID_LEN 9
#define RSA_OID_TLV TAG_OID, RSA_OID_LEN, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
#define RSA_OID_TLV_LEN (TLV_HEAD + RSA_OID_LEN)
/* The content length of AlgorithmIdentifier { rsaEncryption, NULL }. */
#define ALG_NULL_LEN (RSA_OID_TLV_LEN + TLV_HEAD)
/* AlgorithmIdentifier { rsaEncryption, NULL } and INTEGER 65537 in DER. */
static const CK_BYTE RSA_ALG[] = { TAG_SEQUENCE, ALG_NULL_LEN, RSA_OID_TLV, TAG_NULL, 0 };
_Static_assert(sizeof(RSA_ALG) == TLV_HEAD + ALG_NULL_LEN, "RSA_OID_LEN counts the OID's bytes");
static const CK_BYTE E_65537[] = { 0x02, 0x03, 0x01, 0x00, 0x01 };

/* The fewest long-form length bytes `len` needs; 0 for the short form. */
static size_t min_len_bytes(size_t len)
{
    return (len < LONG_FORM) ? 0 : ((len <= UINT8_MAX) ? 1 : 2);
}

/* Write `tag` and `len` at out + *k, the length in `len_bytes` long-form
 * length bytes (0 for the short form). */
static void put_head(CK_BYTE *out, size_t *k, CK_BYTE tag, size_t len, size_t len_bytes)
{
    out[(*k)++] = tag;
    if (len_bytes == 0)
    {
        out[(*k)++] = (CK_BYTE)len;
        return;
    }
    out[(*k)++] = (CK_BYTE)(LONG_FORM | len_bytes);
    for (size_t i = len_bytes; i > 0; i--)
    {
        out[(*k)++] = (CK_BYTE)(len >> (CHAR_BIT * (i - 1)));
    }
}

/*
 * A SubjectPublicKeyInfo with the DER AlgorithmIdentifier `alg`, exponent 65537
 * and a modulus of `n_len` N_BYTE bytes, whose INTEGER length takes
 * `n_len_bytes` long-form length bytes (0 for the short form); every other
 * length is minimal. Returns its length; `out` holds SPKI_MAX bytes.
 */
static size_t spki_with_alg(
    CK_BYTE *out,
    const CK_BYTE *alg,
    size_t alg_len,
    size_t n_len,
    size_t n_len_bytes
)
{
    size_t rsa = (TLV_HEAD + n_len_bytes + n_len) + sizeof(E_65537);
    size_t bits = 1 + (TLV_HEAD + min_len_bytes(rsa) + rsa);
    size_t outer = alg_len + (TLV_HEAD + min_len_bytes(bits) + bits);
    size_t k = 0;
    put_head(out, &k, TAG_SEQUENCE, outer, min_len_bytes(outer));
    memcpy(out + k, alg, alg_len);
    k += alg_len;
    put_head(out, &k, TAG_BIT_STRING, bits, min_len_bytes(bits));
    out[k++] = 0; /* no unused bits */
    put_head(out, &k, TAG_SEQUENCE, rsa, min_len_bytes(rsa));
    put_head(out, &k, TAG_INTEGER, n_len, n_len_bytes);
    memset(out + k, N_BYTE, n_len);
    k += n_len;
    memcpy(out + k, E_65537, sizeof(E_65537));
    return k + sizeof(E_65537);
}

/* spki_with_alg with { rsaEncryption, NULL }. */
static size_t rsa_spki(CK_BYTE *out, size_t n_len, size_t n_len_bytes)
{
    return spki_with_alg(out, RSA_ALG, sizeof(RSA_ALG), n_len, n_len_bytes);
}

static void test_der_lengths(void)
{
    printf("== spki_rsa: DER lengths ==\n");
    /* Only the modulus length varies; DER allows exactly one encoding of it. */
    struct
    {
        size_t n_len;
        size_t len_bytes;
        bool ok;
        const char *what;
    } rows[] = {
        { 127, 0, true, "a 127-byte modulus with a short-form length is read" },
        { 127, 1, false, "a 127-byte modulus with a long-form length is refused" },
        { 128, 1, true, "a 128-byte modulus with one length byte is read" },
        { 255, 1, true, "a 255-byte modulus with one length byte is read" },
        { 255, 2, false, "a 255-byte modulus with a leading zero length byte is refused" },
        { 256, 2, true, "a 256-byte modulus with two length bytes is read" },
    };
    for (size_t i = 0; i < COUNT(rows); i++)
    {
        CK_BYTE spki[SPKI_MAX];
        size_t len = rsa_spki(spki, rows[i].n_len, rows[i].len_bytes);
        tsra_pkcs11_rsa_public key;
        bool ok = tsra_pkcs11_spki_rsa(spki, len, &key);
        CHECK((ok == rows[i].ok) && (!ok || (key.n_len == rows[i].n_len)), rows[i].what);
    }
}

static void test_alg_params(void)
{
    printf("== spki_rsa: AlgorithmIdentifier parameters ==\n");
    static const CK_BYTE absent[] = { TAG_SEQUENCE, RSA_OID_TLV_LEN, RSA_OID_TLV };
    static const CK_BYTE truncated[] = { TAG_SEQUENCE, ALG_NULL_LEN, RSA_OID_TLV, TAG_NULL, 1 };
    static const CK_BYTE content[] = {
        TAG_SEQUENCE, ALG_NULL_LEN + 1, RSA_OID_TLV, TAG_NULL, 1, 0
    };
    static const CK_BYTE trailing[] = {
        TAG_SEQUENCE, ALG_NULL_LEN + 1, RSA_OID_TLV, TAG_NULL, 0, 0
    };
    static const CK_BYTE other[] = { TAG_SEQUENCE, ALG_NULL_LEN, RSA_OID_TLV, TAG_OCTET_STRING, 0 };
    struct
    {
        const CK_BYTE *alg;
        size_t len;
        bool ok;
        const char *what;
    } rows[] = {
        { RSA_ALG, sizeof(RSA_ALG), true, "NULL parameters are read" },
        { absent, sizeof(absent), false, "absent parameters are refused" },
        { truncated, sizeof(truncated), false, "a NULL whose length runs past the end is refused" },
        { content, sizeof(content), false, "a NULL with content is refused" },
        { trailing, sizeof(trailing), false, "a byte after the NULL is refused" },
        { other, sizeof(other), false, "an OCTET STRING instead of the NULL is refused" },
    };
    for (size_t i = 0; i < COUNT(rows); i++)
    {
        CK_BYTE spki[SPKI_MAX];
        size_t len = spki_with_alg(
            spki,
            rows[i].alg,
            rows[i].len,
            RSA_UNWRAP_MODULUS_BYTES,
            min_len_bytes(RSA_UNWRAP_MODULUS_BYTES)
        );
        tsra_pkcs11_rsa_public key;
        CHECK(tsra_pkcs11_spki_rsa(spki, len, &key) == rows[i].ok, rows[i].what);
    }
}

static void test_match(void)
{
    printf("== unwrapping_key_match ==\n");
    CK_BYTE spki[SPKI_MAX];
    size_t len = rsa_spki(spki, RSA_UNWRAP_MODULUS_BYTES, min_len_bytes(RSA_UNWRAP_MODULUS_BYTES));
    CK_BYTE n[RSA_UNWRAP_MODULUS_BYTES];
    memset(n, N_BYTE, sizeof(n));
    CHECK(
        tsra_pkcs11_unwrapping_key_match(spki, len, n, sizeof(n)) == CKR_OK,
        "the device key's own modulus -> CKR_OK"
    );
    n[sizeof(n) - 1] ^= 1;
    CHECK(
        tsra_pkcs11_unwrapping_key_match(spki, len, n, sizeof(n)) ==
            CKR_UNWRAPPING_KEY_HANDLE_INVALID,
        "another modulus -> CKR_UNWRAPPING_KEY_HANDLE_INVALID"
    );
    n[sizeof(n) - 1] ^= 1;
    CHECK(
        (tsra_pkcs11_unwrapping_key_match(spki, len, n, sizeof(n) - 1) ==
         CKR_UNWRAPPING_KEY_HANDLE_INVALID) &&
            (tsra_pkcs11_unwrapping_key_match(spki, len, NULL, 0) ==
             CKR_UNWRAPPING_KEY_HANDLE_INVALID),
        "a shorter modulus or none -> CKR_UNWRAPPING_KEY_HANDLE_INVALID"
    );
    CHECK(
        tsra_pkcs11_unwrapping_key_match(SPKI, sizeof(SPKI), SPKI + SPKI_N_OFFSET, SPKI_N_LEN) ==
            CKR_DEVICE_ERROR,
        "a device key of another size -> CKR_DEVICE_ERROR, even with its own modulus"
    );
}

/* ========================================================================= */
/* Private-key targets (src/tsra_pkcs11_unwrap_private.c)                    */
/* ========================================================================= */

/*
 * The blob lengths of private keys. EC: OpenSSL's PKCS#8 of P-256, P-384 and
 * P-521 keys with their public point is 138, 185 and 241 bytes; RFC 5649 pads
 * that to 144, 192 and 248 and adds 8, after the 256-byte OAEP block: 408,
 * 456 and 512. RSA: every component at its shortest DER encoding the firmware
 * takes (a modulus of k bytes, primes of k/2, a 1-byte exponent, private
 * exponent and CRT values) gives a 2048-bit PKCS#8 of 570 bytes, a blob of
 * 840; at its longest (sign bytes, a 4-byte exponent) 1222, 1798 and 2379
 * bytes for 2048, 3072 and 4096 bits, blobs of 1488, 2064 and 2648. Each size
 * starts one semiblock above the longest of the size below.
 */
#define SEMIBLOCK 8
static const struct
{
    CK_KEY_TYPE kt;
    CK_ULONG len;
    CK_RV want;
    CK_ULONG bits;
    tsra_pkcs11_ec_curve_t curve;
} WINDOWS[] = {
    { CKK_EC, 408, CKR_OK, 0, TSRA_PKCS11_CURVE_P256 },
    { CKK_EC, 456, CKR_OK, 0, TSRA_PKCS11_CURVE_P384 },
    { CKK_EC, 512, CKR_OK, 0, TSRA_PKCS11_CURVE_P521 },
    { CKK_EC, 408 - SEMIBLOCK, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_EC, 408 + SEMIBLOCK, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_EC, 456 - SEMIBLOCK, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_EC, 512 + SEMIBLOCK, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_EC, 1488, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 0, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 512, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 840 - SEMIBLOCK, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 840, CKR_OK, 2048, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 1488, CKR_OK, 2048, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 1487, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 1489, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 1488 + SEMIBLOCK, CKR_OK, 3072, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 2064, CKR_OK, 3072, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 2064 + SEMIBLOCK, CKR_OK, 4096, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 2640, CKR_OK, 4096, TSRA_PKCS11_CURVE_NONE }, /* OpenSSL's 2374 bytes */
    { CKK_RSA, 2648, CKR_OK, 4096, TSRA_PKCS11_CURVE_NONE },
    { CKK_RSA, 2648 + SEMIBLOCK, CKR_WRAPPED_KEY_LEN_RANGE, 0, TSRA_PKCS11_CURVE_NONE },
};

static void test_private_windows(void)
{
    printf("== private_blob_size ==\n");
    for (size_t i = 0; i < COUNT(WINDOWS); i++)
    {
        CK_ULONG bits = 1;
        tsra_pkcs11_ec_curve_t curve = TSRA_PKCS11_CURVE_P256;
        CK_RV rv = tsra_pkcs11_private_blob_size(WINDOWS[i].kt, WINDOWS[i].len, &bits, &curve);
        char msg[128];
        snprintf(
            msg,
            sizeof(msg),
            "%s blob of %lu bytes -> 0x%lx, %lu bits, curve %d",
            (WINDOWS[i].kt == CKK_RSA) ? "an RSA" : "an EC",
            WINDOWS[i].len,
            WINDOWS[i].want,
            WINDOWS[i].bits,
            (int)WINDOWS[i].curve
        );
        CHECK(
            (rv == WINDOWS[i].want) && (bits == WINDOWS[i].bits) && (curve == WINDOWS[i].curve),
            msg
        );
    }
    CK_ULONG bits = 0;
    tsra_pkcs11_ec_curve_t curve = TSRA_PKCS11_CURVE_NONE;
    CHECK(
        (tsra_pkcs11_private_blob_size(CKK_RSA, 1488, NULL, &curve) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_private_blob_size(CKK_RSA, 1488, &bits, NULL) == CKR_ARGUMENTS_BAD),
        "NULL outputs -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        tsra_pkcs11_private_blob_size(CKK_AES, 1488, &bits, &curve) == CKR_ARGUMENTS_BAD,
        "another key type -> CKR_ARGUMENTS_BAD"
    );
}

static CK_KEY_TYPE g_ec = CKK_EC;
static CK_OBJECT_CLASS g_wide_class[2] = { CKO_PRIVATE_KEY, CKO_PRIVATE_KEY };
static CK_ULONG g_wide_bool = CK_TRUE;
static CK_BYTE g_material[4] = { 0x0A, 0x0B, 0x0C, 0x0D };
static CK_BYTE g_p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static CK_BYTE g_p384[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static CK_BYTE g_bad_params[] = { 0x06, 0x05, 0x2b };
/* secp256k1, a named curve the token does not support. */
static CK_BYTE g_secp256k1[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a };
static CK_MECHANISM_TYPE g_one_mech = CKM_SHA256_RSA_PKCS;
static CK_MECHANISM_TYPE g_many_mechs[KEYGEN_MAX_ALLOWED_MECHS + 1];
static char g_name[] = "imported";

/* The private-key verdicts, each template judged at `len`. */
typedef struct
{
    const char *what;
    CK_ATTRIBUTE tmpl[6];
    CK_ULONG count;
    CK_ULONG len;
    CK_RV want;
} private_case;

#define RSA_PRIV ATTR(CKA_CLASS, g_private), ATTR(CKA_KEY_TYPE, g_rsa)
#define EC_PRIV ATTR(CKA_CLASS, g_private), ATTR(CKA_KEY_TYPE, g_ec)
#define RSA_BLOB 1488
#define EC_BLOB 456

static const private_case PRIVATE_CASES[] = {
    { "RSA, CKA_SIGN", { RSA_PRIV, ATTR(CKA_SIGN, g_true) }, 3, RSA_BLOB, CKR_OK },
    { "RSA, CKA_DECRYPT", { RSA_PRIV, ATTR(CKA_DECRYPT, g_true) }, 3, RSA_BLOB, CKR_OK },
    { "RSA, CKA_SIGN with CKA_DECRYPT FALSE",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_DECRYPT, g_false) },
      4,
      RSA_BLOB,
      CKR_OK },
    { "EC, CKA_SIGN", { EC_PRIV, ATTR(CKA_SIGN, g_true) }, 3, EC_BLOB, CKR_OK },
    { "EC, CKA_DERIVE", { EC_PRIV, ATTR(CKA_DERIVE, g_true) }, 3, EC_BLOB, CKR_OK },
    { "no class",
      { ATTR(CKA_KEY_TYPE, g_rsa), ATTR(CKA_SIGN, g_true) },
      2,
      RSA_BLOB,
      CKR_TEMPLATE_INCOMPLETE },
    { "no key type",
      { ATTR(CKA_CLASS, g_private), ATTR(CKA_SIGN, g_true) },
      2,
      RSA_BLOB,
      CKR_TEMPLATE_INCOMPLETE },
    { "a secret class",
      { ATTR(CKA_CLASS, g_secret), ATTR(CKA_KEY_TYPE, g_rsa), ATTR(CKA_SIGN, g_true) },
      3,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "a class of the wrong width",
      { ATTR(CKA_CLASS, g_wide_class), ATTR(CKA_KEY_TYPE, g_rsa), ATTR(CKA_SIGN, g_true) },
      3,
      RSA_BLOB,
      CKR_ATTRIBUTE_VALUE_INVALID },
    { "an AES key type",
      { ATTR(CKA_CLASS, g_private), ATTR(CKA_KEY_TYPE, g_aes), ATTR(CKA_SIGN, g_true) },
      3,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "RSA signs and decrypts",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_DECRYPT, g_true) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "RSA with no usage", { RSA_PRIV }, 2, RSA_BLOB, CKR_TEMPLATE_INCONSISTENT },
    { "RSA with only usages FALSE",
      { RSA_PRIV, ATTR(CKA_SIGN, g_false) },
      3,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "RSA unwraps",
      { RSA_PRIV, ATTR(CKA_UNWRAP, g_true) },
      3,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "RSA derives",
      { RSA_PRIV, ATTR(CKA_DERIVE, g_true) },
      3,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "RSA signs with recovery",
      { RSA_PRIV, ATTR(CKA_SIGN_RECOVER, g_true) },
      3,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "RSA signs and verifies",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_VERIFY, g_true) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "EC signs and derives",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_DERIVE, g_true) },
      4,
      EC_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "EC decrypts",
      { EC_PRIV, ATTR(CKA_DECRYPT, g_true) },
      3,
      EC_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "a usage of the wrong width",
      { RSA_PRIV, ATTR(CKA_SIGN, g_wide_bool) },
      3,
      RSA_BLOB,
      CKR_ATTRIBUTE_VALUE_INVALID },
    { "a repeated attribute",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_SIGN, g_true) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "CKA_LOCAL",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_LOCAL, g_false) },
      4,
      RSA_BLOB,
      CKR_ATTRIBUTE_READ_ONLY },
    { "CKA_NEVER_EXTRACTABLE",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_NEVER_EXTRACTABLE, g_true) },
      4,
      RSA_BLOB,
      CKR_ATTRIBUTE_READ_ONLY },
    { "a private exponent",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_PRIVATE_EXPONENT, g_material) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "a prime",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_PRIME_1, g_material) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "CKA_VALUE",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_VALUE, g_material) },
      4,
      EC_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "a modulus",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_MODULUS, g_material) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "a public exponent",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_PUBLIC_EXPONENT, g_material) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "a modulus size",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_MODULUS_BITS, g_bits) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "an EC point",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EC_POINT, g_material) },
      4,
      EC_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "not sensitive",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_SENSITIVE, g_false) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "sensitive",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_SENSITIVE, g_true) },
      4,
      RSA_BLOB,
      CKR_OK },
    { "extractable",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EXTRACTABLE, g_true) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "not extractable",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EXTRACTABLE, g_false) },
      4,
      RSA_BLOB,
      CKR_OK },
    { "always authenticate",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_ALWAYS_AUTHENTICATE, g_true) },
      4,
      RSA_BLOB,
      CKR_ATTRIBUTE_VALUE_INVALID },
    { "not always authenticate",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_ALWAYS_AUTHENTICATE, g_false) },
      4,
      RSA_BLOB,
      CKR_OK },
    { "a public token key",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_TOKEN, g_true), ATTR(CKA_PRIVATE, g_false) },
      5,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "a public session key",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_PRIVATE, g_false) },
      4,
      RSA_BLOB,
      CKR_OK },
    { "an empty allowed list",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), { CKA_ALLOWED_MECHANISMS, g_many_mechs, 0 } },
      4,
      RSA_BLOB,
      CKR_ATTRIBUTE_VALUE_INVALID },
    { "an over-long allowed list",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_ALLOWED_MECHANISMS, g_many_mechs) },
      4,
      RSA_BLOB,
      CKR_ATTRIBUTE_VALUE_INVALID },
    { "an allowed list",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_ALLOWED_MECHANISMS, g_one_mech) },
      4,
      RSA_BLOB,
      CKR_OK },
    { "an attribute array",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), { CKA_UNWRAP_TEMPLATE, NULL, 0 } },
      4,
      RSA_BLOB,
      CKR_ATTRIBUTE_TYPE_INVALID },
    { "an RSA key with a curve",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EC_PARAMS, g_p256) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "the blob's curve",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EC_PARAMS, g_p384) },
      4,
      EC_BLOB,
      CKR_OK },
    { "another curve",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EC_PARAMS, g_p256) },
      4,
      EC_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "a malformed curve",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EC_PARAMS, g_bad_params) },
      4,
      EC_BLOB,
      CKR_ATTRIBUTE_VALUE_INVALID },
    { "an empty curve",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), { CKA_EC_PARAMS, g_p256, 0 } },
      4,
      EC_BLOB,
      CKR_ATTRIBUTE_VALUE_INVALID },
    { "an unsupported curve",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EC_PARAMS, g_secp256k1) },
      4,
      EC_BLOB,
      CKR_CURVE_NOT_SUPPORTED },
    { "a public key info",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_PUBLIC_KEY_INFO, g_material) },
      4,
      RSA_BLOB,
      CKR_TEMPLATE_INCONSISTENT },
    { "a malformed curve before the length",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EC_PARAMS, g_bad_params) },
      4,
      0,
      CKR_ATTRIBUTE_VALUE_INVALID },
    { "an RSA key in an EC blob",
      { RSA_PRIV, ATTR(CKA_SIGN, g_true) },
      3,
      EC_BLOB,
      CKR_WRAPPED_KEY_LEN_RANGE },
    { "an EC key in an RSA blob",
      { EC_PRIV, ATTR(CKA_SIGN, g_true) },
      3,
      RSA_BLOB,
      CKR_WRAPPED_KEY_LEN_RANGE },
    { "attribute verdicts before the class",
      { ATTR(CKA_KEY_TYPE, g_rsa), ATTR(CKA_LOCAL, g_true) },
      2,
      RSA_BLOB,
      CKR_ATTRIBUTE_READ_ONLY },
    { "the usage before the length", { RSA_PRIV }, 2, 0, CKR_TEMPLATE_INCONSISTENT },
    { "a curve that is not the blob's after the length",
      { EC_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_EC_PARAMS, g_p256) },
      4,
      0,
      CKR_WRAPPED_KEY_LEN_RANGE },
};

static void test_private_check(void)
{
    printf("== unwrap_private_check ==\n");
    for (size_t i = 0; i < COUNT(g_many_mechs); i++)
    {
        g_many_mechs[i] = CKM_SHA256_RSA_PKCS;
    }
    for (size_t i = 0; i < COUNT(PRIVATE_CASES); i++)
    {
        const private_case *c = &PRIVATE_CASES[i];
        tsra_pkcs11_private_target out;
        const char *why = NULL;
        CK_RV rv = tsra_pkcs11_unwrap_private_check(c->tmpl, c->count, c->len, &out, &why);
        char msg[160];
        snprintf(msg, sizeof(msg), "%s -> 0x%lx", c->what, c->want);
        CHECK((rv == c->want) && ((rv != CKR_TEMPLATE_INCONSISTENT) || (why != NULL)), msg);
    }
    tsra_pkcs11_private_target out;
    CK_ATTRIBUTE rsa[] = { RSA_PRIV, ATTR(CKA_DECRYPT, g_true), ATTR(CKA_TOKEN, g_true) };
    CHECK(
        (tsra_pkcs11_unwrap_private_check(rsa, COUNT(rsa), 2064, &out, NULL) == CKR_OK) &&
            (out.key_type == CKK_RSA) && (out.rsa_bits == 3072) &&
            (out.curve == TSRA_PKCS11_CURVE_NONE) && (out.usage == CKA_DECRYPT) && out.token,
        "an RSA decrypting token key at 2064 bytes -> 3072 bits, its use and CKA_TOKEN"
    );
    CK_ATTRIBUTE ec[] = { EC_PRIV, ATTR(CKA_DERIVE, g_true) };
    CHECK(
        (tsra_pkcs11_unwrap_private_check(ec, COUNT(ec), 512, &out, NULL) == CKR_OK) &&
            (out.key_type == CKK_EC) && (out.curve == TSRA_PKCS11_CURVE_P521) &&
            (out.usage == CKA_DERIVE) && !out.token,
        "an EC deriving session key at 512 bytes -> P-521"
    );
    CHECK(
        tsra_pkcs11_unwrap_private_check(rsa, COUNT(rsa), RSA_BLOB, NULL, NULL) ==
            CKR_ARGUMENTS_BAD,
        "NULL output -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        tsra_pkcs11_unwrap_private_check(NULL, 1, RSA_BLOB, &out, NULL) == CKR_ARGUMENTS_BAD,
        "a NULL template with a count -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        tsra_pkcs11_unwrap_private_check(rsa, TEMPLATE_MAX_ATTRS + 1, RSA_BLOB, &out, NULL) ==
            CKR_ARGUMENTS_BAD,
        "a count over TEMPLATE_MAX_ATTRS -> CKR_ARGUMENTS_BAD"
    );
}

/* Whether a built template holds each type once. */
static bool unique_types(const CK_ATTRIBUTE *t, CK_ULONG n)
{
    for (CK_ULONG i = 0; i < n; i++)
    {
        if (tsra_pkcs11_tmpl_find(t, i, t[i].type) != NULL)
        {
            return false;
        }
    }
    return true;
}

static bool has_bool(const CK_ATTRIBUTE *t, CK_ULONG n, CK_ATTRIBUTE_TYPE type, CK_BBOOL b)
{
    return has(t, n, type, &b, sizeof(b));
}

static void sha1(const CK_BYTE *in, CK_ULONG len, CK_BYTE *out)
{
    tsra_pkcs11_digest_op_t *op = NULL;
    if (tsra_pkcs11_digest_op_new(CKM_SHA_1, &op) == CKR_OK)
    {
        tsra_pkcs11_digest_op_update(op, in, len);
        tsra_pkcs11_digest_op_final(op, out);
        tsra_pkcs11_digest_op_free(op);
    }
}

static void test_private_build(void)
{
    printf("== unwrap_private_build ==\n");
    static const CK_ULONG k2048 = 256; /* the modulus bytes of the RSA-2048 SPKI below */
    CK_BYTE spki[SPKI_MAX];
    size_t spki_len = rsa_spki(spki, k2048, 2);
    CK_BYTE n[256];
    memset(n, N_BYTE, sizeof(n));
    CK_BYTE id[TSRA_PKCS11_SHA1_DIGEST_LEN];
    sha1(n, sizeof(n), id);
    CK_BYTE e[] = { 0x01, 0x00, 0x01 };
    CK_ULONG bits = 2048;
    CK_MECHANISM_TYPE none = CK_UNAVAILABLE_INFORMATION;
    CK_OBJECT_CLASS pub_cls = CKO_PUBLIC_KEY;

    tsra_pkcs11_private_target t = { CKK_RSA, 2048, TSRA_PKCS11_CURVE_NONE, CKA_SIGN, CK_FALSE };
    CK_ATTRIBUTE tmpl[] = { RSA_PRIV, ATTR(CKA_SIGN, g_true), ATTR(CKA_LABEL, g_name) };
    static tsra_pkcs11_private_fill fill;
    CK_ATTRIBUTE priv[COUNT(tmpl) + UNWRAP_PRIV_APPENDED_ATTRS];
    CK_ATTRIBUTE pub[UNWRAP_PUB_ATTRS];
    CK_ULONG np = 0;
    CK_ULONG nu = 0;
    CK_RV rv = tsra_pkcs11_unwrap_private_build(
        &t,
        tmpl,
        COUNT(tmpl),
        spki,
        spki_len,
        &fill,
        priv,
        &np,
        pub,
        &nu
    );
    CHECK(
        (rv == CKR_OK) && unique_types(priv, np) && unique_types(pub, nu),
        "RSA: each type once on both"
    );
    CHECK(
        (np >= COUNT(tmpl)) && (memcmp(priv, tmpl, sizeof(tmpl)) == 0),
        "RSA private key: the caller's template first, verbatim"
    );
    CHECK(
        has_bool(priv, np, CKA_PRIVATE, CK_TRUE) && has_bool(priv, np, CKA_SENSITIVE, CK_TRUE) &&
            has_bool(priv, np, CKA_EXTRACTABLE, CK_FALSE) &&
            has_bool(priv, np, CKA_LOCAL, CK_FALSE) &&
            has_bool(priv, np, CKA_ALWAYS_SENSITIVE, CK_FALSE) &&
            has_bool(priv, np, CKA_NEVER_EXTRACTABLE, CK_FALSE) &&
            has(priv, np, CKA_KEY_GEN_MECHANISM, &none, sizeof(none)),
        "RSA private key: private, sensitive, not extractable, and imported, not local"
    );
    CHECK(
        has_bool(priv, np, CKA_DECRYPT, CK_FALSE) &&
            has_bool(priv, np, CKA_SIGN_RECOVER, CK_FALSE) &&
            has_bool(priv, np, CKA_UNWRAP, CK_FALSE) && has_bool(priv, np, CKA_DERIVE, CK_FALSE),
        "RSA private key: the other usages FALSE"
    );
    CHECK(
        has(priv, np, CKA_MODULUS, n, sizeof(n)) &&
            has(priv, np, CKA_PUBLIC_EXPONENT, e, sizeof(e)) &&
            has(priv, np, CKA_ID, id, sizeof(id)) &&
            (tsra_pkcs11_tmpl_find(priv, np, CKA_MODULUS_BITS) == NULL),
        "RSA private key: the modulus and exponent of the SPKI, CKA_ID its SHA-1, no "
        "CKA_MODULUS_BITS"
    );
    CHECK(
        has(pub, nu, CKA_CLASS, &pub_cls, sizeof(pub_cls)) &&
            has(pub, nu, CKA_KEY_TYPE, &g_rsa, sizeof(g_rsa)) &&
            has_bool(pub, nu, CKA_TOKEN, CK_FALSE) && has_bool(pub, nu, CKA_PRIVATE, CK_FALSE) &&
            has(pub, nu, CKA_ID, id, sizeof(id)) &&
            has(pub, nu, CKA_LABEL, g_name, sizeof(g_name)) &&
            has_bool(pub, nu, CKA_LOCAL, CK_FALSE) &&
            has(pub, nu, CKA_KEY_GEN_MECHANISM, &none, sizeof(none)),
        "RSA public key: a session public key with the template's label and the same ID"
    );
    CHECK(
        has_bool(pub, nu, CKA_VERIFY, CK_TRUE) && has_bool(pub, nu, CKA_ENCRYPT, CK_FALSE) &&
            has_bool(pub, nu, CKA_VERIFY_RECOVER, CK_FALSE) &&
            has_bool(pub, nu, CKA_WRAP, CK_FALSE) && has_bool(pub, nu, CKA_DERIVE, CK_FALSE),
        "RSA public key of a signing key: verifies only"
    );
    CHECK(
        has(pub, nu, CKA_MODULUS, n, sizeof(n)) &&
            has(pub, nu, CKA_PUBLIC_EXPONENT, e, sizeof(e)) &&
            has(pub, nu, CKA_MODULUS_BITS, &bits, sizeof(bits)) &&
            (tsra_pkcs11_tmpl_find(pub, nu, CKA_SENSITIVE) == NULL),
        "RSA public key: modulus, exponent and CKA_MODULUS_BITS"
    );

    /* A decrypting token key with its own ID. */
    CK_BYTE my_id[] = { 'i', 'd' };
    CK_ATTRIBUTE dec[] = { RSA_PRIV,
                           ATTR(CKA_DECRYPT, g_true),
                           ATTR(CKA_TOKEN, g_true),
                           ATTR(CKA_ID, my_id) };
    t.usage = CKA_DECRYPT;
    t.token = CK_TRUE;
    CK_ATTRIBUTE priv2[COUNT(dec) + UNWRAP_PRIV_APPENDED_ATTRS];
    rv = tsra_pkcs11_unwrap_private_build(
        &t,
        dec,
        COUNT(dec),
        spki,
        spki_len,
        &fill,
        priv2,
        &np,
        pub,
        &nu
    );
    CHECK(
        (rv == CKR_OK) && unique_types(priv2, np) && has(priv2, np, CKA_ID, my_id, sizeof(my_id)) &&
            has(pub, nu, CKA_ID, my_id, sizeof(my_id)) && has_bool(pub, nu, CKA_TOKEN, CK_TRUE) &&
            has_bool(pub, nu, CKA_ENCRYPT, CK_TRUE) && has_bool(pub, nu, CKA_VERIFY, CK_FALSE) &&
            has_bool(priv2, np, CKA_SIGN, CK_FALSE) &&
            (tsra_pkcs11_tmpl_find(pub, nu, CKA_LABEL) == NULL),
        "RSA decrypting token key: the template's ID and CKA_TOKEN on both, an encrypting public "
        "key"
    );

    /* EC: the point from an SPKI the EC encoder writes. */
    CK_BYTE point[1 + (2 * 32)];
    memset(point, 0x11, sizeof(point));
    point[0] = EC_POINT_UNCOMPRESSED;
    CK_BYTE ec_spki[EC_SPKI_DER_MAX];
    CK_ULONG ec_spki_len = sizeof(ec_spki);
    CK_RV enc = tsra_pkcs11_ec_spki_from_point(
        TSRA_PKCS11_CURVE_P256,
        point,
        sizeof(point),
        ec_spki,
        &ec_spki_len
    );
    CK_BYTE point_id[TSRA_PKCS11_SHA1_DIGEST_LEN];
    sha1(point, sizeof(point), point_id);
    CK_BYTE der_point[2 + sizeof(point)] = { 0x04, (CK_BYTE)sizeof(point) };
    memcpy(der_point + 2, point, sizeof(point));
    tsra_pkcs11_private_target et = { CKK_EC, 0, TSRA_PKCS11_CURVE_P256, CKA_DERIVE, CK_FALSE };
    CK_ATTRIBUTE ec[] = { EC_PRIV, ATTR(CKA_DERIVE, g_true), ATTR(CKA_EC_PARAMS, g_p256) };
    CK_ATTRIBUTE priv3[COUNT(ec) + UNWRAP_PRIV_APPENDED_ATTRS];
    rv = tsra_pkcs11_unwrap_private_build(
        &et,
        ec,
        COUNT(ec),
        ec_spki,
        ec_spki_len,
        &fill,
        priv3,
        &np,
        pub,
        &nu
    );
    CHECK(
        (enc == CKR_OK) && (rv == CKR_OK) && unique_types(priv3, np) && unique_types(pub, nu) &&
            has(priv3, np, CKA_EC_PARAMS, g_p256, sizeof(g_p256)) &&
            (tsra_pkcs11_tmpl_find(priv3, np, CKA_EC_POINT) == NULL) &&
            (tsra_pkcs11_tmpl_find(priv3, np, CKA_MODULUS) == NULL) &&
            has(priv3, np, CKA_ID, point_id, sizeof(point_id)),
        "EC private key: the curve once, no point, CKA_ID the SHA-1 of the point"
    );
    CHECK(
        has(pub, nu, CKA_EC_PARAMS, g_p256, sizeof(g_p256)) &&
            has(pub, nu, CKA_EC_POINT, der_point, sizeof(der_point)) &&
            has(pub, nu, CKA_ID, point_id, sizeof(point_id)) &&
            has_bool(pub, nu, CKA_DERIVE, CK_TRUE) && has_bool(pub, nu, CKA_VERIFY, CK_FALSE) &&
            (tsra_pkcs11_tmpl_find(pub, nu, CKA_MODULUS) == NULL),
        "EC public key of a deriving key: derives, with the curve and the point in an OCTET STRING"
    );

    /* A public key info that is not the target's. */
    t.usage = CKA_SIGN;
    t.token = CK_FALSE;
    t.rsa_bits = 3072;
    CHECK(
        tsra_pkcs11_unwrap_private_build(
            &t,
            tmpl,
            COUNT(tmpl),
            spki,
            spki_len,
            &fill,
            priv,
            &np,
            pub,
            &nu
        ) == CKR_DEVICE_ERROR,
        "an RSA-2048 SPKI for a 3072-bit target -> CKR_DEVICE_ERROR"
    );
    t.rsa_bits = 2048;
    CHECK(
        tsra_pkcs11_unwrap_private_build(
            &t,
            tmpl,
            COUNT(tmpl),
            ec_spki,
            ec_spki_len,
            &fill,
            priv,
            &np,
            pub,
            &nu
        ) == CKR_DEVICE_ERROR,
        "an EC SPKI for an RSA target -> CKR_DEVICE_ERROR"
    );
    et.curve = TSRA_PKCS11_CURVE_P384;
    CHECK(
        tsra_pkcs11_unwrap_private_build(
            &et,
            ec,
            COUNT(ec),
            ec_spki,
            ec_spki_len,
            &fill,
            priv3,
            &np,
            pub,
            &nu
        ) == CKR_DEVICE_ERROR,
        "a P-256 SPKI for a P-384 target -> CKR_DEVICE_ERROR"
    );
    CHECK(
        tsra_pkcs11_unwrap_private_build(
            &t,
            tmpl,
            COUNT(tmpl),
            spki,
            spki_len - 1,
            &fill,
            priv,
            &np,
            pub,
            &nu
        ) == CKR_DEVICE_ERROR,
        "a truncated SPKI -> CKR_DEVICE_ERROR"
    );
    CHECK(
        (tsra_pkcs11_unwrap_private_build(
             NULL,
             tmpl,
             COUNT(tmpl),
             spki,
             spki_len,
             &fill,
             priv,
             &np,
             pub,
             &nu
         ) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_unwrap_private_build(
                 &t,
                 NULL,
                 1,
                 spki,
                 spki_len,
                 &fill,
                 priv,
                 &np,
                 pub,
                 &nu
             ) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_unwrap_private_build(
                 &t,
                 tmpl,
                 COUNT(tmpl),
                 NULL,
                 spki_len,
                 &fill,
                 priv,
                 &np,
                 pub,
                 &nu
             ) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_unwrap_private_build(
                 &t,
                 tmpl,
                 COUNT(tmpl),
                 spki,
                 spki_len,
                 &fill,
                 priv,
                 &np,
                 NULL,
                 &nu
             ) == CKR_ARGUMENTS_BAD),
        "NULL arguments -> CKR_ARGUMENTS_BAD"
    );
}

int main(void)
{
    test_params();
    test_template();
    test_unwrapping_key();
    test_pair_check();
    test_build();
    test_der_lengths();
    test_alg_params();
    test_match();
    test_private_windows();
    test_private_check();
    test_private_build();
    printf(
        g_fail ? "\nunwrap_params_test: FAILED (%d checks)\n"
               : "\nunwrap_params_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
