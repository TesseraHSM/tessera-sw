// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the device-free half of the EC slice: the key-pair template
 * logic and the EC encodings (src/tsra_pkcs11_ec_template.c) and the sign
 * mechanism table (src/tsra_pkcs11_template.c). No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src ec_template_test.c \
 *       ../src/tsra_pkcs11_ec_template.c ../src/tsra_pkcs11_template.c \
 *       ../src/tsra_pkcs11_attr_types.c -o ec_template_test && ./ec_template_test
 *
 * Covers the CKA_EC_PARAMS decoder (the three curves, other curves, explicit
 * parameters, malformed DER), the CKA_EC_POINT encoder from a public key info
 * (every curve, every malformation), the raw ECDSA length rule, the sign
 * mechanism table, the CK_RV matrix of tsra_pkcs11_ec_keygen_check (the
 * SIGN-or-DERIVE rule above all) and the append rules of
 * tsra_pkcs11_ec_keygen_build. Built with UBSan, so the misaligned templates
 * are real checks.
 */

#include "tsra_pkcs11_ec_template.h"
#include "tsra_pkcs11_template.h"

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
#define BOOL_ATTR(t, b)                                                                            \
    {                                                                                              \
        (t), (void *)&(b), sizeof(CK_BBOOL)                                                        \
    }

/* DER tags the test encodes with. */
#define TAG_OCTET_STRING 0x04
#define TAG_BIT_STRING 0x03
#define TAG_SEQUENCE 0x30

static const CK_BYTE OID_P256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static const CK_BYTE OID_P384[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static const CK_BYTE OID_P521[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
static const CK_BYTE OID_SECP256K1[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a };
static const CK_BYTE OID_EC_PUBLIC_KEY[] = { 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };

static CK_BBOOL g_true = CK_TRUE;
static CK_BBOOL g_false = CK_FALSE;
static CK_OBJECT_CLASS g_pub_cls = CKO_PUBLIC_KEY;
static CK_OBJECT_CLASS g_priv_cls = CKO_PRIVATE_KEY;
static CK_KEY_TYPE g_ec = CKK_EC;
static CK_BYTE g_p256[sizeof(OID_P256)];

typedef struct
{
    tsra_pkcs11_ec_curve_t curve;
    const CK_BYTE *oid;
    CK_ULONG oid_len;
    CK_ULONG coord;
    const char *name;
} curve_case;

static const curve_case CURVES[] = {
    { TSRA_PKCS11_CURVE_P256, OID_P256, sizeof(OID_P256), 32, "P-256" },
    { TSRA_PKCS11_CURVE_P384, OID_P384, sizeof(OID_P384), 48, "P-384" },
    { TSRA_PKCS11_CURVE_P521, OID_P521, sizeof(OID_P521), 66, "P-521" },
};

/* Write the DER element tag || length || content at `out`; returns its size. */
static size_t put_tlv(CK_BYTE *out, CK_BYTE tag, const CK_BYTE *content, size_t len)
{
    size_t n = 0;
    out[n++] = tag;
    if (len >= 0x80)
    {
        out[n++] = 0x81;
    }
    out[n++] = (CK_BYTE)len;
    memmove(out + n, content, len);
    return n + len;
}

/*
 * A SubjectPublicKeyInfo of an EC key on the curve `oid`, with an
 * uncompressed point whose coordinates are `coord` bytes of a pattern (the
 * walker does not judge the point). `bits_lead` is the unused-bits byte and
 * `point_lead` the point's first byte. Returns the encoding's size.
 */
static size_t make_spki(
    CK_BYTE *out,
    const CK_BYTE *oid,
    size_t oid_len,
    size_t coord,
    CK_BYTE bits_lead,
    CK_BYTE point_lead
)
{
    CK_BYTE alg_body[32];
    memcpy(alg_body, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY));
    memcpy(alg_body + sizeof(OID_EC_PUBLIC_KEY), oid, oid_len);
    CK_BYTE body[256];
    size_t n = put_tlv(body, TAG_SEQUENCE, alg_body, sizeof(OID_EC_PUBLIC_KEY) + oid_len);
    CK_BYTE bits[1 + EC_POINT_DER_MAX];
    bits[0] = bits_lead;
    bits[1] = point_lead;
    for (size_t i = 0; i < (2 * coord); i++)
    {
        bits[2 + i] = (CK_BYTE)(i + 1);
    }
    n += put_tlv(body + n, TAG_BIT_STRING, bits, 2 + (2 * coord));
    return put_tlv(out, TAG_SEQUENCE, body, n);
}

static void test_params(void)
{
    printf("== tsra_pkcs11_ec_params_curve ==\n");
    tsra_pkcs11_ec_curve_t curve = TSRA_PKCS11_CURVE_P256;
    for (size_t i = 0; i < COUNT(CURVES); i++)
    {
        CK_RV rv = tsra_pkcs11_ec_params_curve(CURVES[i].oid, CURVES[i].oid_len, &curve);
        CHECK((rv == CKR_OK) && (curve == CURVES[i].curve), CURVES[i].name);
        CHECK(
            tsra_pkcs11_ec_coord_len(CURVES[i].curve) == CURVES[i].coord,
            "its coordinate (and r and s) length"
        );
    }
    CHECK(
        (tsra_pkcs11_ec_params_curve(OID_SECP256K1, sizeof(OID_SECP256K1), &curve) ==
         CKR_CURVE_NOT_SUPPORTED) &&
            (curve == TSRA_PKCS11_CURVE_NONE),
        "secp256k1 -> CKR_CURVE_NOT_SUPPORTED, no curve"
    );
    static const CK_BYTE ed25519_name[] = { 0x13, 0x0c, 'e', 'd', 'w', 'a', 'r',
                                            'd',  's',  '2', '5', '5', '1', '9' };
    CHECK(
        tsra_pkcs11_ec_params_curve(ed25519_name, sizeof(ed25519_name), &curve) ==
            CKR_CURVE_NOT_SUPPORTED,
        "a curve name (Edwards) -> CKR_CURVE_NOT_SUPPORTED"
    );
    static const CK_BYTE implicit_ca[] = { 0x05, 0x00 };
    CHECK(
        tsra_pkcs11_ec_params_curve(implicit_ca, sizeof(implicit_ca), &curve) ==
            CKR_CURVE_NOT_SUPPORTED,
        "implicitlyCA (NULL) -> CKR_CURVE_NOT_SUPPORTED"
    );
    /* Explicit parameters: a SEQUENCE, here with a long-form length. */
    CK_BYTE explicit_params[3 + 0x90];
    memset(explicit_params, 0x02, sizeof(explicit_params));
    explicit_params[0] = TAG_SEQUENCE;
    explicit_params[1] = 0x81;
    explicit_params[2] = 0x90;
    CHECK(
        tsra_pkcs11_ec_params_curve(explicit_params, sizeof(explicit_params), &curve) ==
            CKR_CURVE_NOT_SUPPORTED,
        "explicit parameters -> CKR_CURVE_NOT_SUPPORTED"
    );
    CHECK(
        tsra_pkcs11_ec_params_curve(OID_P256, sizeof(OID_P256) - 1, &curve) ==
            CKR_ATTRIBUTE_VALUE_INVALID,
        "a truncated OID -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_BYTE trailing[sizeof(OID_P256) + 1];
    memcpy(trailing, OID_P256, sizeof(OID_P256));
    trailing[sizeof(OID_P256)] = 0;
    CHECK(
        tsra_pkcs11_ec_params_curve(trailing, sizeof(trailing), &curve) ==
            CKR_ATTRIBUTE_VALUE_INVALID,
        "a trailing byte -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    static const CK_BYTE long_form_overrun[] = { 0x30, 0x82, 0xff };
    CHECK(
        tsra_pkcs11_ec_params_curve(long_form_overrun, sizeof(long_form_overrun), &curve) ==
            CKR_ATTRIBUTE_VALUE_INVALID,
        "a length field cut short -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    static const CK_BYTE too_many_len_bytes[] = { 0x30, 0x83, 0x00, 0x00, 0x00 };
    CHECK(
        tsra_pkcs11_ec_params_curve(too_many_len_bytes, sizeof(too_many_len_bytes), &curve) ==
            CKR_ATTRIBUTE_VALUE_INVALID,
        "three length bytes -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CHECK(
        tsra_pkcs11_ec_params_curve(OID_P256, 0, &curve) == CKR_ATTRIBUTE_VALUE_INVALID,
        "an empty value -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CHECK(
        tsra_pkcs11_ec_params_curve(NULL, 10, &curve) == CKR_ATTRIBUTE_VALUE_INVALID,
        "a NULL value -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CHECK(
        tsra_pkcs11_ec_params_curve(OID_P256, sizeof(OID_P256), NULL) ==
            CKR_ATTRIBUTE_VALUE_INVALID,
        "a NULL output -> refused"
    );
    CHECK(tsra_pkcs11_ec_coord_len(TSRA_PKCS11_CURVE_NONE) == 0, "no curve: no coordinate");
}

static void test_point(void)
{
    printf("== tsra_pkcs11_ec_point_from_spki ==\n");
    CK_BYTE spki[256];
    CK_BYTE out[EC_POINT_DER_MAX];
    char msg[96];
    for (size_t i = 0; i < COUNT(CURVES); i++)
    {
        const curve_case *c = &CURVES[i];
        size_t n = make_spki(spki, c->oid, c->oid_len, c->coord, 0x00, 0x04);
        CK_ULONG out_len = sizeof(out);
        CK_RV rv = tsra_pkcs11_ec_point_from_spki(spki, n, c->curve, out, &out_len);
        CK_ULONG point_len = 1 + (2 * c->coord);
        CK_ULONG header = (point_len < 0x80) ? 2 : 3;
        snprintf(
            msg,
            sizeof(msg),
            "%s: DER OCTET STRING of %lu bytes",
            c->name,
            header + point_len
        );
        CHECK(
            (rv == CKR_OK) && (out_len == (header + point_len)) && (out[0] == TAG_OCTET_STRING),
            msg
        );
        CHECK(
            ((header == 2) ? (out[1] == point_len) : ((out[1] == 0x81) && (out[2] == point_len))) &&
                (memcmp(out + header, spki + n - point_len, point_len) == 0),
            "the length and the uncompressed point inside"
        );

        out_len = header + point_len - 1;
        CHECK(
            (tsra_pkcs11_ec_point_from_spki(spki, n, c->curve, out, &out_len) ==
             CKR_BUFFER_TOO_SMALL) &&
                (out_len == (header + point_len)),
            "one byte short -> CKR_BUFFER_TOO_SMALL with the length"
        );
    }
    size_t n = make_spki(spki, OID_P256, sizeof(OID_P256), 32, 0x00, 0x04);
    CK_ULONG out_len = sizeof(out);
    CHECK(
        tsra_pkcs11_ec_point_from_spki(spki, n, TSRA_PKCS11_CURVE_P384, out, &out_len) ==
            CKR_DEVICE_ERROR,
        "a P-256 key asked for as P-384 -> CKR_DEVICE_ERROR"
    );
    out_len = sizeof(out);
    CHECK(
        tsra_pkcs11_ec_point_from_spki(spki, n - 1, TSRA_PKCS11_CURVE_P256, out, &out_len) ==
            CKR_DEVICE_ERROR,
        "a truncated info -> CKR_DEVICE_ERROR"
    );
    CK_BYTE longer[256];
    memcpy(longer, spki, n);
    longer[n] = 0;
    out_len = sizeof(out);
    CHECK(
        tsra_pkcs11_ec_point_from_spki(longer, n + 1, TSRA_PKCS11_CURVE_P256, out, &out_len) ==
            CKR_DEVICE_ERROR,
        "a trailing byte -> CKR_DEVICE_ERROR"
    );
    n = make_spki(spki, OID_P256, sizeof(OID_P256), 32, 0x00, 0x02);
    out_len = sizeof(out);
    CHECK(
        tsra_pkcs11_ec_point_from_spki(spki, n, TSRA_PKCS11_CURVE_P256, out, &out_len) ==
            CKR_DEVICE_ERROR,
        "a compressed point -> CKR_DEVICE_ERROR"
    );
    n = make_spki(spki, OID_P256, sizeof(OID_P256), 32, 0x01, 0x04);
    out_len = sizeof(out);
    CHECK(
        tsra_pkcs11_ec_point_from_spki(spki, n, TSRA_PKCS11_CURVE_P256, out, &out_len) ==
            CKR_DEVICE_ERROR,
        "unused bits in the BIT STRING -> CKR_DEVICE_ERROR"
    );
    n = make_spki(spki, OID_P256, sizeof(OID_P256), 31, 0x00, 0x04);
    out_len = sizeof(out);
    CHECK(
        tsra_pkcs11_ec_point_from_spki(spki, n, TSRA_PKCS11_CURVE_P256, out, &out_len) ==
            CKR_DEVICE_ERROR,
        "a point of the wrong length -> CKR_DEVICE_ERROR"
    );
    n = make_spki(spki, OID_P256, sizeof(OID_P256), 32, 0x00, 0x04);
    spki[4] = 0x07; /* the algorithm OID's tag: no longer id-ecPublicKey */
    out_len = sizeof(out);
    CHECK(
        tsra_pkcs11_ec_point_from_spki(spki, n, TSRA_PKCS11_CURVE_P256, out, &out_len) ==
            CKR_DEVICE_ERROR,
        "another key algorithm -> CKR_DEVICE_ERROR"
    );
    out_len = sizeof(out);
    CHECK(
        (tsra_pkcs11_ec_point_from_spki(NULL, 0, TSRA_PKCS11_CURVE_P256, out, &out_len) ==
         CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_point_from_spki(spki, n, TSRA_PKCS11_CURVE_NONE, out, &out_len) ==
             CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_point_from_spki(spki, n, TSRA_PKCS11_CURVE_P256, NULL, &out_len) ==
             CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_point_from_spki(spki, n, TSRA_PKCS11_CURVE_P256, out, NULL) ==
             CKR_ARGUMENTS_BAD),
        "NULL arguments and no curve -> CKR_ARGUMENTS_BAD"
    );
}

static void test_raw_len_and_mechs(void)
{
    printf("== raw ECDSA lengths and the sign mechanism table ==\n");
    CHECK(
        tsra_pkcs11_ecdsa_raw_len_ok(20) && tsra_pkcs11_ecdsa_raw_len_ok(32) &&
            tsra_pkcs11_ecdsa_raw_len_ok(48) && tsra_pkcs11_ecdsa_raw_len_ok(64),
        "20, 32, 48 and 64 bytes are taken"
    );
    CHECK(
        !tsra_pkcs11_ecdsa_raw_len_ok(0) && !tsra_pkcs11_ecdsa_raw_len_ok(28) &&
            !tsra_pkcs11_ecdsa_raw_len_ok(31) && !tsra_pkcs11_ecdsa_raw_len_ok(33) &&
            !tsra_pkcs11_ecdsa_raw_len_ok(66),
        "0, 28 (SHA-224), 31, 33 and 66 bytes are not"
    );

    const tsra_pkcs11_sign_mech *m = tsra_pkcs11_sign_mech_find(CKM_ECDSA);
    CHECK((m != NULL) && (m->key_type == CKK_EC) && !m->multipart, "CKM_ECDSA: EC, one-shot");
    static const CK_MECHANISM_TYPE hashed[] = { CKM_ECDSA_SHA1,
                                                CKM_ECDSA_SHA256,
                                                CKM_ECDSA_SHA384,
                                                CKM_ECDSA_SHA512 };
    bool all = true;
    for (size_t i = 0; i < COUNT(hashed); i++)
    {
        m = tsra_pkcs11_sign_mech_find(hashed[i]);
        all =
            all && (m != NULL) && (m->mech == hashed[i]) && (m->key_type == CKK_EC) && m->multipart;
    }
    CHECK(all, "CKM_ECDSA_SHA1/256/384/512: EC, multi-part");
    CHECK(
        (tsra_pkcs11_sign_mech_find(CKM_ECDSA_SHA224) == NULL) &&
            (tsra_pkcs11_sign_mech_find(CKM_ECDSA_SHA3_256) == NULL) &&
            (tsra_pkcs11_sign_mech_find(CKM_AES_CBC) == NULL),
        "SHA-224, SHA-3 and cipher mechanisms are not signed"
    );
}

/* A complete pair of templates for a P-256 signing key. */
typedef struct
{
    CK_ATTRIBUTE pub[8];
    CK_ULONG pub_n;
    CK_ATTRIBUTE priv[8];
    CK_ULONG priv_n;
} pair_tmpl;

static void base_pair(pair_tmpl *t)
{
    memcpy(g_p256, OID_P256, sizeof(OID_P256));
    CK_ATTRIBUTE pub[] = { ATTR(CKA_EC_PARAMS, g_p256), BOOL_ATTR(CKA_VERIFY, g_true) };
    CK_ATTRIBUTE priv[] = { BOOL_ATTR(CKA_SIGN, g_true) };
    memcpy(t->pub, pub, sizeof(pub));
    t->pub_n = COUNT(pub);
    memcpy(t->priv, priv, sizeof(priv));
    t->priv_n = COUNT(priv);
}

static CK_RV check_pair(const pair_tmpl *t, tsra_pkcs11_ec_keygen *kg, const char **why)
{
    tsra_pkcs11_ec_keygen local;
    return tsra_pkcs11_ec_keygen_check(
        CKM_EC_KEY_PAIR_GEN,
        t->pub,
        t->pub_n,
        t->priv,
        t->priv_n,
        (kg != NULL) ? kg : &local,
        why
    );
}

/* The base pair with `a` added to the public (`pub`) or private template. */
static CK_RV check_with(bool pub, CK_ATTRIBUTE a, const char **why)
{
    pair_tmpl t;
    base_pair(&t);
    if (pub)
    {
        t.pub[t.pub_n++] = a;
    }
    else
    {
        t.priv[t.priv_n++] = a;
    }
    return check_pair(&t, NULL, why);
}

static void test_check(void)
{
    printf("== tsra_pkcs11_ec_keygen_check ==\n");
    pair_tmpl t;
    base_pair(&t);
    tsra_pkcs11_ec_keygen kg;
    const char *why = "stale";
    CHECK(
        (check_pair(&t, &kg, &why) == CKR_OK) && (kg.curve == TSRA_PKCS11_CURVE_P256) && kg.sign &&
            !kg.pub_token && !kg.priv_token && (kg.params == &t.pub[0]) && (why == NULL),
        "P-256 signing pair: curve, usage, session objects, no reason"
    );
    CHECK(
        tsra_pkcs11_ec_keygen_check(
            CKM_RSA_PKCS_KEY_PAIR_GEN,
            t.pub,
            t.pub_n,
            t.priv,
            t.priv_n,
            &kg,
            NULL
        ) == CKR_MECHANISM_INVALID,
        "another mechanism -> CKR_MECHANISM_INVALID"
    );
    CHECK(
        (tsra_pkcs11_ec_keygen_check(CKM_EC_KEY_PAIR_GEN, NULL, 1, t.priv, t.priv_n, &kg, NULL) ==
         CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_keygen_check(CKM_EC_KEY_PAIR_GEN, t.pub, t.pub_n, NULL, 1, &kg, NULL) ==
             CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_keygen_check(
                 CKM_EC_KEY_PAIR_GEN,
                 t.pub,
                 t.pub_n,
                 t.priv,
                 t.priv_n,
                 NULL,
                 NULL
             ) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_keygen_check(
                 CKM_EC_KEY_PAIR_GEN,
                 t.pub,
                 65,
                 t.priv,
                 t.priv_n,
                 &kg,
                 NULL
             ) == CKR_ARGUMENTS_BAD),
        "NULL templates with entries, NULL output, too many entries -> CKR_ARGUMENTS_BAD"
    );

    /* Every curve, and a deriving pair with token objects. */
    for (size_t i = 0; i < COUNT(CURVES); i++)
    {
        CK_BYTE oid[16];
        memcpy(oid, CURVES[i].oid, CURVES[i].oid_len);
        CK_ATTRIBUTE pub[] = { { CKA_EC_PARAMS, oid, CURVES[i].oid_len },
                               BOOL_ATTR(CKA_TOKEN, g_true) };
        CK_ATTRIBUTE priv[] = { BOOL_ATTR(CKA_DERIVE, g_true), BOOL_ATTR(CKA_TOKEN, g_true) };
        CK_RV rv = tsra_pkcs11_ec_keygen_check(CKM_EC_KEY_PAIR_GEN, pub, 2, priv, 2, &kg, NULL);
        CHECK(
            (rv == CKR_OK) && (kg.curve == CURVES[i].curve) && !kg.sign && kg.pub_token &&
                kg.priv_token,
            CURVES[i].name
        );
    }

    /* SIGN or DERIVE, never both, never neither. */
    why = NULL;
    CHECK(
        (check_with(false, (CK_ATTRIBUTE)BOOL_ATTR(CKA_DERIVE, g_true), &why) ==
         CKR_TEMPLATE_INCONSISTENT) &&
            (why != NULL) && (strstr(why, "CKA_SIGN and CKA_DERIVE") != NULL),
        "SIGN and DERIVE -> CKR_TEMPLATE_INCONSISTENT, with the reason"
    );
    base_pair(&t);
    t.priv_n = 0;
    CHECK(
        check_pair(&t, NULL, NULL) == CKR_TEMPLATE_INCONSISTENT,
        "neither (absent) -> inconsistent"
    );
    CK_ATTRIBUTE neither[] = { BOOL_ATTR(CKA_SIGN, g_false), BOOL_ATTR(CKA_DERIVE, g_false) };
    memcpy(t.priv, neither, sizeof(neither));
    t.priv_n = COUNT(neither);
    CHECK(
        check_pair(&t, NULL, NULL) == CKR_TEMPLATE_INCONSISTENT,
        "neither (FALSE) -> inconsistent"
    );
    CK_ATTRIBUTE derive_only[] = { BOOL_ATTR(CKA_SIGN, g_false), BOOL_ATTR(CKA_DERIVE, g_true) };
    memcpy(t.priv, derive_only, sizeof(derive_only));
    t.priv_n = COUNT(derive_only);
    t.pub_n = 1; /* EC_PARAMS only */
    CHECK(
        (check_pair(&t, &kg, NULL) == CKR_OK) && !kg.sign,
        "DERIVE with SIGN FALSE stated -> a deriving pair"
    );
    CHECK(
        check_with(true, (CK_ATTRIBUTE)BOOL_ATTR(CKA_DERIVE, g_true), NULL) ==
            CKR_TEMPLATE_INCONSISTENT,
        "a deriving public key for a signing private key -> inconsistent"
    );
    t.pub[t.pub_n++] = (CK_ATTRIBUTE)BOOL_ATTR(CKA_VERIFY, g_true);
    CHECK(
        check_pair(&t, NULL, NULL) == CKR_TEMPLATE_INCONSISTENT,
        "a verifying public key for a deriving private key -> inconsistent"
    );
    CHECK(
        check_with(true, (CK_ATTRIBUTE)BOOL_ATTR(CKA_DERIVE, g_false), NULL) == CKR_OK,
        "CKA_DERIVE FALSE on the public key of a signing pair is fine"
    );

    /* Class, key type, protection, material. */
    static CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
    static CK_KEY_TYPE rsa = CKK_RSA;
    CHECK(
        check_with(true, (CK_ATTRIBUTE)ATTR(CKA_CLASS, g_pub_cls), NULL) == CKR_OK,
        "public CKA_CLASS stated"
    );
    CHECK(
        check_with(false, (CK_ATTRIBUTE)ATTR(CKA_CLASS, g_priv_cls), NULL) == CKR_OK,
        "private CKA_CLASS stated"
    );
    CHECK(
        check_with(true, (CK_ATTRIBUTE)ATTR(CKA_KEY_TYPE, g_ec), NULL) == CKR_OK,
        "CKK_EC stated"
    );
    CHECK(
        check_with(true, (CK_ATTRIBUTE)ATTR(CKA_CLASS, g_priv_cls), NULL) ==
            CKR_TEMPLATE_INCONSISTENT,
        "the private class in the public template -> inconsistent"
    );
    CHECK(
        check_with(false, (CK_ATTRIBUTE)ATTR(CKA_CLASS, secret), NULL) == CKR_TEMPLATE_INCONSISTENT,
        "a secret class in the private template -> inconsistent"
    );
    CHECK(
        check_with(false, (CK_ATTRIBUTE)ATTR(CKA_KEY_TYPE, rsa), NULL) == CKR_TEMPLATE_INCONSISTENT,
        "CKK_RSA -> inconsistent"
    );
    CHECK(
        check_with(false, (CK_ATTRIBUTE)BOOL_ATTR(CKA_SENSITIVE, g_false), NULL) ==
            CKR_TEMPLATE_INCONSISTENT,
        "a non-sensitive private key -> inconsistent"
    );
    CHECK(
        check_with(false, (CK_ATTRIBUTE)BOOL_ATTR(CKA_EXTRACTABLE, g_true), NULL) ==
            CKR_TEMPLATE_INCONSISTENT,
        "an extractable private key -> inconsistent"
    );
    CHECK(
        (check_with(false, (CK_ATTRIBUTE)BOOL_ATTR(CKA_SENSITIVE, g_true), NULL) == CKR_OK) &&
            (check_with(false, (CK_ATTRIBUTE)BOOL_ATTR(CKA_EXTRACTABLE, g_false), NULL) == CKR_OK),
        "sensitive and unextractable stated are fine"
    );
    static CK_BYTE value[32];
    CHECK(
        check_with(false, (CK_ATTRIBUTE)ATTR(CKA_VALUE, value), NULL) == CKR_TEMPLATE_INCONSISTENT,
        "CKA_VALUE -> inconsistent"
    );
    static CK_BYTE point[65];
    CHECK(
        check_with(true, (CK_ATTRIBUTE)ATTR(CKA_EC_POINT, point), NULL) ==
            CKR_TEMPLATE_INCONSISTENT,
        "CKA_EC_POINT -> inconsistent (the token computes it)"
    );
    CHECK(
        check_with(false, (CK_ATTRIBUTE)BOOL_ATTR(CKA_LOCAL, g_true), NULL) ==
            CKR_ATTRIBUTE_READ_ONLY,
        "CKA_LOCAL -> CKR_ATTRIBUTE_READ_ONLY"
    );
    CHECK(
        check_with(true, (CK_ATTRIBUTE)BOOL_ATTR(CKA_VERIFY, g_true), NULL) ==
            CKR_TEMPLATE_INCONSISTENT,
        "a repeated attribute -> inconsistent"
    );
    CK_ULONG wide = 1;
    CHECK(
        check_with(false, (CK_ATTRIBUTE){ CKA_TOKEN, &wide, sizeof(wide) }, NULL) ==
            CKR_ATTRIBUTE_VALUE_INVALID,
        "a CK_BBOOL of CK_ULONG width -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CHECK(
        check_with(true, (CK_ATTRIBUTE){ CKA_LABEL, NULL, 4 }, NULL) == CKR_ATTRIBUTE_VALUE_INVALID,
        "a NULL value with a length -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CK_MECHANISM_TYPE mechs[KEYGEN_MAX_ALLOWED_MECHS + 1] = { CKM_ECDSA };
    CHECK(
        check_with(
            false,
            (CK_ATTRIBUTE){ CKA_ALLOWED_MECHANISMS, mechs, sizeof(CK_MECHANISM_TYPE) },
            NULL
        ) == CKR_OK,
        "a one-entry CKA_ALLOWED_MECHANISMS is kept"
    );
    CHECK(
        (check_with(false, (CK_ATTRIBUTE){ CKA_ALLOWED_MECHANISMS, mechs, 0 }, NULL) ==
         CKR_ATTRIBUTE_VALUE_INVALID) &&
            (check_with(
                 false,
                 (CK_ATTRIBUTE){ CKA_ALLOWED_MECHANISMS, mechs, sizeof(mechs) },
                 NULL
             ) == CKR_ATTRIBUTE_VALUE_INVALID),
        "an empty or over-long CKA_ALLOWED_MECHANISMS -> CKR_ATTRIBUTE_VALUE_INVALID"
    );

    /* CKA_EC_PARAMS. */
    base_pair(&t);
    t.pub[0] = t.pub[1];
    t.pub_n = 1;
    CHECK(check_pair(&t, NULL, NULL) == CKR_TEMPLATE_INCOMPLETE, "no CKA_EC_PARAMS -> incomplete");
    static CK_BYTE k1[sizeof(OID_SECP256K1)];
    memcpy(k1, OID_SECP256K1, sizeof(k1));
    base_pair(&t);
    t.pub[0] = (CK_ATTRIBUTE)ATTR(CKA_EC_PARAMS, k1);
    CHECK(
        check_pair(&t, NULL, NULL) == CKR_CURVE_NOT_SUPPORTED,
        "secp256k1 -> CKR_CURVE_NOT_SUPPORTED"
    );
    t.pub[0].ulValueLen = 3;
    CHECK(
        check_pair(&t, NULL, NULL) == CKR_ATTRIBUTE_VALUE_INVALID,
        "truncated CKA_EC_PARAMS -> CKR_ATTRIBUTE_VALUE_INVALID"
    );
    CHECK(
        check_with(false, (CK_ATTRIBUTE)ATTR(CKA_EC_PARAMS, g_p256), NULL) == CKR_OK,
        "the same CKA_EC_PARAMS in the private template is fine"
    );
    static CK_BYTE p384[sizeof(OID_P384)];
    memcpy(p384, OID_P384, sizeof(p384));
    why = NULL;
    CHECK(
        (check_with(false, (CK_ATTRIBUTE)ATTR(CKA_EC_PARAMS, p384), &why) ==
         CKR_TEMPLATE_INCONSISTENT) &&
            (why != NULL),
        "another curve in the private template -> inconsistent, with a reason"
    );

    /* First failure wins: shapes in template order, public first. */
    base_pair(&t);
    t.pub[t.pub_n++] = (CK_ATTRIBUTE){ CKA_TOKEN, &wide, sizeof(wide) };
    t.priv[t.priv_n++] = (CK_ATTRIBUTE)BOOL_ATTR(CKA_LOCAL, g_true);
    CHECK(
        check_pair(&t, NULL, NULL) == CKR_ATTRIBUTE_VALUE_INVALID,
        "a public shape error is reported before a private read-only one"
    );
}

static void test_check_unaligned(void)
{
    printf("== tsra_pkcs11_ec_keygen_check: unaligned values ==\n");
    static unsigned char blob[64];
    CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
    CK_KEY_TYPE kt = CKK_EC;
    /* Starting at offset 1 puts every CK_ULONG-wide value on an odd address. */
    unsigned char *p_cls = blob + 1;
    unsigned char *p_kt = p_cls + sizeof(cls);
    unsigned char *p_params = p_kt + sizeof(kt);
    memcpy(p_cls, &cls, sizeof(cls));
    memcpy(p_kt, &kt, sizeof(kt));
    memcpy(p_params, OID_P384, sizeof(OID_P384));
    CK_ATTRIBUTE pub[] = { { CKA_EC_PARAMS, p_params, sizeof(OID_P384) } };
    CK_ATTRIBUTE priv[] = {
        { CKA_CLASS, p_cls, sizeof(cls) },
        { CKA_KEY_TYPE, p_kt, sizeof(kt) },
        BOOL_ATTR(CKA_SIGN, g_true),
    };
    tsra_pkcs11_ec_keygen kg;
    CHECK(
        (tsra_pkcs11_ec_keygen_check(CKM_EC_KEY_PAIR_GEN, pub, 1, priv, 3, &kg, NULL) == CKR_OK) &&
            (kg.curve == TSRA_PKCS11_CURVE_P384),
        "values at odd addresses decode as they would aligned"
    );
    CK_KEY_TYPE rsa = CKK_RSA;
    memcpy(p_kt, &rsa, sizeof(rsa));
    CHECK(
        tsra_pkcs11_ec_keygen_check(CKM_EC_KEY_PAIR_GEN, pub, 1, priv, 3, &kg, NULL) ==
            CKR_TEMPLATE_INCONSISTENT,
        "an unaligned CKK_RSA is still refused"
    );
}

static const CK_ATTRIBUTE *find(const CK_ATTRIBUTE *t, CK_ULONG n, CK_ATTRIBUTE_TYPE type)
{
    return tsra_pkcs11_tmpl_find(t, n, type);
}

static bool has_bool(const CK_ATTRIBUTE *t, CK_ULONG n, CK_ATTRIBUTE_TYPE type, CK_BBOOL want)
{
    const CK_ATTRIBUTE *a = find(t, n, type);
    return (a != NULL) && (a->ulValueLen == sizeof(CK_BBOOL)) &&
           (*(const CK_BBOOL *)a->pValue == want);
}

static bool has_ulong(const CK_ATTRIBUTE *t, CK_ULONG n, CK_ATTRIBUTE_TYPE type, CK_ULONG want)
{
    const CK_ATTRIBUTE *a = find(t, n, type);
    CK_ULONG v = 0;
    if ((a == NULL) || (a->ulValueLen != sizeof(v)))
    {
        return false;
    }
    memcpy(&v, a->pValue, sizeof(v));
    return v == want;
}

static void test_build(void)
{
    printf("== tsra_pkcs11_ec_keygen_build ==\n");
    pair_tmpl t;
    base_pair(&t);
    tsra_pkcs11_ec_keygen kg;
    CHECK(check_pair(&t, &kg, NULL) == CKR_OK, "base pair checks");
    CK_BYTE point[3 + 1 + 64];
    memset(point, 0xA5, sizeof(point));
    tsra_pkcs11_ec_keygen_fill fill;
    CK_ATTRIBUTE pub_full[8 + EC_PUB_APPENDED_ATTRS];
    CK_ATTRIBUTE priv_full[8 + EC_PRIV_APPENDED_ATTRS];
    CK_ULONG pub_n = 0;
    CK_ULONG priv_n = 0;
    CK_RV rv = tsra_pkcs11_ec_keygen_build(
        &kg,
        t.pub,
        t.pub_n,
        t.priv,
        t.priv_n,
        point,
        sizeof(point),
        &fill,
        pub_full,
        &pub_n,
        priv_full,
        &priv_n
    );
    CHECK(rv == CKR_OK, "builds");
    CHECK(
        pub_n == (t.pub_n + EC_PUB_APPENDED_ATTRS - 1),
        "public: CKA_VERIFY was the caller's, the rest appended"
    );
    CHECK(
        priv_n == (t.priv_n + EC_PRIV_APPENDED_ATTRS - 1),
        "private: CKA_SIGN was the caller's, the rest appended"
    );
    CHECK(
        has_ulong(pub_full, pub_n, CKA_CLASS, CKO_PUBLIC_KEY) &&
            has_ulong(pub_full, pub_n, CKA_KEY_TYPE, CKK_EC) &&
            has_bool(pub_full, pub_n, CKA_PRIVATE, CK_FALSE) &&
            has_bool(pub_full, pub_n, CKA_VERIFY, CK_TRUE) &&
            has_bool(pub_full, pub_n, CKA_DERIVE, CK_FALSE) &&
            has_bool(pub_full, pub_n, CKA_LOCAL, CK_TRUE) &&
            has_ulong(pub_full, pub_n, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN),
        "public: class, type, not private, verifies, local, generated by CKM_EC_KEY_PAIR_GEN"
    );
    const CK_ATTRIBUTE *p = find(pub_full, pub_n, CKA_EC_POINT);
    CHECK(
        (p != NULL) && (p->ulValueLen == sizeof(point)) &&
            (memcmp(p->pValue, point, sizeof(point)) == 0) && (p->pValue == (void *)fill.point),
        "public: CKA_EC_POINT is a copy kept in the fill"
    );
    p = find(priv_full, priv_n, CKA_EC_PARAMS);
    CHECK(
        has_ulong(priv_full, priv_n, CKA_CLASS, CKO_PRIVATE_KEY) &&
            has_ulong(priv_full, priv_n, CKA_KEY_TYPE, CKK_EC) && (p != NULL) &&
            (p->ulValueLen == sizeof(OID_P256)) &&
            (memcmp(p->pValue, OID_P256, sizeof(OID_P256)) == 0) &&
            has_bool(priv_full, priv_n, CKA_PRIVATE, CK_TRUE) &&
            has_bool(priv_full, priv_n, CKA_SENSITIVE, CK_TRUE) &&
            has_bool(priv_full, priv_n, CKA_EXTRACTABLE, CK_FALSE) &&
            has_bool(priv_full, priv_n, CKA_SIGN, CK_TRUE) &&
            has_bool(priv_full, priv_n, CKA_DERIVE, CK_FALSE) &&
            has_bool(priv_full, priv_n, CKA_LOCAL, CK_TRUE) &&
            has_bool(priv_full, priv_n, CKA_ALWAYS_SENSITIVE, CK_TRUE) &&
            has_bool(priv_full, priv_n, CKA_NEVER_EXTRACTABLE, CK_TRUE) &&
            has_ulong(priv_full, priv_n, CKA_KEY_GEN_MECHANISM, CKM_EC_KEY_PAIR_GEN),
        "private: class, type, the public curve, private, protected, signs, local"
    );
    CHECK(find(priv_full, priv_n, CKA_EC_POINT) == NULL, "private: no CKA_EC_POINT");

    /* The caller's own values win where the token only defaults. */
    CK_ATTRIBUTE pub2[] = { ATTR(CKA_EC_PARAMS, g_p256), BOOL_ATTR(CKA_PRIVATE, g_true) };
    CK_ATTRIBUTE priv2[] = { BOOL_ATTR(CKA_DERIVE, g_true), BOOL_ATTR(CKA_PRIVATE, g_false) };
    CHECK(
        tsra_pkcs11_ec_keygen_check(CKM_EC_KEY_PAIR_GEN, pub2, 2, priv2, 2, &kg, NULL) == CKR_OK,
        "deriving pair with stated privacy checks"
    );
    rv = tsra_pkcs11_ec_keygen_build(
        &kg,
        pub2,
        2,
        priv2,
        2,
        point,
        sizeof(point),
        &fill,
        pub_full,
        &pub_n,
        priv_full,
        &priv_n
    );
    CHECK(
        (rv == CKR_OK) && has_bool(pub_full, pub_n, CKA_PRIVATE, CK_TRUE) &&
            has_bool(pub_full, pub_n, CKA_VERIFY, CK_FALSE) &&
            has_bool(pub_full, pub_n, CKA_DERIVE, CK_TRUE) &&
            has_bool(priv_full, priv_n, CKA_PRIVATE, CK_FALSE) &&
            has_bool(priv_full, priv_n, CKA_SIGN, CK_FALSE),
        "the caller's CKA_PRIVATE is kept; a deriving pair derives on both halves"
    );

    CHECK(
        (tsra_pkcs11_ec_keygen_build(
             &kg,
             pub2,
             2,
             priv2,
             2,
             point,
             0,
             &fill,
             pub_full,
             &pub_n,
             priv_full,
             &priv_n
         ) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_keygen_build(
                 &kg,
                 pub2,
                 2,
                 priv2,
                 2,
                 point,
                 EC_POINT_DER_MAX + 1,
                 &fill,
                 pub_full,
                 &pub_n,
                 priv_full,
                 &priv_n
             ) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_keygen_build(
                 NULL,
                 pub2,
                 2,
                 priv2,
                 2,
                 point,
                 sizeof(point),
                 &fill,
                 pub_full,
                 &pub_n,
                 priv_full,
                 &priv_n
             ) == CKR_ARGUMENTS_BAD) &&
            (tsra_pkcs11_ec_keygen_build(
                 &kg,
                 NULL,
                 2,
                 priv2,
                 2,
                 point,
                 sizeof(point),
                 &fill,
                 pub_full,
                 &pub_n,
                 priv_full,
                 &priv_n
             ) == CKR_ARGUMENTS_BAD),
        "an empty or over-long point and NULL arguments -> CKR_ARGUMENTS_BAD"
    );
}

int main(void)
{
    test_params();
    test_point();
    test_raw_len_and_mechs();
    test_check();
    test_check_unaligned();
    test_build();
    printf(
        g_fail ? "\nec_template_test: FAILED (%d checks)\n"
               : "\nec_template_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
