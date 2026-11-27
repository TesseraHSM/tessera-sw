// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * C_UnwrapKey into a private key (see tsra_pkcs11_unwrap_private.h). The
 * secret-key targets and the CKM_RSA_AES_KEY_WRAP parameters are in
 * tsra_pkcs11_unwrap_params.c, the device call in tsra_pkcs11_key.c and the
 * entry point in tsra_pkcs11_unwrap.c.
 */

#include "tsra_pkcs11_unwrap_private.h"
#include "tsra_pkcs11_key.h"
#include "tsra_pkcs11_template.h"
#include "tsra_pkcs11_unwrap_params.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

/* A DER element is its tag byte, its length bytes and its content. The length
 * takes one byte below DER_LONG_FORM, else a count byte and the length's own
 * bytes. */
#define DER_TAG_BYTES 1
#define DER_LONG_FORM 0x80

/* The content lengths of the fixed PKCS#8 fields: the INTEGER version (0 for
 * PKCS#8 and PKCS#1, 1 for SEC 1), the rsaEncryption OID 1.2.840.113549.1.1.1
 * and its NULL parameters, the id-ecPublicKey OID 1.2.840.10045.2.1 (RFC 5208,
 * RFC 8017 appendix A.1.2, RFC 5915). */
#define DER_VERSION_LEN 1
#define OID_RSA_ENCRYPTION_LEN 9
#define DER_NULL_LEN 0
#define OID_EC_PUBLIC_KEY_LEN 7

/* The PKCS#1 RSAPrivateKey components after the modulus, the exponent and the
 * private exponent: the two primes, and the three CRT values. */
#define RSA_PRIMES 2
#define RSA_CRT_VALUES 3

/* The firmware's longest public exponent (key_assurance.rs check_rsa_components). */
#define RSA_MAX_EXPONENT_BYTES 4

/* The unused-bits byte at the start of a BIT STRING's content. */
#define DER_BIT_STRING_UNUSED 1

/* RFC 5649 pads its input to whole 8-byte semiblocks before it adds
 * AES_KWP_OVERHEAD. */
#define AES_KWP_SEMIBLOCK 8

_Static_assert(
    (RSA_UNWRAP_MODULUS_BYTES % AES_KWP_SEMIBLOCK) == 0,
    "every blob length is a whole number of semiblocks"
);

/* The RSA sizes the device unwraps, smallest first. */
static const CK_ULONG RSA_SIZES[] = { RSA_MIN_KEY_BITS, RSA_MID_KEY_BITS, RSA_MAX_KEY_BITS };

/* The usages of a private key and, at the same index, the public key's
 * counterpart. A device key pair has exactly one of them. */
static const CK_ATTRIBUTE_TYPE PRIV_USAGES[] = { CKA_SIGN,
                                                 CKA_DECRYPT,
                                                 CKA_SIGN_RECOVER,
                                                 CKA_UNWRAP,
                                                 CKA_DERIVE };
static const CK_ATTRIBUTE_TYPE PUB_USAGES[] = { CKA_VERIFY,
                                                CKA_ENCRYPT,
                                                CKA_VERIFY_RECOVER,
                                                CKA_WRAP,
                                                CKA_DERIVE };

#define USAGE_COUNT (sizeof(PRIV_USAGES) / sizeof(PRIV_USAGES[0]))

_Static_assert(
    USAGE_COUNT == (sizeof(PUB_USAGES) / sizeof(PUB_USAGES[0])),
    "every private usage has its public counterpart"
);

/* The room tsra_pkcs11_unwrap_private_build needs. The private key: four
 * defaults (CKA_PRIVATE, CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_ID), a usage
 * flag each, two public values and four origin attributes. The public key:
 * class, key type, CKA_TOKEN, CKA_PRIVATE, CKA_ID and CKA_LABEL, a usage flag
 * each, three public values, CKA_LOCAL and CKA_KEY_GEN_MECHANISM. */
_Static_assert(UNWRAP_PRIV_APPENDED_ATTRS == (4 + USAGE_COUNT + 2 + 4), "the private key's room");
_Static_assert(UNWRAP_PUB_ATTRS == (6 + USAGE_COUNT + 3 + 2), "the public key's room");

/* The length of a DER element with `len` content bytes, header included. */
static CK_ULONG der_size(CK_ULONG len)
{
    CK_ULONG len_bytes = 1;
    if (len >= DER_LONG_FORM)
    {
        for (CK_ULONG l = len; l > 0; l >>= CHAR_BIT)
        {
            len_bytes++;
        }
    }
    return DER_TAG_BYTES + len_bytes + len;
}

/*
 * The PKCS#8 length of an RSA key of `k` modulus bytes with every component at
 * its shortest or its `longest` DER encoding the firmware takes. An INTEGER
 * holds its magnitude and, when the top bit is set, a zero byte in front. The
 * modulus has exactly `k` bytes and so, as n = p * q and neither exceeds half
 * of it, each prime exactly half; the exponent has one to four; the private
 * exponent is below the modulus and the CRT values below a prime.
 */
static CK_ULONG rsa_pkcs8_len(CK_ULONG k, bool longest)
{
    CK_ULONG half = k / 2;
    CK_ULONG sign = longest ? 1 : 0;
    CK_ULONG e = longest ? (RSA_MAX_EXPONENT_BYTES + 1) : 1;
    CK_ULONG d = longest ? (k + 1) : 1;
    CK_ULONG crt = longest ? (half + 1) : 1;
    CK_ULONG pkcs1 = der_size(DER_VERSION_LEN) + der_size(k + sign) + der_size(e) + der_size(d) +
                     (RSA_PRIMES * der_size(half + sign)) + (RSA_CRT_VALUES * der_size(crt));
    CK_ULONG alg = der_size(der_size(OID_RSA_ENCRYPTION_LEN) + der_size(DER_NULL_LEN));
    return der_size(der_size(DER_VERSION_LEN) + alg + der_size(der_size(pkcs1)));
}

/*
 * The PKCS#8 length of an EC key on `curve` as the firmware takes it: a SEC 1
 * key with its version, the scalar as long as the order, and the uncompressed
 * public point in [1], and the named curve in the algorithm.
 */
static CK_ULONG ec_pkcs8_len(tsra_pkcs11_ec_curve_t curve)
{
    CK_ULONG oid_len = 0;
    (void)tsra_pkcs11_ec_curve_params(curve, &oid_len);
    CK_ULONG coord = tsra_pkcs11_ec_coord_len(curve);
    CK_ULONG point = 1 + (2 * coord); /* EC_POINT_UNCOMPRESSED, then x and y */
    CK_ULONG sec1 = der_size(DER_VERSION_LEN) + der_size(coord) +
                    der_size(der_size(DER_BIT_STRING_UNUSED + point));
    CK_ULONG alg = der_size(der_size(OID_EC_PUBLIC_KEY_LEN) + oid_len);
    return der_size(der_size(DER_VERSION_LEN) + alg + der_size(der_size(sec1)));
}

/* The blob carrying a PKCS#8 key of `len` bytes. */
static CK_ULONG blob_len(CK_ULONG len)
{
    CK_ULONG padded = ((len + AES_KWP_SEMIBLOCK - 1) / AES_KWP_SEMIBLOCK) * AES_KWP_SEMIBLOCK;
    return RSA_UNWRAP_MODULUS_BYTES + padded + AES_KWP_OVERHEAD;
}

CK_RV tsra_pkcs11_private_blob_size(
    CK_KEY_TYPE key_type,
    CK_ULONG wrapped_len,
    CK_ULONG *rsa_bits,
    tsra_pkcs11_ec_curve_t *curve
)
{
    if ((rsa_bits == NULL) || (curve == NULL) || ((key_type != CKK_RSA) && (key_type != CKK_EC)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    *rsa_bits = 0;
    *curve = TSRA_PKCS11_CURVE_NONE;
    if (key_type == CKK_EC)
    {
        for (int c = TSRA_PKCS11_CURVE_P256; c <= TSRA_PKCS11_CURVE_P521; c++)
        {
            if (blob_len(ec_pkcs8_len((tsra_pkcs11_ec_curve_t)c)) == wrapped_len)
            {
                *curve = (tsra_pkcs11_ec_curve_t)c;
                return CKR_OK;
            }
        }
        return CKR_WRAPPED_KEY_LEN_RANGE;
    }
    if ((wrapped_len % AES_KWP_SEMIBLOCK) != 0)
    {
        return CKR_WRAPPED_KEY_LEN_RANGE;
    }
    CK_ULONG below = 0; /* the longest blob of the size below */
    for (size_t i = 0; i < (sizeof(RSA_SIZES) / sizeof(RSA_SIZES[0])); i++)
    {
        CK_ULONG k = RSA_SIZES[i] / CHAR_BIT;
        CK_ULONG lo = blob_len(rsa_pkcs8_len(k, false));
        CK_ULONG hi = blob_len(rsa_pkcs8_len(k, true));
        if ((wrapped_len > below) && (wrapped_len >= lo) && (wrapped_len <= hi))
        {
            *rsa_bits = RSA_SIZES[i];
            return CKR_OK;
        }
        below = hi;
    }
    return CKR_WRAPPED_KEY_LEN_RANGE;
}

/* Whether `t` is one of the nine usage attributes of a key pair. */
static bool is_usage(CK_ATTRIBUTE_TYPE t)
{
    for (size_t i = 0; i < USAGE_COUNT; i++)
    {
        if ((PRIV_USAGES[i] == t) || (PUB_USAGES[i] == t))
        {
            return true;
        }
    }
    return false;
}

/* Whether `t` is a public value the blob, not the template, sets. */
static bool is_public_value(CK_ATTRIBUTE_TYPE t)
{
    return (t == CKA_MODULUS) || (t == CKA_MODULUS_BITS) || (t == CKA_PUBLIC_EXPONENT) ||
           (t == CKA_EC_POINT) || (t == CKA_PUBLIC_KEY_INFO);
}

/* The per-attribute half of tsra_pkcs11_unwrap_private_check for tmpl[i];
 * `out` and `priv` collect what the checks over the whole template need. */
static CK_RV check_attr(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG i,
    tsra_pkcs11_private_target *out,
    CK_BBOOL *priv,
    const char **why
)
{
    const CK_ATTRIBUTE *a = &tmpl[i];
    CK_RV rv = tsra_pkcs11_attr_check(a);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (tsra_pkcs11_tmpl_find(tmpl, i, a->type) != NULL)
    {
        *why = "an attribute is repeated";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    if (tsra_pkcs11_attr_is_token_set(a))
    {
        return CKR_ATTRIBUTE_READ_ONLY;
    }
    if (tsra_pkcs11_attr_is_key_material(a->type) || is_public_value(a->type))
    {
        *why = "an unwrapped key takes its key material and public values from the blob";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    /* The sign init reads a stored list back into a buffer of this size. */
    if ((a->type == CKA_ALLOWED_MECHANISMS) &&
        ((a->ulValueLen == 0) ||
         ((a->ulValueLen / sizeof(CK_MECHANISM_TYPE)) > KEYGEN_MAX_ALLOWED_MECHS)))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    CK_ULONG v = 0;
    CK_BBOOL b = CK_FALSE;
    switch (a->type)
    {
    case CKA_CLASS:
        rv = tsra_pkcs11_tmpl_ulong(a, &v);
        if ((rv == CKR_OK) && (v != CKO_PRIVATE_KEY))
        {
            *why = "the class is not CKO_PRIVATE_KEY";
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
        return rv;
    case CKA_KEY_TYPE:
        rv = tsra_pkcs11_tmpl_ulong(a, &v);
        if ((rv == CKR_OK) && (v != CKK_RSA) && (v != CKK_EC))
        {
            *why = "a private key unwraps only as CKK_RSA or CKK_EC";
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
        out->key_type = v;
        return rv;
    case CKA_SENSITIVE:
    case CKA_EXTRACTABLE:
        rv = tsra_pkcs11_tmpl_bool(a, &b);
        if ((rv == CKR_OK) && ((b != CK_FALSE) != (a->type == CKA_SENSITIVE)))
        {
            /* Device keys only ever exist masked. */
            *why = "the private key must be sensitive and unextractable";
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
        return rv;
    case CKA_ALWAYS_AUTHENTICATE:
        rv = tsra_pkcs11_tmpl_bool(a, &b);
        if ((rv == CKR_OK) && b)
        {
            /* Nothing would enforce it: there is no CKU_CONTEXT_SPECIFIC login. */
            *why = "CKA_ALWAYS_AUTHENTICATE is not supported: the token has no "
                   "context-specific login";
            rv = CKR_ATTRIBUTE_VALUE_INVALID;
        }
        return rv;
    case CKA_TOKEN:
        return tsra_pkcs11_tmpl_bool(a, &out->token);
    case CKA_PRIVATE:
        return tsra_pkcs11_tmpl_bool(a, priv);
    default:
        return CKR_OK; /* usages are judged together below; the rest is stored verbatim */
    }
}

/*
 * The one usage of the private key the template asks for: *usage receives
 * it when exactly one usage is TRUE and the key type allows it there (CKA_SIGN
 * or CKA_DECRYPT for RSA, CKA_SIGN or CKA_DERIVE for EC), else
 * CKR_TEMPLATE_INCONSISTENT.
 */
static CK_RV check_usage(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_KEY_TYPE kt,
    CK_ATTRIBUTE_TYPE *usage,
    const char **why
)
{
    CK_ATTRIBUTE_TYPE other = (kt == CKK_RSA) ? CKA_DECRYPT : CKA_DERIVE;
    CK_ULONG on = 0;
    bool foreign = false;
    for (CK_ULONG i = 0; i < count; i++)
    {
        CK_BBOOL b = CK_FALSE;
        if (!is_usage(tmpl[i].type) || (tsra_pkcs11_tmpl_bool(&tmpl[i], &b) != CKR_OK) || !b)
        {
            continue; /* the shape check passed every usage as one CK_BBOOL */
        }
        on++;
        *usage = tmpl[i].type;
        foreign = foreign || ((tmpl[i].type != CKA_SIGN) && (tmpl[i].type != other));
    }
    if ((on == 1) && !foreign)
    {
        return CKR_OK;
    }
    *why = (kt == CKK_RSA) ? "an RSA private key needs exactly one of CKA_SIGN and CKA_DECRYPT "
                             "TRUE and no other usage: the device key signs or decrypts"
                           : "an EC private key needs exactly one of CKA_SIGN and CKA_DERIVE "
                             "TRUE and no other usage: the device key signs or derives";
    return CKR_TEMPLATE_INCONSISTENT;
}

CK_RV tsra_pkcs11_unwrap_private_check(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ULONG wrapped_len,
    tsra_pkcs11_private_target *out,
    const char **why
)
{
    const char *unused = NULL;
    if (why == NULL)
    {
        why = &unused;
    }
    *why = NULL;
    if (out == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(out, 0, sizeof(*out));
    CK_RV rv = tsra_pkcs11_tmpl_check_bounds(tmpl, count);
    CK_BBOOL priv = CK_TRUE; /* a private key is private unless the template says otherwise */
    for (CK_ULONG i = 0; (rv == CKR_OK) && (i < count); i++)
    {
        rv = check_attr(tmpl, i, out, &priv, why);
    }
    if (rv != CKR_OK)
    {
        return rv;
    }
    if ((tsra_pkcs11_tmpl_find(tmpl, count, CKA_CLASS) == NULL) ||
        (tsra_pkcs11_tmpl_find(tmpl, count, CKA_KEY_TYPE) == NULL))
    {
        return CKR_TEMPLATE_INCOMPLETE;
    }
    if (out->token && !priv)
    {
        /* Only a sealed record guards the attributes that limit the key. */
        *why = "a token private key must be private: the file store seals only private objects";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    rv = check_usage(tmpl, count, out->key_type, &out->usage, why);
    if (rv != CKR_OK)
    {
        return rv;
    }
    const CK_ATTRIBUTE *params = tsra_pkcs11_tmpl_find(tmpl, count, CKA_EC_PARAMS);
    if ((params != NULL) && (out->key_type == CKK_RSA))
    {
        *why = "an RSA key has no CKA_EC_PARAMS";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    /* A value naming no supported curve gets the verdict EC keygen gives it. */
    tsra_pkcs11_ec_curve_t named = TSRA_PKCS11_CURVE_NONE;
    if (params != NULL)
    {
        rv = tsra_pkcs11_ec_params_curve(params->pValue, params->ulValueLen, &named);
        if (rv != CKR_OK)
        {
            return rv;
        }
    }
    rv = tsra_pkcs11_private_blob_size(out->key_type, wrapped_len, &out->rsa_bits, &out->curve);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if ((params != NULL) && (named != out->curve))
    {
        *why = "CKA_EC_PARAMS names another curve than the wrapped key's";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    return CKR_OK;
}

CK_RV tsra_pkcs11_unwrap_private_build(
    const tsra_pkcs11_private_target *t,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    const CK_BYTE *spki,
    CK_ULONG spki_len,
    tsra_pkcs11_private_fill *fill,
    CK_ATTRIBUTE *priv_full,
    CK_ULONG *priv_n,
    CK_ATTRIBUTE *pub_full,
    CK_ULONG *pub_n
)
{
    if ((t == NULL) || (spki == NULL) || (fill == NULL) || (priv_full == NULL) ||
        (priv_n == NULL) || (pub_full == NULL) || (pub_n == NULL) ||
        ((tmpl == NULL) && (count > 0)) || ((t->key_type != CKK_RSA) && (t->key_type != CKK_EC)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    /* The public values, and the bytes CKA_ID hashes: the modulus, or the
     * uncompressed point. */
    tsra_pkcs11_rsa_public rsa = { NULL, 0, NULL, 0 };
    CK_ULONG params_len = 0;
    const CK_BYTE *params = tsra_pkcs11_ec_curve_params(t->curve, &params_len);
    CK_ULONG point_len = sizeof(fill->point);
    const CK_BYTE *raw = NULL;
    CK_ULONG raw_len = 0;
    if (t->key_type == CKK_RSA)
    {
        if (!tsra_pkcs11_spki_rsa(spki, spki_len, &rsa) || (rsa.n_len != (t->rsa_bits / CHAR_BIT)))
        {
            return CKR_DEVICE_ERROR;
        }
        raw = rsa.n;
        raw_len = rsa.n_len;
    }
    else
    {
        if ((params == NULL) ||
            (tsra_pkcs11_ec_point_from_spki(spki, spki_len, t->curve, fill->point, &point_len) !=
             CKR_OK) ||
            !tsra_pkcs11_ec_point_from_der(fill->point, point_len, t->curve, &raw))
        {
            return CKR_DEVICE_ERROR;
        }
        raw_len = 1 + (2 * tsra_pkcs11_ec_coord_len(t->curve)); /* the prefix, then x and y */
    }
    const CK_ATTRIBUTE *id = tsra_pkcs11_tmpl_find(tmpl, count, CKA_ID);
    if (id == NULL)
    {
        tsra_pkcs11_digest_op_t *sha1 = NULL;
        CK_RV rv = tsra_pkcs11_digest_op_new(CKM_SHA_1, &sha1);
        if (rv != CKR_OK)
        {
            return rv;
        }
        tsra_pkcs11_digest_op_update(sha1, raw, raw_len);
        tsra_pkcs11_digest_op_final(sha1, fill->id);
        tsra_pkcs11_digest_op_free(sha1);
    }
    fill->pub_cls = CKO_PUBLIC_KEY;
    fill->kt = t->key_type;
    fill->btrue = CK_TRUE;
    fill->bfalse = CK_FALSE;
    fill->token = t->token;
    fill->kgm = CK_UNAVAILABLE_INFORMATION;
    fill->bits = t->rsa_bits;
    const CK_ATTRIBUTE id_attr =
        (id != NULL) ? *id : (CK_ATTRIBUTE){ CKA_ID, fill->id, sizeof(fill->id) };
    const CK_ATTRIBUTE pub_values[] = {
        { CKA_MODULUS, (void *)rsa.n, rsa.n_len },
        { CKA_PUBLIC_EXPONENT, (void *)rsa.e, rsa.e_len },
        { CKA_MODULUS_BITS, &fill->bits, sizeof(fill->bits) },
    };
    const CK_ATTRIBUTE ec_params = { CKA_EC_PARAMS, (void *)params, params_len };
    const CK_ATTRIBUTE local = { CKA_LOCAL, &fill->bfalse, sizeof(fill->bfalse) };
    const CK_ATTRIBUTE kgm = { CKA_KEY_GEN_MECHANISM, &fill->kgm, sizeof(fill->kgm) };

    CK_ULONG k = 0;
    for (CK_ULONG i = 0; i < count; i++)
    {
        priv_full[k++] = tmpl[i];
    }
    const CK_ATTRIBUTE priv_defaults[] = {
        { CKA_PRIVATE, &fill->btrue, sizeof(fill->btrue) },
        { CKA_SENSITIVE, &fill->btrue, sizeof(fill->btrue) },
        { CKA_EXTRACTABLE, &fill->bfalse, sizeof(fill->bfalse) },
        id_attr,
    };
    for (size_t i = 0; i < (sizeof(priv_defaults) / sizeof(priv_defaults[0])); i++)
    {
        tsra_pkcs11_tmpl_append(priv_full, &k, tmpl, count, priv_defaults[i]);
    }
    /* The key's own usage is TRUE in the template; the rest are stated FALSE. */
    for (size_t i = 0; i < USAGE_COUNT; i++)
    {
        tsra_pkcs11_tmpl_append(
            priv_full,
            &k,
            tmpl,
            count,
            (CK_ATTRIBUTE){ PRIV_USAGES[i], &fill->bfalse, sizeof(fill->bfalse) }
        );
    }
    /* Refused by the check as inputs, so always appended; PKCS#11 defines the
     * modulus and the public exponent on an RSA private key too. */
    if (t->key_type == CKK_RSA)
    {
        priv_full[k++] = pub_values[0];
        priv_full[k++] = pub_values[1];
    }
    else
    {
        tsra_pkcs11_tmpl_append(priv_full, &k, tmpl, count, ec_params);
    }
    priv_full[k++] = local;
    priv_full[k++] = (CK_ATTRIBUTE){ CKA_ALWAYS_SENSITIVE, &fill->bfalse, sizeof(fill->bfalse) };
    priv_full[k++] = (CK_ATTRIBUTE){ CKA_NEVER_EXTRACTABLE, &fill->bfalse, sizeof(fill->bfalse) };
    priv_full[k++] = kgm;
    *priv_n = k;

    k = 0;
    pub_full[k++] = (CK_ATTRIBUTE){ CKA_CLASS, &fill->pub_cls, sizeof(fill->pub_cls) };
    pub_full[k++] = (CK_ATTRIBUTE){ CKA_KEY_TYPE, &fill->kt, sizeof(fill->kt) };
    pub_full[k++] = (CK_ATTRIBUTE){ CKA_TOKEN, &fill->token, sizeof(fill->token) };
    pub_full[k++] = (CK_ATTRIBUTE){ CKA_PRIVATE, &fill->bfalse, sizeof(fill->bfalse) };
    pub_full[k++] = id_attr;
    const CK_ATTRIBUTE *label = tsra_pkcs11_tmpl_find(tmpl, count, CKA_LABEL);
    if (label != NULL)
    {
        pub_full[k++] = *label;
    }
    for (size_t i = 0; i < USAGE_COUNT; i++)
    {
        CK_BBOOL *on = (PRIV_USAGES[i] == t->usage) ? &fill->btrue : &fill->bfalse;
        pub_full[k++] = (CK_ATTRIBUTE){ PUB_USAGES[i], on, sizeof(*on) };
    }
    if (t->key_type == CKK_RSA)
    {
        for (size_t i = 0; i < (sizeof(pub_values) / sizeof(pub_values[0])); i++)
        {
            pub_full[k++] = pub_values[i];
        }
    }
    else
    {
        pub_full[k++] = ec_params;
        pub_full[k++] = (CK_ATTRIBUTE){ CKA_EC_POINT, fill->point, point_len };
    }
    pub_full[k++] = local;
    pub_full[k++] = kgm;
    *pub_n = k;
    return CKR_OK;
}
