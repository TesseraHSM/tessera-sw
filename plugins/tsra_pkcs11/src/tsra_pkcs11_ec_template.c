// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * EC key-pair template handling and the EC encodings (see
 * tsra_pkcs11_ec_template.h).
 */

#include "tsra_pkcs11_ec_template.h"
#include "tsra_pkcs11_digest.h"
#include "tsra_pkcs11_template.h"

#include <stddef.h>
#include <string.h>

/* DER tags this file reads or writes. */
#define DER_OCTET_STRING 0x04
#define DER_BIT_STRING 0x03
#define DER_SEQUENCE 0x30
/* A length byte with this bit set counts the length bytes that follow. */
#define DER_LONG_FORM 0x80
/* The most length bytes read: every length here is below 64 KiB. */
#define DER_MAX_LEN_BYTES 2
/* The first byte of an uncompressed point (SEC 1). */
#define EC_POINT_UNCOMPRESSED 0x04

/* The DER named-curve OIDs (RFC 5480): CKA_EC_PARAMS and the curve in the
 * device's public key info. */
static const CK_BYTE OID_P256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static const CK_BYTE OID_P384[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static const CK_BYTE OID_P521[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23 };
/* id-ecPublicKey, the algorithm of an EC SubjectPublicKeyInfo. */
static const CK_BYTE OID_EC_PUBLIC_KEY[] = { 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };

typedef struct
{
    tsra_pkcs11_ec_curve_t curve;
    const CK_BYTE *oid;
    CK_ULONG oid_len;
    CK_ULONG coord_len;
} curve_info;

static const curve_info CURVES[] = {
    { TSRA_PKCS11_CURVE_P256, OID_P256, sizeof(OID_P256), 32 },
    { TSRA_PKCS11_CURVE_P384, OID_P384, sizeof(OID_P384), 48 },
    { TSRA_PKCS11_CURVE_P521, OID_P521, sizeof(OID_P521), 66 },
};

static const curve_info *find_curve(tsra_pkcs11_ec_curve_t curve)
{
    for (size_t i = 0; i < (sizeof(CURVES) / sizeof(CURVES[0])); i++)
    {
        if (CURVES[i].curve == curve)
        {
            return &CURVES[i];
        }
    }
    return NULL;
}

/*
 * Read one DER element at *p (before `end`): its tag, and its content as
 * *val / *val_len. Definite lengths up to two length bytes, which covers
 * every value here, in their minimal DER form: the long form only from 128
 * on and without a leading zero byte. *p moves past the element. false if it
 * does not fit or is not DER.
 */
static bool der_next(
    const CK_BYTE **p,
    const CK_BYTE *end,
    CK_BYTE *tag,
    const CK_BYTE **val,
    CK_ULONG *val_len
)
{
    const CK_BYTE *q = *p;
    if ((end - q) < 2)
    {
        return false;
    }
    *tag = *q++;
    CK_ULONG len = *q++;
    if ((len & DER_LONG_FORM) != 0)
    {
        CK_ULONG n = len & ~(CK_ULONG)DER_LONG_FORM;
        if ((n == 0) || (n > DER_MAX_LEN_BYTES) || ((CK_ULONG)(end - q) < n) || (*q == 0))
        {
            return false;
        }
        len = 0;
        for (CK_ULONG i = 0; i < n; i++)
        {
            len = (len << 8) | *q++;
        }
        if (len < DER_LONG_FORM)
        {
            return false; /* DER writes it in the short form */
        }
    }
    if ((CK_ULONG)(end - q) < len)
    {
        return false;
    }
    *val = q;
    *val_len = len;
    *p = q + len;
    return true;
}

CK_RV tsra_pkcs11_ec_params_curve(const void *value, CK_ULONG len, tsra_pkcs11_ec_curve_t *out)
{
    if (out != NULL)
    {
        *out = TSRA_PKCS11_CURVE_NONE;
    }
    if ((value == NULL) || (out == NULL))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    const CK_BYTE *p = (const CK_BYTE *)value;
    const CK_BYTE *end = p + len;
    CK_BYTE tag = 0;
    const CK_BYTE *val = NULL;
    CK_ULONG val_len = 0;
    if (!der_next(&p, end, &tag, &val, &val_len) || (p != end))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    for (size_t i = 0; i < (sizeof(CURVES) / sizeof(CURVES[0])); i++)
    {
        if ((len == CURVES[i].oid_len) && (memcmp(value, CURVES[i].oid, len) == 0))
        {
            *out = CURVES[i].curve;
            return CKR_OK;
        }
    }
    return CKR_CURVE_NOT_SUPPORTED;
}

CK_ULONG tsra_pkcs11_ec_coord_len(tsra_pkcs11_ec_curve_t curve)
{
    const curve_info *c = find_curve(curve);
    return (c != NULL) ? c->coord_len : 0;
}

CK_RV tsra_pkcs11_ec_point_from_spki(
    const CK_BYTE *spki,
    CK_ULONG spki_len,
    tsra_pkcs11_ec_curve_t curve,
    CK_BYTE *out,
    CK_ULONG *out_len
)
{
    const curve_info *c = find_curve(curve);
    if ((spki == NULL) || (out == NULL) || (out_len == NULL) || (c == NULL))
    {
        return CKR_ARGUMENTS_BAD;
    }
    /* SEQUENCE { SEQUENCE { id-ecPublicKey, curve }, BIT STRING { 0, point } } */
    const CK_BYTE *p = spki;
    const CK_BYTE *end = spki + spki_len;
    CK_BYTE tag = 0;
    const CK_BYTE *seq = NULL;
    CK_ULONG seq_len = 0;
    if (!der_next(&p, end, &tag, &seq, &seq_len) || (tag != DER_SEQUENCE) || (p != end))
    {
        return CKR_DEVICE_ERROR;
    }
    p = seq;
    end = seq + seq_len;
    const CK_BYTE *alg = NULL;
    CK_ULONG alg_len = 0;
    const CK_BYTE *bits = NULL;
    CK_ULONG bits_len = 0;
    if (!der_next(&p, end, &tag, &alg, &alg_len) || (tag != DER_SEQUENCE) ||
        (alg_len != (sizeof(OID_EC_PUBLIC_KEY) + c->oid_len)) ||
        (memcmp(alg, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY)) != 0) ||
        (memcmp(alg + sizeof(OID_EC_PUBLIC_KEY), c->oid, c->oid_len) != 0))
    {
        return CKR_DEVICE_ERROR;
    }
    CK_ULONG point_len = 1 + (2 * c->coord_len);
    if (!der_next(&p, end, &tag, &bits, &bits_len) || (tag != DER_BIT_STRING) || (p != end) ||
        (bits_len != (1 + point_len)) || (bits[0] != 0) || (bits[1] != EC_POINT_UNCOMPRESSED))
    {
        return CKR_DEVICE_ERROR;
    }

    /* From 128 bytes on (the P-521 point) the length takes a long form of one
     * length byte; no point here reaches 256 bytes. */
    CK_BYTE header[3];
    CK_ULONG h = 0;
    header[h++] = DER_OCTET_STRING;
    if (point_len >= DER_LONG_FORM)
    {
        header[h++] = DER_LONG_FORM | 1;
    }
    header[h++] = (CK_BYTE)point_len;
    if (*out_len < (h + point_len))
    {
        *out_len = h + point_len;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(out, header, h);
    memcpy(out + h, bits + 1, point_len);
    *out_len = h + point_len;
    return CKR_OK;
}

bool tsra_pkcs11_ecdsa_raw_len_ok(CK_ULONG len)
{
    return (len == TSRA_PKCS11_SHA1_DIGEST_LEN) || (len == TSRA_PKCS11_SHA256_DIGEST_LEN) ||
           (len == TSRA_PKCS11_SHA384_DIGEST_LEN) || (len == TSRA_PKCS11_SHA512_DIGEST_LEN);
}

/* Check the attributes both templates of a pair share the rules for. */
static CK_RV check_common(const CK_ATTRIBUTE *tmpl, CK_ULONG i, const char **why)
{
    const CK_ATTRIBUTE *a = &tmpl[i];
    CK_RV rv = tsra_pkcs11_attr_check(a);
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* A repeated type would split what the device makes (last value wins)
     * from what is stored and read back (first value wins). */
    if (tsra_pkcs11_tmpl_find(tmpl, i, a->type) != NULL)
    {
        *why = "an attribute is repeated";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    if (tsra_pkcs11_attr_is_token_set(a))
    {
        return CKR_ATTRIBUTE_READ_ONLY;
    }
    if (tsra_pkcs11_attr_is_key_material(a->type) || (a->type == CKA_EC_POINT))
    {
        *why = "a generated key takes no key material or EC point";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    /* The sign init reads a stored list back into a buffer of this size. */
    if ((a->type == CKA_ALLOWED_MECHANISMS) &&
        ((a->ulValueLen == 0) ||
         ((a->ulValueLen / sizeof(CK_MECHANISM_TYPE)) > KEYGEN_MAX_ALLOWED_MECHS)))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    return CKR_OK;
}

/* CKA_CLASS must be `cls` and CKA_KEY_TYPE CKK_EC where the template has
 * them. */
static CK_RV check_class(const CK_ATTRIBUTE *a, CK_OBJECT_CLASS cls, const char **why)
{
    CK_ULONG v = 0;
    if ((a->type != CKA_CLASS) && (a->type != CKA_KEY_TYPE))
    {
        return CKR_OK;
    }
    CK_RV rv = tsra_pkcs11_tmpl_ulong(a, &v);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (((a->type == CKA_CLASS) && (v != cls)) || ((a->type == CKA_KEY_TYPE) && (v != CKK_EC)))
    {
        *why = "the class or key type is not that of an EC key pair";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    return CKR_OK;
}

/* Read the CK_BBOOL attribute of type `t` into *out if `a` is one. */
static CK_RV read_bool(const CK_ATTRIBUTE *a, CK_ATTRIBUTE_TYPE t, CK_BBOOL *out)
{
    return (a->type == t) ? tsra_pkcs11_tmpl_bool(a, out) : CKR_OK;
}

CK_RV tsra_pkcs11_ec_keygen_check(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *pub,
    CK_ULONG pub_count,
    const CK_ATTRIBUTE *priv,
    CK_ULONG priv_count,
    tsra_pkcs11_ec_keygen *out,
    const char **why
)
{
    const char *unused = NULL;
    if (why == NULL)
    {
        why = &unused;
    }
    *why = NULL;
    if ((out == NULL) || ((pub == NULL) && (pub_count > 0)) || ((priv == NULL) && (priv_count > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(out, 0, sizeof(*out));
    if (mech != CKM_EC_KEY_PAIR_GEN)
    {
        return CKR_MECHANISM_INVALID;
    }
    CK_RV rv = tsra_pkcs11_tmpl_check_bounds(pub, pub_count);
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_tmpl_check_bounds(priv, priv_count);
    }
    if (rv != CKR_OK)
    {
        return rv;
    }

    CK_BBOOL verify = CK_FALSE;
    CK_BBOOL pub_derive = CK_FALSE;
    for (CK_ULONG i = 0; (rv == CKR_OK) && (i < pub_count); i++)
    {
        rv = check_common(pub, i, why);
        if (rv == CKR_OK)
        {
            rv = check_class(&pub[i], CKO_PUBLIC_KEY, why);
        }
        if (rv == CKR_OK)
        {
            rv = read_bool(&pub[i], CKA_TOKEN, &out->pub_token);
        }
        if (rv == CKR_OK)
        {
            rv = read_bool(&pub[i], CKA_VERIFY, &verify);
        }
        if (rv == CKR_OK)
        {
            rv = read_bool(&pub[i], CKA_DERIVE, &pub_derive);
        }
    }

    CK_BBOOL sign = CK_FALSE;
    CK_BBOOL derive = CK_FALSE;
    CK_BBOOL sensitive = CK_TRUE;
    CK_BBOOL extractable = CK_FALSE;
    CK_BBOOL always_auth = CK_FALSE;
    for (CK_ULONG i = 0; (rv == CKR_OK) && (i < priv_count); i++)
    {
        rv = check_common(priv, i, why);
        if (rv == CKR_OK)
        {
            rv = check_class(&priv[i], CKO_PRIVATE_KEY, why);
        }
        if (rv == CKR_OK)
        {
            rv = read_bool(&priv[i], CKA_TOKEN, &out->priv_token);
        }
        if (rv == CKR_OK)
        {
            rv = read_bool(&priv[i], CKA_SIGN, &sign);
        }
        if (rv == CKR_OK)
        {
            rv = read_bool(&priv[i], CKA_DERIVE, &derive);
        }
        if (rv == CKR_OK)
        {
            rv = read_bool(&priv[i], CKA_SENSITIVE, &sensitive);
        }
        if (rv == CKR_OK)
        {
            rv = read_bool(&priv[i], CKA_EXTRACTABLE, &extractable);
        }
        if ((rv == CKR_OK) && (!sensitive || extractable))
        {
            /* Device keys only ever exist masked. */
            *why = "the private key must be sensitive and unextractable";
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
        if (rv == CKR_OK)
        {
            rv = read_bool(&priv[i], CKA_ALWAYS_AUTHENTICATE, &always_auth);
        }
        if ((rv == CKR_OK) && always_auth)
        {
            /* Nothing would enforce it: there is no CKU_CONTEXT_SPECIFIC login. */
            *why = "CKA_ALWAYS_AUTHENTICATE is not supported: the token has no "
                   "context-specific login";
            rv = CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }
    if (rv != CKR_OK)
    {
        return rv;
    }

    out->params = tsra_pkcs11_tmpl_find(pub, pub_count, CKA_EC_PARAMS);
    if (out->params == NULL)
    {
        return CKR_TEMPLATE_INCOMPLETE;
    }
    rv = tsra_pkcs11_ec_params_curve(out->params->pValue, out->params->ulValueLen, &out->curve);
    if (rv != CKR_OK)
    {
        return rv;
    }
    const CK_ATTRIBUTE *priv_params = tsra_pkcs11_tmpl_find(priv, priv_count, CKA_EC_PARAMS);
    if ((priv_params != NULL) &&
        ((priv_params->ulValueLen != out->params->ulValueLen) ||
         (memcmp(priv_params->pValue, out->params->pValue, out->params->ulValueLen) != 0)))
    {
        *why = "the private CKA_EC_PARAMS differs from the public one";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    if (sign == derive)
    {
        *why = "an EC private key needs exactly one of CKA_SIGN and CKA_DERIVE: the device "
               "makes a signing key or a deriving key, never both";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    if ((sign && pub_derive) || (derive && verify))
    {
        *why = "the public key usage does not match the private key's";
        return CKR_TEMPLATE_INCONSISTENT;
    }
    out->sign = (sign == CK_TRUE);
    return CKR_OK;
}

CK_RV tsra_pkcs11_ec_keygen_build(
    const tsra_pkcs11_ec_keygen *kg,
    const CK_ATTRIBUTE *pub,
    CK_ULONG pub_count,
    const CK_ATTRIBUTE *priv,
    CK_ULONG priv_count,
    const CK_BYTE *point,
    CK_ULONG point_len,
    tsra_pkcs11_ec_keygen_fill *fill,
    CK_ATTRIBUTE *pub_full,
    CK_ULONG *pub_n,
    CK_ATTRIBUTE *priv_full,
    CK_ULONG *priv_n
)
{
    if ((kg == NULL) || (kg->params == NULL) || (fill == NULL) || (pub_full == NULL) ||
        (pub_n == NULL) || (priv_full == NULL) || (priv_n == NULL) ||
        ((pub == NULL) && (pub_count > 0)) || ((priv == NULL) && (priv_count > 0)) ||
        (point == NULL) || (point_len == 0) || (point_len > sizeof(fill->point)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    fill->pub_cls = CKO_PUBLIC_KEY;
    fill->priv_cls = CKO_PRIVATE_KEY;
    fill->kt = CKK_EC;
    fill->btrue = CK_TRUE;
    fill->bfalse = CK_FALSE;
    fill->kgm = CKM_EC_KEY_PAIR_GEN;
    memcpy(fill->point, point, point_len);
    CK_BBOOL *sign = kg->sign ? &fill->btrue : &fill->bfalse;
    CK_BBOOL *derive = kg->sign ? &fill->bfalse : &fill->btrue;
    const CK_ATTRIBUTE local = { CKA_LOCAL, &fill->btrue, sizeof(fill->btrue) };
    const CK_ATTRIBUTE kgm = { CKA_KEY_GEN_MECHANISM, &fill->kgm, sizeof(fill->kgm) };

    CK_ULONG k = 0;
    for (CK_ULONG i = 0; i < pub_count; i++)
    {
        pub_full[k++] = pub[i];
    }
    tsra_pkcs11_tmpl_append(
        pub_full,
        &k,
        pub,
        pub_count,
        (CK_ATTRIBUTE){ CKA_CLASS, &fill->pub_cls, sizeof(fill->pub_cls) }
    );
    tsra_pkcs11_tmpl_append(
        pub_full,
        &k,
        pub,
        pub_count,
        (CK_ATTRIBUTE){ CKA_KEY_TYPE, &fill->kt, sizeof(fill->kt) }
    );
    tsra_pkcs11_tmpl_append(
        pub_full,
        &k,
        pub,
        pub_count,
        (CK_ATTRIBUTE){ CKA_PRIVATE, &fill->bfalse, sizeof(fill->bfalse) }
    );
    tsra_pkcs11_tmpl_append(
        pub_full,
        &k,
        pub,
        pub_count,
        (CK_ATTRIBUTE){ CKA_VERIFY, sign, sizeof(*sign) }
    );
    tsra_pkcs11_tmpl_append(
        pub_full,
        &k,
        pub,
        pub_count,
        (CK_ATTRIBUTE){ CKA_DERIVE, derive, sizeof(*derive) }
    );
    pub_full[k++] = (CK_ATTRIBUTE){ CKA_EC_POINT, fill->point, point_len };
    pub_full[k++] = local;
    pub_full[k++] = kgm;
    *pub_n = k;

    k = 0;
    for (CK_ULONG i = 0; i < priv_count; i++)
    {
        priv_full[k++] = priv[i];
    }
    tsra_pkcs11_tmpl_append(
        priv_full,
        &k,
        priv,
        priv_count,
        (CK_ATTRIBUTE){ CKA_CLASS, &fill->priv_cls, sizeof(fill->priv_cls) }
    );
    tsra_pkcs11_tmpl_append(
        priv_full,
        &k,
        priv,
        priv_count,
        (CK_ATTRIBUTE){ CKA_KEY_TYPE, &fill->kt, sizeof(fill->kt) }
    );
    tsra_pkcs11_tmpl_append(priv_full, &k, priv, priv_count, *kg->params);
    tsra_pkcs11_tmpl_append(
        priv_full,
        &k,
        priv,
        priv_count,
        (CK_ATTRIBUTE){ CKA_PRIVATE, &fill->btrue, sizeof(fill->btrue) }
    );
    tsra_pkcs11_tmpl_append(
        priv_full,
        &k,
        priv,
        priv_count,
        (CK_ATTRIBUTE){ CKA_SENSITIVE, &fill->btrue, sizeof(fill->btrue) }
    );
    tsra_pkcs11_tmpl_append(
        priv_full,
        &k,
        priv,
        priv_count,
        (CK_ATTRIBUTE){ CKA_EXTRACTABLE, &fill->bfalse, sizeof(fill->bfalse) }
    );
    tsra_pkcs11_tmpl_append(
        priv_full,
        &k,
        priv,
        priv_count,
        (CK_ATTRIBUTE){ CKA_SIGN, sign, sizeof(*sign) }
    );
    tsra_pkcs11_tmpl_append(
        priv_full,
        &k,
        priv,
        priv_count,
        (CK_ATTRIBUTE){ CKA_DERIVE, derive, sizeof(*derive) }
    );
    /* Rejected by the check as inputs, so always appended. */
    priv_full[k++] = local;
    priv_full[k++] = (CK_ATTRIBUTE){ CKA_ALWAYS_SENSITIVE, &fill->btrue, sizeof(fill->btrue) };
    priv_full[k++] = (CK_ATTRIBUTE){ CKA_NEVER_EXTRACTABLE, &fill->btrue, sizeof(fill->btrue) };
    priv_full[k++] = kgm;
    *priv_n = k;
    return CKR_OK;
}
