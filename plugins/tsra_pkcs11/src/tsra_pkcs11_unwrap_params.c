// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * CKM_RSA_AES_KEY_WRAP and the RSA unwrapping key pair (see
 * tsra_pkcs11_unwrap_params.h).
 */

#include "tsra_pkcs11_unwrap_params.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

/* The DER tags an RSA SubjectPublicKeyInfo is made of. */
#define DER_INTEGER 0x02
#define DER_BIT_STRING 0x03
#define DER_OID 0x06
#define DER_SEQUENCE 0x30
/* Long-form length octets beyond this would describe more than 4 GiB. */
#define DER_MAX_LEN_OCTETS 4

/* rsaEncryption, 1.2.840.113549.1.1.1 (RFC 3279), as DER content octets. */
static const CK_BYTE OID_RSA_ENCRYPTION[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
};

/* The usage attributes of a key pair; each half may carry only its own. */
static const CK_ATTRIBUTE_TYPE USAGE_ATTRS[] = {
    CKA_ENCRYPT,      CKA_DECRYPT, CKA_WRAP,   CKA_UNWRAP,         CKA_SIGN,
    CKA_SIGN_RECOVER, CKA_VERIFY,  CKA_DERIVE, CKA_VERIFY_RECOVER,
};

/* The usages each half states as FALSE when the caller leaves them out. */
static const CK_ATTRIBUTE_TYPE PRIV_OTHER_USAGES[] = { CKA_DECRYPT,
                                                       CKA_SIGN,
                                                       CKA_SIGN_RECOVER,
                                                       CKA_DERIVE };
static const CK_ATTRIBUTE_TYPE PUB_OTHER_USAGES[] = { CKA_ENCRYPT,
                                                      CKA_VERIFY,
                                                      CKA_VERIFY_RECOVER,
                                                      CKA_DERIVE };

_Static_assert(
    (sizeof(PRIV_OTHER_USAGES) / sizeof(PRIV_OTHER_USAGES[0])) ==
        (sizeof(PUB_OTHER_USAGES) / sizeof(PUB_OTHER_USAGES[0])),
    "both halves append the same number of usage defaults"
);

/* The OAEP hashes the SDK unwraps with, each with its MGF1 twin. */
static const struct
{
    CK_MECHANISM_TYPE hash;
    CK_RSA_PKCS_MGF_TYPE mgf;
} OAEP_HASHES[] = {
    { CKM_SHA256, CKG_MGF1_SHA256 },
    { CKM_SHA384, CKG_MGF1_SHA384 },
    { CKM_SHA512, CKG_MGF1_SHA512 },
};

CK_RV tsra_pkcs11_unwrap_params_check(const CK_MECHANISM *mech, tsra_pkcs11_rsa_aes_params *out)
{
    if ((mech == NULL) || (out == NULL))
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(out, 0, sizeof(*out));
    if (mech->mechanism != CKM_RSA_AES_KEY_WRAP)
    {
        return CKR_MECHANISM_INVALID;
    }
    if ((mech->pParameter == NULL) || (mech->ulParameterLen != sizeof(CK_RSA_AES_KEY_WRAP_PARAMS)))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    /* Neither block carries an alignment guarantee, so both are copied out. */
    CK_RSA_AES_KEY_WRAP_PARAMS p;
    memcpy(&p, mech->pParameter, sizeof(p));
    if (((p.ulAESKeyBits != (AES128_KEY_BYTES * CHAR_BIT)) &&
         (p.ulAESKeyBits != (AES192_KEY_BYTES * CHAR_BIT)) &&
         (p.ulAESKeyBits != (AES256_KEY_BYTES * CHAR_BIT))) ||
        (p.pOAEPParams == NULL))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    CK_RSA_PKCS_OAEP_PARAMS oaep;
    memcpy(&oaep, p.pOAEPParams, sizeof(oaep));
    if ((oaep.source != CKZ_DATA_SPECIFIED) || (oaep.ulSourceDataLen != 0))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    for (size_t i = 0; i < (sizeof(OAEP_HASHES) / sizeof(OAEP_HASHES[0])); i++)
    {
        if ((oaep.hashAlg == OAEP_HASHES[i].hash) && (oaep.mgf == OAEP_HASHES[i].mgf))
        {
            out->hash = oaep.hashAlg;
            out->aes_key_bits = p.ulAESKeyBits;
            return CKR_OK;
        }
    }
    return CKR_MECHANISM_PARAM_INVALID;
}

/* How long the blob carrying a key of `key_len` bytes of family `p` is. */
static CK_ULONG blob_len_for(const tsra_pkcs11_keygen_policy *p, CK_ULONG key_len)
{
    CK_ULONG one = RSA_UNWRAP_MODULUS_BYTES + AES_KWP_OVERHEAD;
    if (p->kind == TSRA_PKCS11_KIND_AES_XTS)
    {
        return AES_XTS_BLOB_HEADER + (2 * (one + (key_len / 2)));
    }
    return one + key_len;
}

CK_RV tsra_pkcs11_unwrap_check_template(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ULONG wrapped_len,
    tsra_pkcs11_unwrap_target *out
)
{
    if (out == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(out, 0, sizeof(*out));
    CK_RV rv = tsra_pkcs11_tmpl_check_bounds(tmpl, count);
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* The key type names the family's generation mechanism; a malformed one is
     * left for the check to report. */
    const CK_ATTRIBUTE *type = tsra_pkcs11_tmpl_find(tmpl, count, CKA_KEY_TYPE);
    CK_KEY_TYPE kt = CKK_AES;
    if ((type != NULL) && (type->pValue != NULL) && (type->ulValueLen == sizeof(kt)))
    {
        memcpy(&kt, type->pValue, sizeof(kt));
    }
    rv = tsra_pkcs11_keygen_check_template(
        (kt == CKK_AES_XTS) ? CKM_AES_XTS_KEY_GEN : CKM_AES_KEY_GEN,
        tmpl,
        count,
        &out->policy,
        &out->value_len,
        &out->token
    );
    bool have_len = (rv == CKR_OK);
    if (!have_len && (rv != CKR_TEMPLATE_INCOMPLETE))
    {
        return rv;
    }
    if ((type == NULL) || (tsra_pkcs11_tmpl_find(tmpl, count, CKA_CLASS) == NULL))
    {
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* Without CKA_VALUE_LEN the blob's length names the key's. */
    bool derived = false;
    for (CK_ULONG i = 0; !have_len && (out->policy->value_lens[i] != 0); i++)
    {
        if (blob_len_for(out->policy, out->policy->value_lens[i]) == wrapped_len)
        {
            out->value_len = out->policy->value_lens[i];
            have_len = true;
            derived = true;
        }
    }
    if (!have_len || (blob_len_for(out->policy, out->value_len) != wrapped_len))
    {
        return CKR_WRAPPED_KEY_LEN_RANGE;
    }
    if (count > 0)
    {
        memcpy(out->tmpl, tmpl, count * sizeof(*tmpl));
    }
    out->count = count;
    if (derived)
    {
        out->tmpl[out->count++] =
            (CK_ATTRIBUTE){ CKA_VALUE_LEN, &out->value_len, sizeof(out->value_len) };
    }
    return CKR_OK;
}

/* Read the fixed-width attribute `type` into `value`: CKR_OK only when the
 * object carries it at exactly `len` bytes, CKR_ATTRIBUTE_TYPE_INVALID when
 * it carries it at another width; `read` failures otherwise pass through. */
static CK_RV read_exact(
    tsra_pkcs11_attr_reader read,
    void *ctx,
    CK_ATTRIBUTE_TYPE type,
    void *value,
    CK_ULONG len
)
{
    CK_ATTRIBUTE a = { type, value, len };
    CK_RV rv = read(ctx, &a);
    if ((rv == CKR_BUFFER_TOO_SMALL) || ((rv == CKR_OK) && (a.ulValueLen != len)))
    {
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    return rv;
}

CK_RV tsra_pkcs11_unwrapping_key_check(tsra_pkcs11_attr_reader read, void *ctx)
{
    if (read == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    CK_OBJECT_CLASS cls = 0;
    CK_RV rv = read_exact(read, ctx, CKA_CLASS, &cls, sizeof(cls));
    if (rv == CKR_OBJECT_HANDLE_INVALID)
    {
        return CKR_UNWRAPPING_KEY_HANDLE_INVALID;
    }
    CK_KEY_TYPE kt = 0;
    if (rv == CKR_OK)
    {
        rv = read_exact(read, ctx, CKA_KEY_TYPE, &kt, sizeof(kt));
    }
    if ((rv == CKR_ATTRIBUTE_TYPE_INVALID) || (rv == CKR_ATTRIBUTE_SENSITIVE) ||
        ((rv == CKR_OK) && ((cls != CKO_PRIVATE_KEY) || (kt != CKK_RSA))))
    {
        return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
    }
    if (rv != CKR_OK)
    {
        return rv;
    }
    CK_BBOOL unwrap = CK_FALSE;
    rv = read_exact(read, ctx, CKA_UNWRAP, &unwrap, sizeof(unwrap));
    if ((rv == CKR_ATTRIBUTE_TYPE_INVALID) || (rv == CKR_ATTRIBUTE_SENSITIVE) ||
        ((rv == CKR_OK) && !unwrap))
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    return rv;
}

/* Whether `t` is one of the key pair usage attributes. */
static bool is_usage(CK_ATTRIBUTE_TYPE t)
{
    for (size_t i = 0; i < (sizeof(USAGE_ATTRS) / sizeof(USAGE_ATTRS[0])); i++)
    {
        if (USAGE_ATTRS[i] == t)
        {
            return true;
        }
    }
    return false;
}

/* Read a CK_ULONG-wide attribute the shape check already passed. */
static CK_ULONG ulong_value(const CK_ATTRIBUTE *a)
{
    CK_ULONG v = 0;
    memcpy(&v, a->pValue, sizeof(v));
    return v;
}

/* The check of one half of the unwrapping key pair request; see
 * tsra_pkcs11_unwrapping_pair_check. */
static CK_RV half_check(bool priv, const CK_ATTRIBUTE *tmpl, CK_ULONG count, CK_BBOOL *token)
{
    CK_ATTRIBUTE_TYPE own = priv ? CKA_UNWRAP : CKA_WRAP;
    bool have_own = false;
    bool have_bits = false;
    *token = CK_FALSE;
    CK_RV rv = tsra_pkcs11_tmpl_check_bounds(tmpl, count);
    for (CK_ULONG i = 0; (rv == CKR_OK) && (i < count); i++)
    {
        const CK_ATTRIBUTE *a = &tmpl[i];
        rv = tsra_pkcs11_attr_check(a);
        if (rv != CKR_OK)
        {
            break;
        }
        CK_BBOOL b = CK_FALSE;
        if (tsra_pkcs11_tmpl_find(tmpl, i, a->type) != NULL)
        {
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
        else if (tsra_pkcs11_attr_is_token_set(a))
        {
            rv = CKR_ATTRIBUTE_READ_ONLY;
        }
        else if (tsra_pkcs11_attr_is_key_material(a->type))
        {
            rv = CKR_TEMPLATE_INCONSISTENT;
        }
        else if (is_usage(a->type))
        {
            /* The shape check left exactly one CK_BBOOL to read. */
            b = *(const CK_BBOOL *)a->pValue;
            have_own = have_own || ((a->type == own) && b);
            rv = ((a->type == own) == (b != CK_FALSE)) ? CKR_OK : CKR_TEMPLATE_INCONSISTENT;
        }
        else
        {
            switch (a->type)
            {
            case CKA_CLASS:
                rv = (ulong_value(a) == (priv ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY))
                         ? CKR_OK
                         : CKR_TEMPLATE_INCONSISTENT;
                break;
            case CKA_KEY_TYPE:
                rv = (ulong_value(a) == CKK_RSA) ? CKR_OK : CKR_TEMPLATE_INCONSISTENT;
                break;
            case CKA_MODULUS_BITS:
                have_bits = true;
                rv = (!priv && (ulong_value(a) == RSA_UNWRAP_KEY_BITS)) ? CKR_OK
                                                                        : CKR_TEMPLATE_INCONSISTENT;
                break;
            case CKA_MODULUS:
                rv = CKR_TEMPLATE_INCONSISTENT; /* the device's, not the caller's */
                break;
            case CKA_PUBLIC_EXPONENT:
                rv = priv ? CKR_TEMPLATE_INCONSISTENT : CKR_OK;
                break;
            case CKA_SENSITIVE:
            case CKA_EXTRACTABLE:
                /* The device key never leaves the device. */
                b = *(const CK_BBOOL *)a->pValue;
                rv = (!priv || ((b != CK_FALSE) == (a->type == CKA_SENSITIVE)))
                         ? CKR_OK
                         : CKR_TEMPLATE_INCONSISTENT;
                break;
            case CKA_ALWAYS_AUTHENTICATE:
                /* Nothing would enforce it: there is no CKU_CONTEXT_SPECIFIC login. */
                rv = (*(const CK_BBOOL *)a->pValue == CK_FALSE) ? CKR_OK
                                                                : CKR_ATTRIBUTE_VALUE_INVALID;
                break;
            case CKA_ALLOWED_MECHANISMS:
                rv = (a->ulValueLen > 0) ? CKR_OK : CKR_TEMPLATE_INCONSISTENT;
                for (CK_ULONG m = 0;
                     (rv == CKR_OK) && (m < (a->ulValueLen / sizeof(CK_MECHANISM_TYPE)));
                     m++)
                {
                    CK_MECHANISM_TYPE t = 0;
                    memcpy(&t, (const CK_BYTE *)a->pValue + (m * sizeof(t)), sizeof(t));
                    rv = (t == CKM_RSA_AES_KEY_WRAP) ? CKR_OK : CKR_TEMPLATE_INCONSISTENT;
                }
                break;
            case CKA_TOKEN:
                rv = tsra_pkcs11_tmpl_bool(a, token);
                break;
            default:
                break; /* stored verbatim on the object */
            }
        }
    }
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (!have_own)
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    return (priv || have_bits) ? CKR_OK : CKR_TEMPLATE_INCOMPLETE;
}

CK_RV tsra_pkcs11_unwrapping_pair_check(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *pub,
    CK_ULONG npub,
    const CK_ATTRIBUTE *priv,
    CK_ULONG npriv,
    CK_BBOOL *pub_token,
    CK_BBOOL *priv_token
)
{
    if ((pub_token == NULL) || (priv_token == NULL) || ((pub == NULL) && (npub > 0)) ||
        ((priv == NULL) && (npriv > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    *pub_token = CK_FALSE;
    *priv_token = CK_FALSE;
    if (mech != CKM_RSA_PKCS_KEY_PAIR_GEN)
    {
        return CKR_MECHANISM_INVALID;
    }
    CK_RV rv = half_check(false, pub, npub, pub_token);
    return (rv == CKR_OK) ? half_check(true, priv, npriv, priv_token) : rv;
}

/*
 * The DER element at *p, which must end by `end` and carry `tag`: *val and
 * *val_len receive its content, and *p moves past it.
 */
static bool der_next(
    const CK_BYTE **p,
    const CK_BYTE *end,
    CK_BYTE tag,
    const CK_BYTE **val,
    CK_ULONG *val_len
)
{
    const CK_BYTE *q = *p;
    if (((end - q) < 2) || (*q++ != tag))
    {
        return false;
    }
    CK_ULONG len = *q++;
    if ((len & 0x80u) != 0)
    {
        CK_ULONG octets = len & 0x7Fu;
        if ((octets == 0) || (octets > DER_MAX_LEN_OCTETS) || ((CK_ULONG)(end - q) < octets))
        {
            return false;
        }
        len = 0;
        for (CK_ULONG i = 0; i < octets; i++)
        {
            len = (len << 8) | *q++;
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

/* A DER INTEGER's content as a positive big-endian number without leading
 * zeros; false for a negative or zero one. */
static bool der_positive(const CK_BYTE **v, CK_ULONG *len)
{
    if ((*len == 0) || (((*v)[0] & 0x80u) != 0))
    {
        return false;
    }
    while ((*len > 0) && ((*v)[0] == 0))
    {
        (*v)++;
        (*len)--;
    }
    return *len > 0;
}

bool tsra_pkcs11_spki_rsa(const CK_BYTE *der, CK_ULONG len, tsra_pkcs11_rsa_public *out)
{
    if ((der == NULL) || (out == NULL))
    {
        return false;
    }
    const CK_BYTE *end = der + len;
    const CK_BYTE *spki = NULL;
    const CK_BYTE *alg = NULL;
    const CK_BYTE *oid = NULL;
    const CK_BYTE *bits = NULL;
    const CK_BYTE *rsa = NULL;
    CK_ULONG spki_len = 0;
    CK_ULONG alg_len = 0;
    CK_ULONG oid_len = 0;
    CK_ULONG bits_len = 0;
    CK_ULONG rsa_len = 0;
    const CK_BYTE *p = der;
    if (!der_next(&p, end, DER_SEQUENCE, &spki, &spki_len) || (p != end))
    {
        return false;
    }
    p = spki;
    end = spki + spki_len;
    if (!der_next(&p, end, DER_SEQUENCE, &alg, &alg_len) ||
        !der_next(&p, end, DER_BIT_STRING, &bits, &bits_len) || (p != end))
    {
        return false;
    }
    const CK_BYTE *a = alg;
    if (!der_next(&a, alg + alg_len, DER_OID, &oid, &oid_len) ||
        (oid_len != sizeof(OID_RSA_ENCRYPTION)) ||
        (memcmp(oid, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION)) != 0))
    {
        return false;
    }
    /* The key is the bit string's content after its unused-bits octet, 0. */
    if ((bits_len < 1) || (bits[0] != 0))
    {
        return false;
    }
    p = bits + 1;
    end = bits + bits_len;
    if (!der_next(&p, end, DER_SEQUENCE, &rsa, &rsa_len) || (p != end))
    {
        return false;
    }
    p = rsa;
    end = rsa + rsa_len;
    tsra_pkcs11_rsa_public k;
    if (!der_next(&p, end, DER_INTEGER, &k.n, &k.n_len) ||
        !der_next(&p, end, DER_INTEGER, &k.e, &k.e_len) || (p != end) ||
        !der_positive(&k.n, &k.n_len) || !der_positive(&k.e, &k.e_len))
    {
        return false;
    }
    *out = k;
    return true;
}

CK_RV tsra_pkcs11_unwrapping_half_build(
    bool priv,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    const tsra_pkcs11_rsa_public *key,
    tsra_pkcs11_pair_fill *fill,
    CK_ATTRIBUTE *full,
    CK_ULONG *n
)
{
    if ((key == NULL) || (key->n == NULL) || (key->e == NULL) || (fill == NULL) || (full == NULL) ||
        (n == NULL) || ((tmpl == NULL) && (count > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    /* A caller's exponent may carry leading zeros; its value must be the key's. */
    const CK_ATTRIBUTE *exp = tsra_pkcs11_tmpl_find(tmpl, count, CKA_PUBLIC_EXPONENT);
    if (exp != NULL)
    {
        const CK_BYTE *v = (const CK_BYTE *)exp->pValue;
        CK_ULONG len = exp->ulValueLen;
        while ((len > 0) && (v[0] == 0))
        {
            v++;
            len--;
        }
        if ((len != key->e_len) || (memcmp(v, key->e, len) != 0))
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
    }
    tsra_pkcs11_digest_op_t *sha1 = NULL;
    CK_RV rv = tsra_pkcs11_digest_op_new(CKM_SHA_1, &sha1);
    if (rv != CKR_OK)
    {
        return rv;
    }
    tsra_pkcs11_digest_op_update(sha1, key->n, key->n_len);
    tsra_pkcs11_digest_op_final(sha1, fill->id);
    tsra_pkcs11_digest_op_free(sha1);
    fill->cls = priv ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
    fill->kt = CKK_RSA;
    fill->btrue = CK_TRUE;
    fill->bfalse = CK_FALSE;
    fill->kgm = CKM_RSA_PKCS_KEY_PAIR_GEN;
    fill->mech = CKM_RSA_AES_KEY_WRAP;

    CK_ULONG k = 0;
    for (CK_ULONG i = 0; i < count; i++)
    {
        full[k++] = tmpl[i];
    }
    CK_ATTRIBUTE defaults[] = {
        { CKA_CLASS, &fill->cls, sizeof(fill->cls) },
        { CKA_KEY_TYPE, &fill->kt, sizeof(fill->kt) },
        { CKA_PRIVATE, priv ? &fill->btrue : &fill->bfalse, sizeof(CK_BBOOL) },
        { CKA_ID, fill->id, sizeof(fill->id) },
        { CKA_PUBLIC_EXPONENT, (void *)key->e, key->e_len },
        { CKA_ALLOWED_MECHANISMS, &fill->mech, sizeof(fill->mech) },
    };
    for (size_t i = 0; i < (sizeof(defaults) / sizeof(defaults[0])); i++)
    {
        tsra_pkcs11_tmpl_append(full, &k, tmpl, count, defaults[i]);
    }
    const CK_ATTRIBUTE_TYPE *others = priv ? PRIV_OTHER_USAGES : PUB_OTHER_USAGES;
    for (size_t i = 0; i < (sizeof(PUB_OTHER_USAGES) / sizeof(PUB_OTHER_USAGES[0])); i++)
    {
        tsra_pkcs11_tmpl_append(
            full,
            &k,
            tmpl,
            count,
            (CK_ATTRIBUTE){ others[i], &fill->bfalse, sizeof(fill->bfalse) }
        );
    }
    if (priv)
    {
        tsra_pkcs11_tmpl_append(
            full,
            &k,
            tmpl,
            count,
            (CK_ATTRIBUTE){ CKA_SENSITIVE, &fill->btrue, sizeof(fill->btrue) }
        );
        tsra_pkcs11_tmpl_append(
            full,
            &k,
            tmpl,
            count,
            (CK_ATTRIBUTE){ CKA_EXTRACTABLE, &fill->bfalse, sizeof(fill->bfalse) }
        );
        full[k++] = (CK_ATTRIBUTE){ CKA_ALWAYS_SENSITIVE, &fill->btrue, sizeof(fill->btrue) };
        full[k++] = (CK_ATTRIBUTE){ CKA_NEVER_EXTRACTABLE, &fill->btrue, sizeof(fill->btrue) };
    }
    /* Rejected by the check as inputs, so always appended. */
    full[k++] = (CK_ATTRIBUTE){ CKA_MODULUS, (void *)key->n, key->n_len };
    full[k++] = (CK_ATTRIBUTE){ CKA_LOCAL, &fill->btrue, sizeof(fill->btrue) };
    full[k++] = (CK_ATTRIBUTE){ CKA_KEY_GEN_MECHANISM, &fill->kgm, sizeof(fill->kgm) };
    *n = k;
    return CKR_OK;
}
