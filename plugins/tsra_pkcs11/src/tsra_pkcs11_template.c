// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * AES key-generation template handling and the cipher mechanism policy (see
 * tsra_pkcs11_template.h). This is the CKA_ → key-property normaliser: the
 * device prop list is built from the extracted values only, never from the raw
 * template — the SDK hard-rejects SENSITIVE/EXTRACTABLE/LOCAL as inputs and
 * takes u32/1-byte property values where PKCS#11 has CK_ULONG/CK_BBOOL.
 */

#include "tsra_pkcs11_template.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The one tag length the device produces, in the unit CK_GCM_PARAMS uses. */
#define GCM_TAG_BITS (AES_GCM_TAG_LEN * 8)

/* XTS tweaks are held to their low 64 bits: V2 device sessions refuse more and
 * the mock ignores the rest, so one rule holds on every session kind. */
#define XTS_TWEAK_LOW_LEN sizeof(uint64_t)

/* The key families C_GenerateKey can produce; see tsra_pkcs11_keygen_policy. */
static const tsra_pkcs11_keygen_policy POLICY_AES = {
    .keygen_mech = CKM_AES_KEY_GEN,
    .kind = TSRA_PKCS11_KIND_AES,
    .key_type = CKK_AES,
    .value_lens = { AES128_KEY_BYTES, AES192_KEY_BYTES, AES256_KEY_BYTES, 0 },
    .mechs = { CKM_AES_CBC, CKM_AES_CBC_PAD },
    .mech_count = 2,
};
static const tsra_pkcs11_keygen_policy POLICY_AES_GCM = {
    .keygen_mech = CKM_AES_KEY_GEN,
    .kind = TSRA_PKCS11_KIND_AES_GCM,
    .key_type = CKK_AES,
    .value_lens = { AES256_KEY_BYTES, 0 },
    .mechs = { CKM_AES_GCM },
    .mech_count = 1,
};
static const tsra_pkcs11_keygen_policy POLICY_AES_XTS = {
    .keygen_mech = CKM_AES_XTS_KEY_GEN,
    .kind = TSRA_PKCS11_KIND_AES_XTS,
    .key_type = CKK_AES_XTS,
    .value_lens = { AES_XTS_KEY_BYTES, 0 },
    .mechs = { CKM_AES_XTS },
    .mech_count = 1,
};

static const tsra_pkcs11_cipher_mech CIPHER_MECHS[] = {
    { CKM_AES_CBC, TSRA_PKCS11_KIND_AES, CKK_AES },
    { CKM_AES_CBC_PAD, TSRA_PKCS11_KIND_AES, CKK_AES },
    { CKM_AES_GCM, TSRA_PKCS11_KIND_AES_GCM, CKK_AES },
    { CKM_AES_XTS, TSRA_PKCS11_KIND_AES_XTS, CKK_AES_XTS },
};

static const tsra_pkcs11_sign_mech SIGN_MECHS[] = {
    { CKM_ECDSA, CKK_EC, false },       { CKM_ECDSA_SHA1, CKK_EC, true },
    { CKM_ECDSA_SHA256, CKK_EC, true }, { CKM_ECDSA_SHA384, CKK_EC, true },
    { CKM_ECDSA_SHA512, CKK_EC, true },
};

const CK_ATTRIBUTE *tsra_pkcs11_tmpl_find(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ATTRIBUTE_TYPE t
)
{
    if (tmpl == NULL)
    {
        return NULL;
    }
    for (CK_ULONG i = 0; i < count; i++)
    {
        if (tmpl[i].type == t)
        {
            return &tmpl[i];
        }
    }
    return NULL;
}

CK_RV tsra_pkcs11_tmpl_bool(const CK_ATTRIBUTE *a, CK_BBOOL *out)
{
    if ((a == NULL) || (a->pValue == NULL) || (out == NULL))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (a->ulValueLen != sizeof(CK_BBOOL))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    *out = (*(const CK_BBOOL *)a->pValue != CK_FALSE) ? CK_TRUE : CK_FALSE;
    return CKR_OK;
}

/* CKA_CLASS, CKA_KEY_TYPE and CKA_VALUE_LEN are all CK_ULONG-wide, so one
 * decoder serves all three; the call sites keep naming their own type. */
_Static_assert(sizeof(CK_OBJECT_CLASS) == sizeof(CK_ULONG), "CKA_CLASS is CK_ULONG-wide");
_Static_assert(sizeof(CK_KEY_TYPE) == sizeof(CK_ULONG), "CKA_KEY_TYPE is CK_ULONG-wide");

/*
 * pValue is whatever pointer the caller handed us and carries no alignment
 * guarantee (a template packed into a byte buffer is enough to misalign it),
 * so the value is copied out instead of dereferenced through a cast. Reading
 * a CK_BBOOL needs no such care: it is one byte wide.
 */
CK_RV tsra_pkcs11_tmpl_ulong(const CK_ATTRIBUTE *a, CK_ULONG *out)
{
    if ((a == NULL) || (a->pValue == NULL) || (out == NULL))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (a->ulValueLen != sizeof(CK_ULONG))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    memcpy(out, a->pValue, sizeof(*out));
    return CKR_OK;
}

/*
 * Entry `i` of a CK_MECHANISM_TYPE array attribute. The value is whatever
 * pointer the caller handed us, with no alignment guarantee, so it is copied
 * out rather than indexed through a cast (see tsra_pkcs11_tmpl_ulong).
 */
static CK_MECHANISM_TYPE mech_at(const void *value, CK_ULONG i)
{
    CK_MECHANISM_TYPE m;
    memcpy(&m, (const CK_BYTE *)value + (i * sizeof(m)), sizeof(m));
    return m;
}

static bool policy_has_mech(const tsra_pkcs11_keygen_policy *p, CK_MECHANISM_TYPE m)
{
    for (CK_ULONG i = 0; i < p->mech_count; i++)
    {
        if (p->mechs[i] == m)
        {
            return true;
        }
    }
    return false;
}

static bool policy_has_len(const tsra_pkcs11_keygen_policy *p, CK_ULONG len)
{
    for (CK_ULONG i = 0; p->value_lens[i] != 0; i++)
    {
        if (p->value_lens[i] == len)
        {
            return true;
        }
    }
    return false;
}

/* Whether every entry of the CKA_ALLOWED_MECHANISMS attribute `a` (shape
 * already checked) lies in `p`'s family. */
static bool list_within(const CK_ATTRIBUTE *a, const tsra_pkcs11_keygen_policy *p)
{
    CK_ULONG n = a->ulValueLen / sizeof(CK_MECHANISM_TYPE);
    for (CK_ULONG i = 0; i < n; i++)
    {
        if (!policy_has_mech(p, mech_at(a->pValue, i)))
        {
            return false;
        }
    }
    return true;
}

/* The family `mech` generates, given the caller's CKA_ALLOWED_MECHANISMS
 * (`allowed`, NULL if absent). */
static CK_RV resolve_policy(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *allowed,
    const tsra_pkcs11_keygen_policy **out
)
{
    if (mech == CKM_AES_XTS_KEY_GEN)
    {
        if ((allowed != NULL) && !list_within(allowed, &POLICY_AES_XTS))
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        *out = &POLICY_AES_XTS;
        return CKR_OK;
    }
    /* CKM_AES_KEY_GEN: PKCS#11 has no GCM key-generation mechanism, so the
     * allowed-mechanism list is how a caller asks for the GCM kind. */
    if ((allowed == NULL) || list_within(allowed, &POLICY_AES))
    {
        *out = &POLICY_AES;
        return CKR_OK;
    }
    if (list_within(allowed, &POLICY_AES_GCM))
    {
        *out = &POLICY_AES_GCM;
        return CKR_OK;
    }
    /* Mixed families, or a mechanism no AES key from this token can serve. */
    return CKR_TEMPLATE_INCONSISTENT;
}

CK_RV tsra_pkcs11_keygen_check_template(
    CK_MECHANISM_TYPE mech,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    const tsra_pkcs11_keygen_policy **policy,
    CK_ULONG *value_len,
    CK_BBOOL *token
)
{
    if ((policy == NULL) || (value_len == NULL) || (token == NULL) ||
        ((tmpl == NULL) && (count > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    *policy = NULL;
    *value_len = 0;
    *token = CK_FALSE;
    if ((mech != CKM_AES_KEY_GEN) && (mech != CKM_AES_XTS_KEY_GEN))
    {
        return CKR_MECHANISM_INVALID;
    }
    CK_BBOOL have_value_len = CK_FALSE;
    CK_BBOOL have_key_type = CK_FALSE;
    CK_KEY_TYPE key_type = 0;
    const CK_ATTRIBUTE *allowed = NULL;

    CK_RV rv = tsra_pkcs11_tmpl_check_bounds(tmpl, count);
    if (rv != CKR_OK)
    {
        return rv;
    }
    for (CK_ULONG i = 0; i < count; i++)
    {
        const CK_ATTRIBUTE *a = &tmpl[i];
        rv = tsra_pkcs11_attr_check(a);
        if (rv != CKR_OK)
        {
            return rv;
        }
        /* A type repeated with a different value is inconsistent, and would also
         * split the generation input (last value wins) from what is stored and
         * later read back (first value wins). */
        if (tsra_pkcs11_tmpl_find(tmpl, i, a->type) != NULL)
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        if (tsra_pkcs11_attr_is_token_set(a))
        {
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        if (tsra_pkcs11_attr_is_key_material(a->type))
        {
            return CKR_TEMPLATE_INCONSISTENT; /* generated keys take no material */
        }
        CK_BBOOL b = CK_FALSE;
        CK_ULONG scalar = 0;
        switch (a->type)
        {
        case CKA_CLASS:
            rv = tsra_pkcs11_tmpl_ulong(a, &scalar);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if ((CK_OBJECT_CLASS)scalar != CKO_SECRET_KEY)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_KEY_TYPE:
            rv = tsra_pkcs11_tmpl_ulong(a, &scalar);
            if (rv != CKR_OK)
            {
                return rv;
            }
            /* Not an AES type at all is wrong for any family; which of the two
             * the family wants is checked once the family is known. */
            if (((CK_KEY_TYPE)scalar != CKK_AES) && ((CK_KEY_TYPE)scalar != CKK_AES_XTS))
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            key_type = (CK_KEY_TYPE)scalar;
            have_key_type = CK_TRUE;
            break;
        case CKA_VALUE_LEN:
            rv = tsra_pkcs11_tmpl_ulong(a, value_len);
            if (rv != CKR_OK)
            {
                return rv;
            }
            /* Likewise: a length no family has is wrong at once. */
            if ((*value_len != AES128_KEY_BYTES) && (*value_len != AES192_KEY_BYTES) &&
                (*value_len != AES256_KEY_BYTES) && (*value_len != AES_XTS_KEY_BYTES))
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            have_value_len = CK_TRUE;
            break;
        case CKA_ALLOWED_MECHANISMS:
            if ((a->ulValueLen == 0) ||
                ((a->ulValueLen / sizeof(CK_MECHANISM_TYPE)) > KEYGEN_MAX_ALLOWED_MECHS))
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            allowed = a;
            break;
        case CKA_SENSITIVE:
            rv = tsra_pkcs11_tmpl_bool(a, &b);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if (!b)
            {
                /* Device keys only ever exist masked; a non-sensitive (readable)
                 * key cannot be produced. */
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_EXTRACTABLE:
            rv = tsra_pkcs11_tmpl_bool(a, &b);
            if (rv != CKR_OK)
            {
                return rv;
            }
            if (b)
            {
                return CKR_TEMPLATE_INCONSISTENT; /* see CKA_SENSITIVE */
            }
            break;
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
            /* Direction policy is stored and enforced host-side at operation
             * init (the device key always carries both — see
             * tsra_pkcs11_key.h); only the value's shape is checked here. */
            rv = tsra_pkcs11_tmpl_bool(a, &b);
            if (rv != CKR_OK)
            {
                return rv;
            }
            break;
        case CKA_TOKEN:
            rv = tsra_pkcs11_tmpl_bool(a, token);
            if (rv != CKR_OK)
            {
                return rv;
            }
            break;
        default:
            break; /* stored verbatim on the object */
        }
    }

    const tsra_pkcs11_keygen_policy *p = NULL;
    rv = resolve_policy(mech, allowed, &p);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (have_key_type && (key_type != p->key_type))
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    /* The key-generation mechanisms derive the strength solely from
     * CKA_VALUE_LEN; an unwrap takes it from the wrapped key instead. */
    *policy = p;
    if (!have_value_len)
    {
        return CKR_TEMPLATE_INCOMPLETE;
    }
    if (!policy_has_len(p, *value_len))
    {
        *policy = NULL;
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    return CKR_OK;
}

void tsra_pkcs11_tmpl_append(
    CK_ATTRIBUTE *full,
    CK_ULONG *n,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_ATTRIBUTE a
)
{
    if (tsra_pkcs11_tmpl_find(tmpl, count, a.type) == NULL)
    {
        full[(*n)++] = a;
    }
}

CK_RV tsra_pkcs11_keygen_build_template(
    const tsra_pkcs11_keygen_policy *policy,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    bool local,
    tsra_pkcs11_keygen_fill *fill,
    CK_ATTRIBUTE *full,
    CK_ULONG *n
)
{
    if ((policy == NULL) || (fill == NULL) || (full == NULL) || (n == NULL) ||
        ((tmpl == NULL) && (count > 0)) || (policy->mech_count == 0) ||
        (policy->mech_count > KEYGEN_MAX_KEY_MECHS))
    {
        return CKR_ARGUMENTS_BAD;
    }
    fill->cls = CKO_SECRET_KEY;
    fill->kt = policy->key_type;
    fill->btrue = CK_TRUE;
    fill->bfalse = CK_FALSE;
    fill->kgm = local ? policy->keygen_mech : CK_UNAVAILABLE_INFORMATION;
    memcpy(fill->mechs, policy->mechs, policy->mech_count * sizeof(fill->mechs[0]));

    CK_ULONG k = 0;
    for (CK_ULONG i = 0; i < count; i++)
    {
        full[k++] = tmpl[i];
    }
    tsra_pkcs11_tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE){ CKA_CLASS, &fill->cls, sizeof(fill->cls) }
    );
    tsra_pkcs11_tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE){ CKA_KEY_TYPE, &fill->kt, sizeof(fill->kt) }
    );
    tsra_pkcs11_tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE){ CKA_PRIVATE, &fill->btrue, sizeof(fill->btrue) }
    );
    tsra_pkcs11_tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE
        ){ CKA_ALLOWED_MECHANISMS, fill->mechs, policy->mech_count * sizeof(fill->mechs[0]) }
    );
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
    tsra_pkcs11_tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE){ CKA_ENCRYPT, &fill->btrue, sizeof(fill->btrue) }
    );
    tsra_pkcs11_tmpl_append(
        full,
        &k,
        tmpl,
        count,
        (CK_ATTRIBUTE){ CKA_DECRYPT, &fill->btrue, sizeof(fill->btrue) }
    );
    /* Rejected by the check as inputs, so always appended. A key that came
     * from outside the token has been neither local nor always protected. */
    CK_BBOOL *origin = local ? &fill->btrue : &fill->bfalse;
    full[k++] = (CK_ATTRIBUTE){ CKA_LOCAL, origin, sizeof(*origin) };
    full[k++] = (CK_ATTRIBUTE){ CKA_ALWAYS_SENSITIVE, origin, sizeof(*origin) };
    full[k++] = (CK_ATTRIBUTE){ CKA_NEVER_EXTRACTABLE, origin, sizeof(*origin) };
    full[k++] = (CK_ATTRIBUTE){ CKA_KEY_GEN_MECHANISM, &fill->kgm, sizeof(fill->kgm) };
    *n = k;
    return CKR_OK;
}

tsra_pkcs11_key_scope_t tsra_pkcs11_key_scope_props(CK_BBOOL ck_token, CK_BBOOL ck_private)
{
    (void)ck_token;
    (void)ck_private;
    return TSRA_PKCS11_SCOPE_PARTITION;
}

/* ========================================================================= */
/* Cipher mechanism policy                                                   */
/* ========================================================================= */

const tsra_pkcs11_cipher_mech *tsra_pkcs11_cipher_mech_find(CK_MECHANISM_TYPE mech)
{
    for (size_t i = 0; i < (sizeof(CIPHER_MECHS) / sizeof(CIPHER_MECHS[0])); i++)
    {
        if (CIPHER_MECHS[i].mech == mech)
        {
            return &CIPHER_MECHS[i];
        }
    }
    return NULL;
}

const tsra_pkcs11_sign_mech *tsra_pkcs11_sign_mech_find(CK_MECHANISM_TYPE mech)
{
    for (size_t i = 0; i < (sizeof(SIGN_MECHS) / sizeof(SIGN_MECHS[0])); i++)
    {
        if (SIGN_MECHS[i].mech == mech)
        {
            return &SIGN_MECHS[i];
        }
    }
    return NULL;
}

bool tsra_pkcs11_key_mech_permitted(
    CK_RV get_rv,
    const void *value,
    CK_ULONG len,
    CK_MECHANISM_TYPE mech
)
{
    if (get_rv == CKR_ATTRIBUTE_TYPE_INVALID)
    {
        return policy_has_mech(&POLICY_AES, mech);
    }
    if ((get_rv != CKR_OK) || (value == NULL) || ((len % sizeof(CK_MECHANISM_TYPE)) != 0))
    {
        return false;
    }
    CK_ULONG n = len / sizeof(CK_MECHANISM_TYPE);
    for (CK_ULONG i = 0; i < n; i++)
    {
        if (mech_at(value, i) == mech)
        {
            return true;
        }
    }
    return false;
}

CK_RV tsra_pkcs11_xts_tweak_check(const void *param, CK_ULONG param_len)
{
    if ((param == NULL) || (param_len != AES_XTS_TWEAK_LEN))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    /* Little-endian: the low 64 bits come first. */
    const CK_BYTE *b = (const CK_BYTE *)param;
    bool low_all_ones = true;
    for (CK_ULONG i = 0; i < AES_XTS_TWEAK_LEN; i++)
    {
        if ((i >= XTS_TWEAK_LOW_LEN) && (b[i] != 0))
        {
            return CKR_MECHANISM_PARAM_INVALID; /* at or above 2^64 */
        }
        if ((i < XTS_TWEAK_LOW_LEN) && (b[i] != 0xFF))
        {
            low_all_ones = false;
        }
    }
    /* 2^64 - 1 cannot be advanced past the data unit within 64 bits. */
    return low_all_ones ? CKR_MECHANISM_PARAM_INVALID : CKR_OK;
}

CK_RV tsra_pkcs11_gcm_params_check(const void *param, CK_ULONG param_len, CK_GCM_PARAMS *out)
{
    if (out == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if ((param == NULL) || (param_len != sizeof(CK_GCM_PARAMS)))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    /* pParameter carries no alignment guarantee either. */
    memcpy(out, param, sizeof(*out));
    if ((out->pIv == NULL) || (out->ulIvLen != AES_GCM_IV_LEN) ||
        (out->ulTagBits != GCM_TAG_BITS) || ((out->pAAD == NULL) && (out->ulAADLen > 0)) ||
        (out->ulAADLen > (CK_ULONG)UINT32_MAX))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    return CKR_OK;
}

CK_RV tsra_pkcs11_cipher_out_len(
    CK_MECHANISM_TYPE mech,
    bool encrypt,
    CK_ULONG in_len,
    CK_ULONG *out_len
)
{
    if (out_len == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    *out_len = 0;
    CK_RV range = encrypt ? CKR_DATA_LEN_RANGE : CKR_ENCRYPTED_DATA_LEN_RANGE;
    switch (mech)
    {
    case CKM_AES_GCM:
        /* The device buffers are 32-bit, and the appended tag must not push
         * the reported length past a 32-bit CK_ULONG either. */
        if (encrypt)
        {
            if (in_len > ((CK_ULONG)UINT32_MAX - AES_GCM_TAG_LEN))
            {
                return range;
            }
            *out_len = in_len + AES_GCM_TAG_LEN;
        }
        else
        {
            if ((in_len < AES_GCM_TAG_LEN) || (in_len > (CK_ULONG)UINT32_MAX))
            {
                return range;
            }
            *out_len = in_len - AES_GCM_TAG_LEN;
        }
        return CKR_OK;
    case CKM_AES_XTS:
        if ((in_len == 0) || ((in_len % AES_BLOCK_LEN) != 0) || (in_len > AES_XTS_MAX_DATA_LEN))
        {
            return range;
        }
        *out_len = in_len;
        return CKR_OK;
    default:
        return CKR_MECHANISM_INVALID;
    }
}

bool tsra_pkcs11_gcm_fits(CK_ULONG aad_len, CK_ULONG data_len)
{
    /* Either length past 32 bits cannot fit, and with a 64-bit CK_ULONG the
     * sum below would wrap. */
    if (((uint64_t)aad_len > UINT32_MAX) || ((uint64_t)data_len > UINT32_MAX))
    {
        return false;
    }
    /* 64-bit arithmetic: CK_ULONG is only 32 bits wide on LLP64 platforms. */
    uint64_t padded =
        (((uint64_t)aad_len + (AES_GCM_AAD_ALIGN - 1)) / AES_GCM_AAD_ALIGN) * AES_GCM_AAD_ALIGN;
    return (padded + (uint64_t)data_len) <= (uint64_t)UINT32_MAX;
}

CK_RV tsra_pkcs11_cbc_final_check(
    bool encrypt,
    bool pad,
    CK_ULONG fed_mod,
    bool fed_any,
    bool *run_final
)
{
    if (run_final == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    *run_final = false;
    if (encrypt)
    {
        if (!pad && (fed_mod != 0))
        {
            return CKR_DATA_LEN_RANGE;
        }
    }
    else if ((fed_mod != 0) || (pad && !fed_any))
    {
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    *run_final = pad || fed_any;
    return CKR_OK;
}

bool tsra_pkcs11_multipart_fits(
    CK_MECHANISM_TYPE mech,
    bool encrypt,
    CK_ULONG aad_len,
    CK_ULONG total
)
{
    switch (mech)
    {
    case CKM_AES_GCM:
        if (encrypt)
        {
            return (total <= ((CK_ULONG)UINT32_MAX - AES_GCM_TAG_LEN)) &&
                   tsra_pkcs11_gcm_fits(aad_len, total);
        }
        /* Until the tag is complete there is no ciphertext to measure. */
        return (total <= (CK_ULONG)UINT32_MAX) &&
               ((total < AES_GCM_TAG_LEN) || tsra_pkcs11_gcm_fits(aad_len, total - AES_GCM_TAG_LEN)
               );
    case CKM_AES_XTS:
        return total <= AES_XTS_MAX_DATA_LEN;
    default:
        return false;
    }
}
