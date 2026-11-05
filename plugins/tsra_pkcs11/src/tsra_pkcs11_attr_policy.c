// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * C_CreateObject, C_SetAttributeValue and C_DestroyObject policy (see
 * tsra_pkcs11_attr_policy.h).
 */

#include "tsra_pkcs11_attr_policy.h"
#include "tsra_pkcs11_ec_template.h"
#include "tsra_pkcs11_template.h"

#include <stddef.h>
#include <string.h>

/* Object classes a rule applies to. */
#define P11_CLS_DATA 0x01u
#define P11_CLS_SECRET 0x02u
#define P11_CLS_PUBLIC 0x04u
#define P11_CLS_PRIVATE 0x08u
#define P11_CLS_CERT 0x10u
#define P11_CLS_OTHER 0x20u /* any other class, or none recorded */
#define P11_CLS_KEY (P11_CLS_SECRET | P11_CLS_PUBLIC | P11_CLS_PRIVATE)
#define P11_CLS_ANY (P11_CLS_DATA | P11_CLS_CERT | P11_CLS_KEY | P11_CLS_OTHER)

typedef enum
{
    P11_VAL_ANY = 0,     /* any value of the attribute's type */
    P11_VAL_LATCH_TRUE,  /* a CK_BBOOL that, once TRUE, stays TRUE */
    P11_VAL_LATCH_FALSE, /* a CK_BBOOL that, once FALSE, stays FALSE */
    P11_VAL_FIXED,       /* defined for the class, never modifiable */
} value_rule;

typedef struct
{
    CK_ATTRIBUTE_TYPE type;
    unsigned classes;
    value_rule rule;
} attr_rule;

/*
 * The footnote-8 attributes of PKCS#11 v3.1 §4 for the classes this module
 * stores, then the attributes those classes define as fixed. Storage-object
 * attributes other than CKA_LABEL change only through C_CopyObject, and
 * data-object attributes carry no footnote 8. Listing the fixed ones keeps the
 * answer CKR_ATTRIBUTE_READ_ONLY even when the store never recorded the
 * attribute (a CKA_TOKEN left to its default, say); an attribute on neither list
 * is read-only if the object carries it and invalid if it does not.
 */
static const attr_rule ATTR_RULES[] = {
    { CKA_LABEL, P11_CLS_ANY, P11_VAL_ANY },
    { CKA_ID, P11_CLS_KEY, P11_VAL_ANY },
    { CKA_START_DATE, P11_CLS_KEY, P11_VAL_ANY },
    { CKA_END_DATE, P11_CLS_KEY, P11_VAL_ANY },
    { CKA_DERIVE, P11_CLS_KEY, P11_VAL_ANY },
    { CKA_SUBJECT, P11_CLS_PUBLIC | P11_CLS_PRIVATE, P11_VAL_ANY },
    { CKA_ENCRYPT, P11_CLS_SECRET | P11_CLS_PUBLIC, P11_VAL_ANY },
    { CKA_VERIFY, P11_CLS_SECRET | P11_CLS_PUBLIC, P11_VAL_ANY },
    { CKA_WRAP, P11_CLS_SECRET | P11_CLS_PUBLIC, P11_VAL_ANY },
    { CKA_VERIFY_RECOVER, P11_CLS_PUBLIC, P11_VAL_ANY },
    { CKA_DECRYPT, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_ANY },
    { CKA_SIGN, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_ANY },
    { CKA_UNWRAP, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_ANY },
    { CKA_SIGN_RECOVER, P11_CLS_PRIVATE, P11_VAL_ANY },
    { CKA_SENSITIVE, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_LATCH_TRUE },
    { CKA_WRAP_WITH_TRUSTED, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_LATCH_TRUE },
    { CKA_EXTRACTABLE, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_LATCH_FALSE },

    { CKA_CLASS, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_TOKEN, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_PRIVATE, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_MODIFIABLE, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_COPYABLE, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_DESTROYABLE, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_UNIQUE_ID, P11_CLS_ANY, P11_VAL_FIXED },
    { CKA_APPLICATION, P11_CLS_DATA, P11_VAL_FIXED },
    { CKA_OBJECT_ID, P11_CLS_DATA, P11_VAL_FIXED },
    { CKA_VALUE, P11_CLS_DATA | P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_FIXED },
    { CKA_KEY_TYPE, P11_CLS_KEY, P11_VAL_FIXED },
    { CKA_LOCAL, P11_CLS_KEY, P11_VAL_FIXED },
    { CKA_KEY_GEN_MECHANISM, P11_CLS_KEY, P11_VAL_FIXED },
    { CKA_ALLOWED_MECHANISMS, P11_CLS_KEY, P11_VAL_FIXED },
    { CKA_VALUE_LEN, P11_CLS_SECRET, P11_VAL_FIXED },
    { CKA_CHECK_VALUE, P11_CLS_SECRET, P11_VAL_FIXED },
    { CKA_ALWAYS_SENSITIVE, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_FIXED },
    { CKA_NEVER_EXTRACTABLE, P11_CLS_SECRET | P11_CLS_PRIVATE, P11_VAL_FIXED },
};

static const attr_rule *find_rule(CK_ATTRIBUTE_TYPE type, unsigned cls)
{
    for (size_t i = 0; i < sizeof(ATTR_RULES) / sizeof(ATTR_RULES[0]); i++)
    {
        if ((ATTR_RULES[i].type == type) && ((ATTR_RULES[i].classes & cls) != 0))
        {
            return &ATTR_RULES[i];
        }
    }
    return NULL;
}

/*
 * The object's current CK_BBOOL `type`: `absent` when it does not carry one,
 * `malformed` when the stored value is not a CK_BBOOL. Callers pass the
 * restrictive reading as `malformed`, so a bad stored value never loosens a
 * rule.
 */
static CK_RV read_bool(
    tsra_pkcs11_attr_reader read,
    void *ctx,
    CK_ATTRIBUTE_TYPE type,
    CK_BBOOL absent,
    CK_BBOOL malformed,
    CK_BBOOL *out
)
{
    CK_BBOOL b = CK_FALSE;
    CK_ATTRIBUTE a = { type, &b, sizeof(b) };
    CK_RV rv = read(ctx, &a);
    if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
    {
        *out = absent;
        return CKR_OK;
    }
    if ((rv == CKR_OK) && (a.ulValueLen == sizeof(b)))
    {
        *out = (b != CK_FALSE) ? CK_TRUE : CK_FALSE;
        return CKR_OK;
    }
    if ((rv == CKR_OK) || (rv == CKR_BUFFER_TOO_SMALL) || (rv == CKR_ATTRIBUTE_SENSITIVE))
    {
        *out = malformed;
        return CKR_OK;
    }
    return rv;
}

/* The rule-table bit of object class `cls`; P11_CLS_OTHER for a class this
 * module does not store, which C_CreateObject refuses. */
static unsigned class_bit(CK_OBJECT_CLASS cls)
{
    switch (cls)
    {
    case CKO_DATA:
        return P11_CLS_DATA;
    case CKO_CERTIFICATE:
        return P11_CLS_CERT;
    case CKO_SECRET_KEY:
        return P11_CLS_SECRET;
    case CKO_PUBLIC_KEY:
        return P11_CLS_PUBLIC;
    case CKO_PRIVATE_KEY:
        return P11_CLS_PRIVATE;
    default:
        return P11_CLS_OTHER;
    }
}

/*
 * Map CKA_CLASS to the rule-table bit. An object with no CKA_CLASS, or with one
 * that is not a CK_OBJECT_CLASS (the store holds what it is given, and a file
 * store can be edited), is still a valid target: it gets P11_CLS_OTHER, the
 * most restrictive class (only CKA_LABEL may change), and the read outcome
 * that says so is not an error of the call. Only a failure to read the object
 * at all, such as CKR_OBJECT_HANDLE_INVALID, is returned.
 */
static CK_RV read_class(tsra_pkcs11_attr_reader read, void *ctx, unsigned *out)
{
    *out = P11_CLS_OTHER;
    CK_OBJECT_CLASS cls = 0;
    CK_ATTRIBUTE a = { CKA_CLASS, &cls, sizeof(cls) };
    CK_RV rv = read(ctx, &a);
    if ((rv == CKR_ATTRIBUTE_TYPE_INVALID) || (rv == CKR_BUFFER_TOO_SMALL) ||
        (rv == CKR_ATTRIBUTE_SENSITIVE))
    {
        return CKR_OK; /* absent, too wide, or unreadable: no usable class */
    }
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (a.ulValueLen != sizeof(cls))
    {
        return CKR_OK; /* too narrow: no usable class */
    }
    *out = class_bit(cls);
    return CKR_OK;
}

/* The object-level gates of C_SetAttributeValue and C_DestroyObject, in this
 * order: a token object needs a read/write session, and the object's `allow`
 * flag (CKA_MODIFIABLE or CKA_DESTROYABLE; TRUE when absent) must be TRUE. */
static CK_RV object_gate(
    tsra_pkcs11_attr_reader read,
    void *ctx,
    CK_BBOOL rw_session,
    CK_ATTRIBUTE_TYPE allow
)
{
    CK_BBOOL token = CK_FALSE;
    CK_RV rv = read_bool(read, ctx, CKA_TOKEN, CK_FALSE, CK_TRUE, &token);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (token && !rw_session)
    {
        return CKR_SESSION_READ_ONLY;
    }
    CK_BBOOL allowed = CK_TRUE;
    rv = read_bool(read, ctx, allow, CK_TRUE, CK_FALSE, &allowed);
    if (rv != CKR_OK)
    {
        return rv;
    }
    return allowed ? CKR_OK : CKR_ACTION_PROHIBITED;
}

/* Whether the object carries `type` at all (a sensitive value counts). */
static CK_RV carries(tsra_pkcs11_attr_reader read, void *ctx, CK_ATTRIBUTE_TYPE type, CK_BBOOL *out)
{
    CK_ATTRIBUTE a = { type, NULL, 0 };
    CK_RV rv = read(ctx, &a);
    if ((rv == CKR_OK) || (rv == CKR_ATTRIBUTE_SENSITIVE))
    {
        *out = CK_TRUE;
        return CKR_OK;
    }
    if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
    {
        *out = CK_FALSE;
        return CKR_OK;
    }
    return rv;
}

static CK_RV check_value(
    const attr_rule *r,
    const CK_ATTRIBUTE *a,
    tsra_pkcs11_attr_reader read,
    void *ctx
)
{
    CK_BBOOL want = CK_FALSE;
    CK_BBOOL cur = CK_FALSE;
    CK_RV rv = CKR_OK;
    switch (r->rule)
    {
    case P11_VAL_FIXED:
        return CKR_ATTRIBUTE_READ_ONLY;
    case P11_VAL_ANY:
        return CKR_OK; /* the shape is checked already */
    case P11_VAL_LATCH_TRUE:
        rv = tsra_pkcs11_tmpl_bool(a, &want);
        if (rv == CKR_OK)
        {
            rv = read_bool(read, ctx, a->type, CK_FALSE, CK_TRUE, &cur);
        }
        if ((rv == CKR_OK) && cur && !want)
        {
            rv = CKR_ATTRIBUTE_READ_ONLY;
        }
        return rv;
    case P11_VAL_LATCH_FALSE:
        rv = tsra_pkcs11_tmpl_bool(a, &want);
        if (rv == CKR_OK)
        {
            /* Absent reads as TRUE, as C_GetAttributeValue's sensitivity gate
             * treats a missing CKA_EXTRACTABLE. */
            rv = read_bool(read, ctx, a->type, CK_TRUE, CK_FALSE, &cur);
        }
        if ((rv == CKR_OK) && !cur && want)
        {
            rv = CKR_ATTRIBUTE_READ_ONLY;
        }
        return rv;
    }
    return CKR_GENERAL_ERROR; /* unreachable: every rule is handled above */
}

CK_RV tsra_pkcs11_setattr_check(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_BBOOL rw_session,
    tsra_pkcs11_attr_reader read,
    void *ctx
)
{
    if (read == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    CK_RV rv = tsra_pkcs11_tmpl_check_bounds(tmpl, count);
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* Read first even for an empty template: it is also what proves the handle. */
    rv = object_gate(read, ctx, rw_session, CKA_MODIFIABLE);
    if (rv != CKR_OK)
    {
        return rv;
    }
    unsigned cls = P11_CLS_OTHER;
    rv = read_class(read, ctx, &cls);
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
        if (tsra_pkcs11_tmpl_find(tmpl, i, a->type) != NULL)
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        const attr_rule *r = find_rule(a->type, cls);
        if (r == NULL)
        {
            CK_BBOOL has = CK_FALSE;
            rv = carries(read, ctx, a->type, &has);
            if (rv != CKR_OK)
            {
                return rv;
            }
            return has ? CKR_ATTRIBUTE_READ_ONLY : CKR_ATTRIBUTE_TYPE_INVALID;
        }
        rv = check_value(r, a, read, ctx);
        if (rv != CKR_OK)
        {
            return rv;
        }
    }
    return CKR_OK;
}

CK_RV tsra_pkcs11_destroy_check(CK_BBOOL rw_session, tsra_pkcs11_attr_reader read, void *ctx)
{
    if (read == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    return object_gate(read, ctx, rw_session, CKA_DESTROYABLE);
}

/*
 * A public key of a type this token uses needs what it cannot be used
 * without: an EC key its curve, one the token supports, and a point encoded
 * for that curve; an RSA key its modulus and exponent. Other key types are
 * stored as given.
 */
static CK_RV public_key_check(const CK_ATTRIBUTE *tmpl, CK_ULONG count)
{
    CK_ULONG kt = 0;
    const CK_ATTRIBUTE *type = tsra_pkcs11_tmpl_find(tmpl, count, CKA_KEY_TYPE);
    if ((type == NULL) || (tsra_pkcs11_tmpl_ulong(type, &kt) != CKR_OK))
    {
        return CKR_OK;
    }
    if (kt == CKK_RSA)
    {
        return ((tsra_pkcs11_tmpl_find(tmpl, count, CKA_MODULUS) != NULL) &&
                (tsra_pkcs11_tmpl_find(tmpl, count, CKA_PUBLIC_EXPONENT) != NULL))
                   ? CKR_OK
                   : CKR_TEMPLATE_INCOMPLETE;
    }
    if (kt != CKK_EC)
    {
        return CKR_OK;
    }
    const CK_ATTRIBUTE *params = tsra_pkcs11_tmpl_find(tmpl, count, CKA_EC_PARAMS);
    const CK_ATTRIBUTE *point = tsra_pkcs11_tmpl_find(tmpl, count, CKA_EC_POINT);
    if ((params == NULL) || (point == NULL))
    {
        return CKR_TEMPLATE_INCOMPLETE;
    }
    tsra_pkcs11_ec_curve_t curve = TSRA_PKCS11_CURVE_NONE;
    CK_RV rv = tsra_pkcs11_ec_params_curve(params->pValue, params->ulValueLen, &curve);
    return (rv == CKR_OK) ? tsra_pkcs11_ec_point_check(point->pValue, point->ulValueLen, curve)
                          : rv;
}

CK_RV tsra_pkcs11_create_check(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    CK_BBOOL rw_session,
    CK_BBOOL *token
)
{
    if (token == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    *token = CK_FALSE;
    CK_RV rv = tsra_pkcs11_tmpl_check_bounds(tmpl, count);
    if (rv != CKR_OK)
    {
        return rv;
    }
    CK_BBOOL have_class = CK_FALSE;
    CK_BBOOL material = CK_FALSE;
    CK_OBJECT_CLASS cls = 0;
    for (CK_ULONG i = 0; i < count; i++)
    {
        const CK_ATTRIBUTE *a = &tmpl[i];
        rv = tsra_pkcs11_attr_check(a);
        if (rv != CKR_OK)
        {
            return rv;
        }
        /* Which of two values the object has would depend on who reads it. */
        if (tsra_pkcs11_tmpl_find(tmpl, i, a->type) != NULL)
        {
            return CKR_TEMPLATE_INCONSISTENT;
        }
        if (tsra_pkcs11_attr_is_token_set(a))
        {
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        if (a->type == CKA_CLASS)
        {
            memcpy(&cls, a->pValue, sizeof(cls)); /* shape checked, may be unaligned */
            have_class = CK_TRUE;
        }
        else if (a->type == CKA_TOKEN)
        {
            *token = (*(const CK_BBOOL *)a->pValue != CK_FALSE) ? CK_TRUE : CK_FALSE;
        }
        else if (tsra_pkcs11_attr_is_key_material(a->type))
        {
            material = CK_TRUE;
        }
    }
    if (*token && !rw_session)
    {
        return CKR_SESSION_READ_ONLY;
    }
    if (!have_class)
    {
        return CKR_TEMPLATE_INCOMPLETE;
    }
    if (class_bit(cls) == P11_CLS_OTHER)
    {
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    CK_BBOOL secret = ((cls == CKO_SECRET_KEY) || (cls == CKO_PRIVATE_KEY)) ? CK_TRUE : CK_FALSE;
    if ((secret || (cls == CKO_PUBLIC_KEY)) && material)
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    if (secret)
    {
        return CKR_TEMPLATE_INCOMPLETE;
    }
    return (cls == CKO_PUBLIC_KEY) ? public_key_check(tmpl, count) : CKR_OK;
}
