// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * CKM_ECDH1_DERIVE and CKM_HKDF_DERIVE (see tsra_pkcs11_derive_params.h). The
 * AES target reuses the key-generation template rules; the generic secret and
 * HMAC targets, which only C_DeriveKey makes, are checked here against
 * families of their own and built by the same template builder.
 */

#include "tsra_pkcs11_derive_params.h"
#include "tsra_pkcs11_digest.h"

#include <stdbool.h>
#include <string.h>

_Static_assert(EC_SPKI_DER_MAX <= ECDH_PEER_DER_MAX, "every peer key fits the device command");

/* The usage attributes; a generic secret or HMAC key states TRUE only for the
 * usages of its device key, which keeps them (tsra_pkcs11_setattr_check). */
static const CK_ATTRIBUTE_TYPE USAGES[] = {
    CKA_ENCRYPT,      CKA_DECRYPT, CKA_WRAP,   CKA_UNWRAP,         CKA_SIGN,
    CKA_SIGN_RECOVER, CKA_VERIFY,  CKA_DERIVE, CKA_VERIFY_RECOVER,
};

/*
 * The ECDH secret: a shared secret on the device that only derives, so its
 * only mechanism is HKDF. Its length is the curve's (tsra_pkcs11_ec_coord_len),
 * so it lists none.
 */
static const tsra_pkcs11_keygen_policy POLICY_SHARED_SECRET = {
    .keygen_mech = CK_UNAVAILABLE_INFORMATION,
    .kind = TSRA_PKCS11_KIND_SHARED_SECRET,
    .key_type = CKK_GENERIC_SECRET,
    .value_lens = { 0 },
    .mechs = { CKM_HKDF_DERIVE },
    .mech_count = 1,
    .usages = { CKA_DERIVE },
    .usage_count = 1,
};

/* The HMAC keys HKDF derives: the device fixes the hash and makes the key as
 * long as it (api/lib HsmHmacKey::validate_props), signing and verifying. */
static const tsra_pkcs11_keygen_policy POLICY_HMAC[] = {
    {
        .keygen_mech = CK_UNAVAILABLE_INFORMATION,
        .kind = TSRA_PKCS11_KIND_HMAC_SHA256,
        .key_type = CKK_SHA256_HMAC,
        .value_lens = { TSRA_PKCS11_SHA256_DIGEST_LEN, 0 },
        .mechs = { CKM_SHA256_HMAC },
        .mech_count = 1,
        .usages = { CKA_SIGN, CKA_VERIFY },
        .usage_count = 2,
    },
    {
        .keygen_mech = CK_UNAVAILABLE_INFORMATION,
        .kind = TSRA_PKCS11_KIND_HMAC_SHA384,
        .key_type = CKK_SHA384_HMAC,
        .value_lens = { TSRA_PKCS11_SHA384_DIGEST_LEN, 0 },
        .mechs = { CKM_SHA384_HMAC },
        .mech_count = 1,
        .usages = { CKA_SIGN, CKA_VERIFY },
        .usage_count = 2,
    },
    {
        .keygen_mech = CK_UNAVAILABLE_INFORMATION,
        .kind = TSRA_PKCS11_KIND_HMAC_SHA512,
        .key_type = CKK_SHA512_HMAC,
        .value_lens = { TSRA_PKCS11_SHA512_DIGEST_LEN, 0 },
        .mechs = { CKM_SHA512_HMAC },
        .mech_count = 1,
        .usages = { CKA_SIGN, CKA_VERIFY },
        .usage_count = 2,
    },
};

/* The HKDF PRFs the module takes: SHA-1 is left out, as are the HMAC keys of
 * it, so derivation and HMAC use one hash family. */
static const CK_MECHANISM_TYPE HKDF_PRFS[] = { CKM_SHA256, CKM_SHA384, CKM_SHA512 };

static CK_RV ecdh_params(const CK_MECHANISM *mech, tsra_pkcs11_derive_params *out)
{
    if ((mech->pParameter == NULL) || (mech->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    /* The block carries no alignment guarantee, so it is copied out. */
    CK_ECDH1_DERIVE_PARAMS p;
    memcpy(&p, mech->pParameter, sizeof(p));
    /* With CKD_NULL, PKCS#11 wants no shared data; the SDK has no KDF here. */
    if ((p.kdf != CKD_NULL) || (p.ulSharedDataLen != 0) || (p.pSharedData != NULL) ||
        (p.pPublicData == NULL) || (p.ulPublicDataLen == 0))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    out->public_data = p.pPublicData;
    out->public_len = p.ulPublicDataLen;
    return CKR_OK;
}

static CK_RV hkdf_params(const CK_MECHANISM *mech, tsra_pkcs11_derive_params *out)
{
    if ((mech->pParameter == NULL) || (mech->ulParameterLen != sizeof(CK_HKDF_PARAMS)))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    CK_HKDF_PARAMS p;
    memcpy(&p, mech->pParameter, sizeof(p)); /* unaligned, as for ECDH */
    /* The SDK runs extract and expand together, and nothing else. */
    if ((p.bExtract == CK_FALSE) || (p.bExpand == CK_FALSE))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    bool prf_ok = false;
    for (size_t i = 0; i < (sizeof(HKDF_PRFS) / sizeof(HKDF_PRFS[0])); i++)
    {
        prf_ok = prf_ok || (p.prfHashMechanism == HKDF_PRFS[i]);
    }
    if (!prf_ok)
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    switch (p.ulSaltType)
    {
    case CKF_HKDF_SALT_NULL:
        if (p.ulSaltLen != 0)
        {
            return CKR_MECHANISM_PARAM_INVALID; /* a salt length with no salt */
        }
        break;
    case CKF_HKDF_SALT_DATA:
        if (((p.pSalt == NULL) && (p.ulSaltLen > 0)) || (p.ulSaltLen > HKDF_MAX_SALT_LEN))
        {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        out->salt = (p.ulSaltLen > 0) ? p.pSalt : NULL;
        out->salt_len = p.ulSaltLen;
        break;
    default:
        /* CKF_HKDF_SALT_KEY among them: the SDK takes the salt as bytes only. */
        return CKR_MECHANISM_PARAM_INVALID;
    }
    if (((p.pInfo == NULL) && (p.ulInfoLen > 0)) || (p.ulInfoLen > HKDF_MAX_INFO_LEN))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    out->prf = p.prfHashMechanism;
    out->info = (p.ulInfoLen > 0) ? p.pInfo : NULL;
    out->info_len = p.ulInfoLen;
    return CKR_OK;
}

CK_RV tsra_pkcs11_derive_params_check(const CK_MECHANISM *mech, tsra_pkcs11_derive_params *out)
{
    if ((mech == NULL) || (out == NULL))
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(out, 0, sizeof(*out));
    switch (mech->mechanism)
    {
    case CKM_ECDH1_DERIVE:
        out->mech = CKM_ECDH1_DERIVE;
        out->base_key_type = CKK_EC;
        return ecdh_params(mech, out);
    case CKM_HKDF_DERIVE:
        out->mech = CKM_HKDF_DERIVE;
        out->base_key_type = CKK_GENERIC_SECRET;
        return hkdf_params(mech, out);
    default:
        return CKR_MECHANISM_INVALID;
    }
}

CK_RV tsra_pkcs11_ecdh_peer_spki(
    tsra_pkcs11_ec_curve_t curve,
    const CK_BYTE *data,
    CK_ULONG len,
    CK_BYTE *spki,
    CK_ULONG *spki_len
)
{
    CK_ULONG coord = tsra_pkcs11_ec_coord_len(curve);
    if ((spki == NULL) || (spki_len == NULL) || (coord == 0))
    {
        return CKR_ARGUMENTS_BAD;
    }
    if ((data == NULL) || (len == 0))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    /* PKCS#11 passes the bare point and allows the DER form CKA_EC_POINT
     * holds. The two never have the same length on one curve, so the length
     * picks the form; the DER one is read as CKA_EC_POINT is checked. */
    CK_ULONG point_len = 1 + (2 * coord);
    const CK_BYTE *point = data;
    if ((len != point_len) && !tsra_pkcs11_ec_point_from_der(data, len, curve, &point))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    if (point[0] != EC_POINT_UNCOMPRESSED)
    {
        return CKR_MECHANISM_PARAM_INVALID; /* compressed, hybrid or infinity */
    }
    return tsra_pkcs11_ec_spki_from_point(curve, point, point_len, spki, spki_len);
}

/*
 * Read the fixed-width attribute `type` into `value` (at most a CK_ULONG):
 * CKR_OK only when the object carries it at exactly `len` bytes, and `value`
 * is untouched otherwise. An absent, over-long, short or unreadable one is
 * CKR_ATTRIBUTE_TYPE_INVALID, the policy's "missing"; other failures of `read`
 * pass through.
 */
static CK_RV read_exact(
    tsra_pkcs11_attr_reader read,
    void *ctx,
    CK_ATTRIBUTE_TYPE type,
    void *value,
    CK_ULONG len
)
{
    CK_BYTE buf[sizeof(CK_ULONG)];
    if (len > sizeof(buf))
    {
        return CKR_ARGUMENTS_BAD; /* defensive: the callers read CK_ULONG and CK_BBOOL */
    }
    CK_ATTRIBUTE a = { type, buf, len };
    CK_RV rv = read(ctx, &a);
    if ((rv == CKR_OK) && (a.ulValueLen == len))
    {
        memcpy(value, buf, len);
        return CKR_OK;
    }
    if ((rv == CKR_OK) || (rv == CKR_BUFFER_TOO_SMALL) || (rv == CKR_ATTRIBUTE_TYPE_INVALID) ||
        (rv == CKR_ATTRIBUTE_SENSITIVE))
    {
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }
    return rv;
}

/* Read a CK_BBOOL attribute into *out, FALSE unless the object carries TRUE. */
static CK_RV read_flag(
    tsra_pkcs11_attr_reader read,
    void *ctx,
    CK_ATTRIBUTE_TYPE type,
    CK_BBOOL *out
)
{
    CK_BBOOL b = CK_FALSE;
    CK_RV rv = read_exact(read, ctx, type, &b, sizeof(b));
    *out = ((rv == CKR_OK) && (b != CK_FALSE)) ? CK_TRUE : CK_FALSE;
    return (rv == CKR_ATTRIBUTE_TYPE_INVALID) ? CKR_OK : rv;
}

CK_RV tsra_pkcs11_derive_base_check(
    CK_MECHANISM_TYPE mech,
    tsra_pkcs11_attr_reader read,
    void *ctx,
    tsra_pkcs11_derive_base *out
)
{
    if ((read == NULL) || (out == NULL) ||
        ((mech != CKM_ECDH1_DERIVE) && (mech != CKM_HKDF_DERIVE)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(out, 0, sizeof(*out));
    bool ecdh = (mech == CKM_ECDH1_DERIVE);
    CK_KEY_TYPE kt = CK_UNAVAILABLE_INFORMATION;
    CK_OBJECT_CLASS cls = CK_UNAVAILABLE_INFORMATION;
    CK_BBOOL derive = CK_FALSE;
    CK_RV rv = read_exact(read, ctx, CKA_KEY_TYPE, &kt, sizeof(kt));
    if ((rv == CKR_OK) || (rv == CKR_ATTRIBUTE_TYPE_INVALID))
    {
        rv = read_exact(read, ctx, CKA_CLASS, &cls, sizeof(cls));
    }
    if ((rv == CKR_OK) || (rv == CKR_ATTRIBUTE_TYPE_INVALID))
    {
        rv = read_flag(read, ctx, CKA_DERIVE, &derive);
    }
    /* Only a missing attribute is a policy verdict; a store failure is
     * reported as itself. */
    if ((rv != CKR_OK) && (rv != CKR_ATTRIBUTE_TYPE_INVALID))
    {
        return rv;
    }
    if (kt != (ecdh ? CKK_EC : CKK_GENERIC_SECRET))
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    /* The EC public key holds the pair's masked blob too; only the private
     * key derives. Another class is the wrong kind of key, as SoftHSM's
     * C_DeriveKey answers. */
    if (cls != (ecdh ? CKO_PRIVATE_KEY : CKO_SECRET_KEY))
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (derive == CK_FALSE)
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED; /* as SoftHSM's C_DeriveKey and C_UnwrapKey here */
    }
    CK_MECHANISM_TYPE mechs[KEYGEN_MAX_ALLOWED_MECHS];
    CK_ATTRIBUTE list = { CKA_ALLOWED_MECHANISMS, mechs, sizeof(mechs) };
    rv = read(ctx, &list);
    if ((rv != CKR_OK) && (rv != CKR_ATTRIBUTE_TYPE_INVALID) && (rv != CKR_BUFFER_TOO_SMALL) &&
        (rv != CKR_ATTRIBUTE_SENSITIVE))
    {
        return rv;
    }
    /* No list: every mechanism of the key type, as at C_SignInit. */
    if ((rv != CKR_ATTRIBUTE_TYPE_INVALID) &&
        !tsra_pkcs11_key_mech_permitted(rv, mechs, list.ulValueLen, mech))
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED; /* as C_SignInit and C_EncryptInit here */
    }
    if (ecdh)
    {
        /* The curve fixes the peer point's length before the device is asked. */
        CK_BYTE params[EC_PARAMS_DER_MAX];
        CK_ATTRIBUTE a = { CKA_EC_PARAMS, params, sizeof(params) };
        rv = read(ctx, &a);
        if ((rv != CKR_OK) && (rv != CKR_ATTRIBUTE_TYPE_INVALID) && (rv != CKR_BUFFER_TOO_SMALL) &&
            (rv != CKR_ATTRIBUTE_SENSITIVE))
        {
            return rv;
        }
        if ((rv != CKR_OK) ||
            (tsra_pkcs11_ec_params_curve(params, a.ulValueLen, &out->curve) != CKR_OK))
        {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
    }
    rv = read_flag(read, ctx, CKA_ALWAYS_SENSITIVE, &out->always_sensitive);
    if (rv == CKR_OK)
    {
        rv = read_flag(read, ctx, CKA_NEVER_EXTRACTABLE, &out->never_extractable);
    }
    return rv;
}

/* The family of a key `mech` derives with CKA_KEY_TYPE `kt`, besides AES;
 * NULL for a key type it does not derive. */
static const tsra_pkcs11_keygen_policy *policy_for(CK_MECHANISM_TYPE mech, CK_KEY_TYPE kt)
{
    if (mech == CKM_ECDH1_DERIVE)
    {
        return (kt == CKK_GENERIC_SECRET) ? &POLICY_SHARED_SECRET : NULL;
    }
    for (size_t i = 0; i < (sizeof(POLICY_HMAC) / sizeof(POLICY_HMAC[0])); i++)
    {
        if (POLICY_HMAC[i].key_type == kt)
        {
            return &POLICY_HMAC[i];
        }
    }
    return NULL;
}

static bool has_usage(const tsra_pkcs11_keygen_policy *p, CK_ATTRIBUTE_TYPE t)
{
    for (CK_ULONG i = 0; i < p->usage_count; i++)
    {
        if (p->usages[i] == t)
        {
            return true;
        }
    }
    return false;
}

/* Whether every entry of the CKA_ALLOWED_MECHANISMS attribute `a` is in
 * `p`'s family. tsra_pkcs11_attr_check refused a length that is not whole
 * mechanism types, so the division below drops nothing. */
static bool mechs_within(const CK_ATTRIBUTE *a, const tsra_pkcs11_keygen_policy *p)
{
    for (CK_ULONG i = 0; i < (a->ulValueLen / sizeof(CK_MECHANISM_TYPE)); i++)
    {
        CK_MECHANISM_TYPE m = 0;
        memcpy(&m, (const CK_BYTE *)a->pValue + (i * sizeof(m)), sizeof(m)); /* unaligned */
        bool in = false;
        for (CK_ULONG j = 0; j < p->mech_count; j++)
        {
            in = in || (p->mechs[j] == m);
        }
        if (!in)
        {
            return false;
        }
    }
    return true;
}

/* Copy the checked template into *out, with CKA_VALUE_LEN appended when the
 * caller left it out. */
static void keep_template(
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    bool append_len,
    tsra_pkcs11_derive_target *out
)
{
    if (count > 0)
    {
        memcpy(out->tmpl, tmpl, count * sizeof(*tmpl));
    }
    out->count = count;
    if (append_len)
    {
        out->tmpl[out->count++] =
            (CK_ATTRIBUTE){ CKA_VALUE_LEN, &out->value_len, sizeof(out->value_len) };
    }
}

/* An AES key from HKDF, by the key-generation rules, in the CBC family. */
static CK_RV aes_check(const CK_ATTRIBUTE *tmpl, CK_ULONG count, tsra_pkcs11_derive_target *out)
{
    CK_RV rv = tsra_pkcs11_keygen_check_template(
        CKM_AES_KEY_GEN,
        tmpl,
        count,
        &out->policy,
        &out->value_len,
        &out->token
    );
    /* The SDK derives no GCM key (api/lib HsmGenericSecretKey takes the CBC
     * kind only), whatever the length says. */
    if (((rv == CKR_OK) || (rv == CKR_TEMPLATE_INCOMPLETE)) && (out->policy != NULL) &&
        (out->policy->kind != TSRA_PKCS11_KIND_AES))
    {
        rv = CKR_TEMPLATE_INCONSISTENT;
    }
    if ((rv == CKR_OK) && ((tsra_pkcs11_tmpl_find(tmpl, count, CKA_CLASS) == NULL) ||
                           (tsra_pkcs11_tmpl_find(tmpl, count, CKA_KEY_TYPE) == NULL)))
    {
        rv = CKR_TEMPLATE_INCOMPLETE; /* required, as in secret_check */
    }
    if (rv != CKR_OK)
    {
        out->policy = NULL;
        return rv;
    }
    keep_template(tmpl, count, false, out);
    return CKR_OK;
}

/* A generic secret from ECDH or an HMAC key from HKDF. */
static CK_RV secret_check(
    CK_MECHANISM_TYPE mech,
    tsra_pkcs11_ec_curve_t curve,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    tsra_pkcs11_derive_target *out
)
{
    const tsra_pkcs11_keygen_policy *p = NULL;
    const CK_ATTRIBUTE *allowed = NULL;
    bool have_class = false;
    bool have_len = false;
    CK_ULONG len = 0;
    CK_BBOOL priv = CK_TRUE; /* a derived key is private unless the template says otherwise */
    for (CK_ULONG i = 0; i < count; i++)
    {
        const CK_ATTRIBUTE *a = &tmpl[i];
        CK_RV rv = tsra_pkcs11_attr_check(a);
        if (rv != CKR_OK)
        {
            return rv;
        }
        if (tsra_pkcs11_tmpl_find(tmpl, i, a->type) != NULL)
        {
            return CKR_TEMPLATE_INCONSISTENT; /* which value would be stored is unclear */
        }
        if (tsra_pkcs11_attr_is_token_set(a))
        {
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        if (tsra_pkcs11_attr_is_key_material(a->type))
        {
            return CKR_TEMPLATE_INCONSISTENT; /* the device makes the value */
        }
        /* tsra_pkcs11_attr_check passed the shape, so the reads below succeed. */
        CK_ULONG v = 0;
        CK_BBOOL b = CK_FALSE;
        switch (a->type)
        {
        case CKA_CLASS:
            (void)tsra_pkcs11_tmpl_ulong(a, &v);
            if (v != CKO_SECRET_KEY)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            have_class = true;
            break;
        case CKA_KEY_TYPE:
            (void)tsra_pkcs11_tmpl_ulong(a, &v);
            p = policy_for(mech, v);
            if (p == NULL)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_VALUE_LEN:
            (void)tsra_pkcs11_tmpl_ulong(a, &len);
            have_len = true;
            break;
        case CKA_SENSITIVE:
            (void)tsra_pkcs11_tmpl_bool(a, &b);
            if (b == CK_FALSE)
            {
                return CKR_TEMPLATE_INCONSISTENT; /* the device holds it masked only */
            }
            break;
        case CKA_EXTRACTABLE:
            (void)tsra_pkcs11_tmpl_bool(a, &b);
            if (b != CK_FALSE)
            {
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKA_TOKEN:
            (void)tsra_pkcs11_tmpl_bool(a, &out->token);
            break;
        case CKA_PRIVATE:
            (void)tsra_pkcs11_tmpl_bool(a, &priv);
            break;
        case CKA_ALLOWED_MECHANISMS:
            /* tsra_pkcs11_derive_base_check reads a stored list back into a
             * buffer of this size. */
            if ((a->ulValueLen == 0) ||
                ((a->ulValueLen / sizeof(CK_MECHANISM_TYPE)) > KEYGEN_MAX_ALLOWED_MECHS))
            {
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            allowed = a;
            break;
        default:
            break; /* usages are judged below, the rest is stored verbatim */
        }
    }
    /* Only a sealed record guards a token key, and only private records are. */
    if ((out->token != CK_FALSE) && (priv == CK_FALSE))
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    if (!have_class || (p == NULL))
    {
        /* SoftHSM defaults these only for the CKM_CONCATENATE_* mechanisms. */
        return CKR_TEMPLATE_INCOMPLETE;
    }
    /* The key type can come late in the template, so usages and mechanisms
     * are judged once it is known. */
    for (size_t u = 0; u < (sizeof(USAGES) / sizeof(USAGES[0])); u++)
    {
        CK_BBOOL b = CK_FALSE;
        (void)tsra_pkcs11_tmpl_bool(tsra_pkcs11_tmpl_find(tmpl, count, USAGES[u]), &b);
        if ((b != CK_FALSE) && !has_usage(p, USAGES[u]))
        {
            return CKR_TEMPLATE_INCONSISTENT; /* the device key cannot do it */
        }
    }
    if ((allowed != NULL) && !mechs_within(allowed, p))
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    CK_ULONG want =
        (p == &POLICY_SHARED_SECRET) ? tsra_pkcs11_ec_coord_len(curve) : p->value_lens[0];
    if (have_len && (len != want))
    {
        return CKR_ATTRIBUTE_VALUE_INVALID; /* the device makes no other length */
    }
    out->policy = p;
    out->value_len = want;
    keep_template(tmpl, count, !have_len, out);
    return CKR_OK;
}

CK_RV tsra_pkcs11_derive_check_template(
    CK_MECHANISM_TYPE mech,
    tsra_pkcs11_ec_curve_t curve,
    const CK_ATTRIBUTE *tmpl,
    CK_ULONG count,
    tsra_pkcs11_derive_target *out
)
{
    if (out == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(out, 0, sizeof(*out));
    if (((mech != CKM_ECDH1_DERIVE) && (mech != CKM_HKDF_DERIVE)) ||
        ((mech == CKM_ECDH1_DERIVE) && (tsra_pkcs11_ec_coord_len(curve) == 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    CK_RV rv = tsra_pkcs11_tmpl_check_bounds(tmpl, count);
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* An absent or malformed key type is left for the AES rules to report. */
    CK_KEY_TYPE kt = CKK_AES;
    (void)tsra_pkcs11_tmpl_ulong(tsra_pkcs11_tmpl_find(tmpl, count, CKA_KEY_TYPE), &kt);
    if ((mech == CKM_HKDF_DERIVE) && ((kt == CKK_AES) || (kt == CKK_AES_XTS)))
    {
        return aes_check(tmpl, count, out);
    }
    return secret_check(mech, curve, tmpl, count, out);
}
