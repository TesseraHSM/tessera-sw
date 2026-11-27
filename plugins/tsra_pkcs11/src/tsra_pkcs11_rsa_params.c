// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * The RSA mechanism parameters (see tsra_pkcs11_rsa_params.h). The mechanism
 * table and the sign table elsewhere decide which mechanisms exist; this file
 * only judges their parameters.
 */

#include "tsra_pkcs11_rsa_params.h"
#include "tsra_pkcs11_digest.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The two bytes RFC 8017 encodings add on top of the hash lengths: the 0xbc
 * trailer and the 0x01 separator of PSS, the leading 0x00 and the 0x01
 * separator of OAEP. */
#define RSA_PAD_FIXED_BYTES 2

/* The hashes the RSA mechanisms run, each with its MGF1 twin. */
static const struct
{
    CK_MECHANISM_TYPE hash;
    CK_RSA_PKCS_MGF_TYPE mgf;
} MGF1[] = {
    { CKM_SHA_1, CKG_MGF1_SHA1 },
    { CKM_SHA256, CKG_MGF1_SHA256 },
    { CKM_SHA384, CKG_MGF1_SHA384 },
    { CKM_SHA512, CKG_MGF1_SHA512 },
};

/* The PSS mechanisms and the hash each signs with; 0 for the pre-hashed one,
 * which takes any hash of MGF1. */
static const struct
{
    CK_MECHANISM_TYPE mech;
    CK_MECHANISM_TYPE hash;
} PSS_MECHS[] = {
    { CKM_RSA_PKCS_PSS, 0 },
    { CKM_SHA1_RSA_PKCS_PSS, CKM_SHA_1 },
    { CKM_SHA256_RSA_PKCS_PSS, CKM_SHA256 },
    { CKM_SHA384_RSA_PKCS_PSS, CKM_SHA384 },
    { CKM_SHA512_RSA_PKCS_PSS, CKM_SHA512 },
};

/* Whether `mgf` is MGF1 with `hash`, a hash of MGF1. */
static bool mgf1_of(CK_MECHANISM_TYPE hash, CK_RSA_PKCS_MGF_TYPE mgf)
{
    for (size_t i = 0; i < (sizeof(MGF1) / sizeof(MGF1[0])); i++)
    {
        if (MGF1[i].hash == hash)
        {
            return MGF1[i].mgf == mgf;
        }
    }
    return false;
}

CK_RV tsra_pkcs11_sign_params_check(
    const CK_MECHANISM *mech,
    CK_RSA_PKCS_PSS_PARAMS *pss,
    bool *is_pss
)
{
    if ((mech == NULL) || (pss == NULL) || (is_pss == NULL))
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(pss, 0, sizeof(*pss));
    *is_pss = false;
    size_t i = 0;
    while ((i < (sizeof(PSS_MECHS) / sizeof(PSS_MECHS[0]))) &&
           (PSS_MECHS[i].mech != mech->mechanism))
    {
        i++;
    }
    if (i == (sizeof(PSS_MECHS) / sizeof(PSS_MECHS[0])))
    {
        return ((mech->pParameter == NULL) && (mech->ulParameterLen == 0))
                   ? CKR_OK
                   : CKR_MECHANISM_PARAM_INVALID;
    }
    if ((mech->pParameter == NULL) || (mech->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS)))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    /* pParameter carries no alignment guarantee, so it is copied out. */
    CK_RSA_PKCS_PSS_PARAMS p;
    memcpy(&p, mech->pParameter, sizeof(p));
    if (((PSS_MECHS[i].hash != 0) && (p.hashAlg != PSS_MECHS[i].hash)) ||
        !mgf1_of(p.hashAlg, p.mgf))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    *pss = p;
    *is_pss = true;
    return CKR_OK;
}

bool tsra_pkcs11_pss_salt_ok(CK_ULONG mod_bits, const CK_RSA_PKCS_PSS_PARAMS *pss)
{
    CK_ULONG h_len = (pss != NULL) ? tsra_pkcs11_digest_mech_len(pss->hashAlg) : 0;
    if ((h_len == 0) || (mod_bits == 0))
    {
        return false;
    }
    CK_ULONG em_len = ((mod_bits - 1) + (CHAR_BIT - 1)) / CHAR_BIT;
    return (em_len >= (h_len + RSA_PAD_FIXED_BYTES)) &&
           (pss->sLen <= (em_len - h_len - RSA_PAD_FIXED_BYTES));
}

CK_RV tsra_pkcs11_oaep_params_check(const void *param, CK_ULONG len, tsra_pkcs11_oaep_params *out)
{
    if (out == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(out, 0, sizeof(*out));
    if ((param == NULL) || (len != sizeof(CK_RSA_PKCS_OAEP_PARAMS)))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    CK_RSA_PKCS_OAEP_PARAMS p;
    memcpy(&p, param, sizeof(p));
    if (((p.hashAlg != CKM_SHA256) && (p.hashAlg != CKM_SHA384) && (p.hashAlg != CKM_SHA512)) ||
        !mgf1_of(p.hashAlg, p.mgf) || (p.source != CKZ_DATA_SPECIFIED) ||
        ((p.pSourceData == NULL) && (p.ulSourceDataLen > 0)) ||
        (p.ulSourceDataLen > (CK_ULONG)UINT32_MAX))
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    out->hash = p.hashAlg;
    if (p.ulSourceDataLen > 0)
    {
        out->label = (const CK_BYTE *)p.pSourceData;
        out->label_len = p.ulSourceDataLen;
    }
    return CKR_OK;
}

CK_ULONG tsra_pkcs11_oaep_max_msg(CK_ULONG mod_len, CK_MECHANISM_TYPE hash)
{
    CK_ULONG h_len = tsra_pkcs11_digest_mech_len(hash);
    if ((h_len == 0) || (mod_len < ((2 * h_len) + RSA_PAD_FIXED_BYTES)))
    {
        return 0;
    }
    return mod_len - (2 * h_len) - RSA_PAD_FIXED_BYTES;
}
