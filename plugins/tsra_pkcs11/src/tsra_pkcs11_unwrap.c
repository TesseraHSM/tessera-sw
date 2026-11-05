// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Key import: C_UnwrapKey with CKM_RSA_AES_KEY_WRAP into AES, AES-GCM and
 * AES-XTS keys, and the partition's RSA unwrapping key pair that it unwraps
 * with, which C_GenerateKeyPair hands out as objects. Unwrap is the only way
 * a key made outside the token enters it; there is no plaintext import and no
 * C_WrapKey, since no key ever leaves the device.
 *
 * The unwrapping key lives on the device for good, so its objects carry no
 * key body: C_UnwrapKey fetches the device key afresh each time and checks
 * that it is still the key the object describes. The pure CK_MECHANISM,
 * template and DER logic is in tsra_pkcs11_unwrap_params.c, the device calls
 * in tsra_pkcs11_key.c.
 */

#include "tsra_pkcs11_internal.h"
#include "tsra_pkcs11_key.h"
#include "tsra_pkcs11_unwrap_params.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* The object a policy check reads; the caller holds the login. */
typedef struct
{
    CK_SLOT_ID slot;
    CK_OBJECT_HANDLE h;
} object_ref;

static CK_RV read_object(void *ctx, CK_ATTRIBUTE *a)
{
    const object_ref *o = (const object_ref *)ctx;
    return g_tsra_pkcs11.store.ops->get_attr(g_tsra_pkcs11.store.ctx, o->slot, CK_TRUE, o->h, a, 1);
}

CK_RV tsra_pkcs11_unwrapping_pair_generate(
    tsra_pkcs11_session_t *s,
    uint32_t hsm_session,
    const CK_ATTRIBUTE *pub,
    CK_ULONG pub_count,
    const CK_ATTRIBUTE *priv,
    CK_ULONG priv_count,
    CK_OBJECT_HANDLE *h_pub,
    CK_OBJECT_HANDLE *h_priv
)
{
    if ((s == NULL) || (h_pub == NULL) || (h_priv == NULL))
    {
        return CKR_ARGUMENTS_BAD;
    }
    CK_BBOOL pub_token = CK_FALSE;
    CK_BBOOL priv_token = CK_FALSE;
    CK_RV rv = tsra_pkcs11_unwrapping_pair_check(
        CKM_RSA_PKCS_KEY_PAIR_GEN,
        pub,
        pub_count,
        priv,
        priv_count,
        &pub_token,
        &priv_token
    );
    if ((rv == CKR_OK) && (pub_token || priv_token) && ((s->flags & CKF_RW_SESSION) == 0))
    {
        rv = CKR_SESSION_READ_ONLY;
    }
    if (rv != CKR_OK)
    {
        return rv;
    }

    CK_BYTE *spki = NULL;
    CK_ULONG spki_len = 0;
    CK_ATTRIBUTE *pub_full = NULL;
    CK_ATTRIBUTE *priv_full = NULL;
    CK_OBJECT_HANDLE pub_handle = CK_INVALID_HANDLE;
    rv = tsra_pkcs11_key_unwrapping_pair(hsm_session, NULL, &spki, &spki_len);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    tsra_pkcs11_rsa_public key;
    if (!tsra_pkcs11_spki_rsa(spki, spki_len, &key) || (key.n_len != RSA_UNWRAP_MODULUS_BYTES))
    {
        TSRA_PKCS11_LOG("unwrapping key: not an RSA-%u public key", RSA_UNWRAP_KEY_BITS);
        rv = CKR_DEVICE_ERROR;
        goto cleanup;
    }

    /* Both templates are built before either object exists, so a refused
     * public exponent leaves nothing behind. */
    pub_full =
        (CK_ATTRIBUTE *)malloc((pub_count + UNWRAPPING_PAIR_APPENDED_ATTRS) * sizeof(CK_ATTRIBUTE));
    priv_full = (CK_ATTRIBUTE *)malloc(
        (priv_count + UNWRAPPING_PAIR_APPENDED_ATTRS) * sizeof(CK_ATTRIBUTE)
    );
    if ((pub_full == NULL) || (priv_full == NULL))
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    tsra_pkcs11_pair_fill pub_fill;
    tsra_pkcs11_pair_fill priv_fill;
    CK_ULONG n_pub = 0;
    CK_ULONG n_priv = 0;
    rv =
        tsra_pkcs11_unwrapping_half_build(false, pub, pub_count, &key, &pub_fill, pub_full, &n_pub);
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_unwrapping_half_build(
            true,
            priv,
            priv_count,
            &key,
            &priv_fill,
            priv_full,
            &n_priv
        );
    }
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_store_key(s, pub_full, n_pub, pub_token, NULL, 0, &pub_handle);
    }
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_store_key(s, priv_full, n_priv, priv_token, NULL, 0, h_priv);
        if (rv != CKR_OK)
        {
            tsra_pkcs11_discard_key(s, pub_handle);
        }
    }
    if (rv == CKR_OK)
    {
        *h_pub = pub_handle;
        TSRA_PKCS11_LOG(
            "C_GenerateKeyPair: unwrapping key, pub=%lu priv=%lu",
            (unsigned long)*h_pub,
            (unsigned long)*h_priv
        );
    }

cleanup:
    free(spki);
    free(pub_full);
    free(priv_full);
    return rv;
}

/*
 * The device's unwrapping key for the object `h`: a handle to its private
 * key, once the device key is shown to be the one whose modulus the object
 * carries. On the mock every process provisions a fresh partition with a fresh
 * unwrapping key, so a token object from another process names a key that is
 * gone.
 */
static CK_RV unwrapping_key_handle(const tsra_pkcs11_slot_t *slot, object_ref *obj, uint32_t *out)
{
    CK_BYTE *spki = NULL;
    CK_ULONG spki_len = 0;
    uint32_t dev = 0;
    CK_RV rv = tsra_pkcs11_key_unwrapping_pair(slot->hsm_session, &dev, &spki, &spki_len);
    if (rv != CKR_OK)
    {
        return rv;
    }
    tsra_pkcs11_rsa_public key;
    CK_BYTE modulus[RSA_UNWRAP_MODULUS_BYTES];
    CK_ATTRIBUTE a = { CKA_MODULUS, modulus, sizeof(modulus) };
    if (!tsra_pkcs11_spki_rsa(spki, spki_len, &key) || (key.n_len != sizeof(modulus)))
    {
        TSRA_PKCS11_LOG("unwrapping key: not an RSA-%u public key", RSA_UNWRAP_KEY_BITS);
        rv = CKR_DEVICE_ERROR;
    }
    else if ((read_object(obj, &a) != CKR_OK) || (a.ulValueLen != sizeof(modulus)) ||
             (memcmp(modulus, key.n, sizeof(modulus)) != 0))
    {
        TSRA_PKCS11_LOG("unwrapping key: the object names another partition's key");
        rv = CKR_UNWRAPPING_KEY_HANDLE_INVALID;
    }
    free(spki);
    if (rv != CKR_OK)
    {
        tsra_pkcs11_key_release(dev);
        return rv;
    }
    *out = dev;
    return CKR_OK;
}

CK_RV C_UnwrapKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey,
    CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    if (!g_tsra_pkcs11.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    tsra_pkcs11_lock();
    tsra_pkcs11_session_t *s = tsra_pkcs11_session_lookup(hSession);
    if (s == NULL)
    {
        tsra_pkcs11_unlock();
        return CKR_SESSION_HANDLE_INVALID;
    }
    /* Precedence: bad handle, arguments, mechanism and its parameter, login
     * state, the unwrapping key, then the template and the blob's length. */
    tsra_pkcs11_rsa_aes_params params = { 0, 0 };
    CK_RV rv = CKR_ARGUMENTS_BAD;
    if ((phKey != NULL_PTR) && ((pWrappedKey != NULL_PTR) || (ulWrappedKeyLen == 0)) &&
        ((pTemplate != NULL_PTR) || (ulAttributeCount == 0)))
    {
        rv = tsra_pkcs11_unwrap_params_check(pMechanism, &params);
    }
    tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[s->slot];
    if ((rv == CKR_OK) && (!slot->user_logged_in || (slot->hsm_session == 0)))
    {
        rv = CKR_USER_NOT_LOGGED_IN; /* unwrapping needs the device session */
    }
    object_ref obj = { s->slot, hUnwrappingKey };
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_unwrapping_key_check(read_object, &obj);
    }
    /* Holds the template that is stored, so it must stay put until then. */
    tsra_pkcs11_unwrap_target target;
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_unwrap_check_template(
            pTemplate,
            ulAttributeCount,
            ulWrappedKeyLen,
            &target
        );
    }
    if ((rv == CKR_OK) && target.token && ((s->flags & CKF_RW_SESSION) == 0))
    {
        rv = CKR_SESSION_READ_ONLY;
    }
    if (rv != CKR_OK)
    {
        tsra_pkcs11_unlock();
        return rv;
    }

    uint32_t dev = 0;
    CK_BYTE *blob = NULL;
    CK_ULONG blob_len = 0;
    CK_ATTRIBUTE *full = NULL;
    rv = unwrapping_key_handle(slot, &obj, &dev);
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    /* The unwrapped key is private unless the template says otherwise (see
     * tsra_pkcs11_keygen_build_template); the scope does not depend on it. */
    CK_BBOOL priv = CK_TRUE;
    (void
    )tsra_pkcs11_tmpl_bool(tsra_pkcs11_tmpl_find(target.tmpl, target.count, CKA_PRIVATE), &priv);
    rv = tsra_pkcs11_key_aes_unwrap(
        dev,
        params.hash,
        params.aes_key_bits,
        target.policy->kind,
        (uint32_t)(target.value_len * CHAR_BIT),
        tsra_pkcs11_key_scope_props(target.token, priv),
        pWrappedKey,
        ulWrappedKeyLen,
        &blob,
        &blob_len
    );
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    full = (CK_ATTRIBUTE *)malloc((target.count + KEYGEN_APPENDED_ATTRS) * sizeof(CK_ATTRIBUTE));
    if (full == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    tsra_pkcs11_keygen_fill fill;
    CK_ULONG n = 0;
    rv = tsra_pkcs11_keygen_build_template(
        target.policy,
        target.tmpl,
        target.count,
        false,
        &fill,
        full,
        &n
    );
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_store_key(s, full, n, target.token, blob, blob_len, phKey);
    }
    if (rv == CKR_OK)
    {
        TSRA_PKCS11_LOG(
            "C_UnwrapKey: kind %d, %lu bytes, obj=%lu (blob %lu bytes)",
            (int)target.policy->kind,
            (unsigned long)target.value_len,
            (unsigned long)*phKey,
            (unsigned long)blob_len
        );
    }

cleanup:
    tsra_pkcs11_key_release(dev);
    if (blob != NULL)
    {
        tsra_pkcs11_wipe(blob, blob_len);
        free(blob);
    }
    free(full);
    tsra_pkcs11_unlock();
    return rv;
}
