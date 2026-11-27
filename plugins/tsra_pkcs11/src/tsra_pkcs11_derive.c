// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Key derivation: C_DeriveKey with CKM_ECDH1_DERIVE into the shared secret
 * (a CKK_GENERIC_SECRET object that only derives) and CKM_HKDF_DERIVE from
 * that secret into an AES-CBC or an HMAC key. The two run in sequence: ECDH
 * against a peer's public point, then HKDF. Both keys exist only as masked
 * blobs, like every key here; no derived value ever reaches the host.
 *
 * The base key's policy, its curve and its masked blob come from one read of
 * its record. The pure CK_MECHANISM, base key and template logic is in
 * tsra_pkcs11_derive_params.c, the device calls in tsra_pkcs11_key.c.
 * CKM_SP800_108_COUNTER_KDF, which the SDK also has, is not offered.
 */

#include "tsra_pkcs11_derive_params.h"
#include "tsra_pkcs11_internal.h"
#include "tsra_pkcs11_key.h"

#include <limits.h>
#include <stdlib.h>

/* What base_key_read decides on and reports. */
typedef struct
{
    CK_MECHANISM_TYPE mech;
    tsra_pkcs11_derive_base base;
} base_key_ctx;

/*
 * The base key's policy for the mechanism (tsra_pkcs11_derive_base_check). The
 * store runs it on the record it returns the masked blob from, so a record
 * rewritten in between cannot pass the policy with one version and supply the
 * blob from another; the class it checks keeps a record of another kind (a
 * sealed record's key among them) from being used as a base key.
 */
static CK_RV base_key_read(void *cctx, tsra_pkcs11_objstore_reader read, void *rctx)
{
    base_key_ctx *bk = (base_key_ctx *)cctx;
    return tsra_pkcs11_derive_base_check(bk->mech, read, rctx, &bk->base);
}

CK_RV C_DeriveKey(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey,
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
    /* Precedence as in C_UnwrapKey: arguments, mechanism and its parameter,
     * login state, the base key, then the template and the read-only session
     * for a token key. The ECDH point is judged with the base key, whose
     * curve fixes its length. */
    tsra_pkcs11_derive_params params;
    CK_RV rv = CKR_ARGUMENTS_BAD;
    if ((phKey != NULL_PTR) && ((pTemplate != NULL_PTR) || (ulAttributeCount == 0)))
    {
        rv = tsra_pkcs11_derive_params_check(pMechanism, &params);
    }
    tsra_pkcs11_slot_t *slot = &g_tsra_pkcs11.slots[s->slot];
    if ((rv == CKR_OK) && (!slot->user_logged_in || (slot->hsm_session == 0)))
    {
        rv = CKR_USER_NOT_LOGGED_IN; /* unmasking the base key needs the device session */
    }
    if (rv != CKR_OK)
    {
        tsra_pkcs11_unlock();
        return rv;
    }

    CK_BYTE *body = NULL;
    CK_ULONG body_len = 0;
    CK_ULONG body_cap = 0; /* the read may report a larger body_len if the record changed */
    CK_BYTE *blob = NULL;
    CK_ULONG blob_len = 0;
    CK_ATTRIBUTE *full = NULL;
    base_key_ctx bk = { params.mech, { TSRA_PKCS11_CURVE_NONE, CK_FALSE, CK_FALSE } };
    rv = g_tsra_pkcs11.store.ops->get_key_body(
        g_tsra_pkcs11.store.ctx,
        s->slot,
        CK_TRUE,
        hBaseKey,
        NULL,
        &body_len,
        NULL,
        NULL
    );
    if (rv == CKR_OBJECT_HANDLE_INVALID)
    {
        rv = CKR_KEY_HANDLE_INVALID; /* the handle names a key at this entry point */
    }
    if ((rv == CKR_OK) && (body_len == 0))
    {
        rv = CKR_KEY_HANDLE_INVALID; /* no masked blob: it backs no device key */
    }
    if (rv != CKR_OK)
    {
        goto cleanup;
    }
    body_cap = body_len;
    body = (CK_BYTE *)malloc(body_cap);
    if (body == NULL)
    {
        rv = CKR_HOST_MEMORY;
        goto cleanup;
    }
    /* The policy, the curve and the blob come from this one read. */
    rv = g_tsra_pkcs11.store.ops->get_key_body(
        g_tsra_pkcs11.store.ctx,
        s->slot,
        CK_TRUE,
        hBaseKey,
        body,
        &body_len,
        base_key_read,
        &bk
    );
    if (rv == CKR_OBJECT_HANDLE_INVALID)
    {
        rv = CKR_KEY_HANDLE_INVALID; /* removed since the length was read */
    }
    if (rv != CKR_OK)
    {
        goto cleanup;
    }

    CK_BYTE spki[EC_SPKI_DER_MAX];
    CK_ULONG spki_len = sizeof(spki);
    if (params.mech == CKM_ECDH1_DERIVE)
    {
        rv = tsra_pkcs11_ecdh_peer_spki(
            bk.base.curve,
            params.public_data,
            params.public_len,
            spki,
            &spki_len
        );
    }
    /* Holds the template that is stored, so it must stay put until then. */
    tsra_pkcs11_derive_target target;
    if (rv == CKR_OK)
    {
        rv = tsra_pkcs11_derive_check_template(
            params.mech,
            bk.base.curve,
            pTemplate,
            ulAttributeCount,
            &target
        );
    }
    if ((rv == CKR_OK) && target.token && ((s->flags & CKF_RW_SESSION) == 0))
    {
        rv = CKR_SESSION_READ_ONLY;
    }
    if (rv != CKR_OK)
    {
        goto cleanup;
    }

    /* A derived key is private unless the template says otherwise (see
     * tsra_pkcs11_derive_build_template); the scope does not depend on it. */
    CK_BBOOL priv = CK_TRUE;
    (void
    )tsra_pkcs11_tmpl_bool(tsra_pkcs11_tmpl_find(target.tmpl, target.count, CKA_PRIVATE), &priv);
    tsra_pkcs11_key_scope_t scope = tsra_pkcs11_key_scope_props(target.token, priv);
    if (params.mech == CKM_ECDH1_DERIVE)
    {
        rv = tsra_pkcs11_key_ecdh(
            slot->hsm_session,
            body,
            body_len,
            bk.base.curve,
            spki,
            spki_len,
            scope,
            &blob,
            &blob_len
        );
    }
    else
    {
        /* The template check bounds value_len to a key length, far within 32 bits. */
        rv = tsra_pkcs11_key_hkdf(
            slot->hsm_session,
            body,
            body_len,
            params.prf,
            params.salt,
            params.salt_len,
            params.info,
            params.info_len,
            target.policy->kind,
            (uint32_t)(target.value_len * CHAR_BIT),
            scope,
            &blob,
            &blob_len
        );
    }
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
    rv = tsra_pkcs11_derive_build_template(
        target.policy,
        target.tmpl,
        target.count,
        bk.base.always_sensitive,
        bk.base.never_extractable,
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
            "C_DeriveKey: mechanism 0x%lx, kind %d, %lu bytes, obj=%lu (blob %lu bytes)",
            (unsigned long)params.mech,
            (int)target.policy->kind,
            (unsigned long)target.value_len,
            (unsigned long)*phKey,
            (unsigned long)blob_len
        );
    }

cleanup:
    if (body != NULL)
    {
        tsra_pkcs11_wipe(body, body_cap);
        free(body);
    }
    if (blob != NULL)
    {
        tsra_pkcs11_wipe(blob, blob_len);
        free(blob);
    }
    free(full);
    tsra_pkcs11_unlock();
    return rv;
}
