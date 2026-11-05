// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"
#include "tsra_pkcs11_config.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Object-store seam.
 *
 * PKCS#11 assumes a persistent, attribute-templated, searchable object store.
 * The TSRA device provides none of it (it returns each key as an opaque masked
 * blob and enumerates nothing), so the object layer is emulated host-side behind
 * this vtable. The store holds each object's full attribute set plus, for keys,
 * the opaque TSRA masked blob as the key body; it deals in CK_RV only and never
 * calls the HSM.
 *
 * Two backends implement the seam: the in-memory backend
 * (tsra_pkcs11_objstore_mem.c), the default, whose objects do not survive
 * C_Finalize, and the persistent file backend (tsra_pkcs11_objstore_file.c),
 * opt-in via TSRA_PKCS11_PERSIST, which writes token objects through to disk.
 * The framework callers do not change when the backend is swapped —
 * construction picks the backend, everything else goes through `ops`/`ctx`.
 * The file backend seals private token objects through device services the
 * module hands it at construction (tsra_pkcs11_store_cipher), so the store
 * itself still never calls the SDK.
 */

typedef struct tsra_pkcs11_objstore_ops tsra_pkcs11_objstore_ops;

/*
 * Reads one attribute of the object a set_attr or destroy check is deciding
 * on, with get_attr semantics for a single-entry template.
 */
typedef CK_RV (*tsra_pkcs11_objstore_reader)(void *rctx, CK_ATTRIBUTE *a);

/*
 * Decides whether a set_attr or destroy may go ahead, from the object as `read`
 * sees it; anything but CKR_OK refuses the call. The backend runs it after it
 * has locked and loaded the object and before it writes, so the decision and
 * the write see the same state even when another process shares the store.
 */
typedef CK_RV (*tsra_pkcs11_objstore_check)(
    void *cctx,
    tsra_pkcs11_objstore_reader read,
    void *rctx
);

typedef struct
{
    const tsra_pkcs11_objstore_ops *ops;
    void *ctx; /* backend-owned; opaque to callers */
} tsra_pkcs11_objstore;

/*
 * Every object is bound to the slot (token) it was created in, so handle-based
 * ops carry the calling `slot` and `user_logged_in`: the device authenticates
 * the partition (token), never individual objects, so the host enforces PKCS#11
 * token isolation and private-object login-gating here. An object in another
 * slot, or a private object while not logged in, is not visible to the caller
 * and yields CKR_OBJECT_HANDLE_INVALID (rather than leaking its existence).
 *
 * Handles are unique within a slot for the lifetime of the store and are never
 * reused after a destroy: the framework reaps a closing session's objects by
 * slot and handle, and a reused handle would let it destroy a stranger's
 * object. Two slots may hand out the same handle (the file backend numbers
 * token objects per token directory); no caller looks a handle up without its
 * slot.
 */
struct tsra_pkcs11_objstore_ops
{
    /* Create an object in `slot`; a private object requires `user_logged_in`. */
    CK_RV(*create)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     const CK_ATTRIBUTE *tmpl,
     CK_ULONG count,
     CK_OBJECT_HANDLE *out);
    /* `check` (may be NULL) runs first, under the same lock as the removal;
     * its refusal is returned and the object stays. */
    CK_RV(*destroy)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     CK_OBJECT_HANDLE h,
     tsra_pkcs11_objstore_check check,
     void *cctx);
    CK_RV(*get_attr)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     CK_OBJECT_HANDLE h,
     CK_ATTRIBUTE *tmpl,
     CK_ULONG count);
    /*
     * Apply `tmpl` all-or-nothing. `check` (may be NULL) runs first, even for
     * an empty template, under the same lock as the write; its refusal is
     * returned and nothing changes.
     */
    CK_RV(*set_attr)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     CK_OBJECT_HANDLE h,
     const CK_ATTRIBUTE *tmpl,
     CK_ULONG count,
     tsra_pkcs11_objstore_check check,
     void *cctx);

    /*
     * Materialise the matches for a template into an opaque cursor the caller
     * drains with `find` and releases with `find_final`. `slot` scopes the
     * search; private objects are excluded unless `user_logged_in`.
     */
    CK_RV(*find_init)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     const CK_ATTRIBUTE *tmpl,
     CK_ULONG count,
     void **cursor);
    CK_RV (*find)(void *ctx, void *cursor, CK_OBJECT_HANDLE *out, CK_ULONG max, CK_ULONG *count);
    void (*find_final)(void *ctx, void *cursor);

    /*
     * Attach the opaque TSRA masked blob (tsra_key_get_prop(MASKED_KEY)) as a
     * key object's body. Set by the crypto layer once a key is generated or
     * imported; unused until key operations land.
     */
    CK_RV(*set_key_body)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     CK_OBJECT_HANDLE h,
     const CK_BYTE *blob,
     CK_ULONG len);

    /*
     * Retrieve a key object's masked-blob body (the input to tsra_key_unmask).
     * Two-call sizing: with blob == NULL, *len receives the body length; a
     * length of 0 means the object carries no body. The body is internal to the
     * module and is never exposed through C_GetAttributeValue.
     */
    CK_RV(*get_key_body)
    (void *ctx,
     CK_SLOT_ID slot,
     CK_BBOOL user_logged_in,
     CK_OBJECT_HANDLE h,
     CK_BYTE *blob,
     CK_ULONG *len);

    /*
     * The object's size for C_GetObjectSize: the bytes of its attribute values
     * plus its key body. PKCS#11 asks only for an approximation, so framing and
     * per-attribute overhead are left out; both backends count the same way, so
     * an object reports the same size whichever store holds it.
     */
    CK_RV(*get_size)
    (void *ctx, CK_SLOT_ID slot, CK_BBOOL user_logged_in, CK_OBJECT_HANDLE h, CK_ULONG *size);

    void (*teardown)(void *ctx); /* free the whole store (C_Finalize) */
    CK_RV (*persist)(void *ctx); /* NULL on the in-memory backend */
};

/* Construct the in-memory backend into `out`. */
CK_RV tsra_pkcs11_objstore_mem_create(tsra_pkcs11_objstore *out);

/*
 * The device services the file backend seals private token objects with
 * (CKA_PRIVATE TRUE): every write of such a record generates an AES-GCM key on
 * the device for that record alone, kept in the record as its masked blob, so
 * each key encrypts exactly once. The backend calls them under the module lock,
 * only for a `slot` whose user is logged in; the module runs them in that
 * slot's device session.
 */
typedef struct
{
    /* Generate a record key: *blob receives its masked blob in a malloc'd
     * buffer the caller wipes and frees. */
    CK_RV (*key_generate)(CK_SLOT_ID slot, CK_BYTE **blob, CK_ULONG *blob_len);
    /*
     * AES-GCM in place with the record key whose masked blob is `key`: `data`
     * holds the plaintext or ciphertext and receives the result, `tag` (16
     * bytes) is written on encrypt and checked on decrypt.
     * CKR_KEY_HANDLE_INVALID means the device does not unmask `key` (the
     * partition was provisioned afresh).
     */
    CK_RV(*gcm)
    (CK_SLOT_ID slot,
     bool encrypt,
     const CK_BYTE *key,
     CK_ULONG key_len,
     const CK_BYTE *aad,
     CK_ULONG aad_len,
     CK_BYTE *data,
     CK_ULONG data_len,
     CK_BYTE *tag);
} tsra_pkcs11_store_cipher;

/*
 * Construct the persistent file backend into `out`, rooted at cfg->store_dir.
 * Objects are written through to disk so token objects survive a process restart
 * and are visible to other processes sharing the directory
 * (tsra_pkcs11_objstore_file.c). `cipher` is borrowed and must outlive the store.
 */
CK_RV tsra_pkcs11_objstore_file_create(
    tsra_pkcs11_objstore *out,
    const tsra_pkcs11_config *cfg,
    const tsra_pkcs11_store_cipher *cipher
);

#ifdef __cplusplus
}
#endif
