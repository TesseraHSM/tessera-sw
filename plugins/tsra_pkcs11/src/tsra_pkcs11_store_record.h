// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "tsra_pkcs11_compat.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * On-disk record codec for the persistent object store (tsra_pkcs11_objstore_file.c).
 *
 * An object is serialized as a fixed little-endian header ("P11O", a version, a
 * flags field, an attribute count and a masked-blob length, a total length)
 * followed by its payload: a flat sequence of attribute records
 * [type u32][len u32][value bytes] and then the opaque masked-blob key body.
 * The masked blob is a distinguished trailing field, not an attribute, so it is
 * never returned by C_GetAttributeValue.
 *
 * A sealed record (a private object) carries, between header and payload, the
 * masked blob of the key that sealed it; its payload is AES-GCM ciphertext
 * followed by the tag, with every byte before the payload as additional data.
 * Decoding validates the magic, version, flags and every length against the
 * buffer, and a sealed record's tag, so a torn or tampered record is rejected
 * rather than misread.
 *
 * Explicit little-endian + magic + version mirror the repo's persisted formats
 * (fw part_store / key_vault, key-masking aead). The token.meta file ("P11M")
 * shares the same header discipline.
 *
 * This codec links no libcrypto (uses libc malloc/free) so it compiles in the
 * no-device smoke build; sealing goes through a callback.
 */

#define P11_RECORD_VERSION 2
#define P11_RECORD_TAG_LEN 16
/* token.meta is versioned apart from the records. */
#define P11_META_VERSION 1
#define P11_META_SIZE 24

/* One attribute. `value` is borrowed by tsra_pkcs11_record_encode (read-only) and owned
 * by a tsra_pkcs11_record_decode result (freed by tsra_pkcs11_record_free); NULL when len == 0.
 */
typedef struct
{
    CK_ATTRIBUTE_TYPE type;
    unsigned char *value;
    CK_ULONG len;
} tsra_pkcs11_rec_attr;

/* A whole object: its attributes plus the opaque masked-blob key body (NULL when
 * the object is not a key). Ownership follows the attributes (see above). */
typedef struct
{
    tsra_pkcs11_rec_attr *attrs;
    CK_ULONG attr_count;
    unsigned char *body;
    CK_ULONG body_len;
} tsra_pkcs11_rec_object;

/*
 * AES-GCM in place over a sealed record's payload: `data` holds data_len bytes
 * of plaintext (encrypt) or ciphertext (decrypt) and receives the result.
 * `key` is the masked blob of the record's key, `tag` P11_RECORD_TAG_LEN
 * bytes: written on encrypt, checked on decrypt.
 */
typedef CK_RV (*tsra_pkcs11_record_gcm)(
    void *ctx,
    bool encrypt,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *aad,
    size_t aad_len,
    unsigned char *data,
    size_t data_len,
    unsigned char *tag
);

/* How a record is sealed or opened. Decoding reads only `gcm` and `ctx`; the
 * key comes from the record. */
typedef struct
{
    tsra_pkcs11_record_gcm gcm;
    void *ctx;                /* passed to gcm */
    const unsigned char *key; /* encode: the masked blob of the record's key */
    size_t key_len;
} tsra_pkcs11_record_seal;

/*
 * Encode `obj` into the P11O record format, sealed when `seal` is not NULL.
 * Two-call: with buf == NULL, sets *len to the required size and returns CKR_OK
 * without sealing; otherwise writes into buf, returning CKR_BUFFER_TOO_SMALL
 * when *len is short and otherwise setting *len to the bytes written. `obj`'s
 * buffers are read, not owned. A failed seal is returned as is, with buf wiped.
 * The encoded buffer may hold sensitive attribute bytes; the caller wipes it
 * after writing.
 */
CK_RV tsra_pkcs11_record_encode(
    const tsra_pkcs11_rec_object *obj,
    const tsra_pkcs11_record_seal *seal,
    unsigned char *buf,
    size_t *len
);

/*
 * Decode a P11O record from buf[len] into *out, validating the header and every
 * length; a sealed record is opened through `seal` (CKR_ARGUMENTS_BAD when it
 * is NULL), whose error is returned as is. On success *out owns
 * freshly-allocated buffers (free with tsra_pkcs11_record_free); on any
 * inconsistency returns an error and *out is zeroed.
 */
CK_RV tsra_pkcs11_record_decode(
    const unsigned char *buf,
    size_t len,
    const tsra_pkcs11_record_seal *seal,
    tsra_pkcs11_rec_object *out
);

/*
 * Read the format version and the sealed flag from a record's header without
 * decoding the rest, so a sealed record can be skipped while logged out and an
 * outdated one reported. CKR_FUNCTION_FAILED when buf does not start with a
 * P11O header.
 */
CK_RV tsra_pkcs11_record_peek(
    const unsigned char *buf,
    size_t len,
    uint16_t *version,
    bool *sealed
);

/* Wipe and free the owned buffers of a decoded object; NULL-safe, leaves *obj
 * zeroed. */
void tsra_pkcs11_record_free(tsra_pkcs11_rec_object *obj);

/*
 * token.meta codec (P11M): the persistent monotonic handle counter and a
 * generation counter. Two-call like tsra_pkcs11_record_encode; decode validates the
 * fixed P11_META_SIZE layout.
 */
CK_RV tsra_pkcs11_meta_encode(
    CK_ULONG next_handle,
    CK_ULONG generation,
    unsigned char *buf,
    size_t *len
);
CK_RV
tsra_pkcs11_meta_decode(
    const unsigned char *buf,
    size_t len,
    CK_ULONG *next_handle,
    CK_ULONG *generation
);

#ifdef __cplusplus
}
#endif
