// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/*
 * Stand-ins for what the module hands the file store, for the device-free
 * harnesses: the device services that seal private records
 * (tsra_pkcs11_store_cipher) and the debug log.
 *
 * The fake cipher is not cryptography. It XORs the data with a keystream
 * drawn from the key, and its tag is an FNV-1a hash over key, additional data
 * and ciphertext, which changes with any single byte, so a tampered record
 * still fails to open. A key carries the fake device's epoch, the process ID
 * and a serial number, so no two keys are alike across processes either.
 * After fake_epoch changes (a partition provisioned afresh) older keys no
 * longer unmask (CKR_KEY_HANDLE_INVALID), and they do again once it changes
 * back.
 */

#include "tsra_pkcs11_objstore.h"
#include "tsra_pkcs11_store_record.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FAKE_KEY_LEN 16

/* White-box offsets into a P11O record: magic[4] | u16 version | u16 flags |
 * u32 attr_count | u32 body_len | u32 total_len, then, sealed, u32 key_len |
 * key. */
#define REC_VERSION_AT 4
#define REC_FLAGS_AT 6
#define REC_COUNT_AT 8
#define REC_HEADER_LEN 20
#define REC_KEY_AT (REC_HEADER_LEN + sizeof(uint32_t))
#define FAKE_FNV_OFFSET 0xcbf29ce484222325ULL
#define FAKE_FNV_PRIME 0x100000001b3ULL

static uint32_t fake_epoch = 1;
static uint32_t fake_keys_made = 0;
/* When not CKR_OK, every GCM call fails with it: a device or session failure. */
static CK_RV fake_gcm_fail = CKR_OK;
static char fake_log_last[512];

static inline uint64_t fake_fnv(uint64_t h, const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        h = (h ^ p[i]) * FAKE_FNV_PRIME;
    }
    return h;
}

/* A key is the epoch, the process ID and a serial number (native u32 each),
 * zero-padded. */
static inline CK_RV fake_key_generate(CK_SLOT_ID slot, CK_BYTE **blob, CK_ULONG *blob_len)
{
    (void)slot;
    CK_BYTE *k = (CK_BYTE *)calloc(1, FAKE_KEY_LEN);
    if (k == NULL)
    {
        return CKR_HOST_MEMORY;
    }
    uint32_t pid = (uint32_t)getpid();
    uint32_t serial = ++fake_keys_made;
    memcpy(k, &fake_epoch, sizeof(fake_epoch));
    memcpy(k + sizeof(fake_epoch), &pid, sizeof(pid));
    memcpy(k + sizeof(fake_epoch) + sizeof(pid), &serial, sizeof(serial));
    *blob = k;
    *blob_len = FAKE_KEY_LEN;
    return CKR_OK;
}

static inline void fake_tag(
    const CK_BYTE *key,
    CK_ULONG key_len,
    const CK_BYTE *aad,
    CK_ULONG aad_len,
    const CK_BYTE *ct,
    CK_ULONG ct_len,
    CK_BYTE *tag
)
{
    uint64_t h = fake_fnv(FAKE_FNV_OFFSET, key, key_len);
    h = fake_fnv(h, aad, aad_len);
    h = fake_fnv(h, ct, ct_len);
    uint64_t h2 = fake_fnv(h, (const unsigned char *)"tag", 3);
    memcpy(tag, &h, sizeof(h));
    memcpy(tag + sizeof(h), &h2, sizeof(h2));
}

static inline void fake_xor(const CK_BYTE *key, CK_ULONG key_len, CK_BYTE *d, CK_ULONG n)
{
    uint64_t s = fake_fnv(FAKE_FNV_OFFSET, key, key_len);
    for (CK_ULONG i = 0; i < n; i++)
    {
        if ((i % sizeof(s)) == 0)
        {
            s = (s ^ i) * FAKE_FNV_PRIME;
        }
        d[i] ^= (CK_BYTE)(s >> (8 * (i % sizeof(s))));
    }
}

static inline CK_RV fake_gcm(
    CK_SLOT_ID slot,
    bool encrypt,
    const CK_BYTE *key,
    CK_ULONG key_len,
    const CK_BYTE *aad,
    CK_ULONG aad_len,
    CK_BYTE *data,
    CK_ULONG data_len,
    CK_BYTE *tag
)
{
    (void)slot;
    if (fake_gcm_fail != CKR_OK)
    {
        return fake_gcm_fail;
    }
    if ((key_len != FAKE_KEY_LEN) || (memcmp(key, &fake_epoch, sizeof(fake_epoch)) != 0))
    {
        return CKR_KEY_HANDLE_INVALID;
    }
    if (encrypt)
    {
        fake_xor(key, key_len, data, data_len);
        fake_tag(key, key_len, aad, aad_len, data, data_len, tag);
        return CKR_OK;
    }
    CK_BYTE want[P11_RECORD_TAG_LEN];
    fake_tag(key, key_len, aad, aad_len, data, data_len, want);
    if (memcmp(want, tag, sizeof(want)) != 0)
    {
        return CKR_FUNCTION_FAILED; /* what the device reports for a tag mismatch */
    }
    fake_xor(key, key_len, data, data_len);
    return CKR_OK;
}

static const tsra_pkcs11_store_cipher FAKE_CIPHER = {
    .key_generate = fake_key_generate,
    .gcm = fake_gcm,
};

/* The file backend logs through the module's tracer, which no harness links. */
void tsra_pkcs11_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(fake_log_last, sizeof(fake_log_last), fmt, ap);
    va_end(ap);
}
