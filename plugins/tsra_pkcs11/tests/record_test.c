// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Standalone unit test for the object-record codec (src/tsra_pkcs11_store_record.c).
 * No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src \
 *       record_test.c ../src/tsra_pkcs11_store_record.c -o record_test && ./record_test
 *
 * Covers: two-call sizing, encode/decode round-trip (attrs incl. zero-length,
 * plus a masked-blob body), the empty object, buffer-too-small, and that decode
 * rejects a bad magic / version / flag / truncation / trailing-garbage /
 * inconsistent length rather than misreading it. Sealed records: round trip
 * through the fake cipher (store_fakes.h), no plaintext in the encoding, a
 * change to any single byte refused, a key the device no longer unmasks or a
 * missing key refused, and a failed seal leaving nothing behind. Also the
 * P11M meta codec.
 */

#include "store_fakes.h"
#include "tsra_pkcs11_store_record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fail = 0;
static int g_checks = 0;

#define CHECK(cond, msg)                                                                           \
    do                                                                                             \
    {                                                                                              \
        g_checks++;                                                                                \
        if (cond)                                                                                  \
        {                                                                                          \
            printf("  ok   : %s\n", (msg));                                                        \
        }                                                                                          \
        else                                                                                       \
        {                                                                                          \
            printf("  FAIL : %s\n", (msg));                                                        \
            g_fail = 1;                                                                            \
        }                                                                                          \
    } while (0)

/* The codec's sealing callback over the fake device cipher. */
static CK_RV codec_gcm(
    void *ctx,
    bool encrypt,
    const unsigned char *key,
    size_t key_len,
    const unsigned char *aad,
    size_t aad_len,
    unsigned char *data,
    size_t data_len,
    unsigned char *tag
)
{
    (void)ctx;
    return fake_gcm(0, encrypt, key, key_len, aad, aad_len, data, data_len, tag);
}

/* Encode obj (sealed when `seal` is set) into a freshly malloc'd buffer via the
 * two-call path. */
static unsigned char *encode_alloc(
    const tsra_pkcs11_rec_object *obj,
    const tsra_pkcs11_record_seal *seal,
    size_t *out_len
)
{
    size_t need = 0;
    if (tsra_pkcs11_record_encode(obj, seal, NULL, &need) != CKR_OK)
    {
        return NULL;
    }
    unsigned char *buf = (unsigned char *)malloc(need ? need : 1);
    if (buf == NULL)
    {
        return NULL;
    }
    size_t len = need;
    if (tsra_pkcs11_record_encode(obj, seal, buf, &len) != CKR_OK || len != need)
    {
        free(buf);
        return NULL;
    }
    *out_len = need;
    return buf;
}

static int attrs_equal(const tsra_pkcs11_rec_object *a, const tsra_pkcs11_rec_object *b)
{
    if (a->attr_count != b->attr_count || a->body_len != b->body_len)
    {
        return 0;
    }
    for (CK_ULONG i = 0; i < a->attr_count; i++)
    {
        if (a->attrs[i].type != b->attrs[i].type || a->attrs[i].len != b->attrs[i].len)
        {
            return 0;
        }
        if (a->attrs[i].len > 0 &&
            memcmp(a->attrs[i].value, b->attrs[i].value, a->attrs[i].len) != 0)
        {
            return 0;
        }
    }
    if (a->body_len > 0 && memcmp(a->body, b->body, a->body_len) != 0)
    {
        return 0;
    }
    return 1;
}

static int contains(const unsigned char *hay, size_t n, const unsigned char *needle, size_t m)
{
    for (size_t i = 0; (m > 0) && (i + m <= n); i++)
    {
        if (memcmp(hay + i, needle, m) == 0)
        {
            return 1;
        }
    }
    return 0;
}

int main(void)
{
    /* An object with a bool, a "ulong", a byte-string, a zero-length attr, and a
     * masked-blob body. */
    CK_BBOOL tval = CK_TRUE;
    CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
    unsigned char label[] = "my-key-label";
    unsigned char body[300];
    for (int i = 0; i < 300; i++)
    {
        body[i] = (unsigned char)(i * 3 + 5);
    }
    tsra_pkcs11_rec_attr in_attrs[] = {
        { CKA_CLASS, (unsigned char *)&cls, sizeof(cls) },
        { CKA_TOKEN, &tval, sizeof(tval) },
        { CKA_LABEL, label, (CK_ULONG)strlen((char *)label) },
        { CKA_ID, NULL, 0 }, /* zero-length attribute */
    };
    tsra_pkcs11_rec_object in = { in_attrs, 4, body, sizeof(body) };

    size_t enc_len = 0;
    unsigned char *enc = encode_alloc(&in, NULL, &enc_len);
    CHECK(enc != NULL, "two-call encode");

    tsra_pkcs11_rec_object dec;
    CHECK(tsra_pkcs11_record_decode(enc, enc_len, NULL, &dec) == CKR_OK, "decode ok");
    CHECK(attrs_equal(&in, &dec), "round-trip identical (attrs + body)");
    CHECK(dec.attrs[3].len == 0 && dec.attrs[3].value == NULL, "zero-length attr decodes to NULL");
    tsra_pkcs11_record_free(&dec);

    /* buffer-too-small on the fill call. */
    size_t small = enc_len - 1;
    unsigned char *tiny = (unsigned char *)malloc(small);
    CHECK(
        tsra_pkcs11_record_encode(&in, NULL, tiny, &small) == CKR_BUFFER_TOO_SMALL,
        "encode rejects short buffer"
    );
    free(tiny);

    /* empty object (no attrs, no body). */
    tsra_pkcs11_rec_object empty = { NULL, 0, NULL, 0 };
    size_t elen = 0;
    unsigned char *ebuf = encode_alloc(&empty, NULL, &elen);
    tsra_pkcs11_rec_object edec;
    CHECK(
        ebuf && tsra_pkcs11_record_decode(ebuf, elen, NULL, &edec) == CKR_OK &&
            edec.attr_count == 0 && edec.body_len == 0,
        "empty object round-trips"
    );
    tsra_pkcs11_record_free(&edec);

    /* corruption rejections (each mutates a fresh copy). */
    unsigned char *c = (unsigned char *)malloc(enc_len);
    tsra_pkcs11_rec_object junk;

    memcpy(c, enc, enc_len);
    c[0] = 'X'; /* magic */
    CHECK(tsra_pkcs11_record_decode(c, enc_len, NULL, &junk) != CKR_OK, "decode rejects bad magic");

    memcpy(c, enc, enc_len);
    c[REC_VERSION_AT] = 3;
    CHECK(
        tsra_pkcs11_record_decode(c, enc_len, NULL, &junk) != CKR_OK,
        "decode rejects unknown version"
    );

    memcpy(c, enc, enc_len);
    c[REC_VERSION_AT] = 1;
    uint16_t version = 0;
    bool sealed = true;
    CHECK(
        tsra_pkcs11_record_decode(c, enc_len, NULL, &junk) != CKR_OK &&
            tsra_pkcs11_record_peek(c, enc_len, &version, &sealed) == CKR_OK && version == 1 &&
            !sealed,
        "decode refuses a version-1 record, and peek names its version"
    );

    memcpy(c, enc, enc_len);
    c[REC_FLAGS_AT] = 2;
    CHECK(
        tsra_pkcs11_record_decode(c, enc_len, NULL, &junk) != CKR_OK,
        "decode rejects an unknown flag"
    );

    memcpy(c, enc, enc_len);
    CHECK(
        tsra_pkcs11_record_decode(c, enc_len - 1, NULL, &junk) != CKR_OK,
        "decode rejects truncation (len mismatch)"
    );

    memcpy(c, enc, enc_len);
    c[REC_COUNT_AT] = 0xFF; /* attr_count huge */
    CHECK(
        tsra_pkcs11_record_decode(c, enc_len, NULL, &junk) != CKR_OK,
        "decode rejects oversized attr_count"
    );
    free(c);
    CHECK(
        tsra_pkcs11_record_peek(enc, REC_HEADER_LEN - 1, &version, &sealed) != CKR_OK,
        "peek rejects a buffer shorter than the header"
    );

    /* one extra trailing byte -> total_len mismatch. */
    unsigned char *ext = (unsigned char *)malloc(enc_len + 1);
    memcpy(ext, enc, enc_len);
    ext[enc_len] = 0;
    CHECK(
        tsra_pkcs11_record_decode(ext, enc_len + 1, NULL, &junk) != CKR_OK,
        "decode rejects trailing garbage"
    );
    free(ext);
    free(ebuf);

    /* --- sealed records --- */
    CK_BYTE *key = NULL;
    CK_ULONG key_len = 0;
    fake_key_generate(0, &key, &key_len);
    tsra_pkcs11_record_seal seal = { codec_gcm, NULL, key, key_len };
    size_t sl = 0;
    unsigned char *sec = encode_alloc(&in, &seal, &sl);
    CHECK(sec != NULL && sl > enc_len, "sealed encode (two-call)");
    CHECK(
        sec != NULL && tsra_pkcs11_record_peek(sec, sl, &version, &sealed) == CKR_OK &&
            version == P11_RECORD_VERSION && sealed,
        "peek reports a sealed record of the current version"
    );
    CHECK(
        sec != NULL && !contains(sec, sl, label, sizeof(label) - 1) &&
            !contains(sec, sl, body, sizeof(body)),
        "no attribute value or body byte sequence appears in clear"
    );
    tsra_pkcs11_rec_object sdec;
    CHECK(
        sec != NULL && tsra_pkcs11_record_decode(sec, sl, &seal, &sdec) == CKR_OK &&
            attrs_equal(&in, &sdec),
        "sealed round-trip identical (attrs + body)"
    );
    tsra_pkcs11_record_free(&sdec);
    CHECK(
        sec != NULL && tsra_pkcs11_record_decode(sec, sl, NULL, &sdec) == CKR_ARGUMENTS_BAD,
        "a sealed record does not decode without a cipher"
    );

    CHECK(
        sec != NULL && memcmp(sec + REC_KEY_AT, key, key_len) == 0,
        "the record carries its key in clear before the payload"
    );

    /* Tamper matrix: one flipped bit anywhere is refused. */
    int all_refused = (sec != NULL);
    unsigned char *t = (unsigned char *)malloc(sl);
    for (size_t i = 0; all_refused && (i < sl); i++)
    {
        memcpy(t, sec, sl);
        t[i] ^= 0x01;
        if (tsra_pkcs11_record_decode(t, sl, &seal, &junk) == CKR_OK)
        {
            printf("  byte %zu: a flipped bit was accepted\n", i);
            tsra_pkcs11_record_free(&junk);
            all_refused = 0;
        }
    }
    CHECK(all_refused, "a flipped bit in any byte of a sealed record is refused");
    CHECK(
        tsra_pkcs11_record_decode(sec, sl - 1, &seal, &junk) != CKR_OK,
        "a truncated sealed record is refused"
    );

    /* A key the device no longer unmasks, and a record without a key. */
    fake_epoch++;
    CHECK(
        tsra_pkcs11_record_decode(sec, sl, &seal, &junk) == CKR_KEY_HANDLE_INVALID,
        "a record key from another provisioning is refused (KEY_HANDLE_INVALID)"
    );
    size_t probe = sl;
    CHECK(
        tsra_pkcs11_record_encode(&in, &seal, t, &probe) == CKR_KEY_HANDLE_INVALID && t[0] == 0 &&
            t[sl - 1] == 0,
        "a failed seal returns its error and leaves the buffer wiped"
    );
    fake_epoch--;
    memcpy(t, sec, sl);
    memset(t + REC_HEADER_LEN, 0, sizeof(uint32_t)); /* key_len = 0 */
    CHECK(
        tsra_pkcs11_record_decode(t, sl, &seal, &junk) == CKR_FUNCTION_FAILED,
        "a sealed record without a key is refused"
    );
    tsra_pkcs11_record_seal nokey = { codec_gcm, NULL, NULL, 0 };
    CHECK(
        tsra_pkcs11_record_encode(&in, &nokey, NULL, &probe) == CKR_ARGUMENTS_BAD,
        "encode refuses to seal without a key"
    );

    free(t);
    free(sec);
    free(key);
    free(enc);

    /* meta (P11M) round-trip + rejection. */
    unsigned char mbuf[P11_META_SIZE];
    size_t mlen = sizeof(mbuf);
    CHECK(
        tsra_pkcs11_meta_encode(0x1122334455667788ULL, 42, mbuf, &mlen) == CKR_OK &&
            mlen == P11_META_SIZE,
        "meta encode"
    );
    CK_ULONG nh = 0, gen = 0;
    CHECK(
        tsra_pkcs11_meta_decode(mbuf, sizeof(mbuf), &nh, &gen) == CKR_OK &&
            nh == 0x1122334455667788ULL && gen == 42,
        "meta round-trips next_handle + generation"
    );
    mbuf[0] = 'Z';
    CHECK(
        tsra_pkcs11_meta_decode(mbuf, sizeof(mbuf), &nh, &gen) != CKR_OK,
        "meta decode rejects bad magic"
    );

    printf(g_fail ? "\nRECORD FAIL (%d checks)\n" : "\nRECORD OK (%d checks)\n", g_checks);
    return g_fail;
}
