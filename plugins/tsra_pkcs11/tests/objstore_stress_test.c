// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Multi-process stress test for the persistent object-store backend
 * (src/tsra_pkcs11_objstore_file.c). No device, no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src objstore_stress_test.c \
 *       ../src/tsra_pkcs11_objstore_file.c ../src/tsra_pkcs11_objstore_mem.c \
 *       ../src/tsra_pkcs11_store_io.c ../src/tsra_pkcs11_store_record.c -o objstore_stress_test
 * -lpthread
 *
 * N worker processes each create M token objects in the same slot directory of
 * a shared store; the parent then enumerates and must see exactly N*M objects.
 * If the counter-first allocation or the cross-process flock were wrong, two
 * creates would collide on a handle number and overwrite one another, so the
 * final count would be short — this asserts none are lost and every record is
 * intact (find decodes each one). Every other object is private, sealed with
 * the fake device cipher (store_fakes.h), and no two sealed records may share
 * a key: each write seals with a key of its own.
 */

#include "store_fakes.h"
#include "tsra_pkcs11_objstore.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define N_WORKERS 4
#define PER_WORKER 25

static CK_BBOOL ck_false = CK_FALSE;
static CK_BBOOL ck_true = CK_TRUE;

/* Create one token DATA object with a per-worker/index unique label; every
 * other one is private. */
static CK_RV create_one(tsra_pkcs11_objstore *s, CK_SLOT_ID slot, int worker, int idx)
{
    CK_BBOOL priv = ((idx % 2) != 0) ? CK_TRUE : CK_FALSE;
    char label[32];
    int n = snprintf(label, sizeof(label), "w%d-obj%d", worker, idx);
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &cls, sizeof(cls) },
        { CKA_TOKEN, &ck_true, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, priv ? &ck_true : &ck_false, sizeof(CK_BBOOL) },
        { CKA_LABEL, label, (CK_ULONG)n },
    };
    CK_OBJECT_HANDLE h = 0;
    return s->ops->create(s->ctx, slot, CK_TRUE, tmpl, 4, &h);
}

/* The keys of every sealed record in `dir`, FAKE_KEY_LEN bytes each; returns
 * how many it found. */
static size_t sealed_keys(const char *dir, unsigned char (*out)[FAKE_KEY_LEN], size_t max)
{
    DIR *d = opendir(dir);
    size_t n = 0;
    struct dirent *e;
    while ((d != NULL) && ((e = readdir(d)) != NULL) && (n < max))
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        unsigned char buf[512];
        FILE *f = fopen(path, "rb");
        size_t len = (f != NULL) ? fread(buf, 1, sizeof(buf), f) : 0;
        if (f != NULL)
        {
            fclose(f);
        }
        uint16_t version = 0;
        bool sealed = false;
        if ((tsra_pkcs11_record_peek(buf, len, &version, &sealed) == CKR_OK) && sealed &&
            (len > REC_KEY_AT + FAKE_KEY_LEN))
        {
            memcpy(out[n++], buf + REC_KEY_AT, FAKE_KEY_LEN);
        }
    }
    if (d != NULL)
    {
        closedir(d);
    }
    return n;
}

int main(void)
{
    char root[] = "/tmp/tsra_pkcs11_objstore_stress.XXXXXX";
    if (mkdtemp(root) == NULL)
    {
        perror("mkdtemp");
        return 1;
    }
    tsra_pkcs11_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.store_dir, sizeof(cfg.store_dir), "%s", root);
    cfg.store_persist = true;
    const CK_SLOT_ID SLOT = 0;

    /* Ensure the store (and, via the first creator, the token dir) exists before
     * forking, so all workers contend on the same directory and lock. */
    tsra_pkcs11_objstore seed;
    if (tsra_pkcs11_objstore_file_create(&seed, &cfg, &FAKE_CIPHER) != CKR_OK)
    {
        fprintf(stderr, "seed store create failed\n");
        return 1;
    }
    seed.ops->teardown(seed.ctx);

    for (int w = 0; w < N_WORKERS; w++)
    {
        pid_t pid = fork();
        if (pid == 0)
        {
            tsra_pkcs11_objstore s;
            if (tsra_pkcs11_objstore_file_create(&s, &cfg, &FAKE_CIPHER) != CKR_OK)
            {
                _exit(2);
            }
            int rc = 0;
            for (int i = 0; i < PER_WORKER; i++)
            {
                if (create_one(&s, SLOT, w, i) != CKR_OK)
                {
                    rc = 3;
                    break;
                }
            }
            s.ops->teardown(s.ctx);
            _exit(rc);
        }
    }
    int workers_ok = 1;
    for (int w = 0; w < N_WORKERS; w++)
    {
        int st = 0;
        wait(&st);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        {
            workers_ok = 0;
        }
    }

    /* Enumerate everything the workers created. */
    tsra_pkcs11_objstore s;
    if (tsra_pkcs11_objstore_file_create(&s, &cfg, &FAKE_CIPHER) != CKR_OK)
    {
        fprintf(stderr, "final store create failed\n");
        return 1;
    }
    CK_OBJECT_CLASS cls = CKO_DATA;
    CK_ATTRIBUTE q[] = { { CKA_CLASS, &cls, sizeof(cls) } };
    void *cur = NULL;
    CK_ULONG total = 0;
    if (s.ops->find_init(s.ctx, SLOT, CK_TRUE, q, 1, &cur) == CKR_OK)
    {
        for (;;)
        {
            CK_OBJECT_HANDLE batch[64];
            CK_ULONG got = 0;
            if (s.ops->find(s.ctx, cur, batch, 64, &got) != CKR_OK || got == 0)
            {
                break;
            }
            total += got;
        }
        s.ops->find_final(s.ctx, cur);
    }
    s.ops->teardown(s.ctx);

    int expected = N_WORKERS * PER_WORKER;
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/slot-%lu", root, (unsigned long)SLOT);
    unsigned char keys[N_WORKERS * PER_WORKER][FAKE_KEY_LEN];
    size_t sealed = sealed_keys(dir, keys, N_WORKERS * PER_WORKER);
    int unique = (sealed == (size_t)(N_WORKERS * (PER_WORKER / 2)));
    for (size_t i = 0; i < sealed; i++)
    {
        for (size_t j = i + 1; j < sealed; j++)
        {
            unique = unique && (memcmp(keys[i], keys[j], FAKE_KEY_LEN) != 0);
        }
    }
    int ok = workers_ok && unique && total == (CK_ULONG)expected;
    printf(
        "STRESS %s (%d workers ok: %s, %lu of %d objects found, %zu sealed with distinct "
        "keys: %s)\n",
        ok ? "OK" : "FAIL",
        N_WORKERS,
        workers_ok ? "yes" : "no",
        (unsigned long)total,
        expected,
        sealed,
        unique ? "yes" : "no"
    );
    return ok ? 0 : 1;
}
