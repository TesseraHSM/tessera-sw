// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Standalone unit test for the object-store filesystem primitives
 * (src/tsra_pkcs11_store_io.c). Builds and links directly against that source, no
 * device and no libcrypto:
 *
 *   gcc -I ../include/pkcs11-v3.1 -I ../src \
 *       store_io_test.c ../src/tsra_pkcs11_store_io.c -o store_io_test && ./store_io_test
 *
 * Covers: directory create + owner-only verification, path-traversal rejection,
 * atomic write (0600, no leftover temp), read + two-call absence semantics,
 * idempotent unlink, oversize rejection, an empty file read as corrupt, a stale
 * temp file never reused, create refusing to replace, FIFOs refused without
 * blocking, and cross-process exclusion via the advisory lock (K children each
 * doing M locked read-modify-writes must total exactly K*M, which a
 * non-exclusive lock would miss by losing updates). The directory fsync failures that writes and
 * unlinks report need a failing filesystem and are not provoked here.
 */

#define _DEFAULT_SOURCE

#include "tsra_pkcs11_store_io.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

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

static mode_t file_mode(const char *dir, const char *name)
{
    char path[8192];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    struct stat st;
    if (stat(path, &st) != 0)
    {
        return 0;
    }
    return st.st_mode & 07777;
}

static nlink_t file_links(const char *dir, const char *name)
{
    char path[8192];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    struct stat st;
    return (stat(path, &st) == 0) ? st.st_nlink : 0;
}

static int file_exists(const char *dir, const char *name)
{
    char path[8192];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    struct stat st;
    return stat(path, &st) == 0;
}

/* One child: M iterations of lock -> read counter -> +1 -> write -> unlock. */
static void child_increment(const char *dir, int iters)
{
    for (int i = 0; i < iters; i++)
    {
        int fd = -1;
        if (tsra_pkcs11_store_lock(dir, &fd) != CKR_OK)
        {
            _exit(2);
        }
        unsigned char *buf = NULL;
        size_t len = 0;
        size_t val = 0;
        if (tsra_pkcs11_store_read(dir, "counter", &buf, &len) != CKR_OK)
        {
            tsra_pkcs11_store_unlock(fd);
            _exit(3);
        }
        if (buf != NULL && len == sizeof(val))
        {
            memcpy(&val, buf, sizeof(val));
        }
        free(buf);
        val++;
        /* Widen the read-modify-write window so a missing lock would race. */
        usleep(200);
        if (tsra_pkcs11_store_write(dir, "counter", (unsigned char *)&val, sizeof(val)) != CKR_OK)
        {
            tsra_pkcs11_store_unlock(fd);
            _exit(4);
        }
        tsra_pkcs11_store_unlock(fd);
    }
    _exit(0);
}

int main(void)
{
    char root[] = "/tmp/tsra_pkcs11_store_io_test.XXXXXX";
    if (mkdtemp(root) == NULL)
    {
        perror("mkdtemp");
        return 1;
    }
    char store[4096];
    snprintf(store, sizeof(store), "%s/store", root);
    printf("== store dir: %s ==\n", store);

    /* dir_ensure: create then idempotent, 0700. */
    CHECK(tsra_pkcs11_store_dir_ensure(store) == CKR_OK, "dir_ensure creates the store dir");
    CHECK(tsra_pkcs11_store_dir_ensure(store) == CKR_OK, "dir_ensure is idempotent when present");
    struct stat dst;
    CHECK(stat(store, &dst) == 0 && (dst.st_mode & 07777) == 0700, "store dir is 0700");

    /* path_join rejects traversal / separators, accepts a flat name. */
    char out[4608];
    CHECK(
        tsra_pkcs11_store_path_join(out, sizeof(out), store, "obj1") == CKR_OK,
        "path_join accepts flat name"
    );
    CHECK(
        tsra_pkcs11_store_path_join(out, sizeof(out), store, "a/b") == CKR_ARGUMENTS_BAD,
        "path_join rejects '/'"
    );
    CHECK(
        tsra_pkcs11_store_path_join(out, sizeof(out), store, "..") == CKR_ARGUMENTS_BAD,
        "path_join rejects '..'"
    );
    CHECK(
        tsra_pkcs11_store_path_join(out, sizeof(out), store, "../x") == CKR_ARGUMENTS_BAD,
        "path_join rejects '../x'"
    );
    CHECK(
        tsra_pkcs11_store_path_join(out, sizeof(out), store, "") == CKR_ARGUMENTS_BAD,
        "path_join rejects empty"
    );

    /* write + read round-trip, 0600, no leftover temp. */
    unsigned char payload[100];
    for (int i = 0; i < 100; i++)
    {
        payload[i] = (unsigned char)(i * 7 + 1);
    }
    CHECK(tsra_pkcs11_store_write(store, "obj1", payload, sizeof(payload)) == CKR_OK, "write obj1");
    CHECK(file_mode(store, "obj1") == 0600, "obj1 is 0600");
    CHECK(!file_exists(store, ".obj1.tmp"), "no leftover temp after write");
    unsigned char *rd = NULL;
    size_t rdlen = 0;
    CHECK(
        tsra_pkcs11_store_read(store, "obj1", &rd, &rdlen) == CKR_OK && rd != NULL &&
            rdlen == sizeof(payload) && memcmp(rd, payload, sizeof(payload)) == 0,
        "read obj1 round-trips"
    );
    free(rd);

    /* missing file: CKR_OK with out == NULL (absence, not error). */
    rd = (unsigned char *)1;
    rdlen = 99;
    CHECK(
        tsra_pkcs11_store_read(store, "nope", &rd, &rdlen) == CKR_OK && rd == NULL && rdlen == 0,
        "read of missing file is absence, not error"
    );

    /* rewrite (overwrite) then unlink idempotently. */
    CHECK(
        tsra_pkcs11_store_write(store, "obj1", payload, 10) == CKR_OK,
        "overwrite obj1 (shorter)"
    );
    CHECK(
        tsra_pkcs11_store_read(store, "obj1", &rd, &rdlen) == CKR_OK && rdlen == 10,
        "overwrite took effect"
    );
    free(rd);
    CHECK(tsra_pkcs11_store_unlink(store, "obj1") == CKR_OK, "unlink obj1");
    CHECK(
        tsra_pkcs11_store_read(store, "obj1", &rd, &rdlen) == CKR_OK && rd == NULL,
        "obj1 gone after unlink"
    );
    CHECK(tsra_pkcs11_store_unlink(store, "obj1") == CKR_OK, "unlink is idempotent");

    /* oversize write rejected. */
    size_t big = P11_STORE_MAX_FILE_SIZE + 1;
    unsigned char *bigbuf = (unsigned char *)calloc(1, big);
    CHECK(
        bigbuf != NULL && tsra_pkcs11_store_write(store, "big", bigbuf, big) == CKR_DEVICE_MEMORY,
        "oversize write rejected (CKR_DEVICE_MEMORY)"
    );
    free(bigbuf);
    CHECK(
        tsra_pkcs11_store_write(store, "zero", payload, 0) == CKR_ARGUMENTS_BAD,
        "zero-length write rejected (the store never writes an empty file)"
    );

    /* An empty file is corrupt, not absent. */
    char path[8192];
    snprintf(path, sizeof(path), "%s/empty", store);
    int efd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (efd >= 0)
    {
        close(efd);
    }
    rd = (unsigned char *)1;
    CHECK(
        efd >= 0 && tsra_pkcs11_store_read(store, "empty", &rd, &rdlen) == CKR_FUNCTION_FAILED &&
            rd == NULL,
        "read of an empty file -> CKR_FUNCTION_FAILED"
    );

    /* A stale temp file (here a second link to another file, mode 0644) is
     * replaced, never written through. */
    CHECK(
        tsra_pkcs11_store_write(store, "victim", payload, sizeof(payload)) == CKR_OK,
        "write victim"
    );
    char victim[8192];
    snprintf(victim, sizeof(victim), "%s/victim", store);
    snprintf(path, sizeof(path), "%s/.obj2.tmp", store);
    CHECK(link(victim, path) == 0 && chmod(path, 0644) == 0, "plant .obj2.tmp as a link to victim");
    CHECK(
        tsra_pkcs11_store_write(store, "obj2", payload, 10) == CKR_OK,
        "write obj2 over the plant"
    );
    CHECK(
        tsra_pkcs11_store_read(store, "victim", &rd, &rdlen) == CKR_OK && rd != NULL &&
            rdlen == sizeof(payload),
        "victim is untouched"
    );
    free(rd);
    CHECK(
        file_mode(store, "obj2") == 0600 && file_links(store, "obj2") == 1 &&
            file_links(store, "victim") == 1 && !file_exists(store, ".obj2.tmp"),
        "obj2 is a fresh 0600 inode, sharing nothing with victim"
    );

    /* create publishes a new name only. */
    CHECK(tsra_pkcs11_store_create(store, "c1", payload, 10) == CKR_OK, "create c1");
    CHECK(
        tsra_pkcs11_store_create(store, "c1", payload, sizeof(payload)) == CKR_FUNCTION_FAILED,
        "create over an existing c1 -> CKR_FUNCTION_FAILED"
    );
    CHECK(
        tsra_pkcs11_store_read(store, "c1", &rd, &rdlen) == CKR_OK && rdlen == 10 &&
            file_mode(store, "c1") == 0600 && file_links(store, "c1") == 1 &&
            !file_exists(store, ".c1.tmp"),
        "c1 kept its first content, one link, no leftover temp"
    );
    free(rd);

    /* FIFOs are refused, not waited on: a blocking open would hang the test
     * until the alarm fires. */
    alarm(10);
    snprintf(path, sizeof(path), "%s/fifo", store);
    CHECK(
        mkfifo(path, 0600) == 0 &&
            tsra_pkcs11_store_read(store, "fifo", &rd, &rdlen) == CKR_FUNCTION_FAILED,
        "read of a FIFO -> CKR_FUNCTION_FAILED"
    );
    char sub[4200];
    snprintf(sub, sizeof(sub), "%s/sub", store);
    snprintf(path, sizeof(path), "%s/.lock", sub);
    int lfd = -1;
    CHECK(
        tsra_pkcs11_store_dir_ensure(sub) == CKR_OK && mkfifo(path, 0600) == 0 &&
            tsra_pkcs11_store_lock(sub, &lfd) == CKR_FUNCTION_FAILED && lfd == -1,
        "a FIFO as .lock -> CKR_FUNCTION_FAILED"
    );
    alarm(0);

    /* cross-process exclusion: K children * M locked increments == K*M. */
    const int K = 4, M = 50;
    size_t zero = 0;
    CHECK(
        tsra_pkcs11_store_write(store, "counter", (unsigned char *)&zero, sizeof(zero)) == CKR_OK,
        "counter initialized to 0"
    );
    for (int k = 0; k < K; k++)
    {
        pid_t pid = fork();
        if (pid == 0)
        {
            child_increment(store, M);
        }
    }
    int status = 0, kids_ok = 1;
    for (int k = 0; k < K; k++)
    {
        int st = 0;
        wait(&st);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
        {
            kids_ok = 0;
        }
    }
    (void)status;
    CHECK(kids_ok, "all lock children exited cleanly");
    unsigned char *cbuf = NULL;
    size_t clen = 0;
    size_t total = 0;
    if (tsra_pkcs11_store_read(store, "counter", &cbuf, &clen) == CKR_OK && cbuf != NULL &&
        clen == sizeof(total))
    {
        memcpy(&total, cbuf, sizeof(total));
    }
    free(cbuf);
    printf("  counter total = %zu (expect %d)\n", total, K * M);
    CHECK(
        total == (size_t)(K * M),
        "cross-process lock serialized all increments (no lost updates)"
    );

    printf(g_fail ? "\nSTORE_IO FAIL (%d checks)\n" : "\nSTORE_IO OK (%d checks)\n", g_checks);
    return g_fail;
}
