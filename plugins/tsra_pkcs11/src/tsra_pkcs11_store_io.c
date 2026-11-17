// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * _DEFAULT_SOURCE exposes flock(2), lstat(2), fsync(2) and the O_NOFOLLOW /
 * O_DIRECTORY / O_CLOEXEC open flags on glibc; it must precede every include.
 * The provider gets these from its CMake build, but this file also compiles in
 * the bare no-device smoke build (a plain gcc over the sources, no -lcrypto), so
 * the request is stated here.
 */
#define _DEFAULT_SOURCE

#include "tsra_pkcs11_store_io.h"
#include "tsra_pkcs11_wipe.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

/* store_dir (up to 4096) + '/' + name (up to 256) + temp affix (".<name>.tmp")
 * + NUL, with headroom. tsra_pkcs11_store_path_join rejects anything that still would
 * not fit via the snprintf truncation check, so this is only a comfortable
 * upper bound. */
#define P11_STORE_PATH_MAX 4608

static CK_RV ckr_from_errno(int e)
{
    switch (e)
    {
    case ENOMEM:
        return CKR_HOST_MEMORY;
    case ENOSPC:
    case EDQUOT:
        return CKR_DEVICE_MEMORY; /* out of disk / quota */
    default:
        return CKR_FUNCTION_FAILED;
    }
}

/* fsync `dir`, so a rename, link or unlink in it survives a crash. The
 * object store's counter-first rule relies on that, so a failure is reported
 * rather than ignored. */
static CK_RV sync_dir(const char *dir)
{
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd < 0)
    {
        return ckr_from_errno(errno);
    }
    int rc = fsync(dfd);
    int e = errno;
    close(dfd);
    return (rc == 0) ? CKR_OK : ckr_from_errno(e);
}

CK_RV tsra_pkcs11_store_path_join(char *out, size_t outlen, const char *dir, const char *name)
{
    if (out == NULL || dir == NULL || name == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    /* `name` must be a single flat component: no separator, no traversal. Mirror
     * the provider's build_storage_path reject set (tsra_ossl_resiliency.c). */
    size_t nlen = strnlen(name, P11_STORE_MAX_NAME_LEN + 1);
    if (nlen == 0 || nlen > P11_STORE_MAX_NAME_LEN)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (strchr(name, '/') != NULL || strcmp(name, "..") == 0 || strstr(name, "../") != NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    int written = snprintf(out, outlen, "%s/%s", dir, name);
    if (written < 0 || (size_t)written >= outlen)
    {
        return CKR_FUNCTION_FAILED;
    }
    return CKR_OK;
}

CK_RV tsra_pkcs11_store_dir_ensure(const char *dir)
{
    if (dir == NULL || dir[0] == '\0')
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (mkdir(dir, S_IRWXU) == 0) /* 0700: owner-only */
    {
        return CKR_OK;
    }
    if (errno != EEXIST)
    {
        return ckr_from_errno(errno);
    }
    /* Already present: require a real directory, owned by us, with no group or
     * other access (defense against a pre-planted world-writable store dir). */
    struct stat st;
    if (lstat(dir, &st) != 0)
    {
        return ckr_from_errno(errno);
    }
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid() || (st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    {
        return CKR_FUNCTION_FAILED;
    }
    return CKR_OK;
}

/* The body of tsra_pkcs11_store_write (`replace`) and tsra_pkcs11_store_create. */
static CK_RV write_file(
    const char *dir,
    const char *name,
    const unsigned char *data,
    size_t len,
    bool replace
)
{
    if ((dir == NULL) || (name == NULL) || (data == NULL) || (len == 0))
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (len > P11_STORE_MAX_FILE_SIZE)
    {
        return CKR_DEVICE_MEMORY; /* C_CreateObject and C_SetAttributeValue have no *_LEN_RANGE */
    }

    char path[P11_STORE_PATH_MAX];
    char tmp[P11_STORE_PATH_MAX];
    CK_RV rv = tsra_pkcs11_store_path_join(path, sizeof(path), dir, name);
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* Temp name is derived from the target so it lands in the same directory
     * (rename is only atomic within one filesystem). */
    int written = snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", dir, name);
    if (written < 0 || (size_t)written >= sizeof(tmp))
    {
        return CKR_FUNCTION_FAILED;
    }

    /* A temp file left by a crash may carry another mode or further hard
     * links; remove it, so O_EXCL always makes a fresh 0600 inode. */
    (void)unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        return ckr_from_errno(errno);
    }

    size_t off = 0;
    while (off < len)
    {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            int e = errno;
            close(fd);
            unlink(tmp);
            return ckr_from_errno(e);
        }
        off += (size_t)n;
    }
    /* Flush data before the rename so a crash cannot expose a renamed-but-empty
     * file. */
    if (fsync(fd) != 0)
    {
        int e = errno;
        close(fd);
        unlink(tmp);
        return ckr_from_errno(e);
    }
    if (close(fd) != 0)
    {
        int e = errno;
        unlink(tmp);
        return ckr_from_errno(e);
    }
    /* Both are atomic: readers see old or new, never partial. link() fails
     * with EEXIST instead of replacing an existing target. */
    if ((replace ? rename(tmp, path) : link(tmp, path)) != 0)
    {
        int e = errno;
        unlink(tmp);
        return ckr_from_errno(e);
    }
    if (!replace)
    {
        (void)unlink(tmp); /* a leftover second link is removed by the next write */
    }
    return sync_dir(dir);
}

CK_RV tsra_pkcs11_store_write(
    const char *dir,
    const char *name,
    const unsigned char *data,
    size_t len
)
{
    return write_file(dir, name, data, len, true);
}

CK_RV tsra_pkcs11_store_create(
    const char *dir,
    const char *name,
    const unsigned char *data,
    size_t len
)
{
    return write_file(dir, name, data, len, false);
}

CK_RV tsra_pkcs11_store_read(const char *dir, const char *name, unsigned char **out, size_t *len)
{
    if (dir == NULL || name == NULL || out == NULL || len == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    *out = NULL;
    *len = 0;

    char path[P11_STORE_PATH_MAX];
    CK_RV rv = tsra_pkcs11_store_path_join(path, sizeof(path), dir, name);
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* O_NONBLOCK: opening a FIFO planted under this name would otherwise block
     * until a writer appears; the regular-file check below then rejects it. */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
    {
        /* Absence is a valid state, not an error (mirrors tsra_file_load). */
        if (errno == ENOENT)
        {
            return CKR_OK;
        }
        return ckr_from_errno(errno);
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        int e = errno;
        close(fd);
        return ckr_from_errno(e);
    }
    /* Reject anything that is not a plain file, and a size we will not read.
     * The store never writes an empty file, so an empty one is corrupt. */
    if ((!S_ISREG(st.st_mode)) || (st.st_size <= 0) ||
        ((unsigned long long)st.st_size > P11_STORE_MAX_FILE_SIZE))
    {
        close(fd);
        return CKR_FUNCTION_FAILED;
    }
    size_t size = (size_t)st.st_size;

    unsigned char *buf = (unsigned char *)malloc(size);
    if (buf == NULL)
    {
        close(fd);
        return CKR_HOST_MEMORY;
    }
    size_t off = 0;
    while (off < size)
    {
        ssize_t n = read(fd, buf + off, size - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            int e = errno;
            tsra_pkcs11_wipe(buf, size);
            free(buf);
            close(fd);
            return ckr_from_errno(e);
        }
        if (n == 0)
        {
            break; /* file shrank under us — treat as a torn read below */
        }
        off += (size_t)n;
    }
    close(fd);
    if (off != size)
    {
        tsra_pkcs11_wipe(buf, size);
        free(buf);
        return CKR_FUNCTION_FAILED;
    }
    *out = buf;
    *len = size;
    return CKR_OK;
}

CK_RV tsra_pkcs11_store_unlink(const char *dir, const char *name)
{
    if (dir == NULL || name == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    char path[P11_STORE_PATH_MAX];
    CK_RV rv = tsra_pkcs11_store_path_join(path, sizeof(path), dir, name);
    if (rv != CKR_OK)
    {
        return rv;
    }
    if (unlink(path) != 0 && errno != ENOENT)
    {
        return ckr_from_errno(errno);
    }
    /* Also when the name was already gone: whoever removed it may not have
     * synced, and a destroyed object must not come back after a crash. */
    return sync_dir(dir);
}

CK_RV tsra_pkcs11_store_lock(const char *dir, int *lock_fd)
{
    if (dir == NULL || lock_fd == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    *lock_fd = -1;

    char path[P11_STORE_PATH_MAX];
    CK_RV rv = tsra_pkcs11_store_path_join(path, sizeof(path), dir, ".lock");
    if (rv != CKR_OK)
    {
        return rv;
    }
    /* Fresh fd per acquisition: flock is per open-file-description, so a shared
     * fd would let a second acquirer's lock silently succeed. O_NONBLOCK as in
     * tsra_pkcs11_store_read; it does not make flock(2) non-blocking. */
    int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, S_IRUSR | S_IWUSR);
    if (fd < 0)
    {
        return ckr_from_errno(errno);
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
    {
        close(fd);
        return CKR_FUNCTION_FAILED;
    }
    if (flock(fd, LOCK_EX) != 0)
    {
        int e = errno;
        close(fd);
        return ckr_from_errno(e);
    }
    *lock_fd = fd;
    return CKR_OK;
}

void tsra_pkcs11_store_unlock(int lock_fd)
{
    if (lock_fd < 0)
    {
        return;
    }
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
}
