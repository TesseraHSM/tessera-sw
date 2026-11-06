// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the environment configuration, the PIN rules and the owner
 * backup key (src/tsra_pkcs11_config.c), driven through tsra_pkcs11_config_load
 * with setenv. No device, no libcrypto:
 *
 *   gcc -DTSRA_WITH_HSM -I ../include/pkcs11-v3.1 -I ../src config_test.c \
 *       ../src/tsra_pkcs11_config.c ../src/tsra_pkcs11_store_io.c \
 *       -o config_test && ./config_test
 *
 * Built like a hardware build, TSRA_WITH_HSM without TSRA_FEATURE_EMULATOR: no
 * built-in partition ID and no built-in owner backup key, and a load without
 * either fails. Covers the store directory failing closed (empty, relative,
 * "..", overlong) while an unset variable takes the default, the "file:"
 * prefix, the boolean switches, the credentials (malformed fails closed), the
 * PIN normalisation, the owner backup key file named at load and read later,
 * and the wipe.
 */

#define _DEFAULT_SOURCE

#include "tsra_pkcs11_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(TSRA_WITH_HSM) || defined(TSRA_FEATURE_EMULATOR)
#error "config_test pins the hardware build: TSRA_WITH_HSM without TSRA_FEATURE_EMULATOR"
#endif

/* What every load of a hardware build needs; main sets both. The key file is
 * only named at load, so it need not exist. */
#define P11_TEST_ID "000102030405060708090a0b0c0d0e0f"
#define P11_TEST_OBK_PATH "/srv/obk.bin"

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

static bool all_bytes(const CK_BYTE *p, size_t n, CK_BYTE v)
{
    for (size_t i = 0; i < n; i++)
    {
        if (p[i] != v)
        {
            return false;
        }
    }
    return true;
}

/* Set environment variable `name` to `value`, or unset it for NULL. */
static void set_env(const char *name, const char *value)
{
    if (value == NULL)
    {
        unsetenv(name);
    }
    else
    {
        setenv(name, value, 1);
    }
}

/* Load with TSRA_PKCS11_STORE_DIR set to `dir` (unset for NULL). */
static CK_RV load_with_dir(const char *dir, tsra_pkcs11_config *cfg)
{
    set_env(TSRA_PKCS11_ENV_STORE_DIR, dir);
    return tsra_pkcs11_config_load(cfg);
}

static void test_store_dir(void)
{
    printf("== store directory ==\n");
    tsra_pkcs11_config cfg;
    CHECK(
        (load_with_dir(NULL, &cfg) == CKR_OK) &&
            (strcmp(cfg.store_dir, TSRA_PKCS11_DEFAULT_STORE_DIR) == 0),
        "unset -> the default directory"
    );
    CHECK(
        (load_with_dir("/srv/p11", &cfg) == CKR_OK) && (strcmp(cfg.store_dir, "/srv/p11") == 0),
        "a plain path is taken as is"
    );
    CHECK(
        (load_with_dir("file:/srv/p11", &cfg) == CKR_OK) &&
            (strcmp(cfg.store_dir, "/srv/p11") == 0),
        "a file: prefix is stripped"
    );
    CHECK(load_with_dir("", &cfg) == CKR_GENERAL_ERROR, "empty -> CKR_GENERAL_ERROR");
    CHECK(strstr(cfg.error, TSRA_PKCS11_ENV_STORE_DIR) != NULL, "the reason names the variable");
    CHECK(
        load_with_dir("file:", &cfg) == CKR_GENERAL_ERROR,
        "empty after file: -> CKR_GENERAL_ERROR"
    );
    CHECK(load_with_dir("srv/p11", &cfg) == CKR_GENERAL_ERROR, "relative -> CKR_GENERAL_ERROR");
    CHECK(
        load_with_dir("file:srv/p11", &cfg) == CKR_GENERAL_ERROR,
        "relative after file: -> CKR_GENERAL_ERROR"
    );
    CHECK(load_with_dir("/srv/../etc", &cfg) == CKR_GENERAL_ERROR, "'..' -> CKR_GENERAL_ERROR");
    CHECK(
        load_with_dir("file:../p11", &cfg) == CKR_GENERAL_ERROR,
        "'..' after file: -> CKR_GENERAL_ERROR"
    );

    /* The longest path that fits store_dir, and one byte more. */
    static char path[TSRA_PKCS11_PATH_LEN + 1];
    memset(path, 'a', TSRA_PKCS11_PATH_LEN - 1);
    path[0] = '/';
    path[TSRA_PKCS11_PATH_LEN - 1] = '\0';
    CHECK(
        (load_with_dir(path, &cfg) == CKR_OK) && (strcmp(cfg.store_dir, path) == 0),
        "the longest path that fits is taken"
    );
    path[TSRA_PKCS11_PATH_LEN - 1] = 'a';
    path[TSRA_PKCS11_PATH_LEN] = '\0';
    CHECK(load_with_dir(path, &cfg) == CKR_GENERAL_ERROR, "one byte longer -> CKR_GENERAL_ERROR");
    unsetenv(TSRA_PKCS11_ENV_STORE_DIR);
    tsra_pkcs11_config_clear(&cfg);
}

static void test_switches(void)
{
    printf("== boolean switches ==\n");
    tsra_pkcs11_config cfg;
    static const struct
    {
        const char *value; /* NULL: unset */
        CK_RV rv;
        bool on;
    } rows[] = {
        { NULL, CKR_OK, false },
        { "1", CKR_OK, true },
        { "true", CKR_OK, true },
        { "TRUE", CKR_OK, true },
        { "0", CKR_OK, false },
        { "False", CKR_OK, false },
        { "", CKR_GENERAL_ERROR, false },
        { "yes", CKR_GENERAL_ERROR, false },
        { "1 ", CKR_GENERAL_ERROR, false },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
    {
        char msg[96];
        set_env(TSRA_PKCS11_ENV_PERSIST, rows[i].value);
        CK_RV rv = tsra_pkcs11_config_load(&cfg);
        snprintf(
            msg,
            sizeof(msg),
            "%s='%s' -> %s",
            TSRA_PKCS11_ENV_PERSIST,
            (rows[i].value != NULL) ? rows[i].value : "(unset)",
            (rows[i].rv != CKR_OK) ? "CKR_GENERAL_ERROR"
            : rows[i].on           ? "file store"
                                   : "memory store"
        );
        CHECK((rv == rows[i].rv) && ((rv != CKR_OK) || (cfg.store_persist == rows[i].on)), msg);
    }
    unsetenv(TSRA_PKCS11_ENV_PERSIST);

    CHECK((tsra_pkcs11_config_load(&cfg) == CKR_OK) && !cfg.debug, "debug is off by default");
    setenv(TSRA_PKCS11_ENV_DEBUG, "1", 1);
    CHECK((tsra_pkcs11_config_load(&cfg) == CKR_OK) && cfg.debug, "TSRA_PKCS11_DEBUG=1 -> on");
    setenv(TSRA_PKCS11_ENV_DEBUG, "on", 1);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR) && !cfg.debug,
        "TSRA_PKCS11_DEBUG=on -> CKR_GENERAL_ERROR, not traced"
    );
    setenv(TSRA_PKCS11_ENV_DEBUG, "1", 1);
    setenv(TSRA_PKCS11_ENV_STORE_DIR, "/srv/../etc", 1);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR) && cfg.debug,
        "a refused configuration still carries the debug setting"
    );
    unsetenv(TSRA_PKCS11_ENV_DEBUG);
    unsetenv(TSRA_PKCS11_ENV_STORE_DIR);
    tsra_pkcs11_config_clear(&cfg);
}

static void test_credentials(void)
{
    printf("== credentials ==\n");
    tsra_pkcs11_config cfg;
    unsetenv(TSRA_PKCS11_ENV_ID);
    unsetenv(TSRA_PKCS11_ENV_PIN);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR) && !cfg.id_set &&
            (strstr(cfg.error, TSRA_PKCS11_ENV_ID) != NULL),
        "no partition ID -> CKR_GENERAL_ERROR (none built into a hardware build)"
    );
    setenv(TSRA_PKCS11_ENV_ID, P11_TEST_ID, 1);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_OK) && !cfg.default_pin_set,
        "unset -> no default PIN"
    );

    setenv(TSRA_PKCS11_ENV_ID, "000102030405060708090a0B0c0D0e0F", 1);
    setenv(TSRA_PKCS11_ENV_PIN, "ffffffffffffffffffffffffffffffff", 1);
    bool counting = true;
    CHECK(tsra_pkcs11_config_load(&cfg) == CKR_OK, "valid hex loads");
    for (size_t i = 0; i < sizeof(cfg.id); i++)
    {
        counting = counting && (cfg.id[i] == i);
    }
    CHECK(counting && cfg.id_set, "the id decodes, either hex case");
    CHECK(
        all_bytes(cfg.default_pin, sizeof(cfg.default_pin), 0xFF) && cfg.default_pin_set,
        "the default PIN decodes"
    );

    static const struct
    {
        const char *hex;
        const char *name;
    } bad[] = {
        { "000102030405060708090a0b0c0d0e0", "odd length (31)" },
        { "000102030405060708090a0b0c0d0e0f00", "overlong (34)" },
        { "000102030405060708090a0b0c0d0eXY", "a non-hex digit" },
        { "", "empty" },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        char msg[96];
        setenv(TSRA_PKCS11_ENV_ID, bad[i].hex, 1);
        snprintf(msg, sizeof(msg), "id %s -> CKR_GENERAL_ERROR", bad[i].name);
        CHECK(tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR, msg);
        setenv(TSRA_PKCS11_ENV_ID, "000102030405060708090a0b0c0d0e0f", 1);
        setenv(TSRA_PKCS11_ENV_PIN, bad[i].hex, 1);
        snprintf(msg, sizeof(msg), "default PIN %s -> CKR_GENERAL_ERROR", bad[i].name);
        CHECK(
            (tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR) &&
                (strstr(cfg.error, TSRA_PKCS11_ENV_PIN) != NULL),
            msg
        );
        setenv(TSRA_PKCS11_ENV_PIN, "ffffffffffffffffffffffffffffffff", 1);
    }
    setenv(TSRA_PKCS11_ENV_ID, P11_TEST_ID, 1);
    unsetenv(TSRA_PKCS11_ENV_PIN);

    tsra_pkcs11_config_clear(&cfg);
    CHECK(all_bytes((const CK_BYTE *)&cfg, sizeof(cfg), 0), "config_clear zeroes the whole config");
    tsra_pkcs11_config_clear(NULL);
    CHECK(tsra_pkcs11_config_load(NULL) == CKR_ARGUMENTS_BAD, "NULL config -> CKR_ARGUMENTS_BAD");
}

static void test_pin_normalise(void)
{
    printf("== PIN normalisation ==\n");
    static const struct
    {
        const char *pin; /* NULL: no buffer */
        CK_ULONG len;
        CK_RV rv;
        const char *name;
    } rows[] = {
        { NULL, 0, CKR_PIN_LEN_RANGE, "no PIN" },
        { "", 0, CKR_PIN_LEN_RANGE, "an empty PIN" },
        { NULL, 4, CKR_ARGUMENTS_BAD, "a NULL PIN with a length" },
        { "123", 3, CKR_PIN_LEN_RANGE, "3 bytes" },
        { "1234", 4, CKR_OK, "4 bytes" },
        { "0123456789abcdef", 16, CKR_OK, "16 bytes" },
        { "0123456789abcdefg", 17, CKR_PIN_LEN_RANGE, "17 bytes" },
        { "12\0"
          "4",
          4,
          CKR_PIN_INVALID,
          "a NUL inside" },
        { "1234\0\0", 6, CKR_PIN_INVALID, "trailing NULs: not the same credential as 1234" },
        { "p\xc3\xa4ss", 5, CKR_OK, "UTF-8 beyond ASCII" },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
    {
        CK_BYTE out[P11_CREDS_PIN_LEN];
        memset(out, 0xEE, sizeof(out));
        CK_RV rv = tsra_pkcs11_pin_normalise((const CK_UTF8CHAR *)rows[i].pin, rows[i].len, out);
        bool shaped = (rv == CKR_OK) ? ((memcmp(out, rows[i].pin, rows[i].len) == 0) &&
                                        all_bytes(out + rows[i].len, sizeof(out) - rows[i].len, 0))
                                     : all_bytes(out, sizeof(out), 0xEE);
        char msg[96];
        snprintf(
            msg,
            sizeof(msg),
            "%s -> 0x%lx, %s",
            rows[i].name,
            (unsigned long)rows[i].rv,
            (rv == CKR_OK) ? "zero-padded" : "output untouched"
        );
        CHECK((rv == rows[i].rv) && shaped, msg);
    }
    CHECK(
        tsra_pkcs11_pin_normalise((const CK_UTF8CHAR *)"1234", 4, NULL) == CKR_ARGUMENTS_BAD,
        "NULL output -> CKR_ARGUMENTS_BAD"
    );
}

/* Write `len` bytes of `fill` to `path`. */
static bool write_file(const char *path, CK_BYTE fill, size_t len)
{
    CK_BYTE buf[64];
    memset(buf, fill, sizeof(buf));
    FILE *f = fopen(path, "wb");
    bool ok = (f != NULL) && (len <= sizeof(buf)) && (fwrite(buf, 1, len, f) == len);
    return (f != NULL) && (fclose(f) == 0) && ok;
}

static void test_obk(const char *root)
{
    printf("== owner backup key ==\n");
    tsra_pkcs11_config cfg;
    CK_BYTE obk[P11_OBK_LEN];
    char key[TSRA_PKCS11_PATH_LEN];
    char path[TSRA_PKCS11_PATH_LEN + 8];
    snprintf(key, sizeof(key), "%s/obk.bin", root);

    unsetenv(TSRA_PKCS11_ENV_OBK_PATH);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR) &&
            (strstr(cfg.error, TSRA_PKCS11_ENV_OBK_PATH) != NULL),
        "none configured -> CKR_GENERAL_ERROR (no built-in key in a hardware build)"
    );
    CHECK(
        tsra_pkcs11_config_obk(&cfg, obk) == CKR_FUNCTION_FAILED,
        "reading without a path -> CKR_FUNCTION_FAILED"
    );
    snprintf(path, sizeof(path), "%s/missing.bin", root);
    setenv(TSRA_PKCS11_ENV_OBK_PATH, path, 1);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_OK) && (strcmp(cfg.obk_path, path) == 0),
        "a missing file loads: the key is read at login, not at load"
    );

    CHECK(write_file(key, 0x5A, P11_OBK_LEN), "write a 48-byte key file");
    snprintf(path, sizeof(path), "file:%s", key);
    setenv(TSRA_PKCS11_ENV_OBK_PATH, path, 1);
    memset(obk, 0, sizeof(obk));
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_OK) && (strcmp(cfg.obk_path, key) == 0) &&
            (tsra_pkcs11_config_obk(&cfg, obk) == CKR_OK) && all_bytes(obk, sizeof(obk), 0x5A),
        "a 48-byte file is the key (file: prefix stripped)"
    );

    static const size_t sizes[] = { P11_OBK_LEN - 1, P11_OBK_LEN + 1, 0 };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
    {
        char msg[64];
        snprintf(msg, sizeof(msg), "a %zu-byte file -> CKR_FUNCTION_FAILED", sizes[i]);
        CHECK(
            write_file(key, 0x5A, sizes[i]) &&
                (tsra_pkcs11_config_obk(&cfg, obk) == CKR_FUNCTION_FAILED),
            msg
        );
    }
    CHECK(write_file(key, 0x5A, P11_OBK_LEN), "restore the key file");

    snprintf(path, sizeof(path), "%s/obk-link.bin", root);
    CHECK(
        (symlink(key, path) == 0) &&
            (snprintf(cfg.obk_path, sizeof(cfg.obk_path), "%s", path) > 0) &&
            (tsra_pkcs11_config_obk(&cfg, obk) == CKR_FUNCTION_FAILED),
        "a symbolic link -> CKR_FUNCTION_FAILED"
    );
    unlink(path);
    snprintf(cfg.obk_path, sizeof(cfg.obk_path), "%s/missing.bin", root);
    CHECK(
        tsra_pkcs11_config_obk(&cfg, obk) == CKR_FUNCTION_FAILED,
        "missing -> CKR_FUNCTION_FAILED"
    );
    snprintf(cfg.obk_path, sizeof(cfg.obk_path), "%s", root);
    CHECK(
        tsra_pkcs11_config_obk(&cfg, obk) == CKR_FUNCTION_FAILED,
        "a directory -> CKR_FUNCTION_FAILED"
    );

    setenv(TSRA_PKCS11_ENV_OBK_PATH, "/etc/../obk.bin", 1);
    CHECK(tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR, "'..' -> CKR_GENERAL_ERROR");
    setenv(TSRA_PKCS11_ENV_OBK_PATH, "obk.bin", 1);
    CHECK(tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR, "relative -> CKR_GENERAL_ERROR");
    setenv(TSRA_PKCS11_ENV_OBK_PATH, P11_TEST_OBK_PATH, 1);
    CHECK(
        tsra_pkcs11_config_obk(NULL, obk) == CKR_ARGUMENTS_BAD,
        "NULL config -> CKR_ARGUMENTS_BAD"
    );
    unlink(key);
    tsra_pkcs11_config_clear(&cfg);
}

int main(void)
{
    char root[] = "/tmp/tsra_pkcs11_config_test.XXXXXX";
    if (mkdtemp(root) == NULL)
    {
        perror("mkdtemp");
        return 1;
    }
    unsetenv(TSRA_PKCS11_ENV_CONF);
    setenv(TSRA_PKCS11_ENV_ID, P11_TEST_ID, 1);
    setenv(TSRA_PKCS11_ENV_OBK_PATH, P11_TEST_OBK_PATH, 1);
    test_store_dir();
    test_switches();
    test_credentials();
    test_pin_normalise();
    test_obk(root);
    rmdir(root);
    printf(
        g_fail ? "\nconfig_test: FAILED (%d checks)\n" : "\nconfig_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
