// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/*
 * Unit test for the configuration file (TSRA_PKCS11_CONF): the pure parser
 * tsra_pkcs11_config_parse on text, and tsra_pkcs11_config_load on files with
 * setenv. No device, no libcrypto:
 *
 *   gcc -DTSRA_WITH_HSM -I ../include/pkcs11-v3.1 -I ../src config_file_test.c \
 *       ../src/tsra_pkcs11_config.c ../src/tsra_pkcs11_store_io.c \
 *       -o config_file_test && ./config_file_test
 *
 * Covers comments and blank lines, blanks and CRLF line ends, every key,
 * unknown keys and credentials refused, malformed lines and values, overlong
 * values, the "file:" prefix, relative paths and ".." failing closed, a NUL
 * byte, the line number in the reason, a missing file, the environment winning
 * over the file, and the sample file next to the README. Built like a hardware
 * build, so every file a load accepts names an obk_path and main sets the
 * partition ID.
 */

#define _DEFAULT_SOURCE

#include "tsra_pkcs11_config.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

/* A config holding the defaults load starts from, then `text` parsed on top. */
static CK_RV parse(tsra_pkcs11_config *cfg, const char *text)
{
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->store_dir, sizeof(cfg->store_dir), "%s", TSRA_PKCS11_DEFAULT_STORE_DIR);
    return tsra_pkcs11_config_parse(cfg, text, strlen(text));
}

static void test_accepted(void)
{
    printf("== accepted files ==\n");
    tsra_pkcs11_config cfg;
    CHECK(
        (parse(&cfg, "# only a comment\n\n   \n\t# indented comment\n") == CKR_OK) &&
            (strcmp(cfg.store_dir, TSRA_PKCS11_DEFAULT_STORE_DIR) == 0) && !cfg.store_persist &&
            !cfg.debug && (cfg.obk_path[0] == '\0'),
        "comments and blank lines change nothing"
    );
    CHECK(tsra_pkcs11_config_parse(&cfg, NULL, 0) == CKR_OK, "no text at all");
    CHECK(
        (parse(&cfg, "store_dir=/srv/p11\npersist=1\ndebug=true\nobk_path=/etc/tsra/obk.bin\n") ==
         CKR_OK) &&
            (strcmp(cfg.store_dir, "/srv/p11") == 0) && cfg.store_persist && cfg.debug &&
            (strcmp(cfg.obk_path, "/etc/tsra/obk.bin") == 0),
        "every key"
    );
    CHECK(
        (parse(&cfg, "  store_dir \t=\t /srv/p 11  \r\n persist = TRUE\r\n") == CKR_OK) &&
            (strcmp(cfg.store_dir, "/srv/p 11") == 0) && cfg.store_persist,
        "blanks around key and value and CRLF line ends are ignored, inner blanks kept"
    );
    CHECK(
        (parse(&cfg, "persist = 1\ndebug = 1") == CKR_OK) && cfg.debug,
        "a last line without a line end"
    );
    CHECK(
        (parse(&cfg, "store_dir = file:/srv/p11\nobk_path = file:/srv/obk.bin\n") == CKR_OK) &&
            (strcmp(cfg.store_dir, "/srv/p11") == 0) && (strcmp(cfg.obk_path, "/srv/obk.bin") == 0),
        "a file: prefix is stripped"
    );
    CHECK(
        (parse(&cfg, "persist = 1\npersist = 0\n") == CKR_OK) && !cfg.store_persist,
        "a repeated key: the last line wins"
    );

    /* The longest value that fits, and one byte more. */
    static char text[TSRA_PKCS11_PATH_LEN + 32];
    int n = snprintf(text, sizeof(text), "store_dir = /");
    memset(text + n, 'a', TSRA_PKCS11_PATH_LEN - 2);
    text[n + TSRA_PKCS11_PATH_LEN - 2] = '\0';
    CHECK(
        (parse(&cfg, text) == CKR_OK) && (strlen(cfg.store_dir) == TSRA_PKCS11_PATH_LEN - 1),
        "the longest path that fits is taken"
    );
    strcat(text, "a");
    CHECK(parse(&cfg, text) == CKR_GENERAL_ERROR, "one byte longer -> CKR_GENERAL_ERROR");
}

static void test_refused(void)
{
    printf("== refused files ==\n");
    static const struct
    {
        const char *text;
        const char *name;
    } rows[] = {
        { "persit = 1\n", "a misspelt key" },
        { "pin = 1234\n", "a PIN" },
        { "id = 000102030405060708090a0b0c0d0e0f\n", "a partition ID" },
        { "TSRA_PKCS11_PIN = 31323334000000000000000000000000\n", "a credential variable" },
        { "Persist = 1\n", "a key in another case" },
        { "= 1\n", "no key" },
        { "persist\n", "no '='" },
        { "persist = yes\n", "a boolean other than 1, 0, true or false" },
        { "persist = 1 # on\n", "a trailing comment (comments are whole lines)" },
        { "debug =\n", "an empty boolean" },
        { "store_dir =\n", "an empty path" },
        { "obk_path = file:\n", "an empty path after file:" },
        { "store_dir = /srv/../etc\n", "'..' in a path" },
        { "obk_path = ../obk.bin\n", "'..' in the key path" },
        { "store_dir = srv/p11\n", "a relative path" },
        { "obk_path = file:obk.bin\n", "a relative key path after file:" },
    };
    tsra_pkcs11_config cfg;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
    {
        char msg[96];
        snprintf(msg, sizeof(msg), "%s -> CKR_GENERAL_ERROR", rows[i].name);
        CHECK(parse(&cfg, rows[i].text) == CKR_GENERAL_ERROR, msg);
    }

    CHECK(
        (parse(&cfg, "# settings\n\npersist = 1\nstore_dir = /a/../b\n") == CKR_GENERAL_ERROR) &&
            (strstr(cfg.error, "line 4") != NULL) && (strstr(cfg.error, "store_dir") != NULL),
        "the reason names the line and the key"
    );
    CHECK(
        (parse(&cfg, "pin = 1234\n") == CKR_GENERAL_ERROR) && (strstr(cfg.error, "1234") == NULL),
        "the reason never repeats a value"
    );
    static const char nul[] = "persist = 1\0\ndebug = 1\n";
    memset(&cfg, 0, sizeof(cfg));
    CHECK(
        tsra_pkcs11_config_parse(&cfg, nul, sizeof(nul) - 1) == CKR_GENERAL_ERROR,
        "a NUL byte -> CKR_GENERAL_ERROR"
    );
    CHECK(
        tsra_pkcs11_config_parse(&cfg, NULL, 1) == CKR_ARGUMENTS_BAD,
        "NULL text with a length -> CKR_ARGUMENTS_BAD"
    );
    CHECK(
        tsra_pkcs11_config_parse(NULL, "", 0) == CKR_ARGUMENTS_BAD,
        "NULL config -> CKR_ARGUMENTS_BAD"
    );
}

/* Write `text` to `path`. */
static bool write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    bool ok = (f != NULL) && (fputs(text, f) >= 0);
    return (f != NULL) && (fclose(f) == 0) && ok;
}

static void test_load(const char *root)
{
    printf("== TSRA_PKCS11_CONF ==\n");
    tsra_pkcs11_config cfg;
    char conf[TSRA_PKCS11_PATH_LEN];
    char env[TSRA_PKCS11_PATH_LEN + 8];
    snprintf(conf, sizeof(conf), "%s/pkcs11.conf", root);

    snprintf(env, sizeof(env), "%s/missing.conf", root);
    setenv(TSRA_PKCS11_ENV_CONF, env, 1);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR) &&
            (strstr(cfg.error, TSRA_PKCS11_ENV_CONF) != NULL),
        "a missing file -> CKR_GENERAL_ERROR"
    );
    setenv(TSRA_PKCS11_ENV_CONF, root, 1);
    CHECK(tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR, "a directory -> CKR_GENERAL_ERROR");
    setenv(TSRA_PKCS11_ENV_CONF, "", 1);
    CHECK(tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR, "an empty name -> CKR_GENERAL_ERROR");
    snprintf(env, sizeof(env), "%s/../pkcs11.conf", root);
    setenv(TSRA_PKCS11_ENV_CONF, env, 1);
    CHECK(
        tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR,
        "'..' in the name -> CKR_GENERAL_ERROR"
    );

    CHECK(
        write_text(conf, "persist = 1\nstore_dir = /srv/file\nobk_path = /srv/obk.bin\n"),
        "write a file"
    );
    snprintf(env, sizeof(env), "file:%s", conf);
    setenv(TSRA_PKCS11_ENV_CONF, env, 1);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_OK) && cfg.store_persist &&
            (strcmp(cfg.store_dir, "/srv/file") == 0) &&
            (strcmp(cfg.obk_path, "/srv/obk.bin") == 0),
        "the file is applied (file: prefix stripped)"
    );
    char cwd[PATH_MAX];
    CHECK((getcwd(cwd, sizeof(cwd)) != NULL) && (chdir(root) == 0), "enter the file's directory");
    setenv(TSRA_PKCS11_ENV_CONF, "pkcs11.conf", 1);
    CHECK(
        tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR,
        "a relative name -> CKR_GENERAL_ERROR, though it names the file"
    );
    CHECK(chdir(cwd) == 0, "leave it again");
    setenv(TSRA_PKCS11_ENV_CONF, env, 1);
    setenv(TSRA_PKCS11_ENV_STORE_DIR, "/srv/env", 1);
    setenv(TSRA_PKCS11_ENV_PERSIST, "0", 1);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_OK) && !cfg.store_persist &&
            (strcmp(cfg.store_dir, "/srv/env") == 0) && (strcmp(cfg.obk_path, "/srv/obk.bin") == 0),
        "the environment wins over the file, key by key"
    );
    setenv(TSRA_PKCS11_ENV_STORE_DIR, "/srv/../env", 1);
    CHECK(
        tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR,
        "a bad variable fails closed over a good file"
    );
    unsetenv(TSRA_PKCS11_ENV_STORE_DIR);
    unsetenv(TSRA_PKCS11_ENV_PERSIST);

    CHECK(write_text(conf, "debug = 1\nunknown = 1\n"), "write a bad file");
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR) && cfg.debug &&
            (strstr(cfg.error, "line 2") != NULL),
        "a refused file is traced when it asked for it before the bad line"
    );
    setenv(TSRA_PKCS11_ENV_DEBUG, "1", 1);
    CHECK(write_text(conf, "unknown = 1\n"), "write another bad file");
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_GENERAL_ERROR) && cfg.debug,
        "a refused file is traced when TSRA_PKCS11_DEBUG asks for it"
    );
    unsetenv(TSRA_PKCS11_ENV_DEBUG);

    /* The sample sits next to the README, one directory above this source;
     * realpath drops the "..", which the module refuses. */
    char sample[TSRA_PKCS11_PATH_LEN];
    char real[PATH_MAX];
    const char *slash = strrchr(__FILE__, '/');
    snprintf(
        sample,
        sizeof(sample),
        "%.*s/../tsra_pkcs11.conf.sample",
        (slash != NULL) ? (int)(slash - __FILE__) : 1,
        (slash != NULL) ? __FILE__ : "."
    );
    CHECK(realpath(sample, real) != NULL, "the sample file exists");
    setenv(TSRA_PKCS11_ENV_CONF, real, 1);
    CHECK(
        (tsra_pkcs11_config_load(&cfg) == CKR_OK) && cfg.store_persist && !cfg.debug &&
            (strcmp(cfg.store_dir, TSRA_PKCS11_DEFAULT_STORE_DIR) == 0) &&
            (strcmp(cfg.obk_path, "/var/lib/tsra/obk.bin") == 0),
        "the sample file loads with the values it documents"
    );
    unsetenv(TSRA_PKCS11_ENV_CONF);
    unlink(conf);
    tsra_pkcs11_config_clear(&cfg);
}

int main(void)
{
    char root[] = "/tmp/tsra_pkcs11_config_file_test.XXXXXX";
    if (mkdtemp(root) == NULL)
    {
        perror("mkdtemp");
        return 1;
    }
    static const char *const vars[] = {
        TSRA_PKCS11_ENV_CONF,  TSRA_PKCS11_ENV_STORE_DIR, TSRA_PKCS11_ENV_PERSIST,
        TSRA_PKCS11_ENV_DEBUG, TSRA_PKCS11_ENV_OBK_PATH,  TSRA_PKCS11_ENV_ID,
        TSRA_PKCS11_ENV_PIN,
    };
    for (size_t i = 0; i < sizeof(vars) / sizeof(vars[0]); i++)
    {
        unsetenv(vars[i]);
    }
    setenv(TSRA_PKCS11_ENV_ID, "000102030405060708090a0b0c0d0e0f", 1);
    test_accepted();
    test_refused();
    test_load(root);
    rmdir(root);
    printf(
        g_fail ? "\nconfig_file_test: FAILED (%d checks)\n"
               : "\nconfig_file_test: all %d checks passed\n",
        g_checks
    );
    return g_fail;
}
