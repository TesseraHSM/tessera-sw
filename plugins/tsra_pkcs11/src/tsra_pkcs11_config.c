// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "tsra_pkcs11_config.h"
#include "tsra_pkcs11_store_io.h"
#include "tsra_pkcs11_wipe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Staging bound for hex_decode: the longest credential. */
#define P11_HEX_DECODE_MAX P11_CREDS_ID_LEN

/* The settings of the configuration file, each with the environment variable
 * that wins over it. */
static const struct
{
    const char *key;
    const char *env;
    size_t offset; /* of the field in tsra_pkcs11_config */
    bool is_path;  /* a char[TSRA_PKCS11_PATH_LEN] path, else a bool */
} settings[] = {
    { "store_dir", TSRA_PKCS11_ENV_STORE_DIR, offsetof(tsra_pkcs11_config, store_dir), true },
    { "persist", TSRA_PKCS11_ENV_PERSIST, offsetof(tsra_pkcs11_config, store_persist), false },
    { "debug", TSRA_PKCS11_ENV_DEBUG, offsetof(tsra_pkcs11_config, debug), false },
    { "obk_path", TSRA_PKCS11_ENV_OBK_PATH, offsetof(tsra_pkcs11_config, obk_path), true },
};
#define P11_SETTING_COUNT (sizeof(settings) / sizeof(settings[0]))

/* Decode exactly `bytes` bytes from a 2*bytes hex string. Returns 0 on success,
 * -1 if the string is the wrong length or contains a non-hex character. `out` is
 * written only on full success (via a local staging buffer). */
static int hex_decode(const char *hex, CK_BYTE *out, size_t bytes)
{
    CK_BYTE tmp[P11_HEX_DECODE_MAX];
    int rc = -1;
    /* strnlen bounds the scan to the expected length, so a string missing its
     * terminator within bytes * 2 + 1 chars is rejected rather than run past. */
    if (hex == NULL || out == NULL || bytes > sizeof(tmp) ||
        strnlen(hex, bytes * 2 + 1) != bytes * 2)
    {
        return -1;
    }
    for (size_t i = 0; i < bytes; i++)
    {
        char ch = hex[i * 2];
        char cl = hex[i * 2 + 1];
        int hi = (ch >= '0' && ch <= '9')   ? ch - '0'
                 : (ch >= 'a' && ch <= 'f') ? ch - 'a' + 10
                 : (ch >= 'A' && ch <= 'F') ? ch - 'A' + 10
                                            : -1;
        int lo = (cl >= '0' && cl <= '9')   ? cl - '0'
                 : (cl >= 'a' && cl <= 'f') ? cl - 'a' + 10
                 : (cl >= 'A' && cl <= 'F') ? cl - 'A' + 10
                                            : -1;
        if (hi < 0 || lo < 0)
        {
            goto cleanup;
        }
        tmp[i] = (CK_BYTE)((hi << 4) | lo);
    }
    memcpy(out, tmp, bytes);
    rc = 0;

cleanup:
    tsra_pkcs11_wipe(tmp, sizeof(tmp)); /* it staged credential bytes */
    return rc;
}

/* Return `path` advanced past a leading "file:" scheme, mirroring the provider's
 * handling of path values; returns the original pointer when the prefix is
 * absent (NULL passes through unchanged). */
static const char *strip_file_prefix(const char *path)
{
    static const char FILE_PREFIX[] = "file:";
    if ((path != NULL) && (strncmp(path, FILE_PREFIX, sizeof(FILE_PREFIX) - 1) == 0))
    {
        return path + (sizeof(FILE_PREFIX) - 1);
    }
    return path;
}

/* Require an absolute path without any ".." component, so a configured path
 * cannot depend on the working directory or point outside its intended
 * location. The ".." rule is the one the provider applies to its key material
 * paths and its resiliency storage dir. */
static bool path_is_safe(const char *path)
{
    return (path != NULL) && (path[0] == '/') && (strstr(path, "..") == NULL);
}

/* Booleans are 1, 0, true or false in any case; anything else is refused, so a
 * typo cannot quietly select the memory store. */
static bool parse_bool(const char *value, bool *out)
{
    if (value == NULL)
    {
        return false;
    }
    if ((strcmp(value, "1") == 0) || (strcasecmp(value, "true") == 0))
    {
        *out = true;
        return true;
    }
    if ((strcmp(value, "0") == 0) || (strcasecmp(value, "false") == 0))
    {
        *out = false;
        return true;
    }
    return false;
}

/* Set setting `s` of `cfg` from `value`. Returns NULL, or why the value is
 * refused (the field is then unchanged). */
static const char *setting_set(tsra_pkcs11_config *cfg, size_t s, const char *value)
{
    void *field = (char *)cfg + settings[s].offset;
    if (!settings[s].is_path)
    {
        return parse_bool(value, (bool *)field) ? NULL : "not 1, 0, true or false";
    }
    const char *path = strip_file_prefix(value);
    if (!path_is_safe(path) || (strnlen(path, TSRA_PKCS11_PATH_LEN) == TSRA_PKCS11_PATH_LEN))
    {
        /* A truncated path would name another file. */
        return "not absolute, contains \"..\" or too long";
    }
    memcpy(field, path, strlen(path) + 1);
    return NULL;
}

/* The index of the setting named by key[0..n), or P11_SETTING_COUNT. */
static size_t setting_find(const char *key, size_t n)
{
    size_t s = 0;
    while ((s < P11_SETTING_COUNT) &&
           ((strlen(settings[s].key) != n) || (memcmp(settings[s].key, key, n) != 0)))
    {
        s++;
    }
    return s;
}

/* Narrow [*a, *b) past leading and trailing blanks; a CR counts, for files
 * with CRLF line ends. */
static void trim(const char **a, const char **b)
{
    while ((*a < *b) && ((**a == ' ') || (**a == '\t') || (**a == '\r')))
    {
        (*a)++;
    }
    while ((*b > *a) && (((*b)[-1] == ' ') || ((*b)[-1] == '\t') || ((*b)[-1] == '\r')))
    {
        (*b)--;
    }
}

CK_RV tsra_pkcs11_config_parse(tsra_pkcs11_config *cfg, const char *text, size_t len)
{
    if ((cfg == NULL) || ((text == NULL) && (len > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (len == 0)
    {
        return CKR_OK;
    }
    /* A NUL would silently end a value early. */
    if (memchr(text, '\0', len) != NULL)
    {
        snprintf(cfg->error, sizeof(cfg->error), "the file contains a NUL byte");
        return CKR_GENERAL_ERROR;
    }
    const char *end = text + len;
    size_t line = 0;
    for (const char *p = text; p < end; line++)
    {
        const char *eol = (const char *)memchr(p, '\n', (size_t)(end - p));
        const char *a = p;
        const char *b = (eol != NULL) ? eol : end;
        p = (eol != NULL) ? eol + 1 : end;
        trim(&a, &b);
        if ((a == b) || (*a == '#'))
        {
            continue;
        }
        const char *eq = (const char *)memchr(a, '=', (size_t)(b - a));
        if (eq == NULL)
        {
            snprintf(cfg->error, sizeof(cfg->error), "line %zu: not \"key = value\"", line + 1);
            return CKR_GENERAL_ERROR;
        }
        const char *ka = a;
        const char *kb = eq;
        const char *va = eq + 1;
        const char *vb = b;
        trim(&ka, &kb);
        trim(&va, &vb);
        /* An unknown key is refused rather than skipped: a misspelt key would
         * leave its default in force, and credentials are no keys at all. */
        size_t s = setting_find(ka, (size_t)(kb - ka));
        if (s == P11_SETTING_COUNT)
        {
            snprintf(cfg->error, sizeof(cfg->error), "line %zu: unknown key", line + 1);
            return CKR_GENERAL_ERROR;
        }
        char value[TSRA_PKCS11_PATH_LEN];
        size_t n = (size_t)(vb - va);
        const char *why = "too long";
        if (n < sizeof(value))
        {
            memcpy(value, va, n);
            value[n] = '\0';
            why = setting_set(cfg, s, value);
        }
        if (why != NULL)
        {
            snprintf(
                cfg->error,
                sizeof(cfg->error),
                "line %zu: %s: %s",
                line + 1,
                settings[s].key,
                why
            );
            return CKR_GENERAL_ERROR;
        }
    }
    return CKR_OK;
}

/* Read the whole regular file `path` through the store's hardened reader (no
 * symbolic link, no FIFO, bounded size). *out is NULL for a missing file. */
static CK_RV read_file(const char *path, unsigned char **out, size_t *len)
{
    if (path == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    char dir[TSRA_PKCS11_PATH_LEN] = ".";
    const char *name = path;
    const char *slash = strrchr(path, '/');
    if (slash != NULL)
    {
        size_t n = (size_t)(slash - path);
        if (n >= sizeof(dir))
        {
            return CKR_ARGUMENTS_BAD;
        }
        memcpy(dir, path, n);
        dir[n] = '\0'; /* "" for a file in the root: the join puts the '/' back */
        name = slash + 1;
    }
    return tsra_pkcs11_store_read(dir, name, out, len);
}

/* Apply the file TSRA_PKCS11_CONF names, when it is set. */
static CK_RV load_file(tsra_pkcs11_config *cfg)
{
    const char *env = getenv(TSRA_PKCS11_ENV_CONF);
    if (env == NULL)
    {
        return CKR_OK;
    }
    const char *path = strip_file_prefix(env);
    unsigned char *text = NULL;
    size_t len = 0;
    CK_RV rv = CKR_GENERAL_ERROR;
    if (path_is_safe(path) && (strnlen(path, TSRA_PKCS11_PATH_LEN) < TSRA_PKCS11_PATH_LEN) &&
        (read_file(path, &text, &len) == CKR_OK) && (text != NULL))
    {
        rv = tsra_pkcs11_config_parse(cfg, (const char *)text, len);
    }
    else
    {
        snprintf(
            cfg->error,
            sizeof(cfg->error),
            "%s: not absolute, missing, empty or not a regular file",
            TSRA_PKCS11_ENV_CONF
        );
    }
    free(text);
    return rv;
}

/* Decode the credential in environment variable `env` (2 * `n` hex characters)
 * into `out` and set *is_set. Unset leaves both alone. */
static CK_RV load_credential(
    tsra_pkcs11_config *cfg,
    const char *env,
    CK_BYTE *out,
    size_t n,
    bool *is_set
)
{
    const char *hex = getenv(env);
    if (hex == NULL)
    {
        return CKR_OK;
    }
    if (hex_decode(hex, out, n) != 0)
    {
        snprintf(cfg->error, sizeof(cfg->error), "%s: not %zu hex characters", env, n * 2);
        return CKR_GENERAL_ERROR;
    }
    *is_set = true;
    return CKR_OK;
}

CK_RV tsra_pkcs11_config_load(tsra_pkcs11_config *cfg)
{
    if (cfg == NULL)
    {
        return CKR_ARGUMENTS_BAD;
    }
    memset(cfg, 0, sizeof(*cfg));
#ifdef TSRA_FEATURE_EMULATOR
    /* The emulator accepts any non-zero partition ID. */
    memset(cfg->id, 0x01, sizeof(cfg->id));
    cfg->id_set = true;
#endif
    memcpy(cfg->store_dir, TSRA_PKCS11_DEFAULT_STORE_DIR, sizeof(TSRA_PKCS11_DEFAULT_STORE_DIR));
    /* Taken once ahead of the file as well, so a refused file can be traced. */
    const char *debug = getenv(TSRA_PKCS11_ENV_DEBUG);
    if (debug != NULL)
    {
        (void)parse_bool(debug, &cfg->debug);
    }

    CK_RV rv = load_file(cfg);
    for (size_t s = 0; (rv == CKR_OK) && (s < P11_SETTING_COUNT); s++)
    {
        const char *value = getenv(settings[s].env);
        const char *why = (value != NULL) ? setting_set(cfg, s, value) : NULL;
        if (why != NULL)
        {
            snprintf(cfg->error, sizeof(cfg->error), "%s: %s", settings[s].env, why);
            rv = CKR_GENERAL_ERROR;
        }
    }
    if (rv == CKR_OK)
    {
        rv = load_credential(cfg, TSRA_PKCS11_ENV_ID, cfg->id, sizeof(cfg->id), &cfg->id_set);
    }
    if (rv == CKR_OK)
    {
        rv = load_credential(
            cfg,
            TSRA_PKCS11_ENV_PIN,
            cfg->default_pin,
            sizeof(cfg->default_pin),
            &cfg->default_pin_set
        );
    }
#if defined(TSRA_WITH_HSM) && !defined(TSRA_FEATURE_EMULATOR)
    if ((rv == CKR_OK) && !cfg->id_set)
    {
        snprintf(
            cfg->error,
            sizeof(cfg->error),
            "%s: a hardware build needs it",
            TSRA_PKCS11_ENV_ID
        );
        rv = CKR_GENERAL_ERROR;
    }
    /* Named, not read: C_Login reads the file, so the key never stays in
     * memory for the life of the process. */
    if ((rv == CKR_OK) && (cfg->obk_path[0] == '\0'))
    {
        snprintf(
            cfg->error,
            sizeof(cfg->error),
            "%s or obk_path: a hardware build needs it",
            TSRA_PKCS11_ENV_OBK_PATH
        );
        rv = CKR_GENERAL_ERROR;
    }
#endif
    return rv;
}

CK_RV tsra_pkcs11_pin_normalise(
    const CK_UTF8CHAR *pin,
    CK_ULONG pin_len,
    CK_BYTE out[P11_CREDS_PIN_LEN]
)
{
    if ((out == NULL) || ((pin == NULL) && (pin_len > 0)))
    {
        return CKR_ARGUMENTS_BAD;
    }
    if ((pin_len < TSRA_PKCS11_MIN_PIN_LEN) || (pin_len > TSRA_PKCS11_MAX_PIN_LEN))
    {
        return CKR_PIN_LEN_RANGE;
    }
    if (memchr(pin, '\0', pin_len) != NULL)
    {
        return CKR_PIN_INVALID;
    }
    memset(out, 0, P11_CREDS_PIN_LEN);
    memcpy(out, pin, pin_len);
    return CKR_OK;
}

CK_RV tsra_pkcs11_config_obk(const tsra_pkcs11_config *cfg, CK_BYTE obk[P11_OBK_LEN])
{
    if ((cfg == NULL) || (obk == NULL))
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (cfg->obk_path[0] == '\0')
    {
#ifdef TSRA_FEATURE_EMULATOR
        memset(obk, 0xA5, P11_OBK_LEN); /* the emulator takes any 48 bytes */
        return CKR_OK;
#else
        return CKR_FUNCTION_FAILED;
#endif
    }
    unsigned char *buf = NULL;
    size_t len = 0;
    CK_RV rv = CKR_FUNCTION_FAILED;
    if ((read_file(cfg->obk_path, &buf, &len) == CKR_OK) && (len == P11_OBK_LEN))
    {
        memcpy(obk, buf, P11_OBK_LEN);
        rv = CKR_OK;
    }
    tsra_pkcs11_wipe(buf, len);
    free(buf);
    return rv;
}

void tsra_pkcs11_config_clear(tsra_pkcs11_config *cfg)
{
    tsra_pkcs11_wipe(cfg, sizeof(*cfg)); /* NULL-safe */
}
