// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stdint.h>

#include <openssl/params.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Custom OpenSSL Parameters (keymgmt)
 * */

#define TSRA_OSSL_PKEY_PARAM_KEY_USAGE "tsra.key_usage"
#define TSRA_OSSL_PKEY_PARAM_MASKED_KEY "tsra.masked_key"
#define TSRA_OSSL_PKEY_PARAM_SESSION "tsra.session"
#define TSRA_OSSL_PKEY_PARAM_INPUT_KEY "tsra.input_key"
#define TSRA_OSSL_PKEY_PARAM_WRAPPED_KEY "tsra.wrapped_key"

/*
 * Key kind selector.
 * SKEYMGMT (AES): "AES" (default), "AES-GCM", or "AES-XTS".
 * KEYMGMT (RSA import): "RSA" or "RSA-CRT" (default).
 */
#define TSRA_OSSL_PKEY_PARAM_KEY_KIND "tsra.key_kind"

/* Key usage types - single usage for the entire key pair */
typedef enum
{
    KEY_USAGE_DIGITAL_SIGNATURE = 0, /* Private: sign, Public: verify */
    KEY_USAGE_KEY_AGREEMENT = 1,     /* Both: derive */
    KEY_USAGE_KEY_ENCIPHERMENT = 2,  /* Private: decrypt, Public: encrypt */
    KEY_USAGE_KEY_WRAPPING = 3,      /* Private: unwrap, Public: wrap */
} TSRA_KEY_USAGE_TYPE;

/*
 * Parse a key usage string and return the corresponding type
 * @value   string containing key usage ("digitalSignature", "keyAgreement",
 *          "keyEncipherment", or "keyWrapping")
 * @usage_type output parameter for the key usage type
 *
 * @returns 0 on success, -1 on failure
 * */
int tsra_ossl_key_usage_from_str(const char *value, TSRA_KEY_USAGE_TYPE *usage_type);

/*
 * Convert key usage type to string representation
 * @usage_type the key usage type to convert
 * @returns string representation ("digitalSignature", "keyAgreement", "keyEncipherment",
 * or "keyWrapping"), or "unknown"
 * */
const char *tsra_ossl_key_usage_to_str(TSRA_KEY_USAGE_TYPE usage_type);

/*
 * parse a session parameter string and return a boolean value
 * @value   string containing session preference ("true", "false", "1", "0", "yes", "no")
 *
 * @returns 1 for session key, 0 for persistent key, -1 on failure
 * */
int tsra_ossl_session_from_str(const char *value);

/*
 * validate a masked key file path parameter
 * @filepath   string containing the file path where masked key should be written
 *
 * @returns 0 on success (valid path), -1 on failure (invalid path)
 * */
int tsra_ossl_masked_key_filepath_validate(const char *filepath);

/*
 * validate an input key file path parameter
 * @filepath   string containing the file path of the key to import
 *
 * @returns 0 on success (valid path), -1 on failure (invalid path)
 * */
int tsra_ossl_input_key_filepath_validate(const char *filepath);

/*
 * Get private key property ID for a given key usage type
 * @usage_type the key usage type
 * @returns the private key property ID (SIGN, DERIVE, or DECRYPT)
 * */
uint32_t tsra_ossl_get_priv_key_property(TSRA_KEY_USAGE_TYPE usage_type);

/*
 * Get public key property ID for a given key usage type
 * @usage_type the key usage type
 * @returns the public key property ID (VERIFY, DERIVE, or ENCRYPT)
 * */
uint32_t tsra_ossl_get_pub_key_property(TSRA_KEY_USAGE_TYPE usage_type);

/*
 * Read a UTF-8 string parameter into a fixed-size buffer.
 *
 * OSSL_PARAM_UTF8_STRING data carries an explicit length and is not required
 * to be NUL-terminated, so a value must be copied out before it can be used
 * as a C string.  The copy is always NUL-terminated; out is left untouched
 * when the parameter is absent.
 *
 * @params    parameter array to search
 * @key       parameter name
 * @out       destination buffer, written only when the parameter is present
 * @out_size  size of out in bytes
 *
 * @returns 1 when present and copied, 0 when absent, -1 when present but not
 * a UTF-8 string or too long for out
 * */
int tsra_ossl_get_str_param(const OSSL_PARAM params[], const char *key, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif
