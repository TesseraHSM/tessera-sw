// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <stdint.h>
#include <tsra.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Load file contents into an tsra_buffer.
 *
 * Returns TSRA_STATUS_SUCCESS with buffer->ptr == NULL when the file does not
 * exist (ENOENT) — absence is treated as "not yet created", not an error.
 * Returns TSRA_STATUS_SUCCESS with buffer->ptr != NULL on success.
 * Returns TSRA_STATUS_INTERNAL_ERROR on all other failures and sets the
 * OpenSSL error stack with a descriptive message.
 *
 * On success with a non-empty file, the caller must
 * OPENSSL_cleanse(buffer->ptr, buffer->len) + OPENSSL_free(buffer->ptr).
 */
tsra_status tsra_file_load(const char *path, struct tsra_buffer *buffer);

/*
 * Write data to a file with owner-only (0600) permissions.
 *
 * Rejects non-regular files. Permissions are enforced on the open file
 * descriptor, so pre-existing broader permissions are tightened. Symbolic
 * links are not followed. The file is removed on any write failure. The
 * OpenSSL error stack is populated with a descriptive message on failure.
 *
 * Returns TSRA_STATUS_SUCCESS on success, TSRA_STATUS_INTERNAL_ERROR on error.
 */
tsra_status tsra_file_write(const char *path, const uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif
