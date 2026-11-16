// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/*
 * Public constants of the tsra OpenSSL 1.1.x engine.
 */

/*
 * EVP_CIPHER_CTX_ctrl() type: attach an HSM AES key to an AES-CBC,
 * AES-256-GCM or AES-256-XTS context of the engine's ciphers. ptr is a
 * NUL-terminated "tsra://<masked-key-file>;type=<t>[;bits=<n>]" URI, type aes
 * for AES-CBC, aes-gcm for AES-256-GCM or aes-xts for AES-256-XTS, and arg
 * must be 0. The key size must match the cipher (e.g. 256 bits for
 * NID_aes_256_cbc, 512 for NID_aes_256_xts).
 *
 * Pass the engine to the first init, attach the key, then set the IV:
 *
 *   EVP_EncryptInit_ex(ctx, ENGINE_get_cipher(e, NID_aes_256_cbc), e, NULL, NULL);
 *   EVP_CIPHER_CTX_ctrl(ctx, TSRA_CTRL_SET_KEY_URI, 0,
 *                       (void *)"tsra:///keys/aes256.bin;type=aes");
 *   EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
 *   EVP_EncryptUpdate(ctx, ...);
 *   EVP_EncryptFinal_ex(ctx, ...);
 *
 * The last key set wins: the key stays attached across inits that keep the
 * cipher (e.g. a new IV for the next message) until a raw-key init or another
 * TSRA_CTRL_SET_KEY_URI replaces it. The HSM-side key is released when it
 * is replaced or the context is cleaned up; the masked key file is not
 * modified.
 *
 * AES-GCM with an HSM key runs in one shot: a 12-byte IV, AAD updates first,
 * the data in one update that writes all output, and for decryption the whole
 * 16-byte tag, set after the IV and before the data. Each message needs a new
 * IV and holds at most 16 KiB: the AAD padded to 32 bytes, plus the data. The
 * TLS and IV-generation controls are not supported.
 *
 *   EVP_DecryptInit_ex(ctx, ENGINE_get_cipher(e, NID_aes_256_gcm), e, NULL, NULL);
 *   EVP_CIPHER_CTX_ctrl(ctx, TSRA_CTRL_SET_KEY_URI, 0,
 *                       (void *)"tsra:///keys/gcm.bin;type=aes-gcm");
 *   EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, iv);
 *   EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag);
 *   EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);
 *   EVP_DecryptUpdate(ctx, out, &len, ciphertext, ciphertext_len);
 *   EVP_DecryptFinal_ex(ctx, out + len, &len);
 *
 * AES-XTS with an HSM key takes one data unit per update: whole 16-byte
 * blocks (no ciphertext stealing), 16 to 8192 bytes, under the 16-byte IV as
 * its tweak. The IV stays as set, so set a new one for each data unit; the
 * final writes nothing. The all-ones IV is refused.
 *
 *   EVP_EncryptInit_ex(ctx, ENGINE_get_cipher(e, NID_aes_256_xts), e, NULL, NULL);
 *   EVP_CIPHER_CTX_ctrl(ctx, TSRA_CTRL_SET_KEY_URI, 0,
 *                       (void *)"tsra:///keys/xts.bin;type=aes-xts");
 *   EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, tweak);
 *   EVP_EncryptUpdate(ctx, out, &len, sector, 4096);
 *   EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, next_tweak);
 *   EVP_EncryptUpdate(ctx, out + 4096, &len, next_sector, 4096);
 */
#define TSRA_CTRL_SET_KEY_URI 0x415A0001

/*
 * ENGINE_ctrl_cmd_string() command: generate an AES key in the HSM and write
 * its masked key file, replacing any file there. The argument is
 * "tsra://<masked-key-file>;type=<t>[;bits=<n>]" with type aes (128, 192 or
 * 256 bits; default 256), aes-gcm (256) or aes-xts (512). An aes key attaches
 * to the AES-CBC cipher of its size, an aes-gcm key to AES-256-GCM and an
 * aes-xts key to AES-256-XTS, with TSRA_CTRL_SET_KEY_URI.
 *
 *   ENGINE_ctrl_cmd_string(e, TSRA_CMD_GENERATE_KEY,
 *                          "tsra:///keys/aes256.bin;type=aes", 0);
 *
 * From the command line:
 *
 *   openssl engine -t -post 'GENERATE_KEY:tsra:///keys/aes256.bin;type=aes' <engine>
 */
#define TSRA_CMD_GENERATE_KEY "GENERATE_KEY"
