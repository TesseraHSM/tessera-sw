// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cstdint>
#include <string>
#include <tsra_api.h>
#include <vector>

#include "handle/test_creds.hpp"

/// Result of dynamic POTA endorsement generation.
/// Contains a raw r||s signature (96 bytes for P-384) and a DER-encoded
/// SubjectPublicKeyInfo public key.
struct PotaEndorsement
{
    std::vector<uint8_t> signature;
    std::vector<uint8_t> public_key_der;
};

/// Signs a PID public key with the hardcoded POTA private key.
///
/// This is the core signing logic shared by generate_pota_endorsement()
/// and the resiliency POTA callback. It takes a raw DER-encoded PID public
/// key (SubjectPublicKeyInfo), extracts the uncompressed point, hashes it
/// with SHA-384, signs with ECDSA P-384, and returns the raw r||s
/// signature + the hardcoded POTA public key DER.
///
/// @param pid_pub_key_der  DER-encoded PID public key (SubjectPublicKeyInfo).
/// @param pid_pub_key_der_len  Length of the DER buffer.
/// @return PotaEndorsement containing signature and public key DER.
/// @throws std::runtime_error on failure.
PotaEndorsement sign_pota_endorsement(const uint8_t *pid_pub_key_der, size_t pid_pub_key_der_len);

/// Generates a POTA endorsement dynamically.
///
/// On Windows this uses BCrypt/SymCrypt; on Linux it uses OpenSSL.
///
/// 1. Queries the PID public key from the partition via tsra_part_get_prop
/// 2. Parses the DER SubjectPublicKeyInfo to extract uncompressed point
/// 3. Loads the hardcoded ECC P-384 private key
/// 4. Hashes the uncompressed point with SHA-384
/// 5. Signs the hash with ECDSA P-384
/// 6. Returns the hardcoded public key DER
///
/// @param part_handle The partition handle (must be opened, before init)
/// @return PotaEndorsement containing signature and public key DER
/// @throws std::runtime_error on failure
PotaEndorsement generate_pota_endorsement(tsra_handle part_handle);

/// Holds all the OBK + POTA configuration needed for tsra_part_init.
/// All internal buffers and pointers remain valid for the lifetime of this object.
struct PartInitConfig
{
    PotaEndorsement generated;
    tsra_buffer sig_buf;
    tsra_buffer pubkey_buf;
    tsra_pota_endorsement_data pota_data;
    tsra_pota_endorsement pota_endorsement;
    tsra_buffer obk_buf;
    tsra_owner_backup_key_config backup_config;
    std::vector<uint8_t> mobk_cache; // holds cached MOBK data for lifetime management
};

/// Builds the OBK backup config and POTA endorsement for partition init.
///
/// When TSRA_USE_TPM is set, both are configured with TPM sources.
/// Otherwise, the hardcoded TEST_OBK is used for the backup key and
/// a POTA endorsement is dynamically generated from the partition's
/// PID public key using the hardcoded signing key.
///
/// @param part_handle The partition handle (must be opened, before init)
/// @param config Output config whose backup_config and pota_endorsement fields
///               can be passed directly to tsra_part_init. Must be
///               zero-initialized by the caller.
void make_part_init_config(tsra_handle part_handle, PartInitConfig &config);

/// Returns the MOBK file path for cross-process caching.
/// Uses TSRA_MOBK_PATH from the environment if set, otherwise
/// defaults to "mobk.bin" in the system temporary directory.
std::string get_mobk_path();

/// Load a cached MOBK from the on-disk file, if it exists.
std::vector<uint8_t> load_mobk_file(const std::string &path);

/// Persist the MOBK to disk so it survives process restarts.
void save_mobk_file(const std::string &path, const std::vector<uint8_t> &mobk);

/// Queries the MOBK partition property and returns it as a byte vector.
/// Returns an empty vector if the property is not available.
std::vector<uint8_t> query_mobk_property(tsra_handle part_handle);

/// Performs tsra_part_init with OBK-first / MOBK-fallback strategy.
///
/// 1. Tries init with the raw OBK (cold-device path).
/// 2. On BK3_ALREADY_INITIALIZED (warm device), loads the cached MOBK
///    from file and retries with the MOBK.
/// 3. On success, persists the MOBK to file for subsequent runs.
///
/// @param part_handle   Opened partition handle
/// @param creds         Partition credentials
/// @param init_config   OBK + POTA config (from make_part_init_config)
/// @param resiliency_config Optional resiliency config (nullptr if not used)
/// @return tsra_status from the final tsra_part_init call
tsra_status part_init_with_mobk_fallback(
    tsra_handle part_handle,
    tsra_credentials *creds,
    PartInitConfig &init_config,
    tsra_resiliency_config *resiliency_config
);
