/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 */

#ifndef TSRA_API_H
#define TSRA_API_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/*
 Size of AES-GCM IV in bytes.
 */
#define TSRA_AES_GCM_IV_SIZE 12

/*
 Size of AES-GCM tag in bytes.
 */
#define TSRA_AES_GCM_TAG_SIZE 16

/*
 Length, in bytes, of a partition PSK (Pre-Shared Key). This module is
 shared with the native crate (which does not depend on the wire-types
 crate), so the value is a literal here and pinned to the wire-schema
 `PSK_LEN` by a static assert in the DDI layer.
 */
#define TSRA_PSK_LEN 32

enum tsra_status
#ifdef __cplusplus
    : int32_t
#endif // __cplusplus
{
    TSRA_STATUS_SUCCESS = 0,
    TSRA_STATUS_INVALID_ARGUMENT = -1,
    TSRA_STATUS_INVALID_HANDLE = -2,
    TSRA_STATUS_INDEX_OUT_OF_RANGE = -3,
    TSRA_STATUS_BUFFER_TOO_SMALL = -4,
    TSRA_STATUS_INTERNAL_ERROR = -5,
    TSRA_STATUS_RNG_ERROR = -6,
    TSRA_STATUS_INVALID_KEY_SIZE = -7,
    TSRA_STATUS_DDI_CMD_FAILURE = -8,
    TSRA_STATUS_PROPERTY_NOT_PRESENT = -9,
    TSRA_STATUS_KEY_CLASS_NOT_SPECIFIED = -10,
    TSRA_STATUS_KEY_KIND_NOT_SPECIFIED = -11,
    TSRA_STATUS_INVALID_KEY = -12,
    TSRA_STATUS_UNSUPPORTED_KEY_KIND = -13,
    TSRA_STATUS_UNSUPPORTED_ALGORITHM = -14,
    TSRA_STATUS_INVALID_SIGNATURE = -15,
    TSRA_STATUS_INVALID_KEY_PROPS = -16,
    TSRA_STATUS_UNSUPPORTED_PROPERTY = -17,
    TSRA_STATUS_CERT_CHAIN_CHANGED = -18,
    TSRA_STATUS_INVALID_TWEAK = -19,
    TSRA_STATUS_NOT_FOUND = -20,
    TSRA_STATUS_IO_ABORTED = -21,
    TSRA_STATUS_IO_ABORT_IN_PROGRESS = -22,
    TSRA_STATUS_CREDENTIALS_NOT_ESTABLISHED = -23,
    TSRA_STATUS_NONCE_MISMATCH = -24,
    TSRA_STATUS_PARTITION_NOT_PROVISIONED = -25,
    TSRA_STATUS_MASKED_KEY_DECODE_FAILED = -26,
    TSRA_STATUS_ECC_VERIFY_FAILED = -27,
    TSRA_STATUS_SESSION_NEEDS_RENEGOTIATION = -29,
    TSRA_STATUS_PENDING_KEY_GENERATION = -30,
    TSRA_STATUS_KEY_NOT_FOUND = -31,
    TSRA_STATUS_PARTITION_ALREADY_PROVISIONED = -33,
    TSRA_STATUS_VAULT_APP_LIMIT_REACHED = -34,
    TSRA_STATUS_RETRY_EXHAUSTED = -35,
    TSRA_STATUS_DEVICE_NOT_READY = -36,
    TSRA_STATUS_CANNOT_DELETE_INTERNAL_KEYS = -37,
    TSRA_STATUS_UNSUPPORTED_API_REVISION = -38,
    TSRA_STATUS_DEVICE_NOT_ACCESSIBLE = -39,
    TSRA_STATUS_INVALID_CONTEXT_STATE = -40,
    TSRA_STATUS_BK3_ALREADY_INITIALIZED = -41,
    TSRA_STATUS_INVALID_SESSION = -42,
    TSRA_STATUS_SD_ALREADY_INITIALIZED = -43,
    TSRA_STATUS_SD_PEER_CLONING_NOT_ALLOWED = -44,
    TSRA_STATUS_UNSUPPORTED_KEY_OPERATION = -45,
    TSRA_STATUS_CRYPTO_NOT_INITIALIZED = -46,
    TSRA_STATUS_CRYPTO_BUFFER_TOO_SMALL = -47,
    TSRA_STATUS_CRYPTO_INPUT_TOO_LARGE = -48,
    TSRA_STATUS_CRYPTO_INVALID_ALG = -49,
    TSRA_STATUS_CRYPTO_TIMEOUT = -50,
    TSRA_STATUS_CRYPTO_UNALIGNED_CPTR = -51,
    TSRA_STATUS_CRYPTO_INVALID_ARG = -52,
    TSRA_STATUS_CRYPTO_INVALID_IV_LENGTH = -53,
    TSRA_STATUS_CRYPTO_INVALID_KEY_LENGTH = -54,
    TSRA_STATUS_CRYPTO_INVALID_DATA_LENGTH = -55,
    TSRA_STATUS_CRYPTO_INVALID_CONTEXT_LENGTH = -56,
    TSRA_STATUS_CRYPTO_INVALID_PARTIAL_CONTEXT = -57,
    TSRA_STATUS_CRYPTO_UNSUPPORTED_MODE = -58,
    TSRA_STATUS_CRYPTO_UNALIGNED_BUFFER = -59,
    TSRA_STATUS_CRYPTO_NOT_SUPPORTED = -60,
    TSRA_STATUS_CRYPTO_HARDWARE_ERROR = -61,
    TSRA_STATUS_CRYPTO_CPT_RSA_UC_ERR_MOD_LEN_INVALID = -62,
    TSRA_STATUS_CRYPTO_CPT_RSA_UC_ERR_EXP_LEN_INVALID = -63,
    TSRA_STATUS_CRYPTO_CPT_RSA_UC_ERR_DATA_LEN_INVALID = -64,
    TSRA_STATUS_CRYPTO_CPT_GC_UC_ERR_DATA_LEN_INVALID = -65,
    TSRA_STATUS_CRYPTO_CPT_GC_UC_ERR_CIPHER_UNSUPPORTED = -66,
    TSRA_STATUS_CRYPTO_CPT_GC_UC_ERR_AUTH_UNSUPPORTED = -67,
    TSRA_STATUS_CRYPTO_CPT_GC_UC_ERR_HASH_MODE_UNSUPPORTED = -68,
    TSRA_STATUS_CRYPTO_CPT_GC_UC_ERR_ICV_MISCOMPARE = -69,
    TSRA_STATUS_CRYPTO_CPT_GC_UC_ERR_KEY_LEN_INVALID = -70,
    TSRA_STATUS_CRYPTO_CPT_RSA_UC_ERR_PKCS_DECODING = -71,
    TSRA_STATUS_CRYPTO_CPT_RSA_UC_ERR_PKCS_SIGNATURE_INVALID = -72,
    TSRA_STATUS_CRYPTO_CPT_FAULT = -73,
    TSRA_STATUS_CRYPTO_CPT_SW_ERR = -74,
    TSRA_STATUS_CRYPTO_CPT_HW_ERR = -75,
    TSRA_STATUS_CRYPTO_CPT_INST_ERR = -76,
    TSRA_STATUS_CRYPTO_CPT_SW_WARN = -77,
    /*
     Authentication of a masked key's AES-GCM envelope failed.
     */
    TSRA_STATUS_MASKED_KEY_AUTHENTICATION_FAILED = -78,
    TSRA_STATUS_PANIC = INT32_MIN,
};
#ifndef __cplusplus
typedef int32_t tsra_status;
#endif // __cplusplus

/*
 HSM Algorithm identifier enumeration.

 This enum defines all supported cryptographic algorithms in the HSM.
 The values are organized by algorithm family:
 - 0x0000xxxx: Masking algorithms
 - 0x0001xxxx: RSA algorithms
 - 0x0002xxxx: Elliptic Curve algorithms
 - 0x0003xxxx: AES algorithms
 - 0x0004xxxx: Hash algorithms (SHA family)
 - 0x0005xxxx: HMAC algorithms
 - 0x0006xxxx: Key Derivation Function algorithms

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum tsra_algo_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Masking key generation algorithm.
     */
    TSRA_ALGO_ID_MASKING_KEY_GEN = 1,
    /*
     Masking key wrap algorithm.
     */
    TSRA_ALGO_ID_MASKING_KEYWRAP = 2,
    /*
     RSA Key Unwrap Key Pair Generation.
     */
    TSRA_ALGO_ID_RSA_KEY_UNWRAPPING_KEY_PAIR_GEN = 65537,
    /*
     RSA PKCS#1 v1.5 SHA-1 Sign & Verify.
     */
    TSRA_ALGO_ID_RSA_PKCS_SHA1 = 65539,
    /*
     RSA PKCS#1 v1.5 SHA-256 Sign & Verify.
     */
    TSRA_ALGO_ID_RSA_PKCS_SHA256 = 65540,
    /*
     RSA PKCS#1 v1.5 SHA-384 Sign & Verify.
     */
    TSRA_ALGO_ID_RSA_PKCS_SHA384 = 65541,
    /*
     RSA PKCS#1 v1.5 SHA-512 Sign & Verify.
     */
    TSRA_ALGO_ID_RSA_PKCS_SHA512 = 65542,
    /*
     RSA PKCS#1 PSS Sign & Verify.
     */
    TSRA_ALGO_ID_RSA_PKCS_PSS = 65543,
    /*
     RSA PKCS#1 PSS SHA-1 Sign & Verify.
     */
    TSRA_ALGO_ID_RSA_PKCS_PSS_SHA1 = 65544,
    /*
     RSA PKCS#1 PSS SHA-256 Sign & Verify.
     */
    TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256 = 65545,
    /*
     RSA PKCS#1 PSS SHA-384 Sign & Verify.
     */
    TSRA_ALGO_ID_RSA_PKCS_PSS_SHA384 = 65546,
    /*
     RSA PKCS#1 PSS SHA-512 Sign & Verify.
     */
    TSRA_ALGO_ID_RSA_PKCS_PSS_SHA512 = 65547,
    /*
     RSA PKCS#1 OAEP Encrypt & Decrypt.
     */
    TSRA_ALGO_ID_RSA_PKCS_OAEP = 65548,
    /*
     RSA PKCS#1  Encrypt & Decrypt.
     */
    TSRA_ALGO_ID_RSA_PKCS = 65549,
    /*
     RSA AES Key Wrap & Unwrap.
     */
    TSRA_ALGO_ID_RSA_AES_KEY_WRAP = 65550,
    /*
     RSA AES Wrap.
     */
    TSRA_ALGO_ID_RSA_AES_WRAP = 65551,
    /*
     EC Key Pair Generation.
     */
    TSRA_ALGO_ID_EC_KEY_PAIR_GEN = 131073,
    /*
     ECDSA Sign & Verify.
     */
    TSRA_ALGO_ID_ECDSA = 131074,
    /*
     ECDSA SHA-1 Sign & Verify.
     */
    TSRA_ALGO_ID_ECDSA_SHA1 = 131075,
    /*
     ECDSA SHA-256 Sign & Verify.
     */
    TSRA_ALGO_ID_ECDSA_SHA256 = 131076,
    /*
     ECDSA SHA-384 Sign & Verify.
     */
    TSRA_ALGO_ID_ECDSA_SHA384 = 131077,
    /*
     ECDSA SHA-512 Sign & Verify.
     */
    TSRA_ALGO_ID_ECDSA_SHA512 = 131078,
    /*
     ECDH Derive.
     */
    TSRA_ALGO_ID_ECDH = 131079,
    /*
     AES Key Generation.
     */
    TSRA_ALGO_ID_AES_KEY_GEN = 196609,
    /*
     AES CBC Encrypt & Decrypt.
     */
    TSRA_ALGO_ID_AES_CBC = 196610,
    /*
     AES CBC Pad Encrypt & Decrypt.
     */
    TSRA_ALGO_ID_AES_CBC_PAD = 196611,
    /*
     AES XTS Key Generation.
     */
    TSRA_ALGO_ID_AES_XTS_KEY_GEN = 196612,
    /*
     AES XTS Encrypt & Decrypt.
     */
    TSRA_ALGO_ID_AES_XTS = 196613,
    /*
     AES GCM Key Generation.
     */
    TSRA_ALGO_ID_AES_GCM_KEY_GEN = 196614,
    /*
     AES GCM Encrypt & Decrypt.
     */
    TSRA_ALGO_ID_AES_GCM = 196615,
    /*
     SHA-1 Digest.
     */
    TSRA_ALGO_ID_SHA1 = 262145,
    /*
     SHA-256 Digest.
     */
    TSRA_ALGO_ID_SHA256 = 262146,
    /*
     SHA-384 Digest.
     */
    TSRA_ALGO_ID_SHA384 = 262147,
    /*
     SHA-512 Digest.
     */
    TSRA_ALGO_ID_SHA512 = 262148,
    /*
     HMAC SHA-1 Sign & Verify.
     */
    TSRA_ALGO_ID_HMAC_SHA1 = 327681,
    /*
     HMAC SHA-256 Sign & Verify.
     */
    TSRA_ALGO_ID_HMAC_SHA256 = 327682,
    /*
     HMAC SHA-384 Sign & Verify.
     */
    TSRA_ALGO_ID_HMAC_SHA384 = 327683,
    /*
     HMAC SHA-512 Sign & Verify.
     */
    TSRA_ALGO_ID_HMAC_SHA512 = 327684,
    /*
     HKDF Derive.
     */
    TSRA_ALGO_ID_HKDF_DERIVE = 393217,
    /*
     SP 800-108 KDF Counter Derive.
     */
    TSRA_ALGO_ID_KBKDF_COUNTER_DERIVE = 393218,
    /*
     Security-domain sealing key generation.
     */
    TSRA_ALGO_ID_SD_SEALING_KEY_GEN = 458753,
};
#ifndef __cplusplus
typedef uint32_t tsra_algo_id;
#endif // __cplusplus

/*
 Key property identifier enumeration.

 This enum defines the various properties that can be associated with cryptographic keys
 in the HSM. Each property has a unique identifier that is used to query or set specific
 attributes of a key object.

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum tsra_key_prop_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Key class property (e.g., Private, Public, Secret).
     */
    TSRA_KEY_PROP_ID_CLASS = 1,
    /*
     Key kind property (e.g., RSA, ECC, AES).
     */
    TSRA_KEY_PROP_ID_KIND = 2,
    /*
     Bit length of the key.
     */
    TSRA_KEY_PROP_ID_BIT_LEN = 3,
    /*
     Human-readable label for the key.
     */
    TSRA_KEY_PROP_ID_LABEL = 4,
    /*
     Public key information associated with the key.
     */
    TSRA_KEY_PROP_ID_PUB_KEY_INFO = 5,
    /*
     Elliptic curve identifier for ECC keys.
     */
    TSRA_KEY_PROP_ID_EC_CURVE = 6,
    /*
     Whether the key is masked (protected by hardware).
     */
    TSRA_KEY_PROP_ID_MASKED_KEY = 7,
    /*
     Session handle associated with the key.
     */
    TSRA_KEY_PROP_ID_SESSION = 8,
    /*
     Whether the key was generated locally in the HSM.
     */
    TSRA_KEY_PROP_ID_LOCAL = 9,
    /*
     Whether the key is sensitive (cannot be revealed in plaintext).
     */
    TSRA_KEY_PROP_ID_SENSITIVE = 10,
    /*
     Whether the key can be extracted from the HSM.
     */
    TSRA_KEY_PROP_ID_EXTRACTABLE = 11,
    /*
     Whether the key can be used for encryption operations.
     */
    TSRA_KEY_PROP_ID_ENCRYPT = 12,
    /*
     Whether the key can be used for decryption operations.
     */
    TSRA_KEY_PROP_ID_DECRYPT = 13,
    /*
     Whether the key can be used for signing operations.
     */
    TSRA_KEY_PROP_ID_SIGN = 14,
    /*
     Whether the key can be used for verification operations.
     */
    TSRA_KEY_PROP_ID_VERIFY = 15,
    /*
     Whether the key can be used for key wrapping operations.
     */
    TSRA_KEY_PROP_ID_WRAP = 16,
    /*
     Whether the key can be used for key unwrapping operations.
     */
    TSRA_KEY_PROP_ID_UNWRAP = 17,
    /*
     Whether the key can be used for key derivation operations.
     */
    TSRA_KEY_PROP_ID_DERIVE = 18,
};
#ifndef __cplusplus
typedef uint32_t tsra_key_prop_id;
#endif // __cplusplus

/*
 Cryptographic key algorithm type.

 Specifies the algorithm family for a cryptographic key.
 */
enum tsra_key_kind
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     RSA asymmetric key kind.
     */
    TSRA_KEY_KIND_RSA = 1,
    /*
     Elliptic Curve (EC) asymmetric key kind.
     */
    TSRA_KEY_KIND_ECC = 2,
    /*
     Advanced Encryption Standard (AES) symmetric key kind.
     */
    TSRA_KEY_KIND_AES = 3,
    /*
     AES XTS symmetric key kind.
     */
    TSRA_KEY_KIND_AES_XTS = 4,
    /*
     Shared secret key kind.
     */
    TSRA_KEY_KIND_SHARED_SECRET = 5,
    /*
     HMAC SHA 1 is not supported.
     HMAC SHA 256
     */
    TSRA_KEY_KIND_HMAC_SHA256 = 7,
    /*
     HMAC SHA 384
     */
    TSRA_KEY_KIND_HMAC_SHA384 = 8,
    /*
     HMAC SHA 512
     */
    TSRA_KEY_KIND_HMAC_SHA512 = 9,
    /*
     AES GCM symmetric key kind.
     */
    TSRA_KEY_KIND_AES_GCM = 10,
    /*
     HSM Sealing key kind (used for sealing/unsealing operations).
     */
    TSRA_KEY_KIND_SEALING = 11,
    /*
     RSA CRT
     */
    TSRA_KEY_KIND_RSA_CRT = 12,
};
#ifndef __cplusplus
typedef uint32_t tsra_key_kind;
#endif // __cplusplus

/*
 Owner backup key source.

 Specifies the source of the owner backup key (OBK) during partition initialization.
 */
enum tsra_owner_backup_key_source
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Caller provided backup key.
     */
    TSRA_OWNER_BACKUP_KEY_SOURCE_CALLER = 1,
    /*
     TPM-sealed backup key (retrieved from device and unsealed).
     */
    TSRA_OWNER_BACKUP_KEY_SOURCE_TPM = 2,
};
#ifndef __cplusplus
typedef uint32_t tsra_owner_backup_key_source;
#endif // __cplusplus

/*
 HSM partition owner trust anchor (aka POTA) endorsement source.
 */
enum tsra_pota_endorsement_source
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Caller provided endorsement.
     */
    TSRA_POTA_ENDORSEMENT_SOURCE_CALLER = 1,
    /*
     TPM-generated endorsement.
     */
    TSRA_POTA_ENDORSEMENT_SOURCE_TPM = 2,
};
#ifndef __cplusplus
typedef uint32_t tsra_pota_endorsement_source;
#endif // __cplusplus

/*
 Partition property identifier enumeration.

 This enum defines the various properties that can be queried from an HSM partition.
 Each property has a unique identifier that is used to retrieve specific attributes
 of a partition.

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum tsra_part_prop_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Device type property (Virtual or Physical).
     */
    TSRA_PART_PROP_ID_TYPE = 1,
    /*
     OS device path.
     */
    TSRA_PART_PROP_ID_PATH = 2,
    /*
     Driver version string.
     */
    TSRA_PART_PROP_ID_DRIVER_VERSION = 3,
    /*
     Firmware version string.
     */
    TSRA_PART_PROP_ID_FIRMWARE_VERSION = 4,
    /*
     Hardware version string.
     */
    TSRA_PART_PROP_ID_HARDWARE_VERSION = 5,
    /*
     PCI hardware ID (bus:device:function).
     */
    TSRA_PART_PROP_ID_PCI_HW_ID = 6,
    /*
     Minimum API revision supported by the device.
     */
    TSRA_PART_PROP_ID_MIN_API_REV = 7,
    /*
     Maximum API revision supported by the device.
     */
    TSRA_PART_PROP_ID_MAX_API_REV = 8,
    /*
     Manufacturer certificate chain in PEM format.
     */
    TSRA_PART_PROP_ID_MANUFACTURER_CERT_CHAIN = 9,
    /*
     Backup masking key (BMK).
     */
    TSRA_PART_PROP_ID_BACKUP_MASKING_KEY = 10,
    /*
     Masked owner backup key (MOBK).
     */
    TSRA_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY = 11,
    /*
     Partition identity (PID) public key in DER format.
     */
    TSRA_PART_PROP_ID_PART_PUB_KEY = 12,
    /*
     16-byte partition identity (PID).
     */
    TSRA_PART_PROP_ID_PART_EX_PID = 13,
    /*
     Raw ECC-P384 partition identity public key (`x ‖ y`, 96 bytes).
     */
    TSRA_PART_PROP_ID_PART_EX_PUB_KEY = 14,
};
#ifndef __cplusplus
typedef uint32_t tsra_part_prop_id;
#endif // __cplusplus

/*
 Channel-level integrity profile for a security-domain (TBOR) session,
 selected by the caller when opening a session via `open_session_ex`.

 API-layer mirror of `tsra_ddi_tbor_types::SessionType`; kept as a
 separate `#[open_enum]` so the public API surface does not leak the
 DDI-layer wire type.
 */
enum tsra_session_ex_type
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Channel transports bodies without per-message MAC.
     */
    TSRA_SESSION_EX_TYPE_PLAIN_TEXT = 0,
    /*
     Channel transports bodies wrapped in an outer per-message HMAC
     envelope.
     */
    TSRA_SESSION_EX_TYPE_AUTHENTICATED = 1,
};
#ifndef __cplusplus
typedef uint32_t tsra_session_ex_type;
#endif // __cplusplus

/*
 Session property identifier enumeration.

 This enum defines the various properties that can be queried from an HSM session.
 Each property has a unique identifier that is used to retrieve specific attributes
 of a session.

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum tsra_session_prop_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     API revision used by the session.
     */
    TSRA_SESSION_PROP_ID_API_REV = 1,
};
#ifndef __cplusplus
typedef uint32_t tsra_session_prop_id;
#endif // __cplusplus

/*
 Elliptic Curve Cryptography (ECC) curve identifier.

 Specifies the elliptic curve used for ECC keys, as defined by NIST.
 */
enum tsra_ecc_curve
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     NIST P-256 curve (secp256r1), approximately 128-bit security strength.
     */
    TSRA_ECC_CURVE_P256 = 1,
    /*
     NIST P-384 curve (secp384r1), approximately 192-bit security strength.
     */
    TSRA_ECC_CURVE_P384 = 2,
    /*
     NIST P-521 curve (secp521r1), approximately 256-bit security strength.
     */
    TSRA_ECC_CURVE_P521 = 3,
};
#ifndef __cplusplus
typedef uint32_t tsra_ecc_curve;
#endif // __cplusplus

/*
 Cryptographic key class.

 Defines the fundamental category of a cryptographic key.
 */
enum tsra_key_class
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Symmetric secret key (e.g., AES, HMAC).
     */
    TSRA_KEY_CLASS_SECRET = 1,
    /*
     Public key from an asymmetric key pair.
     */
    TSRA_KEY_CLASS_PUBLIC = 2,
    /*
     Private key from an asymmetric key pair.
     */
    TSRA_KEY_CLASS_PRIVATE = 3,
};
#ifndef __cplusplus
typedef uint32_t tsra_key_class;
#endif // __cplusplus

/*
 HSM partition type.

 Indicates whether the partition is a virtual (simulated) or physical (hardware) device.
 */
enum tsra_part_type
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     Virtual/simulated partition.
     */
    TSRA_PART_TYPE_VIRTUAL = 1,
    /*
     Physical hardware partition.
     */
    TSRA_PART_TYPE_PHYSICAL = 2,
};
#ifndef __cplusplus
typedef uint32_t tsra_part_type;
#endif // __cplusplus

/*
 MGF1 (Mask Generation Function 1) identifier enumeration.

 This enum defines the supported mask generation functions used in RSA operations,
 particularly for OAEP padding schemes. MGF1 is based on hash functions and provides
 deterministic mask generation for cryptographic operations.

 The enum is represented as a u32 to ensure compatibility with C APIs and consistent
 memory layout across different platforms.
 */
enum tsra_mgf1_id
#ifdef __cplusplus
    : uint32_t
#endif // __cplusplus
{
    /*
     MGF1 with SHA-256 hash function
     */
    TSRA_MGF1_ID_SHA256 = 1,
    /*
     MGF1 with SHA-384 hash function
     */
    TSRA_MGF1_ID_SHA384 = 2,
    /*
     MGF1 with SHA-512 hash function
     */
    TSRA_MGF1_ID_SHA512 = 3,
    /*
     MGF1 with SHA-1 hash function
     */
    TSRA_MGF1_ID_SHA1 = 4,
};
#ifndef __cplusplus
typedef uint32_t tsra_mgf1_id;
#endif // __cplusplus

/*
 Opaque partition-policy builder handle.

 Created by [`tsra_part_policy_builder_new`], populated through the
 `tsra_part_policy_builder_set_*` setters, serialized with
 [`tsra_part_policy_build`], and released with
 [`tsra_part_policy_builder_free`].
 */
struct tsra_part_policy_builder;

/*
 Error type used throughout the native API.

 An alias for `HsmError` that represents all possible error conditions
 in the HSM API. This type is returned across the ABI boundary and can
 be converted to appropriate error codes for C callers.
 */
typedef tsra_status tsra_status;

/*
 Handle type for referencing HSM objects across the FFI boundary.

 A 32-bit unsigned integer used as an opaque handle to reference HSM objects
 such as partitions, sessions, and keys. Handles are managed by the global
 handle table and should be treated as opaque identifiers by C callers.
 */
typedef uint32_t tsra_handle;

/*
 Cryptographic algorithm structure for specifying algorithm parameters.

 This structure is used to specify the algorithm identifier and
 any associated parameters for cryptographic operations in the HSM.

 # Safety
 When using this struct from C code:
 - `params` must point to valid memory for `len` bytes
 - `params` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management

 */
struct tsra_algo
{
    /*
     Algorithm identifier.
     */
    tsra_algo_id id;
    /*
     Pointer to algorithm-specific parameters.
     */
    void *params;
    /*
     Length of the algorithm-specific parameters.
     */
    uint32_t len;
};

/*
 Buffer structure for passing data

 # Safety
 When using this struct from C code:
 - `ptr` must point to valid memory for `len` bytes
 - `ptr` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management
 */
struct tsra_buffer
{
    void *ptr;
    uint32_t len;
};

/*
 A DARC certificate chain: an array of `len` `tsra_buffer`s, each a
 DER-encoded certificate (root to leaf). The DER bytes are borrowed, not
 copied.
 */
struct tsra_darc_cert_chain
{
    /*
     Pointer to an array of `len` DER certificate `tsra_buffer`s.
     */
    const struct tsra_buffer *certs;
    /*
     Number of certificates in `certs`.
     */
    uint32_t len;
};

/*
 Input buffers for [`tsra_darc_tmk_export`].
 */
struct tsra_darc_tmk_export_params
{
    /*
     Source's masked DARC KEX key (from `tsra_darc_kex_key_gen`),
     exactly `MASKED_KEX_KEY_LEN` (276 B).
     */
    const struct tsra_buffer *masked_sender_key;
    /*
     Masked TMK (from `tsra_darc_tmk_gen`), exactly `MASKED_TMK_LEN`
     (260 B).
     */
    const struct tsra_buffer *masked_tmk;
    /*
     Unified partition-policy image (584 B) whose `DATAPubKey` anchors
     `target_cert_chain`.
     */
    const struct tsra_buffer *policy;
    /*
     DATA-anchored target certificate chain (1..=2 certs).
     */
    struct tsra_darc_cert_chain target_cert_chain;
};

/*
 Input buffers for [`tsra_darc_tmk_import`].
 */
struct tsra_darc_tmk_import_params
{
    /*
     Target's masked DARC KEX key (from `tsra_darc_kex_key_gen`),
     exactly `MASKED_KEX_KEY_LEN` (276 B).
     */
    const struct tsra_buffer *masked_kex_key;
    /*
     Unified partition-policy image (584 B) whose `POTAPubKey` anchors
     `remote_cert_chain`.
     */
    const struct tsra_buffer *policy;
    /*
     Sealed TMK (from `tsra_darc_tmk_export`), exactly `SEALED_TMK_LEN`
     (145 B).
     */
    const struct tsra_buffer *sealed_tmk;
    /*
     POTA-anchored source certificate chain (1..=2 certs).
     */
    struct tsra_darc_cert_chain remote_cert_chain;
};

/*
 Input parameters for [`tsra_darc_key_wrap`].
 */
struct tsra_darc_key_wrap_params
{
    /*
     Handle to the source EC private key to export (the transferred key).
     */
    tsra_handle source_key;
    /*
     Masked TMK (from `tsra_darc_tmk_gen` or `tsra_darc_tmk_import`),
     exactly `MASKED_TMK_LEN` (260 B).
     */
    const struct tsra_buffer *masked_tmk;
};

/*
 Key property

 # Safety
 When using this struct from C code:
 - `val` must point to valid memory for `len` bytes
 - `val` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management

 */
struct tsra_key_prop
{
    /*
     Property identifier
     */
    tsra_key_prop_id id;
    /*
     Pointer to the property value
     */
    void *val;
    /*
     Length of the property value in bytes
     */
    uint32_t len;
};

/*
 List of key properties

 # Safety
 When using this struct from C code:
 - `props` must point to valid memory for `count` elements
 - Each element's `val` must point to valid memory for `len` bytes
 - The lifetimes of `props` and its elements must exceed the lifetime of this struct
 - Caller is responsible for proper memory management

 */
struct tsra_key_prop_list
{
    /*
     Pointer to an array of key properties
     */
    struct tsra_key_prop *props;
    /*
     Number of key properties in the array
     */
    uint32_t count;
};

/*
 Input parameters for [`tsra_darc_key_unwrap`].
 */
struct tsra_darc_key_unwrap_params
{
    /*
     Masked TMK (from `tsra_darc_tmk_import`), exactly `MASKED_TMK_LEN`
     (260 B).
     */
    const struct tsra_buffer *masked_tmk;
    /*
     AES-KWP-wrapped `COSE_Key` (from `tsra_darc_key_wrap`), at most
     `DARC_UNWRAP_WRAPPED_KEY_MAX_LEN` (512 B).
     */
    const struct tsra_buffer *wrapped_key;
    /*
     Requested properties for the recovered private key. The recovered
     key's kind (curve) is validated against these.
     */
    const struct tsra_key_prop_list *priv_key_props;
    /*
     Requested properties for the recovered public key.
     */
    const struct tsra_key_prop_list *pub_key_props;
};

/*
 Key kind type used in the native API.

 An alias for `HsmKeyKind` that represents the algorithm type of a cryptographic key.
 This type is used across the FFI boundary to indicate whether a key is RSA, ECC, AES, etc.
 */
typedef tsra_key_kind tsra_key_kind;

#if !defined(_WIN32)
/*
 Character (single-byte for non-Windows)
 */
typedef uint8_t tsra_char;
#endif

#if defined(_WIN32)
/*
 Character (UTF-16 for Windows)
 */
typedef uint16_t tsra_char;
#endif

/*
 String
 */
struct tsra_str
{
    /*
     Pointer to the string
     */
    tsra_char *str;
    /*
     Length of the string (including null terminator)
     */
    uint32_t len;
};

/*
 API revision structure used to specify the desired API version.

 This structure allows clients to specify the major and minor version
 numbers of the API they wish to use. It is used to ensure compatibility
 between different versions of the HSM API.

 */
struct tsra_api_rev
{
    /*
     Major version number
     */
    uint32_t major;
    /*
     Minor version number
     */
    uint32_t minor;
};

/*
 FFI-safe partition info structure.

 C-compatible representation of `HsmPartitionInfo` with the path
 expressed as an `TsraStr` (pointer + length) instead of a Rust `String`,
 and the supported API revision range as min/max fields.
 */
struct tsra_part_info
{
    /*
     Device path (caller-owned buffer, filled by the API)
     */
    struct tsra_str path;
    /*
     Minimum supported API revision
     */
    struct tsra_api_rev api_rev_min;
    /*
     Maximum supported API revision
     */
    struct tsra_api_rev api_rev_max;
};

/*
 credentials structure used for authentication.

 This structure contains the identifier and PIN required
 to authenticate with the HSM.

 */
struct tsra_credentials
{
    /*
     Identifier (16 bytes)
     */
    uint8_t id[16];
    /*
     PIN (16 bytes)
     */
    uint8_t pin[16];
};

/*
 Owner backup key source used in the native API.
 An alias for `HsmOwnerBackupKeySource` that represents the source of the owner backup key
 (caller-provided or TPM-sealed).
 */
typedef tsra_owner_backup_key_source tsra_owner_backup_key_source;

struct tsra_owner_backup_key_config
{
    /*
     Source of the owner backup key
     */
    tsra_owner_backup_key_source source;
    /*
     Pointer to the plaintext owner backup key buffer (OBK).
     Required when `source` is `Caller` and `masked_owner_backup_key`
     is NULL. The device's `init_bk3` operation is one-shot per
     power cycle, so callers should provide OBK only on the first
     init and cache the resulting MOBK (read via the
     `MaskedOwnerBackupKey` property) for subsequent inits.
     */
    const struct tsra_buffer *owner_backup_key;
    /*
     Pointer to the masked owner backup key buffer (MOBK).
     When non-NULL on a `Caller` source, the SDK skips the OBK→MOBK
     derivation and uses this MOBK directly. Exactly one of
     `owner_backup_key` or `masked_owner_backup_key` must be non-NULL
     for the `Caller` source.
     */
    const struct tsra_buffer *masked_owner_backup_key;
};

/*
 POTA endorsement source used in the native API.
 An alias for `HsmPotaEndorsementSource` that represents the source of the POTA endorsement
 (caller-provided or TPM-generated).
 */
typedef tsra_pota_endorsement_source tsra_pota_endorsement_source;

struct tsra_pota_endorsement_data
{
    /*
     Pointer to the signature buffer
     */
    const struct tsra_buffer *signature;
    /*
     Pointer to the public key buffer
     */
    const struct tsra_buffer *public_key;
};

struct tsra_pota_endorsement
{
    /*
     Source of the POTA endorsement
     */
    tsra_pota_endorsement_source source;
    /*
     Pointer to the POTA endorsement data (if source is Caller)
     */
    const struct tsra_pota_endorsement_data *endorsement;
};

/*
 Storage operations for resiliency.

 All three function pointers are required.

 `read`: Reads data for the given key into the output buffer. If the
 output buffer is too small (or null/zero-length), sets `output->len` to
 the required size and returns `TSRA_STATUS_BUFFER_TOO_SMALL`. Returns
 `TSRA_STATUS_NOT_FOUND` when the key does not exist.

 `write`: Writes data for the given key (create or overwrite).

 `clear`: Deletes data for the given key. No error if key doesn't exist.
 */
struct tsra_resiliency_storage_ops
{
    tsra_status (*read)(void *ctx, const char *key, struct tsra_buffer *value);
    tsra_status (*write)(void *ctx, const char *key, const struct tsra_buffer *value);
    tsra_status (*clear)(void *ctx, const char *key);
};

/*
 Lock operations for cross-process/thread restore coordination.

 Both function pointers are required. The lock is non-reentrant.
 */
struct tsra_resiliency_lock_ops
{
    tsra_status (*lock)(void *ctx);
    tsra_status (*unlock)(void *ctx);
};

/*
 POTA endorsement callback.

 The `endorse` callback re-endorses the device's PID certificate public
 key with the caller's POTA private key. Uses the two-call buffer pattern:
 first call with null/zero output buffers to query sizes, second call to
 fill them.
 */
struct tsra_pota_callback_ops
{
    tsra_status (*endorse)(
        void *ctx,
        const struct tsra_buffer *pota_pub_key_der,
        const struct tsra_buffer *pid_pub_key_der,
        const struct tsra_buffer *pid_cert_chain_pem,
        struct tsra_buffer *signature,
        struct tsra_buffer *endorsement_pub_key
    );
};

/*
 MOBK provider callback.

 The `get_mobk` callback returns the caller's MOBK (masked owner backup
 key) during resiliency restore, allowing the SDK to re-provision the
 partition without re-running `init_bk3` (which is one-shot per device
 power cycle). Uses the two-call buffer pattern: first call with
 null/zero output buffer to query size, second call to fill it.
 */
struct tsra_mobk_callback_ops
{
    tsra_status (*get_mobk)(void *ctx, struct tsra_buffer *mobk);
};

/*
 Resiliency configuration passed to `tsra_part_init`.

 - `ctx`: Opaque context pointer passed back to every callback. The SDK
   never dereferences this — the caller owns and manages it. Must remain
   valid until `tsra_part_close` returns. **Must not** contain or
   reference the same partition handle — see module-level safety docs.
 - `storage_ops` and `lock_ops` are always required (inline).
 - `pota_callback_ops`: Pointer to POTA callback ops. NULL when POTA
   endorsement source is TPM. Must be non-null when source is Caller.
 - `mobk_callback_ops`: Pointer to MOBK callback ops. NULL when OBK
   source is TPM. Must be non-null when source is Caller.
 */
struct tsra_resiliency_config
{
    void *ctx;
    struct tsra_resiliency_storage_ops storage_ops;
    struct tsra_resiliency_lock_ops lock_ops;
    const struct tsra_pota_callback_ops *pota_callback_ops;
    const struct tsra_mobk_callback_ops *mobk_callback_ops;
};

/*
 Partition property structure for querying partition attributes.

 # Safety
 When using this struct from C code:
 - `val` must point to valid memory for `len` bytes
 - `val` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management
 */
struct tsra_part_prop
{
    /*
     Property identifier.
     */
    tsra_part_prop_id id;
    /*
     Pointer to the property value.
     */
    void *val;
    /*
     Length of the property value in bytes.
     */
    uint32_t len;
};

/*
 One certificate chain in an SD attestation-evidence party: an array of
 `len` `tsra_buffer`s, each a DER-encoded certificate (root to leaf).
 */
struct tsra_sd_cert_chain
{
    /*
     Pointer to an array of `len` DER certificate `tsra_buffer`s.
     */
    const struct tsra_buffer *certs;
    /*
     Number of certificates in `certs`.
     */
    uint32_t len;
};

/*
 Attestation evidence for one SD-backup party: required manufacturer and
 partition-owner chains, an optional device-owner chain, and a COSE_Sign1
 report. The DER bytes are borrowed, not copied.
 */
struct tsra_sd_evidence
{
    /*
     Manufacturer certificate chain.
     */
    struct tsra_sd_cert_chain mfgr_cert_chain;
    /*
     Optional device-owner certificate chain; set len to zero to omit it.
     If supplied, it must validate and share the manufacturer leaf key.
     */
    struct tsra_sd_cert_chain owner_cert_chain;
    /*
     Partition-owner certificate chain.
     */
    struct tsra_sd_cert_chain part_owner_cert_chain;
    /*
     COSE_Sign1 attestation-report buffer.
     */
    const struct tsra_buffer *report;
};

/*
 Input buffers for [`tsra_sd_create_remote_backup`].
 */
struct tsra_sd_create_remote_backup_params
{
    /*
     Unified partition-policy image (584 B) describing the domain.
     */
    const struct tsra_buffer *part_policy;
    /*
     Sender's masked SD-sealing key (from `tsra_key_gen`), exactly
     `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct tsra_buffer *masked_sealing_key;
    /*
     Receiver key certificate chain (spec `RcvrCertChain`): validated
     and anchored to the policy SATA key, its leaf is the recipient key
     the remote backup is sealed to.  Always required.
     */
    struct tsra_sd_cert_chain receiver_cert_chain;
    /*
     Receiver attestation evidence.  Verified only when the policy sets
     `require_trusted_sa_key`; pass empty chains and an empty report
     otherwise.
     */
    const struct tsra_sd_evidence *receiver_evidence;
};

/*
 Input buffers for [`tsra_sd_reseal_remote_backup`].
 */
struct tsra_sd_reseal_remote_backup_params
{
    /*
     Unified partition-policy image (584 B) describing the domain.
     */
    const struct tsra_buffer *part_policy;
    /*
     Receiver's masked SD-sealing key (from `tsra_key_gen`) that
     unseals the source backup, exactly `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct tsra_buffer *masked_sealing_key;
    /*
     Source (sender) attestation evidence.
     */
    const struct tsra_sd_evidence *src_evidence;
    /*
     Destination (receiver) attestation evidence.
     */
    const struct tsra_sd_evidence *dest_evidence;
    /*
     Source remote backup to reseal, exactly `POK_REMOTE_BACKUP_LEN`
     (161 B).
     */
    const struct tsra_buffer *src_remote_backup;
};

/*
 Input buffers for [`tsra_sd_restore_remote_backup`].
 */
struct tsra_sd_restore_remote_backup_params
{
    /*
     Unified partition-policy image (584 B) describing the domain.
     */
    const struct tsra_buffer *part_policy;
    /*
     Receiver's masked SD-sealing key (from `tsra_key_gen`) that
     unseals the backup, exactly `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct tsra_buffer *masked_sealing_key;
    /*
     Sender key certificate chain (spec `SndrCertChain`): validated and
     anchored to the policy SATA key, its leaf is the sender key that
     sealed the remote backup.  Always required.
     */
    struct tsra_sd_cert_chain sender_cert_chain;
    /*
     Sender attestation evidence.  Verified only when the policy sets
     `require_trusted_sa_key`; pass empty chains and an empty report
     otherwise.
     */
    const struct tsra_sd_evidence *sender_evidence;
    /*
     Remote backup to restore, exactly `POK_REMOTE_BACKUP_LEN` (161 B).
     */
    const struct tsra_buffer *src_remote_backup;
    /*
     Previous security-domain masking-key backup, exactly
     `SD_MK_BACKUP_LEN` (260 B).
     */
    const struct tsra_buffer *prev_sd_mk_backup;
};

/*
 Input buffers for [`tsra_sd_create_peer_backup`].
 */
struct tsra_sd_create_peer_backup_params
{
    /*
     Unified partition-policy image (584 B) describing the domain.
     */
    const struct tsra_buffer *part_policy;
    /*
     Sender's masked SD-sealing key (from `tsra_key_gen`), exactly
     `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct tsra_buffer *masked_sealing_key;
    /*
     Destination (peer) attestation evidence.
     */
    const struct tsra_sd_evidence *dst_evidence;
    /*
     Device-local partition-owner-key backup (276 B) from which BKS3 is
     recovered.
     */
    const struct tsra_buffer *pok_local_backup;
};

/*
 Input buffers for [`tsra_sd_restore_peer_backup`].
 */
struct tsra_sd_restore_peer_backup_params
{
    /*
     Unified partition-policy image (584 B) describing the domain.
     */
    const struct tsra_buffer *part_policy;
    /*
     Receiver's masked SD-sealing key (from `tsra_key_gen`) that
     unseals the backup, exactly `MASKED_SEALING_KEY_LEN` (276 B).
     */
    const struct tsra_buffer *masked_sealing_key;
    /*
     Source (peer) attestation evidence.
     */
    const struct tsra_sd_evidence *src_evidence;
    /*
     Peer backup to restore, exactly `POK_REMOTE_BACKUP_LEN` (161 B).
     */
    const struct tsra_buffer *pok_peer_backup;
    /*
     Previous security-domain masking-key backup, exactly
     `SD_MK_BACKUP_LEN` (260 B).
     */
    const struct tsra_buffer *prev_sd_mk_backup;
};

/*
 Input buffers for [`tsra_sd_restore_local_backup`].
 */
struct tsra_sd_restore_local_backup_params
{
    /*
     Device-local partition-owner-key backup to restore, exactly
     `MASKED_SD_LEN` (276 B).
     */
    const struct tsra_buffer *pok_local_backup;
    /*
     Security-domain masking-key backup, exactly `SD_MK_BACKUP_LEN`
     (260 B).
     */
    const struct tsra_buffer *sd_mk_backup;
};

/*
 PSK credential for opening a security-domain session.

 Pairs the PSK slot (`psk_id`) with an optional caller-supplied PSK.
 When the `psk` **field** (below) is NULL, the partition **default** PSK
 for the slot is used — required for the first session, before the
 default is rotated via `tsra_sess_ex_psk_change`. After rotation,
 point the `psk` field at the rotated secret.
 */
struct tsra_session_psk
{
    /*
     PSK slot: 0 = Crypto Officer, 1 = Crypto User.
     */
    uint8_t psk_id;
    /*
     Optional PSK buffer (exactly `TSRA_PSK_LEN` bytes); NULL selects the
     partition default PSK for the slot.
     */
    const struct tsra_buffer *psk;
};

typedef tsra_session_ex_type tsra_session_ex_type;

/*
 Input buffers for [`tsra_sess_ex_part_init`].

 Groups the security-domain provisioning inputs into a single struct so
 the call site does not pass them as separate arguments. Each field
 points to an `tsra_buffer`; `sapota_thumbprint` is optional and may
 be NULL to omit it.
 */
struct tsra_sess_ex_part_init_params
{
    /*
     Unified partition policy image buffer.
     */
    const struct tsra_buffer *part_policy;
    /*
     Machine seed plaintext buffer.
     */
    const struct tsra_buffer *mach_seed;
    /*
     POTA public-key thumbprint buffer.
     */
    const struct tsra_buffer *pota_thumbprint;
    /*
     SATA public-key thumbprint buffer.
     */
    const struct tsra_buffer *sata_thumbprint;
    /*
     Optional SAPOTA thumbprint buffer; NULL to omit.
     */
    const struct tsra_buffer *sapota_thumbprint;
};

/*
 Input buffers for [`tsra_sess_ex_part_final`].

 Groups the security-domain finalization inputs into a single struct so
 the call site does not pass them as separate arguments. `pta_cert_chain`
 points to an array of `pta_cert_chain_len` `tsra_buffer`s, each holding
 one DER-encoded PTA certificate (root to leaf). `prev_local_mk_backup` is
 optional and may be NULL to omit it.
 */
struct tsra_sess_ex_part_final_params
{
    /*
     Unified partition policy image buffer, re-supplied for `POTAPubKey`
     recovery; must match the policy given to `part_init`.
     */
    const struct tsra_buffer *part_policy;
    /*
     Pointer to an array of `pta_cert_chain_len` `tsra_buffer`s, each a
     DER-encoded PTA certificate (root to leaf).
     */
    const struct tsra_buffer *pta_cert_chain;
    /*
     Number of certificates in `pta_cert_chain`.
     */
    uint32_t pta_cert_chain_len;
    /*
     Optional previous `local_mk` backup envelope to restore; NULL to omit.
     */
    const struct tsra_buffer *prev_local_mk_backup;
};

/*
 Session property structure for querying session attributes.

 # Safety
 When using this struct from C code:
 - `val` must point to valid memory for `len` bytes
 - `val` lifetime must exceed the lifetime of this struct
 - Caller is responsible for proper memory management
 */
struct tsra_session_prop
{
    /*
     Property identifier.
     */
    tsra_session_prop_id id;
    /*
     Pointer to the property value.
     */
    void *val;
    /*
     Length of the property value in bytes.
     */
    uint32_t len;
};

/*
 AES CBC parameters.
 */
struct tsra_algo_aes_cbc_params
{
    /*
     IV
     */
    uint8_t iv[16];
};

/*
 AES GCM parameters.
 */
struct tsra_algo_aes_gcm_params
{
    /*
     IV (12 bytes)
     */
    uint8_t iv[TSRA_AES_GCM_IV_SIZE];
    /*
     Tag (16 bytes) for decryption; updated after encryption.
     */
    uint8_t tag[TSRA_AES_GCM_TAG_SIZE];
    /*
     Optional AAD buffer
     */
    const struct tsra_buffer *aad;
};

/*
 AES-XTS algorithm parameters.

 This structure defines the parameters required for AES-XTS encryption/decryption,
 including the sector number (tweak) and data unit length.
 */
struct tsra_algo_aes_xts_params
{
    /*
     Sector number (tweak value) in little-endian byte format.
     This is a 128-bit value that provides additional security by
     varying the encryption for each data unit.
     */
    uint8_t sector_num[16];
    /*
     Data Unit Length in bytes.
     Specifies the size of each data unit to be encrypted/decrypted.
     Must be at least 16 bytes for XTS mode.
     */
    uint32_t data_unit_length;
};

/*
 ECDH parameter structure matching C API
 */
struct tsra_algo_ecdh_params
{
    const struct tsra_buffer *pub_key;
};

/*
 HKDF parameter structure matching C API
 */
struct tsra_algo_hkdf_params
{
    tsra_algo_id hmac_algo_id;
    const struct tsra_buffer *salt;
    const struct tsra_buffer *info;
};

/*
 SP 800-108 Counter Mode KDF parameter structure matching C API
 */
struct tsra_algo_kbkdf_counter_params
{
    tsra_algo_id hmac_algo_id;
    const struct tsra_buffer *label;
    const struct tsra_buffer *context;
};

/*
 RSA PKCS OAEP encryption/decryption parameters matching C API.

 Defines parameters for OAEP (Optimal Asymmetric Encryption Padding) operations,
 which provide secure probabilistic encryption using a hash function, mask
 generation function (MGF1), and optional label for context binding.
 */
struct tsra_algo_rsa_pkcs_oaep_params
{
    /*
     Hash algorithm identifier used for OAEP padding
     */
    tsra_algo_id hash_algo_id;
    /*
     MGF1 mask generation function identifier.
     */
    tsra_mgf1_id mgf1_hash_algo_id;
    /*
     Optional label for encryption context (can be null)
     */
    const struct tsra_buffer *label;
};

/*
 RSA-AES key wrapping parameters matching C API.

 Defines parameters for RSA-AES key wrap/unwrap operations, which combine
 RSA encryption with AES key wrapping to securely transport symmetric keys.
 The RSA key encrypts an AES key, which in turn wraps the target key material.
 */
struct tsra_algo_rsa_aes_key_wrap_params
{
    /*
     AES key size in bits (typically 128, 192, or 256)
     */
    uint32_t aes_key_bits;
    /*
     OAEP parameters for RSA encryption of the AES key
     */
    const struct tsra_algo_rsa_pkcs_oaep_params *oaep_params;
};

/*
 RSA-AES Wrap algorithm parameters structure matching C API

 This structure specifies the parameters for RSA-AES generic wrapping,
 which combines RSA-OAEP encryption with AES wrapping to securely
 transport data.
 */
struct tsra_algo_rsa_aes_wrap_params
{
    /*
     AES key bits
     */
    uint32_t aes_key_bits;
    /*
     OAEP parameters
     */
    const struct tsra_algo_rsa_pkcs_oaep_params *oaep_params;
};

/*
 RSA PKCS PSS signature parameters matching C API.

 Defines parameters for PSS (Probabilistic Signature Scheme) operations,
 which provide probabilistic signature generation using a hash function,
 mask generation function (MGF1), and salt for enhanced security.
 */
struct tsra_algo_rsa_pkcs_pss_params
{
    /*
     Hash algorithm identifier used for PSS signature
     */
    tsra_algo_id hash_algo_id;
    /*
     MGF1 mask generation function identifier (typically matches hash_algo_id)
     */
    tsra_mgf1_id mgf_id;
    /*
     Salt length in bytes (typically matches hash output size)
     */
    uint32_t salt_len;
};

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

/*
 Compute cryptographic digest (hash) of data using the specified algorithm.

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[in] data Pointer to data buffer to be hashed
 @param[out] digest Pointer to digest output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_digest(
    tsra_handle sess_handle,
    const struct tsra_algo *algo,
    const struct tsra_buffer *data,
    struct tsra_buffer *digest
);

/*
 Initialize a streaming digest operation.

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[out] ctx_handle Pointer to receive the digest context handle

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_digest_init(
    tsra_handle sess_handle,
    const struct tsra_algo *algo,
    tsra_handle *ctx_handle
);

/*
 Update a streaming digest operation with more data.

 @param[in] ctx_handle Handle to the digest context
 @param[in] data Pointer to data buffer to digest

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_digest_update(tsra_handle ctx_handle, const struct tsra_buffer *data);

/*
 Finish a streaming digest operation and produce the digest.

 @param[in] ctx_handle Handle to the digest context
 @param[out] digest Pointer to digest output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 TSRA_STATUS_BUFFER_TOO_SMALL is returned.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_digest_finish(tsra_handle ctx_handle, struct tsra_buffer *digest);

/*
 Encrypt data using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the encryption key
 @param[in] plain_text Pointer to plaintext data buffer
 @param[out] cipher_text Pointer to ciphertext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_encrypt(
    struct tsra_algo *algo,
    tsra_handle key_handle,
    const struct tsra_buffer *plain_text,
    struct tsra_buffer *cipher_text
);

/*
 Decrypt data using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the decryption key
 @param[in] cipher_text Pointer to ciphertext data buffer
 @param[out] plain_text Pointer to plaintext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_decrypt(
    struct tsra_algo *algo,
    tsra_handle key_handle,
    const struct tsra_buffer *cipher_text,
    struct tsra_buffer *plain_text
);

/*
 Initialize streaming encryption operation.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the encryption key
 @param[out] ctx_handle Pointer to receive the streaming context handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_encrypt_init(
    struct tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx_handle
);

/*
 Update streaming encryption operation with additional plaintext data.

 @param[in] ctx_handle Handle to the streaming encryption context
 @param[in] plain_text Pointer to plaintext data buffer to encrypt
 @param[out] cipher_text Pointer to ciphertext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.
 Note: Output may be less than input size if buffering occurs (e.g., for block alignment).

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_encrypt_update(
    tsra_handle ctx_handle,
    const struct tsra_buffer *plain_text,
    struct tsra_buffer *cipher_text
);

/*
 Finish streaming encryption operation and retrieve any remaining ciphertext.

 @param[in] ctx_handle Handle to the streaming encryption context
 @param[out] cipher_text Pointer to ciphertext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_encrypt_finish(tsra_handle ctx_handle, struct tsra_buffer *cipher_text);

/*
 Initialize streaming decryption operation.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the decryption key
 @param[out] ctx_handle Pointer to receive the streaming context handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_decrypt_init(
    struct tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx_handle
);

/*
 Update streaming decryption operation with additional ciphertext data.

 @param[in] ctx_handle Handle to the streaming decryption context
 @param[in] cipher_text Pointer to ciphertext data buffer to decrypt
 @param[out] plain_text Pointer to plaintext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.
 Note: Output may be less than input size if buffering occurs (e.g., for block alignment).

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_decrypt_update(
    tsra_handle ctx_handle,
    const struct tsra_buffer *cipher_text,
    struct tsra_buffer *plain_text
);

/*
 Finish streaming decryption operation and retrieve any remaining plaintext.

 @param[in] ctx_handle Handle to the streaming decryption context
 @param[out] plain_text Pointer to plaintext output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_decrypt_finish(tsra_handle ctx_handle, struct tsra_buffer *plain_text);

/*
 Sign data using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the signing key
 @param[in] data Pointer to data buffer to be signed
 @param[out] sig Pointer to signature output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_sign(
    struct tsra_algo *algo,
    tsra_handle key_handle,
    const struct tsra_buffer *data,
    struct tsra_buffer *sig
);

/*
 Verify signature using a cryptographic key and algorithm.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the verification key
 @param[in] data Pointer to data buffer that was signed
 @param[in] sig Pointer to signature buffer to verify

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_verify(
    struct tsra_algo *algo,
    tsra_handle key_handle,
    const struct tsra_buffer *data,
    const struct tsra_buffer *sig
);

/*
 Initialize streaming sign operation.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the signing key
 @param[out] ctx_handle Pointer to receive the streaming context handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_sign_init(
    struct tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx_handle
);

/*
 Update streaming sign operation with additional data.

 @param[in] ctx_handle Handle to the streaming sign context
 @param[in] data Pointer to data buffer to be signed

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_sign_update(tsra_handle ctx_handle, const struct tsra_buffer *data);

/*
 Finish streaming sign operation and retrieve signature.

 @param[in] ctx_handle Handle to the streaming sign context
 @param[out] sig Pointer to signature output buffer

 @return 0 on success, or a negative error code on failure.
 If output buffer is insufficient, required length is updated in the output buffer and
 the function returns the TSRA_STATUS_BUFFER_TOO_SMALL error.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_sign_finish(tsra_handle ctx_handle, struct tsra_buffer *sig);

/*
 Initialize streaming verify operation.

 @param[in] algo Pointer to algorithm specification
 @param[in] key_handle Handle to the verification key
 @param[out] ctx_handle Pointer to receive the streaming context handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_verify_init(
    struct tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx_handle
);

/*
 Update streaming verify operation with additional data.

 @param[in] ctx_handle Handle to the streaming verify context
 @param[in] data Pointer to data buffer that was signed

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_verify_update(tsra_handle ctx_handle, const struct tsra_buffer *data);

/*
 Finish streaming verify operation and verify signature.

 @param[in] ctx_handle Handle to the streaming verify context
 @param[in] sig Pointer to signature buffer to verify

 @return 0 on success, or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_crypt_verify_finish(tsra_handle ctx_handle, const struct tsra_buffer *sig);

/*
 @brief Generate a DARC key-exchange (KEX) key

 Generates a new DARC key-exchange key (ECC-P384) on the calling
 session's partition and returns the masked private key plus its raw
 P-384 public key (`x ‖ y`, 96 bytes). Run on the target it yields the
 HPKE receiver identity; run on the source it yields the HPKE sender-auth
 identity. The key is not stored on the device.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] scope Requested key scope (1-byte `KeyScope` discriminant)
 @param[in,out] masked_key Output buffer for the masked KEX private key
                (`MASKED_KEX_KEY_LEN`, 276 B)
 @param[in,out] pub_key Output buffer for the raw P-384 public key
                (`KEX_PUB_KEY_LEN`, 96 B)

 Both output buffers follow the probe/fill convention and are validated
 **before** the round-trip.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - Each output buffer must be a valid `tsra_buffer` with writable
   backing storage of the advertised length.
 */
tsra_status tsra_darc_kex_key_gen(
    tsra_handle sess_handle,
    uint8_t scope,
    struct tsra_buffer *masked_key,
    struct tsra_buffer *pub_key
);

/*
 @brief Mint a DARC Transfer Masking Key (TMK)

 Mints a fresh 256-bit TMK on the source's partition and returns it
 masked under the partition SDMK. The key is not stored on the device.

 @param[in] sess_handle Handle to the security-domain session
 @param[in,out] masked_tmk Output buffer for the masked TMK
                (`MASKED_TMK_LEN`, 260 B)

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `masked_tmk` must be a valid `tsra_buffer` with writable backing
   storage of the advertised length.
 */
tsra_status tsra_darc_tmk_gen(tsra_handle sess_handle, struct tsra_buffer *masked_tmk);

/*
 @brief Seal a DARC TMK to an authenticated target

 Validates the target certificate chain against the policy `DATAPubKey`,
 then HPKE-Auth seals the TMK to the target's KEX key, returning the
 sealed TMK.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Export input buffers
 @param[in,out] sealed_tmk Output buffer for the sealed TMK
                (`SEALED_TMK_LEN`, 145 B)

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer pointers must be valid; the
   `target_cert_chain.certs` array must hold `len` valid `tsra_buffer`s.
 - `sealed_tmk` must be a valid `tsra_buffer` with writable backing
   storage of the advertised length.
 */
tsra_status tsra_darc_tmk_export(
    tsra_handle sess_handle,
    const struct tsra_darc_tmk_export_params *params,
    struct tsra_buffer *sealed_tmk
);

/*
 @brief Import (open) a sealed DARC TMK on the target

 Validates the source certificate chain against the policy `POTAPubKey`,
 HPKE-Auth opens the sealed TMK, and re-masks it under the partition
 SDMK, returning the masked TMK.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Import input buffers
 @param[in,out] masked_tmk Output buffer for the imported masked TMK
                (`MASKED_TMK_LEN`, 260 B)

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer pointers must be valid; the
   `remote_cert_chain.certs` array must hold `len` valid `tsra_buffer`s.
 - `masked_tmk` must be a valid `tsra_buffer` with writable backing
   storage of the advertised length.
 */
tsra_status tsra_darc_tmk_import(
    tsra_handle sess_handle,
    const struct tsra_darc_tmk_import_params *params,
    struct tsra_buffer *masked_tmk
);

/*
 @brief Wrap a designated EC private key under a DARC TMK

 AES-KWP-wraps the source key's EC2 `COSE_Key` under the TMK, returning
 the wrapped transport blob. The source key is supplied as a handle (the
 same handle model as `tsra_key_unwrap_pair`); the raw key material
 never leaves the device.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Wrap input parameters (source key handle + masked TMK)
 @param[in,out] wrapped_key Output buffer for the wrapped key (at most
                `DARC_WRAP_WRAPPED_KEY_MAX_LEN`, 512 B). Follows the
                probe/fill convention: on `BufferTooSmall` the required
                size is written to `wrapped_key.len`.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params.source_key` must be a valid EC private-key handle and
   `params.masked_tmk` a valid `tsra_buffer`.
 - `wrapped_key` must be a valid `tsra_buffer` with writable backing
   storage of the advertised length.
 */
tsra_status tsra_darc_key_wrap(
    tsra_handle sess_handle,
    const struct tsra_darc_key_wrap_params *params,
    struct tsra_buffer *wrapped_key
);

/*
 @brief Unwrap and install a transferred key pair on the target

 AES-KWP-unwraps `wrapped_key` under the TMK and installs the recovered
 EC key pair, returning handles to the private and public keys (the same
 handle model as `tsra_key_unwrap_pair`). The recovered curve is
 validated against `priv_key_props`.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Unwrap input parameters
 @param[out] priv_key_handle Handle to the recovered private key
 @param[out] pub_key_handle Handle to the recovered public key

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/prop-list pointers must be valid.
 - `priv_key_handle` and `pub_key_handle` must be valid, writable,
   distinct handle pointers.
 */
tsra_status tsra_darc_key_unwrap(
    tsra_handle sess_handle,
    const struct tsra_darc_key_unwrap_params *params,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
);

/*
 Frees a context handle and releases associated resources.

 The handle is invalidated and must not be used after this call.

 Callers **must** call this function for every valid context handle once it
 is no longer needed, regardless of whether the associated operation
 completed successfully or encountered an error.

 # Safety

 - The `handle` must be a valid handle previously returned by one of the
   context creation functions.
 - The handle must not have been previously freed.
 - After this call, the handle becomes invalid and must not be used.

 # Returns

 * `TSRA_STATUS_SUCCESS` - Handle freed successfully
 * `TSRA_STATUS_INVALID_HANDLE` - Invalid or already freed handle
 */
tsra_status tsra_free_ctx_handle(tsra_handle handle);

/*
 Generate a symmetric key

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[in] key_props Pointer to key properties list
 @param[out] key_handle Pointer to store the generated key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_key_gen(
    tsra_handle sess_handle,
    const struct tsra_algo *algo,
    const struct tsra_key_prop_list *key_props,
    tsra_handle *key_handle
);

/*
 Generate an asymmetric key pair

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[in] priv_key_props Pointer to private key properties list
 @param[in] pub_key_props Pointer to public key properties list
 @param[out] priv_key_handle Pointer to store the generated private key handle
 @param[out] pub_key_handle Pointer to store the generated public key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_key_gen_pair(
    tsra_handle sess_handle,
    struct tsra_algo *algo,
    const struct tsra_key_prop_list *priv_key_props,
    const struct tsra_key_prop_list *pub_key_props,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
);

/*
 Delete a key from the HSM

 @param[in] key_handle Handle to the key to delete

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is marked unsafe due to no_mangle.
 */
tsra_status tsra_key_delete(tsra_handle key_handle);

/*
 Derive a key from a base key

 @param[in] sess_handle Handle to the HSM session
 @param[in] algo Pointer to algorithm specification
 @param[in] base_key Handle to the base key
 @param[in] key_props Pointer to key properties list for the derived key
 @param[out] key_handle Pointer to store the derived key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_key_derive(
    tsra_handle sess_handle,
    struct tsra_algo *algo,
    tsra_handle base_key,
    const struct tsra_key_prop_list *key_props,
    tsra_handle *key_handle
);

/*
 Unwrap a wrapped key using an unwrapping key

 This function unwraps (decrypts) a previously wrapped key using the specified
 unwrapping key and algorithm. The unwrapped key is imported into the HSM with
 the provided key properties.

 @param[in] algo Pointer to algorithm specification for unwrapping
 @param[in] unwrapping_key Handle to the key used to unwrap (decrypt) the wrapped key
 @param[in] wrapped_key Pointer to buffer containing the wrapped key data
 @param[in] key_props Pointer to key properties list for the unwrapped key
 @param[out] key_handle Pointer to store the unwrapped key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_key_unwrap(
    struct tsra_algo *algo,
    tsra_handle unwrapping_key,
    struct tsra_buffer *wrapped_key,
    const struct tsra_key_prop_list *key_props,
    tsra_handle *key_handle
);

/*
 Unwrap a wrapped key pair using an unwrapping key

 This function unwraps (decrypts) a previously wrapped key pair using the specified
 unwrapping key and algorithm. The unwrapped key pair is imported into the HSM with
 the provided key properties.

 @param[in] algo Pointer to algorithm specification for unwrapping
 @param[in] unwrapping_key Handle to the key used to unwrap (decrypt) the wrapped key pair
 @param[in] wrapped_key Pointer to buffer containing the wrapped key pair data
 @param[in] priv_key_props Pointer to private key properties list for the unwrapped key
 @param[in] pub_key_props Pointer to public key properties list for the unwrapped key
 @param[out] priv_key_handle Pointer to store the unwrapped private key handle
 @param[out] pub_key_handle Pointer to store the unwrapped public key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_key_unwrap_pair(
    struct tsra_algo *algo,
    tsra_handle unwrapping_key,
    const struct tsra_buffer *wrapped_key,
    const struct tsra_key_prop_list *priv_key_props,
    const struct tsra_key_prop_list *pub_key_props,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
);

/*
 Unmask a masked symmetric key

 This function unmasks a previously masked symmetric key. The masked key contains
 the key material and properties, so no external properties or unwrapping keys
 are needed. The key is imported into the HSM within the provided session.

 @param[in] sess_handle Handle to the HSM session
 @param[in] key_kind The kind of key to unmask (e.g., AES)
 @param[in] masked_key Pointer to buffer containing the masked key data
 @param[out] key_handle Pointer to store the unmasked key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_key_unmask(
    tsra_handle sess_handle,
    tsra_key_kind key_kind,
    const struct tsra_buffer *masked_key,
    tsra_handle *key_handle
);

/*
 Unmask a masked key pair

 This function unmasks a previously masked key pair. The masked key contains
 the key material and properties, so no external properties or unwrapping keys
 are needed. The key pair is imported into the HSM within the provided session.

 @param[in] sess_handle Handle to the HSM session
 @param[in] key_kind The kind of key pair to unmask (RSA or ECC)
 @param[in] masked_key Pointer to buffer containing the masked key pair data
 @param[out] priv_key_handle Pointer to store the unmasked private key handle
 @param[out] pub_key_handle Pointer to store the unmasked public key handle

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_key_unmask_pair(
    tsra_handle sess_handle,
    tsra_key_kind key_kind,
    const struct tsra_buffer *masked_key,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
);

/*
 Generate a key attestation report

 This function generates an attestation report for a key.

 @param[in] key_handle Handle to the key to attest
 @param[in] report_data Pointer to buffer containing custom data to include in the report (exactly
 128 bytes)
 @param[out] report Pointer to buffer to receive the attestation report

 @return 0 on success, or a negative error code on failure

 # Notes
 - The function performs a two-pass operation: first to determine the required buffer
   size, then to generate the actual report
 - The report buffer's length field will be updated with the actual report size

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_generate_key_report(
    tsra_handle key_handle,
    const struct tsra_buffer *report_data,
    struct tsra_buffer *report
);

/*
 Get a property of a key

 @param[in] key Handle to the key
 @param[in/out] key_prop Pointer to key property structure. On input, specifies which property to
 get. On output, contains the property value.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_key_get_prop(tsra_handle key_handle, struct tsra_key_prop *key_prop);

/*
 @brief Allocate a new partition-policy builder

 On success, writes a handle to `*out_builder` whose policy starts from
 a version defaulting to `major = 1, minor = 0` with every other field
 zeroed; set the required POTA and SATA keys and any optional fields
 through the `tsra_part_policy_builder_set_*` functions, then serialize
 it with `tsra_part_policy_build`. Release it with
 `tsra_part_policy_builder_free`.

 A key / `info` / backing-id that does not satisfy its field's length
 requirement is rejected at `tsra_part_policy_build` time (returning
 `TSRA_STATUS_INVALID_ARGUMENT`) rather than silently truncated or
 padded.
 Missing either POTA or SATA key also causes `tsra_part_policy_build`
 to return `TSRA_STATUS_INVALID_ARGUMENT`.
 Unsupported major versions and reserved flag bits are rejected at
 build time as well.

 @param[out] out_builder Receives the non-NULL builder handle on
             success; left unmodified on failure.

 @return `TSRA_STATUS_SUCCESS` on success, or
         `TSRA_STATUS_INVALID_ARGUMENT` if `out_builder` is NULL.

 # Safety

 - `out_builder` must be a valid, writable pointer to storage for one
   `tsra_part_policy_builder *`.
 */
tsra_status tsra_part_policy_builder_new(struct tsra_part_policy_builder **out_builder);

/*
 @brief Free a partition-policy builder

 Releases a handle returned by `tsra_part_policy_builder_new`.
 Passing NULL is a no-op. The handle must not be used afterwards.

 @param[in] builder Builder handle to free (may be NULL)

 # Safety

 - `builder` must be NULL or a handle returned by
   `tsra_part_policy_builder_new` that has not already been freed.
 */
void tsra_part_policy_builder_free(struct tsra_part_policy_builder *builder);

/*
 @brief Set the policy version (`major.minor`)

 Major version must be 1; any minor version is accepted. An unsupported
 major version is rejected at `tsra_part_policy_build` time.

 @param[in] builder Builder handle
 @param[in] major Major version number
 @param[in] minor Minor version number
 @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL handle

 # Safety

 - `builder` must be a live handle from `tsra_part_policy_builder_new`.
 */
tsra_status tsra_part_policy_builder_set_version(
    struct tsra_part_policy_builder *builder,
    uint8_t major,
    uint8_t minor
);

/*
 @brief Set the POTA (Partition Owner Trust Anchor) public key

 @param[in] builder Builder handle
 @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
 @param[in] key Raw public-key bytes
 @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `tsra_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `tsra_buffer`.
 */
tsra_status tsra_part_policy_builder_set_pota_key(
    struct tsra_part_policy_builder *builder,
    uint16_t kind,
    const struct tsra_buffer *key
);

/*
 @brief Set the SATA (Sealing Authority Trust Anchor) public key

 @param[in] builder Builder handle
 @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
 @param[in] key Raw public-key bytes
 @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `tsra_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `tsra_buffer`.
 */
tsra_status tsra_part_policy_builder_set_sata_key(
    struct tsra_part_policy_builder *builder,
    uint16_t kind,
    const struct tsra_buffer *key
);

/*
 @brief Set the SAPOTA (Sealing Authority's POTA) public key

 @param[in] builder Builder handle
 @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
 @param[in] key Raw public-key bytes
 @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `tsra_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `tsra_buffer`.
 */
tsra_status tsra_part_policy_builder_set_sapota_key(
    struct tsra_part_policy_builder *builder,
    uint16_t kind,
    const struct tsra_buffer *key
);

/*
 @brief Set the backing-partition identifier

 @param[in] builder Builder handle
 @param[in] id Backing-partition identifier bytes
 @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `tsra_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `tsra_buffer`.
 */
tsra_status tsra_part_policy_builder_set_backup_part_id(
    struct tsra_part_policy_builder *builder,
    const struct tsra_buffer *id
);

/*
 @brief Set the backing-partition public key

 @param[in] builder Builder handle
 @param[in] kind Key-kind discriminant (e.g. 0 = ECC P-384)
 @param[in] key Raw public-key bytes
 @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `tsra_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `tsra_buffer`.
 */
tsra_status tsra_part_policy_builder_set_backup_part_pub_key(
    struct tsra_part_policy_builder *builder,
    uint16_t kind,
    const struct tsra_buffer *key
);

/*
 @brief Set the caller-provided opaque `info` field

 @param[in] builder Builder handle
 @param[in] info Opaque info bytes
 @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL
         handle / buffer

 # Safety

 - `builder` must be a live handle from `tsra_part_policy_builder_new`.
 - the buffer pointer must be NULL or point to a valid `tsra_buffer`.
 */
tsra_status tsra_part_policy_builder_set_info(
    struct tsra_part_policy_builder *builder,
    const struct tsra_buffer *info
);

/*
 @brief Set the policy flag bits

 Bits 0-2 are supported; reserved bits 3-7 are rejected at
 `tsra_part_policy_build` time.

 @param[in] builder Builder handle
 @param[in] flags Raw flag bits (see the `PolicyFlags` definition)
 @return `TSRA_STATUS_SUCCESS`, or `TSRA_STATUS_INVALID_ARGUMENT` on a NULL handle

 # Safety

 - `builder` must be a live handle from `tsra_part_policy_builder_new`.
 */
tsra_status tsra_part_policy_builder_set_flags(
    struct tsra_part_policy_builder *builder,
    uint8_t flags
);

/*
 @brief Serialize the policy into its canonical wire image

 Writes exactly `PART_POLICY_LEN` bytes — the image accepted by
 `tsra_sess_ex_part_init` / `tsra_sess_ex_part_final` — into
 `out`. If `out` is too small, sets `out.len` to the required size and
 returns `TSRA_STATUS_BUFFER_TOO_SMALL` without writing. The builder is left
 usable (unchanged) for further serialization.
 Both POTA and SATA keys must be set; otherwise returns
 `TSRA_STATUS_INVALID_ARGUMENT`, even for a size probe.
 Unsupported major versions and reserved flag bits also return
 `TSRA_STATUS_INVALID_ARGUMENT` before writing output.

 @param[in] builder Builder handle
 @param[out] out Buffer to receive the serialized policy image
 @return `TSRA_STATUS_SUCCESS`, `TSRA_STATUS_INVALID_ARGUMENT` on a
         NULL or misaligned handle / buffer, or
         `TSRA_STATUS_BUFFER_TOO_SMALL` if `out` is too small

 # Safety

 - `builder` must be a live handle from `tsra_part_policy_builder_new`.
 - `out` must be a valid pointer to an `tsra_buffer` with writable
   backing storage of its advertised length.
 */
tsra_status tsra_part_policy_build(
    struct tsra_part_policy_builder *builder,
    struct tsra_buffer *out
);

/*
 Get the list of HSM partitions

 @param[out] handle Handle to the HSM partition list
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences a raw pointer.
 The caller must ensure that the pointer is valid and points to a valid `TsraHandle`.

 */
tsra_status tsra_part_get_list(tsra_handle *handle);

/*
 Free the HSM partition list

 @param[in] handle Handle to the HSM partition list
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is marked unsafe due to unsafe(no_mangle).

 */
tsra_status tsra_part_free_list(tsra_handle handle);

/*
 Get partition count

 @param[in] handle Handle to the HSM partition list
 @param[out] count Number of partitions
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences a raw pointer.
 The caller must ensure that handle is a valid `TsraHandle`.
 The caller must also ensure that the pointer is valid and points to a valid `TsraU32`.

 */
tsra_status tsra_part_get_count(tsra_handle handle, uint32_t *count);

/*
 Get partition info at the given index

 @param[in] handle Handle to the HSM partition list
 @param[in] index Index of the partition
 @param[in/out] part_info Pointer to an `TsraPartInfo` structure.
                On input, `part_info.path.len` is the size of the buffer pointed to by
 `part_info.path.str`. On output, `part_info.path.len` is set to the required/written size.
                `part_info.api_rev_min` / `part_info.api_rev_max` are only valid on
                `TSRA_STATUS_SUCCESS`.

 @return 0 on success, TSRA_STATUS_BUFFER_TOO_SMALL if the path buffer is too small
         (part_info.path.len is updated to the required size), or a negative error code on failure.

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.

 */
tsra_status tsra_part_get_info(
    tsra_handle handle,
    uint32_t index,
    struct tsra_part_info *part_info
);

/*
 Open an HSM partition with a specified API revision

 The caller selects an API revision within the range reported by
 `tsra_part_get_info`. All subsequent operations on this handle
 (including sessions opened from it) will use the selected revision.

 @param[in] path Pointer to an `tsra_str` containing the partition
            device path. The `str` field must point to a valid
            null-terminated buffer and `len` must include the null
            terminator (i.e. `str[len-1] == 0`).
 @param[out] handle Handle to the opened HSM partition
 @param[in] api_rev API revision to use for this partition handle
 @return 0 on success, TSRA_STATUS_UNSUPPORTED_API_REVISION if api_rev is
         outside the partition's supported range, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 The caller must ensure that `path` is a valid pointer to an `TsraStr`
 whose `str` field points to a null-terminated buffer of `len`
 `tsra_char` elements (including the terminator).
 The caller must also ensure that the `handle` argument is a valid `TsraHandle` pointer.

 */
tsra_status tsra_part_open(
    const struct tsra_str *path,
    tsra_handle *handle,
    struct tsra_api_rev api_rev
);

/*
 Initialize an HSM partition

 @param[in] part_handle Handle to the HSM partition
 @param[in] creds Pointer to application credentials (ID and PIN)
 @param[in] bmk Optional backup masking key buffer (can be null)
 @param[in] muk Optional masked unwrapping key buffer (can be null)
 @param[in] backup_key_config Configuration for owner backup key
 @param[in] pota_endorsement POTA endorsement configuration
 @param[in] resiliency_config Optional resiliency configuration (can be null).
            When non-null, enables automatic retry/recovery for transient
            hardware resets. If POTA source is Caller, `pota_callback_ops`
            must be non-null. If POTA source is TPM, `pota_callback_ops`
            must be null.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.

 */
tsra_status tsra_part_init(
    tsra_handle part_handle,
    const struct tsra_credentials *creds,
    const struct tsra_buffer *bmk,
    const struct tsra_buffer *muk,
    const struct tsra_owner_backup_key_config *backup_key_config,
    const struct tsra_pota_endorsement *pota_endorsement,
    const struct tsra_resiliency_config *resiliency_config
);

/*
 Close an HSM partition

 @param[in] handle Handle to the HSM partition
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences a raw pointer.
 This function is marked unsafe due to unsafe(no_mangle).

 */
tsra_status tsra_part_close(tsra_handle handle);

/*
 Reset the HSM partition state

 including established credentials and active sessions. This is useful for
 test cleanup and recovery scenarios.

 @param[in] part_handle Handle to the HSM partition
 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences a raw pointer.
 This function is marked unsafe due to unsafe(no_mangle).

 */
tsra_status tsra_part_reset(tsra_handle part_handle);

/*
 Get a property of a partition

 @param[in] handle Handle to the partition
 @param[in/out] part_prop Pointer to partition property structure. On input, specifies which
 property to get. On output, contains the property value.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_part_get_prop(tsra_handle handle, struct tsra_part_prop *part_prop);

/*
 @brief Create a new security domain and its remote backup

 Creates a security domain under the calling session's partition from
 `params.part_policy`, using the sender's masked sealing key. The
 recipient key is recovered from the authoritative
 `params.receiver_cert_chain` (always required, anchored to the policy
 SATA key); the `params.receiver_evidence` is optional and verified only
 when the policy sets `require_trusted_sa_key`. Returns the three backups
 the firmware produces.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Create-backup input buffers
 @param[in,out] pok_remote_backup Output buffer for the remote
                partition-owner-key backup (161 B).
 @param[in,out] pok_local_backup Output buffer for the local
                partition-owner-key backup (276 B).
 @param[in,out] sd_mk_backup Output buffer for the security-domain
                masking-key backup (260 B).

 All three output buffers follow the probe/fill convention and are
 validated **before** the domain is created, so the one-shot command is
 not consumed when a buffer is too small.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `TsraSdCertChain.certs` must point to `len` valid `tsra_buffer`s.
 - Each output buffer must be a valid `tsra_buffer` with writable
   backing storage of the advertised length.
 */
tsra_status tsra_sd_create_remote_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_create_remote_backup_params *params,
    struct tsra_buffer *pok_remote_backup,
    struct tsra_buffer *pok_local_backup,
    struct tsra_buffer *sd_mk_backup
);

/*
 @brief Reseal an existing remote backup to a new recipient

 HPKE-opens `params.src_remote_backup` with the receiver's masked
 sealing key (authenticated by the source sender in `params.src_evidence`)
 and reseals the recovered backup to the destination receiver
 (`params.dest_evidence`), returning the resealed remote backup.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Reseal-backup input buffers
 @param[in,out] dst_remote_backup Output buffer for the resealed remote
                partition-owner-key backup (161 B).

 The output buffer follows the probe/fill convention and is validated
 **before** the reseal is performed.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `TsraSdCertChain.certs` must point to `len` valid `tsra_buffer`s.
 - `dst_remote_backup` must be a valid `tsra_buffer` with writable
   backing storage of the advertised length.
 */
tsra_status tsra_sd_reseal_remote_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_reseal_remote_backup_params *params,
    struct tsra_buffer *dst_remote_backup
);

/*
 @brief Restore a security domain from a remote backup

 HPKE-opens `params.src_remote_backup` with the receiver's masked sealing
 key (authenticated by the sender key recovered from
 `params.sender_cert_chain`), recovers the security-domain masking key
 from `params.prev_sd_mk_backup`, and returns the refreshed device-local
 backups.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Restore-backup input buffers
 @param[in,out] pok_local_backup Output buffer for the local
                partition-owner-key backup (276 B).
 @param[in,out] sd_mk_backup Output buffer for the security-domain
                masking-key backup (260 B).

 Both output buffers follow the probe/fill convention and are validated
 **before** the restore is performed.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `TsraSdCertChain.certs` must point to `len` valid `tsra_buffer`s.
 - Each output buffer must be a valid `tsra_buffer` with writable
   backing storage of the advertised length.
 */
tsra_status tsra_sd_restore_remote_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_restore_remote_backup_params *params,
    struct tsra_buffer *pok_local_backup,
    struct tsra_buffer *sd_mk_backup
);

/*
 @brief Create a peer-transferable backup of a security domain

 Recovers BKS3 from `params.pok_local_backup` and HPKE-Auth-seals it to
 the destination peer named by `params.dst_evidence` (authenticated by
 the sender's masked sealing key), returning the peer backup. Gated by
 the security domain's `allow_peer_cloning` policy flag.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Create-peer-backup input buffers
 @param[in,out] pok_peer_backup Output buffer for the peer
                partition-owner-key backup (161 B).

 The output buffer follows the probe/fill convention and is validated
 **before** the peer backup is created.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `TsraSdCertChain.certs` must point to `len` valid `tsra_buffer`s.
 - `pok_peer_backup` must be a valid `tsra_buffer` with writable
   backing storage of the advertised length.
 */
tsra_status tsra_sd_create_peer_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_create_peer_backup_params *params,
    struct tsra_buffer *pok_peer_backup
);

/*
 @brief Restore a security domain from a peer backup

 HPKE-opens `params.pok_peer_backup` with the receiver's masked sealing
 key (authenticated by the source peer in `params.src_evidence`), recovers
 the security-domain masking key from `params.prev_sd_mk_backup`, and
 returns the refreshed device-local backups.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Restore-backup input buffers
 @param[in,out] pok_local_backup Output buffer for the local
                partition-owner-key backup (276 B).
 @param[in,out] sd_mk_backup Output buffer for the security-domain
                masking-key backup (260 B).

 Both output buffers follow the probe/fill convention and are validated
 **before** the restore is performed.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer/evidence pointers must be valid; each
   `TsraSdCertChain.certs` must point to `len` valid `tsra_buffer`s.
 - Each output buffer must be a valid `tsra_buffer` with writable
   backing storage of the advertised length.
 */
tsra_status tsra_sd_restore_peer_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_restore_peer_backup_params *params,
    struct tsra_buffer *pok_local_backup,
    struct tsra_buffer *sd_mk_backup
);

/*
 @brief Restore a security domain from its device-local backups

 Restores the security domain from the device-local
 `params.pok_local_backup` and `params.sd_mk_backup`, returning the
 refreshed device-local backups. No attestation evidence is involved.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Restore-backup input buffers
 @param[in,out] pok_local_backup Output buffer for the refreshed local
                partition-owner-key backup (276 B).
 @param[in,out] sd_mk_backup Output buffer for the refreshed
                security-domain masking-key backup (260 B).

 Both output buffers follow the probe/fill convention and are validated
 **before** the restore is performed.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` and each of its buffer pointers must be valid.
 - Each output buffer must be a valid `tsra_buffer` with writable
   backing storage of the advertised length.
 */
tsra_status tsra_sd_restore_local_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_restore_local_backup_params *params,
    struct tsra_buffer *pok_local_backup,
    struct tsra_buffer *sd_mk_backup
);

/*
 @brief Open an HSM session

 Opens a session using the API revision that was selected when the
 partition was opened with `tsra_part_open`.

 @param[in] dev_handle Handle to the HSM partition
 @param[in] creds Pointer to the application credentials
 @param[in] seed Pointer to the optional seed buffer
 @param[out] sess_handle Pointer to the session handle to be allocated

 @return `TsraError` indicating the result of the operation

 # Safety

 - `dev_handle` must be a valid partition handle.
 - `creds` must be a valid pointer to an `TsraCredentials` structure.
 - `sess_handle` must be a valid pointer to memory where the session handle
   will be written.
 */
tsra_status tsra_sess_open(
    tsra_handle dev_handle,
    const struct tsra_credentials *creds,
    const struct tsra_buffer *seed,
    tsra_handle *sess_handle
);

/*
 @brief Close an HSM session

 @param[in] handle Handle to the HSM session

 @return `TsraError` indicating the result of the operation

 # Safety

 - `handle` must be a valid session handle previously returned by
   `tsra_sess_open`.
 - The handle must not have been previously closed.
 - After this call, the handle becomes invalid and must not be used.
 */
tsra_status tsra_sess_close(tsra_handle handle);

/*
 @brief Open a security-domain session to the device

 Opens a security-domain session using the API revision negotiated when
 the partition was opened, and returns a handle to the resulting
 session. `psk` selects the role slot and (optionally) the PSK, and
 `session_type` selects the channel integrity profile pinned for the
 session.

 @param[in] dev_handle Handle to the HSM partition
 @param[in] psk PSK credential — slot plus optional PSK
            (see `tsra_session_psk`)
 @param[in] session_type Channel integrity profile to pin for the session
 @param[out] sess_handle Pointer to the session handle to be allocated

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `dev_handle` must be a valid partition handle.
 - `psk` must be a valid pointer to an `tsra_session_psk` whose `psk`
   field is NULL or a valid `tsra_buffer` holding exactly `TSRA_PSK_LEN`
   bytes.
 - `sess_handle` must be a valid pointer to memory where the session handle
   will be written.
 */
tsra_status tsra_sess_ex_open(
    tsra_handle dev_handle,
    const struct tsra_session_psk *psk,
    tsra_session_ex_type session_type,
    tsra_handle *sess_handle
);

/*
 @brief Provision a partition's security domain

 Initializes the partition from the machine seed and unified partition
 policy, together with the partition-owner (POTA), security-administrator
 (SATA), and optional secondary-owner (SAPOTA) trust-anchor thumbprints,
 returning the partition's certificate-signing request and attestation
 report.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Provisioning input buffers
            (see `tsra_sess_ex_part_init_params`)
 @param[in,out] pta_csr Output buffer for the DER PKCS#10 CSR. On input
                `len` is the capacity; on success it is set to the number
                of bytes written. If the buffer is too small (or `ptr` is
                NULL with `len == 0`), `len` is set to the maximum possible
                output size (the buffer is validated up-front against a
                fixed wire-schema bound, so the probe reports that bound
                rather than the exact byte count for this device) and
                `TSRA_STATUS_BUFFER_TOO_SMALL` is returned **before** the
                partition is provisioned — so the standard two-call probe
                (call once with a zero-length buffer to learn the required
                capacity, then retry) is safe for this one-shot command.
                When either output buffer is too small, **both** `pta_csr`
                and `pta_report` have their `len` set to their maximum
                bound, so a single probe reports both required sizes. A
                buffer sized to that bound is always large enough; the
                `len` written on success is the exact number of bytes. A
                NULL `ptr` with a non-zero `len` is rejected with
                `TSRA_STATUS_INVALID_ARGUMENT`.
 @param[in,out] pta_report Output buffer for the attestation report, with
                the same capacity/length contract as `pta_csr`.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` must be a valid pointer to an `tsra_sess_ex_part_init_params`
   whose `mach_seed`, `part_policy`, `pota_thumbprint`, and
   `sata_thumbprint` are valid `tsra_buffer` pointers, and whose
   `sapota_thumbprint` is NULL or a valid `tsra_buffer` pointer.
 - `pta_csr` and `pta_report` must be valid pointers to distinct
   `tsra_buffer` structures with writable backing storage of the
   advertised length.
 */
tsra_status tsra_sess_ex_part_init(
    tsra_handle sess_handle,
    const struct tsra_sess_ex_part_init_params *params,
    struct tsra_buffer *pta_csr,
    struct tsra_buffer *pta_report
);

/*
 @brief Finalize a partition's security domain

 Completes provisioning started by `tsra_sess_ex_part_init`: re-supplies
 the unified partition policy and the PTA certificate chain (root to leaf),
 optionally restoring a prior `local_mk` backup, and returns the current
 `local_mk` backup envelope the firmware produced.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] params Finalization input buffers
            (see `tsra_sess_ex_part_final_params`)
 @param[in,out] local_mk_backup Output buffer for the `local_mk` backup
                envelope. On input `len` is the capacity; on success it is
                set to the number of bytes written. If the buffer is too
                small (or `ptr` is NULL with `len == 0`), `len` is set to
                the maximum possible output size and
                `TSRA_STATUS_BUFFER_TOO_SMALL` is returned **before** the
                partition is finalized, so the standard two-call probe
                (call once with a zero-length buffer to learn the required
                capacity, then retry) is safe for this one-shot command. A
                NULL `ptr` with a non-zero `len` is rejected with
                `TSRA_STATUS_INVALID_ARGUMENT`.

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `params` must be a valid pointer to an `tsra_sess_ex_part_final_params`
   whose `part_policy` is a valid `tsra_buffer` pointer, whose
   `pta_cert_chain` points to `pta_cert_chain_len` valid `tsra_buffer`s,
   and whose `prev_local_mk_backup` is NULL or a valid `tsra_buffer`
   pointer.
 - `local_mk_backup` must be a valid pointer to an `tsra_buffer` with
   writable backing storage of the advertised length.
 */
tsra_status tsra_sess_ex_part_final(
    tsra_handle sess_handle,
    const struct tsra_sess_ex_part_final_params *params,
    struct tsra_buffer *local_mk_backup
);

/*
 @brief Rotate the calling session's partition PSK

 Replaces the PSK of the slot implied by the session role (CO session
 → CO, CU session → CU) with `new_psk`, sealed under the session key.
 Required once on a fresh partition to move past the default-PSK gate
 before provisioning.

 @param[in] sess_handle Handle to the security-domain session
 @param[in] new_psk New PSK buffer; must be exactly `TSRA_PSK_LEN` (32 B)

 @return `TsraStatus` indicating the result of the operation

 # Safety

 - `sess_handle` must be a valid security-domain session handle.
 - `new_psk` must be a valid pointer to an `tsra_buffer` whose
   backing storage holds exactly `TSRA_PSK_LEN` bytes.
 */
tsra_status tsra_sess_ex_psk_change(tsra_handle sess_handle, const struct tsra_buffer *new_psk);

/*
 Get a property of a session

 @param[in] handle Handle to the session
 @param[in/out] session_prop Pointer to session property structure. On input, specifies which
 property to get. On output, contains the property value.

 @return 0 on success, or a negative error code on failure

 @internal
 # Safety
 This function is unsafe because it dereferences raw pointers.
 */
tsra_status tsra_session_get_prop(tsra_handle handle, struct tsra_session_prop *session_prop);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

#endif /* TSRA_API_H */
