# Algorithms 

Following are the support cryptographic algorithms

## Tessera Integrated HSM Masking Key Generation

WIP

## RSA PKCS#1 v1.5 Key Generation

Generates an RSA Key pair as defined in [PKCS #1: RSA Encryption Version 1.5](https://datatracker.ietf.org/doc/html/rfc2313). 
The keys are generated with public exponent of 65537.

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN`                         |
| **Params**                 | None                                                         |
| **Required Properties**    | ***Public Key Properties***                                  |
|                            | \small - `TSRA_KEY_PROP_ID_BIT_LEN`                          |
|                            | ***Private Key  Properties***                                |
|                            | \small - none                                                |
| **Contributed Properties** | ***Public Key Properties***                                  |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                            |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                             |
|                            | \small - `TSRA_KEY_PROP_PUB_KEY_INFO`                        |
|                            | ***Private Key Properties***                                 |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                            |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                             |
|                            | \small - `TSRA_KEY_PROP_PUB_KEY_INFO`                        |
| **Supported Operations**   | [tsra_key_gen_pair](#tsra_key_gen_pair)                      |
| **PKCS#11 Mechanism**      | CKM_RSA_PKCS_KEY_PAIR_GEN                             &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 Sign & Verify

The PKCS #1 v1.5 RSA algorithm, is a signing and verification mechanism based on the RSA public-key crypto system 
and the block formats initially defined in [PKCS #1: RSA Encryption Version 1.5](https://datatracker.ietf.org/doc/html/rfc2313). 
This algorithm does not compute a message digest as specified in PKCS #1 v1.5.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS`                                   |
| **Params**                 | None                                                        |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                     |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)           |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)       |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)         |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                 |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)       |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)   |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)     |
| **PKCS#11 Mechanism**      | CKM_RSA_PKCS                                         &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 SHA-1 Sign & Verify

The PKCS #1 v1.5 RSA algorithm for signing and verification with SHA-1. The algorithm performs
digest operation on the data using SHA-1 algorithm.

|                            |                                                           |
| -------------------------- | --------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_SHA1`                            |
| **Params**                 | None                                                      |
| **Required Properties**    | None                                                      |
| **Contributed Properties** | None                                                      |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                   |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)         |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)     |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)       |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)               |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)     |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update) |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)   |
| **PKCS#11 Mechanism**      | CKM_SHA1_RSA_PKCS                                  &nbsp; |


**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_SHA1,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 SHA-256 Sign & Verify

The PKCS #1 v1.5 RSA algorithm for signing and verification with SHA-256. The algorithm performs
digest operation on the data using SHA-256 algorithm.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_SHA256`                            |
| **Params**                 | None                                                        |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                     |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)           |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)       |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)         |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                 |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)       |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)   |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)     |
| **PKCS#11 Mechanism**      | CKM_SHA256_RSA_PKCS                                  &nbsp; |


**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_SHA256,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 SHA-384 Sign & Verify

The PKCS #1 v1.5 RSA algorithm for signing and verification with SHA-384. The algorithm performs
digest operation on the data using SHA-384 algorithm.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_SHA384`                            |
| **Params**                 | None                                                        |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                     |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)           |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)       |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)         |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                 |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)       |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)   |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)     |
| **PKCS#11 Mechanism**      | CKM_SHA384_RSA_PKCS                                  &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_SHA384,
    .params = NULL,
    .len = 0,
};
```

## RSA PKCS#1 v1.5 SHA-512 Sign & Verify

The PKCS #1 v1.5 RSA algorithm for signing and verification with SHA-512. The algorithm performs
digest operation on the data using SHA-512 algorithm.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_SHA512`                            |
| **Params**                 | None                                                        |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                     |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)           |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)       |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)         |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                 |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)       |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)   |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)     |
| **PKCS#11 Mechanism**      | CKM_SHA512_RSA_PKCS                                  &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_SHA512,
    .params = NULL,
    .len = 0,
};
```


## RSA PKCS#1 PSS Sign & Verify

The PKCS #1 RSA PSS is a mechanism based on the RSA public-key crypto system and the PSS block 
format defined in [PKCS #1: RSA Encryption Version 1.5](https://datatracker.ietf.org/doc/html/rfc2313).
This algorithm does not compute a message digest as specified in PKCS #1 v1.5.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_PSS`                                       |
| **Params**                 | [tsra_algo_rsa_pkcs_pss_params](#tsra_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                             |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)                   |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)               |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)                 |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                         |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)               |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)           |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)             |
| **PKCS#11 Mechanism**      | CKM_RSA_PKCS_PSS                                                    |


**Example**
```cpp
struct tsra_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = TSRA_ALGO_ID_SHA256,
    .mgf_id = TSRA_MGF1_ID_SHA256,
    .salt_len = 0,
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct tsra_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 PSS SHA-1 Sign & Verify

The PKCS#1 PSS RSA algorithm for signing and verification with SHA-1. The algorithm performs
digest operation on the data using SHA-1 algorithm.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_PSS_SHA1`                                  |
| **Params**                 | [tsra_algo_rsa_pkcs_pss_params](#tsra_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                             |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)                   |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)               |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)                 |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                         |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)               |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)           |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)             |
| **PKCS#11 Mechanism**      | CKM_SHA1_RSA_PKCS_PSS                                               |


**Example**
```cpp
// Note: hash_algo_id and mgf_id must use SHA-1   
struct tsra_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = TSRA_ALGO_ID_SHA1,
    .mgf_id = TSRA_MGF1_ID_SHA1,
    .salt_len = 0,
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct tsra_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 PSS SHA-256 Sign & Verify

The PKCS#1 PSS RSA algorithm for signing and verification with SHA-256. The algorithm performs
digest operation on the data using SHA-256 algorithm.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256`                                |
| **Params**                 | [tsra_algo_rsa_pkcs_pss_params](#tsra_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                             |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)                   |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)               |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)                 |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                         |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)               |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)           |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)             |
| **PKCS#11 Mechanism**      | CKM_SHA256_RSA_PKCS_PSS                                             |


**Example**
```cpp
// Note: hash_algo_id and mgf_id must use SHA-256   
struct tsra_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = TSRA_ALGO_ID_SHA256,
    .mgf_id = TSRA_MGF1_ID_SHA256,
    .salt_len = 0,
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct tsra_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 PSS SHA-384 Sign & Verify

The PKCS#1 PSS RSA algorithm for signing and verification with SHA-384. The algorithm performs
digest operation on the data using SHA-384 algorithm.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_PSS_SHA384`                                |
| **Params**                 | [tsra_algo_rsa_pkcs_pss_params](#tsra_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                             |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)                   |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)               |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)                 |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                         |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)               |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)           |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)             |
| **PKCS#11 Mechanism**      | CKM_SHA384_RSA_PKCS_PSS                                             |


**Example**
```cpp
// Note: hash_algo_id and mgf_id must use SHA-384   
struct tsra_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = TSRA_ALGO_ID_SHA384,
    .mgf_id = TSRA_MGF1_ID_SHA384,
    .salt_len = 0,
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct tsra_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 PSS SHA-512 Sign & Verify

The PKCS#1 PSS RSA algorithm for signing and verification with SHA-512. The algorithm performs
digest operation on the data using SHA-512 algorithm.

|                            |                                                                     |
| -------------------------- | ------------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_PSS_SHA512`                                |
| **Params**                 | [tsra_algo_rsa_pkcs_pss_params](#tsra_algo_rsa_pkcs_pss_params) |
| **Required Properties**    | None                                                                |
| **Contributed Properties** | None                                                                |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                             |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)                   |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)               |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)                 |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                         |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)               |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)           |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)             |
| **PKCS#11 Mechanism**      | CKM_SHA512_RSA_PKCS_PSS                                             |


**Example**
```cpp
// Note: hash_algo_id and mgf_id must use SHA-512   
struct tsra_algo_rsa_pkcs_pss_params params = {
    .hash_algo_id = TSRA_ALGO_ID_SHA512,
    .mgf_id = TSRA_MGF1_ID_SHA512,
    .salt_len = 0,
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_PSS,
    .params = &params,
    .len = sizeof(struct tsra_algo_rsa_pkcs_pss_params),
};
```

## RSA PKCS#1 OAEP Encrypt & Decrypt

The PKCS#1 RSA OAEP  is a multi-purpose mechanism based on the RSA public-key crypto system and the 
OAEP block format defined in PKCS#1.  It supports single-part encryption and decryption.

|                            |                                                                       |
| -------------------------- | --------------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_PKCS_OAEP`                                        |
| **Params**                 | [tsra_algo_rsa_pkcs_oaep_params](#tsra_algo_rsa_pkcs_oaep_params) |
| **Required Properties**    | None                                                                  |
| **Contributed Properties** | None                                                                  |
| **Supported Operations**   | [tsra_crypt_encrypt](#tsra_crypt_encrypt)                         |
|                            | [tsra_crypt_encrypt_init](#tsra_crypt_encrypt_init)               |
|                            | [tsra_crypt_encrypt_update](#tsra_crypt_encrypt_update)           |
|                            | [tsra_crypt_encrypt_finish](#tsra_crypt_encrypt_finish)             |
|                            | [tsra_crypt_decrypt](#tsra_crypt_decrypt)                         |
|                            | [tsra_crypt_decrypt_init](#tsra_crypt_decrypt_init)               |
|                            | [tsra_crypt_decrypt_update](#tsra_crypt_decrypt_update)           |
|                            | [tsra_crypt_decrypt_finish](#tsra_crypt_decrypt_finish)             |
| **PKCS#11 Mechanism**      | CKM_RSA_PKCS_OAEP                                                     |

**Example**
```cpp
struct tsra_buffer label = {
    .buf = NULL,
    .len = 0,
};

// Note: hash_algo_id and mgf_id must use the same hash algorithm
struct tsra_algo_rsa_pkcs_oaep_params params = {
    .hash_algo_id = TSRA_ALGO_ID_SHA256,
    .mgf_id = TSRA_MGF1_ID_SHA256,
    .label = &label,
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_PKCS_OAEP,
    .params = &params,
    .len = sizeof(struct tsra_algo_rsa_pkcs_oaep_params),
};
```

## RSA AES Key Wrap & Unwrap

The RSA AES key wrap is an algorithm based on the RSA public-key cryptos system and the AES key wrap algorithm. 
The algorithm can wrap and unwrap a target asymmetric key of any length and type using an RSA key.

- A temporary AES key is used for wrapping the target key using TSRA_ALGO_ID_AES_KEY_WRAP_KWP mechanism.
- The temporary AES key is wrapped with the wrapping RSA key using TSRA_ALGO_ID_RSA_PKCS_OAEP mechanism.

EX sessions support SHA-1, SHA-256, SHA-384, and SHA-512 for the OAEP and
MGF1 hashes, which must match. SHA-1 requires firmware with TBOR OAEP-SHA1
support and is intended for legacy compatibility; prefer SHA-2 for new
applications. This does not change legacy-session behavior.

|                            |                                                                             |
| -------------------------- | --------------------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_RSA_AES_KEY_WRAP`                                            |
| **Params**                 | [tsra_algo_rsa_aes_key_wrap_params](#tsra_algo_rsa_aes_key_wrap_params) |
| **Required Properties**    | None                                                                        |
| **Contributed Properties** | None                                                                        |
| **Supported Operations**   | [tsra_key_unwrap](#tsra_key_unwrap)                                     |
| **PKCS#11 Mechanism**      | CKM_RSA_AES_KEY_WRAP                                                        |

```cpp
struct tsra_buffer label = {
    .buf = NULL,
    .len = 0,
};

// Note: hash_algo_id and mgf_id must use the same hash algorithm
struct tsra_algo_rsa_pkcs_oaep_params oaep_params = {
    .hash_algo_id = TSRA_ALGO_ID_SHA256,
    .mgf_id = TSRA_MGF1_ID_SHA256,
    .label = &label,
};

struct tsra_algo_rsa_aes_key_wrap_params params = {
    .aes_key_bits = 256,
    .oaep_params = &oaep_params,
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_RSA_AES_KEY_WRAP,
    .params = &params,
    .len = sizeof(struct tsra_algo_rsa_aes_key_wrap_params),
};
```

## EC Key Pair Generation

The EC (also related to ECDSA) key pair generation is an algorithm, that uses the method defined
by [SEC 1: Elliptic Curve Cryptography, Version 2.0](https://www.secg.org/sec1-v2.pdf).

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `TSRA_ALGO_ID_EC_KEY_PAIR_GEN`                               |
| **Params**                 | None                                                         |
| **Required Properties**    | ***Public Key Properties***                                  |
|                            | \small - `TSRA_KEY_PROP_ID_EC_CURVE`                         |
|                            | ***Private Key  Properties***                                |
|                            | \small - none                                                |
| **Contributed Properties** | ***Public Key Properties***                                  |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                            |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                             |
|                            | \small - `TSRA_KEY_PROP_PUB_KEY_INFO`                        |
|                            | ***Private Key Properties***                                 |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                            |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                             |
|                            | \small - `TSRA_KEY_PROP_PUB_KEY_INFO`                        |
| **Supported Operations**   | [tsra_key_gen_pair](#tsra_key_gen_pair)                      |
| **PKCS#11 Mechanism**      | CKM_EC_KEY_PAIR_GEN                                   &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_EC_KEY_PAIR_GEN,
    .params = NULL,
    .len = 0,
};
```

## ECDSA Sign & Verify

ECDSA without hashing is an algorithm for single-part signatures and verification for ECDSA.

EX sessions support SHA-256, SHA-384, and SHA-512 digests on P-256, P-384,
and P-521. When the digest is longer than the curve's order, signing retains
the most significant bits as required by ECDSA; for example, P-256 with
SHA-512 uses the first 256 bits of the big-endian digest.

|                            |                                                           |
| -------------------------- | --------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_ECDSA`                                    |
| **Params**                 | None                                                      |
| **Required Properties**    | None                                                      |
| **Contributed Properties** | None                                                      |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                   |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)         |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)     |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)       |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)               |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)     |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update) |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)   |
| **PKCS#11 Mechanism**      | CKM_ECDSA                                         &nbsp;  |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_ECDSA,
    .params = NULL,
    .len = 0,
};
```

## ECDSA SHA-1 Sign & Verify

ECDSA with hashing is an algorithm for single-part & multi-part signatures and verification
for ECDSA. This mechanism computes the entire ECDSA specification, including the hashing
with SHA-1

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_ECDSA_SHA1`                                    |
| **Params**                 | None                                                           |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                        |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)              |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)          |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)            |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                    |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)          |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)      |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)        |
| **PKCS#11 Mechanism**      | CKM_ECDSA_SHA_1                                         &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_ECDSA_SHA1,
    .params = NULL,
    .len = 0,
};
```

## ECDSA SHA-256 Sign & Verify

ECDSA with hashing is an algorithm for single-part & multi-part signatures and verification
for ECDSA. This mechanism computes the entire ECDSA specification, including the hashing
with SHA-256

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `TSRA_ALGO_ID_ECDSA_SHA256`                                |
| **Params**                 | None                                                         |
| **Required Properties**    | None                                                         |
| **Contributed Properties** | None                                                         |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                      |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)            |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)        |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)          |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                  |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)        |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)    |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)      |
| **PKCS#11 Mechanism**      | CKM_ECDSA_256                                         &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_ECDSA_SHA256,
    .params = NULL,
    .len = 0,
};
```

## ECDSA SHA-384 Sign & Verify

ECDSA with hashing is an algorithm for single-part & multi-part signatures and verification
for ECDSA. This mechanism computes the entire ECDSA specification, including the hashing
with SHA-384

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `TSRA_ALGO_ID_ECDSA_SHA384`                                |
| **Params**                 | None                                                         |
| **Required Properties**    | None                                                         |
| **Contributed Properties** | None                                                         |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                      |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)            |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)        |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)          |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                  |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)        |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)    |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)      |
| **PKCS#11 Mechanism**      | CKM_ECDSA_384                                         &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_ECDSA_SHA384,
    .params = NULL,
    .len = 0,
};
```

## ECDSA SHA-512 Sign & Verify

ECDSA with hashing is an algorithm for single-part & multi-part signatures and verification
for ECDSA. This mechanism computes the entire ECDSA specification, including the hashing
with SHA-512

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `TSRA_ALGO_ID_ECDSA_SHA512`                                |
| **Params**                 | None                                                         |
| **Required Properties**    | None                                                         |
| **Contributed Properties** | None                                                         |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                      |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)            |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)        |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)          |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                  |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)        |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)    |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)      |
| **PKCS#11 Mechanism**      | CKM_ECDSA_512                                         &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_ECDSA_SHA512,
    .params = NULL,
    .len = 0,
};
```

## ECDH Derive

The elliptic curve Diffie-Hellman (ECDH) key derivation ,is an algorithm for key derivation based 
on the Diffie-Hellman version of the elliptic curve key agreement scheme, as defined in 
[SEC 1: Elliptic Curve Cryptography, Version 2.0](https://www.secg.org/sec1-v2.pdf), where each party 
contributes one key pair all using the same EC domain parameters.

|                            |                                                                 |
| -------------------------- | --------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_ECDH`                                             |
| **Params**                 | [tsra_algo_ecdh_params](#tsra_algo_ecdh_params)                 |
| **Required Properties**    | None                                                            |
| **Contributed Properties** | None                                                            |
| **Supported Operations**   | [tsra_key_derive](#tsra_key_derive)                             |
| **PKCS#11 Mechanism**      | CKM_ECDH1_DERIVE                                         &nbsp; |

**Example**

```cpp
struct tsra_algo_ecdh_params params = {
    .pub_key = pub_key,
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_ECDH,
    .params = &params,
    .len = sizeof(struct tsra_algo_ecdh_params),
};
```

## AES Key Generation

The AES key generation is a key generation algorithm for 
[NIST FIPS 197 Advanced Encryption Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf).

|                            |                                                          |
| -------------------------- | -------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_KEY_GEN`                               |
| **Params**                 | None                                                     |
| **Required Properties**    | ***Public Key Properties***                              |
|                            | \small - `TSRA_KEY_PROP_ID_BIT_LEN`                      |
|                            | ***Private Key  Properties***                            |
|                            | \small - none                                            |
| **Contributed Properties** | ***Public Key Properties***                              |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                        |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                         |
|                            | ***Private Key Properties***                             |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                        |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                         |
| **Supported Operations**   | [tsra_key_gen](#tsra_key_gen)                            |
| **PKCS#11 Mechanism**      | CKM_AES_KEY_GEN                                   &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_KEY_GEN,
    .params = NULL,
    .len = 0,
};
```

## AES CBC Encrypt & Decrypt

AES-CBC is an algorithm for symmetric block encryption as defined by
[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_CBC`                                    |
| **Params**                 | [tsra_algo_aes_cbc_params](#tsra_algo_aes_cbc_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_encrypt](#tsra_crypt_encrypt)               |
|                            | [tsra_crypt_encrypt_init](#tsra_crypt_encrypt_init)     |
|                            | [tsra_crypt_encrypt_update](#tsra_crypt_encrypt_update) |
|                            | [tsra_crypt_encrypt_finish](#tsra_crypt_encrypt_finish)   |
|                            | [tsra_crypt_decrypt](#tsra_crypt_decrypt)               |
|                            | [tsra_crypt_decrypt_init](#tsra_crypt_decrypt_init)     |
|                            | [tsra_crypt_decrypt_update](#tsra_crypt_decrypt_update) |
|                            | [tsra_crypt_decrypt_finish](#tsra_crypt_decrypt_finish)   |
| **PKCS#11 Mechanism**      | CKM_AES_CBC                                         &nbsp;  |

**Example**

```cpp
struct tsra_buffer iv = {
    .buf = some_iv,
    .len = 16,
};

struct tsra_algo_aes_cbc_params params = {
    .iv = &iv
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_CBC,
    .params = &params,
    .len = sizeof(struct tsra_algo_aes_cbc_params),
};
```

## AES CBC Pad Encrypt & Decrypt

AES-CBC is an algorithm for symmetric block encryption as defined by
[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).
This algorithm performs padding based on [PKCS#7](https://datatracker.ietf.org/doc/html/rfc2315)

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_CBC_PAD`                                |
| **Params**                 | [tsra_algo_aes_cbc_params](#tsra_algo_aes_cbc_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_encrypt](#tsra_crypt_encrypt)               |
|                            | [tsra_crypt_encrypt_init](#tsra_crypt_encrypt_init)     |
|                            | [tsra_crypt_encrypt_update](#tsra_crypt_encrypt_update) |
|                            | [tsra_crypt_encrypt_finish](#tsra_crypt_encrypt_finish)   |
|                            | [tsra_crypt_decrypt](#tsra_crypt_decrypt)               |
|                            | [tsra_crypt_decrypt_init](#tsra_crypt_decrypt_init)     |
|                            | [tsra_crypt_decrypt_update](#tsra_crypt_decrypt_update) |
|                            | [tsra_crypt_decrypt_finish](#tsra_crypt_decrypt_finish)   |
| **PKCS#11 Mechanism**      | CKM_AES_CBC_PAD                                      &nbsp; |

**Example**

```cpp
struct tsra_algo_aes_cbc_params params = {
    .iv = {0}
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_CBC_PAD,
    .params = &params,
    .len = sizeof(struct tsra_algo_aes_cbc_params),
};
```

## AES XTS Key Generation

The double-length AES-XTS key generation is an algorithm for generating double-length AES-XTS keys. 
Supported key lengths are 64 bytes. Keys are internally split into half-length sub-keys of 32 bytes.

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_XTS_KEY_GEN`                               |
| **Params**                 | None                                                         |
| **Required Properties**    | ***Public Key Properties***                                  |
|                            | \small - `TSRA_KEY_PROP_ID_BIT_LEN`                          |
|                            | ***Private Key  Properties***                                |
|                            | \small - none                                                |
| **Contributed Properties** | ***Public Key Properties***                                  |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                            |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                             |
|                            | ***Private Key Properties***                                 |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                            |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                             |
| **Supported Operations**   | [tsra_key_gen](#tsra_key_gen)                                |
| **PKCS#11 Mechanism**      | CKM_AES_XTS_KEY_GEN                                   &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_XTS_KEY_GEN,
    .params = NULL,
    .len = 0,
};
```

## AES XTS Encrypt & Decrypt

AES-XTS (XEX-based Tweaked CodeBook mode with CipherText Stealing), is an algorithm for single and multiple-part 
encryption and decryption. It is specified in [NIST SP800-38E](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38e.pdf).

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_XTS`                                    |
| **Params**                 | [tsra_algo_aes_xts_params](#tsra_algo_aes_xts_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_encrypt](#tsra_crypt_encrypt)               |
|                            | [tsra_crypt_encrypt_init](#tsra_crypt_encrypt_init)     |
|                            | [tsra_crypt_encrypt_update](#tsra_crypt_encrypt_update) |
|                            | [tsra_crypt_encrypt_finish](#tsra_crypt_encrypt_finish)   |
|                            | [tsra_crypt_decrypt](#tsra_crypt_decrypt)               |
|                            | [tsra_crypt_decrypt_init](#tsra_crypt_decrypt_init)     |
|                            | [tsra_crypt_decrypt_update](#tsra_crypt_decrypt_update) |
|                            | [tsra_crypt_decrypt_finish](#tsra_crypt_decrypt_finish)   |
| **PKCS#11 Mechanism**      | CKM_AES_XTS                                         &nbsp;  |

**Example**

```cpp
struct tsra_algo_aes_xts_params params = {
    .sector_num = {0}
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_XTS,
    .params = &params,
    .len = sizeof(struct tsra_algo_aes_xts_params),
};
```
## AES GCM Key Generation

The AES-GCM key generation is an algorithm for generating AES keys used with the GCM (Galois/Counter Mode) authenticated encryption mode as defined by [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_GCM_KEY_GEN`                               |
| **Params**                 | None                                                         |
| **Required Properties**    | ***Public Key Properties***                                  |
|                            | \small - `TSRA_KEY_PROP_ID_BIT_LEN`                          |
|                            | ***Private Key  Properties***                                |
|                            | \small - none                                                |
| **Contributed Properties** | ***Public Key Properties***                                  |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                            |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                             |
|                            | ***Private Key Properties***                                 |
|                            | \small - `TSRA_KEY_PROP_ID_CLASS`                            |
|                            | \small - `TSRA_KEY_PROP_ID_TYPE`                             |
| **Supported Operations**   | [tsra_key_gen](#tsra_key_gen)                                |
| **PKCS#11 Mechanism**      | CKM_AES_GCM_KEY_GEN                                   &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_GCM_KEY_GEN,
    .params = NULL,
    .len = 0,
};
```

## AES GCM Encrypt & Decrypt

AES-GCM is an authenticated encryption algorithm as defined by
[NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_GCM`                                    |
| **Params**                 | [tsra_algo_aes_gcm_params](#tsra_algo_aes_gcm_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_encrypt](#tsra_crypt_encrypt)               |
|                            | [tsra_crypt_encrypt_init](#tsra_crypt_encrypt_init)     |
|                            | [tsra_crypt_encrypt_update](#tsra_crypt_encrypt_update) |
|                            | [tsra_crypt_encrypt_finish](#tsra_crypt_encrypt_finish)   |
|                            | [tsra_crypt_decrypt](#tsra_crypt_decrypt)               |
|                            | [tsra_crypt_decrypt_init](#tsra_crypt_decrypt_init)     |
|                            | [tsra_crypt_decrypt_update](#tsra_crypt_decrypt_update) |
|                            | [tsra_crypt_decrypt_finish](#tsra_crypt_decrypt_finish)   |
| **PKCS#11 Mechanism**      | CKM_AES_GCM                                         &nbsp;  |

**Example**

```cpp
struct tsra_buffer aad = {
    .buf = some_aad,
    .len = aad_len,
};

struct tsra_algo_aes_gcm_params params = {
    .iv = {0},
    .tag = {0},
    .aad = &aad,
};

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_GCM,
    .params = &params,
    .len = sizeof(struct tsra_algo_aes_gcm_params),
};
```

## AES ECB Encrypt & Decrypt

AES-ECB is an algorithm for symmetric block encryption as defined by
[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

Input must be a non-empty multiple of 16 bytes; otherwise
`TSRA_STATUS_INVALID_ARGUMENT` is returned. When streaming, a trailing partial
block is rejected by the finish call. No padding is applied.

This algorithm is only supported on extended sessions opened with
[tsra_sess_ex_open](#tsra_sess_ex_open); other sessions return
`TSRA_STATUS_UNSUPPORTED_ALGORITHM`.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_ECB`                                    |
| **Params**                 | None (`params` must be NULL and `len` must be 0)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_encrypt](#tsra_crypt_encrypt)               |
|                            | [tsra_crypt_encrypt_init](#tsra_crypt_encrypt_init)     |
|                            | [tsra_crypt_encrypt_update](#tsra_crypt_encrypt_update) |
|                            | [tsra_crypt_encrypt_finish](#tsra_crypt_encrypt_finish)   |
|                            | [tsra_crypt_decrypt](#tsra_crypt_decrypt)               |
|                            | [tsra_crypt_decrypt_init](#tsra_crypt_decrypt_init)     |
|                            | [tsra_crypt_decrypt_update](#tsra_crypt_decrypt_update) |
|                            | [tsra_crypt_decrypt_finish](#tsra_crypt_decrypt_finish)   |
| **PKCS#11 Mechanism**      | CKM_AES_ECB                                         &nbsp;  |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_ECB,
    .params = NULL,
    .len = 0,
};
```

## AES CFB Encrypt & Decrypt

AES-CFB is the CFB-128 (full-block cipher feedback) mode of symmetric encryption as defined by
[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

AES-CFB is a stream mode: input of any length is accepted and the output has
the same length as the input. No padding is applied. Empty input produces empty
output.

On return, `iv` holds the last full ciphertext block processed (unchanged if
no full block was produced), so block-aligned calls can be chained. Chaining single-shot calls is only
correct when every call except the last processes a multiple of 16 bytes; to
process a message in arbitrary-length chunks, use one streaming context
(`tsra_crypt_*_init` / `_update` / `_finish`).

This algorithm is only supported on extended sessions opened with
[tsra_sess_ex_open](#tsra_sess_ex_open); other sessions return
`TSRA_STATUS_UNSUPPORTED_ALGORITHM`.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_CFB`                                    |
| **Params**                 | [tsra_algo_aes_cfb_params](#tsra_algo_aes_cfb_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_encrypt](#tsra_crypt_encrypt)               |
|                            | [tsra_crypt_encrypt_init](#tsra_crypt_encrypt_init)     |
|                            | [tsra_crypt_encrypt_update](#tsra_crypt_encrypt_update) |
|                            | [tsra_crypt_encrypt_finish](#tsra_crypt_encrypt_finish)   |
|                            | [tsra_crypt_decrypt](#tsra_crypt_decrypt)               |
|                            | [tsra_crypt_decrypt_init](#tsra_crypt_decrypt_init)     |
|                            | [tsra_crypt_decrypt_update](#tsra_crypt_decrypt_update) |
|                            | [tsra_crypt_decrypt_finish](#tsra_crypt_decrypt_finish)   |
| **PKCS#11 Mechanism**      | CKM_AES_CFB128                                         &nbsp;  |

**Example**

```cpp
struct tsra_algo_aes_cfb_params params;
memcpy(params.iv, some_iv, sizeof(params.iv));

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_CFB,
    .params = &params,
    .len = sizeof(struct tsra_algo_aes_cfb_params),
};
```

## AES OFB Encrypt & Decrypt

AES-OFB is the OFB (output feedback) mode of symmetric encryption as defined by
[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

AES-OFB is a stream mode: input of any length is accepted and the output has
the same length as the input. No padding is applied. Empty input produces empty
output.

On return, `iv` holds the last keystream block generated, so block-aligned calls can be chained. Chaining single-shot calls is only
correct when every call except the last processes a multiple of 16 bytes; to
process a message in arbitrary-length chunks, use one streaming context
(`tsra_crypt_*_init` / `_update` / `_finish`).

This algorithm is only supported on extended sessions opened with
[tsra_sess_ex_open](#tsra_sess_ex_open); other sessions return
`TSRA_STATUS_UNSUPPORTED_ALGORITHM`.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_OFB`                                    |
| **Params**                 | [tsra_algo_aes_ofb_params](#tsra_algo_aes_ofb_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_encrypt](#tsra_crypt_encrypt)               |
|                            | [tsra_crypt_encrypt_init](#tsra_crypt_encrypt_init)     |
|                            | [tsra_crypt_encrypt_update](#tsra_crypt_encrypt_update) |
|                            | [tsra_crypt_encrypt_finish](#tsra_crypt_encrypt_finish)   |
|                            | [tsra_crypt_decrypt](#tsra_crypt_decrypt)               |
|                            | [tsra_crypt_decrypt_init](#tsra_crypt_decrypt_init)     |
|                            | [tsra_crypt_decrypt_update](#tsra_crypt_decrypt_update) |
|                            | [tsra_crypt_decrypt_finish](#tsra_crypt_decrypt_finish)   |
| **PKCS#11 Mechanism**      | CKM_AES_OFB                                         &nbsp;  |

**Example**

```cpp
struct tsra_algo_aes_ofb_params params;
memcpy(params.iv, some_iv, sizeof(params.iv));

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_OFB,
    .params = &params,
    .len = sizeof(struct tsra_algo_aes_ofb_params),
};
```

## AES CTR Encrypt & Decrypt

AES-CTR is the CTR (counter) mode of symmetric encryption as defined by
[NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)

AES-CTR is a stream mode: input of any length is accepted and the output has
the same length as the input. No padding is applied. Empty input produces empty
output.

`iv` is the initial 128-bit counter block, incremented as a big-endian integer
(wrapping modulo 2^128) for each block. On return, `iv` holds the initial
counter advanced by the number of blocks processed (a trailing partial block
counts as one), so block-aligned calls can be chained. Chaining single-shot calls is only
correct when every call except the last processes a multiple of 16 bytes; to
process a message in arbitrary-length chunks, use one streaming context
(`tsra_crypt_*_init` / `_update` / `_finish`).

This algorithm is only supported on extended sessions opened with
[tsra_sess_ex_open](#tsra_sess_ex_open); other sessions return
`TSRA_STATUS_UNSUPPORTED_ALGORITHM`.

|                            |                                                             |
| -------------------------- | ----------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_AES_CTR`                                    |
| **Params**                 | [tsra_algo_aes_ctr_params](#tsra_algo_aes_ctr_params)   |
| **Required Properties**    | None                                                        |
| **Contributed Properties** | None                                                        |
| **Supported Operations**   | [tsra_crypt_encrypt](#tsra_crypt_encrypt)               |
|                            | [tsra_crypt_encrypt_init](#tsra_crypt_encrypt_init)     |
|                            | [tsra_crypt_encrypt_update](#tsra_crypt_encrypt_update) |
|                            | [tsra_crypt_encrypt_finish](#tsra_crypt_encrypt_finish)   |
|                            | [tsra_crypt_decrypt](#tsra_crypt_decrypt)               |
|                            | [tsra_crypt_decrypt_init](#tsra_crypt_decrypt_init)     |
|                            | [tsra_crypt_decrypt_update](#tsra_crypt_decrypt_update) |
|                            | [tsra_crypt_decrypt_finish](#tsra_crypt_decrypt_finish)   |
| **PKCS#11 Mechanism**      | CKM_AES_CTR                                         &nbsp;  |

**Example**

```cpp
struct tsra_algo_aes_ctr_params params;
memcpy(params.iv, some_iv, sizeof(params.iv));

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_AES_CTR,
    .params = &params,
    .len = sizeof(struct tsra_algo_aes_ctr_params),
};
```

## SHA-1 Digest

The SHA-1 is an algorithm for message digesting data. It generates a 160-bit message digest as defined in 
[FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

|                            |                                                              |
| -------------------------- | ------------------------------------------------------------ |
| **Algorithm ID**           | `TSRA_ALGO_ID_SHA1`                                        |
| **Params**                 | None                                                         |
| **Required Properties**    | None                                                         |
| **Contributed Properties** | None                                                         |
| **Supported Operations**   | [tsra_crypt_digest](#tsra_crypt_digest)                  |
|                            | [tsra_crypt_digest_init](#tsra_crypt_digest_init)        |
|                            | [tsra_crypt_digest_update](#tsra_crypt_digest_update)    |
|                            | [tsra_crypt_digest_finish](#tsra_crypt_digest_finish)      |
| **PKCS#11 Mechanism**      | CKM_SHA_1                                             &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_SHA1,
    .params = NULL,
    .len = 0,
};
```

## SHA-256 Digest

The SHA-256 is an algorithm for message digesting data. It generates a 256-bit message digest as defined in 
[FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

|                            |                                                               |
| -------------------------- | ------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_SHA256`                                       |
| **Params**                 | None                                                          |
| **Required Properties**    | None                                                          |
| **Contributed Properties** | None                                                          |
| **Supported Operations**   | [tsra_crypt_digest](#tsra_crypt_digest)                   |
|                            | [tsra_crypt_digest_init](#tsra_crypt_digest_init)         |
|                            | [tsra_crypt_digest_update](#tsra_crypt_digest_update)     |
|                            | [tsra_crypt_digest_finish](#tsra_crypt_digest_finish)       |
| **PKCS#11 Mechanism**      | CKM_SHA256                                             &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_SHA256,
    .params = NULL,
    .len = 0,
};
```

## SHA-384 Digest

The SHA-384 is an algorithm for message digesting data. It generates a 384-bit message digest as defined in 
[FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

|                            |                                                               |
| -------------------------- | ------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_SHA384`                                       |
| **Params**                 | None                                                          |
| **Required Properties**    | None                                                          |
| **Contributed Properties** | None                                                          |
| **Supported Operations**   | [tsra_crypt_digest](#tsra_crypt_digest)                   |
|                            | [tsra_crypt_digest_init](#tsra_crypt_digest_init)         |
|                            | [tsra_crypt_digest_update](#tsra_crypt_digest_update)     |
|                            | [tsra_crypt_digest_finish](#tsra_crypt_digest_finish)       |
| **PKCS#11 Mechanism**      | CKM_SHA384                                             &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_SHA384,
    .params = NULL,
    .len = 0,
};
```

## SHA-512 Digest

The SHA-512 is an algorithm for message digesting data. It generates a 512-bit message digest as defined in 
[FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

|                            |                                                               |
| -------------------------- | ------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_SHA512`                                       |
| **Params**                 | None                                                          |
| **Required Properties**    | None                                                          |
| **Contributed Properties** | None                                                          |
| **Supported Operations**   | [tsra_crypt_digest](#tsra_crypt_digest)                   |
|                            | [tsra_crypt_digest_init](#tsra_crypt_digest_init)         |
|                            | [tsra_crypt_digest_update](#tsra_crypt_digest_update)     |
|                            | [tsra_crypt_digest_finish](#tsra_crypt_digest_finish)       |
| **PKCS#11 Mechanism**      | CKM_SHA512                                             &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_SHA512,
    .params = NULL,
    .len = 0,
};
```

## HMAC SHA-1 Sign & Verify

The SHA-1 HMAC is an algorithm for signatures and verification. It uses the HMAC construction, 
based on the SHA-1 hash function.

|                            |                                                               |
| -------------------------- | ------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_HMAC_SHA1`                                    |
| **Params**                 | None                                                          |
| **Required Properties**    | None                                                          |
| **Contributed Properties** | None                                                          |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                       |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)             |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)         |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)           |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                   |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)         |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)     |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)       |
| **PKCS#11 Mechanism**      | CKM_SHA_1_HMAC                                         &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_HMAC_SHA1,
    .params = NULL,
    .len = 0,
};
```

## HMAC SHA-256 Sign & Verify

The SHA-256 HMAC is an algorithm for signatures and verification. It uses the HMAC construction, 
based on the SHA-256 hash function.

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_HMAC_SHA256`                                   |
| **Params**                 | None                                                           |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                        |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)              |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)          |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)            |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                    |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)          |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)      |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)        |
| **PKCS#11 Mechanism**      | CKM_SHA256_HMAC                                         &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_HMAC_SHA256,
    .params = NULL,
    .len = 0,
};
```

## HMAC SHA-384 Sign & Verify

The SHA-384 HMAC is an algorithm for signatures and verification. It uses the HMAC construction, 
based on the SHA-384 hash function.

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_HMAC_SHA384`                                   |
| **Params**                 | None                                                           |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                        |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)              |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)          |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)            |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                    |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)          |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)      |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)        |
| **PKCS#11 Mechanism**      | CKM_SHA384_HMAC                                         &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_HMAC_SHA384,
    .params = NULL,
    .len = 0,
};
```

## HMAC SHA-512 Sign & Verify

The SHA-512 HMAC is an algorithm for signatures and verification. It uses the HMAC construction, 
based on the SHA-512 hash function.

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_HMAC_SHA512`                                   |
| **Params**                 | None                                                           |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [tsra_crypt_sign](#tsra_crypt_sign)                        |
|                            | [tsra_crypt_sign_init](#tsra_crypt_sign_init)              |
|                            | [tsra_crypt_sign_update](#tsra_crypt_sign_update)          |
|                            | [tsra_crypt_sign_finish](#tsra_crypt_sign_finish)            |
|                            | [tsra_crypt_verify](#tsra_crypt_verify)                    |
|                            | [tsra_crypt_verify_init](#tsra_crypt_verify_init)          |
|                            | [tsra_crypt_verify_update](#tsra_crypt_verify_update)      |
|                            | [tsra_crypt_verify_finish](#tsra_crypt_verify_finish)        |
| **PKCS#11 Mechanism**      | CKM_SHA512_HMAC                                         &nbsp; |

**Example**

```cpp
struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_HMAC_SHA512,
    .params = NULL,
    .len = 0,
};
```

## HKDF Derive

HKDF derivation implements the KDF as specified in [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869).

The `hmac_algo_id` selects SHA-1, SHA-256, SHA-384, or SHA-512 as the HKDF
PRF, independently of the derived key type. SHA-1 is supported with both
legacy and EX sessions; EX requires firmware with TBOR HKDF-SHA1 support.
Prefer SHA-2 for new applications and use SHA-1 only for legacy compatibility.

|                            |                                                                |
| -------------------------- | -------------------------------------------------------------- |
| **Algorithm ID**           | `TSRA_ALGO_ID_HKDF_DERIVE`                                     |
| **Params**                 | [tsra_algo_hkdf_params](#tsra_algo_hkdf_params)                |
| **Required Properties**    | None                                                           |
| **Contributed Properties** | None                                                           |
| **Supported Operations**   | [tsra_key_derive](#tsra_key_derive)                            |
| **PKCS#11 Mechanism**      | CKM_HKDF_DERIVE                                         &nbsp; |

**Example**

```cpp
struct tsra_algo_hkdf_params params = {
    .hmac_algo_id = TSRA_ALGO_ID_HMAC_SHA512,
    .salt = NULL,
    .info = NULL,
}

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_HKDF_DERIVE,
    .params = &params,
    .len = sizeof(tsra_algo_hkdf_params),
};
```

## SP 800-108 KDF Counter Derive

SP 800-108 KDF Counter mode derivation implements the KDF as specified in
[NIST SP 800-108](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1-upd1.pdf).

|                            |                                                                          |
| -------------------------- | ------------------------------------------------------------------------ |
| **Algorithm ID**           | `TSRA_ALGO_ID_KBKDF_COUNTER_DERIVE`                                    |
| **Params**                 | [tsra_algo_kbkdf_counter_params](#tsra_algo_kbkdf_counter_params)      |
| **Required Properties**    | None                                                                     |
| **Contributed Properties** | None                                                                     |
| **Supported Operations**   | [tsra_key_derive](#tsra_key_derive)                                  |
| **PKCS#11 Mechanism**      | CKM_SP800_108_COUNTER_KDF                                         &nbsp; |

At least one of `label` / `context` must be provided; deriving with both absent is
rejected.

**Example**

```cpp
struct tsra_algo_kbkdf_counter_params params = {
    .hmac_algo_id = TSRA_ALGO_ID_HMAC_SHA512,
    .label = NULL,
    .context = NULL,
}

struct tsra_algo algo = {
    .id = TSRA_ALGO_ID_KBKDF_COUNTER_DERIVE,
    .params = &params,
    .len = sizeof(tsra_algo_kbkdf_counter_params),
};
```

\pagebreak
