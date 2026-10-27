# Data Structures

## Typedefs

### tsra_byte

Boolean type

```cpp
typedef uint8_t tsra_byte;
```

### tsra_u8

Unsigned 8-bit integer

```cpp
typedef uint8_t tsra_u8;
```

### tsra_u16

Unsigned 16-bit integer

```cpp
typedef uint16_t tsra_u16;
```

### tsra_u32

Unsigned 32-bit integer

```cpp
typedef uint32_t tsra_u32;
```

### tsra_64

Unsigned 64-bit integer

```cpp
typedef uint64_t tsra_u64;
```

### tsra_void

Void type

```cpp
typedef void tsra_void;
```

### tsra_bool

Boolean type

```cpp
typedef uint32_t tsra_bool;
```
Possible values are defined by [TSRA_BOOL_XXX](#tsra_bool_xxx)

### tsra_handle

Handle type

```cpp
typedef uint32_t tsra_handle;
```

### tsra_char

Character type

```cpp
#if !defined(_WIN32)
    typedef char tsra_char;
#endif

#if defined(_WIN32)
    typedef wchar tsra_char;
#endif
```
### tsra_utf8_char

UTF-8 Character type

```cpp
typedef unsigned char tsra_utf8_char;
```

### tsra_part_type

Device type

```cpp
typedef uint32_t tsra_part_type;
```

Possible values are defined by [TSRA_PART_TYPE_XXX](#tsra_part_type_xxx)

### tsra_part_prop_id

Device property id type

```cpp
typedef uint32_t tsra_part_prop_id;
```

Possible values are defined by [TSRA_PART_PROP_ID_XXX](#tsra_part_prop_id_xxx)

### tsra_key_class

Key class type

```cpp
typedef uint32_t tsra_key_class;
```

Possible values are defined by [TSRA_KEY_CLASS_XXX](#tsra_key_class_xxx)

### tsra_key_type

Key type type

```cpp
typedef uint32_t tsra_key_type;
```

Possible values are defined by [TSRA_KEY_TYPE_XXX](#tsra_key_type_xxx)

### tsra_key_prop_id

Key Property ID type

```cpp
typedef uint32_t tsra_key_prop_id;
```

Possible values are defined by [TSRA_KEY_PROP_ID_XXX](#tsra_key_prop_id_xxx)

### tsra_algo_id

Algorithm ID type

```cpp
typedef uint32_t tsra_algo_id;
```

Possible values are defined by [TSRA_ALGO_ID_XXX](#tsra_algo_id_xxx)

### tsra_ec_curve_id

Elliptic Curve ID type

```cpp
typedef uint32_t tsra_ec_curve_id;
```

Possible values are defined by [TSRA_EC_CURVE_ID_XXX](#tsra_ec_curve_id_xxx)


### tsra_mgf1_id

Mask Generation Function ID type

```cpp
typedef uint32_t tsra_mgf1_id;
```

Possible values are defined by [TSRA_MGF1_ID_XXX](#tsra_mgf1_id_xxx)

### tsra_sess_type

Session kind type

```cpp
typedef uint32_t tsra_sess_type;
```

Possible values are defined by [TSRA_SESS_TYPE_XXX](#tsra_sess_type_xxx)

### tsra_session_ex_type

Security-domain session channel integrity profile

```cpp
typedef uint32_t tsra_session_ex_type;
```

Possible values are defined by [TSRA_SESSION_EX_TYPE_XXX](#tsra_session_ex_type_xxx)


<!--

### tsra_cert_chain_id

Certificate chain ID type

```cpp
typedef uint32_t tsra_cert_chain_id;
```

Possible values are defined by [TSRA_CERT_CHAIN_ID_XXX](#tsra_cert_chain_id_xxx)

-->

## Defines

### TSRA_BOOL_XXX

Boolean values

```cpp
#define TSRA_BOOL_FALSE 0
#define TSRA_BOOL_TRUE 1
```

### TSRA_PART_PROP_ID_XXX

Device property identifiers

```cpp
#define TSRA_PART_PROP_ID_TYPE 1
#define TSRA_PART_PROP_ID_PATH 2
#define TSRA_PART_PROP_ID_DRIVER_VERSION 3
#define TSRA_PART_PROP_ID_FIRMWARE_VERSION 4
#define TSRA_PART_PROP_ID_HARDWARE_VERSION 5
#define TSRA_PART_PROP_ID_PCI_HW_ID 6
#define TSRA_PART_PROP_ID_MIN_API_REV 7
#define TSRA_PART_PROP_ID_MAX_API_REV 8
#define TSRA_PART_PROP_ID_MANUFACTURER_CERT_CHAIN 9
#define TSRA_PART_PROP_ID_BACKUP_MASKING_KEY 10
#define TSRA_PART_PROP_ID_MASKED_OWNER_BACKUP_KEY 11
#define TSRA_PART_PROP_ID_PART_PUB_KEY 12
```

### TSRA_PART_TYPE_XXX

Device type values

```cpp
#define TSRA_PART_TYPE_VIRTUAL 1
#define TSRA_PART_TYPE_PHYSICAL 2
```

### TSRA_KEY_CLASS_XXX

Key class type values

```cpp
#define TSRA_KEY_CLASS_PRIVATE 1
#define TSRA_KEY_CLASS_PUBLIC 2
#define TSRA_KEY_CLASS_SECRET 3
```

### TSRA_KEY_TYPE_XXX

Key type values

```cpp
#define TSRA_KEY_TYPE_RSA 1
#define TSRA_KEY_TYPE_EC 2
#define TSRA_KEY_TYPE_AES 3
#define TSRA_KEY_TYPE_AES_XTS 4
#define TSRA_KEY_TYPE_AES_GCM 5
#define TSRA_KEY_TYPE_GENERIC 6
#define TSRA_KEY_TYPE_HMAC_SHA1 7
#define TSRA_KEY_TYPE_HMAC_SHA256 8
#define TSRA_KEY_TYPE_HMAC_SHA384 9
#define TSRA_KEY_TYPE_HMAC_SHA512 10
#define TSRA_KEY_TYPE_MASKING 11
```

### TSRA_KEY_PROP_ID_XXX

Key property ID type values

```cpp
#define TSRA_KEY_PROP_ID_CLASS 1
#define TSRA_KEY_PROP_ID_KIND 2
#define TSRA_KEY_PROP_ID_BIT_LEN 3
#define TSRA_KEY_PROP_ID_LABEL 4
#define TSRA_KEY_PROP_PUB_KEY_INFO 5
#define TSRA_KEY_PROP_ID_EC_CURVE 6
#define TSRA_KEY_PROP_ID_MASKED_KEY 7
#define TSRA_KEY_PROP_ID_SESSION 8
#define TSRA_KEY_PROP_ID_LOCAL 9
#define TSRA_KEY_PROP_ID_SENSITIVE 10
#define TSRA_KEY_PROP_ID_EXTRACTABLE 11
#define TSRA_KEY_PROP_ID_ENCRYPT 12
#define TSRA_KEY_PROP_ID_DECRYPT 13
#define TSRA_KEY_PROP_ID_SIGN 14
#define TSRA_KEY_PROP_ID_VERIFY 15
#define TSRA_KEY_PROP_ID_WRAP 16
#define TSRA_KEY_PROP_ID_UNWRAP 17
#define TSRA_KEY_PROP_ID_DERIVE 18
```

### TSRA_ALGO_ID_XXX

Algorithm ID type values

```cpp
#define TSRA_ALGO_ID_MASKING_KEY_GEN 0x00000001
#define TSRA_ALGO_ID_MASKING_KEYWRAP 0x00000002
#define TSRA_ALGO_ID_RSA_PKCS_KEY_PAIR_GEN 0x00010001
#define TSRA_ALGO_ID_RSA_PKCS 0x00010002
#define TSRA_ALGO_ID_RSA_PKCS_SHA1 0x00010003
#define TSRA_ALGO_ID_RSA_PKCS_SHA256 0x00010004
#define TSRA_ALGO_ID_RSA_PKCS_SHA384 0x00010005
#define TSRA_ALGO_ID_RSA_PKCS_SHA512 0x00010006
#define TSRA_ALGO_ID_RSA_PKCS_PSS 0x00010007
#define TSRA_ALGO_ID_RSA_PKCS_PSS_SHA1 0x00010008
#define TSRA_ALGO_ID_RSA_PKCS_PSS_SHA256 0x00010009
#define TSRA_ALGO_ID_RSA_PKCS_PSS_SHA384 0x0001000A
#define TSRA_ALGO_ID_RSA_PKCS_PSS_SHA512 0x0001000B
#define TSRA_ALGO_ID_RSA_PKCS_OAEP 0x0001000C
#define TSRA_ALGO_ID_RSA_PKCS 0x0001000D
#define TSRA_ALGO_ID_RSA_AES_KEY_WRAP 0x0001000E
#define TSRA_ALGO_ID_EC_KEY_PAIR_GEN 0x00020001
#define TSRA_ALGO_ID_ECDSA 0x00020002
#define TSRA_ALGO_ID_ECDSA_SHA1 0x00020003
#define TSRA_ALGO_ID_ECDSA_SHA256 0x00020004
#define TSRA_ALGO_ID_ECDSA_SHA384 0x00020005
#define TSRA_ALGO_ID_ECDSA_SHA512 0x00020006
#define TSRA_ALGO_ID_ECDH 0x00020007
#define TSRA_ALGO_ID_AES_KEY_GEN 0x00030001
#define TSRA_ALGO_ID_AES_CBC 0x00030002
#define TSRA_ALGO_ID_AES_CBC_PAD 0x00030003
#define TSRA_ALGO_ID_AES_XTS_KEY_GEN 0x00030004
#define TSRA_ALGO_ID_AES_XTS 0x00030005
#define TSRA_ALGO_ID_AES_GCM_KEY_GEN 0x00030006
#define TSRA_ALGO_ID_AES_GCM 0x00030007
#define TSRA_ALGO_ID_SHA1 0x00040001
#define TSRA_ALGO_ID_SHA256 0x00040002
#define TSRA_ALGO_ID_SHA384 0x00040003
#define TSRA_ALGO_ID_SHA512 0x00040004
#define TSRA_ALGO_ID_HMAC_SHA1 0x00050001
#define TSRA_ALGO_ID_HMAC_SHA256 0x00050002
#define TSRA_ALGO_ID_HMAC_SHA384 0x00050003
#define TSRA_ALGO_ID_HMAC_SHA512 0x00050004
#define TSRA_ALGO_ID_HKDF_DERIVE 0x00060001
#define TSRA_ALGO_ID_KBKDF_COUNTER_DERIVE 0x00060002
#define TSRA_ALGO_ID_SD_SEALING_KEY_GEN 0x00070001
```

### TSRA_MGF1_ID_XXX

```cpp
#define TSRA_MGF1_ID_SHA256 1
#define TSRA_MGF1_ID_SHA384 2
#define TSRA_MGF1_ID_SHA512 3
```
### TSRA_EC_CURVE_ID_XXX

```cpp
#define TSRA_EC_CURVE_ID_P256 1
#define TSRA_EC_CURVE_ID_P384 2
#define TSRA_EC_CURVE_ID_P521 3
```

### TSRA_SESS_TYPE_XXX

```cpp
#define TSRA_SESS_TYPE_CLEAR 1
#define TSRA_SESS_TYPE_AUTHENTICATED 2
#define TSRA_SESS_TYPE_ENCRYPTED 3
```

### TSRA_SESSION_EX_TYPE_XXX

Security-domain session channel integrity profile values

```cpp
#define TSRA_SESSION_EX_TYPE_PLAIN_TEXT 0
#define TSRA_SESSION_EX_TYPE_AUTHENTICATED 1
```

<!-- 
### TSRA_CERT_CHAIN_ID_XXX

```cpp
#define TSRA_CERT_CHAIN_ID_MANUFACTURER 1
#define TSRA_CERT_CHAIN_ID_DEV_OWNER 2
#define TSRA_CERT_CHAIN_ID_PART_OWNER 3
```
 -->

## Structures

### tsra_part_prop

```cpp
struct tsra_part_prop {
    tsra_part_prop_id id;
    tsra_void *val;
    tsra_u32 len;
};
```

**Fields**

 | Field | Type                                        | Description                                    |
 | ----- | ------------------------------------------- | ---------------------------------------------- |
 | id    | [tsra_part_prop_id](#tsra_part_prop_id)     | [device property id](#tsra_part_prop_id_xxx)   |
 | val   | [tsra_void *](#tsra_void)                   | value of the property.                         |
 | len   | [tsra_u32](#tsra_u32)                       | size of the `val` field in bytes               |

### tsra_str

A sized string buffer.

```cpp
struct tsra_str {
    tsra_char *str;
    tsra_u32 len;
};
```

**Fields**

 | Field | Type                            | Description                                        |
 | ----- | ------------------------------- | -------------------------------------------------- |
 | str   | [tsra_char *](#tsra_char)  | pointer to string buffer                           |
 | len   | [tsra_u32](#tsra_u32)      | length of the string (including null terminator)   |

### tsra_part_info

Partition information returned by [`tsra_part_get_info`](#tsra_part_get_info).

```cpp
struct tsra_part_info {
    struct tsra_str path;
    struct tsra_api_rev api_rev_min;
    struct tsra_api_rev api_rev_max;
    bool sd_initialized;
};
```

**Fields**

 | Field       | Type                                     | Description                                         |
 | ----------- | ---------------------------------------- | --------------------------------------------------- |
 | path        | [struct tsra_str](#tsra_str)         | device path (caller-owned buffer, filled by the API) |
 | api_rev_min | [struct tsra_api_rev](#tsra_api_rev) | minimum supported API revision                      |
 | api_rev_max | [struct tsra_api_rev](#tsra_api_rev) | maximum supported API revision                      |
 | sd_initialized | bool                                  | whether the security domain is initialized; false when unsupported |

On input, `path.len` is the capacity of the caller-allocated buffer pointed to by `path.str`,
in `tsra_char` elements (including the null terminator).
On output, `path.len` is set to the number of `tsra_char` elements written
(or the required count when `TSRA_STATUS_BUFFER_TOO_SMALL` is returned).
`api_rev_min`, `api_rev_max`, and `sd_initialized` are only valid when the return status is
`TSRA_STATUS_SUCCESS`. Initialization is captured when `tsra_part_get_list` creates the list;
create a new list to refresh it.

Adding `sd_initialized` changes the structure layout. C callers must be recompiled against
the updated header.

### tsra_api_rev

API Revision

 ```cpp
struct tsra_api_rev {
    uint32_t major;
    uint32_t minor;
};
```

**Fields**

 | Field | Type | Description                                                 |
 | ----- | ---- | ----------------------------------------------------------- |
 | minor | u32  | minor version                                               |
 | major | u32  | major version                                        &nbsp; |


### tsra_uuid

UUID

 ```cpp
struct tsra_uuid{
    tsra_byte bytes[16];
};
```

**Fields**

 | Field | Type                            | Description                     |
 | ----- | ------------------------------- | ------------------------------- |
 | bytes | [tsra_byte[16]](#tsra_byte)     | uuid bytes               &nbsp; |


### tsra_credentials

Application credential

```cpp
struct tsra_credentials {
    uint8_t id[16];
    uint8_t pin[16];
};

```

**Fields**

 | Field | Type        | Description                                                   |
 | ----- | ----------- | ------------------------------------------------------------- |
 | id    | uint8_t[16] | application id                                                |
 | pin   | uint8_t[16] | application pin                                        &nbsp; |


### tsra_buffer

A sized buffer

```cpp
struct tsra_buffer{
  tsra_byte *ptr;
  tsra_u32 len;
};

```

**Fields**

 | Field | Type                         | Description                                                       |
 | ----- | ---------------------------- | ----------------------------------------------------------------- |
 | ptr   | [tsra_byte*](#tsra_byte)     | pointer to buffer                                                 |
 | len   | [tsra_u32](#tsra_u32)        | length of the buffer                                       &nbsp; |


### tsra_key_prop

Key property

```cpp
struct tsra_key_prop {
    tsra_key_prop_id id;
    tsra_void* val;
    tsra_u32 len;
};

```

**Fields**

 | Field | Type                                      | Description                                |
 | ----- | ----------------------------------------- | ------------------------------------------ |
 | id    | [tsra_key_prop_id](#tsra_key_prop_id)     | [key property id](#tsra_key_prop_id_xxx)   |
 | val   | [tsra_void *](#tsra_void)                 | key property value                         |
 | len   | [tsra_u32](#tsra_u32)                     | size of the `val` field in bytes           |

### tsra_key_prop_list

Key property list

```cpp
struct tsra_key_prop_list {
    tsra_key_prop* props;
    tsra_u32 count;
};
```

**Fields**

 | Field | Type                                  | Description                    |
 | ----- | ------------------------------------- | ------------------------------ |
 | props | [tsra_key_prop *](#tsra_key_prop)     | key property list              |
 | count | [tsra_u32](#tsra_u32)                 | count of properties in `props` |

### tsra_algo

Crypto algorithm

```cpp
struct tsra_algo {
    tsra_algo_id id;
    tsra_void* params;
    tsra_u32 len;
};

```

**Fields**

 | Field  | Type                              | Description                         |
 | ------ | --------------------------------- | ----------------------------------- |
 | id     | [tsra_algo_id](#tsra_algo_id)     | [algorithm id](#tsra_algo_id_xxx)   |
 | params | [tsra_void *](#tsra_void)         | algorithm parameters                |
 | len    | [tsra_u32](#tsra_u32)             | size of the `param` field in bytes  |


### tsra_algo_rsa_pkcs_pss_params

RSA PSS Algorithm parameters.

```cpp
struct tsra_algo_rsa_pkcs_pss_params {
    tsra_algo_id hash_algo_id;
    tsra_mgf1_id mgf_id;
    tsra_u32 salt_len;
};

```

**Fields**

 | Field        | Type                              | Description                                        |
 | ------------ | --------------------------------- | -------------------------------------------------- |
 | hash_algo_id | [tsra_algo_id](#tsra_algo_id)     | [hash algorithm id](#tsra_algo_id_xxx)             |
 | mgf1         | [tsra_mgf1_id](#tsra_mgf1_id)     | [mask generation function id](#tsra_mgf1_id_xxx)   |
 | salt_len     | [tsra_u32](#tsra_u32)             | salt length                                        |

### tsra_algo_rsa_pkcs_oaep_params

RSA OAEP Algorithm parameters.

`hash_algo_id` and `mgf_id` must use the same hash function.

```cpp
struct tsra_algo_rsa_pkcs_oaep_params {
    tsra_algo_id hash_algo_id;
    tsra_mgf1_id mgf_id;
    const tsra_buffer *label;
};
```

**Fields**

 | Field        | Type                              | Description                                        |
 | ------------ | --------------------------------- | -------------------------------------------------- |
 | hash_algo_id | [tsra_algo_id](#tsra_algo_id)     | [hash algorithm id](#tsra_algo_id_xxx)             |
 | mgf1         | [tsra_mgf1_id](#tsra_mgf1_id)     | [mask generation function id](#tsra_mgf1_id_xxx)   |
 | label        | [tsra_buffer *](#tsra_buffer)     | label                                              |


### tsra_algo_rsa_aes_key_wrap_params

RSA AES Key wrap parameters.

```cpp
struct tsra_algo_rsa_aes_key_wrap_params {
    tsra_u32 aes_key_bits;
    tsra_algo_rsa_pkcs_oaep_params *oaep_params;
};
```

| Field        | Type                               | Description                    |
| ------------ | ---------------------------------- | ------------------------------ |
| aes_key_bits | [tsra_u32](#tsra_u32)              | length of the AES key in bits. |
|              |                                    | can be only 128, 192 or 256    |
| oaep_params  | tsra_algo_rsa_pkcs_oaep_params *   | OAEP parameters                |

### tsra_algo_echd_params

ECDH Algorithm parameters

Parameters for ECDH Algorithm

```cpp
struct tsra_algo_ecdh_params {
    tsra_buffer *pub_key;
};
```

| Field   | Type                              | Description                           |
| ------- | --------------------------------- | ------------------------------------- |
| pub_key | [tsra_buffer *](#tsra_buffer)     | public key of the initiator    &nbsp; |

### tsra_algo_aes_cbc_params

Parameters for AES CBC Algorithm

```cpp
struct tsra_algo_aes_cbc_params {
    tsra_buffer *iv;
};
```

| Field | Type                              | Description                                       |
| ----- | --------------------------------- | ------------------------------------------------- |
| iv    | [tsra_buffer *](#tsra_buffer)     | initialization vector. must be 16 bytes    &nbsp; |

### tsra_algo_aes_gcm_params

Parameters for AES GCM Algorithm

```cpp
struct tsra_algo_aes_gcm_params {
    uint8_t iv[12];
    uint8_t tag[16];
    tsra_buffer *aad;
};
```

| Field | Type                              | Description                                                               |
| ----- | --------------------------------- | ------------------------------------------------------------------------- |
| iv    | uint8_t[12]                       | initialization vector. must be 12 bytes                            &nbsp; |
| tag   | uint8_t[16]                       | authentication tag (16 bytes). required for decrypt                &nbsp; |
| aad   | [tsra_buffer *](#tsra_buffer)     | additional authenticated data (optional). may be NULL             &nbsp;  |


### tsra_algo_aes_xts_params

Parameters for AES XTS Algorithm

```cpp
struct tsra_algo_aes_xts_params {
    uint8_t sector_num[16];
    uint32_t data_unit_length;
};
```

| Field            | Type     | Description                                                           |
| ---------------- | -------  | --------------------------------------------------------------------- |
| sector_num       | uint8_t  | sector or data unit sequence number                            &nbsp; |
| data_unit_length | uint32_t | data unit length                                               &nbsp; |


### tsra_resiliency_storage_ops

Storage callbacks for resiliency.

```cpp
struct tsra_resiliency_storage_ops {
    tsra_status (*read)(void *ctx, const char *key, tsra_buffer *value);
    tsra_status (*write)(void *ctx, const char *key, const tsra_buffer *value);
    tsra_status (*clear)(void *ctx, const char *key);
};
```

| Field | Type             | Description                                                                 |
| ----- | ---------------- | --------------------------------------------------------------------------- |
| read  | function pointer | Read data for the given key. Returns `TSRA_STATUS_NOT_FOUND` when key does not exist. Uses two-call buffer pattern. |
| write | function pointer | Write data for the given key (create or overwrite).                         |
| clear | function pointer | Delete data for the given key. No error if key doesn't exist.               |

### tsra_resiliency_lock_ops

Lock callbacks for cross-process/thread restore coordination.

```cpp
struct tsra_resiliency_lock_ops {
    tsra_status (*lock)(void *ctx);
    tsra_status (*unlock)(void *ctx);
};
```

| Field  | Type             | Description                                              |
| ------ | ---------------- | -------------------------------------------------------- |
| lock   | function pointer | Acquire the lock. Blocks until available. Non-reentrant. |
| unlock | function pointer | Release the lock.                                        |

### tsra_pota_callback_ops

POTA re-endorsement callback for resiliency.

```cpp
struct tsra_pota_callback_ops {
    tsra_status (*endorse)(void *ctx,
                              const tsra_buffer *pota_pub_key_der,
                              const tsra_buffer *pid_pub_key_der,
                              const tsra_buffer *pid_cert_chain_pem,
                              tsra_buffer *signature,
                              tsra_buffer *endorsement_pub_key);
};
```

| Field              | Type             | Description                                                                        |
| ------------------ | ---------------- | ---------------------------------------------------------------------------------- |
| endorse            | function pointer | Sign the device's PID public key for POTA endorsement. The SDK retrieves the PID public key and certificate chain from the device and passes them via `pid_pub_key_der` and `pid_cert_chain_pem` respectively. `pota_pub_key_der` is the caller's original endorsement public key, passed for identification. `pid_cert_chain_pem` contains the PEM-encoded PID certificate chain. Uses two-call buffer pattern for `signature` and `endorsement_pub_key` outputs. |

### tsra_mobk_callback_ops

MOBK (Masked Owner Backup Key) provider callback for resiliency.

```cpp
struct tsra_mobk_callback_ops {
    tsra_status (*get_mobk)(void *ctx, tsra_buffer *mobk);
};
```

| Field    | Type             | Description                                                                                                      |
| -------- | ---------------- | ---------------------------------------------------------------------------------------------------------------- |
| get_mobk | function pointer | Return the caller's MOBK. Uses the two-call buffer pattern for `mobk`: first call with `mobk->ptr == NULL` returns the required size in `mobk->len` and `TSRA_STATUS_BUFFER_TOO_SMALL`; second call fills the buffer. Called during resiliency restore so the SDK can retrieve the MOBK without caching the key material. |

### tsra_resiliency_config

Resiliency configuration passed to `tsra_part_init`.

```cpp
struct tsra_resiliency_config {
    void *ctx;
    tsra_resiliency_storage_ops storage_ops;
    tsra_resiliency_lock_ops lock_ops;
    const tsra_pota_callback_ops *pota_callback_ops;
    const tsra_mobk_callback_ops *mobk_callback_ops;
};
```

| Field              | Type                                                              | Description                                                                                   |
| ------------------ | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| ctx                | void *                                                            | Opaque context pointer passed to every callback. Caller-owned; must remain valid until `tsra_part_close` returns. The SDK never dereferences `ctx` itself — it is passed opaquely to each callback. **Must not** store or reference the same `tsra_handle` being initialized — callbacks are invoked while the partition's internal lock is held, so calling back into the same partition will deadlock. |
| storage_ops        | [tsra_resiliency_storage_ops](#tsra_resiliency_storage_ops)   | Storage callbacks (required).                                                                 |
| lock_ops           | [tsra_resiliency_lock_ops](#tsra_resiliency_lock_ops)         | Lock callbacks (required).                                                                    |
| pota_callback_ops  | [tsra_pota_callback_ops *](#tsra_pota_callback_ops)           | POTA callback (NULL when POTA source is TPM; required when source is Caller).                 |
| mobk_callback_ops  | [tsra_mobk_callback_ops *](#tsra_mobk_callback_ops)           | MOBK callback (NULL when OBK source is TPM; required when source is Caller).                  |

All callbacks must be thread-safe — they may be called concurrently from multiple threads.

### tsra_algo_hkdf_params

Parameters for HKDF Algorithm

```cpp
struct tsra_algo_hkdf_params {
    tsra_algo_id hmac_algo_id;
    tsra_buffer *salt;
    tsra_buffer *info;
};
```

| Field        | Type                              | Description                                      |
| ------------ | --------------------------------- | ------------------------------------------------ |
| hmac_algo_id | [tsra_algo_id](#tsra_algo_id)     | HMAC algorithm                            &nbsp; |
| salt         | [tsra_buffer *](#tsra_buffer)     | salt                                             |
| info         | [tsra_buffer *](#tsra_buffer)     | info                                             |

### tsra_algo_kbkdf_counter_params

Parameters for SP 800-108 Counter KDF Algorithm

At least one of `label` / `context` must be provided; deriving with both absent is
rejected.

```cpp
struct tsra_algo_kbkdf_counter_params {
    tsra_algo_id hmac_algo_id;
    tsra_buffer *label;
    tsra_buffer *context;
};
```

| Field        | Type                              | Description                                      |
| ------------ | --------------------------------- | ------------------------------------------------ |
| hmac_algo_id | [tsra_algo_id](#tsra_algo_id)     | HMAC algorithm                            &nbsp; |
| label        | [tsra_buffer *](#tsra_buffer)     | Optional label (at least one of label/context)   |
| context      | [tsra_buffer *](#tsra_buffer)     | Optional context (at least one of label/context) |
