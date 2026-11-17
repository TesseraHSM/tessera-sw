# Key Operations

## tsra_key_gen

Generate symmetric key.

`TSRA_KEY_KIND_GENERIC_SECRET` cannot be generated. It is an import-only
key type; use RSA-AES unwrap and restore it using `tsra_key_unmask`.

```cpp
tsra_status tsra_key_gen(
    tsra_handle sess_handle,
    tsra_algo *algo,
    const tsra_key_prop_list *key_props,
    tsra_handle *key_handle
    );
```

**Parameters**

 | Parameter        | Name                                                 | Description                  |
 | ---------------- | ---------------------------------------------------- | ---------------------------- |
 | [in] sess_handle | [tsra_handle](#tsra_handle)                          | session handle               |
 | [in] algo        | [tsra_algo *](#tsra_algo)                            | algorithm params             |
 | [in] key_props   | [const tsra_key_prop_list*](#tsra_key_prop_list)     | key properties               |
 | [out] key_handle | [tsra_handle *](#tsra_handle)                        | key handle for generated key |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_key_gen_pair

Generate asymmetric key pair

```cpp
tsra_status tsra_key_gen_pair(
    tsra_handle sess_handle,
    tsra_algo *algo,
    const tsra_key_prop_list *priv_key_props,
    const tsra_key_prop_list *pub_key_props,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
    );
```

**Parameters**

 | Parameter             | Name                                                 | Description                          |
 | --------------------- | ---------------------------------------------------- | ------------------------------------ |
 | [in] sess_handle      | [tsra_handle](#tsra_handle)                          | session handle                       |
 | [in] algo             | [tsra_algo *](#tsra_algo)                            | algorithm params                     |
 | [in] priv_key_props   | [const tsra_key_prop_list*](#tsra_key_prop_list)     | private key properties               |
 | [in] pub_key_props    | [const tsra_key_prop_list*](#tsra_key_prop_list)     | public key properties                |
 | [out] priv_key_handle | [tsra_handle *](#tsra_handle)                        | key handle for generated private key |
 | [out] pub_key_handle  | [tsra_handle *](#tsra_handle)                        | key handle for generated public key  |

**Notes**

- `priv_key_handle` and `pub_key_handle` must point to distinct output addresses.
- Passing the same pointer for both outputs returns `TSRA_STATUS_INVALID_ARGUMENT`.

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_key_unwrap_pair

Unwrap a key pair.

```cpp
tsra_status tsra_key_unwrap_pair(
    tsra_algo *algo,
    tsra_handle unwrapping_key,
    const tsra_buffer *wrapped_key,
    const tsra_key_prop_list *priv_key_props,
    const tsra_key_prop_list *pub_key_props,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
    );
```

**Parameters**

 | Parameter             | Name                                                 | Description                          |
 | --------------------- | ---------------------------------------------------- | ------------------------------------ |
 | [in] algo             | [tsra_algo *](#tsra_algo)                            | algorithm params                     |
 | [in] unwrapping_key   | [tsra_handle](#tsra_handle)                          | unwrapping key handle                |
 | [in] wrapped_key      | [const tsra_buffer *](#tsra_buffer)                  | wrapped key pair                     |
 | [in] priv_key_props   | [const tsra_key_prop_list*](#tsra_key_prop_list)     | private key properties               |
 | [in] pub_key_props    | [const tsra_key_prop_list*](#tsra_key_prop_list)     | public key properties                |
 | [out] priv_key_handle | [tsra_handle *](#tsra_handle)                        | key handle for unwrapped private key |
 | [out] pub_key_handle  | [tsra_handle *](#tsra_handle)                        | key handle for unwrapped public key  |

**Notes**

- `priv_key_handle` and `pub_key_handle` must point to distinct output addresses.
- Passing the same pointer for both outputs returns `TSRA_STATUS_INVALID_ARGUMENT`.

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_key_unwrap

Unwrap a key.

```cpp
tsra_status tsra_key_unwrap(
    tsra_handle sess_handle,
    tsra_algo *algo,
    tsra_handle unwrapping_key,
    const tsra_buffer *wrapped_key,
    const tsra_key_prop_list *key_props,
    tsra_handle *key_handle
    );
```

**Parameters**

 | Parameter           | Name                                                 | Description                  |
 | ------------------- | ---------------------------------------------------- | ---------------------------- |
 | [in] sess_handle    | [tsra_handle](#tsra_handle)                          | session handle               |
 | [in] algo           | [tsra_algo *](#tsra_algo)                            | algorithm params             |
 | [in] unwrapping_key | [tsra_handle](#tsra_handle)                          | unwrapping key handle        |
 | [in] wrapped_key    | [tsra_buffer *](#tsra_buffer)                        | wrapped key                  |
 | [in] key_props      | [const tsra_key_prop_list*](#tsra_key_prop_list)     | key properties               |
 | [out] key_handle    | [tsra_handle *](#tsra_handle)                        | key handle for unwrapped key |

### Generic Secret Wrapped Key Format

Set CLASS to `TSRA_KEY_CLASS_SECRET`, KIND to `TSRA_KEY_KIND_GENERIC_SECRET`,
and BIT_LEN to a multiple of 8 from 128 through 1024 (16-128 bytes).
DERIVE must be true; SIGN, VERIFY, ENCRYPT, DECRYPT, WRAP, and UNWRAP
must be false, and EC_CURVE must be absent. The recovered plaintext is
the raw secret bytes, not ASN.1. Its actual length must match BIT_LEN.
The key is imported (`LOCAL` is false) and is usable only as a KBKDF base key.

Use the existing `TSRA_ALGO_ID_RSA_AES_KEY_WRAP` algorithm:
`RSA-OAEP(KEK) || AES-KWP(secret)`. Both legacy and EX sessions support
generic-secret import and authenticated unmasking with matching firmware.
KBKDF itself remains legacy/MBOR-only.

The 16-128 byte range and import-only policy are TSRA restrictions, not
PKCS#11 requirements. PKCS#11 generic secrets have no universal numeric
size range and may also be generated or derived. TSRA ECDH results remain
the distinct `TSRA_KEY_KIND_SHARED_SECRET` type and cannot be relabeled
as generic secrets.

**AES-XTS wrapped key format**

For `TSRA_KEY_KIND_AES_XTS` (512 bits) the `wrapped_key` format depends on the
session type:

- Sessions opened with `tsra_sess_open`: a key-pair blob
  `header || wrap(K1) || wrap(K2)`, where each half is an RSA-AES-wrapped
  AES-256 key.
- Sessions opened with `tsra_sess_ex_open`: a single RSA-AES wrap of the
  64-byte key `K1 || K2` (PKCS#11 `CKK_AES_XTS`). `K1` and `K2` must differ.

### HMAC Wrapped Key Format

HMAC key unwrapping requires a session opened with `tsra_sess_ex_open`,
available from API revision 1.1. Legacy sessions opened with `tsra_sess_open`
do not support this operation, even when using API revision 1.1.
Set CLASS to `TSRA_KEY_CLASS_SECRET` and select the matching KIND and BIT_LEN:

| KIND | BIT_LEN | Raw Key Length |
| ---- | ------- | -------------- |
| `TSRA_KEY_KIND_HMAC_SHA256` | 256 | 32 bytes |
| `TSRA_KEY_KIND_HMAC_SHA384` | 384 | 48 bytes |
| `TSRA_KEY_KIND_HMAC_SHA512` | 512 | 64 bytes |

Both SIGN and VERIFY must be true. ENCRYPT, DECRYPT, DERIVE, WRAP, and UNWRAP
must be false, and ECC_CURVE must be absent. Unsupported sizes or usage
properties return `TSRA_STATUS_INVALID_KEY_PROPS`.

The wrapped plaintext is the raw HMAC key, not an ASN.1 structure. Use
`TSRA_ALGO_ID_RSA_AES_KEY_WRAP` to unwrap the RSA-OAEP-wrapped AES key followed
by the AES-KWP-wrapped HMAC key material. The resulting handle supports
`tsra_crypt_sign` and `tsra_crypt_verify`; its MASKED_KEY property can be
restored using `tsra_key_unmask` with the same HMAC key kind.

Legacy sessions return `TSRA_STATUS_UNSUPPORTED_KEY_OPERATION` for otherwise
valid HMAC unwrap properties, regardless of the negotiated API revision.

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_key_unmask

Reconstruct a symmetric or shared-secret key from its masked blob.

```cpp
tsra_status tsra_key_unmask(
    tsra_handle sess_handle,
    tsra_key_kind key_kind,
    const tsra_buffer *masked_key,
    tsra_handle *key_handle
    );
```

**Parameters**

 | Parameter        | Name                                | Description                       |
 | ---------------- | ----------------------------------- | --------------------------------- |
 | [in] sess_handle | [tsra_handle](#tsra_handle)          | session handle                    |
 | [in] key_kind    | tsra_key_kind                       | supported symmetric/secret kind   |
 | [in] masked_key  | [const tsra_buffer *](#tsra_buffer) | masked key blob                   |
 | [out] key_handle | [tsra_handle *](#tsra_handle)       | handle for the reconstructed key  |

**Authentication**

- A legacy session authenticates and imports the key into the device.
- An extended session authenticates the blob on the device with TBOR
  `VerifyKey` (AEAD tag over the metadata and key material, and the session
  binding of session-scoped blobs), then returns an unpinned host handle. No
  device-resident key is created.
- A blob with a modified tag, metadata, or key material, or a session-scoped
  blob supplied to another session, fails with
  `TSRA_STATUS_MASKED_KEY_AUTHENTICATION_FAILED`.

Requesting `TSRA_KEY_KIND_SHARED_SECRET` for an authenticated AES or HMAC blob
returns `TSRA_STATUS_INVALID_KEY_PROPS`. Restore these keys using their
corresponding AES or HMAC key kinds instead.

**Returns**

`TSRA_STATUS_SUCCESS` on successful reconstruction, error code otherwise.

## tsra_key_unmask_pair

Unmask a key pair.

```cpp
tsra_status tsra_key_unmask_pair(
    tsra_handle sess_handle,
    tsra_key_kind key_kind,
    const tsra_buffer *masked_key,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
    );
```

**Parameters**

 | Parameter             | Name                                    | Description                         |
 | --------------------- | --------------------------------------- | ----------------------------------- |
 | [in] sess_handle      | [tsra_handle](#tsra_handle)             | session handle                      |
 | [in] key_kind         | tsra_key_kind                           | key kind to unmask (RSA or ECC)     |
 | [in] masked_key       | [const tsra_buffer *](#tsra_buffer)     | masked key pair                     |
 | [out] priv_key_handle | [tsra_handle *](#tsra_handle)           | key handle for unmasked private key |
 | [out] pub_key_handle  | [tsra_handle *](#tsra_handle)           | key handle for unmasked public key  |

**Notes**

- `priv_key_handle` and `pub_key_handle` must point to distinct output addresses.
- Passing the same pointer for both outputs returns `TSRA_STATUS_INVALID_ARGUMENT`.
- On an extended session the device authenticates the masked key and
  returns its public key; no device-resident key is created.

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_key_derive

Derive a key from an existing key.

```cpp
tsra_status tsra_key_derive(
    tsra_handle sess_handle,
    tsra_algo *algo,
    tsra_handle base_key,
    const tsra_key_prop_list *key_props,
    tsra_handle *key_handle
    );
```

**Parameters**

 | Parameter        | Name                                                 | Description                |
 | ---------------- | ---------------------------------------------------- | -------------------------- |
 | [in] sess_handle | [tsra_handle](#tsra_handle)                          | session handle             |
 | [in] algo        | [tsra_algo *](#tsra_algo)                            | algorithm params           |
 | [in] base_key    | [tsra_handle](#tsra_handle)                          | base key handle            |
 | [in] key_props   | [const tsra_key_prop_list*](#tsra_key_prop_list)     | key properties             |
 | [out] key_handle | [tsra_handle *](#tsra_handle)                        | key handle for derived key |

**Output key properties**

HKDF and KBKDF support AES and HMAC outputs. Each key type validates its
properties before DDI dispatch: AES requires 128, 192, or 256 bits and both
ENCRYPT and DECRYPT; HMAC requires the size matching its SHA variant and both
SIGN and VERIFY. Other operation permissions and ECC_CURVE must be absent,
and CLASS must be `TSRA_KEY_CLASS_SECRET`.

Invalid output properties, including unsupported output key kinds and invalid
sizes, return `TSRA_STATUS_INVALID_KEY_PROPS` before transport-specific checks.
This replaces the previous DDI-dependent errors for those cases.

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_key_delete

Delete a key.

```cpp
tsra_status tsra_key_delete(
    tsra_handle key,
    );
```

**Parameters**

 | Parameter        | Name                            | Description                   |
 | ---------------- | ------------------------------- | ----------------------------- |
 | [in] key         | [tsra_handle](#tsra_handle)     | key to delete         &nsbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_key_get_prop

Get key property.

```cpp
tsra_status tsra_key_get_prop(
    tsra_handle key,
    tsra_key_prop *key_prop,
    );
```

**Parameters**

 | Parameter          | Name                                  | Description                   |
 | ------------------ | ------------------------------------- | ----------------------------- |
 | [in] key           | [tsra_handle](#tsra_handle)           | key to delete         &nsbsp; |
 | [in, out] key_prop | [tsra_key_prop *](#tsra_key_prop)     | key property to retrieve      |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_key_set_prop

Set key property.

```cpp
tsra_status tsra_key_set_prop(
    tsra_handle sess_handle,
    tsra_handle key,
    const tsra_key_prop *key_prop,
    );
```

**Parameters**

 | Parameter        | Name                                  | Description                   |
 | ---------------- | ------------------------------------- | ----------------------------- |
 | [in] sess_handle | [tsra_handle](#tsra_handle)           | session handle                |
 | [in] key         | [tsra_handle](#tsra_handle)           | key to delete         &nsbsp; |
 | [in] key_prop    | [tsra_key_prop *](#tsra_key_prop)     | key property to set           |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise
