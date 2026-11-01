# Key Operations

## tsra_key_gen

Generate symmetric key.

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

**AES-XTS wrapped key format**

For `TSRA_KEY_KIND_AES_XTS` (512 bits) the `wrapped_key` format depends on the
session type:

- Sessions opened with `tsra_sess_open`: a key-pair blob
  `header || wrap(K1) || wrap(K2)`, where each half is an RSA-AES-wrapped
  AES-256 key.
- Sessions opened with `tsra_sess_ex_open`: a single RSA-AES wrap of the
  64-byte key `K1 || K2` (PKCS#11 `CKK_AES_XTS`). `K1` and `K2` must differ.

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
