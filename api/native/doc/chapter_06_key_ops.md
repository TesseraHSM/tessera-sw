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

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

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
