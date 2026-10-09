# Cryptographic Operations

This section discusses the various cryptographic operation that can be performed
on an established session.

## Encrypt

### tsra_crypt_encrypt

```cpp
tsra_status tsra_crypt_encrypt(
    tsra_algo *algo,
    tsra_handle key_handle,
    const tsra_buffer *plain_text,
    tsra_buffer *cipher_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] algo             | [tsra_algo *](#tsra_algo)         | algorithm params   |
 | [in] key_handle       | [tsra_handle](#tsra_handle)       | key handle         |
 | [in] plain_text       | [tsra_buffer *](#tsra_buffer)     | plain text         |
 | [in, out] cipher_text | [tsra_buffer *](#tsra_buffer)     | cipher text &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_encrypt_init

```cpp
tsra_status tsra_crypt_encrypt_init(
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] algo        | [tsra_algo *](#tsra_algo)       | algorithm params            |
 | [in] key_handle  | [tsra_handle](#tsra_handle)     | key handle       &nbsp;     |
 | [out] ctx_handle | [tsra_handle](#tsra_handle)     | context handle       &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_encrypt_update

```cpp
tsra_status tsra_crypt_encrypt_update(
    tsra_handle ctx_handle,
    const tsra_buffer *plain_text,
    tsra_buffer *cipher_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] ctx_handle       | [tsra_handle](#tsra_handle)       | context handle     |
 | [in] plain_text       | [tsra_buffer *](#tsra_buffer)     | plain text         |
 | [in, out] cipher_text | [tsra_buffer *](#tsra_buffer)     | cipher text &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_encrypt_finish

```cpp
tsra_status tsra_crypt_encrypt_finish(
    tsra_handle ctx_handle,
    tsra_buffer *cipher_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] ctx_handle       | [tsra_handle](#tsra_handle)       | context handle     |
 | [in, out] cipher_text | [tsra_buffer *](#tsra_buffer)     | cipher text &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## Decrypt

### tsra_crypt_decrypt

```cpp
tsra_status tsra_crypt_decrypt(
    tsra_algo *algo,
    tsra_handle key_handle,
    const tsra_buffer *cipher_text,
    tsra_buffer *plain_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] algo             | [tsra_algo *](#tsra_algo)         | algorithm params   |
 | [in] key_handle       | [tsra_handle](#tsra_handle)       | key handle         |
 | [in] cipher_text      | [tsra_buffer *](#tsra_buffer)     | cipher text        |
 | [in, out] plain_text  | [tsra_buffer *](#tsra_buffer)     | plain text &nbsp;  |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_decrypt_init

```cpp
tsra_status tsra_crypt_decrypt_init(
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] algo        | [tsra_algo *](#tsra_algo)       | algorithm params            |
 | [in] key_handle  | [tsra_handle](#tsra_handle)     | key handle       &nbsp;     |
 | [out] ctx_handle | [tsra_handle](#tsra_handle)     | context handle       &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_decrypt_update

```cpp
tsra_status tsra_crypt_decrypt_update(
    tsra_handle ctx_handle,
    const tsra_buffer *cipher_text,
    tsra_buffer *plain_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] ctx_handle       | [tsra_handle](#tsra_handle)       | context handle     |
 | [in] cipher_text      | [tsra_buffer *](#tsra_buffer)     | cipher text        |
 | [in, out] plain_text  | [tsra_buffer *](#tsra_buffer)     | plain text &nbsp;  |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_decrypt_finish

```cpp
tsra_status tsra_crypt_decrypt_finish(
    tsra_handle ctx_handle,
    tsra_buffer *plain_text,
    );
```

**Parameters**

 | Parameter             | Name                              | Description        |
 | --------------------- | --------------------------------- | ------------------ |
 | [in] ctx_handle       | [tsra_handle](#tsra_handle)       | context handle     |
 | [in, out] plain_text  | [tsra_buffer *](#tsra_buffer)     | cipher text &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## Sign

### tsra_crypt_sign

```cpp
tsra_status tsra_crypt_sign(
    tsra_algo *algo,
    tsra_handle key_handle,
    const tsra_buffer *data,
    tsra_buffer *sig,
    );
```

**Parameters**

 | Parameter        | Name                              | Description           |
 | ---------------- | --------------------------------- | --------------------- |
 | [in] algo        | [tsra_algo *](#tsra_algo)         | algorithm params      |
 | [in] key_handle  | [tsra_handle](#tsra_handle)       | key handle            |
 | [in] data        | [tsra_buffer *](#tsra_buffer)     | data to sign          |
 | [in, out] sig    | [tsra_buffer *](#tsra_buffer)     | signature      &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_sign_init

```cpp
tsra_status tsra_crypt_sign_init(
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] algo        | [tsra_algo *](#tsra_algo)       | algorithm params            |
 | [in] key_handle  | [tsra_handle](#tsra_handle)     | key handle       &nbsp;     |
 | [out] ctx_handle | [tsra_handle](#tsra_handle)     | context handle       &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_sign_update

```cpp
tsra_status tsra_crypt_sign_update(
    tsra_handle ctx_handle,
    const tsra_buffer *data,
    );
```

**Parameters**

 | Parameter       | Name                              | Description               |
 | --------------- | --------------------------------- | ------------------------- |
 | [in] ctx_handle | [tsra_handle](#tsra_handle)       | context handle            |
 | [in] data       | [tsra_buffer *](#tsra_buffer)     | data to sign       &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_sign_finish

```cpp
tsra_status tsra_crypt_sign_finish(
    tsra_handle ctx_handle,
    tsra_buffer *sig,
    );
```

**Parameters**

 | Parameter       | Name                              | Description               |
 | --------------- | --------------------------------- | ------------------------- |
 | [in] ctx_handle | [tsra_handle](#tsra_handle)       | context handle            |
 | [in, out] sig   | [tsra_buffer *](#tsra_buffer)     | signature          &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## Verify

### tsra_crypt_verify

```cpp
tsra_status tsra_crypt_verify(
    tsra_algo *algo,
    tsra_handle key_handle,
    const tsra_buffer *data,
    tsra_buffer *sig,
    );
```

**Parameters**

 | Parameter        | Name                              | Description           |
 | ---------------- | --------------------------------- | --------------------- |
 | [in] algo        | [tsra_algo *](#tsra_algo)         | algorithm params      |
 | [in] key_handle  | [tsra_handle](#tsra_handle)       | key handle            |
 | [in] data        | [tsra_buffer *](#tsra_buffer)     | data to sign          |
 | [in, out] sig    | [tsra_buffer *](#tsra_buffer)     | signature      &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_verify_init

```cpp
tsra_status tsra_crypt_verify_init(
    tsra_algo *algo,
    tsra_handle key_handle,
    tsra_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] algo        | [tsra_algo *](#tsra_algo)       | algorithm params            |
 | [in] key_handle  | [tsra_handle](#tsra_handle)     | key handle                  |
 | [out] ctx_handle | [tsra_handle](#tsra_handle)     | context handle       &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_verify_update

```cpp
tsra_status tsra_crypt_verify_update(
    tsra_handle ctx_handle,
    const tsra_buffer *data,
    );
```

**Parameters**

 | Parameter       | Name                              | Description               |
 | --------------- | --------------------------------- | ------------------------- |
 | [in] ctx_handle | [tsra_handle](#tsra_handle)       | context handle            |
 | [in] data       | [tsra_buffer *](#tsra_buffer)     | data to sign       &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_verify_finish

```cpp
tsra_status tsra_crypt_verify_finish(
    tsra_handle ctx_handle,
    const tsra_buffer *sig,
    );
```

**Parameters**

 | Parameter       | Name                              | Description               |
 | --------------- | --------------------------------- | ------------------------- |
 | [in] ctx_handle | [tsra_handle](#tsra_handle)       | context handle            |
 | [in, out] sig   | [tsra_buffer *](#tsra_buffer)     | signature          &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## Digest

### tsra_crypt_digest

```cpp
tsra_status tsra_crypt_digest(
    tsra_handle sess_handle,
    tsra_algo *algo,
    const tsra_buffer *data,
    tsra_buffer *digest
    );
```

**Parameters**

 | Parameter        | Name                              | Description              |
 | ---------------- | --------------------------------- | ------------------------ |
 | [in] sess_handle | [tsra_handle](#tsra_handle)       | session handle           |
 | [in] algo        | [tsra_algo *](#tsra_algo)         | algorithm params         |
 | [in] data        | [tsra_buffer *](#tsra_buffer)     | data                     |
 | [in, out] digest | [tsra_buffer *](#tsra_buffer)     | digest            &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_digest_init

```cpp
tsra_status tsra_crypt_digest_init(
    tsra_handle sess_handle,
    tsra_algo *algo,
    tsra_handle *ctx_handle
    );
```

**Parameters**

 | Parameter        | Name                            | Description                 |
 | ---------------- | ------------------------------- | --------------------------- |
 | [in] sess_handle | [tsra_handle](#tsra_handle)     | session handle              |
 | [in] algo        | [tsra_algo *](#tsra_algo)       | algorithm params            |
 | [out] ctx_handle | [tsra_handle](#tsra_handle)     | context handle       &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_digest_update

```cpp
tsra_status tsra_crypt_digest_update(
    tsra_handle ctx_handle,
    const tsra_buffer *data,
    );
```

**Parameters**

 | Parameter       | Name                              | Description                |
 | --------------- | --------------------------------- | -------------------------- |
 | [in] ctx_handle | [tsra_handle](#tsra_handle)       | context handle             |
 | [in] data       | [tsra_buffer *](#tsra_buffer)     | data                &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_crypt_digest_finish

```cpp
tsra_status tsra_crypt_digest_finish(
    tsra_handle ctx_handle,
    tsra_buffer *digest
    );
```

**Parameters**

 | Parameter        | Name                              | Description              |
 | ---------------- | --------------------------------- | ------------------------ |
 | [in] ctx_handle  | [tsra_handle](#tsra_handle)       | context handle           |
 | [in, out] digest | [tsra_buffer *](#tsra_buffer)     | digest            &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise
