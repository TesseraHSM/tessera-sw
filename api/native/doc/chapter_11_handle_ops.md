# Handle Operations

## tsra_free_ctx_handle

Free a streaming context handle

```cpp
tsra_status tsra_free_ctx_handle(
    tsra_handle handle
    );
```

**Parameters**

 | Parameter   | Name                            | Description                   |
 | ----------- | ------------------------------- | ----------------------------- |
 | [in] handle | [tsra_handle](#tsra_handle)     | context handle to free &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

**Description**

This function releases a context handle (digest, sign, verify, encrypt, decrypt, HMAC sign, HMAC verify, RSA sign, or RSA verify) and frees all associated resources. The handle is invalidated and must not be used after this call.

Callers **must** call `tsra_free_ctx_handle` for every valid context handle once it is no longer needed, whether the multi-step operation completed successfully, was abandoned due to an error, or was never fully executed.