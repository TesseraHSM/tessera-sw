# Partition API

## tsra_part_get_list

Allocates and returns the device list.

```cpp
tsra_status tsra_part_get_list(
    tsra_handle *handle
    );
```

**Parameters**

| Parameter    | Name                              | Description                               |
| :----------- | --------------------------------- | ----------------------------------------- |
| [out] handle | [tsra_handle *](#tsra_handle)     | device list handle                 &nbsp; |

**Returns**

 `TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_part_free_list

Releases the memory allocated for device list 

```cpp
tsra_status tsra_part_free_list(
    tsra_handle handle
    );
```

**Parameters**

| Parameter   | Name                            | Description                                   |
| :---------- | ------------------------------- | --------------------------------------------- |
| [in] handle | [tsra_handle](#tsra_handle)     | handle to free                         &nbsp; |

**Returns**

 `TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_part_get_count

Get the count of the devices in the list

```cpp
tsra_u32 tsra_part_get_count(
    tsra_handle handle
    );
```

**Parameters**

| Parameter   | Name                            | Description                                   |
| :---------- | ------------------------------- | --------------------------------------------- |
| [in] handle | [tsra_handle](#tsra_handle)     | device list handle                     &nbsp; |

**Returns**

 Device count on success, 0 on failure or empty list

## tsra_part_get_info

Retrieves partition information at the given index, including the OS device path
and the supported API revision range and security-domain initialization state.

```cpp
tsra_status tsra_part_get_info(
    tsra_handle handle,
    tsra_u32 index,
    struct tsra_part_info *part_info
    );
```

**Parameters**

 | Parameter           | Name                                            | Description                               |
 | ------------------- | ----------------------------------------------- | ----------------------------------------- |
 | [in] handle         | [tsra_handle](#tsra_handle)                     | device list handle                        |
 | [in] index          | [tsra_u32](#tsra_u32)                           | index of the partition in list            |
 | [in, out] part_info | [struct tsra_part_info *](#tsra_part_info)      | partition info structure           &nbsp; |

On input, `part_info.path.len` is the capacity of the buffer pointed to by `part_info.path.str`,
expressed as a count of `tsra_char` elements (including the null terminator).
On output, `part_info.path.len` is set to the required/written count of `tsra_char` elements.
`part_info.api_rev_min`, `part_info.api_rev_max`, and `part_info.sd_initialized` are only
valid when the return status is `TSRA_STATUS_SUCCESS`.

`part_info.sd_initialized` is `true` when the security domain is initialized and `false`
otherwise, including when initialization-state reporting is unsupported.
It reflects initialization when [`tsra_part_get_list`](#tsra_part_get_list)
created the list; create a new list to refresh the value.

**Returns**

`TSRA_STATUS_SUCCESS` on success, `TSRA_STATUS_BUFFER_TOO_SMALL` if the path buffer is too
small (with `part_info.path.len` updated to the required count of elements), or a negative error code on failure

## tsra_part_open

Open a handle to the partition with a specified API revision.

The caller selects an API revision within the range reported by
[`tsra_part_get_info`](#tsra_part_get_info). All subsequent operations on
this partition handle (including sessions opened from it) will use the
selected revision.

```cpp
tsra_status tsra_part_open(
    const struct tsra_str *path,
    tsra_handle *handle,
    struct tsra_api_rev api_rev
    );

```

**Parameters**

 | Parameter    | Name                                     | Description                                          |
 | ------------ | ---------------------------------------- | ---------------------------------------------------- |
 | [in] path    | [const struct tsra_str*](#tsra_str)      | OS device path                                       |
 | [out] handle | [tsra_handle *](#tsra_handle)            | device handle                                        |
 | [in] api_rev | [struct tsra_api_rev](#tsra_api_rev)     | API revision to use for this partition handle &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, `TSRA_STATUS_UNSUPPORTED_API_REVISION` if
`api_rev` is outside the partition's supported range, or a negative error code otherwise

## tsra_owner_backup_key_config

Configuration for owner backup key (OBK) selection during partition initialization.

```cpp
struct tsra_owner_backup_key_config {
    tsra_owner_backup_key_source source;
    const struct tsra_buffer *owner_backup_key;
};
```

**Fields**

| Field             | Type                                                  | Description |
| ----------------- | ----------------------------------------------------- | ----------- |
| source            | [tsra_owner_backup_key_source](#tsra_owner_backup_key_source) | OBK source selection |
| owner_backup_key  | [struct tsra_buffer*](#tsra_buffer)               | Optional OBK buffer; required when `source` is `TSRA_OWNER_BACKUP_KEY_SOURCE_CALLER`, must be NULL otherwise |

## tsra_owner_backup_key_source

Specifies the source of the owner backup key (OBK).

```cpp
typedef enum tsra_owner_backup_key_source {
    TSRA_OWNER_BACKUP_KEY_SOURCE_CALLER = 1,
    TSRA_OWNER_BACKUP_KEY_SOURCE_TPM    = 2,
} tsra_owner_backup_key_source;
```

**Notes**
- When `source` is `TSRA_OWNER_BACKUP_KEY_SOURCE_CALLER`, `owner_backup_key` must be non-NULL and non-empty.
- When `source` is `TSRA_OWNER_BACKUP_KEY_SOURCE_TPM`, `owner_backup_key` must be NULL.

## tsra_pota_endorsement

Configuration for partition owner trust anchor (POTA) endorsement during partition initialization.

```cpp
struct tsra_pota_endorsement {
    tsra_pota_endorsement_source source;
    const struct tsra_pota_endorsement_data *endorsement;
};
```

**Fields**

| Field       | Type                                                                         | Description |
| ----------- | ---------------------------------------------------------------------------- | ----------- |
| source      | [tsra_pota_endorsement_source](#tsra_pota_endorsement_source)           | POTA endorsement source selection |
| endorsement | [struct tsra_pota_endorsement_data*](#tsra_pota_endorsement_data)       | Endorsement data; required when `source` is `TSRA_POTA_ENDORSEMENT_SOURCE_CALLER`, must be NULL otherwise |

## tsra_pota_endorsement_data

Caller-provided POTA endorsement data containing a signature and the corresponding public key.

```cpp
struct tsra_pota_endorsement_data {
    const struct tsra_buffer *signature;
    const struct tsra_buffer *public_key;
};
```

**Fields**

| Field      | Type                                    | Description |
| ---------- | --------------------------------------- | ----------- |
| signature  | [struct tsra_buffer*](#tsra_buffer) | Pointer to the signature buffer (must be non-NULL and non-empty) |
| public_key | [struct tsra_buffer*](#tsra_buffer) | Pointer to the public key buffer (must be non-NULL and non-empty) |

## tsra_pota_endorsement_source

Specifies the source of the POTA endorsement.

```cpp
typedef enum tsra_pota_endorsement_source {
    TSRA_POTA_ENDORSEMENT_SOURCE_CALLER = 1,
    TSRA_POTA_ENDORSEMENT_SOURCE_TPM    = 2,
} tsra_pota_endorsement_source;
```

**Notes**
- When `source` is `TSRA_POTA_ENDORSEMENT_SOURCE_CALLER`, `endorsement` must be non-NULL with non-empty `signature` and `public_key` buffers.
- When `source` is `TSRA_POTA_ENDORSEMENT_SOURCE_TPM`, `endorsement` must be NULL.
- Any other `source` value returns `TSRA_STATUS_INVALID_ARGUMENT`.

## tsra_part_init

Initialize a partition with credentials

```cpp
tsra_status tsra_part_init(
    tsra_handle handle,
    const struct tsra_credentials *creds,
    const struct tsra_buffer *bmk,
    const struct tsra_buffer *muk,
    const struct tsra_owner_backup_key_config *backup_key_config,
    const struct tsra_pota_endorsement *pota_endorsement,
    const struct tsra_resiliency_config *resiliency_config
    );
```

**Parameters**

| Parameter               | Name                                                                      | Description                                                      |
| ----------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| [in] handle             | [tsra_handle](#tsra_handle)                                               | device handle                                                    |
| [in] creds              | [struct tsra_credentials*](#tsra_credentials)                             | device credential                                                |
| [in] bmk                | [struct tsra_buffer*](#tsra_buffer)                                       | optional backup masking key (can be NULL)                        |
| [in] muk                | [struct tsra_buffer*](#tsra_buffer)                                       | optional masked unwrapping key (can be NULL)                     |
| [in] backup_key_config  | [struct tsra_owner_backup_key_config*](#tsra_owner_backup_key_config)     | owner backup key configuration (must be non-NULL)                |
| [in] pota_endorsement   | [struct tsra_pota_endorsement*](#tsra_pota_endorsement)                   | POTA endorsement configuration (must be non-NULL)                |
| [in] resiliency_config  | [struct tsra_resiliency_config*](#tsra_resiliency_config)                 | optional resiliency configuration (can be NULL)                  |

When `resiliency_config` is non-NULL, the SDK enables automatic retry and recovery for transient hardware resets. The caller provides storage, lock, and (optionally) POTA re-endorsement and MOBK provider callbacks. If POTA endorsement source is `TSRA_POTA_ENDORSEMENT_SOURCE_CALLER`, `pota_callback_ops` must be non-NULL. If source is `TSRA_POTA_ENDORSEMENT_SOURCE_TPM`, `pota_callback_ops` must be NULL. Similarly, if OBK source is `TSRA_OWNER_BACKUP_KEY_SOURCE_CALLER`, `mobk_callback_ops` must be non-NULL. If source is `TSRA_OWNER_BACKUP_KEY_SOURCE_TPM`, `mobk_callback_ops` must be NULL. Passing NULL for `resiliency_config` disables resiliency.

> **POTA callback:** The POTA `endorse` callback is
> invoked during resiliency recovery. The SDK retrieves the device's
> PID public key and certificate chain and passes them to the callback,
> so the implementation only needs to sign the provided key — it does
> not need to query the device. The callback is invoked while the
> partition's internal lock is held; its implementation must not call
> TSRA APIs on the same `tsra_handle` being initialized or
> restored, to avoid deadlock.
> See [`tsra_pota_callback_ops`](#tsra_pota_callback_ops)
> for details.

> **MOBK callback:** The MOBK `get_mobk` callback is invoked during
> resiliency recovery to re-provision the caller's Owner Backup Key.
> The SDK does not cache the plaintext OBK — it calls this callback
> on demand. The callback is invoked while the partition's internal
> lock is held; its implementation must not call TSRA APIs on the
> same `tsra_handle` being initialized or restored, to avoid deadlock.
> See [`tsra_mobk_callback_ops`](#tsra_mobk_callback_ops)
> for details.

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_part_close

Close partition handle

```cpp
tsra_status tsra_part_close(
    tsra_handle handle
    );

```

**Parameters**

 | Parameter    | Name                            | Description                 |
 | ------------ | ------------------------------- | --------------------------- |
 | [in] handle  | [tsra_handle](#tsra_handle)     | device handle        &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_part_get_prop

Retrieve partition property

**Properties**

| Description                                        | Type                                     | Define                                            |
| -------------------------------------------------- | ---------------------------------------- | ------------------------------------------------- |
| device type                                        | [tsra_part_type](#tsra_part_type)    | \scriptsize TSRA_PART_PROP_ID_TYPE              |
| os device path                                     | [tsra_char*](#tsra_char)             | \scriptsize TSRA_PART_PROP_ID_PATH              |
| driver version                                     | [tsra_char*](#tsra_char)             | \scriptsize TSRA_PART_PROP_ID_DRIVER_VERSION    |
| firmware version                                   | [tsra_char*](#tsra_char)             | \scriptsize TSRA_PART_PROP_ID_FIRMWARE_VERSION  |
| hardware version                                   | [tsra_char*](#tsra_char)             | \scriptsize TSRA_PART_PROP_ID_HARDWARE_VERSION  |
| pci hardware id (bus:device:function)              | [tsra_char*](#tsra_char)             | \scriptsize TSRA_PART_PROP_ID_PCI_HW_ID         |
| min api revision supported by the device           | [struct tsra_api_rev](#tsra_api_rev) | \scriptsize TSRA_PART_PROP_ID_MIN_API_REV       |
| max api revision supported by the device           | [struct tsra_api_rev](#tsra_api_rev) | \scriptsize TSRA_PART_PROP_ID_MAX_API_REV       |
| manufacturer cert chain in PEM format              | [tsra_char*](#tsra_char)             | \scriptsize TSRA_PART_PROP_ID_MANUFACTURER_CERT_CHAIN |
| partition identity (PID) public key in DER format  | uint8_t*                                 | \scriptsize TSRA_PART_PROP_ID_PART_PUB_KEY    |

```cpp
tsra_status tsra_part_get_prop(
    tsra_handle handle, 
    struct tsra_part_prop *prop
    );
```

**Parameters**

 | Parameter   | Name                                         | Description           |
 | ----------- | -------------------------------------------- | --------------------- |
 | [in] handle | [tsra_handle](#tsra_handle)              | device handle         |
 | [out] prop   | [struct tsra_part_prop *](#tsra_part_prop) | property       &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_part_reset

Clears the partition and reinitializes to factory state.

```cpp
tsra_status tsra_part_reset(
    tsra_handle handle
    );
```
**Parameters**

 | Parameter   | Name                            | Description                   |
 | ----------- | ------------------------------- | ----------------------------- |
 | [in] handle | [tsra_handle](#tsra_handle)     | device handle          &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise
