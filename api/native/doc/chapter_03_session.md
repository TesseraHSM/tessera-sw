# Session API

## tsra_sess_open

Open a session to the device. Session is required to perform
cryptographic commands.

The session uses the API revision that was selected when the partition
was opened with [`tsra_part_open`](#tsra_part_open).

```cpp
tsra_status tsra_sess_open(
    tsra_handle dev_handle,
    const struct tsra_credentials *creds,
    const struct tsra_buffer *seed,
    tsra_handle *sess_handle
    );
```

**Parameters**

 | Parameter         | Name                                              | Description                                      |
 | ----------------- | ------------------------------------------------- | ------------------------------------------------ |
 | [in] dev_handle   | [tsra_handle](#tsra_handle)                       | device handle                                    |
 | [in] creds        | [struct tsra_credentials*](#tsra_credentials)     | application credential                           |
 | [in] seed         | [struct tsra_buffer*](#tsra_buffer)               | optional seed buffer (can be NULL)               |
 | [out] sess_handle | [tsra_handle *](#tsra_handle)                     | new session handle                               |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_sess_close

Close a session

```cpp
tsra_status tsra_sess_close(
    tsra_handle handle
    );
```

**Parameters**

 | Parameter   | Name                            | Description            |
 | ----------- | ------------------------------- | ---------------------- |
 | [in] handle | [tsra_handle](#tsra_handle)     | session handle  &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_sess_set_pin

This method changes the device PIN. Once the pin is change successfully a new
session must be open

```cpp
tsra_status tsra_sess_set_pin(
    tsra_handle handle, 
    const tsra_buffer *new_pin
    );
```

**Parameters**

 | Parameter    | Name                            | Description                |
 | ------------ | ------------------------------- | -------------------------- |
 | [in] handle  | [tsra_handle](#tsra_handle)     | session handle             |
 | [in] new_pin | [tsra_buffer](#tsra_buffer)     | new_pin             &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_session_get_prop

Retrieve session property

**Properties**

| Description                               | Type                                     | Define                                      |
| ----------------------------------------- | ---------------------------------------- | ------------------------------------------- |
| api revision negotiated for the session   | [struct tsra_api_rev](#tsra_api_rev)     | \scriptsize TSRA_SESSION_PROP_ID_API_REV    |

```cpp
tsra_status tsra_session_get_prop(
    tsra_handle handle, 
    struct tsra_session_prop *prop
    );
```

**Parameters**

 | Parameter       | Name                                                 | Description           |
 | --------------- | ---------------------------------------------------- | --------------------- |
 | [in] handle     | [tsra_handle](#tsra_handle)                          | session handle        |
 | [in, out] prop  | [struct tsra_session_prop *](#tsra_session_prop)     | property       &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

\pagebreak
