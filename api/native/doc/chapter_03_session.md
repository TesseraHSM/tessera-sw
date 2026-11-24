# Session API

## tsra_sess_open

Open a session to the device. Session is required to perform
cryptographic commands.

The session uses the API revision that was selected when the partition
was opened with [`tsra_part_open`](#tsra_part_open).

Not supported at API revision 2.0 (it fails with an error status); use
[`tsra_sess_ex_open`](#tsra_sess_ex_open) instead.
That API requires an independently provisioned SHA-384 fingerprint of the
trusted root certificate's DER SubjectPublicKeyInfo; see the security-domain
session documentation for its certificate-path and Tessera profile requirements.

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

## tsra_sess_ex_reopen

Recover a migrated security-domain session in place, keeping its original
masking key so existing session-masked keys remain usable. The SDK retains
the original seed securely and shares its open handshake implementation with
reopen. Supply the trusted root's 48-byte SHA-384 SPKI fingerprint and the
current role PSK (32 bytes), or NULL for the role's public default. A
migration returns the PSKs to their public defaults, so pass NULL unless a
session has rotated the role PSK since.

```cpp
tsra_status tsra_sess_ex_reopen(
    tsra_handle sess_handle,
    const struct tsra_buffer *root_spki_thumbprint,
    const struct tsra_buffer *psk
    );
```

Reopen establishes fresh transport and parameter keys and does not replay an
interrupted command. The migration restored the session's
one-successful-PSK-change allowance, so a session reopened under the default
PSK rotates its role PSK before other commands. An Active session cannot be
reopened. Failed recovery can be retried on the same handle. Rust callers use
`HsmSession::reopen_ex`.

After live migration, session commands report
`TSRA_STATUS_SESSION_NEEDS_RENEGOTIATION` rather than a generic transport failure.
This is an unauthenticated recovery hint, not an authenticated command result.

`tsra_sess_ex_psk_change` rebinds its calling CO or CU session to the new PSK
and AppId without reopening. A second successful change on the same logical
session is rejected with `TSRA_STATUS_PSK_CHANGE_ALREADY_USED`; failed or rolled-back
attempts do not consume the allowance. Peer sessions are not upgraded.

## tsra_sess_close

Close a session. A migrated TBOR session may be closed without reopening:
the SDK uses explicit plaintext cleanup only after renegotiation is reported.
Active and Pending TBOR sessions still require protected close. MBOR behavior
is unchanged.

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

Security-domain backup creation, resealing, and restoration use the session's
negotiated API revision. It can differ from the revision
selected when the partition handle was opened.

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
