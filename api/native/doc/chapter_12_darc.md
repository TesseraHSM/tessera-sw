# DARC Key-Transfer API

The DARC (Device Authentication Root Certificate) API transfers a key from a
**source** partition to a **target** partition without ever exposing it in
the clear on the host. All six commands are Crypto-Officer, in-session
commands issued on a security-domain session (opened with
[`tsra_sess_ex_open`](#tsra_sess_ex_open)); a non security-domain
session is rejected with `TSRA_STATUS_INVALID_SESSION`.

A transfer proceeds in two phases:

- **Key exchange.** Both endpoints call
  [`tsra_darc_kex_key_gen`](#tsra_darc_kex_key_gen) to mint an ephemeral
  DARC KEX key. The source mints a Transfer Masking Key (TMK) with
  [`tsra_darc_tmk_gen`](#tsra_darc_tmk_gen), seals it to the target's KEX
  key with [`tsra_darc_tmk_export`](#tsra_darc_tmk_export), and the target
  opens it with [`tsra_darc_tmk_import`](#tsra_darc_tmk_import). The sealed
  TMK is bound to both endpoints' identities via HPKE-Auth and validated
  against the certificate chains anchored in the unified partition policy.
- **Key wrap.** The source wraps the designated key under the TMK with
  [`tsra_darc_key_wrap`](#tsra_darc_key_wrap); the target unwraps and
  installs it with [`tsra_darc_key_unwrap`](#tsra_darc_key_unwrap).

None of these commands persist state on the device: the KEX keys and TMK are
returned masked under the partition SDMK and exist only for the duration of
the transfer.

## tsra_darc_kex_key_gen

Generate a DARC key-exchange (KEX) key.

Mints a new ephemeral ECC-P384 KEX key on the calling session's partition and
returns the masked private key together with its raw P-384 public key
(`x ‖ y`, 96 bytes). Run on the **target** it yields the HPKE receiver
identity; run on the **source** it yields the HPKE sender-auth identity. The
key is not stored on the device — the caller must retain the returned masked
key for the subsequent export/import call.

```cpp
tsra_status tsra_darc_kex_key_gen(
    tsra_handle sess_handle,
    uint8_t scope,
    tsra_buffer *masked_key,
    tsra_buffer *pub_key
    );
```

**Parameters**

 | Parameter          | Name                            | Description                                              |
 | ------------------ | ------------------------------- | -------------------------------------------------------- |
 | [in] sess_handle   | [tsra_handle](#tsra_handle) | security-domain session handle                           |
 | [in] scope         | uint8_t                         | requested key scope (`KeyScope` discriminant)            |
 | [in,out] masked_key| [tsra_buffer*](#tsra_buffer)| out: masked KEX private key (`MASKED_KEX_KEY_LEN`, 276 B)|
 | [in,out] pub_key   | [tsra_buffer*](#tsra_buffer)| out: raw P-384 public key (`KEX_PUB_KEY_LEN`, 96 B) &nbsp;|

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_darc_tmk_gen

Mint a DARC Transfer Masking Key (TMK).

Mints a fresh 256-bit TMK on the **source** partition and returns it masked
under the partition SDMK. The key is not stored on the device.

```cpp
tsra_status tsra_darc_tmk_gen(
    tsra_handle sess_handle,
    tsra_buffer *masked_tmk
    );
```

**Parameters**

 | Parameter          | Name                            | Description                                     |
 | ------------------ | ------------------------------- | ----------------------------------------------- |
 | [in] sess_handle   | [tsra_handle](#tsra_handle) | security-domain session handle                  |
 | [in,out] masked_tmk| [tsra_buffer*](#tsra_buffer)| out: masked TMK (`MASKED_TMK_LEN`, 260 B) &nbsp;|

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_darc_tmk_export

Seal a DARC TMK to an authenticated target.

Validates `target_cert_chain` against the `DATAPubKey` anchored in the
supplied unified partition policy, then HPKE-Auth seals the TMK to the
target's KEX key using the source's KEX key as the sender-auth identity,
returning the sealed TMK.

```cpp
tsra_status tsra_darc_tmk_export(
    tsra_handle sess_handle,
    const tsra_darc_tmk_export_params *params,
    tsra_buffer *sealed_tmk
    );
```

**Parameters**

 | Parameter          | Name                                                          | Description                                          |
 | ------------------ | ------------------------------------------------------------ | ---------------------------------------------------- |
 | [in] sess_handle   | [tsra_handle](#tsra_handle)                              | security-domain session handle                       |
 | [in] params        | const [tsra_darc_tmk_export_params*](#tsra_darc_tmk_export_params) | export input buffers                        |
 | [in,out] sealed_tmk| [tsra_buffer*](#tsra_buffer)                            | out: sealed TMK (`SEALED_TMK_LEN`, 145 B)     &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_darc_tmk_export_params

Input buffers for [`tsra_darc_tmk_export`](#tsra_darc_tmk_export).

```cpp
struct tsra_darc_tmk_export_params {
    const tsra_buffer *masked_sender_key;
    const tsra_buffer *masked_tmk;
    const tsra_buffer *policy;
    tsra_darc_cert_chain target_cert_chain;
};
```

 | Field             | Name                                                      | Description                                                  |
 | ----------------- | -------------------------------------------------------- | ------------------------------------------------------------ |
 | masked_sender_key | const [tsra_buffer*](#tsra_buffer)                   | source masked KEX key (`MASKED_KEX_KEY_LEN`, 276 B)          |
 | masked_tmk        | const [tsra_buffer*](#tsra_buffer)                   | masked TMK to export (`MASKED_TMK_LEN`, 260 B)              |
 | policy            | const [tsra_buffer*](#tsra_buffer)                   | unified partition policy image anchoring `DATAPubKey`        |
 | target_cert_chain | [tsra_darc_cert_chain](#tsra_darc_cert_chain)        | DATA-anchored target certificate chain (1–2 certs)   &nbsp; |

## tsra_darc_tmk_import

Import (open) a sealed DARC TMK on the target.

Validates `remote_cert_chain` against the `POTAPubKey` anchored in the
supplied unified partition policy, HPKE-Auth opens the sealed TMK against the
target's KEX key, and re-masks the recovered TMK under the target partition
SDMK, returning the masked TMK.

```cpp
tsra_status tsra_darc_tmk_import(
    tsra_handle sess_handle,
    const tsra_darc_tmk_import_params *params,
    tsra_buffer *masked_tmk
    );
```

**Parameters**

 | Parameter          | Name                                                          | Description                                       |
 | ------------------ | ------------------------------------------------------------ | ------------------------------------------------- |
 | [in] sess_handle   | [tsra_handle](#tsra_handle)                              | security-domain session handle                    |
 | [in] params        | const [tsra_darc_tmk_import_params*](#tsra_darc_tmk_import_params) | import input buffers                     |
 | [in,out] masked_tmk| [tsra_buffer*](#tsra_buffer)                            | out: imported masked TMK (`MASKED_TMK_LEN`, 260 B)|

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_darc_tmk_import_params

Input buffers for [`tsra_darc_tmk_import`](#tsra_darc_tmk_import).

```cpp
struct tsra_darc_tmk_import_params {
    const tsra_buffer *masked_kex_key;
    const tsra_buffer *policy;
    const tsra_buffer *sealed_tmk;
    tsra_darc_cert_chain remote_cert_chain;
};
```

 | Field             | Name                                                | Description                                                  |
 | ----------------- | --------------------------------------------------- | ------------------------------------------------------------ |
 | masked_kex_key    | const [tsra_buffer*](#tsra_buffer)              | target masked KEX key (`MASKED_KEX_KEY_LEN`, 276 B)         |
 | policy            | const [tsra_buffer*](#tsra_buffer)              | unified partition policy image anchoring `POTAPubKey`        |
 | sealed_tmk        | const [tsra_buffer*](#tsra_buffer)              | sealed TMK to open (`SEALED_TMK_LEN`, 145 B)               |
 | remote_cert_chain | [tsra_darc_cert_chain](#tsra_darc_cert_chain)   | POTA-anchored source certificate chain (1–2 certs)   &nbsp; |

## tsra_darc_key_wrap

Wrap a designated EC private key under a DARC TMK.

AES-KWP-wraps the source key's EC2 `COSE_Key` (private form) under the TMK,
returning the wrapped transport blob. The source key is supplied as a handle
(the same handle model as [`tsra_key_unwrap_pair`](#tsra_key_unwrap_pair));
its raw key material never leaves the device. The wrapped-key output follows
the probe/fill convention: pass a zero-length or undersized buffer to learn
the required size (returned in `wrapped_key.len` with
`TSRA_STATUS_BUFFER_TOO_SMALL`), then retry with a buffer of at least
`DARC_WRAP_WRAPPED_KEY_MAX_LEN` (512 B).

```cpp
tsra_status tsra_darc_key_wrap(
    tsra_handle sess_handle,
    const tsra_darc_key_wrap_params *params,
    tsra_buffer *wrapped_key
    );
```

**Parameters**

 | Parameter           | Name                                                        | Description                                                        |
 | ------------------- | ---------------------------------------------------------- | ----------------------------------------------------------------- |
 | [in] sess_handle    | [tsra_handle](#tsra_handle)                            | security-domain session handle                                    |
 | [in] params         | const [tsra_darc_key_wrap_params*](#tsra_darc_key_wrap_params) | wrap input parameters                                    |
 | [in,out] wrapped_key| [tsra_buffer*](#tsra_buffer)                          | out: wrapped key (`DARC_WRAP_WRAPPED_KEY_MAX_LEN`, ≤512 B) &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_darc_key_wrap_params

Input parameters for [`tsra_darc_key_wrap`](#tsra_darc_key_wrap).

```cpp
struct tsra_darc_key_wrap_params {
    tsra_handle source_key;
    const tsra_buffer *masked_tmk;
};
```

 | Field      | Name                                    | Description                                                          |
 | ---------- | --------------------------------------- | ------------------------------------------------------------------- |
 | source_key | [tsra_handle](#tsra_handle)         | handle to the source EC private key to export (the transferred key) |
 | masked_tmk | const [tsra_buffer*](#tsra_buffer)  | masked TMK (`MASKED_TMK_LEN`, 260 B) &nbsp;                         |

## tsra_darc_key_unwrap

Unwrap and install a transferred key pair on the target.

AES-KWP-unwraps `wrapped_key` under the TMK and installs the recovered EC key
pair, returning handles to the private and public keys (the same handle model
as [`tsra_key_unwrap_pair`](#tsra_key_unwrap_pair)). The recovered curve
is validated against `priv_key_props`.

```cpp
tsra_status tsra_darc_key_unwrap(
    tsra_handle sess_handle,
    const tsra_darc_key_unwrap_params *params,
    tsra_handle *priv_key_handle,
    tsra_handle *pub_key_handle
    );
```

**Parameters**

 | Parameter             | Name                                                          | Description                                                     |
 | --------------------- | ------------------------------------------------------------ | -------------------------------------------------------------- |
 | [in] sess_handle      | [tsra_handle](#tsra_handle)                              | security-domain session handle                                 |
 | [in] params           | const [tsra_darc_key_unwrap_params*](#tsra_darc_key_unwrap_params) | unwrap input parameters                              |
 | [out] priv_key_handle | [tsra_handle*](#tsra_handle)                            | out: handle to the recovered private key                       |
 | [out] pub_key_handle  | [tsra_handle*](#tsra_handle)                            | out: handle to the recovered public key &nbsp;                 |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_darc_key_unwrap_params

Input parameters for [`tsra_darc_key_unwrap`](#tsra_darc_key_unwrap).

```cpp
struct tsra_darc_key_unwrap_params {
    const tsra_buffer *masked_tmk;
    const tsra_buffer *wrapped_key;
    const tsra_key_prop_list *priv_key_props;
    const tsra_key_prop_list *pub_key_props;
};
```

 | Field          | Name                                          | Description                                                       |
 | -------------- | --------------------------------------------- | ---------------------------------------------------------------- |
 | masked_tmk     | const [tsra_buffer*](#tsra_buffer)        | masked TMK (`MASKED_TMK_LEN`, 260 B)                             |
 | wrapped_key    | const [tsra_buffer*](#tsra_buffer)        | wrapped key to unwrap (`DARC_UNWRAP_WRAPPED_KEY_MAX_LEN`, ≤512 B)|
 | priv_key_props | const [tsra_key_prop_list*](#tsra_key_prop_list) | requested properties for the recovered private key        |
 | pub_key_props  | const [tsra_key_prop_list*](#tsra_key_prop_list) | requested properties for the recovered public key &nbsp;  |

## tsra_darc_cert_chain

A DARC certificate chain: an array of `len` [`tsra_buffer`](#tsra_buffer)s,
each a DER-encoded certificate ordered root to leaf. The DER bytes are
borrowed for the duration of the call, not copied. A chain must contain
between 1 and 2 certificates.

```cpp
struct tsra_darc_cert_chain {
    const tsra_buffer *certs;
    uint32_t len;
};
```

 | Field | Name                                   | Description                                          |
 | ----- | -------------------------------------- | ---------------------------------------------------- |
 | certs | const [tsra_buffer*](#tsra_buffer) | array of `len` DER certificate buffers               |
 | len   | uint32_t                               | number of certificates in `certs` (1–2)      &nbsp;  |
