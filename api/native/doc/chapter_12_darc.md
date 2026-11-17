# DARC Key-Transfer API

The DARC (Device Authentication Root Certificate) API transfers a key from a
**source** partition to a **target** partition without ever exposing it in
the clear on the host. All six commands are Crypto-Officer, in-session
commands issued on a security-domain session (opened with
[`tsra_sess_ex_open`](#tsra_sess_ex_open)); a non security-domain
session is rejected with `TSRA_STATUS_INVALID_SESSION`.

A transfer proceeds in two phases:

- **TMK transfer.** The target calls
  [`tsra_darc_kex_key_gen`](#tsra_darc_kex_key_gen) to mint an ephemeral
  DARC KEX key. The source mints a Transfer Masking Key (TMK) with
  [`tsra_darc_tmk_gen`](#tsra_darc_tmk_gen), seals it to the target's KEX
  key with [`tsra_darc_tmk_export`](#tsra_darc_tmk_export), and the target
  opens it with [`tsra_darc_tmk_import`](#tsra_darc_tmk_import). The sealed
  TMK uses P-384 HPKE Base (HKDF-SHA384, AES-256-GCM). A separate
  PID-signed `Darc` report binds the source PID, recipient key, and exact
  encrypted envelope. DATA authorizes the recipient KEX; POTA authorizes
  the source PID report signer. No source KEX key is required.
- **Key wrap.** The source wraps the designated key under the TMK with
  [`tsra_darc_key_wrap`](#tsra_darc_key_wrap); the target unwraps and
  installs it with [`tsra_darc_key_unwrap`](#tsra_darc_key_unwrap).

None of these commands persist state on the device: the KEX keys and TMK are
returned as masked blobs, not stored on the device. The caller retains them
for subsequent transfer commands.

## tsra_darc_kex_key_gen

Generate a DARC key-exchange (KEX) key.

Mints a new ephemeral ECC-P384 KEX key on the calling session's partition and
returns the masked private key together with its raw P-384 public key
(`x ‖ y`, 96 bytes, big-endian per coordinate — the certificate-leaf form). Run on the **target** it yields the HPKE receiver
identity. Outgoing transfers use the source PID for report signing. The
key is not stored on the device — the caller must retain the returned masked
key for the subsequent import call.

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
 | [in,out] masked_key| [tsra_buffer*](#tsra_buffer)| out: masked KEX private key (`MASKED_KEX_KEY_LEN`, 280 B)|
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
 | [in,out] masked_tmk| [tsra_buffer*](#tsra_buffer)| out: masked TMK (`MASKED_TMK_LEN`, 264 B) &nbsp;|

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_darc_tmk_export

Seal a DARC TMK to an authenticated target.

Validates `target_cert_chain` against the `data_spki_thumbprint` anchored in the
supplied unified partition policy, then HPKE Base seals the TMK to the
target's KEX key and signs a v2 `Darc` operation report with the source PID.
The canonical 113-byte header binds the source PID and recipient key IDs
and is used as both HPKE `info` and AEAD AAD. The report binds the same IDs
and a SHA-384 digest of the entire encrypted envelope.

```cpp
tsra_status tsra_darc_tmk_export(
    tsra_handle sess_handle,
    const tsra_darc_tmk_export_params *params,
    tsra_buffer *sealed_tmk,
    tsra_buffer *report
    );
```

**Parameters**

 | Parameter          | Name                                                          | Description                                          |
 | ------------------ | ------------------------------------------------------------ | ---------------------------------------------------- |
 | [in] sess_handle   | [tsra_handle](#tsra_handle)                              | security-domain session handle                       |
 | [in] params        | const [tsra_darc_tmk_export_params*](#tsra_darc_tmk_export_params) | export input buffers                        |
 | [in,out] sealed_tmk| [tsra_buffer*](#tsra_buffer)                            | out: canonical encrypted TMK (`SEALED_TMK_LEN`, 258 B) |
 | [in,out] report    | [tsra_buffer*](#tsra_buffer)                            | out: required PID-signed operation report (at most 896 B) |

Both outputs follow probe/fill: provide distinct `tsra_buffer` objects
with zero-length buffers to obtain required capacities of 258 and 896
bytes with `TSRA_STATUS_BUFFER_TOO_SMALL`, then retry. On success,
`report.len` is the actual report size. Persist and transport the envelope
and report together.

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_darc_tmk_export_params

Input buffers for [`tsra_darc_tmk_export`](#tsra_darc_tmk_export).

```cpp
struct tsra_darc_tmk_export_params {
    const tsra_buffer *masked_tmk;
    const tsra_buffer *policy;
    tsra_darc_cert_chain target_cert_chain;
};
```

 | Field             | Name                                                      | Description                                                  |
 | ----------------- | -------------------------------------------------------- | ------------------------------------------------------------ |
 | masked_tmk        | const [tsra_buffer*](#tsra_buffer)                   | masked TMK to export (`MASKED_TMK_LEN`, 264 B)              |
 | policy            | const [tsra_buffer*](#tsra_buffer)                   | unified partition policy image anchoring `data_spki_thumbprint`        |
 | target_cert_chain | [tsra_darc_cert_chain](#tsra_darc_cert_chain)        | DATA-anchored target certificate chain (1–2 certs)   &nbsp; |

## tsra_darc_tmk_import

Import (open) a sealed DARC TMK on the target.

Validates `remote_cert_chain` against the `pota_spki_thumbprint` anchored in the
supplied unified partition policy, authorizing the terminal source PID
public key. It verifies the `Darc` report signature, kind, source,
actual recipient, and envelope digest before HPKE Base opening.
It then re-masks the recovered TMK under the target partition SDMK.

The normal source chain has three certificates: POTA root, PTA
intermediate, PID leaf. The source partition's certificate slot 2
provides the PTA-signed PID leaf; append it to the endorsed PTA chain.
A generic public-key report cannot authorize a transfer. Reports do not
themselves provide replay protection or certificate freshness.

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
 | [in,out] masked_tmk| [tsra_buffer*](#tsra_buffer)                            | out: imported masked TMK (`MASKED_TMK_LEN`, 264 B)|

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_darc_tmk_import_params

Input buffers for [`tsra_darc_tmk_import`](#tsra_darc_tmk_import).

```cpp
struct tsra_darc_tmk_import_params {
    const tsra_buffer *masked_kex_key;
    const tsra_buffer *policy;
    const tsra_buffer *sealed_tmk;
    const tsra_buffer *report;
    tsra_darc_cert_chain remote_cert_chain;
};
```

 | Field             | Name                                                | Description                                                  |
 | ----------------- | --------------------------------------------------- | ------------------------------------------------------------ |
 | masked_kex_key    | const [tsra_buffer*](#tsra_buffer)              | target masked KEX key (`MASKED_KEX_KEY_LEN`, 280 B)         |
 | policy            | const [tsra_buffer*](#tsra_buffer)              | unified partition policy image anchoring `pota_spki_thumbprint`        |
 | sealed_tmk        | const [tsra_buffer*](#tsra_buffer)              | canonical encrypted TMK (`SEALED_TMK_LEN`, 258 B)          |
 | report            | const [tsra_buffer*](#tsra_buffer)              | PID-signed `Darc` report returned with `sealed_tmk` (1..=896 B) |
 | remote_cert_chain | [tsra_darc_cert_chain](#tsra_darc_cert_chain)   | POTA-anchored source PID certificate chain (1..=3 certs) |

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
 | masked_tmk | const [tsra_buffer*](#tsra_buffer)  | masked TMK (`MASKED_TMK_LEN`, 264 B) &nbsp;                         |

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
 | masked_tmk     | const [tsra_buffer*](#tsra_buffer)        | masked TMK (`MASKED_TMK_LEN`, 264 B)                             |
 | wrapped_key    | const [tsra_buffer*](#tsra_buffer)        | wrapped key to unwrap (`DARC_UNWRAP_WRAPPED_KEY_MAX_LEN`, ≤512 B)|
 | priv_key_props | const [tsra_key_prop_list*](#tsra_key_prop_list) | requested properties for the recovered private key        |
 | pub_key_props  | const [tsra_key_prop_list*](#tsra_key_prop_list) | requested properties for the recovered public key &nbsp;  |

## tsra_darc_cert_chain

A DARC certificate chain: an array of `len` [`tsra_buffer`](#tsra_buffer)s,
each a DER-encoded certificate ordered root to leaf. The DER bytes are
borrowed for the duration of the call, not copied. A chain must contain
between 1 and 2 certificates for export (DATA-authorized recipient),
or 1 and 3 for import (POTA-authorized source PID).

```cpp
struct tsra_darc_cert_chain {
    const tsra_buffer *certs;
    uint32_t len;
};
```

 | Field | Name                                   | Description                                          |
 | ----- | -------------------------------------- | ---------------------------------------------------- |
 | certs | const [tsra_buffer*](#tsra_buffer) | array of `len` DER certificate buffers               |
 | len   | uint32_t                               | certificate count (1..=2 for export; 1..=3 for import) |
