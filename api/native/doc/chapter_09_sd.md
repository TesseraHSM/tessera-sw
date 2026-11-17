# Security Domain API

The security-domain (SD) API opens a session to a partition and provisions
its security domain. A security-domain session (opened with
[`tsra_sess_ex_open`](#tsra_sess_ex_open)) is required to issue the
provisioning command in this chapter.

### Partition policy

Partition init/final, the security-domain backup operations, and the DARC
TMK export/import take the partition policy as an opaque byte buffer
(`&[u8]` in Rust, `tsra_buffer*` in C). Policy remains an explicit
per-call input; partition and session opening are unchanged.

The policy is a deterministic CBOR document of at most 384 bytes
(`PART_POLICY_MAX_LEN`); the schema is specified in
`docs/tbor-ddi/part_policy.md`. Public keys are named by thumbprint: the
SHA-384 of the key's DER SubjectPublicKeyInfo. Callers may encode the
document themselves or use the
[partition policy builder](#partition-policy-builder) (`PartPolicyBuilder`
in Rust).

The host checks only the length: an empty policy or one longer than
384 bytes is rejected with `TSRA_STATUS_INVALID_ARGUMENT` once the output
buffers are sufficiently sized, so size probes still report
`TSRA_STATUS_BUFFER_TOO_SMALL`. Firmware decodes and validates the
document and rejects a malformed or non-canonical policy.

### Masked sealing-key metadata

The host masked-key decoder recognizes the SD sealing-key metadata kind and
validates the envelope shape. Decoding alone does not authenticate the blob;
on an extended session, `HsmSealingKeyUnmaskAlgo` authenticates it on the
device with TBOR `VerifyKey`, so a tampered or wrong-session blob fails at
unmask with `MaskedKeyAuthenticationFailed`. Local-scoped receivers
require the original partition-local masking key to be restored first.
Generating a replacement key cannot recover backups sealed to the original
receiver. This decoder support does not add a public key-import API or a
native C entry point.

### Sealing-key masking scope

Rust sealing-key generation accepts explicit `HsmKeyScope::Ephemeral`,
`Local`, or `SecurityDomain` scope. The default remains `Local`; `Session`
scope is rejected. SecurityDomain scope requires the SD masking key to
have been provisioned by SD creation or restoration.

Keep a Local- or Ephemeral-scoped recipient key for SD recovery. An SD-scoped
recipient cannot restore its own SD because its masking key must already
be available. Export needs no sender sealing key. After a reset, restore the
SD independently before unmasking an SD-scoped recipient. The caller must
retain the masked blob; it is not stored on-device. Copies are usable wherever
the same SD masking key is available, subject to command authorization.

Key attestation does not distinguish Local scope from SecurityDomain
scope; the report alone does not establish partition-local custody.

### Attestation certificate chains

SD attestation requires a non-empty manufacturer chain, a non-empty
partition-owner chain, and a signed report. The device-owner chain is optional:
set `tsra_sd_evidence.owner_cert_chain` to `{NULL, 0}` to omit it. A supplied
owner chain is still validated and must certify the same report-signing leaf
key as the other chains. Missing manufacturer or partition-owner evidence is
still rejected. The partition-owner trust anchor and report/policy checks are
unchanged; omitting owner evidence does not bypass them.

This applies to reseal and peer backup operations and to remote create/restore
when `require_trusted_sa_key` is set. With that flag clear, remote create
ignores recipient attestation evidence; remote restore ignores source identity
chains but **always requires the source operation report**.

### P-384 transfer reports

SD transfer uses HPKE Base with DHKEM(P-384, HKDF-SHA384), HKDF-SHA384,
and AES-256-GCM. Producers sign an `SdBackup` report with their actual PID.
The report binds that PID, the actual recipient, the complete 322-byte
envelope, and the **transferred SD policy hash**. Reseal uses the requested
SD policy even when its own SA-local policy differs. Consumers verify all
bindings before decapsulation. Local masking, derivation, and SVN checks
are unchanged. Legacy Auth transfer envelopes are not supported.

Source evidence carries the producer's `SdBackup` operation report.
Destination/recipient evidence still carries a `PublicKey` report; it cannot
substitute for source operation evidence. Peer/reseal sources require POTA
authorization. Remote restore requires SAPOTA authorization only when
trusted-SA policy is enabled. Without SAPOTA, the caller supplies a PID key
and the report still verifies, but **does not authenticate SA identity or
establish trusted HSM provenance**. SATA remains recipient-only.

Create-remote, create-peer, and reseal add a required `report` output.
Reserve 896 bytes before issuing the command; success returns its actual
length. All output buffers must be distinct and adequately sized before any
one-shot state change. Keep the report with its envelope and SDMK backup.

## tsra_sess_ex_open

Open a security-domain session to the device.

The session uses the API revision that was selected when the partition was
opened with [`tsra_part_open`](#tsra_part_open). `psk` must be a non-NULL
pointer to an [`tsra_session_psk`](#tsra_session_psk) selecting the role
slot; only its inner `psk` buffer may be NULL, which selects the partition
default PSK for the slot. A NULL `psk` pointer is rejected with
`TSRA_STATUS_INVALID_ARGUMENT`. The `session_type` selects the channel
integrity profile pinned for the session (see
[tsra_session_ex_type](#tsra_session_ex_type)), and a handle to the new
session is returned.

At API revision 2.0 (Duo), the handshake also derives per-direction
AES-256-GCM transport keys. The SDK encrypts the handshake's second
message, every in-session command and the session close with them, and
the device encrypts each response; this applies to both session types.
Out-of-band data is not covered by this encryption. The transport is
transparent to callers: no API or parameter changes.

```cpp
tsra_status tsra_sess_ex_open(
    tsra_handle dev_handle,
    const tsra_session_psk *psk,
    tsra_session_ex_type session_type,
    tsra_handle *sess_handle
    );
```

**Parameters**

 | Parameter         | Name                                                | Description                                    |
 | ----------------- | --------------------------------------------------- | ---------------------------------------------- |
 | [in] dev_handle   | [tsra_handle](#tsra_handle)                     | partition handle                               |
 | [in] psk          | const tsra_session_psk *                          | PSK credential (non-NULL); inner `psk` buffer NULL = default |
 | [in] session_type | [tsra_session_ex_type](#tsra_session_ex_type)   | channel integrity profile to pin               |
 | [out] sess_handle | [tsra_handle *](#tsra_handle)                   | new security-domain session handle      &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_session_psk

PSK credential for [`tsra_sess_ex_open`](#tsra_sess_ex_open): the PSK
slot plus an optional caller-supplied PSK. When the `psk` buffer is NULL,
the partition **default** PSK for the slot is used — required for the first
session, before the default is rotated via
[`tsra_sess_ex_psk_change`](#tsra_sess_ex_psk_change). After rotation,
point `psk` at the rotated 32-byte secret.

```cpp
struct tsra_session_psk {
    uint8_t psk_id;
    const struct tsra_buffer *psk;
};
```

 | Field  | Name                             | Description                                        |
 | ------ | -------------------------------- | -------------------------------------------------- |
 | psk_id | uint8_t                          | PSK slot: 0 = Crypto Officer, 1 = Crypto User      |
 | psk    | [tsra_buffer*](#tsra_buffer) | optional PSK (exactly 32 bytes); NULL = default PSK |

## tsra_sess_ex_part_init

Provision a partition's security domain over a security-domain session.

Initializes the partition from the caller-supplied machine seed
(`mach_seed`) and partition policy (`part_policy`). The policy names the
partition-owner (POTA), security-administrator (SATA), and optional
secondary-owner (SAPOTA) trust anchors by public-key thumbprint. On
success it returns the partition's
certificate-signing request (`pta_csr`) and attestation report
(`pta_report`).

The provisioning inputs are grouped into an
[`tsra_sess_ex_part_init_params`](#tsra_sess_ex_part_init_params)
structure. `pta_csr` and `pta_report` are caller-provided output buffers:
on input `len` is the buffer capacity; on success `len` is set to the
number of bytes written. Because provisioning is a one-shot operation, an
undersized buffer (or a NULL `ptr` with `len == 0`) is rejected with
`TSRA_STATUS_BUFFER_TOO_SMALL` and `len` set to the maximum possible
output size **before** the partition is provisioned. The buffer is
validated up-front against a fixed upper bound, so the probe reports that
bound rather than the exact size for the current device — callers should
expect to allocate up to that maximum. The standard two-call size probe
(call once with a zero-length buffer to learn the required capacity, then
retry with a buffer of at least that size) is therefore safe for this
command. A NULL `ptr` with a non-zero `len` is rejected with
`TSRA_STATUS_INVALID_ARGUMENT`.

```cpp
tsra_status tsra_sess_ex_part_init(
    tsra_handle sess_handle,
    const struct tsra_sess_ex_part_init_params *params,
    struct tsra_buffer *pta_csr,
    struct tsra_buffer *pta_report
    );
```

**Parameters**

 | Parameter            | Name                                                                  | Description                                     |
 | -------------------- | --------------------------------------------------------------------- | ----------------------------------------------- |
 | [in] sess_handle     | [tsra_handle](#tsra_handle)                                       | security-domain session handle                  |
 | [in] params          | [tsra_sess_ex_part_init_params*](#tsra_sess_ex_part_init_params)   | provisioning input buffers                      |
 | [in, out] pta_csr    | [tsra_buffer *](#tsra_buffer)                                     | output buffer for the DER PKCS#10 CSR           |
 | [in, out] pta_report | [tsra_buffer *](#tsra_buffer)                                     | output buffer for the attestation report &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_sess_ex_part_init_params

Partition-policy inputs use the name `part_policy` and appear first in the
provisioning, finalization, and security-domain backup input structures.
Callers must rebuild against the updated header: moving these fields changes
the C struct layouts, even though the function signatures are unchanged.

Provisioning input buffers for
[`tsra_sess_ex_part_init`](#tsra_sess_ex_part_init). Each field points
to an [tsra_buffer](#tsra_buffer).

```cpp
struct tsra_sess_ex_part_init_params {
    const struct tsra_buffer *part_policy;
    const struct tsra_buffer *mach_seed;
};
```

 | Field       | Name                         | Description                                                    |
 | ----------- | ---------------------------- | -------------------------------------------------------------- |
 | part_policy | [tsra_buffer*](#tsra_buffer) | partition policy CBOR document, 1-384 B (see [Partition policy](#partition-policy)) |
 | mach_seed   | [tsra_buffer*](#tsra_buffer) | machine seed plaintext                                         |

## tsra_sess_ex_part_final

Finalize a partition's security domain over a security-domain session.

Completes provisioning started by
[`tsra_sess_ex_part_init`](#tsra_sess_ex_part_init): re-supplies the
partition policy and the PTA certificate chain (root to leaf),
optionally restoring a prior `local_mk` backup, and returns the current
`local_mk` backup envelope the firmware produced.

The inputs are grouped into an
[`tsra_sess_ex_part_final_params`](#tsra_sess_ex_part_final_params)
structure. `local_mk_backup` is a caller-provided output buffer with the
same capacity/length contract and two-call size-probe behavior as the
`tsra_sess_ex_part_init` outputs: an undersized buffer (or a NULL `ptr`
with `len == 0`) is rejected with `TSRA_STATUS_BUFFER_TOO_SMALL` and
`len` set to the maximum **before** the partition is finalized. A NULL
`ptr` with a non-zero `len` is rejected with
`TSRA_STATUS_INVALID_ARGUMENT`.

```cpp
tsra_status tsra_sess_ex_part_final(
    tsra_handle sess_handle,
    const struct tsra_sess_ex_part_final_params *params,
    struct tsra_buffer *local_mk_backup
    );
```

**Parameters**

 | Parameter                 | Name                                                                      | Description                                  |
 | ------------------------- | ------------------------------------------------------------------------- | -------------------------------------------- |
 | [in] sess_handle          | [tsra_handle](#tsra_handle)                                           | security-domain session handle               |
 | [in] params               | [tsra_sess_ex_part_final_params*](#tsra_sess_ex_part_final_params)     | finalization input buffers                   |
 | [in, out] local_mk_backup | [tsra_buffer *](#tsra_buffer)                                         | output buffer for the local_mk backup &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_sess_ex_part_final_params

Finalization input buffers for
[`tsra_sess_ex_part_final`](#tsra_sess_ex_part_final). `pta_cert_chain`
points to an array of `pta_cert_chain_len` [tsra_buffer](#tsra_buffer)s,
each holding one DER-encoded PTA certificate (root to leaf; at most
`MAX_CERTS`). `prev_local_mk_backup` is optional and may be NULL to omit it.

The shared firmware requires the PTA certificate to preserve the exact
DER subject Name from the PTA CSR and to use SHA-1 of the uncompressed
SEC1 PTA public key as its Subject Key Identifier. The PTA certificate
must be a CA with `keyCertSign` usage. A certificate violating this profile
is rejected before finalization, even if its key and POTA signature are valid.

After successful finalization, certificate slot 2 exposes only the PTA-signed
PID certificate at index 0. Shared command code above PAL generates a fresh
certificate on each request using ordinary signing and the existing PTA and
PID keys. DER bytes and lengths can change between requests. Chain metadata
fingerprints an independently generated certificate, so its thumbprint need
not match a subsequent certificate read. Neither a certificate chain nor
issuer metadata is stored in firmware. The caller retains its POTA/PTA chain
and prepends it to this PID certificate to construct root-first evidence.
Slot 0's provisioning behavior is unchanged, though on the std PAL its leaf
certificate is not byte-for-byte identical: `fw/plat/std/common/pal_src/cert.rs`
now derives the slot-0 leaf serial from the PID key's SHA-1 identifier (the
same derivation as the slot-2 PID serial). Slot 1 remains unsupported.
The owner chain can be omitted; manufacturer and partition-owner chains plus
the signed report satisfy the SD attestation requirement.

```cpp
struct tsra_sess_ex_part_final_params {
    const struct tsra_buffer *part_policy;
    const struct tsra_buffer *pta_cert_chain;
    uint32_t pta_cert_chain_len;
    const struct tsra_buffer *prev_local_mk_backup;
};
```

 | Field                | Name                             | Description                                     |
 | -------------------- | -------------------------------- | ----------------------------------------------- |
 | part_policy          | [tsra_buffer*](#tsra_buffer)     | partition policy (must match part_init)         |
 | pta_cert_chain       | [tsra_buffer*](#tsra_buffer)     | array of DER PTA certificates (root to leaf)    |
 | pta_cert_chain_len   | uint32_t                         | number of certificates in the chain             |
 | prev_local_mk_backup | [tsra_buffer*](#tsra_buffer)     | optional prior local_mk backup (may be NULL)    |

## Partition policy builder

The builder assembles the [partition policy](#partition-policy) from typed
fields and emits the deterministic CBOR document. The Rust SDK exposes the
same builder as `PartPolicyBuilder`, plus `policy_key_thumbprint`.

Typical use:

1. [`tsra_part_policy_builder_new`](#tsra_part_policy_builder_new)
   allocates an empty builder.
2. Set the required POTA and SATA keys, and any optional fields, with the
   `tsra_part_policy_builder_set_*` setters.
3. [`tsra_part_policy_build`](#tsra_part_policy_build) writes the document
   into a caller-provided [tsra_buffer](#tsra_buffer), following the
   two-call size-probe contract.
4. [`tsra_part_policy_builder_free`](#tsra_part_policy_builder_free)
   releases the builder.

The document always carries version 1.

### tsra_policy_key_format

Encoding of the key passed to a key setter or to
[`tsra_policy_key_thumbprint`](#tsra_policy_key_thumbprint). Every format
resolves to the same 48-byte SPKI thumbprint stored in the policy.

| Value                               | Key bytes                                     |
|-------------------------------------|-----------------------------------------------|
| `TSRA_POLICY_KEY_FORMAT_THUMBPRINT` | precomputed thumbprint, exactly 48 bytes      |
| `TSRA_POLICY_KEY_FORMAT_SPKI_DER`   | DER SubjectPublicKeyInfo of any algorithm     |
| `TSRA_POLICY_KEY_FORMAT_ECC_P384`   | raw P-384 point `X \|\| Y`, exactly 96 bytes |

`SPKI_DER` is hashed as given and must be one DER SEQUENCE with no trailing
bytes; it covers algorithms without a dedicated raw format (for example
ML-DSA or composite keys).

### tsra_part_policy_builder_new

Allocate a new, empty partition-policy builder.

```cpp
tsra_status tsra_part_policy_builder_new(
    struct tsra_part_policy_builder **out_builder);
```

**Parameters**

- `out_builder` — on success, receives a non-NULL opaque builder handle
  that must be released with `tsra_part_policy_builder_free`. Left
  unmodified on failure.

**Returns**

`TSRA_STATUS_SUCCESS` on success, or `TSRA_STATUS_INVALID_ARGUMENT`
if `out_builder` is NULL.

### tsra_part_policy_builder_free

Release a builder handle. Passing NULL is a no-op.

```cpp
void tsra_part_policy_builder_free(
    struct tsra_part_policy_builder *builder
    );
```

### tsra_part_policy_builder_set_*

Set individual policy fields. A setter returns
`TSRA_STATUS_INVALID_ARGUMENT` only for a NULL or misaligned handle or
buffer, or an unknown key `format`. Invalid field values are recorded and
reported by `tsra_part_policy_build`; the first such error is kept.

| Setter                  | Policy field                  | Rule                          |
|-------------------------|-------------------------------|-------------------------------|
| `set_pota_key`          | `pota_spki_thumbprint`        | required                      |
| `set_sata_key`          | `sata_spki_thumbprint`        | required                      |
| `set_sapota_key`        | `sapota_spki_thumbprint`      | optional                      |
| `set_backup_part_id`    | `backup_part_id`              | exactly 16 bytes; paired      |
| `set_backup_part_key`   | `backup_part_spki_thumbprint` | paired with `backup_part_id`  |
| `set_data_key`          | `data_spki_thumbprint`        | optional                      |
| `set_info`              | `info`                        | at most 64 bytes; empty omits |
| `set_flags`             | `flags`                       | reserved bits must be zero    |

The `flags` byte is a bitfield:

| Bit   | Meaning                  |
|-------|--------------------------|
| 0     | `include_fmc_cdi`        |
| 1     | `require_trusted_sa_key` |
| 2     | `allow_peer_cloning`     |
| 3 – 7 | reserved (must be zero)  |

```cpp
tsra_status tsra_part_policy_builder_set_pota_key(
    struct tsra_part_policy_builder *builder, tsra_policy_key_format format,
    const struct tsra_buffer *key);
tsra_status tsra_part_policy_builder_set_sata_key(
    struct tsra_part_policy_builder *builder, tsra_policy_key_format format,
    const struct tsra_buffer *key);
tsra_status tsra_part_policy_builder_set_sapota_key(
    struct tsra_part_policy_builder *builder, tsra_policy_key_format format,
    const struct tsra_buffer *key);
tsra_status tsra_part_policy_builder_set_backup_part_id(
    struct tsra_part_policy_builder *builder, const struct tsra_buffer *id);
tsra_status tsra_part_policy_builder_set_backup_part_key(
    struct tsra_part_policy_builder *builder, tsra_policy_key_format format,
    const struct tsra_buffer *key);
tsra_status tsra_part_policy_builder_set_data_key(
    struct tsra_part_policy_builder *builder, tsra_policy_key_format format,
    const struct tsra_buffer *key);
tsra_status tsra_part_policy_builder_set_info(
    struct tsra_part_policy_builder *builder, const struct tsra_buffer *info);
tsra_status tsra_part_policy_builder_set_flags(
    struct tsra_part_policy_builder *builder, uint8_t flags);
```

### tsra_part_policy_build

Serialize the policy into its deterministic CBOR document.

```cpp
tsra_status tsra_part_policy_build(
    struct tsra_part_policy_builder *builder,
    struct tsra_buffer *out
    );
```

**Returns**

`TSRA_STATUS_SUCCESS` on success, or `TSRA_STATUS_BUFFER_TOO_SMALL` if
`out` is too small (with `out.len` set to the required size).
`TSRA_STATUS_INVALID_ARGUMENT` is returned, including during size probes,
on a NULL or misaligned handle or buffer, a missing POTA or SATA key, an
unpaired backup id or key, a recorded setter error, or reserved flag bits.

### tsra_policy_key_thumbprint

Compute the 48-byte SPKI thumbprint of a key, the value the policy stores
for it.

```cpp
tsra_status tsra_policy_key_thumbprint(
    tsra_policy_key_format format,
    const struct tsra_buffer *key,
    struct tsra_buffer *out
    );
```

**Returns**

`TSRA_STATUS_SUCCESS` on success, `TSRA_STATUS_INVALID_ARGUMENT` on a
NULL buffer, unknown `format` or malformed `key`, or
`TSRA_STATUS_BUFFER_TOO_SMALL` if `out` is too small (with `out.len` set
to 48).

## tsra_sess_ex_psk_change

Rotate the calling session's own partition PSK.

Replaces the PSK of the slot implied by the session role (CO session → CO,
CU session → CU) with `new_psk`, sealed under the session key. This is
required **once** on a fresh partition to move past the default-PSK gate
before provisioning, and may also be used later to re-rotate. `new_psk`
must be exactly 32 bytes.

```cpp
tsra_status tsra_sess_ex_psk_change(
    tsra_handle sess_handle,
    const struct tsra_buffer *new_psk
    );
```

**Parameters**

 | Parameter        | Name                              | Description                              |
 | ---------------- | --------------------------------- | ---------------------------------------- |
 | [in] sess_handle | [tsra_handle](#tsra_handle)       | security-domain session handle           |
 | [in] new_psk     | [tsra_buffer *](#tsra_buffer)     | new PSK buffer (exactly 32 bytes) &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

## tsra_sd_create_remote_backup

Create a new security domain and its remote backup over a security-domain
session.

Creates a security domain under the calling session's partition from the
unified partition policy, the receiver key certificate chain (spec `RcvrCertChain`),
and — when the policy requires it — the receiver's attestation evidence, and
returns the PID-signed operation report and three backups: the remote
partition-owner-key backup (an HPKE Base envelope of BKS3, 322 bytes), the local
partition-owner-key backup (280 bytes), and the security-domain masking-key
backup (264 bytes).

The `receiver_cert_chain` is always validated and anchored to the policy SATA
key thumbprint; its leaf is the recipient public key (`RcvrPub`) the remote backup is
sealed to. The `receiver_evidence` attestation is verified only
when the policy sets `require_trusted_sa_key`: its partition-owner chain is
anchored to the policy SAPOTA key thumbprint and its report must attest the same
`RcvrPub` recovered from `receiver_cert_chain`, otherwise the create is
rejected with `TSRA_STATUS_INVALID_ARGUMENT`. When the flag is clear the
evidence is ignored (pass empty chains and an empty report). The host does
not decode the policy: it forwards the evidence whenever any of it is
non-empty, and firmware rejects the create if the flag is set and the
evidence is missing.

The inputs are grouped into an
[`tsra_sd_create_remote_backup_params`](#tsra_sd_create_remote_backup_params)
structure. All four distinct output buffers follow the two-call size-probe contract:
an undersized buffer (or a NULL `ptr` with `len == 0`) is rejected with
`TSRA_STATUS_BUFFER_TOO_SMALL` and `len` set to the required size, and
every output buffer is validated **before** the one-shot domain-creation
command is issued, so a too-small buffer never consumes it. A NULL `params`
pointer is rejected with `TSRA_STATUS_INVALID_ARGUMENT`. Creating a domain
is a once-per-partition operation; a second create on an initialized
partition returns `TSRA_STATUS_SD_ALREADY_INITIALIZED`.

```cpp
tsra_status tsra_sd_create_remote_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_create_remote_backup_params *params,
    struct tsra_buffer *pok_remote_backup,
    struct tsra_buffer *pok_local_backup,
    struct tsra_buffer *sd_mk_backup,
    struct tsra_buffer *report
    );
```

**Parameters**

 | Parameter                   | Name                                                                                                     | Description                                       |
 | --------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle            | [tsra_handle](#tsra_handle)                                                                          | security-domain session handle                    |
 | [in] params                 | [tsra_sd_create_remote_backup_params*](#tsra_sd_create_remote_backup_params)         | create-backup input buffers                       |
 | [in, out] pok_remote_backup | [tsra_buffer *](#tsra_buffer)                                                                        | output buffer for the remote pok backup (322 B)   |
 | [in, out] pok_local_backup  | [tsra_buffer *](#tsra_buffer)                                                                        | output buffer for the local pok backup (280 B)    |
 | [in, out] sd_mk_backup      | [tsra_buffer *](#tsra_buffer)                                                                        | output buffer for the sd masking-key backup (264 B) &nbsp; |
 | [in, out] report | [tsra_buffer *](#tsra_buffer) | required PID-signed `SdBackup` report; reserve 896 B |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_sd_create_remote_backup_params

Input buffers for
[`tsra_sd_create_remote_backup`](#tsra_sd_create_remote_backup).

```cpp
struct tsra_sd_create_remote_backup_params {
    const struct tsra_buffer *part_policy;
    struct tsra_sd_cert_chain receiver_cert_chain;
    const struct tsra_sd_evidence *receiver_evidence;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | part_policy        | [tsra_buffer*](#tsra_buffer)           | unified partition-policy image (1-384 B)             |
 | receiver_cert_chain | [tsra_sd_cert_chain](#tsra_sd_cert_chain) | receiver key chain (spec `RcvrCertChain`), SATA-anchored; always required |
 | receiver_evidence  | [tsra_sd_evidence*](#tsra_sd_evidence) | receiver attestation evidence; verified only when policy sets `require_trusted_sa_key` |

## tsra_sd_reseal_remote_backup

Reseal an existing remote backup to a new recipient over a security-domain
session.

**Verifies signatures on both incoming reports**, not just their certificate
chains, before HPKE decapsulation of the source backup:

| Evidence | Required verification |
|---|---|
| `src_evidence` | Verify the `SdBackup` operation report's ES384 signature under the source PID certified by its identity chains. Bind the report to that PID, the complete input envelope, the actual input recipient derived from `masked_sealing_key`, and the request's client SD policy hash. A `PublicKey` report is not sufficient. |
| `dest_evidence` | Verify the `PublicKey` attestation report's ES384 signature under the destination PID certified by its identity chains. Require a P-384 SD-sealing key marked Generated and not Imported, with the same client SD policy hash. Use this attested key as the output recipient. |

For both sides, the partition-owner chain must anchor to the **client
policy's POTA**. Manufacturer and partition-owner chains are required;
all supplied chains for each side must certify the same PID. These
requirements apply regardless of `require_trusted_sa_key`, unlike the
conditional SAPOTA authorization of remote restore.

Only after these checks pass does the SA Base-open and reseal BKS3.
It returns a fresh 322-byte envelope and a new `SdBackup` report signed
by its own PID, binding that PID, the destination key, complete output
envelope, and client SD policy hash. The SA-local policy may differ;
its policy hash is not substituted for the client SD policy hash.

The inputs are grouped into an
[`tsra_sd_reseal_remote_backup_params`](#tsra_sd_reseal_remote_backup_params)
structure. `dst_remote_backup` and `report` follow the same two-call size-probe contract
as the create outputs and is validated **before** the reseal is performed. A
NULL `params` pointer is rejected with `TSRA_STATUS_INVALID_ARGUMENT`.

```cpp
tsra_status tsra_sd_reseal_remote_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_reseal_remote_backup_params *params,
    struct tsra_buffer *dst_remote_backup,
    struct tsra_buffer *report
    );
```

**Parameters**

 | Parameter                   | Name                                                                                                     | Description                                       |
 | --------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle            | [tsra_handle](#tsra_handle)                                                                          | security-domain session handle                    |
 | [in] params                 | [tsra_sd_reseal_remote_backup_params*](#tsra_sd_reseal_remote_backup_params)         | reseal-backup input buffers                       |
 | [in, out] dst_remote_backup | [tsra_buffer *](#tsra_buffer)                                                                        | output buffer for the resealed remote backup (322 B) &nbsp; |
 | [in, out] report | [tsra_buffer *](#tsra_buffer) | required SA-PID-signed `SdBackup` report; reserve 896 B |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_sd_reseal_remote_backup_params

Input buffers for
[`tsra_sd_reseal_remote_backup`](#tsra_sd_reseal_remote_backup).

```cpp
struct tsra_sd_reseal_remote_backup_params {
    const struct tsra_buffer *part_policy;
    const struct tsra_buffer *masked_sealing_key;
    const struct tsra_sd_evidence *src_evidence;
    const struct tsra_sd_evidence *dest_evidence;
    const struct tsra_buffer *src_remote_backup;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | part_policy        | [tsra_buffer*](#tsra_buffer)               | unified partition-policy image (1-384 B)             |
 | masked_sealing_key | [tsra_buffer*](#tsra_buffer)               | receiver's masked SD-sealing key (280 B)           |
 | src_evidence       | [tsra_sd_evidence*](#tsra_sd_evidence)     | source PID identity chains and mandatory `SdBackup` report |
 | dest_evidence      | [tsra_sd_evidence*](#tsra_sd_evidence)     | destination (receiver) attestation evidence        |
 | src_remote_backup  | [tsra_buffer*](#tsra_buffer)               | source remote backup to reseal (322 B)             |

## tsra_sd_restore_remote_backup

Restore a security domain from a remote backup over a security-domain
session.

Verifies the mandatory `SdBackup` report, actual recipient, envelope, and
target SD policy before Base-opening with the receiver's masked key.
Recovers the security-domain masking key from `prev_sd_mk_backup`, and
returns the refreshed device-local backups: the local partition-owner-key
backup (280 bytes) and the security-domain masking-key backup (264 bytes).

`sender_pid_pub_key` carries the report signer's DER SubjectPublicKeyInfo.
The current profile accepts only canonical uncompressed P-384 SPKI
(120 bytes); bare SEC1 points, unsupported algorithms, noncanonical
encodings, and trailing data are rejected. Its SHA-384 SPKI thumbprint
must match the report's `source_pid_spki_thumbprint` (CBOR key 9).
The `recipient_spki_thumbprint` (key 10) similarly binds the actual
receiving encryption key, not the recipient's PID. Both thumbprints
also appear in the SD envelope header; their size remains 48 bytes.

SATA sender authorization is removed. Under `require_trusted_sa_key`,
the source PID chains in `sender_evidence` must anchor to SAPOTA and match
this supplied key. Otherwise chains may be empty and are ignored, but
`sender_evidence.report` remains required. This establishes signature
integrity and transfer bindings, not authenticated SA identity.

The trusted sealing authority may have a different partition policy from the
restored SD. Its operation report's policy hash **must** equal the transferred
SD policy, not the authority-local policy. The destination still requires
the request policy to match its own bound policy.

The inputs are grouped into an
[`tsra_sd_restore_remote_backup_params`](#tsra_sd_restore_remote_backup_params)
structure. Both output buffers follow the two-call size-probe contract and
are validated **before** the restore is performed. A NULL `params` pointer
is rejected with `TSRA_STATUS_INVALID_ARGUMENT`. Restore is a
once-per-partition operation; a restore on an already-initialized partition
returns `TSRA_STATUS_SD_ALREADY_INITIALIZED`.

```cpp
tsra_status tsra_sd_restore_remote_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_restore_remote_backup_params *params,
    struct tsra_buffer *pok_local_backup,
    struct tsra_buffer *sd_mk_backup
    );
```

**Parameters**

 | Parameter                  | Name                                                                                                      | Description                                       |
 | -------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle           | [tsra_handle](#tsra_handle)                                                                           | security-domain session handle                    |
 | [in] params                | [tsra_sd_restore_remote_backup_params*](#tsra_sd_restore_remote_backup_params)        | restore-backup input buffers                      |
 | [in, out] pok_local_backup | [tsra_buffer *](#tsra_buffer)                                                                         | output buffer for the local pok backup (280 B)    |
 | [in, out] sd_mk_backup     | [tsra_buffer *](#tsra_buffer)                                                                         | output buffer for the sd masking-key backup (264 B) &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_sd_restore_remote_backup_params

Input buffers for
[`tsra_sd_restore_remote_backup`](#tsra_sd_restore_remote_backup).

```cpp
struct tsra_sd_restore_remote_backup_params {
    const struct tsra_buffer *part_policy;
    const struct tsra_buffer *masked_sealing_key;
    const struct tsra_buffer *sender_pid_pub_key;
    const struct tsra_sd_evidence *sender_evidence;
    const struct tsra_buffer *src_remote_backup;
    const struct tsra_buffer *prev_sd_mk_backup;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | part_policy        | [tsra_buffer*](#tsra_buffer)           | unified partition-policy image (1-384 B)             |
 | masked_sealing_key | [tsra_buffer*](#tsra_buffer)           | receiver's masked SD-sealing key (280 B)           |
 | sender_pid_pub_key | [tsra_buffer*](#tsra_buffer) | report signer DER SPKI; currently canonical P-384 (120 B) |
 | sender_evidence | [tsra_sd_evidence*](#tsra_sd_evidence) | mandatory `SdBackup` report; SAPOTA PID chains required only under trusted-SA policy |
 | src_remote_backup  | [tsra_buffer*](#tsra_buffer)           | remote backup to restore (322 B)                   |
 | prev_sd_mk_backup  | [tsra_buffer*](#tsra_buffer)           | previous security-domain masking-key backup (264 B)|

## tsra_sd_create_peer_backup

Create a peer-transferable backup of a security domain over a
security-domain session.

Recovers BKS3 from `pok_local_backup` and Base-seals it to the
POTA-authorized same-policy peer in `dst_evidence`, returning the
322-byte envelope and PID-signed `SdBackup` report. No sender key is supplied. Peer
cloning is gated by the security domain's `allow_peer_cloning` policy flag.
The `dst_evidence` partition-owner chain must anchor to the policy POTA
key thumbprint.

The inputs are grouped into an
[`tsra_sd_create_peer_backup_params`](#tsra_sd_create_peer_backup_params)
structure. Both distinct output buffers follow the two-call size-probe contract and
is validated **before** the peer backup is created. A NULL `params` pointer
is rejected with `TSRA_STATUS_INVALID_ARGUMENT`.

```cpp
tsra_status tsra_sd_create_peer_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_create_peer_backup_params *params,
    struct tsra_buffer *pok_peer_backup,
    struct tsra_buffer *report
    );
```

**Parameters**

 | Parameter                | Name                                                                                              | Description                                     |
 | ------------------------ | ------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
 | [in] sess_handle         | [tsra_handle](#tsra_handle)                                                                   | security-domain session handle                  |
 | [in] params              | [tsra_sd_create_peer_backup_params*](#tsra_sd_create_peer_backup_params)      | create-peer-backup input buffers                |
 | [in, out] pok_peer_backup | [tsra_buffer *](#tsra_buffer)                                                                | output buffer for the peer backup (322 B) &nbsp; |
 | [in, out] report | [tsra_buffer *](#tsra_buffer) | required PID-signed `SdBackup` report; reserve 896 B |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_sd_create_peer_backup_params

Input buffers for
[`tsra_sd_create_peer_backup`](#tsra_sd_create_peer_backup).

```cpp
struct tsra_sd_create_peer_backup_params {
    const struct tsra_buffer *part_policy;
    const struct tsra_sd_evidence *dst_evidence;
    const struct tsra_buffer *pok_local_backup;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | part_policy        | [tsra_buffer*](#tsra_buffer)               | unified partition-policy image (1-384 B)             |
 | dst_evidence       | [tsra_sd_evidence*](#tsra_sd_evidence)     | destination (peer) attestation evidence            |
 | pok_local_backup   | [tsra_buffer*](#tsra_buffer)               | device-local partition-owner-key backup (280 B)    |

## tsra_sd_restore_peer_backup

Restore a security domain from a peer backup over a security-domain
session.

Verifies the POTA-authorized source PID's `SdBackup` operation report,
actual recipient, envelope, and SD policy before Base-opening with the receiver key. Recovers the
security-domain masking key from `prev_sd_mk_backup`, and returns the
refreshed device-local backups: the local partition-owner-key backup
(280 bytes) and the security-domain masking-key backup (264 bytes). Peer
cloning is gated by the security domain's `allow_peer_cloning` policy flag.
The `src_evidence` partition-owner chain must anchor to the policy POTA
key thumbprint.

The inputs are grouped into an
[`tsra_sd_restore_peer_backup_params`](#tsra_sd_restore_peer_backup_params)
structure. Both output buffers follow the two-call size-probe contract and
are validated **before** the restore is performed. A NULL `params` pointer
is rejected with `TSRA_STATUS_INVALID_ARGUMENT`. Restore is a
once-per-partition operation; a restore on an already-initialized partition
returns `TSRA_STATUS_SD_ALREADY_INITIALIZED`.

```cpp
tsra_status tsra_sd_restore_peer_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_restore_peer_backup_params *params,
    struct tsra_buffer *pok_local_backup,
    struct tsra_buffer *sd_mk_backup
    );
```

**Parameters**

 | Parameter                  | Name                                                                                                  | Description                                       |
 | -------------------------- | ----------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle           | [tsra_handle](#tsra_handle)                                                                       | security-domain session handle                    |
 | [in] params                | [tsra_sd_restore_peer_backup_params*](#tsra_sd_restore_peer_backup_params)        | restore-backup input buffers                      |
 | [in, out] pok_local_backup | [tsra_buffer *](#tsra_buffer)                                                                     | output buffer for the local pok backup (280 B)    |
 | [in, out] sd_mk_backup     | [tsra_buffer *](#tsra_buffer)                                                                     | output buffer for the sd masking-key backup (264 B) &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_sd_restore_peer_backup_params

Input buffers for
[`tsra_sd_restore_peer_backup`](#tsra_sd_restore_peer_backup).

```cpp
struct tsra_sd_restore_peer_backup_params {
    const struct tsra_buffer *part_policy;
    const struct tsra_buffer *masked_sealing_key;
    const struct tsra_sd_evidence *src_evidence;
    const struct tsra_buffer *pok_peer_backup;
    const struct tsra_buffer *prev_sd_mk_backup;
};
```

 | Field              | Name                                       | Description                                         |
 | ------------------ | ------------------------------------------ | --------------------------------------------------- |
 | part_policy        | [tsra_buffer*](#tsra_buffer)               | unified partition-policy image (1-384 B)              |
 | masked_sealing_key | [tsra_buffer*](#tsra_buffer)               | receiver's masked SD-sealing key (280 B)            |
 | src_evidence       | [tsra_sd_evidence*](#tsra_sd_evidence)     | source (peer) attestation evidence                  |
 | pok_peer_backup    | [tsra_buffer*](#tsra_buffer)               | peer backup to restore (322 B)                      |
 | prev_sd_mk_backup  | [tsra_buffer*](#tsra_buffer)               | previous security-domain masking-key backup (264 B) |

## tsra_sd_restore_local_backup

Restore a security domain from its device-local backups over a
security-domain session.

Restores the security domain from the device-local partition-owner-key
backup and security-domain masking-key backup, returning the refreshed
device-local backups: the local partition-owner-key backup (280 bytes) and
the security-domain masking-key backup (264 bytes). Unlike the remote/peer
restores, this carries no attestation evidence — the backups are masked
under the device-local key.

The inputs are grouped into an
[`tsra_sd_restore_local_backup_params`](#tsra_sd_restore_local_backup_params)
structure. Both output buffers follow the two-call size-probe contract and
are validated **before** the restore is performed. A NULL `params` pointer
is rejected with `TSRA_STATUS_INVALID_ARGUMENT`. Restore is a
once-per-partition operation; a restore on an already-initialized partition
returns `TSRA_STATUS_SD_ALREADY_INITIALIZED`.

```cpp
tsra_status tsra_sd_restore_local_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_restore_local_backup_params *params,
    struct tsra_buffer *pok_local_backup,
    struct tsra_buffer *sd_mk_backup
    );
```

**Parameters**

 | Parameter                  | Name                                                                                                    | Description                                       |
 | -------------------------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle           | [tsra_handle](#tsra_handle)                                                                         | security-domain session handle                    |
 | [in] params                | [tsra_sd_restore_local_backup_params*](#tsra_sd_restore_local_backup_params)        | restore-backup input buffers                      |
 | [in, out] pok_local_backup | [tsra_buffer *](#tsra_buffer)                                                                       | output buffer for the local pok backup (280 B)    |
 | [in, out] sd_mk_backup     | [tsra_buffer *](#tsra_buffer)                                                                       | output buffer for the sd masking-key backup (264 B) &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_sd_restore_local_backup_params

Input buffers for
[`tsra_sd_restore_local_backup`](#tsra_sd_restore_local_backup).

```cpp
struct tsra_sd_restore_local_backup_params {
    const struct tsra_buffer *pok_local_backup;
    const struct tsra_buffer *sd_mk_backup;
};
```

 | Field             | Name                             | Description                                        |
 | ----------------- | -------------------------------- | -------------------------------------------------- |
 | pok_local_backup  | [tsra_buffer*](#tsra_buffer)     | device-local partition-owner-key backup (280 B)    |
 | sd_mk_backup      | [tsra_buffer*](#tsra_buffer)     | security-domain masking-key backup (264 B)         |

### tsra_sd_evidence

Attestation evidence for one security-domain-backup party: three certificate
chains (manufacturer, owner, partition-owner) and a COSE_Sign1 attestation
report. The DER bytes are borrowed, not copied, and must outlive the call.

```cpp
struct tsra_sd_evidence {
    struct tsra_sd_cert_chain mfgr_cert_chain;
    struct tsra_sd_cert_chain owner_cert_chain;
    struct tsra_sd_cert_chain part_owner_cert_chain;
    const struct tsra_buffer *report;
};
```

 | Field                 | Name                                         | Description                                  |
 | --------------------- | -------------------------------------------- | -------------------------------------------- |
 | mfgr_cert_chain       | [tsra_sd_cert_chain](#tsra_sd_cert_chain) | manufacturer certificate chain               |
 | owner_cert_chain      | [tsra_sd_cert_chain](#tsra_sd_cert_chain) | owner certificate chain                      |
 | part_owner_cert_chain | [tsra_sd_cert_chain](#tsra_sd_cert_chain) | partition-owner certificate chain            |
 | report                | [tsra_buffer*](#tsra_buffer)             | COSE_Sign1 attestation report                |

### tsra_sd_cert_chain

One certificate chain in an SD attestation-evidence party: an array of `len`
[tsra_buffer](#tsra_buffer)s, each holding one DER-encoded certificate
ordered root to leaf (at most `EVIDENCE_CHAIN_MAX_CERTS`).

```cpp
struct tsra_sd_cert_chain {
    const struct tsra_buffer *certs;
    uint32_t len;
};
```

 | Field | Name                             | Description                                   |
 | ----- | -------------------------------- | --------------------------------------------- |
 | certs | [tsra_buffer*](#tsra_buffer)     | array of DER certificates (root to leaf)      |
 | len   | uint32_t                         | number of certificates in the chain           |
