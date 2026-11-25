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

Recipient-key attestation requires a non-empty manufacturer chain, a non-empty
partition-owner chain, and a signed report. The device-owner chain is optional:
set `tsra_sd_evidence.owner_cert_chain` to `{NULL, 0}` to omit it. A supplied
owner chain is still validated and must certify the same report-signing leaf
key as the other chains. Missing manufacturer or partition-owner evidence is
still rejected. The partition-owner trust anchor and report/policy checks are
unchanged; omitting owner evidence does not bypass them. Source PID identity
uses the corresponding chain checks, but has no separate report field.

This applies to reseal and peer backup operations and to remote create/restore
when `require_trusted_sa_key` is set. With that flag clear, remote create
ignores recipient attestation evidence; remote restore ignores source identity
chains but **always verifies the signature embedded in the backup**.

### Signed transfers and KEMs

SD transfer uses HPKE Base and AES-256-GCM. The recipient sealing key's
`bits` property selects its KEM; PQ suites use SHAKE256 rather than HKDF-SHA384.

An unsupported TBOR algorithm or certificate bank reports
`TSRA_STATUS_UNSUPPORTED_ALGORITHM`. API revision alone does not establish
PQ capability: session authentication also requires PQ support in the host
crypto provider and a supported authenticated certificate path. Other device
failures must not be treated as an unsupported-capability result.

 | `bits` | Recipient KEM | Masked key | ES384 signed backup | ML-DSA-87 signed backup |
 | ------ | ------------- | ---------- | ------------------- | ---------------------- |
 | 384 | DHKEM(P-384, HKDF-SHA384) | 280 B | 431 B | 4963 B |
 | 1024 | ML-KEM-1024 | 296 B | 1902 B | 6434 B |
 | 1408 | MLKEM1024-P384 | 264 B | 1999 B | 6531 B |

PQ public keys are carried by their `PublicKey` reports. Producers directly
sign the complete binary `SdBackup` envelope with their actual PID in one
COSE_Sign1, using ES384 or ML-DSA-87 according to the policy PTA algorithm.
Its protected header is `{1: -35}` or `{1: -50}`, respectively, and the
unprotected map is empty. COSE external AAD is
ASCII `TSRA-SdBackup-v1` followed by 16 zero bytes (32 bytes total).
It is reconstructed for signing/verification, not transmitted, so the
backup size is unchanged. Empty or wrong-domain transfer signatures are
rejected; PublicKey attestations retain empty COSE external AAD.
The HPKE header is supplied as `info`, with empty HPKE AAD. The signed
header binds the source's SHA-384 canonical-DER-SPKI thumbprint, the recipient
identifier, and
the **transferred SD policy hash**. Reseal uses the requested
SD policy even when its own SA-local policy differs. Consumers verify all
bindings before decapsulation. Local masking, derivation, and SVN checks
are unchanged. Legacy Auth transfer envelopes are not supported.

Device-generated ML-DSA-87 reports, certificates, and CSRs use required
hedging; repeated signing inputs need not yield byte-identical signatures.

Source `tsra_sd_identity_evidence` carries PID certificate chains only.
Destination/recipient evidence still carries a `PublicKey` report; it cannot
substitute for source operation evidence. Peer/reseal sources require POTA
authorization. Remote restore requires SAPOTA authorization only when
trusted-SA policy is enabled. Without SAPOTA, the caller supplies a PID key
and the backup signature still verifies, but **does not authenticate SA identity or
establish trusted HSM provenance**. SATA remains recipient-only.

P-384 recipients use canonical-DER-SPKI thumbprints; PQ recipients use the
algorithm-domain identifiers in the [transfer format](../../../docs/tbor-ddi/commands/key_report.md#transfer-envelope-binding).

Create-remote, create-peer, and reseal return the signature inside the
backup; there is no separate report input or output. Native output probes
require the maximum capacity of **6531 bytes**, including for a P-384 recipient,
before issuing the command. Success sets `len` to the actual size in the table.
All output
buffers must be distinct and adequately sized before any one-shot state
change. Keep the signed backup with the SDMK backup.

## tsra_sess_ex_open

Open a security-domain session to the device.

The session uses the API revision that was selected when the partition was
opened with [`tsra_part_open`](#tsra_part_open). `psk` must be a non-NULL
pointer to an [`tsra_session_psk`](#tsra_session_psk) selecting the role
slot; only its inner `psk` buffer may be NULL, which selects the partition
default PSK for the slot. A NULL `psk` pointer is rejected with
`TSRA_STATUS_INVALID_ARGUMENT`. The `suite` selects the key-establishment
suite (see [tsra_session_suite](#tsra_session_suite)); an unknown value is
rejected with `TSRA_STATUS_INVALID_ARGUMENT`. A handle to the new session
is returned.

`root_spki_thumbprint` is mandatory: a non-NULL buffer containing exactly
48 bytes, the SHA-384 digest of the trusted root certificate's **DER-encoded
SubjectPublicKeyInfo** (not the whole certificate and not raw EC coordinates).
Provision it from an independently trusted manufacturer/enrollment source;
hashing the root just received from an untrusted device is not authentication.
The trusted thumbprint is always required; there is no automatic trust-on-first-use.

Before sending `SessionOpenInit`, the SDK validates the PID certificate's
signatures, validity and CA constraints, authenticates the resulting path's root
against this thumbprint, and requires a **non-PID certificate on that validated path**
with both DICE TCB Info (`2.23.133.5.4.1`) explicitly declaring `layer = 0`
and EKU `1.3.6.1.4.1.311.102.1.50.1`. The DICE layer is context-specific tag
`[4]`; an absent layer is not layer zero. Unused certificates in the supplied
chain do not qualify. The same validated PID key verifies the handshake.
This proves Tessera provenance under the trusted root, not a particular unit's
identity or fresh firmware attestation.

Every security-domain session is encrypted. The handshake authenticates
the device with its suite-selected partition identity signature over
the handshake transcript and the caller with the role PSK, and derives
per-direction AES-256-GCM transport keys. The SDK encrypts the handshake's
second message, every in-session command and the session close with them,
and the device encrypts each response. This holds on every device model.
Out-of-band data is not covered by this encryption. The transport is
transparent to callers.

Choose `TSRA_SESSION_SUITE_ECDH_P384` for classical ECDH key agreement
and ECDSA P-384 handshake authentication.

Choose `TSRA_SESSION_SUITE_ML_KEM1024_ML_DSA87` for both post-quantum key
agreement and ML-DSA-87 authentication. It uses the ML-DSA certificate bank
and requires ML-DSA-87 public keys throughout the authenticated PID path.
Provision that bank's root SPKI pin independently; an ECC-bank pin is not
interchangeable. The public 4627-byte signature travels out-of-band and
is verified before session key derivation. The role PSK, root/profile checks,
SHA-384 key schedule and AES-256-GCM transport are unchanged.
Reopen retains the original suite.

The selected API major/minor appear in the common TBOR header and are
authenticated in the Init signature and session-key derivation, without
duplicate Init body fields. Finish and all subsequent session commands use
that same revision. The SDK rejects a response carrying a different revision.
This binds the selected revision; discovery does not cryptographically
negotiate or guarantee selection of the highest supported revision.

Implicit 32-byte AAD binds each response to the original request IV and
transport context. The SDK retains the expected context locally and checks
authentication before decoding the result; responses may complete out of
order. This adds no wire fields and does not provide exactly-once request
execution or authenticate out-of-band data. Both SDK and firmware must support
this binding format.

```cpp
tsra_status tsra_sess_ex_open(
    tsra_handle dev_handle,
    const tsra_buffer *root_spki_thumbprint,
    const tsra_session_psk *psk,
    tsra_session_suite suite,
    tsra_handle *sess_handle
    );
```

**Parameters**

 | Parameter         | Name                                                | Description                                    |
 | ----------------- | --------------------------------------------------- | ---------------------------------------------- |
 | [in] dev_handle   | [tsra_handle](#tsra_handle)                     | partition handle                               |
 | [in] root_spki_thumbprint | const tsra_buffer *               | Required 48-byte trusted-root SPKI SHA-384 digest |
 | [in] psk          | const tsra_session_psk *                          | PSK credential (non-NULL); inner `psk` buffer NULL = default |
 | [in] suite        | [tsra_session_suite](#tsra_session_suite)       | key-establishment suite                        |
 | [out] sess_handle | [tsra_handle *](#tsra_handle)                   | new security-domain session handle      &nbsp; |

**Returns**

`TSRA_STATUS_SUCCESS` on success. A NULL root buffer, NULL data pointer or a
length other than 48 returns `TSRA_STATUS_INVALID_ARGUMENT` before device
activity. An untrusted root, invalid certificate path or missing/invalid
Tessera profile returns `TSRA_STATUS_INVALID_SIGNATURE`. Other errors are
propagated; no session is established on failure.

### tsra_session_psk

PSK credential for [`tsra_sess_ex_open`](#tsra_sess_ex_open): the PSK
slot plus an optional caller-supplied PSK. When the `psk` buffer is NULL,
the partition **default** PSK for the slot is used — required for the first
session, before the default is rotated via
[`tsra_sess_ex_psk_change`](#tsra_sess_ex_psk_change). After rotation,
point `psk` at the rotated 32-byte secret.

CU sessions opened with the default PSK are bootstrap-only. Before rotation,
normal session commands return `TSRA_STATUS_DEFAULT_PSK_MUST_ROTATE`; only PSK
change and close are permitted. Once any session rotates the partition CU PSK,
all default-authenticated CU sessions, including the rotating session, return
`TSRA_STATUS_DEFAULT_PSK_CHANGED` except when closing. Close and explicitly
open a new session with the rotated credential. The SDK does not automatically
upgrade or reopen the old session. The same changed-default status can be
returned if rotation occurs between Init and Finish during session open.

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
returns three backups: the remote
partition-owner-key backup (one PID-signed HPKE Base artifact sized by KEM and signer), the local
partition-owner-key backup (280 bytes), and the security-domain masking-key
backup (264 bytes).

The `receiver_cert_chain` is always validated and anchored to the policy SATA
key thumbprint; its leaf is the recipient public key (`RcvrPub`) the remote backup is
sealed to. To seal to a PQ sealing key instead, pass that key's
`PublicKey` report re-signed (COSE_Sign1, ES384) by the receiver chain leaf
in `receiver_key_report`. The `receiver_evidence` attestation is verified only
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
structure. All three distinct output buffers follow the two-call size-probe contract:
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
    struct tsra_buffer *sd_mk_backup
    );
```

**Parameters**

 | Parameter                   | Name                                                                                                     | Description                                       |
 | --------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle            | [tsra_handle](#tsra_handle)                                                                          | security-domain session handle                    |
 | [in] params                 | [tsra_sd_create_remote_backup_params*](#tsra_sd_create_remote_backup_params)         | create-backup input buffers                       |
 | [in, out] pok_remote_backup | [tsra_buffer *](#tsra_buffer)                                                                        | complete remote backup; reserve 6531 B |
 | [in, out] pok_local_backup  | [tsra_buffer *](#tsra_buffer)                                                                        | output buffer for the local pok backup (280 B)    |
 | [in, out] sd_mk_backup      | [tsra_buffer *](#tsra_buffer)                                                                        | output buffer for the sd masking-key backup (264 B) &nbsp; |

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
    const struct tsra_buffer *receiver_key_report;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | part_policy        | [tsra_buffer*](#tsra_buffer)           | unified partition-policy image (1-384 B)             |
 | receiver_cert_chain | [tsra_sd_cert_chain](#tsra_sd_cert_chain) | receiver key chain (spec `RcvrCertChain`), SATA-anchored; always required |
 | receiver_evidence  | [tsra_sd_evidence*](#tsra_sd_evidence) | receiver attestation evidence; verified only when policy sets `require_trusted_sa_key` |
 | receiver_key_report | [tsra_buffer*](#tsra_buffer)          | optional leaf-signed key report over a PQ sealing key; null seals to the chain leaf's P-384 key |

## tsra_sd_reseal_remote_backup

Reseal an existing remote backup to a new recipient over a security-domain
session.

**Verifies both the source backup signature and destination report signature**, not just their certificate
chains, before HPKE decapsulation of the source backup:

| Evidence | Required verification |
|---|---|
| `src_evidence` | Authorize the source PID through these identity chains and verify its direct ES384 signature on the complete input backup. Check its signed header against that PID, the actual input recipient derived from `masked_sealing_key`, and the request's client SD policy hash. A `PublicKey` report is not sufficient. |
| `dest_evidence` | Verify the `PublicKey` attestation report's ES384 signature under the destination PID certified by its identity chains. Require a P-384 SD-sealing key marked Generated and not Imported, with the same client SD policy hash. Use this attested key as the output recipient. |

For both sides, the partition-owner chain must anchor to the **client
policy's POTA**. Manufacturer and partition-owner chains are required;
all supplied chains for each side must certify the same PID. These
requirements apply regardless of `require_trusted_sa_key`, unlike the
conditional SAPOTA authorization of remote restore.

Only after these checks pass does the SA Base-open and reseal BKS3.
It returns one fresh `SdBackup` envelope, sized by KEM and signer, signed directly
by its own PID, binding that PID, the destination key, complete output
envelope, and client SD policy hash. The SA-local policy may differ;
its policy hash is not substituted for the client SD policy hash.

The inputs are grouped into an
[`tsra_sd_reseal_remote_backup_params`](#tsra_sd_reseal_remote_backup_params)
structure. `dst_remote_backup` follows the same two-call size-probe contract
as the create outputs and is validated **before** the reseal is performed. A
NULL `params` pointer is rejected with `TSRA_STATUS_INVALID_ARGUMENT`.

```cpp
tsra_status tsra_sd_reseal_remote_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_reseal_remote_backup_params *params,
    struct tsra_buffer *dst_remote_backup
    );
```

**Parameters**

 | Parameter                   | Name                                                                                                     | Description                                       |
 | --------------------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
 | [in] sess_handle            | [tsra_handle](#tsra_handle)                                                                          | security-domain session handle                    |
 | [in] params                 | [tsra_sd_reseal_remote_backup_params*](#tsra_sd_reseal_remote_backup_params)         | reseal-backup input buffers                       |
 | [in, out] dst_remote_backup | [tsra_buffer *](#tsra_buffer)                                                                        | complete resealed backup; reserve 6531 B |

**Returns**

`TSRA_STATUS_SUCCESS` on success, error code otherwise

### tsra_sd_reseal_remote_backup_params

Input buffers for
[`tsra_sd_reseal_remote_backup`](#tsra_sd_reseal_remote_backup).

```cpp
struct tsra_sd_reseal_remote_backup_params {
    const struct tsra_buffer *part_policy;
    const struct tsra_buffer *masked_sealing_key;
    const struct tsra_sd_identity_evidence *src_evidence;
    const struct tsra_sd_evidence *dest_evidence;
    const struct tsra_buffer *src_remote_backup;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | part_policy        | [tsra_buffer*](#tsra_buffer)               | unified partition-policy image (1-384 B)             |
 | masked_sealing_key | [tsra_buffer*](#tsra_buffer)               | receiver's masked SD-sealing key (264 / 280 / 296 B) |
 | src_evidence       | [tsra_sd_identity_evidence*](#tsra_sd_identity_evidence) | source PID identity chains only |
 | dest_evidence      | [tsra_sd_evidence*](#tsra_sd_evidence)     | destination (receiver) attestation evidence        |
 | src_remote_backup  | [tsra_buffer*](#tsra_buffer)               | complete signed source backup; exact length from the KEM/signer table |

## tsra_sd_restore_remote_backup

Restore a security domain from a remote backup over a security-domain
session.

Verifies the `SdBackup` signature, actual recipient, envelope, and
target SD policy before Base-opening with the receiver's masked key.
Recovers the security-domain masking key from `prev_sd_mk_backup`, and
returns the refreshed device-local backups: the local partition-owner-key
backup (280 bytes) and the security-domain masking-key backup (264 bytes).

`sender_pid_pub_key` carries the report signer's DER SubjectPublicKeyInfo.
The profile accepts canonical uncompressed P-384 SPKI (120 bytes) or
ML-DSA-87 SPKI (2614 bytes); bare public keys, unsupported algorithms, noncanonical
encodings, and trailing data are rejected. Its SHA-384 SPKI thumbprint
must match the signed header's `source_pid_spki_thumbprint`.
The signed `recipient_spki_thumbprint` similarly binds the actual
receiving encryption key, not the recipient's PID. Both thumbprints
are 48 bytes and appear only in the binary envelope header.

SATA sender authorization is removed. Under `require_trusted_sa_key`,
the source PID chains in `sender_evidence` must anchor to SAPOTA and match
this supplied key. Otherwise chains may be empty and are ignored, but
the backup's embedded signature remains required. This establishes signature
integrity and transfer bindings, not authenticated SA identity.

The trusted sealing authority may have a different partition policy from the
restored SD. Its signed header's policy hash **must** equal the transferred
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
    const struct tsra_sd_identity_evidence *sender_evidence;
    const struct tsra_buffer *src_remote_backup;
    const struct tsra_buffer *prev_sd_mk_backup;
};
```

 | Field              | Name                                       | Description                                        |
 | ------------------ | ------------------------------------------ | -------------------------------------------------- |
 | part_policy        | [tsra_buffer*](#tsra_buffer)           | unified partition-policy image (1-384 B)             |
 | masked_sealing_key | [tsra_buffer*](#tsra_buffer)           | receiver's masked SD-sealing key (264 / 280 / 296 B) |
 | sender_pid_pub_key | [tsra_buffer*](#tsra_buffer) | canonical PID DER SPKI: P-384 (120 B) or ML-DSA-87 (2614 B) |
 | sender_evidence | [tsra_sd_identity_evidence*](#tsra_sd_identity_evidence) | SAPOTA PID chains required only under trusted-SA policy |
 | src_remote_backup  | [tsra_buffer*](#tsra_buffer)           | complete signed remote backup; exact length from the KEM/signer table |
 | prev_sd_mk_backup  | [tsra_buffer*](#tsra_buffer)           | previous security-domain masking-key backup (264 B)|

## tsra_sd_create_peer_backup

Create a peer-transferable backup of a security domain over a
security-domain session.

Recovers BKS3 from `pok_local_backup` and Base-seals it to the
POTA-authorized same-policy peer in `dst_evidence`, returning the
PID-signed `SdBackup` envelope sized by KEM and signer. No sender key is supplied. Peer
cloning is gated by the security domain's `allow_peer_cloning` policy flag.
The `dst_evidence` partition-owner chain must anchor to the policy POTA
key thumbprint.

The inputs are grouped into an
[`tsra_sd_create_peer_backup_params`](#tsra_sd_create_peer_backup_params)
structure. The output buffer follows the two-call size-probe contract and
is validated **before** the peer backup is created. A NULL `params` pointer
is rejected with `TSRA_STATUS_INVALID_ARGUMENT`.

```cpp
tsra_status tsra_sd_create_peer_backup(
    tsra_handle sess_handle,
    const struct tsra_sd_create_peer_backup_params *params,
    struct tsra_buffer *pok_peer_backup
    );
```

**Parameters**

 | Parameter                | Name                                                                                              | Description                                     |
 | ------------------------ | ------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
 | [in] sess_handle         | [tsra_handle](#tsra_handle)                                                                   | security-domain session handle                  |
 | [in] params              | [tsra_sd_create_peer_backup_params*](#tsra_sd_create_peer_backup_params)      | create-peer-backup input buffers                |
 | [in, out] pok_peer_backup | [tsra_buffer *](#tsra_buffer)                                                                | complete peer backup; reserve 6531 B |

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

Verifies the POTA-authorized source PID's direct `SdBackup` signature,
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
    const struct tsra_sd_identity_evidence *src_evidence;
    const struct tsra_buffer *pok_peer_backup;
    const struct tsra_buffer *prev_sd_mk_backup;
};
```

 | Field              | Name                                       | Description                                         |
 | ------------------ | ------------------------------------------ | --------------------------------------------------- |
 | part_policy        | [tsra_buffer*](#tsra_buffer)               | unified partition-policy image (1-384 B)              |
 | masked_sealing_key | [tsra_buffer*](#tsra_buffer)               | receiver's masked SD-sealing key (264 / 280 / 296 B) |
 | src_evidence       | [tsra_sd_identity_evidence*](#tsra_sd_identity_evidence) | source (peer) PID identity chains |
 | pok_peer_backup    | [tsra_buffer*](#tsra_buffer)               | complete signed peer backup; exact length from the KEM/signer table |
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

Recipient-key attestation evidence: three certificate
chains (manufacturer, owner, partition-owner) and a COSE_Sign1 attestation
report. The DER bytes are borrowed, not copied, and must outlive the call.
The report attests a `PublicKey`, not a transferred backup.

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

### tsra_sd_identity_evidence

Source PID identity for a signed transfer. Certificate bytes are borrowed
and must outlive the call. The transfer signature is inside the backup,
not in this structure. The owner chain is optional; the command and policy
determine whether the manufacturer and partition-owner chains are required.

```cpp
struct tsra_sd_identity_evidence {
    struct tsra_sd_cert_chain mfgr_cert_chain;
    struct tsra_sd_cert_chain owner_cert_chain;
    struct tsra_sd_cert_chain part_owner_cert_chain;
};
```

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
