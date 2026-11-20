<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# RsaSign (`0x35`)

Signs the raw message referenced by an OOB input SGL descriptor using an
authenticated, caller-held masked RSA private key. The device hashes the
message internally and applies RSASSA-PSS or RSASSA-PKCS1-v1_5; this is not
raw `RsaModExp` and is not `RsaEncryptDecrypt`.

The command requires an active CO or CU session and a masked key with the
`sign` usage permission. The masked envelope carries the supported RSA
modulus size (2048, 3072, or 4096 bits) and CRT/non-CRT form; there is no
caller-supplied key-size selector.

## Request fields

| Field | Wire form | Description |
|---|---|---|
| `session_id` | `u16` | Active CO/CU session. |
| `masked_key` | aligned bytes, max 3168 | Authenticated masked RSA private-key envelope. |
| `padding` | `u8` | `0`: PSS; `1`: PKCS#1 v1.5. |
| `hash_algo` | `u8` | Required: `1`: SHA-256, `2`: SHA-384, `3`: SHA-512. |
| `salt_len` | optional `u16` | Required for PSS, including explicit zero; forbidden for v1.5. |
| `message_index` | `u8` | Index of the raw message's input SGL descriptor. |
| `message_len` | `u16` | Raw message length, 0 through 8192 inclusive. |

PSS uses MGF1 with the selected hash and trailer field 1 (`0xBC`). The device
generates the PSS salt internally using its RNG. For modulus length `k`,
`emBits = modulus_bits - 1` and `emLen = ceil(emBits / 8)`; salt length must
not exceed `emLen - digest_len - 2`. The request's salt length is exact and
has no default or maximum-mode sentinel. Digest-length salt (32/48/64 bytes)
is a recommended choice, not a restriction. PKCS#1 v1.5 constructs the
selected hash's DigestInfo; it does not accept a raw DigestInfo or salt.

For an empty message, `message_index` must be zero and no OOB descriptor is
read. Nonempty messages require a valid input descriptor. A direct Data Block
descriptor's length must equal `message_len`. On Uno, a Segment/Last Segment
descriptor is passed unchanged to GDMA, which walks the host SGL and gathers
`message_len` bytes; firmware does not walk SGLs or PRPs.

## Response

The response contains `signature`, an inline byte string exactly the RSA
modulus length: 256, 384, or 512 bytes. Signatures use device operand order:
little-endian on Uno/std Uno and big-endian on std Duo. TBOR framing and SGL
integers remain little-endian.

The host must keep the referenced buffer unchanged and accessible until
command completion. Descriptor capture is not an atomic snapshot of all
message bytes; the digest covers the byte stream actually read once. Session
sealing does not add OOB content guarantees beyond those of the transport.
Uno allocates only `message_len` bytes of scoped DMA scratch, up to 8192 bytes,
without increasing the per-IO heap. It hashes the gathered bytes after DMA
completes and releases the scratch before RSA execution.

Malformed fields, invalid key/scope/permission, and OOB errors return their
specific TBOR status. RNG, hashing, DMA, and RSA execution failures remain
operational errors; no signature is published on failure.
