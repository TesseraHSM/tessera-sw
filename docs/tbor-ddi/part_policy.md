<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Partition Policy (CBOR)

**Status:** Implemented. Decoder: `fw/core/ddi/tbor/types/src/policy.rs`.

## Overview

The partition policy is a caller-asserted document. It names the trust
anchors and options a partition is provisioned under. `PartInit` binds it
into the partition's root secret (`UMS`) and the PTAReport claims, and
commits its SHA-384 digest. `FinalizePart` and later commands receive the
same policy bytes again and check them against the committed digest.

The policy is encoded as a **deterministic CBOR map** with integer keys. It
is carried as an opaque, variable-length TBOR `buffer` field (TBOR itself is
not CBOR; see the [TBOR specification](../../fw/core/ddi/tbor/docs/spec.md)).

The policy does not carry public keys. It identifies each key by its
**public-key thumbprint**, defined below.

## Public-key thumbprint

```
<x>_spki_thumbprint = SHA-384( DER(SubjectPublicKeyInfo) )     // 48 bytes
```

The `SubjectPublicKeyInfo` must be in the canonical P-384 form:

- **algorithm:** `id-ecPublicKey` (1.2.840.10045.2.1) with the named-curve
  parameter `secp384r1` (1.3.132.0.34). Explicit curve parameters are not
  allowed.
- **subjectPublicKey:** the uncompressed SEC1 point `04 ‖ X ‖ Y` (97 bytes).
  Compressed points are not allowed.

That encoding is exactly 120 bytes: a fixed 23-byte prefix followed by the
97-byte point.

```
30 76 30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22 03 62 00 ‖ 04 ‖ X ‖ Y
```

Host tooling can compute a thumbprint with:

```sh
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform DER | openssl dgst -sha384
```

The thumbprint identifies the **key**, not a certificate, so it does not
change when a certificate is reissued for the same key.

## Schema

The policy is a CBOR map whose keys are unsigned integers.

| Key | Name | CBOR type | Presence | Meaning |
|---|---|---|---|---|
| 1 | `version` | uint | required | Policy format version. Must be `1`. |
| 2 | `pota_spki_thumbprint` | bstr (48) | required | Partition Owner Trust Anchor key. |
| 3 | `sata_spki_thumbprint` | bstr (48) | required | Security-domain (SA) Trust Anchor key. |
| 4 | `sapota_spki_thumbprint` | bstr (48) | optional | SA Partition Owner Trust Anchor key. |
| 5 | `backup_part_id` | bstr (16) | optional, with key 6 | Partition ID of the backing partition. |
| 6 | `backup_part_spki_thumbprint` | bstr (48) | optional, with key 5 | Backing partition's PID public key. |
| 7 | `flags` | uint | required | Bitmask; see [Flags](#flags). |
| 8 | `info` | bstr (1..=64) | optional | Opaque caller data. Not interpreted by firmware. |
| 9 | `data_spki_thumbprint` | bstr (48) | optional | DARC (TMK export) Trust Anchor key. |

Keys 5 and 6 must be either both present or both absent.

The maximum encoded size is 345 bytes. `PART_POLICY_MAX_LEN` is 384 bytes,
which leaves room for future fields.

### Flags

| Bit | Name | Meaning |
|---|---|---|
| 0 | `include_fmc_cdi` | Include the FMC Composite Device Identity (CDI-FMC) in key derivations. |
| 1 | `require_trusted_sa_key` | Remote backup create/restore must anchor to `sapota_spki_thumbprint`. |
| 2 | `allow_peer_cloning` | Allow cloning the security domain to a peer partition endorsed by the same POTA. |
| 3..=7 | reserved | Must be zero. |

`flags` must be less than 256 and must not set reserved bits.

## Encoding rules

The policy bytes are hashed into `UMS`, the PTAReport `report_data`, and the
committed policy digest. Any change to the bytes changes the partition, so
there must be exactly one valid encoding of each policy. The firmware
**rejects** (with `InvalidArg`) any policy that does not follow the core
deterministic encoding of RFC 8949 §4.2.1:

- The top level is exactly one definite-length map, with no trailing bytes.
- Map keys are unsigned integers in strictly ascending order, with no
  duplicates.
- Unknown keys are rejected. New fields require a new `version`.
- All integers and lengths use the shortest form.
- Only definite-length items are allowed (no indefinite-length strings or
  containers).
- Tags, floats, `null`, `undefined`, and simple values are rejected.
- An optional field is encoded by leaving its key out. Empty byte strings
  are never valid.
- Byte-string lengths must match the schema exactly.
- The encoded policy must not be larger than `PART_POLICY_MAX_LEN`.

## Test vectors

These vectors match the SDK builder tests (`api/lib/src/ddi/part_policy.rs`).
`T(b)` is 48 bytes of value `b`, encoded `58 30 ‖ T(b)`.

**Thumbprint.** The P-384 generator point G:

```
X = aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
Y = 3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
spki_thumbprint = 9b816e622b2e1a95723958091bfa35d774110a7475ec59c9425e007a8a84e0eb
                  aabef67249e6a0fe621ae4f4d30b0cc8
```

**Minimal policy** (107 bytes): POTA `T(11)`, SATA `T(22)`, flags 0.

```
A4                      map(4)
   01 01                version 1
   02 58 30 T(11)       pota_spki_thumbprint
   03 58 30 T(22)       sata_spki_thumbprint
   07 00                flags 0
```

**Full policy** (345 bytes): every field present, all flags set.

```
A9                      map(9)
   01 01                version 1
   02 58 30 T(11)       pota_spki_thumbprint
   03 58 30 T(22)       sata_spki_thumbprint
   04 58 30 T(33)       sapota_spki_thumbprint
   05 50 44×16          backup_part_id
   06 58 30 T(55)       backup_part_spki_thumbprint
   07 07                flags 7
   08 58 40 77×64       info
   09 58 30 T(66)       data_spki_thumbprint
```

## Firmware use

Every place that uses a policy key today needs only its identity, because
the full key is always available from the request or the partition:

| Field | Use | Check |
|---|---|---|
| `pota_spki_thumbprint` | Anchor of the PTA chain (`FinalizePart`), the partition-owner chain (peer backup create/restore, remote reseal, evidence), and the DARC TMK import sender chain. | Some non-leaf certificate's SPKI thumbprint equals the policy value. |
| `sata_spki_thumbprint` | Anchor of the remote backup create/restore receiver and sender chains. | Same as above. |
| `sapota_spki_thumbprint` | Anchor of the partition-owner chain for remote backup when `require_trusted_sa_key` is set. | Same as above. |
| `data_spki_thumbprint` | Anchor of the DARC TMK export target chain. | Same as above. |
| `backup_part_spki_thumbprint` | `SdCreateRemoteBackup` checks that this partition is the backing partition. | Thumbprint of the partition's PID public key equals the policy value, and `backup_part_id` equals the PID. |

A chain is anchored when the SHA-384 of some non-leaf certificate's
canonical SPKI equals the anchor thumbprint. The certificate parser
(`fw/core/crypto/x509-chain`) accepts only named-curve P-384 keys with
uncompressed points, so firmware rebuilds and hashes the canonical SPKI
directly.

## Persistence and binding

- The partition still stores only the 48-byte SHA-384 policy digest. The
  policy itself is not persisted.
- `PART_POLICY_MAX_LEN` (384) is an upper bound; the host SDK checks only
  that the policy is 1 to 384 bytes and leaves decoding to firmware.
- `UMS` derivation, the PTAReport `report_data`
  (`u16_be(|policy|) ‖ policy`), and the policy digest all use the exact
  CBOR bytes received.

## See also

- [`PartInit`](./commands/part_init.md),
  [`FinalizePart`](./commands/part_final.md)
- Certificate chain validation: `fw/core/crypto/x509-chain/src/validate.rs`
- RFC 8949 §4.2.1 (core deterministic CBOR encoding)
- RFC 5480 (ECC SubjectPublicKeyInfo)
