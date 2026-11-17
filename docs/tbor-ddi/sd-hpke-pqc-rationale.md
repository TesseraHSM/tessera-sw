<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Security-domain transfers: preparing HPKE authentication for PQC

## 1. Scope and comparison baseline

This document covers **security-domain (SD) commands only**. It explains
the move from HPKE Auth with a sender sealing key to **HPKE Base plus a
PID-signed operation report**, including changes to authorization that
are separate from the choice of cryptographic mechanism.

The comparison is between:

- **Existing design:** the SD command specifications and implementations
  on `main` at
  [`697cc5f7`](https://github.com/TesseraHSM/tessera-sw/tree/697cc5f7922d38fc2bbd3ef05ba8b466780e39de).
- **New design:** the SD refactor in `feat/sd-darc-hpke-refac`, specifically
  the handlers and schemas linked below.

The five changed transfer commands retain their existing opcodes and
purposes. Local recovery and the SD key hierarchy are not redesigned.
The per-command specifications remain the wire-contract reference;
this document explains their rationale and security consequences.

**This refactor prepares the authentication architecture for PQC; it
does not itself make SD transfers post-quantum secure.** Its transfer
suite, sealing keys, PID signatures, and key identifiers remain P-384
based. The envelope parser accepts only the fixed classical suite.
ML-KEM and PQ/traditional hybrid SD suites require additional work.

## 2. Why HPKE Auth cannot simply be switched to ML-KEM

### 2.1 HPKE encryption and sender authentication are distinct

[RFC 9180, Sections 4 and 5][rfc9180-modes] defines four modes:

| Mode | Sender authentication input | Required KEM interface |
|---|---|---|
| Base (`0x00`) | None | `Encap` / `Decap` |
| PSK (`0x01`) | Pre-shared secret | `Encap` / `Decap` |
| Auth (`0x02`) | Sender's static KEM private key | `AuthEncap` / `AuthDecap` |
| AuthPSK (`0x03`) | Static KEM private key and PSK | `AuthEncap` / `AuthDecap` |

Auth and AuthPSK are the **Auth\*** modes discussed here. They are not
synonyms for AEAD authentication: Base still authenticates ciphertext
integrity under its derived AEAD key, but anyone knowing the recipient
public key can construct a Base ciphertext. Base alone does not identify
or authorize a sender.

The existing SD design uses **Auth**, not AuthPSK. For DHKEM, Auth mixes
both ephemeral-to-recipient and static-sender-to-recipient DH results
into the KEM shared secret. Thus a sender sealing private key is part of
the encryption operation. This authenticates possession of that key,
not an application identity or an SD policy by itself
([RFC 9180, Section 5.1.3][rfc9180-auth]).

### 2.2 The relevant PQ and hybrid KEMs do not define AuthEncap

The ML-KEM and PQ/traditional hybrid algorithms in
[draft-ietf-hpke-pq-05, Sections 3, 4, and 7.2][pq-auth] provide
`Encap` / `Decap`, **not** `AuthEncap` / `AuthDecap`.
Section 7.2 explicitly identifies PSK-authenticated HPKE or digital
signatures as possible alternatives for applications migrating Auth
mode. RFC 9180 already permits this limitation: a KEM without the Auth
interface supports only Base or PSK mode.

Having an ECDH component inside a hybrid KEM does not make the *combined*
KEM an authenticated KEM. Adding a static DH contribution ourselves
would define a different construction with its own analysis and
interoperability requirements; it would not be a selector change to
the specified hybrid KEM.

The PQ reference above is an **Internet-Draft, work in progress**, not
a published PQ HPKE RFC. Its exact revision is pinned here so that the
claim can be checked independently of later standards changes.
RFC 9180 is the published, Informational HPKE reference.

Also distinguish the two meanings of "hybrid": HPKE combines public-key
and symmetric encryption; a **PQ/traditional hybrid KEM** combines a
post-quantum KEM with a traditional one. HPKE is not automatically PQ
because "hybrid" appears in its name.

### 2.3 Chosen migration: encrypt, then attest the operation

The new SD design separates three decisions:

1. **Recipient authorization:** is this public key allowed to receive BKS3?
2. **Confidentiality:** seal BKS3 to that key using HPKE Base.
3. **Source operation authentication:** the producing partition signs
   the complete encrypted transfer and its security context with its
   actual PID key.

The recipient verifies the signed operation and its authorization
before HPKE decapsulation. This fits an ordinary KEM interface and does
not require distributing pairwise or group PSKs across backup partitions,
peers, and sealing authorities. It reuses the existing PID/certificate
trust model instead.

This is a TSRA application protocol built from HPKE and COSE signatures,
**not a new HPKE mode**. RFC 9180 does not prove the entire SD protocol:
the authorization and binding rules below are necessary parts of its
security argument. The standards supply the building blocks, not the
application's trust policy.

## 3. Existing design versus new design

| Aspect | Existing design on main | New design |
|---|---|---|
| Encryption | P-384 HPKE Auth | P-384 HPKE Base |
| Source authentication | Possession of a sender SD-sealing private key, authenticated through HPKE | PID signature over an `SdBackup` operation report |
| Source evidence for peer restore/reseal | PID-signed `PublicKey` attestation of the sender sealing key | PID identity chains plus the producer's `SdBackup` report |
| Destination evidence for peer export/reseal | `PublicKey` attestation of the recipient sealing key | Retained, including generated SD-sealing provenance and policy checks |
| Create-remote/create-peer sender key input | Caller supplies `masked_sealing_key` | Removed; firmware selects its actual PID signer |
| Reseal key roles | One sealing key opens the input and authenticates the output | Recipient sealing key opens the input; SA PID signs the output |
| HPKE application context | Empty `info` and AAD in the SD transfer handlers | Canonical header used as both `info` and AAD |
| Encrypted BKS3 artifact | `enc[97] \|\| ciphertext_and_tag[64]`: 161 bytes | Header plus the same-sized HPKE outputs: 322 bytes |
| Producer response | Encrypted backup, plus local backups where applicable | Adds a required operation `report` |
| Policy binding | Local policy checks, key-attestation policy claims, and SDBMK derivation | Those applicable checks plus an explicit transferred-policy hash bound to the exact ciphertext |
| Remote-restore sender authorization | SATA-authorized sealing key; additional SAPOTA attestation when requested | No SATA sender chain; SAPOTA-authorized PID when requested, otherwise caller-selected PID with signature verification only |
| Local BKS3/SDMK backup formats | Existing authenticated masking formats | Unchanged |

The final authorization row is an intentional **trust-contract delta**,
not a requirement imposed by ML-KEM. It must not be hidden behind a claim
that all old security properties are unchanged; see Section 7.

Some existing main command-spec tables still say 276-byte masked keys /
local backups and 260-byte SDMK backups. The main **schemas and code
already require 280 and 264 bytes**, respectively. These stale prose
sizes are not protocol changes introduced by this migration. The actual
encrypted remote/peer artifact does change from 161 to 322 bytes.

## 4. New transfer and evidence contract

### 4.1 Key roles and trust anchors

| Term | Role |
|---|---|
| BKS3 | 48-byte SD partition-owner seed transferred inside HPKE; not the live SDMK |
| SDMK | 32-byte live SD masking key; recovered separately from `sd_mk_backup` |
| PID | Partition-identity signing key; signs reports and is not the HPKE recipient key |
| SD sealing key | Recipient KEM key, supplied as a masked private key when opening a transfer |
| POTA | SD policy's partition-owner trust anchor for client/peer PID evidence |
| SATA | Authorizes the recipient key of initial remote creation |
| SAPOTA | Authorizes SA evidence when `require_trusted_sa_key` is enabled |

SATA remains authoritative for the **initial remote recipient**, even
when trusted-SA evidence is optional. POTA and SAPOTA authorize PID
identities through certificate chains; a signature under an arbitrary
PID key does not substitute for either authorization.

When identity evidence is required, the implementation requires
manufacturer and partition-owner chains. A device-owner chain is
optional; if supplied, it must validate and agree on the same PID leaf.
The partition-owner chain must match the selected POTA/SAPOTA anchor.
The manufacturer and optional owner chains are validated for consistency
but are **not independently pinned to manufacturer/owner trust anchors**
by this helper. Do not interpret their presence alone as an additional,
independently rooted manufacturer trust guarantee.

### 4.2 Canonical SD envelope

The current profile is:

```text
suite = DHKEM(P-384, HKDF-SHA384) / HKDF-SHA384 / AES-256-GCM

spki_thumbprint(pk) = SHA-384(canonical_DER_SPKI(pk))
policy_hash = SHA-384(exact validated deterministic-CBOR SD policy)

header =
    "TSRA-XFER"                 // 9 bytes
    || version[1]              // 1
    || report_kind[1]          // SdBackup = 2
    || kem_id_be16             // 0x0011
    || kdf_id_be16             // 0x0002
    || aead_id_be16            // 0x0002
    || source_pid_spki_thumbprint[48]
    || recipient_spki_thumbprint[48]
    || policy_hash[48]

enc, ciphertext_and_tag = HPKE.Base.Seal(
    recipient_public_key, info=header, aad=header, plaintext=BKS3)

envelope = header[161] || enc[97] || ciphertext_and_tag[64]
envelope_hash = SHA-384("TSRA-XFER-HASH-v1" || envelope)
```

Both SD key thumbprints use canonical DER SubjectPublicKeyInfo, matching
the policy trust-anchor fingerprint convention. For the current profile,
SPKI encodes `id-ecPublicKey`, the `secp384r1` named curve, and an uncompressed
`0x04 || X_be[48] || Y_be[48]` point (120 bytes total). The HPKE encapsulation
remains the 97-byte SEC1 point. A matching fingerprint identifies a key;
it does not confer another role's authorization or replace chain validation.

The header authenticates the operation, source, recipient, policy, and
suite selection. Binding the whole envelope also covers the KEM
encapsulation and the GCM ciphertext/tag. The report is excluded from
the envelope hash, avoiding a circular signature dependency.

RFC 9180 Section 8.1 recommends `info` for auxiliary information in
single-shot use. This TSRA profile additionally supplies the same header
as AEAD AAD. That redundant binding is an explicit application choice,
not an RFC requirement or a second independent authentication factor.

The parser rejects unknown versions, unsupported suites, incorrect
operation kinds, wrong lengths, malformed point shape, and trailing data.
Cryptographic point validation occurs during cryptographic use; successful
parsing alone is not authentication.

### 4.3 PublicKey evidence is not export evidence

An `SdBackup` report is a version-2, discriminated COSE_Sign1 report
using ES384. Its signed payload contains:

| CBOR map key | Claim |
|---|---|
| 0 | Report version: 2 |
| 7 | Transferred SD policy hash |
| 8 | Report kind: `SdBackup` (2) |
| 9 | `source_pid_spki_thumbprint`: SHA-384 of the source PID's canonical DER SPKI |
| 10 | `recipient_spki_thumbprint`: SHA-384 of the recipient encryption key's canonical DER SPKI |
| 11 | Complete envelope hash |

The new report format has not been deployed, so the existing revision 2
is retained. The signed kind, rather than a new revision, distinguishes
operation claims from public-key claims. Legacy v1 public-key reports
remain supported.

The exporting command computes these claims internally after validating
the secret and recipient. `seal_backup` derives the source public key
from the partition's actual vaulted PID private key; the caller cannot
select a different source identity or submit a digest for arbitrary
operation signing.

The generic [`KeyReport`](commands/key_report.md) command still produces
**public-key attestation**, including caller report data. Putting an
envelope digest in that report data does not turn it into an export
report. It proves an attestation statement, not that an authorized SD
export of that ciphertext occurred.

Conversely, an `SdBackup` report does not attest a destination sealing
key's attributes. Producer commands still require destination
`PublicKey` evidence wherever their trust contract requires it.
Kind separation prevents substituting one proof for the other.

### 4.4 Receiver acceptance invariant

Before decapsulation, an opening command must establish all of:

```text
authorized source PID, or explicitly selected signature-only SA mode
AND valid PID signature on an SdBackup report
AND report.kind == envelope.kind == SdBackup
AND spki_thumbprint(actual signer PID) == header.source_pid_spki_thumbprint
AND report.source_pid_spki_thumbprint == header.source_pid_spki_thumbprint
AND spki_thumbprint(public key derived from actual recipient private key)
      == header.recipient_spki_thumbprint == report.recipient_spki_thumbprint
AND recomputed_hash(complete envelope) == report.envelope_hash
AND SHA-384(requested SD policy) == header.policy_hash == report.policy_hash
```

The command also checks the bound local policy where applicable.
Reseal deliberately uses the **client SD policy**, not the SA's local
partition policy. All migrated SD opening commands supply an expected
SD policy hash, even though the lower-level transfer helper can be used
without that comparison.

Only after these checks may HPKE Base open the envelope. The opener
decrypts into scratch and copies out exactly 48 bytes only after AEAD
authentication succeeds. A validated report does not bypass HPKE
authentication, and HPKE success does not bypass the report checks.
Recipient-key unmasking can precede report verification; the ordering
guarantee is **before HPKE decapsulation**, not before all private-key
or masking-key use.

## 5. Command-by-command changes

### 5.1 SdSealingKeyGen (0x09): retained recipient-key operation

The [command](commands/sd_sealing_key_gen.md) still generates a P-384
SD-sealing key and returns its masked private key and public key.
There is no new KEM selector in this refactor.

Its role changes for applications: exports no longer need a *sender*
sealing key. Recipients still need the original private key to open a
backup. Use Local or Ephemeral scope for SD bootstrap while its masking
key remains available; post-reset recovery needs the original Local key
and restored local masking key, not a lost ephemeral key. An SD-scoped
key cannot restore the SD whose missing masking key protects it.
Key scope is not a partition-local-custody claim in a public-key report.

### 5.2 SdCreateRemoteBackup (0x0A): create and sign the initial backup

**Main contract:** [existing specification][main-create-remote].
**New contract:** [command specification](commands/sd_create_remote_backup.md).

| Item | Existing | New |
|---|---|---|
| Request | `masked_sealing_key`, `receiver_cert_chain`, `receiver_evidence`, `policy` | Removes the sender `masked_sealing_key`; other inputs retain their roles |
| Source authentication | HPKE Auth with the unmasked sender sealing key | Firmware PID signs the new `SdBackup` report |
| Response | `pok_remote_backup`, `pok_local_backup`, `sd_mk_backup` | Same three logical backups plus required `report`; remote envelope is 322 bytes |

Preserved checks: active CO session, finalized partition, uninitialized
SD, equality with the bound policy, and backing partition ID/PID SPKI
thumbprint matching that policy. The SATA recipient chain remains
mandatory. With `require_trusted_sa_key`, SAPOTA-authorized `PublicKey`
evidence must additionally attest **that same recipient key**; otherwise
that optional recipient evidence is ignored.

Firmware creates fresh BKS3 and SDMK, seals and signs the remote backup,
then uses the unchanged masking/derivation and undo-protected SD commit.
A PID report is not permission to send BKS3 to an uncertified recipient.

### 5.3 SdResealRemoteBackup (0x0B): authenticate input, then re-encrypt

**Main contract:** [existing specification][main-reseal].
**New contract:** [command specification](commands/sd_reseal_remote_backup.md).

| Item | Existing | New |
|---|---|---|
| `masked_sealing_key` | Opens input and authenticates output as HPKE sender | Opens input only |
| `src_evidence` | Source sender's `PublicKey` report attesting its sealing key | Source PID chains plus its `SdBackup` operation report |
| `dest_evidence` | Destination sealing-key `PublicKey` report | Retained |
| Response | `dst_remote_backup` | Fresh 322-byte envelope plus SA-PID-signed `report` |

The SA authorizes the source PID under the **request SD policy's POTA**,
verifies that PID's **signature on the source `SdBackup` operation
report**, and checks the report against the exact input, actual recipient,
and requested SD policy. It separately authorizes the destination PID under
that POTA and verifies the **destination PID's signature on its `PublicKey`
attestation report**. Destination evidence must prove Generated, not
Imported, P-384 SD-sealing provenance and the same requested SD policy hash.
Both signature checks are mandatory regardless of `require_trusted_sa_key`
and complete before source HPKE decapsulation; validating certificate
chains without verifying their reports is insufficient.

Only then does it open BKS3 and seal it to the authorized destination.
The outgoing report identifies the **SA's actual PID**, not the previous
producer, and binds the same **client SD policy hash**. The SA's own
partition policy may differ; substituting its local hash would break
the client SD binding.

This remains a stateless, CO-only operation on an `Initialized`
partition: it does not provision the SA's SD or modify persistent state.
The new report authenticates the immediate resealer; it does not carry
a signed history of every prior hop.

### 5.4 SdRestoreRemoteBackup (0x0C): explicit sender-identity trade-off

**Main contract:** [existing specification][main-restore-remote].
**New contract:** [command specification](commands/sd_restore_remote_backup.md).

| Item | Existing | New |
|---|---|---|
| Sender key input | Required SATA-anchored `sender_cert_chain` yielding the sealing key | Removes that chain; adds `sender_pid_pub_key` as DER SPKI |
| `sender_evidence` report | Optional sealing-key `PublicKey` attestation; required under trusted-SA policy | **Mandatory `SdBackup` operation report**, in both policy modes |
| Source identity checks | SATA always, plus SAPOTA when trusted-SA is set | SAPOTA PID chains only when trusted-SA is set; no SATA sender check |
| Encrypted input | 161-byte Auth artifact | 322-byte Base envelope |
| Response | Refreshed local BKS3 and SDMK backups | Unchanged logical outputs and formats |

When `require_trusted_sa_key` is **set**, the source identity chains must
be SAPOTA-authorized, share the PID leaf, and match the explicitly supplied
PID public key. The report must validate under that PID and bind the target
SD policy, exact envelope, and actual unmasked recipient.

The sender key is carried as a length-delimited DER SPKI, not a thumbprint.
The current profile accepts only canonical uncompressed P-384 SPKI
(120 bytes); raw coordinates, bare SEC1 points, other algorithms,
noncanonical encodings, and trailing data are rejected. SPKI identifies
the algorithm and parameters, allowing future profiles to extend the
accepted algorithms and size bound without replacing the field's framing.
This does not itself enable PQ signatures. The actual key is required to
verify the signature; its thumbprint binds that key to the report and header.

When the flag is **clear**, source certificate chains are ignored, but
the report is **not optional**. Firmware checks the supplied key's
signature and all transfer bindings. Because the caller supplies that
key without an anchored identity check, this provides integrity under a
selected key, **not authenticated SA identity or trusted HSM provenance**.
The old always-on SATA sender authorization is not preserved.

The bound destination policy, recipient-key kind/authentication, exact
BKS3 length, SDMK-backup authentication, SVN checks, one-shot gate, and
undo-protected provisioning remain enforced. The operation policy hash
is the **restored SD's** hash, not necessarily the SA's local policy hash.

### 5.5 SdRestoreLocalBackup (0x0D): no HPKE redesign

The [local restore](commands/sd_restore_local_backup.md) still recovers
BKS3 under `PartLocalMK`, authenticates the SDMK backup under the derived
SDBMK, refreshes both local backups, and provisions SDMK with undo.
It consumes no HPKE envelope or operation report. Its local masking,
policy-derived SDBMK, platform lineage, and one-shot behavior are unchanged.

### 5.6 SdCreatePeerBackup (0x0E): export without a sender sealing key

**Main contract:** [existing specification][main-create-peer].
**New contract:** [command specification](commands/sd_create_peer_backup.md).

| Item | Existing | New |
|---|---|---|
| Request | Sender `masked_sealing_key`, `policy`, `dst_evidence`, `pok_local_backup` | Removes the sender `masked_sealing_key` |
| Secret recovery | Authenticate/unmask local BKS3 backup | Retained |
| Source authentication | HPKE Auth with sender sealing key | Actual exporting PID signs `SdBackup` |
| Response | `pok_peer_backup` | 322-byte peer envelope plus required `report` |

The bound policy must still allow peer cloning. Destination `PublicKey`
evidence must be POTA-authorized, attest a Generated/not Imported SD
sealing key, and carry the same policy hash. Local BKS3 recovery still
authenticates the local backup and applies its key-kind/SVN checks.

This remains stateless and does **not** require the SD-initialized flag:
a finalized partition with the original local masking key and backup
can export without first provisioning SDMK. The signed report now
attests the export, rather than relying on possession of a separate
sender sealing key.

### 5.7 SdRestorePeerBackup (0x0F): validate a peer export operation

**Main contract:** [existing specification][main-restore-peer].
**New contract:** [command specification](commands/sd_restore_peer_backup.md).

| Item | Existing | New |
|---|---|---|
| `src_evidence` | POTA-authorized `PublicKey` report of sender sealing key | POTA-authorized source PID plus mandatory `SdBackup` report |
| Recipient key | `masked_sealing_key` unmasked as `SdSealing` | Retained; derive its public key for the signed recipient-ID check |
| Encrypted input | 161-byte Auth peer artifact | 322-byte Base peer envelope |
| Restore outputs | Local BKS3 and SDMK backups | Unchanged |

The command still verifies equality with the bound SD policy and requires
`allow_peer_cloning`. The source's operation report must carry that policy
and the exact envelope bindings before decapsulation. Source sealing-key
provenance is no longer the proof being consumed; source PID authorization
and a firmware-generated export report replace it. A different key's
`PublicKey` report cannot authorize the import.

SDMK recovery and undo-protected, one-shot provisioning use the same
shared backend as remote/local restore.

### 5.8 KeyReport (0x10) and partition provisioning: supporting boundaries

`KeyReport` remains the destination-key attestation operation, not a
general-purpose `SdBackup` signing API. Its existing signed SD-sealing
flag and Generated/not Imported checks remain important for peer/reseal
recipients. The new operation-report schema does not convert legacy
`PublicKey` reports into export reports.

`PartInit` / `PartFinal` still establish the bound policy, PID identity
chain, and local masking keys. The Auth-to-Base migration does not replace
those trust roots or change the SDMK/SDBMK derivation. No changes to
legacy MBOR behavior are part of this design.

## 6. Security properties and maintained invariants

This analysis assumes uncompromised authorized PID signers and relevant
recipient keys, sound RNG/KDF/AEAD/signature implementations, collision
resistance of SHA-384, and trustworthy execution of the producing and
consuming commands. Signature-only remote restore intentionally weakens
the authorized-signer assumption as described above.

| Property / invariant | How it is maintained; limits |
|---|---|
| BKS3 confidentiality in transit | Base HPKE encrypts the 48-byte seed to an authorized recipient. Only ciphertext and public bindings leave the producer. This branch's P-384 KEM provides classical, not PQ, confidentiality. An authorized SA necessarily sees BKS3 inside its HSM while resealing. |
| Ciphertext integrity | GCM authenticates BKS3 and the header; a separate PID signature binds the whole envelope, including encapsulation and tag. Neither layer is optional. |
| Source operation provenance | In anchored flows, the report verifies under the authorized source PID and is constructed only by the command that actually sealed the secret. This replaces sender-KEM-key possession; it does not claim that both statements are identical. |
| Recipient substitution resistance | Recipient ID is derived from the exact recipient public key during sealing and from the actual unmasked private key during opening; header and report must agree. |
| Source identity substitution resistance | The verifying PID's derived ID must equal the header/report source ID, in addition to the command's chain authorization. A claimed ID alone is not trusted. |
| Policy isolation | Request/bound-policy checks remain where applicable; every SD envelope/report binds the transferred policy. Peer destination reports must match it. SDBMK derivation still binds the provisioned SD policy. |
| Report/envelope mix-and-match resistance | The verifier recomputes the domain-separated hash of the complete envelope. A valid report for another ciphertext, encapsulation, recipient, source, or policy fails. |
| Report-kind / protocol separation | `SdBackup` is a signed discriminator. A `PublicKey` report, caller-controlled report data, another report kind, unknown envelope version, or unsupported suite cannot stand in for it. |
| Recipient authorization | SATA checks remain on remote creation; POTA-attested recipient key/provenance/policy checks remain on peer creation and reseal. Remote-restore source authorization changes separately. |
| Clone permission | Peer create and peer restore still require `allow_peer_cloning`. Operation reports do not bypass the command gate. Reseal retains its separate POTA/client-policy contract. |
| Protected private-key use | Recipient keys remain authenticated masked blobs and must decode as `SdSealing`. Source PID signing uses the actual vaulted PID. No plaintext BKS3/SDMK is a command response. |
| SDMK-backup association | The report does not sign `prev_sd_mk_backup`. Restore still authenticates that blob with SDBMK derived from recovered BKS3, policy, and platform lineage; merely pairing a valid report with an unrelated blob cannot skip this check. |
| SVN / owner-lineage protection | Existing authenticated metadata and versioned-seed derivation remain. A backup with an authenticated SVN newer than the running firmware is rejected. This is not a guarantee of choosing the newest saved backup. |
| One-shot provisioning and atomicity | Create and restore retain the SD-initialized claim and undo-protected vault/property updates. A validation failure does not consume successful provisioning; completion failure retains the existing rollback behavior. |
| Fail-closed plaintext publication | Reports/bindings are checked before HPKE opening; plaintext is copied from scratch only after AEAD success. No fallback to Auth, unsigned Base, or a fresh SD occurs on validation failure. |

The signature also addresses a weakness of DHKEM Auth:
[RFC 9180, Section 9.1.1][rfc9180-kci] describes recipient-key-compromise
impersonation and suggests signing the encapsulation and ciphertext as
a mitigation. Here the signature covers them through the complete
envelope hash. Compromising a recipient KEM key alone does not create a
valid report under another uncompromised, authorized PID. It **does**
compromise confidentiality to that recipient, and does not prevent
replay of already signed transfers.

## 7. Properties changed, lost, or not supplied

### 7.1 Guarantees deliberately changed or lost

| Property | Consequence of the new design |
|---|---|
| Always-on SATA authorization of a remote-restore sender | **Lost.** Trusted mode uses SAPOTA PID authorization instead; non-trusted mode has no anchored SA identity at all. Enabling trusted-SA policy restores an anchored identity requirement, but not the old SATA gate. This is a separate policy decision, not a cryptographic necessity of Base mode. |
| Proof of the source sealing key's possession / attributes | **Replaced**, not preserved verbatim. The sender no longer supplies that key. The receiver relies on the authorized PID's signature over a real export operation, not an attested source sealing-key object. Destination-key provenance checks remain. |
| DHKEM Auth's recipient-forgeability / repudiability | **Not retained.** A PID signature creates publicly verifiable evidence of the signed operation, unlike the Auth relationship where recipient-key compromise permits impersonation. This is useful for audit but changes the deniability/privacy model; it is not a claim of legal non-repudiation. |
| Minimal public transfer metadata | The new cleartext header/report exposes stable source/recipient key IDs and an SD policy hash alongside ciphertext. These authenticate context, but also enable correlation and policy guessing when candidate policies are known. They do not hide identity or policy metadata. |
| Single-artifact recoverability and old wire compatibility | The encrypted artifact is larger and the operation report must be saved with it. An old 161-byte Auth artifact cannot be restored by the migrated commands; a missing report cannot be reconstructed by calling generic `KeyReport`. This is a recovery/availability and migration cost. |

Applications that relied on SATA-authorized **senders** must explicitly
review the remote-restore delta. The existing policy bit must not be
described as preserving that exact old trust contract.

### 7.2 Non-goals and remaining limitations

- **No replay/freshness guarantee.** Reports contain no verifier nonce,
  timestamp, monotonic export counter, or consumed-transfer record.
  Fresh HPKE randomness makes a new export different; it does not make
  an old valid export unacceptable. The one-shot SD gate is per partition
  incarnation, not global anti-replay.
  [RFC 9180, Section 9.7](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7)
  also leaves replay prevention to applications.
- **No newest-backup guarantee.** SVN checks prevent restoring a
  newer-firmware backup on older firmware; they do not prove that the
  caller selected the latest backup at the same SVN or SD incarnation.
- **No forward secrecy against recipient-key compromise.** Stored
  envelopes can be opened if their long-term recipient private key is
  later compromised. This applies to both old Auth and new Base
  ([RFC 9180, Section 9.1][rfc9180-security]).
- **No recipient liveness or delivery confirmation.** Authorization and
  key attestation are not a fresh proof that a live recipient received
  or successfully restored a backup.
- **No protection from a malicious authorized SA or PID.** Resealing
  intentionally delegates access to BKS3. The recipient trusts the
  authorized signing firmware's operation claims; a compromised PID or
  its authority undermines that trust.
- **No complete provenance chain across reseals.** An output report
  identifies its immediate SA producer. Preserve prior reports
  separately if an audit needs the full sequence.
- **No independent manufacturer-root guarantee from the evidence helper.**
  Required chain consistency is not the same as pinning every chain's
  root. The POTA/SAPOTA authorization and its trust assumptions remain
  essential.
- **No end-to-end PQ guarantee in this refactor.** P-384 encryption is
  still vulnerable to a sufficiently capable quantum attacker, and
  ES384/P-384 identity roots remain classical. Introducing a PQ KEM
  later does not automatically make report signatures or identity
  authorization PQ-secure.

These are protocol boundaries, not a statement that all possible
implementation vulnerabilities have been exhaustively reviewed.

## 8. Migration and future PQC requirements

Applications must update host and firmware schemas together; remove
sender sealing-key arguments from producer calls, obtain the producer's
operation report, and pass that report rather than a sender `PublicKey`
report on restore/reseal. Native producer APIs need an additional report
output buffer; reserve the specified 896-byte maximum before a one-shot
operation and persist the actual returned length. The
[native SD API documentation](../../api/native/doc/chapter_09_sd.md)
describes the output-capacity and distinct-buffer contracts.

Store the encrypted backup and report as one logical record, together
with the relevant SDMK backup, policy and certificate material. Preserve
the actual recipient masked key and its masking-key recovery material;
generating a replacement key cannot decrypt an old backup. Keep an
explicit legacy recovery/migration plan before abandoning Auth-format
backups. The implementation does not provide an automatic compatibility
or unsigned fallback.

The architectural invariant for a future ML-KEM or hybrid SD profile is:
**changing the KEM must not remove source signature verification,
recipient authorization, policy binding, or operation-kind separation.**
Completing that migration also requires:

1. Defining and validating suite/version selection, canonical SPKI
   profiles for new key algorithms, larger public keys/encapsulations/envelopes,
   and corresponding host/firmware storage limits. SPKI thumbprints retain
   their 48-byte representation, but the current P-384 key-size bounds
   and crypto implementations do not support another algorithm automatically.
2. Migrating recipient key generation, masking, certification and
   `PublicKey` attestation alongside encryption.
3. Choosing a PQ-safe signature and identity/trust-anchor migration
   strategy if PQ **authentication**, rather than only encryption,
   is required. Classical signatures remain a separate limitation.
4. Binding the chosen suite into both the signed transfer and HPKE
   context, and enforcing the minimum accepted suite in policy. Signed
   suite bytes prevent undetected editing; they do not themselves
   prevent an authorized producer from selecting a disallowed weak suite.
5. Using a specified, analyzed hybrid combiner and its parameter profile,
   not an ad hoc concatenation or an invented Auth interface.
   [PQ HPKE Section 7.1][pq-hybrid-security] explains the conditional
   security benefit of PQ/traditional hybrids.

## 9. Implementation and regression evidence

| Area | Source and what to inspect |
|---|---|
| Actual PID selection and SD-only policy binding | [`sd_transfer.rs`](../../fw/core/lib/src/ddi/tbor/sd_transfer.rs): `seal_backup`, `source`, `open_backup` |
| Envelope encoding and verify-before-open | [`transfer.rs`](../../fw/core/crypto/key-report/src/transfer.rs): `TransferHeader`, `parse_transfer_envelope`, `seal_transfer`, `verify_transfer`, `open_transfer` |
| Report kinds and signed claims | [`report.rs`](../../fw/core/crypto/key-report/src/report.rs), [`encode.rs`](../../fw/core/crypto/key-report/src/encode.rs), [`decode.rs`](../../fw/core/crypto/key-report/src/decode.rs) |
| Anchored PID versus destination-key evidence | [`evidence/src/lib.rs`](../../fw/core/evidence/src/lib.rs): `verify_evidence`, `verify_evidence_signer`, `verify_identity_chains` |
| Retained masking, derivation and commit | [`sd_backup.rs`](../../fw/core/lib/src/ddi/tbor/sd_backup.rs): local BKS3 recovery, `derive_sdbmk`, `reprovision_sd_from_bks3`, `commit_sd_to_vault` |
| Main's actual size authority | [Main SD schemas][main-schema] and [main sealing-key schema][main-key-schema], rather than historical prose constants |

Existing focused regressions support this reasoning; they are not a
formal proof or an assertion of a test run by this document:

- [`key-report/tests/wire.rs`](../../fw/core/crypto/key-report/tests/wire.rs)
  checks typed-report separation, required policy fields, malformed
  reports, and canonical envelope encodings.
- [`key_report_credentials.rs`](../../fw/plat/std/uno/lib/tests/key_report_credentials.rs),
  test `p384_transfer_reports_bind_encryption_identity_kind_and_policy`,
  exercises the SD case for changed encapsulation/ciphertext/tag,
  identity, recipient, policy, kind and signed-claim mismatches. It also
  checks that failure does not publish plaintext and that re-signing a
  changed header cannot rescue ciphertext sealed under the old header.
- The [shared SD command tests](../../ddi/tbor/types/tests/commands/)
  exercise SATA recipient checks, peer/reseal policy and evidence checks,
  actual recipient mismatches, mandatory source operation reports,
  authorized PID matching, and retry after rejected restore inputs.
- [`require_trusted_sa_tests.rs`](../../api/tests/src/sd/require_trusted_sa_tests.rs)
  covers SDK trusted-SA flows, including an SA with a different local
  policy and rejection of unauthorized/mismatched PID evidence.

## 10. Standards references

- **RFC 9180, Hybrid Public Key Encryption (Informational):**
  [Sections 4-5][rfc9180-modes] define KEM interfaces and modes;
  [Section 5.1.3][rfc9180-auth] specifies asymmetric-key authentication;
  [Section 8.1](https://www.rfc-editor.org/rfc/rfc9180.html#section-8.1)
  discusses application context;
  [Section 9.1][rfc9180-security] describes security properties and
  [Section 9.7](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7)
  describes non-goals;
  [Section 9.1.1][rfc9180-kci] discusses KCI and signatures over encrypted
  messages.
- **draft-ietf-hpke-pq-05, Post-Quantum and Post-Quantum/Traditional
  Hybrid Algorithms for HPKE (6 July 2026; work in progress):**
  [Sections 3-4](https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.html#section-3)
  specify ML-KEM and hybrid KEM mappings;
  [Section 7.1][pq-hybrid-security] describes hybrid security;
  [Section 7.2][pq-auth] explicitly states the absence of AuthEncap /
  AuthDecap and identifies signature/PSK alternatives.
- **RFC 9052, CBOR Object Signing and Encryption:**
  [Section 4.2](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2)
  specifies COSE_Sign1;
  [Section 4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4)
  specifies signing and verification. The SD operation claims and trust
  rules are TSRA-specific, not supplied by COSE.

[rfc9180-modes]: https://www.rfc-editor.org/rfc/rfc9180.html#section-4
[rfc9180-auth]: https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1.3
[rfc9180-security]: https://www.rfc-editor.org/rfc/rfc9180.html#section-9.1
[rfc9180-kci]: https://www.rfc-editor.org/rfc/rfc9180.html#section-9.1.1
[pq-auth]: https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.html#section-7.2
[pq-hybrid-security]: https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.html#section-7.1
[main-create-remote]: https://github.com/TesseraHSM/tessera-sw/blob/697cc5f7922d38fc2bbd3ef05ba8b466780e39de/docs/tbor-ddi/commands/sd_create_remote_backup.md
[main-reseal]: https://github.com/TesseraHSM/tessera-sw/blob/697cc5f7922d38fc2bbd3ef05ba8b466780e39de/docs/tbor-ddi/commands/sd_reseal_remote_backup.md
[main-restore-remote]: https://github.com/TesseraHSM/tessera-sw/blob/697cc5f7922d38fc2bbd3ef05ba8b466780e39de/docs/tbor-ddi/commands/sd_restore_remote_backup.md
[main-create-peer]: https://github.com/TesseraHSM/tessera-sw/blob/697cc5f7922d38fc2bbd3ef05ba8b466780e39de/docs/tbor-ddi/commands/sd_create_peer_backup.md
[main-restore-peer]: https://github.com/TesseraHSM/tessera-sw/blob/697cc5f7922d38fc2bbd3ef05ba8b466780e39de/docs/tbor-ddi/commands/sd_restore_peer_backup.md
[main-schema]: https://github.com/TesseraHSM/tessera-sw/blob/697cc5f7922d38fc2bbd3ef05ba8b466780e39de/fw/core/ddi/tbor/types/src/sd_create_remote_backup.rs
[main-key-schema]: https://github.com/TesseraHSM/tessera-sw/blob/697cc5f7922d38fc2bbd3ef05ba8b466780e39de/fw/core/ddi/tbor/types/src/sd_sealing_key_gen.rs
