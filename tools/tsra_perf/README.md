<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# tsra_perf

Throughput and latency of Tessera HSM commands on the regular HSM path,
modeled on `mcr_perf`.

A run spawns `--threads` workers that issue requests back to back through a
warm-up period, a measured window and a cool-down period, all aligned to one
start time so every thread is loaded for the whole window. Only requests that
complete inside the window count, and only the device call is timed (request
encoding, the ioctl and response decoding; not the host checks).

## Correctness first

Numbers from a device that returns wrong answers are worthless, so:

* Before any timing, every selected operation runs twice against each key and
  every response is checked against a host reference implementation (OpenSSL
  through `tsra_crypto`): ECDSA and raw RSA signatures are verified with the
  public key, AES-CBC and AES-GCM outputs are compared with the host's for the
  same key, IV and input, and GCM decrypts must return the original plaintext.
  Any mismatch fails the run.
* PQC operations are checked against `tsra_crypto`'s pure-Rust ML-DSA and
  ML-KEM, which are independent of the firmware's: ML-DSA signatures must
  verify on the host and the device must accept host signatures (and, in the
  pre-flight check, reject a tampered one). Generated keys must have the
  parameter set's lengths, and in the pre-flight check each is used once (an
  ML-DSA key signs, an ML-KEM key decapsulates a host ciphertext). ML-KEM
  shared secrets come back masked under a key the host cannot derive, so
  encapsulate and decapsulate results are checked for shape only (lengths and
  the masked secret's AEAD envelope), as the TBOR PQC tests do.
* `--verify-all` checks every timed response as well. It adds host work
  between requests, so leave it off for the numbers themselves.
* Any failed request makes the run exit non-zero.

## Inputs vary per request

Keyed operations rotate through `--keys` distinct keys (default 8) and each
thread rotates through `--messages` distinct messages (default 64), so every
key meets every message and nothing can be cached or specialized across
requests. GCM encrypts use a fresh IV per request.

ML-DSA verify inputs (`--keys` host keys, each signing the same `--messages`
messages) and ML-KEM decapsulate inputs (`--messages` host ciphertexts per
key) are expensive to make, so they are made once and shared by all threads,
each thread starting at its own key and message.

## Device setup

When a keyed operation is selected the tool factory-resets the device, rotates
the Crypto Officer PSK, initializes and finalizes the partition, and opens one
CO session that all keyed requests share (the hardware allows one session per
file descriptor and one concurrent CO session). Then it generates the ECC keys
on the device and imports host-generated RSA and AES keys with `UnwrapKey`, so
the host can check results. Out-of-session commands (`ApiRev`, `TestAesGcm`)
and MBOR `GetApiRev` use a file descriptor per thread.

The PQC operations (`tbor-mldsa-*`, `tbor-mlkem-*`) run in the same session,
with keys masked under the partition-local scope: ML-DSA sign and ML-KEM
decapsulate use keys generated on the device, ML-DSA verify and ML-KEM
encapsulate use keys generated on the host. Keygen operations generate one key
per request. ML-DSA operations use 64-byte messages and an empty context.

`tbor-aes-gcm-*` uses the test-only `TestAesGcm` command, so the firmware must
be built with `tbor-test-cmds` (the Uno bring-up image is).

Keyed MBOR operations (`mbor-ecc-sign-*`) instead factory-reset the device,
establish an MBOR credential and open an MBOR app session as the MBOR DDI tests
do, then generate their keys in it. `EstablishCredential` is only in firmware
built with the `mbor` feature, and MBOR and TBOR setup do not mix on one boot,
so run keyed MBOR operations on their own, after a power cycle.

## Usage

```sh
# Operation names
tsra_perf list

# One operation, or a weighted mix
tsra_perf perf --threads 4 --op tbor-ecc-sign-p256
tsra_perf perf --threads 4 --op tbor-ecc-sign-p256=3 --op tbor-aes-cbc-encrypt=1

# Each operation alone at several thread counts, saved for later comparison
tsra_perf suite --threads 1,4,16 --test-seconds 20 \
    --label "<firmware version>" --tsv before.tsv --markdown before.md

# Compare two result files
tsra_perf compare before.tsv after.tsv --markdown compare.md
```

`suite` runs the baseline set when no `--op` is given: MBOR and TBOR
`GetApiRev`, TBOR ECC sign (P-256, P-384, P-521), RSA sign (2048 plain and
CRT, 4096 CRT), `TestAesGcm` encrypt and decrypt (2 KiB text, 32 B AAD) and
AES-256-CBC encrypt (1 KiB).

Build with `--features emu` to run against the in-process emulator.

## Results

`results/` holds measured runs on the Uno EVB, named by firmware version, with
the comparison between them.
