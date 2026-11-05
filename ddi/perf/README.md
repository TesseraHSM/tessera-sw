<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# tsra_ddi_perf

Measures the throughput and latency of HSM commands on the DDI path: TBOR
commands, plus MBOR `GetApiRev`.

A run starts `--threads` workers that issue requests back to back through a
warm-up period, a measured window and a cool-down period, all aligned to one
start time so every thread is loaded for the whole window. Only requests that
complete inside the window count, and only the device call is timed (request
encoding, the device round trip and response decoding; not the host checks).

> **Note:** selecting any keyed operation (all but the two `get-api-rev`
> operations) factory-resets the device, rotates the Crypto Officer PSK to a
> fresh random value that is never kept or printed, initializes and finalizes
> the partition, and opens one CO session that all keyed requests share. After
> such a run the device needs a factory reset before other use; the next run
> and the TBOR tests do this themselves. The `get-api-rev` operations use no
> session; MBOR `GetApiRev` never opens an MBOR session.

## Build

```sh
# Against the device driver
cargo build --release -p tsra_ddi_perf

# Against the in-process emulator
cargo build --release -p tsra_ddi_perf --features emu
```

The binary is `target/release/tsra_ddi_perf`. With `cargo run`, pass the
tool's arguments after `--`, e.g.
`cargo run --release -p tsra_ddi_perf --features emu -- list`. Both builds
write the same binary, so rebuild without `--features emu` before measuring
a device.

Every run first prints the device it uses, even with `--quiet`, e.g.
`device: /dev/tsra0 (firmware <version>, driver <version>)`; an emulator
build says `in-process emulator` there.

## Subcommands

```sh
# list: the operation names
tsra_ddi_perf list

# perf: one operation, or a weighted mix (NAME or NAME=WEIGHT, repeatable)
tsra_ddi_perf perf --threads 32 --test-seconds 30 --op tbor-ecc-sign-p256
tsra_ddi_perf perf --threads 32 --test-seconds 30 --op tbor-ecc-sign-p256=3 \
    --op tbor-aes-cbc-encrypt=1 --op mbor-get-api-rev=1

# suite: each operation alone at each thread count, then a summary table
tsra_ddi_perf suite --threads 32 --test-seconds 30 \
    --label "<firmware version>" --tsv before.tsv --markdown before.md

# compare: two result files written with --tsv
tsra_ddi_perf compare before.tsv after.tsv --markdown compare.md
```

`suite --op` takes a comma-separated list (or a repeated `--op`). Without it,
`suite` runs the baseline set: `tbor-get-api-rev`, `tbor-ecc-sign-p256`,
`tbor-rsa-sign-2k`, `tbor-rsa-sign-2k-crt`, `tbor-aes-cbc-encrypt`,
`tbor-mldsa-sign-44` and `tbor-mlkem-decap-512`.

`compare` matches rows by operation, thread count and payload (a later row
replaces an earlier one with the same key) and shows RPS, p50 and p99 from
both files, with the change in RPS and p50.

## Operations

| Operation | Command | Input |
|---|---|---|
| `mbor-get-api-rev` | MBOR `GetApiRev`, no session | - |
| `tbor-get-api-rev` | TBOR `ApiRev`, no session | - |
| `tbor-ecc-sign-p256`, `-p384`, `-p521` | `EccSign` | 32, 48 or 64-byte digest |
| `tbor-rsa-sign-2k`, `-3k`, `-4k` | `RsaModExp` sign | modulus-sized message |
| `tbor-rsa-sign-2k-crt`, `-3k-crt`, `-4k-crt` | `RsaModExp` sign, CRT key | modulus-sized message |
| `tbor-aes-cbc-encrypt`, `-decrypt` | `AesEncryptDecrypt`, AES-256-CBC | `--cbc-len` bytes |
| `tbor-mldsa-keygen-44`, `-65`, `-87` | `MlDsaGenerateKey` | - |
| `tbor-mldsa-sign-44`, `-65`, `-87` | `MlDsaSign` | 64-byte `μ` |
| `tbor-mldsa-verify-44`, `-65`, `-87` | `MlDsaVerify` | host key and signature, 64-byte `μ` |
| `tbor-mlkem-keygen-512`, `-768`, `-1024` | `MlKemGenerateKey` | - |
| `tbor-mlkem-encap-512`, `-768`, `-1024` | `MlKemEncapsulate` | host encapsulation key |
| `tbor-mlkem-decap-512`, `-768`, `-1024` | `MlKemDecapsulate` | host ciphertext |

ECC keys and the ML-DSA sign and ML-KEM decapsulate keys are generated on the
device. RSA and AES keys are generated on the host and imported with
`UnwrapKey`, so the host can check results. All keys are masked under the
partition-local scope. Keygen operations generate one key per request, and
ML-DSA operations use an empty context.

## Options and defaults

| Option | Default | Meaning |
|---|---|---|
| `--threads` | 32 | Worker threads (`suite`: comma-separated list) |
| `--op` | `perf`: required, `suite`: baseline set | Operations to run |
| `--stabilize-seconds` | 5 | Warm-up and cool-down length, each |
| `--test-seconds` | 30 | Measured window length |
| `--keys` | 8 | Distinct keys per key type |
| `--messages` | 64 | Distinct messages per thread |
| `--cbc-len` | 1024 | AES-CBC message length in bytes, a multiple of 16 and at most 1024 |
| `--verify-all` | off | Check every timed response on the host |
| `--max-samples` | 1000000 | Reservoir-sampled latencies kept per thread and operation, at least 1 |
| `--tsv` | none | Append result rows to this TSV file |
| `--markdown` | none | `suite`, `compare`: also write the table to this file |
| `--label` | empty | Stored with each TSV row, e.g. the firmware version; no tabs, line breaks or other control characters |
| `--device` | 0 | Device index, as enumerated by the DDI backend |
| `--quiet` | off | Suppress progress output |

## TSV columns

`--tsv` appends one row per operation and run, and writes the header line when
the file is empty.

| Column | Meaning |
|---|---|
| `unix_time` | When the row was written, in seconds since the Unix epoch |
| `label` | `--label` |
| `op` | Operation name |
| `threads` | Worker threads in the run (shared by all operations of a `perf` mix) |
| `payload` | Request data size, e.g. `32B digest`, `1024B`, `64B mu` or `768B ct` (ML-KEM ciphertext); `-` if none |
| `keys` | `--keys` |
| `seconds` | Measured window, `--test-seconds` |
| `ops` | Requests completed inside the measured window |
| `rps` | `ops / seconds` |
| `mean_us`, `stddev_us` | Full-window mean and standard deviation of the device call latency, in µs |
| `min_us`, `p50_us`, `p90_us`, `p99_us`, `max_us` | Full-window minimum and maximum; percentiles from the reservoir sample, in µs |
| `errors` | Failed requests in any phase; a run with errors exits non-zero |

## Input rotation and host verification

Keyed operations rotate through `--keys` keys and each thread rotates through
`--messages` messages, so nothing can be cached or specialized across
requests. `MlDsaVerify`, `MlKemEncapsulate` and `MlKemDecapsulate` inputs are
made once on the host and shared by all threads, each thread starting at a
different offset.

Before any timing, each selected operation runs `2 × --keys` times and every
response is checked against a host reference (`tsra_crypto`): ECDSA and raw
RSA signatures must verify with the public key, AES-CBC output must match the
host's, device ML-DSA signatures must verify on the host, and `MlDsaVerify`
must accept host signatures (and, in this check, reject a tampered one).
Generated PQC keys must have the parameter set's lengths, and each keygen
operation also uses the exact checked key response once. CBC runs require at
least as many messages as keys so every key is exercised. ML-KEM shared secrets
come back masked under a key the host cannot derive, so KEM results are checked
for shape only. Any mismatch fails the run. `--verify-all` checks every timed
response too; it adds host work between requests, so leave it off for the
numbers themselves.
