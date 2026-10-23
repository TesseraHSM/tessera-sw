<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# tsra_perf results: software vs. BCP AES-GCM

These runs measure what moving the Uno PAL's AES-GCM from software (CP1 AES-CTR
with software GHASH) to the BCP (CDMA) bulk crypto engine did to TBOR
commands. Every keyed TBOR command unmasks its key with AES-GCM, so all of
them are affected, not only `TestAesGcm`.

All runs were on the Uno EVB with host mcrnix (`tsra.ko`), kvanto-manticore
`8c1930e`. Each `(operation, threads)` pair runs alone: 3 s warm-up, 20 s
measured, 3 s cool-down. Requests rotate through 8 keys per key type and 64
messages per thread. Every operation was checked against the host reference
before timing, and every run finished with 0 errors.

```sh
# TBOR runs (the default operation set)
tsra_perf suite --threads 1,4,16 --stabilize-seconds 3 --test-seconds 20 \
    --label <firmware> --tsv <file>.tsv --markdown <file>.md
# MBOR ECC sign, on its own boot of a firmware built with `mbor`
tsra_perf suite --threads 1,4,16 --stabilize-seconds 3 --test-seconds 20 \
    --op mbor-ecc-sign-p256,mbor-ecc-sign-p384 --label <firmware> --tsv <file>.tsv
```

| Files | Firmware | AES-GCM | Notes |
|---|---|---|---|
| `baseline-61023060.*` | `v0.0.0.0-61023060test` (`2c6afca`) | software | As found. RSA and P-521 keys cannot be imported on this image: masking a payload that is not a whole number of AES blocks fails (known-issue 2.4), so those operations are missing. |
| `baseline-61023062.*` | `v0.0.0.0-61023062test` (`cf5f107`) | software | **Baseline.** Adds the masking fix so RSA and P-521 can be measured. Operations present in both baselines agree within 0.5%. |
| `bcp-61023065.*` | `v0.0.0.0-61023065test` (`3c7249e`) | BCP | First BCP run. `GetApiRev` lost about 1.5 µs because the PAL poll loop read a BCP register in GSRAM on every pass; fixed by `e03b09b`. |
| `bcp-61023071.*` | `v0.0.0.0-61023071test` (`e03b09b`) | BCP | **After.** |
| `mbor-61023072.*` | `v0.0.0.0-61023072test` | BCP | `61023071` built with the `mbor` feature, which MBOR `EstablishCredential` needs. Run on its own boot. |
| `compare-61023062-vs-61023071.md` | | | `tsra_perf compare` of the baseline and the after run. |

## Summary (baseline → after)

| Operation | 1 thread RPS | 16 threads RPS | 1 thread p50 µs |
|---|---:|---:|---:|
| TBOR `TestAesGcm` encrypt, 2 KiB + 32 B AAD | 2,034 → 5,382 (+165%) | 2,203 → 6,529 (+196%) | 490.5 → 184.7 |
| TBOR `TestAesGcm` decrypt, 2 KiB + 32 B AAD | 2,011 → 5,334 (+165%) | 2,180 → 6,479 (+197%) | 494.8 → 186.5 |
| TBOR ECC sign P-256 | 2,046 → 2,229 (+9%) | 9,958 → 16,795 (+69%) | 488.1 → 447.9 |
| TBOR ECC sign P-384 | 1,302 → 1,378 (+6%) | 9,821 → 16,303 (+66%) | 767.0 → 724.4 |
| TBOR ECC sign P-521 | 868 → 890 (+3%) | 8,773 → 11,324 (+29%) | 1,145.3 → 1,118.0 |
| TBOR RSA sign 2048 | 439 → 460 (+5%) | 4,913 → 7,230 (+47%) | 2,272.9 → 2,178.5 |
| TBOR RSA sign 2048 CRT | 991 → 1,243 (+25%) | 2,802 → 6,389 (+128%) | 1,005.9 → 802.9 |
| TBOR RSA sign 4096 CRT | 272 → 306 (+12%) | 1,624 → 4,206 (+159%) | 3,661.8 → 3,267.2 |
| TBOR AES-CBC encrypt, 1 KiB | 7,197 → 10,284 (+43%) | 9,432 → 15,829 (+68%) | 138.1 → 96.8 |
| TBOR `GetApiRev` | 35,056 → 34,709 (−1.0%) | 80,556 → 80,543 (0.0%) | 28.4 → 28.5 |
| MBOR `GetApiRev` | 35,016 → 34,645 (−1.1%) | 83,991 → 83,688 (−0.4%) | 28.3 → 28.5 |

The full table, with 4 threads and p99, is in `compare-61023062-vs-61023071.md`.

* **GCM itself** is about 2.6× faster on one thread, and its throughput no
  longer stalls at about 2,200 RPS: software GHASH kept CP1 busy for about
  450 µs per 2 KiB.
* **Keyed operations** gain the most under load. With software GCM, CP1 time
  spent unmasking capped ECC sign at 9–10k RPS for every curve and RSA-2048
  CRT at about 2.8k. Single-thread latency drops by the unmask time: about
  40 µs for ECC P-256 and 200 µs for RSA-2048 CRT, whose masked key is larger.
* **`GetApiRev`** does no crypto; the remaining 1% is within run-to-run noise.

## MBOR ECC sign (`mbor-61023072`)

| Operation | 1 thread | 4 threads | 16 threads |
|---|---:|---:|---:|
| MBOR ECC sign P-256 | 2,408 RPS, p50 414.3 µs | 9,565 RPS | 33,572 RPS |
| MBOR ECC sign P-384 | 1,444 RPS, p50 691.5 µs | 5,760 RPS | 22,709 RPS |

MBOR keeps its keys in the vault, so a sign does no unmasking (and MBOR masking
uses AES-CBC, not GCM). At 16 threads MBOR P-256 signs about twice as fast as
TBOR (33.6k vs. 16.8k RPS). Under load, CP1's per-request work in TBOR, which
includes unmasking every key, is still the limit; the PKA engines are not.
