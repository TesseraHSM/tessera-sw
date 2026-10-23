<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# TBOR vs. MBOR throughput, identical settings

Every TBOR operation that has an MBOR equivalent (all but AES-GCM), measured
with the same firmware, driver, load and inputs on both sides. TBOR was run
with `tsra_perf`, MBOR with `mcr_perf`. TBOR was also run, with the same
settings, on the software-GCM firmware the BCP replaced, to show what the BCP
gained.

## Setup (both sides)

| Setting | Value |
|---|---|
| Firmware | `v0.0.0.0-61023072test`: firmware of `e03b09b` (BCP GCM) built with the `mbor` feature, which MBOR `EstablishCredential` needs. Software-GCM TBOR: `v0.0.0.0-61023062test` (firmware of `cf5f107`; TBOR does not use the `mbor` feature) |
| Driver | `tsra.ko` loaded with `pf_res_cnt=64` (checked in `/sys/module/tsra/parameters/pf_res_cnt`; `mcr_perf` reports resource count 64) |
| Boot | Each side on its own fresh boot: PDU power cycle of the host and the EVB, then driver reload |
| Threads | 1 and 32 |
| Duration | 3 s stabilization, 20 s measured |
| Inputs | One key per operation and one fixed input (`mcr_perf` has no rotation; `tsra_perf --keys 1 --messages 1`) |
| Sessions | Keyed operations share one session and one file descriptor across threads; `GetApiRev` uses one file descriptor per thread |
| Payloads | ECC digest 32/48/64 B (P-256/384/521), RSA operand the modulus size, AES-256-CBC 512 B (`mcr_perf`'s message size) |

```sh
# TBOR
tsra_perf suite --threads 1,32 --stabilize-seconds 3 --test-seconds 20 \
    --keys 1 --messages 1 --cbc-len 512 \
    --op tbor-get-api-rev,tbor-ecc-sign-p256,tbor-ecc-sign-p384,tbor-ecc-sign-p521,tbor-rsa-sign-2k,tbor-rsa-sign-2k-crt,tbor-rsa-sign-4k-crt,tbor-aes-cbc-encrypt
# MBOR, one run per operation and thread count
mcr_perf perf --threads <1|32> --stabilize-seconds 3 --test-seconds 20 --hide-progress \
    --prt-queue-length 1000000 --shared-session custom --<operation> 1
mcr_perf perf --threads <1|32> --stabilize-seconds 3 --test-seconds 20 --hide-progress \
    --prt-queue-length 1000000 --skip-key-create --skip-app-session-create custom --get-api-rev 1
```

`mcr_perf` came from `martichoras` branch `user/jayg/mcr-perf-cleanup-session`
(`7a98adcbf`, which closes the app session its cleanup opens; without it the
leaked sessions fill the session table after a few runs). It looks for
`/dev/azihsm*`, so it ran through a symlink `/dev/azihsm0 -> /dev/tsra0`; the
two drivers share the ioctl interface.

## Results (requests per second)

TBOR with software GCM (`v0.0.0.0-61023062test`) and with BCP GCM
(`v0.0.0.0-61023072test`), and MBOR (`v0.0.0.0-61023072test`):

**32 threads**

| Operation | Payload | TBOR sw GCM | TBOR BCP GCM | BCP vs. sw | MBOR | TBOR BCP / MBOR |
|---|---|---:|---:|---:|---:|---:|
| GetApiRev | - | 82,086 | 81,892 | 0% | 85,391 | 0.96 |
| ECC sign P-256 | 32 B digest | 9,996 | 16,920 | +69% | 36,943 | 0.46 |
| ECC sign P-384 | 48 B digest | 9,744 | 16,452 | +69% | 24,729 | 0.67 |
| ECC sign P-521 | 64 B digest | 8,813 | 11,709 | +33% | 15,928 | 0.74 |
| RSA sign 2048 | 256 B | 4,954 | 8,000 | +62% | 8,025 | 1.00 |
| RSA sign 2048 CRT | 256 B | 2,799 | 6,420 | +129% | 25,534 | 0.25 |
| RSA sign 4096 CRT | 512 B | 1,625 | 4,291 | +164% | 5,457 | 0.79 |
| AES-256-CBC encrypt | 512 B | 9,479 | 15,962 | +68% | 24,705 | 0.65 |

**1 thread**

| Operation | Payload | TBOR sw GCM | TBOR BCP GCM | BCP vs. sw | MBOR | TBOR BCP / MBOR |
|---|---|---:|---:|---:|---:|---:|
| GetApiRev | - | 35,225 | 35,157 | 0% | 34,506 | 1.02 |
| ECC sign P-256 | 32 B digest | 2,043 | 2,229 | +9% | 2,407 | 0.93 |
| ECC sign P-384 | 48 B digest | 1,301 | 1,379 | +6% | 1,445 | 0.95 |
| ECC sign P-521 | 64 B digest | 870 | 890 | +2% | 942 | 0.95 |
| RSA sign 2048 | 256 B | 442 | 459 | +4% | 476 | 0.96 |
| RSA sign 2048 CRT | 256 B | 990 | 1,244 | +26% | 1,484 | 0.84 |
| RSA sign 4096 CRT | 512 B | 274 | 306 | +11% | 327 | 0.93 |
| AES-256-CBC encrypt | 512 B | 7,307 | 10,613 | +45% | 15,042 | 0.71 |

Full statistics: `tbor.tsv` / `tbor.md` and `tbor-sw-gcm-61023062.tsv` /
`tbor-sw-gcm-61023062.md` (`tsra_perf`), `mbor-mcr_perf.tsv`
(converted from the `mcr_perf` output in `mcr_perf-logs/`). `mcr_perf`'s latency quantiles are
histogram-binned, so only throughput is compared here.

## Tool cross-check

On the MBOR boot, `tsra_perf`'s own MBOR operations with the same settings
(`mbor-tsra_perf-crosscheck.tsv`) agree with `mcr_perf` to within 1.6%, so the
two tools measure the same thing:

| MBOR operation | Threads | `mcr_perf` RPS | `tsra_perf` RPS |
|---|---:|---:|---:|
| GetApiRev | 1 | 34,506 | 34,323 |
| GetApiRev | 32 | 85,391 | 85,471 |
| ECC sign P-256 | 1 | 2,407 | 2,406 |
| ECC sign P-256 | 32 | 36,943 | 36,345 |
| ECC sign P-384 | 1 | 1,445 | 1,444 |
| ECC sign P-384 | 32 | 24,729 | 24,787 |
