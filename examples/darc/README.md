# DARC TMK transfer example

Moves a DARC transport master key (TMK) from a source partition to a target
partition for each recipient KEM:

| KEM              | HPKE suite | KEX public key | Sealed TMK |
|------------------|------------|----------------|------------|
| `p384`           | P-384      | 96 B           | 258 B      |
| `mlkem1024`      | HPKE-13    | 1568 B         | 1729 B     |
| `mlkem1024-p384` | HPKE-10    | 1665 B         | 1826 B     |

## Flow

1. `provision` (each party): factory-reset, bind a policy that names shared
   demo POTA/SATA/DATA authorities, finalize, and initialize the security
   domain. Saves two PID chains: POTA-anchored (report signer) and
   DATA-anchored (DARC recipient).
2. `kex` (target): `darc_kex_key_gen` plus `darc_kex_key_report`, the
   target PID's attestation of the KEX key.
3. `export` (source): `darc_tmk_gen`, then `darc_tmk_export` against the
   target's DATA-anchored chain and key report. Produces the HPKE envelope
   and the source PID's `Darc` report.
4. `import` (target): `darc_tmk_import` verifies the report under the
   source's POTA-anchored chain and re-masks the TMK under the target SD.

Artifacts are exchanged through files under `--state-dir`.

## Run

```bash
examples/darc/run_all_kems.sh              # all three KEMs
examples/darc/run_all_kems.sh mlkem1024    # a subset
```

The script starts two `ddi_sock_server` simulators on loopback
(`BASE_PORT`, default 13600) and drives the binary through
`TSRA_DDI_ARGS`. Each subcommand can also be run by hand:

```bash
TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:13600" \
    target/debug/darc --state-dir state provision --name source
```

Development use only: the demo authorities' private keys are stored
unprotected in the state directory and the socket transport is
unauthenticated.
