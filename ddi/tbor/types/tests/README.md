<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# `tsra_ddi_tbor_types` integration test suite

A single test binary, [`tsra_ddi_tbor_tests.rs`](tsra_ddi_tbor_tests.rs),
exposes the [`commands/`](commands/mod.rs) module — one file (or
directory) per TBOR DDI command, each grouping happy-path / FW-reject
/ crypto-reject / default-PSK-gate tests.

Shared test infrastructure lives in the
[`tsra_ddi_tbor_test_harness`](../../../../crates/tbor_test_harness/src/lib.rs)
crate under [`crates/tbor_test_harness`](../../../../crates/tbor_test_harness):
per-test [`TestCtx`](../../../../crates/tbor_test_harness/src/ctx.rs)
fixture, [`SessionGuard`](../../../../crates/tbor_test_harness/src/session_guard.rs)
RAII close, session-establishment + per-command crypto helpers,
canonical error-shape assertions.

## Backend feature regimes

Build modes; see the crate-level doc in
[`crates/tbor_test_harness/src/lib.rs`](../../../../crates/tbor_test_harness/src/lib.rs)
for the full per-feature gating table.

* `--features emu` — canonical configuration, runs the full suite.
* `--features sock` — firmware behind a running socket DDI server.
* No backend feature — native OS backend (`nix` on Linux / `win` on
  Windows); hardware-eligible command tests run against real silicon.

For `PartFinal`, emulator tests transport the real PTA certificate chain
through OOB descriptors and exercise full chain validation. Native M1.0
tests send one schema-required placeholder descriptor with no OOB payload
because the current hardware firmware intentionally ignores certificate
descriptors; native certificate-chain validation remains M1.5 work.

The canonical command is:

```bash
cargo test -p tsra_ddi_tbor_types --tests --features emu
```

For socket runs, start `ddi_sock_server` separately and run tests serially:

```sh
TSRA_DDI_SOCK=tcp://127.0.0.1:1234 cargo nextest run \
  -p tsra_ddi_tbor_types --features sock --test tsra_ddi_tbor_tests \
  --test-threads 1 --no-fail-fast
```

Tests reset the endpoint's shared partition. Use a dedicated server without
other clients. Socket connections permit multiple sessions; per-file-handle
limit tests apply only to the emulator/native drivers. Invalid or closed socket
session IDs can be rejected by the ownership gate before reaching firmware.

## Spec coverage matrix

[`SPEC_COVERAGE.md`](SPEC_COVERAGE.md) maps each TBOR wire-protocol
requirement to the integration test that proves it, plus a short list
of known gaps. Update it alongside any test added, renamed, or
removed; the file's footer documents the maintenance rules.
