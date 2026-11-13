# Second conformance gate: pkcs11-check

[pkcs11-check](https://github.com/mingulov/pkcs11-check) (MIT OR Apache-2.0)
is a black-box PKCS#11 test client written in Python: several thousand pytest
cases for return codes, templates and attributes, sessions and objects,
memory-safety probes and crypto round trips. It is a second, independent
oracle next to Google pkcs11test (`../pkcs11test`). It has one maintainer and
frequent releases, so it runs from a hash-pinned install, never from a
floating version.

## How the gate works

`run.sh [--pr|--full] <module.so> [work-dir]`

1. creates a virtual environment in the work directory and installs
   `requirements.txt` into it: pkcs11-check 0.2.3 and every package it pulls
   in, at exact versions, with `--require-hashes --no-deps`. pip itself runs
   from a wheel pinned by URL and SHA-256 in `run.sh`. The environment is
   reused until `requirements.txt`, a patch or the pip pin changes,
2. applies the patches in this directory to the installed package,
3. runs `pkcs11-check test --slot 0 --skip-slow` (the fast profile) in a fresh
   directory with the module on its memory store, without the downloadable
   vector suites (an empty data directory, so the run does not depend on what
   was fetched locally),
4. judges the run with `report.py`, which reads the per-test records in
   `report.jsonl` and the crash records in `results.json`. pkcs11-check's
   exit status is ignored: it is non-zero whenever any test fails.

Without an option the gate runs the files of the tests in `include-list.txt`
and fails unless every listed test passed. A listed test that failed, is an
xfail, was skipped, does not exist (renamed upstream) or crashed fails the
gate, and so does any crash in the run that `baseline.txt` does not list.

`--pr` is the same gate for the listed tests in the return-code, security and
attribute files (`PR_FILES` in `run.sh`). It is the part that fits the per-PR
budget of three minutes, and the pkcs11 workflow runs it on every pull
request.

`--full` runs the whole fast profile. On top of the gate rules it fails when a
test passes that is neither listed nor in `baseline.txt`: that test belongs on
the list. The nightly workflow runs it.

Measured on the mock build (2026-11-04, a shared 8-core host under load from
other builds): `--pr` 301 tests in 168 s, the gate 1000 tests in 233 s,
`--full` about 6 minutes.

## The include-list and the baseline

`include-list.txt` names every test of the fast profile that passed on the
mock build (the emulator's predecessor; the same tests pass on the emulator),
except those in `baseline.txt`, which pass without showing anything about
this module:

| tag | why it is off the list |
|---|---|
| `rng` | Tests of the generator itself that go through the patched helper below, so they pass on host bytes. |
| `presence-only` | Claim that a token key persists, but only find the object again. Key survival needs the key used, which the GoogleTest suite does (`key_survival.*`). |
| `tool` | Check pkcs11-check's own tables, not the module. |
| `environment` | Depend on host tools (p11-kit) the gate does not pin. |
| `timing` | Benchmarks and timing ratios: no verdict, or flaky on shared runners. |
| `import-refused` | Set up a plaintext key, which `C_CreateObject` refuses, and pass on that refusal without reaching what they test. |
| `crash` | Known crashes. None at present. |

The list only grows: `run.sh` fails when it names fewer tests than `FLOOR`.
When a change turns tests green, `run.sh --full` names them; add them to the
list (or to the baseline with a tag), raise `FLOOR` and mention it in the
commit. The commented blocks at the end of the list name the tests that do not
pass, grouped by reason: what the module refuses by design (plaintext key
import, templates over 1 MiB) and errors of pkcs11-check itself.

pkcs11-check runs a test file in its own process, and a test in its own
process after a crash, so the module starts fresh for every file: the first
login in each process provisions the emulated partition with the test PIN.

## The patch (`rng-helper.patch`)

This token has no random-number generator (`C_GenerateRandom` returns
`CKR_RANDOM_NO_RNG`). pkcs11-check takes the IVs, nonces and payloads of its
crypto tests from the token through one helper, so without the patch 34 tests
fail before they reach what they test. The patch makes that helper fall back to
host random bytes when the token answers `CKR_RANDOM_NO_RNG`. Tests that call
`C_GenerateRandom` directly see the token's real answer. One test that checks
`CKF_RNG` against the helper (`test_rng_flag_matches_capability`) fails with
the patch and passes without it; it stays off the list.

## Updating the pin

Resolve the new version with pip's `--uploaded-prior-to` set at least two
weeks back, write every package as `name==version` with the hashes of its pure
and manylinux wheels, check that the patch still applies, and regenerate the
list and the baseline from a `--full` run. To install without PyPI, put the
pinned wheels into a directory and point `PIP_FIND_LINKS` at it with
`PIP_NO_INDEX=1`, and copy the pip wheel into the work directory, where
`run.sh` looks for it first.

## Running it locally

```sh
cargo build -p tsra_pkcs11
cargo build -p ddi_sock_server
target/debug/ddi_sock_server tcp://127.0.0.1:23456 &
export TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:23456"
export TSRA_PKCS11_ID=01010101010101010101010101010101
export TSRA_PKCS11_OBK_PATH="$(mktemp)"
head -c 48 /dev/urandom > "$TSRA_PKCS11_OBK_PATH"
plugins/tsra_pkcs11/tests/pkcs11-check/run.sh --pr target/debug/tsra_pkcs11.so
```

`tests/run_validation.sh` runs the `--pr` gate too, when the emulator module is
present.
