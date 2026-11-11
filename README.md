# Tessera Integrated HSM SDK

## Project Overview

Tessera Integrated HSM (TSRA) SDK is a modular, cross-platform software development kit (SDK) written in Rust. This repository is home to TSRA SDK, its simulator, and its OpenSSL Provider.
Development status: This project is still under development and is not yet ready for deployment.

## Project Structure

- `api/` - Core TSRA SDK implementation
- `crates/` - Shared support libraries
- `ddi/` - Device Data Interface components for interacting with TSRA hardware
- `ddi/sim/` - TSRA functional simulator
- `plugins/ossl_prov/` - OpenSSL Provider implementation
- `xtask/` - Custom build and automation tasks

## Initial Setup

Before running any commands in this document for the first time, restore required dependencies using these steps:

For Linux systems, first install the following 5 Linux packages with the package manager of the distribution:

```
clang-format-18
gcc-arm-none-eabi
libbsd-dev
libssl-dev
pkg-config
```

For both Linux and Windows systems, run the following to install all other required dependencies:

```bash
cargo xtask precheck --setup
```

## Build Commands

Before running any commands below, ensure you have finished the initial setup steps.

### Building

Build the project using Cargo xtask:

```bash
cargo xtask build
```

Build specific packages using:

```bash
# Build specific packages you are modifying
cargo xtask build --package <package-name>
```

## Testing

Before running any commands below, ensure you have finished the initial setup steps.

### Unit Tests

Use cargo-nextest (recommended):

```bash
# Run tests in specific packages you are modifying against simulator
cargo xtask nextest --transport sock --package <package-name>
```

The same SDK build supports native hardware and socket connections. Set
`TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:1234"` to connect to a
running socket server, or leave it unset for the platform device driver.
Socket servers can front hardware or a simulator; transport selection never
changes credentials, provisioning requirements, or retry policy.

Test runners read `TSRA_TEST_ARGS`, `;`-separated `key=value` pairs (for
example `TSRA_TEST_ARGS="transport=sock;api_rev=1_1"`), and pass connection
settings to the unchanged SDK. The SDK itself never reads this variable.
Unknown keys are an error. Test keys:

- `transport`: `sock` or `ioctl` (the platform device driver); unset means
  `ioctl`.
  `--transport` sets it. With `sock`, each test binary starts an in-process
  `ddi_sock_server` before `main` unless `sock` names an external server.
- `sock`: endpoint of an external `ddi_sock_server`.
- `resource_count`: partition resources of the simulated HSM (default 1; for
  example `4` or `64`). A standalone server reads it only when built with
  `--features test-args`, as xtask does.
- `api_rev`: see below.
- `server_bin`: path to a standalone `ddi_sock_server` binary for tests
  that spawn one; xtask sets it.

### API Revision Modes

`tsra_api_tests` (Rust and C++) selects the session API at runtime from
the `api_rev` key of `TSRA_TEST_ARGS`, written as `MAJOR_MINOR`: `1_0`
for legacy/MBOR `open_session`, or `1_1` (default) and later for EX/TBOR
`open_session_ex`. Tests gate on the minimum revision they need with
`api_rev_at_least(major, minor)` and return early otherwise. `--api-rev` sets
it:

```bash
cargo xtask nextest --transport sock --api-rev 1_1 --package tsra_api_tests
```

EX coverage includes SHA, ECC, RSA, HMAC, HKDF, AES-CBC, and plain-AES key management.
Standalone unmask cases assert that EX returns an unsupported-operation error;
their successful unmask workflows remain legacy-only. AES-GCM/XTS, KBKDF,
generic-secret unmask, and legacy partition/session, cross-partition wrapping-key,
persistence, and resiliency workflows remain legacy-only.

**EX algorithm fixtures reset and finalize every discovered partition, including
hardware partitions. Use only dedicated test partitions.**

## Linting and Formatting

Before running any commands below, ensure you have finished the initial setup steps.

### Required Before Each Commit

Always run formatting checks before committing:

```bash
cargo +nightly xtask fmt --fix
```

It auto fixes formatting issues. This ensures all source code follows rustfmt standards.

Always run copyright checks before committing:

```bash
cargo xtask copyright --fix
```

It auto fixes copyright issues. This ensures all source code has correct copyright headers.

## Precheck Steps

Before running any commands below, ensure you have finished the initial setup steps.

You can run all checks (setup, build, formatting, copyright, linting, tests, code coverage etc.) against simulator with:

```bash
cargo xtask precheck --all
```

It will run all necessary checks to ensure code quality before committing. It will not auto fix linting, formatting or copyright issues.

## License

See [LICENSE](./LICENSE) for details.
