# Tessera Integrated HSM SDK

## Project Overview

Tessera Integrated HSM (TSRA) SDK is a modular, cross-platform software development kit (SDK) written in Rust. This repository is home to TSRA SDK, its simulator, and its OpenSSL Provider.

## Project Structure

- `api/` - Core TSRA SDK implementation
- `crates/` - Shared support libraries
- `ddi/` - Device Data Interface components for interacting with TSRA hardware
- `ddi/sim/` - TSRA functional simulator
- `plugins/ossl_prov/` - OpenSSL Provider implementation
- `xtask/` - Custom build and automation tasks

## Initial Setup

Before running any commands in this document for the first time, restore required dependencies using these steps:

For Linux systems, first install the following 4 Linux packages with the package manager of the distribution:

```
clang-format-18
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
cargo xtask nextest --features mock --package <package-name>
```

### C++ Session Modes

The C++ algorithm fixtures select the session API at compile time. Use
`session-ex-tests` for EX/TBOR sessions on the emulator:

```bash
cargo nextest run --package tsra_api_tests --features emu,session-ex-tests --test cpp
```

Omit `session-ex-tests` for legacy/MBOR sessions, or use `--features mock` for the
legacy mock backend. Mock and `session-ex-tests` cannot be combined. Run builds
for different backends or session modes sequentially because they share native
build outputs.

EX coverage includes SHA, ECC, RSA, HMAC, HKDF, AES-CBC, and plain-AES key management.
Standalone unmask cases assert that EX returns an unsupported-operation error;
their successful unmask workflows remain legacy-only. AES-GCM/XTS, KBKDF,
generic-secret unmask, and legacy partition/session, cross-partition wrapping-key,
persistence, and resiliency workflows remain in the legacy build.

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
