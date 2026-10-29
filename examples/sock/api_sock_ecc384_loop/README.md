# P-384 Loop over TCP

This example follows [ddi_sock_ecc384_loop](../ddi_sock_ecc384_loop/src/main.rs),
using the public Rust API to generate, sign, and verify session-scoped P-384 keys.
Unlike that Unix-gated example, it runs natively on both Windows and Linux over
TCP and defaults to `tcp://127.0.0.1:1234`. TCP does not require VSOCK or a virtual
machine. Windows users do not need WSL or a Linux installation.

The original Unix example is unchanged. This is a client of the existing TCP
DDI server, not the proposed API-level RPC service.

## Safety

Use only a disposable test partition. On the first run, this example rotates the
default Crypto Officer (CO) PSK to the fixed, publicly known test value used by
the reference example (`0xA5` repeated for `PSK_LEN` bytes). Later runs reconnect
using that value. Do not run it against a production partition or one containing
valuable data. Coordinate with other clients because all server connections
share the same partition.

The TCP test server is unauthenticated and unencrypted. Keep it on loopback.
The program prints only a public signature prefix, never key or PSK material.

## Run on Windows or Linux

Run the following commands from the repository root, using PowerShell on Windows
or a shell on Linux. Complete the normal platform-specific SDK build
prerequisites first: Rust/MSVC and the native libraries on Windows, or the Linux
packages listed in the repository setup instructions, including OpenSSL
development libraries and `pkg-config`. Then restore the development tools:

```sh
cargo xtask precheck --setup
```

In the first terminal, start the TCP emulator server:

```sh
cargo run -p ddi_sock_server -- tcp://127.0.0.1:1234
```

Specify the TCP endpoint explicitly on both platforms. Without an endpoint, the
server defaults to TCP on Windows but VSOCK on Linux; this example accepts only
TCP endpoints and does not switch transports automatically.

Wait for its listening message and leave it running. In a second terminal:

```sh
cargo run -p tsra_api_sock_ecc384_loop --features sock -- tcp://127.0.0.1:1234 5
```

The arguments are `[ENDPOINT] [COUNT]`. The defaults are TCP loopback port 1234
and one iteration, so this also works with the server running:

```sh
cargo run -p tsra_api_sock_ecc384_loop --features sock
```

The endpoint must be a `tcp://HOST:PORT` endpoint; the count must be positive.
To use another port, specify that port in both server and client commands.

## What Runs

Each invocation opens one authenticated TBOR V2 session. Each iteration:

1. Generates a new session-scoped ECC P-384 private/public key pair.
2. Hashes an iteration-specific message using SHA-384.
3. Signs the digest using the private key.
4. Verifies the signature with the matching public key.
5. Prints the iteration result and the first 32 signature bytes as hexadecimal.

Any session, key generation, signing, or verification failure exits with an error.
Running the client again against the same server exercises reconnection with the
already-rotated test PSK. Restarting the emulator server loses its state, so the
next run rotates the default PSK again.

The `sock` feature selects the socket backend through `tsra_api/sock`. It is
opt-in to avoid conflicts with workspace `mock` and `emu` builds. The same TCP
endpoint and public API calls are used on Windows and Linux.

## Focused Checks

```sh
cargo xtask nextest --package tsra_api_sock_ecc384_loop --features sock
cargo clippy --package tsra_api_sock_ecc384_loop --all-targets --features sock -- -D warnings
```

The unit tests cover argument validation and public-signature formatting. The
two-terminal run exercises actual session establishment, key generation, signing,
and verification against the emulator. See the
[TCP socket guide](../api_sock_get_api_rev/README.md) for transport details.