# Multithreaded API Socket Example

Open the same HSM partition independently from multiple application threads,
using the public Rust API over TCP. Both the application and emulator server run
natively on Windows and Linux. TCP does not require a virtual machine or VSOCK
driver. Windows users do not need WSL or a Linux installation.

The example queries the supported API revision range. It does not initialize or
reset the partition, rotate credentials, or create cryptographic keys.

## Rationale

The previous socket examples use Unix-domain sockets or Linux VSOCK, neither of
which is a portable transport for native Windows applications. TCP is supported
by Rust's standard library and the server's existing Tokio runtime on Windows
and Linux, without introducing another transport dependency.

TCP carries the length-delimited SQE/CQE protocol and opaque MBOR/TBOR
payloads, with ordered TBOR OOB bytes, fast-path AES-GCM/XTS bulk requests and
sideband partition reset. It does not
introduce a new API protocol or change public API call
signatures. The application uses `tsra_api`; transport selection stays in the
DDI layer and is chosen at runtime by `TSRA_DDI_ARGS=transport=sock`.
The same SDK build supports native hardware and socket connections.

The server runs one shared host-native `StdHsm` emulator and allocates/enables
partition **10** once at startup. Accepting a connection does not create another
partition or emulator instance. All clients of this server access that partition.

```text
Application (Windows or Linux)              Server (Windows or Linux)

Thread 1 -> API partition handle -> TCP 1 --+
Thread 2 -> API partition handle -> TCP 2 --+--> shared StdHsm -> partition 10
Thread 3 -> API partition handle -> TCP 3 --+
```

Each worker calls `HsmPartitionManager::open_partition` independently, creating a
separate socket connection to the same endpoint. Cloning an existing partition
or session handle instead shares its connection. A mutex serializes each
connection's request/response exchanges, but it does not serialize different
connections. The server handles connections in separate tasks; emulator resource
limits and firmware locks can still constrain execution parallelism.

TCP loopback is preferred over Windows named pipes for this example because it
also works unchanged on Linux and reuses the existing stream framing. Existing
Unix-domain and Linux VSOCK client support is retained.

## Windows and Linux Setup

Run the following commands from the repository root, using PowerShell on Windows
or a shell on Linux. Complete the normal platform-specific SDK build
prerequisites: Rust/MSVC and native libraries on Windows, or the Linux packages
listed in the repository setup instructions, including OpenSSL development
libraries and `pkg-config`. The repository specifies the pinned Rust toolchain.

Restore the required development tools first:

```sh
cargo xtask precheck --setup
```

### 1. Start the Server

In the first terminal:

```sh
cargo run -p ddi_sock_server -- tcp://127.0.0.1:1234
```

Pass the TCP endpoint explicitly on both platforms. Without an endpoint, the
server defaults to TCP on Windows but VSOCK on Linux; the application's default
endpoint is TCP on both platforms.

Wait for this startup message:

```text
TSRA DDI server listening on tcp://127.0.0.1:1234; partition 10
```

Keep this process running. Its emulator state is shared by all connections and
is lost when the process exits. Stop it with Ctrl+C after finishing.

### 2. Run the API Workers

In a second terminal:

```sh
cargo run -p tsra_api_sock_get_api_rev -- tcp://127.0.0.1:1234 4
```

The arguments are `[ENDPOINT] [THREADS]`. Both are optional; the defaults are
`tcp://127.0.0.1:1234` and `4`. The thread count must be a positive integer.
For example, to use the defaults:

```sh
cargo run -p tsra_api_sock_get_api_rev
```

Each worker prints its endpoint and supported revision range. Worker output order
is nondeterministic. The final message confirms that all workers finished:

```text
All 4 workers opened the same partition at tcp://127.0.0.1:1234
```

The program configures `TSRA_DDI_ARGS` once before discovery or worker creation.
Discovery negotiates a supported revision; each worker then opens its own handle
with that revision. Opening performs device queries, including `GetApiRev` and
`GetDeviceInfo`. `api_rev_range()` reads the metadata cached on that handle.

### 3. Use a Different Port

If port 1234 is already occupied, use the same alternative in both terminals:

```sh
cargo run -p ddi_sock_server -- tcp://127.0.0.1:2345
cargo run -p tsra_api_sock_get_api_rev -- tcp://127.0.0.1:2345 8
```

These are separate, concurrently running terminal commands, not a sequential
script. Alternatively, build the packages and run the executables directly from
`target/debug` with the same arguments.

## DDI Integration Tests

Use a dedicated server: these suites reset its shared partition. Set
`RUST_LOG=info` on both the server and test processes for informational logging.
Run each suite serially:

```sh
RUST_LOG=info TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:1234" cargo nextest run \
  -p tsra_ddi_mbor_types --test tsra_ddi_tests --test-threads 1
RUST_LOG=info TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:1234" cargo nextest run \
  -p tsra_ddi_tbor_types --test tsra_ddi_tbor_tests --test-threads 1
```

The API tests, including the C++ suite, run the same way; add
`api_rev=1_1` to `TSRA_TEST_ARGS` for TBOR (`open_session_ex`) sessions:

```sh
TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:1234" cargo nextest run \
  -p tsra_api_tests --test-threads 1
```

`TSRA_DDI_ARGS=transport=sock` also selects socket-specific session expectations
and skips hardware-only MBOR bulk crypto tests. Tests of the removed
`key_tag`/named-key lookup feature are disabled.
Connections may own multiple sessions; cloned device handles share their
connection and sessions. A different connection cannot use those sessions.

## Other Transports

The explicit TCP commands above also work on Linux. For backward compatibility,
running `ddi_sock_server` without an endpoint on Linux still starts its VSOCK
listener on port 1234; on Windows it defaults to TCP loopback.

A Linux client can use the existing VSOCK server with:

```sh
cargo run -p tsra_api_sock_get_api_rev -- vsock://4:1234 4
```

Replace `4` in the endpoint with the server guest's CID. Unix-domain paths are
also accepted by the client when used with a compatible Unix-domain server.
Neither transport is required for the TCP setup on Windows or Linux.

## Limits and Safety

- This is a development/test server, not a production HSM service. TCP traffic is
  unauthenticated and unencrypted. Keep the listener on loopback; do not expose
  it to untrusted clients or networks.
- All clients share partition state. For workflows beyond this metadata example,
  coordinate provisioning and reset operations, and open a separate authenticated
  session per worker as appropriate.
- Transport selection is runtime configuration, not a Cargo feature.
- The socket transport carries ordinary MBOR/TBOR commands, with an 8192-byte
  main request/response capacity. TBOR supports up to 64 OOB buffers of up to
  64 KiB each, reconstructed as server-owned SGL descriptors. Reset disables
  and re-enables the existing partition, waiting for active submissions.
  Fast-path AES-GCM/XTS requests carry a 32-dword bulk SQE with up to 16 KiB of
  data inline; the server copies it into its own buffers. Bulk requests require
  an owned Active session: a pending TBOR handshake cannot submit bulk IO.
  Reset preserves ownership for cleanup but blocks bulk IO until the session
  is successfully reopened or authenticated again.
- Client and server must be updated together; the protocol does not provide
  backward compatibility. Disconnected clients' sessions are closed by the
  server rather than left occupying firmware session slots.
- Calls are synchronous. Each connection allows one exchange at a time; this
  example uses multiple connections rather than multiplexing one connection.

For a complete provisioning, signing, and recovery workflow, see the
[socket sealing example](../../sealing/leaf_svc/README.md).

## Troubleshooting

- **Connection refused:** start the server first and check that both endpoints
  use the same address and port.
- **Address already in use:** choose an unused port for both server and client.
- **Failed to query the API revision:** the endpoint must speak the TSRA socket
  protocol and support the API's startup device queries, not just accept TCP.
- **VSOCK requires Linux:** select a `tcp://` endpoint for native Windows.

## Focused Tests

Run these commands from the repository root on Windows or Linux:

```sh
cargo xtask nextest --package tsra_ddi_sock
cargo xtask nextest --package ddi_sock_server
cargo build --package tsra_api_sock_get_api_rev
```

These cover TCP framing, concurrent server connections, and malformed submission
rejection. The
two-terminal run above exercises the complete public-API-to-emulator path.