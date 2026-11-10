# DDI Socket Server (`ddi_sock_server`)

`ddi_sock_server` exposes one in-process `StdHsm` emulator over TCP, Unix
domain sockets, or Linux VSOCK, speaking the framed SQE/CQE protocol from
`tsra_ddi_sock_proto`. It is the reference server for `tsra_ddi_sock`
(selected with `TSRA_DDI_ARGS=transport=sock`) and is used by the socket example programs
(e.g. [`tsra_api_sock_get_api_rev`](../../../examples/sock/api_sock_get_api_rev/README.md)) and by
DDI/API integration test suites run with `TSRA_TEST_ARGS=transport=sock`.

The server allocates and enables partition **10** once at startup. All
connections, across all transports, share that one partition and its
emulator state; emulator state is lost when the process exits. This is an
unauthenticated test/development transport for trusted, isolated
environments, not a production HSM service.

## Concurrency model

`ddi_sock_server` accepts connections concurrently on every transport: each
accepted connection is handled in its own `tokio` task. A `SocketHsm` tracks
which connection owns each session (`SessionOwner`); a connection may only
submit TBOR/bulk operations against sessions it itself opened, so other
clients' concurrent sessions are unaffected. An operation against a session
owned by a different connection fails with `TRANSPORT_SESSION_NOT_OWNED`
rather than succeeding or corrupting that session.

When a connection disconnects, only *its own* sessions are cleaned up (each is
flush-closed), not the whole partition. An in-band `RequestFrame::Reset`
(sent by `tsra_ddi_sock`'s client before each test, and available to any
client) disables and re-enables the **whole partition** — not just the
issuing connection — but preserves `Active` session ownership across the
reset, marking *every* connection's sessions `NeedsRenegotiation` instead of
destroying them; only `Pending` (not-yet-authenticated) session slots are
discarded. Because `Reset` affects every connection sharing the partition,
test suites that call it (as `tsra_ddi_sock`'s client does before each test)
must serialize against a shared server with `--test-threads 1`; running them
at nextest's default parallelism races one test's reset against another
test's in-flight operations.

## Timeouts

Every transport applies the same two-tier read timeout:

- **Idle timeout (5 minutes):** bounds how long a connection may sit idle
  waiting for the *next* request frame's length prefix. A healthy client that
  simply isn't sending anything right now is not penalized; this timeout
  exists to reclaim a connection (and any sessions it owns) from a client
  that vanished without closing its socket.
- **Active timeout (30 seconds):** bounds completing an already-started
  frame — reading the rest of its body, executing it, and writing the
  response. This is much tighter, so a peer that starts a frame and then
  stalls cannot hold a connection open indefinitely.

Both expirations end the connection the same way an orderly client close
does: the server tears down that connection's own sessions and moves on;
other connections are unaffected.

## Build

```bash
cargo build --release -p ddi_sock_server
```

## Run

Serve over TCP (available on every platform this binary builds for,
including Windows):

```bash
cargo run --release -p ddi_sock_server -- tcp://127.0.0.1:1234
```

Serve over a Unix domain socket (any Unix-like platform; no `nix` crate or
Linux-only APIs required):

```bash
cargo run --release -p ddi_sock_server -- unix:///path/to/ddi_sock_server.sock
```

`unix://PATH` removes any pre-existing file at `PATH` before binding, so a
stale socket left behind by a previous run doesn't block startup.

Serve over Linux `AF_VSOCK` (Linux only):

```bash
cargo run --release -p ddi_sock_server -- vsock://*:1234
```

Without an endpoint argument, the server defaults to VSOCK port 1234 on
Linux and TCP loopback (`tcp://127.0.0.1:1234`) elsewhere.

Each mode prints a startup message once its partition is ready, e.g.:

```text
TSRA DDI server listening on unix:///path/to/ddi_sock_server.sock; partition 10
```

Keep the process running for the lifetime of its clients; its emulator state
is shared by every connection and is lost when the process exits.

## Testing against this server

Connections are handled concurrently and a disconnect only cleans up that
connection's own sessions, but `tsra_ddi_sock`'s client issues a
partition-wide `Reset` before each test, which affects every connection
sharing the server. Test suites run with `TSRA_TEST_ARGS=transport=sock`
against a shared server must therefore serialize with `--test-threads 1` to
avoid one test's reset racing another test's in-flight operations. The
`cargo xtask nextest` wrapper doesn't define or forward that option, so
invoke `cargo nextest run` directly. Point `sock=` in `TSRA_TEST_ARGS` at the
server's endpoint:

```bash
TSRA_TEST_ARGS="transport=sock;sock=tcp://127.0.0.1:1234" cargo nextest run --test-threads 1 --package tsra_api_tests
TSRA_TEST_ARGS="transport=sock;sock=/tmp/ddi_sock_server.sock" cargo nextest run --test-threads 1 --package tsra_ddi_mbor_types --test tsra_ddi_tests
```

Note the bare path (no `unix://` prefix) for the Unix client: only the
server CLI accepts `unix://`; `DdiSockDev::connect` recognizes `tcp://` and
VSOCK prefixes but passes anything else straight to `UnixStream::connect`,
so a `unix://` prefix would be treated as a literal (and nonexistent)
filesystem path.

See the [`api_sock_get_api_rev` README](../../../examples/sock/api_sock_get_api_rev/README.md) for
a fuller walkthrough (two-terminal setup, alternative ports, VSOCK client
usage, and troubleshooting) that applies equally to `unix://` endpoints.

## Limits and safety

- Not a production HSM service: traffic is unauthenticated and unencrypted.
  Keep listeners on loopback/local-only paths; do not expose them to
  untrusted clients or networks.
- The socket transport carries ordinary MBOR/TBOR commands with an
  8192-byte main request/response capacity. TBOR supports up to 64 OOB
  buffers of up to 64 KiB each, reconstructed as server-owned SGL
  descriptors. Fast-path AES-GCM/XTS requests carry a 32-dword bulk SQE with
  up to 16 KiB of data inline; the server copies it into its own buffers.
  Bulk requests require an owned `Active` session — a pending TBOR handshake
  cannot submit bulk I/O, and a session marked `NeedsRenegotiation` after a
  reset blocks bulk I/O (reported as `SessionNeedsRenegotiation`) until it
  is reopened or authenticated again.
- Client and server must be updated together; the protocol does not provide
  backward compatibility.
- Calls on a given connection are synchronous: each connection allows one
  exchange at a time. Use multiple connections (or multiple client handles)
  to make independent concurrent requests.

## Focused tests

```bash
cargo xtask nextest --package ddi_sock_server
```

Covers TCP, Unix, and VSOCK framing, concurrent connections sharing a
partition, per-connection session ownership enforcement, reset semantics,
malformed submission rejection, and timeout-triggered disconnects.
