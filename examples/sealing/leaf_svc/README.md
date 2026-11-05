# Leaf sealing service over socket DDI

The `sock` feature runs the existing root and leaf sealing workflows against
host-native firmware in `ddi_sock_server`. TBOR OOB certificate/report bytes are
serialized in index order and reconstructed as server-owned SGL descriptors.
The application APIs, HTTP enrollment protocol, and recovery files are unchanged.

This is an unauthenticated, unencrypted development transport. Keep both DDI and
HTTP listeners on loopback in a trusted environment. Client and server must be
updated together; there is no backward-compatibility negotiation.

## Topology and lifetime

Use **one persistent server process per independent application partition**:

```text
root_svc -> TCP :1234 -> root StdHsm / partition 10
    |
    +-- HTTP :8080 <- leaf_svc -> TCP :1235 -> leaf StdHsm / partition 10
```

All connections to one endpoint share its partition. Do not point root and leaf
at the same endpoint: creation and recovery reset that partition. Each joined
leaf instance also needs its own DDI server. Opening another connection does not
allocate another partition.

Each session belongs to the connection that opened it. Multiple sessions per
connection are supported, but commands cannot use, finish, reopen, or close
another connection's session. Reused slots invalidate the previous owner's
lease. Reset preserves active-session ownership for reopening on the same
connection and discards pending handshakes.

Keep the DDI servers alive across application restarts. Reset disables and
re-enables the existing partition, preserving device-lifetime state and waiting
for in-flight submissions. The server closes sessions owned by disconnected
clients. Exiting a DDI server loses its emulator state; restarting it is not a
replacement for reset or a persistent-device recovery test.

## Build

Complete the repository prerequisites, including `cargo xtask precheck --setup`,
then run from the repository root:

```sh
cargo xtask build --package ddi_sock_server
cargo xtask build --package tsra_sealing_root_svc --features sock
cargo xtask build --package tsra_sealing_leaf_svc --features sock
```

Do not combine `sock` with `emu` or `mock`. `--require-emu` deliberately rejects
socket builds, even though the remote server hosts emulated firmware.

## Create and sign

Run these commands in separate terminals on Linux. Use new state directories
for creation; existing provisioning state is never overwritten.

Start the root and leaf DDI servers:

```sh
cargo run -p ddi_sock_server -- tcp://127.0.0.1:1234
```

```sh
cargo run -p ddi_sock_server -- tcp://127.0.0.1:1235
```

Wait for each server's listening message. Start the root:

```sh
TSRA_DDI_SOCK=tcp://127.0.0.1:1234 \
cargo run -p tsra_sealing_root_svc --features sock -- \
  create --name root --state-dir /tmp/sealing-sock-root \
  --listen 127.0.0.1:8080
```

Wait until `curl --fail http://127.0.0.1:8080/v1/health` reports
`"backend":"sock"`, then create the leaf:

```sh
TSRA_DDI_SOCK=tcp://127.0.0.1:1235 \
cargo run -p tsra_sealing_leaf_svc --features sock -- \
  create --name orders --root http://127.0.0.1:8080 \
  --state-dir /tmp/sealing-sock-orders \
  --listen 127.0.0.1:8081 --events
```

The leaf registers itself, obtains its policy/PTA from root, creates its SD,
uploads its sealed backup and domain-key catalog, and serves fresh-session
challenge signing. Confirm readiness and a verified signature:

```sh
curl --fail http://127.0.0.1:8081/v1/health
curl --fail -H 'Content-Type: application/json' \
  -d '{"challenge":"socket sealing smoke test"}' \
  http://127.0.0.1:8081/v1/sign
```

The health response identifies `sock` and the public domain-key identity.
Signing returns `"verified":true`.

TCP also works on native Windows. In PowerShell, set
`$env:TSRA_DDI_SOCK = "tcp://127.0.0.1:1235"` in the leaf terminal (use port 1234
in the root terminal), then run the corresponding `cargo run` command without
the shell environment prefix. Use Windows state-directory paths.

## Local and remote recovery

Stop the leaf application only, retaining root and both DDI servers. The remote
partition remains initialized, so use explicit `--reset`:

```sh
TSRA_DDI_SOCK=tcp://127.0.0.1:1235 \
cargo run -p tsra_sealing_leaf_svc --features sock -- \
  restore-local --reset --state-dir /tmp/sealing-sock-orders \
  --listen 127.0.0.1:8081
```

Local and security-domain keys must sign and verify; ephemeral/session keys
must be rejected. Repeat health/signing and compare the original identity.

Stop that leaf application and run remote recovery:

```sh
TSRA_DDI_SOCK=tcp://127.0.0.1:1235 \
cargo run -p tsra_sealing_leaf_svc --features sock -- \
  restore-remote --reset --state-dir /tmp/sealing-sock-orders \
  --listen 127.0.0.1:8081 --events
```

Root reseals its original backup to a fresh leaf receiver entirely in its HSM.
Remote recovery needs saved enrollment metadata, the machine seed, and the
partition-local MK backup, but not the local SD backup or `leaf-backup.json`.
Missing/corrupt root backups fail explicitly; there is no local-backup fallback.
Failed reseals retain recovery records and prepared receiver material for retry.

To restart root while retaining its DDI server, use:

```sh
TSRA_DDI_SOCK=tcp://127.0.0.1:1234 \
cargo run -p tsra_sealing_root_svc --features sock -- \
  restore-local --reset --state-dir /tmp/sealing-sock-root \
  --listen 127.0.0.1:8080
```

## Authorized concurrent leaf instance

Start a third DDI server on `tcp://127.0.0.1:1236`. The controller must explicitly
authorize the new instance before it can join:

```sh
curl --fail -H 'Content-Type: application/json' \
  -d '{"instance":"secondary"}' \
  http://127.0.0.1:8080/v1/leaves/orders/instances

TSRA_DDI_SOCK=tcp://127.0.0.1:1236 \
cargo run -p tsra_sealing_leaf_svc --features sock -- \
  join --name orders --instance secondary --root http://127.0.0.1:8080 \
  --state-dir /tmp/sealing-sock-orders-secondary \
  --listen 127.0.0.1:8082 --events
```

Both leaf workers must sign with the same public domain-key identity. Their
local, ephemeral, and session keys remain independent. The primary stays live.

## Automated coverage

The socket integration test launches the real binaries on ephemeral loopback
ports and cleans up its processes/state. Build all three packages above first.
Use the same target directory as `xtask build`:

```sh
CARGO_TARGET_DIR=target/xtask cargo xtask nextest \
  --package tsra_sealing_leaf_svc --features sock
```

If the build target directory is overridden, use that directory instead.
The integration test requires sibling `root_svc` and `ddi_sock_server` binaries.
It covers create/sign, explicit local reset/recovery, root restart, remote
recovery without local SD/remote backups, missing/corrupt-backup rejection,
unauthorized-join rejection, and concurrent authorized signing.

Transport limits are 8192 bytes for the main request/response and 64 OOB items,
each up to 64 KiB. Command schemas may impose tighter limits. Fast-path
AES-GCM/XTS bulk operations are supported. Persistent server-state storage is
not implemented; emulator state is lost when the DDI server exits.
