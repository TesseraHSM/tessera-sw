#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Builds and starts the simulator (ddi_sock_server) for the CI jobs that load
# the product module, which never links a simulator of its own. The server
# runs in the background for the rest of the job, on an ephemeral loopback
# port. TSRA_DDI_ARGS selects the SDK connection; TSRA_TEST_ARGS names the
# server binary for fresh-HSM tests. Both go to $GITHUB_ENV, along with
# explicit provisioning inputs generated for this private simulator.
#
# Usage: start_sock_server.sh <cargo target dir>
set -euo pipefail

TARGET_DIR="${1:?usage: start_sock_server.sh <cargo target dir>}"
: "${GITHUB_ENV:?GITHUB_ENV is not set: run this from a GitHub Actions step}"

cargo build --target-dir "$TARGET_DIR" -p ddi_sock_server
server="$TARGET_DIR/debug/ddi_sock_server"
log="$TARGET_DIR/ddi_sock_server.log"
nohup "$server" tcp://127.0.0.1:0 > "$log" 2>&1 &

endpoint=""
for _ in $(seq 600); do
    endpoint="$(sed -n 's/.*listening on \(tcp:\/\/[^;]*\);.*/\1/p' "$log")"
    [ -n "$endpoint" ] && break
    sleep 0.1
done
[ -n "$endpoint" ] || { cat "$log"; echo "ddi_sock_server did not start" >&2; exit 1; }

echo "ddi_sock_server listening on $endpoint"
echo "TSRA_DDI_ARGS=transport=sock;sock=$endpoint" >> "$GITHUB_ENV"
echo "TSRA_TEST_ARGS=transport=sock;sock=$endpoint;server_bin=$server" >> "$GITHUB_ENV"
obk="$(realpath "$TARGET_DIR")/owner-backup-key.bin"
(umask 077; head -c 48 /dev/urandom > "$obk")
echo "TSRA_PKCS11_ID=01010101010101010101010101010101" >> "$GITHUB_ENV"
echo "TSRA_PKCS11_OBK_PATH=$obk" >> "$GITHUB_ENV"
