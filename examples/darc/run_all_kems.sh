#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Transfer a DARC TMK between two ddi_sock_server simulators once per
# recipient KEM: p384, mlkem1024 (HPKE-13) and mlkem1024-p384 (HPKE-10).
#
# Usage: examples/darc/run_all_kems.sh [KEM...]
# Environment: STATE_ROOT (default: a fresh mktemp dir), BASE_PORT (13600).
# Development transport only: everything listens on loopback.

set -euo pipefail

cd "$(dirname "$0")/../.."
if [[ $# -gt 0 ]]; then
    KEMS=("$@")
else
    KEMS=(p384 mlkem1024 mlkem1024-p384)
fi
STATE_ROOT=${STATE_ROOT:-$(mktemp -d -t darc-kems.XXXXXX)}
BASE_PORT=${BASE_PORT:-13600}
SOURCE_PORT=$BASE_PORT
TARGET_PORT=$((BASE_PORT + 1))

echo "Building simulator and DARC example..."
cargo build --quiet -p ddi_sock_server -p tsra_darc_example
BIN=target/debug

PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

start_server() {
    local port=$1
    "$BIN/ddi_sock_server" "tcp://127.0.0.1:$port" >"$STATE_ROOT/ddi-$port.log" 2>&1 &
    PIDS+=($!)
    for _ in $(seq 1 300); do
        if bash -c "</dev/tcp/127.0.0.1/$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    echo "timed out waiting for DDI server :$port" >&2
    exit 1
}

darc() {
    local port=$1
    shift
    TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:$port" \
        "$BIN/darc" --state-dir "$STATE_ROOT" "$@"
}

start_server "$SOURCE_PORT"
start_server "$TARGET_PORT"

darc "$SOURCE_PORT" provision --name source
darc "$TARGET_PORT" provision --name target

for kem in "${KEMS[@]}"; do
    echo
    echo "================ KEM: $kem ================"
    darc "$TARGET_PORT" kex --name target --kem "$kem"
    darc "$SOURCE_PORT" export --name source --target target
    darc "$TARGET_PORT" import --name target --source source
done
echo
echo "All KEM variants passed: ${KEMS[*]} (state: $STATE_ROOT)"
