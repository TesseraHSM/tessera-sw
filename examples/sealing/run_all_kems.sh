#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Run the root_svc security-domain flows once per transfer KEM against
# ddi_sock_server simulators: p384 (HPKE P-384), mlkem1024 (HPKE-13) and
# mlkem1024-p384 (HPKE-10 hybrid).
#
# For each KEM: remote-restorable create (serving peer cloning), peer clone,
# local restore, remote restore and a temporary-receiver create.
#
# Usage: examples/sealing/run_all_kems.sh [KEM...]
# Environment: STATE_ROOT (default: a fresh mktemp dir), BASE_PORT (13400).
# Development transport only: everything listens on loopback.

set -euo pipefail

cd "$(dirname "$0")/../.."
if [[ $# -gt 0 ]]; then
    KEMS=("$@")
else
    KEMS=(p384 mlkem1024 mlkem1024-p384)
fi
STATE_ROOT=${STATE_ROOT:-$(mktemp -d -t sealing-kems.XXXXXX)}
BASE_PORT=${BASE_PORT:-13400}

echo "Building simulator and root_svc..."
cargo build --quiet -p ddi_sock_server -p tsra_sealing_root_svc
BIN=target/debug

PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for() {
    local what=$1 check=$2
    for _ in $(seq 1 300); do
        if eval "$check" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "timed out waiting for $what" >&2
    exit 1
}

start_server() {
    local port=$1 log=$2
    "$BIN/ddi_sock_server" "tcp://127.0.0.1:$port" >"$log" 2>&1 &
    PIDS+=($!)
    wait_for "DDI server :$port" "bash -c '</dev/tcp/127.0.0.1/$port'"
}

root_svc() {
    local port=$1
    shift
    TSRA_DDI_ARGS="transport=sock;sock=tcp://127.0.0.1:$port" "$BIN/root_svc" "$@"
}

run_kem() {
    local kem=$1 index=$2
    local ddi=$((BASE_PORT + index * 10)) http=$((BASE_PORT + index * 10 + 5))
    local dir="$STATE_ROOT/$kem"
    mkdir -p "$dir"
    echo
    echo "================ KEM: $kem ================"

    start_server "$ddi" "$dir/ddi-root.log"
    start_server "$((ddi + 1))" "$dir/ddi-clone.log"
    start_server "$((ddi + 2))" "$dir/ddi-temp.log"

    echo "--- [$kem] create --remote-restorable (serving peer cloning)"
    root_svc "$ddi" create --name "root-$kem" --state-dir "$dir/root" \
        --kem "$kem" --remote-restorable --listen "127.0.0.1:$http" \
        >"$dir/create.log" 2>&1 &
    local root=$!
    PIDS+=("$root")
    wait_for "root health" \
        "curl --silent --fail http://127.0.0.1:$http/v1/health || ! kill -0 $root"
    kill -0 "$root" 2>/dev/null || {
        cat "$dir/create.log"
        echo "root create failed" >&2
        exit 1
    }
    cat "$dir/create.log"

    echo "--- [$kem] clone onto a fresh partition"
    root_svc "$((ddi + 1))" clone --primary "http://127.0.0.1:$http" \
        --name "peer-$kem" --state-dir "$dir/peer" --kem "$kem"

    kill "$root"
    wait "$root" 2>/dev/null || true

    echo "--- [$kem] restore-local"
    root_svc "$ddi" restore-local --reset --state-dir "$dir/root"

    echo "--- [$kem] restore-remote"
    root_svc "$ddi" restore-remote --reset --state-dir "$dir/root"

    echo "--- [$kem] create with a temporary software receiver"
    root_svc "$((ddi + 2))" create --name "temp-$kem" --state-dir "$dir/temp" \
        --kem "$kem"

    echo "================ KEM $kem: OK ================"
}

index=0
for kem in "${KEMS[@]}"; do
    run_kem "$kem" "$index"
    index=$((index + 1))
done
echo
echo "All KEM variants passed: ${KEMS[*]} (state: $STATE_ROOT)"
