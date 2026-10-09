#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Verify that nginx serves TLS using the tsra provider.

set -euo pipefail

curl -fsk https://localhost:8443/ | grep "tsra"
curl -fsk https://localhost:8443/health | grep "healthy"
