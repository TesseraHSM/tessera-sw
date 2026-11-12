#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Interop smoke: OpenSSL's pkcs11-provider (the distribution package) loads the
# module and serves openssl dgst from the token. The digests must equal
# coreutils', and the provider's debug log must show the token's C_Digest*
# calls, so a silent fallback to OpenSSL's own digests cannot pass.
#
#   pkcs11_provider.sh <module.so> [provider.so]
#
# provider.so defaults to pkcs11.so in OpenSSL's module directory.
set -euo pipefail

MOD="${1:?usage: $0 <module.so> [provider.so]}"
PROV="${2:-$(openssl version -m | sed -E 's/^MODULESDIR: "(.*)"$/\1/')/pkcs11.so}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
[ -f "$PROV" ] || { echo "pkcs11_provider: no provider at $PROV" >&2; exit 1; }

# Early load: the digests are registered from the token's mechanism list when
# the provider starts. The property default, not -propquery: the openssl
# command turns -propquery into a DRBG reconfiguration that fails once the
# module has started its own libcrypto use.
cat > "$WORK/openssl.cnf" <<CNF
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
alg_section = evp_properties
[evp_properties]
default_properties = ?provider=pkcs11
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = $PROV
pkcs11-module-path = $MOD
pkcs11-module-load-behavior = early
activate = 1
CNF
export OPENSSL_CONF="$WORK/openssl.cnf"
openssl version
openssl list -providers

printf abc > "$WORK/small"
head -c 1000000 /dev/zero > "$WORK/large" # several C_DigestUpdate calls
for pair in sha1:sha1sum sha256:sha256sum sha384:sha384sum sha512:sha512sum; do
    md="${pair%%:*}"
    sum="${pair##*:}"
    for f in small large; do
        rm -f "$WORK/debug"
        got="$(PKCS11_PROVIDER_DEBUG="file:$WORK/debug,level:2" openssl dgst "-$md" -r "$WORK/$f" |
            cut -d' ' -f1)"
        exp="$("$sum" < "$WORK/$f" | cut -d' ' -f1)"
        echo "$md $f: provider $got coreutils $exp"
        [ "$got" = "$exp" ] || { echo "pkcs11_provider: $md digest mismatch" >&2; exit 1; }
        grep -q C_DigestInit "$WORK/debug" ||
            { echo "pkcs11_provider: $md was not computed by the token" >&2; exit 1; }
    done
done
echo "pkcs11_provider: OK"
