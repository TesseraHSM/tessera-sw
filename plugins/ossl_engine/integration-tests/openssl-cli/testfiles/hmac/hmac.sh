# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# HMAC with HSM keys on the command line. An HMAC key of each kind is derived
# with ECDH and HKDF through the engine, then MACs with it through
# `openssl dgst -sign tsra://<blob>;type=hmac` in fresh openssl processes. The
# MAC is the digest's length and repeats for the same key and message; another
# digest than the key's, and a message over 1024 bytes, are refused.
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

blob="$KEYDIR/hmac_agree_ec.bin"
peer_priv="$KEYDIR/hmac_peer.pem"
peer_pub="$KEYDIR/hmac_peer_pub.pem"
secret="$KEYDIR/hmac_shared_secret.bin"
msg="$KEYDIR/hmac_msg.txt"
long="$KEYDIR/hmac_long.bin"
rm -f "$blob" "$peer_priv" "$peer_pub" "$secret"

"$OPENSSL_BIN" genpkey -engine tsra -algorithm EC \
    -pkeyopt "ec_paramgen_curve:P-384" \
    -pkeyopt "tsra.masked_key:$blob" \
    -pkeyopt "tsra.key_usage:keyAgreement" \
    -out /dev/null || true
test -s "$blob"
"$OPENSSL_BIN" genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:P-384" -out "$peer_priv"
"$OPENSSL_BIN" pkey -in "$peer_priv" -pubout -out "$peer_pub"
"$OPENSSL_BIN" pkeyutl -derive -engine tsra -keyform engine \
    -inkey "tsra://$blob;type=ec" -peerkey "$peer_pub" -pkeyopt "output_file:$secret"
test -s "$secret"

printf 'engine hmac over the cli' > "$msg"
head -c 1025 /dev/zero > "$long"

for cfg in "SHA256 256 32 sha384" "SHA384 384 48 sha256" "SHA512 512 64 sha256"; do
    read -r md bits len other <<< "$cfg"
    key="$KEYDIR/hmac_key_$bits.bin"
    rm -f "$key"
    "$OPENSSL_BIN" pkeyutl -kdf HKDF -kdflen 1 -engine tsra -engine_impl \
        -pkeyopt "md:$md" \
        -pkeyopt "tsra.ikm_file:$secret" \
        -pkeyopt "derived_key_type:hmac" \
        -pkeyopt "derived_key_bits:$bits" \
        -pkeyopt "output_file:$key"
    test -s "$key"

    uri="tsra://$key;type=hmac"
    dgst=$(echo "$md" | tr 'A-Z' 'a-z')
    "$OPENSSL_BIN" dgst "-$dgst" -engine tsra -keyform engine -sign "$uri" \
        -out "$KEYDIR/hmac_mac1_$bits.bin" "$msg"
    "$OPENSSL_BIN" dgst "-$dgst" -engine tsra -keyform engine -sign "$uri" \
        -out "$KEYDIR/hmac_mac2_$bits.bin" "$msg"
    test "$(stat -c %s "$KEYDIR/hmac_mac1_$bits.bin")" -eq "$len"
    cmp -s "$KEYDIR/hmac_mac1_$bits.bin" "$KEYDIR/hmac_mac2_$bits.bin"

    if "$OPENSSL_BIN" dgst "-$other" -engine tsra -keyform engine -sign "$uri" \
        -out /dev/null "$msg" 2>/dev/null; then
        echo "HMAC-$bits with $other unexpectedly succeeded"
        exit 1
    fi
    if "$OPENSSL_BIN" dgst "-$dgst" -engine tsra -keyform engine -sign "$uri" \
        -out /dev/null "$long" 2>/dev/null; then
        echo "HMAC-$bits over 1025 bytes unexpectedly succeeded"
        exit 1
    fi
    echo "hmac ok: $md"
done

# CHECK: hmac ok: SHA256
# CHECK: hmac ok: SHA384
# CHECK: hmac ok: SHA512
