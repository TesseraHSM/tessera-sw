# RUN: @bash -ea @file @keydir
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# For each supported curve: import a software EC key into the HSM through
# `openssl genpkey -engine tsra -pkeyopt tsra.input_key`, as PKCS#8 and as
# SEC1 DER, then sign with the written masked blob in a fresh openssl process
# and verify under the software key's public key. A key on another curve than
# ec_paramgen_curve is refused and writes no blob.
#
# genpkey cannot write its usual private-key output for an HSM-backed key (see
# create_key.sh), so its exit code is ignored; the masked blob is checked.
source "$(dirname "${BASH_SOURCE[0]}")/../env.sh"

for entry in "p256 P-256 prime256v1 sha256" "p384 P-384 secp384r1 sha384" "p521 P-521 secp521r1 sha512"; do
    read -r tag curve name md <<< "$entry"
    sw="$KEYDIR/ec_import_sw_$tag.pem"
    pub="$KEYDIR/ec_import_pub_$tag.pem"
    msg="$KEYDIR/ec_import_msg_$tag.txt"
    sig="$KEYDIR/ec_import_sig_$tag.bin"
    "$OPENSSL_BIN" ecparam -name "$name" -genkey -noout -out "$sw"
    "$OPENSSL_BIN" ec -in "$sw" -pubout -out "$pub"
    "$OPENSSL_BIN" pkcs8 -topk8 -nocrypt -in "$sw" -outform DER -out "$KEYDIR/ec_import_pkcs8_$tag.der"
    "$OPENSSL_BIN" ec -in "$sw" -outform DER -out "$KEYDIR/ec_import_sec1_$tag.der"
    printf 'engine ecdsa signing with a CLI-imported key (%s)' "$tag" > "$msg"

    for form in pkcs8 sec1; do
        blob="$KEYDIR/ec_import_masked_${tag}_$form.bin"
        rm -f "$blob" "$sig"
        "$OPENSSL_BIN" genpkey -engine tsra -algorithm EC \
            -pkeyopt "ec_paramgen_curve:$curve" \
            -pkeyopt "tsra.input_key:$KEYDIR/ec_import_${form}_$tag.der" \
            -pkeyopt "tsra.masked_key:$blob" > /dev/null || true
        test -s "$blob"

        uri="tsra://$blob;type=ec"
        "$OPENSSL_BIN" dgst "-$md" -engine tsra -keyform engine -sign "$uri" -out "$sig" "$msg"
        "$OPENSSL_BIN" dgst "-$md" -verify "$pub" -signature "$sig" "$msg"
        echo "ec import ok: $tag $form"
    done
done

# A P-384 key imported as P-256 is refused and writes no blob.
blob="$KEYDIR/ec_import_masked_mismatch.bin"
rm -f "$blob"
"$OPENSSL_BIN" genpkey -engine tsra -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -pkeyopt "tsra.input_key:$KEYDIR/ec_import_pkcs8_p384.der" \
    -pkeyopt "tsra.masked_key:$blob" > /dev/null 2>&1 || true
test ! -e "$blob"
echo "ec import curve mismatch refused"

# CHECK: ec import ok: p256 pkcs8
# CHECK: ec import ok: p256 sec1
# CHECK: ec import ok: p384 pkcs8
# CHECK: ec import ok: p384 sec1
# CHECK: ec import ok: p521 pkcs8
# CHECK: ec import ok: p521 sec1
# CHECK: ec import curve mismatch refused
