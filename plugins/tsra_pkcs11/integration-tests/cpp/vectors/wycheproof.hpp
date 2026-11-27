// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// The shapes of the Project Wycheproof vectors the functional tests use. The
/// vectors themselves are not in the repository: the test build fetches
/// Wycheproof at a pinned commit and tools/gen_wycheproof.py writes them into
/// the build directory as wycheproof/*.inc, one array per file. Byte strings
/// are hex; hex() decodes them. `valid` is the vector's verdict: an invalid
/// one must be refused.

#include "vectors/vectors.hpp"

namespace vectors
{

/// AES key wrap with padding (RFC 5649): msg wrapped under key is ct.
struct WycheproofKwp
{
    int tc_id;
    const char *key;
    const char *msg;
    const char *ct;
    bool valid;
};

/// AES-CBC with PKCS#7 padding.
struct WycheproofCbc
{
    int tc_id;
    const char *key;
    const char *iv;
    const char *msg;
    const char *ct;
    bool valid;
};

/// AES-GCM: ct and tag of msg with aad.
struct WycheproofGcm
{
    int tc_id;
    const char *key;
    const char *iv;
    const char *aad;
    const char *msg;
    const char *ct;
    const char *tag;
    bool valid;
};

/// An ECDH peer's public point (SEC 1, as CK_ECDH1_DERIVE_PARAMS takes it) on
/// curve ("P-256", ...). `valid` is whether the token takes it: invalid points
/// and compressed ones are refused, whatever Wycheproof says of the latter.
struct WycheproofEcPoint
{
    int tc_id;
    const char *curve;
    const char *pub;
    bool valid;
};

/// A valid ECDH vector: the peer's uncompressed point `pub` and the private
/// scalar `priv` (big-endian, as an ASN.1 INTEGER's content: a leading zero
/// byte or fewer bytes than the order are possible) agree on `shared`, the
/// big-endian x-coordinate.
struct WycheproofEcdh
{
    int tc_id;
    const char *curve;
    const char *pub;
    const char *priv;
    const char *shared;
};

/// An RSA-OAEP decryption: `ct` decrypts to `msg` under `label` with the
/// PKCS#8 key `pkcs8`, `md` the OAEP and the MGF1 hash; an invalid one does
/// not decrypt.
struct WycheproofOaep
{
    int tc_id;
    const char *md;
    const char *pkcs8;
    const char *msg;
    const char *label;
    const char *ct;
    bool valid;
};

} // namespace vectors
