// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// Helpers for the tests of keys derived on the token: the ECDH and HKDF
/// parameter blocks, and the HKDF input the device reads, which the host
/// oracle needs to recompute a derived key.

#include <utility>
#include <vector>

#include "utils/host_crypto.hpp"
#include "utils/module.hpp"

/// The word the little-endian device (Uno and its simulator) pads ECC values
/// to (fw ECC_COORD_PAD of the Uno platforms).
constexpr size_t kDeviceWord = 4;

/// The HKDF input of an API 1.x device: the ECDH secret in the device's byte
/// order, least significant byte first and zero-padded to whole words (68
/// bytes for P-521), where SP 800-56A and RFC 5869 take the big-endian
/// x-coordinate `z` (a deviation in the README). The tests named
/// *_in_device_byte_order pin it. A firmware that hands HKDF the standard
/// secret turns them red; that is the signal to give the oracle `z` itself and
/// to drop the README deviation.
inline host::Bytes device_ikm(const host::Bytes &z)
{
    host::Bytes out(z.rbegin(), z.rend());
    out.resize(((out.size() + kDeviceWord - 1) / kDeviceWord) * kDeviceWord, 0);
    return out;
}

/// CK_ECDH1_DERIVE_PARAMS with CKD_NULL around a copy of `point` (raw or DER),
/// so a temporary argument is safe.
struct EcdhMechanism
{
    explicit EcdhMechanism(host::Bytes point)
        : point_bytes(std::move(point)), params{ CKD_NULL,
                                                 0,
                                                 nullptr,
                                                 static_cast<CK_ULONG>(point_bytes.size()),
                                                 point_bytes.data() },
          mech{ CKM_ECDH1_DERIVE, &params, sizeof(params) }
    {
    }
    EcdhMechanism(const EcdhMechanism &) = delete; /* params and mech point into this object */
    EcdhMechanism &operator=(const EcdhMechanism &) = delete;

    host::Bytes point_bytes; /* declared before params, which points into it */
    CK_ECDH1_DERIVE_PARAMS params;
    CK_MECHANISM mech;
};

/// CK_HKDF_PARAMS for extract and expand with `prf`, a salt of bytes (none
/// when `salt_null`) and `info`. It keeps copies of both, so temporary
/// arguments are safe.
struct HkdfMechanism
{
    HkdfMechanism(CK_MECHANISM_TYPE prf, host::Bytes salt, host::Bytes info, bool salt_null = false)
        : salt_bytes(std::move(salt)), info_bytes(std::move(info)),
          params{ CK_TRUE,
                  CK_TRUE,
                  prf,
                  salt_null ? CKF_HKDF_SALT_NULL : CKF_HKDF_SALT_DATA,
                  salt_null ? nullptr : salt_bytes.data(),
                  salt_null ? 0 : static_cast<CK_ULONG>(salt_bytes.size()),
                  CK_INVALID_HANDLE,
                  info_bytes.data(),
                  static_cast<CK_ULONG>(info_bytes.size()) },
          mech{ CKM_HKDF_DERIVE, &params, sizeof(params) }
    {
    }
    HkdfMechanism(const HkdfMechanism &) = delete; /* params and mech point into this object */
    HkdfMechanism &operator=(const HkdfMechanism &) = delete;

    /* Declared before params, which points into them. */
    host::Bytes salt_bytes;
    host::Bytes info_bytes;
    CK_HKDF_PARAMS params;
    CK_MECHANISM mech;
};
