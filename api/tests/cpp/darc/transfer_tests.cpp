// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// api-level DARC key-transfer flow over the native C ABI against the
// emulator.
//
// Drives the source->target hand-off on a single partition (acting as both
// endpoints) through the `tsra_darc_*` functions: mint a Transfer Masking
// Key (TMK), mint source and target key-exchange keys, seal the TMK to the
// target (`export`), and re-open it (`import`) — proving the TMK survives the
// export->import round trip. The wrap/unwrap surface is exercised as a full
// happy path — mint an ECC signing key, wrap it under the TMK, unwrap it
// back, then sign with the recovered key and verify against the original
// public key.
//
// The whole file needs the two-phase TBOR HPKE handshake and a fully
// provisioned, SD-initialized partition, which the mock backend does not
// implement, so it is excluded from the mock lane and runs on the emu and
// hardware backends.
#if !defined(TSRA_FEATURE_MOCK)

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <gtest/gtest.h>
#include <scope_guard.hpp>
#include <tsra_api.h>
#include <vector>

#include "algo/ecc/helpers.hpp"
#include "handle/part_list_handle.hpp"
#include "utils/sd_provision.hpp"
#include "utils/utils.hpp"

namespace
{
// Pinned DARC wire lengths. Mirror the `tsra_ddi_tbor_types` constants
// (`MASKED_KEX_KEY_LEN`, `KEX_PUB_KEY_LEN`, `MASKED_TMK_LEN`,
// `SEALED_TMK_LEN`, `DARC_WRAP_WRAPPED_KEY_MAX_LEN`), which are not exposed
// in the C header.
constexpr uint32_t kMaskedKexKeyLen = 276;
constexpr uint32_t kKexPubKeyLen = 96;
constexpr uint32_t kMaskedTmkLen = 260;
constexpr uint32_t kSealedTmkLen = 145;
constexpr uint32_t kWrapWrappedKeyMaxLen = 512;

// Raw P-384 public-key width and per-coordinate width.
constexpr size_t kRawPubLen = 96;
constexpr size_t kCoordLen = 48;

// `KeyScope::Local` discriminant (mirror of `KEY_SCOPE_LOCAL`).
constexpr uint8_t kKeyScopeLocal = 0b011;

/// A minted DARC key-exchange key: its masked blob (the HPKE identity the
/// device unmasks on export/import) and its public key as raw big-endian
/// `X ‖ Y` — the certificate-leaf format the cert chains carry.
struct KexKey
{
    std::vector<uint8_t> masked;  // kMaskedKexKeyLen
    std::vector<uint8_t> pub_raw; // kRawPubLen (big-endian X ‖ Y)
};

/// Mint an `tsra_darc_kex_key_gen` key and convert its device
/// little-endian `x ‖ y` public key into the raw big-endian `X ‖ Y` a
/// certificate leaf carries (reversing each P-384 coordinate).
KexKey mint_kex(tsra_handle session)
{
    KexKey key;
    key.masked.resize(kMaskedKexKeyLen);
    key.pub_raw.resize(kKexPubKeyLen);
    tsra_buffer masked_buf{ key.masked.data(), static_cast<uint32_t>(key.masked.size()) };
    tsra_buffer pub_buf{ key.pub_raw.data(), static_cast<uint32_t>(key.pub_raw.size()) };
    auto err = tsra_darc_kex_key_gen(session, kKeyScopeLocal, &masked_buf, &pub_buf);
    if (err != TSRA_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "tsra_darc_kex_key_gen failed: " << err;
        return KexKey{};
    }
    key.masked.resize(masked_buf.len);
    key.pub_raw.resize(pub_buf.len);
    // Device wire order is little-endian per coordinate; a leaf carries raw
    // big-endian, so reverse each 48-byte coordinate.
    std::reverse(key.pub_raw.begin(), key.pub_raw.begin() + kCoordLen);
    std::reverse(key.pub_raw.begin() + kCoordLen, key.pub_raw.begin() + 2 * kCoordLen);
    return key;
}

/// Mint a masked TMK via `tsra_darc_tmk_gen`. Records a gtest failure and
/// returns an empty vector on error.
std::vector<uint8_t> mint_tmk(tsra_handle session)
{
    std::vector<uint8_t> tmk(kMaskedTmkLen);
    tsra_buffer buf{ tmk.data(), static_cast<uint32_t>(tmk.size()) };
    auto err = tsra_darc_tmk_gen(session, &buf);
    if (err != TSRA_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "tsra_darc_tmk_gen failed: " << err;
        return {};
    }
    tmk.resize(buf.len);
    return tmk;
}
} // namespace

/// Test fixture for the DARC key-transfer commands.
class tsra_darc_transfer_test : public ::testing::Test
{
  protected:
    PartitionListHandle part_list_ = PartitionListHandle{};

    // Open and factory-reset a partition into a clean state. Records a
    // gtest failure and returns 0 on error; the returned handle must be
    // closed by the caller.
    static tsra_handle open_reset_partition(std::vector<tsra_char> &path)
    {
        tsra_str path_str;
        path_str.str = path.data();
        path_str.len = static_cast<uint32_t>(path.size());

        tsra_handle part_handle = 0;
        auto err = tsra_part_open(&path_str, &part_handle, session_ex_test_api_rev());
        if (err != TSRA_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "tsra_part_open failed: " << err;
            return 0;
        }

        err = tsra_part_reset(part_handle);
        if (err != TSRA_STATUS_SUCCESS)
        {
            ADD_FAILURE() << "tsra_part_reset failed: " << err;
            tsra_part_close(part_handle);
            return 0;
        }

        return part_handle;
    }
};

// Full DARC TMK transfer: create a TMK on the source, mint the source and
// target key-exchange identities, seal the TMK to the target
// (DATA-anchored target chain), then re-open it on the target
// (POTA-anchored sender chain) — the export->import hand-off that ships a
// TMK from one endpoint to another.
TEST_F(tsra_darc_transfer_test, tmk_export_import_roundtrip)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        DarcReadyContext ready = provision_darc_session(part_handle);
        if (ready.session == 0)
        {
            return; // provisioning recorded its own failure
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&ready] { tsra_sess_close(ready.session); });

        // (1) Originate a TMK (masked under the SDMK).
        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        ASSERT_EQ(masked_tmk.size(), kMaskedTmkLen);

        // (2) Mint the source and target key-exchange identities.
        KexKey source_kex = mint_kex(ready.session);
        KexKey target_kex = mint_kex(ready.session);
        ASSERT_EQ(source_kex.masked.size(), kMaskedKexKeyLen);
        ASSERT_EQ(target_kex.masked.size(), kMaskedKexKeyLen);

        // (3) Seal the TMK to the target, anchoring the target chain to the
        // policy DATA CA.
        DarcCertChainHolder target_chain = darc_make_chain(ready.data_key, target_kex.pub_raw);
        tsra_buffer sender_buf{ source_kex.masked.data(),
                                static_cast<uint32_t>(source_kex.masked.size()) };
        tsra_buffer tmk_buf{ masked_tmk.data(), static_cast<uint32_t>(masked_tmk.size()) };
        tsra_buffer policy_buf{ ready.policy.data(), static_cast<uint32_t>(ready.policy.size()) };
        tsra_darc_tmk_export_params export_params{
            &sender_buf,
            &tmk_buf,
            &policy_buf,
            target_chain.get(),
        };
        std::vector<uint8_t> sealed_tmk(kSealedTmkLen);
        tsra_buffer sealed_buf{ sealed_tmk.data(), static_cast<uint32_t>(sealed_tmk.size()) };
        auto export_err = tsra_darc_tmk_export(ready.session, &export_params, &sealed_buf);
        ASSERT_EQ(export_err, TSRA_STATUS_SUCCESS);
        sealed_tmk.resize(sealed_buf.len);
        ASSERT_EQ(sealed_tmk.size(), kSealedTmkLen);
        ASSERT_TRUE(any_nonzero(sealed_tmk)) << "sealed TMK must not be all-zero";

        // (4) Re-open the sealed TMK on the target: the target key is the
        // receiver, the source key the sender (attested by a POTA-anchored
        // chain). A non-zero masked TMK proves the hand-off succeeded.
        DarcCertChainHolder source_chain = darc_make_chain(ready.pota_key, source_kex.pub_raw);
        tsra_buffer kex_buf{ target_kex.masked.data(),
                             static_cast<uint32_t>(target_kex.masked.size()) };
        tsra_buffer sealed_in{ sealed_tmk.data(), static_cast<uint32_t>(sealed_tmk.size()) };
        tsra_darc_tmk_import_params import_params{
            &kex_buf,
            &policy_buf,
            &sealed_in,
            source_chain.get(),
        };
        std::vector<uint8_t> imported_tmk(kMaskedTmkLen);
        tsra_buffer imported_buf{ imported_tmk.data(), static_cast<uint32_t>(imported_tmk.size()) };
        auto import_err = tsra_darc_tmk_import(ready.session, &import_params, &imported_buf);
        ASSERT_EQ(import_err, TSRA_STATUS_SUCCESS);
        imported_tmk.resize(imported_buf.len);
        ASSERT_EQ(imported_tmk.size(), kMaskedTmkLen);
        ASSERT_TRUE(any_nonzero(imported_tmk)) << "re-imported masked TMK must not be all-zero";
    });
}

// The key-exchange and TMK generation primitives return well-formed,
// non-zero envelopes of the pinned wire lengths, and each mint is fresh.
TEST_F(tsra_darc_transfer_test, kex_and_tmk_gen_smoke)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        DarcReadyContext ready = provision_darc_session(part_handle);
        if (ready.session == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&ready] { tsra_sess_close(ready.session); });

        std::vector<uint8_t> masked_kex(kMaskedKexKeyLen);
        std::vector<uint8_t> pub_kex(kKexPubKeyLen);
        tsra_buffer masked_buf{ masked_kex.data(), static_cast<uint32_t>(masked_kex.size()) };
        tsra_buffer pub_buf{ pub_kex.data(), static_cast<uint32_t>(pub_kex.size()) };
        ASSERT_EQ(
            tsra_darc_kex_key_gen(ready.session, kKeyScopeLocal, &masked_buf, &pub_buf),
            TSRA_STATUS_SUCCESS
        );
        masked_kex.resize(masked_buf.len);
        pub_kex.resize(pub_buf.len);
        ASSERT_EQ(masked_kex.size(), kMaskedKexKeyLen);
        ASSERT_EQ(pub_kex.size(), kKexPubKeyLen);
        ASSERT_TRUE(any_nonzero(masked_kex)) << "masked KEX key must not be all-zero";
        ASSERT_TRUE(any_nonzero(pub_kex)) << "KEX public key must not be all-zero";

        // Each mint draws a fresh key, so two masked envelopes differ.
        std::vector<uint8_t> masked_kex2(kMaskedKexKeyLen);
        std::vector<uint8_t> pub_kex2(kKexPubKeyLen);
        tsra_buffer masked_buf2{ masked_kex2.data(), static_cast<uint32_t>(masked_kex2.size()) };
        tsra_buffer pub_buf2{ pub_kex2.data(), static_cast<uint32_t>(pub_kex2.size()) };
        ASSERT_EQ(
            tsra_darc_kex_key_gen(ready.session, kKeyScopeLocal, &masked_buf2, &pub_buf2),
            TSRA_STATUS_SUCCESS
        );
        masked_kex2.resize(masked_buf2.len);
        ASSERT_NE(masked_kex, masked_kex2) << "each DarcKexKeyGen must mint a fresh key";

        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        ASSERT_EQ(masked_tmk.size(), kMaskedTmkLen);
        ASSERT_TRUE(any_nonzero(masked_tmk)) << "masked TMK must not be all-zero";
    });
}

// The public wrap/unwrap surface performs a full DARC key transfer: an ECC
// signing key wrapped under a TMK unwraps to a usable key on the same
// partition (acting as both endpoints), and a signature from the recovered
// key verifies against the original public key.
TEST_F(tsra_darc_transfer_test, key_wrap_unwrap_sign_round_trip)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        DarcReadyContext ready = provision_darc_session(part_handle);
        if (ready.session == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&ready] { tsra_sess_close(ready.session); });

        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        ASSERT_EQ(masked_tmk.size(), kMaskedTmkLen);
        tsra_buffer tmk_buf{ masked_tmk.data(), static_cast<uint32_t>(masked_tmk.size()) };

        // Mint a P-256 signing key on the source to transfer under the TMK.
        auto_key source_priv;
        auto_key source_pub;
        ASSERT_EQ(
            generate_ecc_keypair(
                ready.session,
                TSRA_ECC_CURVE_P256,
                /*session_key=*/false,
                source_priv.get_ptr(),
                source_pub.get_ptr()
            ),
            TSRA_STATUS_SUCCESS
        );

        // Wrap the signing key under the TMK.
        tsra_darc_key_wrap_params wrap_params{ source_priv.get(), &tmk_buf };
        std::vector<uint8_t> wrapped(kWrapWrappedKeyMaxLen);
        tsra_buffer wrapped_buf{ wrapped.data(), static_cast<uint32_t>(wrapped.size()) };
        ASSERT_EQ(
            tsra_darc_key_wrap(ready.session, &wrap_params, &wrapped_buf),
            TSRA_STATUS_SUCCESS
        );
        wrapped.resize(wrapped_buf.len);
        tsra_buffer wrapped_in_buf{ wrapped.data(), static_cast<uint32_t>(wrapped.size()) };

        // Unwrap it back on the target under the transferred TMK. The
        // transferred key is persistent (local scope), so pin the recovered
        // key pair to local scope to match the wrapped source key.
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        priv_props.is_session = 0;
        pub_props.is_session = 0;
        tsra_key_prop_list priv_prop_list = priv_props.get_prop_list();
        tsra_key_prop_list pub_prop_list = pub_props.get_prop_list();
        tsra_darc_key_unwrap_params unwrap_params{
            &tmk_buf,
            &wrapped_in_buf,
            &priv_prop_list,
            &pub_prop_list,
        };
        auto_key recovered_priv;
        auto_key recovered_pub;
        ASSERT_EQ(
            tsra_darc_key_unwrap(
                ready.session,
                &unwrap_params,
                recovered_priv.get_ptr(),
                recovered_pub.get_ptr()
            ),
            TSRA_STATUS_SUCCESS
        );

        // Sign with the recovered key and verify against the original public
        // key, proving the transferred key is functionally identical.
        std::vector<uint8_t> message = { 't', 'r', 'a', 'n', 's', 'f', 'e', 'r' };
        EcdsaRoundtripResult roundtrip =
            run_ecdsa_sign_verify_roundtrip(recovered_priv.get(), source_pub.get(), message);
        ASSERT_EQ(roundtrip.status, TSRA_STATUS_SUCCESS)
            << "round-trip failed at " << roundtrip.step << ": " << roundtrip.detail;
    });
}

// A bogus wrapped envelope fails the AES-KWP integrity check under a (valid)
// TMK, proving the ABI marshals the payload through to the on-device crypto
// rather than accepting it blindly.
TEST_F(tsra_darc_transfer_test, key_unwrap_rejects_bogus_envelope)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        DarcReadyContext ready = provision_darc_session(part_handle);
        if (ready.session == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&ready] { tsra_sess_close(ready.session); });

        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        ASSERT_EQ(masked_tmk.size(), kMaskedTmkLen);
        tsra_buffer tmk_buf{ masked_tmk.data(), static_cast<uint32_t>(masked_tmk.size()) };

        std::vector<uint8_t> bogus_wrapped(40, 0);
        tsra_buffer bogus_wrapped_buf{ bogus_wrapped.data(),
                                       static_cast<uint32_t>(bogus_wrapped.size()) };
        DefaultEccPrivKeyProps priv_props;
        DefaultEccPubKeyProps pub_props;
        tsra_key_prop_list priv_prop_list = priv_props.get_prop_list();
        tsra_key_prop_list pub_prop_list = pub_props.get_prop_list();
        tsra_darc_key_unwrap_params unwrap_params{
            &tmk_buf,
            &bogus_wrapped_buf,
            &priv_prop_list,
            &pub_prop_list,
        };
        tsra_handle recovered_priv = 0;
        tsra_handle recovered_pub = 0;
        auto unwrap_err =
            tsra_darc_key_unwrap(ready.session, &unwrap_params, &recovered_priv, &recovered_pub);
        ASSERT_NE(unwrap_err, TSRA_STATUS_SUCCESS)
            << "unwrapping a bogus envelope must be rejected";
    });
}

// A target certificate chain that does not chain up to the policy DATA
// anchor is rejected: the on-device anchor check fails after the policy hash
// verifies, surfacing as `INVALID_ARGUMENT`.
TEST_F(tsra_darc_transfer_test, tmk_export_rejects_unanchored_target_chain)
{
    part_list_.for_each_part([](std::vector<tsra_char> &path) {
        tsra_handle part_handle = open_reset_partition(path);
        if (part_handle == 0)
        {
            return;
        }
        auto part_guard =
            scope_guard::make_scope_exit([&part_handle] { tsra_part_close(part_handle); });

        DarcReadyContext ready = provision_darc_session(part_handle);
        if (ready.session == 0)
        {
            return;
        }
        auto sess_guard =
            scope_guard::make_scope_exit([&ready] { tsra_sess_close(ready.session); });

        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        ASSERT_EQ(masked_tmk.size(), kMaskedTmkLen);
        KexKey source_kex = mint_kex(ready.session);
        KexKey target_kex = mint_kex(ready.session);
        ASSERT_EQ(source_kex.masked.size(), kMaskedKexKeyLen);
        ASSERT_EQ(target_kex.masked.size(), kMaskedKexKeyLen);

        // Anchor the target chain to an unrelated CA while the bound
        // policy's DATA anchor is unchanged, so the anchor check fails.
        std::shared_ptr<CaKey> rogue_ca = darc_generate_ca();
        ASSERT_TRUE(rogue_ca != nullptr);
        DarcCertChainHolder rogue_chain = darc_make_chain(rogue_ca, target_kex.pub_raw);

        tsra_buffer sender_buf{ source_kex.masked.data(),
                                static_cast<uint32_t>(source_kex.masked.size()) };
        tsra_buffer tmk_buf{ masked_tmk.data(), static_cast<uint32_t>(masked_tmk.size()) };
        tsra_buffer policy_buf{ ready.policy.data(), static_cast<uint32_t>(ready.policy.size()) };
        tsra_darc_tmk_export_params export_params{
            &sender_buf,
            &tmk_buf,
            &policy_buf,
            rogue_chain.get(),
        };
        std::vector<uint8_t> sealed_tmk(kSealedTmkLen);
        tsra_buffer sealed_buf{ sealed_tmk.data(), static_cast<uint32_t>(sealed_tmk.size()) };
        auto export_err = tsra_darc_tmk_export(ready.session, &export_params, &sealed_buf);
        ASSERT_EQ(export_err, TSRA_STATUS_INVALID_ARGUMENT)
            << "an unanchored target chain must be rejected with INVALID_ARGUMENT";
    });
}

#endif // !defined(TSRA_FEATURE_MOCK)
