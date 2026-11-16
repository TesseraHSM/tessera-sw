// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// api-level DARC key-transfer flow over the native C ABI against the
// emulator.
//
// Drives the source->target hand-off on a single partition (acting as both
// endpoints) through the `tsra_darc_*` functions for every recipient KEM
// (P-384, ML-KEM-1024, MLKEM1024-P384): mint a Transfer Masking Key (TMK),
// mint a target recipient key and attest it with a PID key report, seal and
// PID-sign the TMK to the target (`export`, DATA-anchored target PID chain),
// and re-open it (`import`, POTA-anchored source PID chain) — proving the
// TMK survives the round trip by transferring a signing key under it.
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
// (`MASKED_KEX_KEY_MAX_LEN`, `KEX_PUB_KEY_MAX_LEN`, `MASKED_TMK_LEN`,
// `SEALED_TMK_MAX_LEN`, `DARC_REPORT_MAX_LEN`,
// `DARC_WRAP_WRAPPED_KEY_MAX_LEN`, `KEY_REPORT_DATA_LEN`), which are not
// exposed in the C header.
constexpr uint32_t kMaskedKexKeyMaxLen = 296;
constexpr uint32_t kKexPubKeyMaxLen = 1665;
constexpr uint32_t kMaskedTmkLen = 264;
constexpr uint32_t kSealedTmkMaxLen = 1826;
constexpr uint32_t kReportMaxLen = 5120;
constexpr uint32_t kWrapWrappedKeyMaxLen = 512;
constexpr uint32_t kKeyReportDataLen = 128;

// `KeyScope::Local` discriminant (mirror of `KEY_SCOPE_LOCAL`).
constexpr uint8_t kKeyScopeLocal = 0b011;

/// Per-KEM pinned lengths of the DARC recipient artifacts.
struct KemCase
{
    uint8_t kem;
    const char *name;
    uint32_t masked_len;
    uint32_t pub_len;
    uint32_t sealed_len;
};

constexpr std::array<KemCase, 3> kKemCases = { {
    { TSRA_TRANSFER_KEM_P384, "P-384", 280, 96, 258 },
    { TSRA_TRANSFER_KEM_MLKEM1024, "ML-KEM-1024", 296, 1568, 1729 },
    { TSRA_TRANSFER_KEM_MLKEM1024_P384, "MLKEM1024-P384", 264, 1665, 1826 },
} };

/// A minted DARC key-exchange key: its masked blob (the HPKE identity the
/// device unmasks on import), its public key, and the partition PID's key
/// report attesting it (the exporter's recipient authentication).
struct KexKey
{
    std::vector<uint8_t> masked;
    std::vector<uint8_t> pub;
    std::vector<uint8_t> report;
};

/// Attest `masked` with `tsra_darc_kex_key_report` (probe, then fill).
/// Records a gtest failure and returns an empty vector on error.
std::vector<uint8_t> kex_report(tsra_handle session, std::vector<uint8_t> &masked)
{
    std::vector<uint8_t> report_data(kKeyReportDataLen, 0xA5);
    tsra_buffer masked_buf{ masked.data(), static_cast<uint32_t>(masked.size()) };
    tsra_buffer data_buf{ report_data.data(), static_cast<uint32_t>(report_data.size()) };
    tsra_buffer probe{ nullptr, 0 };
    auto err = tsra_darc_kex_key_report(session, &masked_buf, &data_buf, &probe);
    if (err != TSRA_STATUS_BUFFER_TOO_SMALL || probe.len == 0)
    {
        ADD_FAILURE() << "tsra_darc_kex_key_report probe: " << err << " len " << probe.len;
        return {};
    }
    std::vector<uint8_t> report(probe.len);
    tsra_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };
    err = tsra_darc_kex_key_report(session, &masked_buf, &data_buf, &report_buf);
    if (err != TSRA_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "tsra_darc_kex_key_report failed: " << err;
        return {};
    }
    report.resize(report_buf.len);
    return report;
}

/// Mint a `tsra_darc_kex_key_gen` key of `kem` and attest it. Records a
/// gtest failure and returns an empty key on error.
KexKey mint_kex(tsra_handle session, uint8_t kem)
{
    KexKey key;
    key.masked.resize(kMaskedKexKeyMaxLen);
    key.pub.resize(kKexPubKeyMaxLen);
    tsra_buffer masked_buf{ key.masked.data(), static_cast<uint32_t>(key.masked.size()) };
    tsra_buffer pub_buf{ key.pub.data(), static_cast<uint32_t>(key.pub.size()) };
    auto err = tsra_darc_kex_key_gen(session, kKeyScopeLocal, kem, &masked_buf, &pub_buf);
    if (err != TSRA_STATUS_SUCCESS)
    {
        ADD_FAILURE() << "tsra_darc_kex_key_gen failed: " << err;
        return KexKey{};
    }
    key.masked.resize(masked_buf.len);
    key.pub.resize(pub_buf.len);
    key.report = kex_report(session, key.masked);
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

/// Output of `tsra_darc_tmk_export`.
struct ExportResult
{
    tsra_status status = TSRA_STATUS_SUCCESS;
    std::vector<uint8_t> sealed;
    std::vector<uint8_t> report;
};

/// Seal `masked_tmk` to the recipient attested by `key_report` under
/// `target_chain`, sizing both outputs by their maximum lengths.
ExportResult export_tmk(
    const DarcReadyContext &ready,
    std::vector<uint8_t> &masked_tmk,
    const DarcCertChainHolder &target_chain,
    std::vector<uint8_t> &key_report
)
{
    std::vector<uint8_t> policy = ready.policy;
    tsra_buffer tmk_buf{ masked_tmk.data(), static_cast<uint32_t>(masked_tmk.size()) };
    tsra_buffer policy_buf{ policy.data(), static_cast<uint32_t>(policy.size()) };
    tsra_buffer report_in{ key_report.data(), static_cast<uint32_t>(key_report.size()) };
    tsra_darc_tmk_export_params params{ &tmk_buf, &policy_buf, target_chain.get(), &report_in };
    ExportResult out;
    out.sealed.resize(kSealedTmkMaxLen);
    out.report.resize(kReportMaxLen);
    tsra_buffer sealed_buf{ out.sealed.data(), static_cast<uint32_t>(out.sealed.size()) };
    tsra_buffer report_buf{ out.report.data(), static_cast<uint32_t>(out.report.size()) };
    out.status = tsra_darc_tmk_export(ready.session, &params, &sealed_buf, &report_buf);
    if (out.status == TSRA_STATUS_SUCCESS)
    {
        out.sealed.resize(sealed_buf.len);
        out.report.resize(report_buf.len);
    }
    return out;
}

/// Open `sealed`/`report` with `masked_kex` under `source_chain` into
/// `imported` (resized to the returned length on success).
tsra_status import_tmk(
    const DarcReadyContext &ready,
    std::vector<uint8_t> &masked_kex,
    std::vector<uint8_t> &sealed,
    std::vector<uint8_t> &report,
    const DarcCertChainHolder &source_chain,
    std::vector<uint8_t> &imported
)
{
    std::vector<uint8_t> policy = ready.policy;
    tsra_buffer kex_buf{ masked_kex.data(), static_cast<uint32_t>(masked_kex.size()) };
    tsra_buffer policy_buf{ policy.data(), static_cast<uint32_t>(policy.size()) };
    tsra_buffer sealed_buf{ sealed.data(), static_cast<uint32_t>(sealed.size()) };
    tsra_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };
    tsra_darc_tmk_import_params params{
        &kex_buf, &policy_buf, &sealed_buf, &report_buf, source_chain.get(),
    };
    imported.assign(kMaskedTmkLen, 0xA5);
    tsra_buffer out{ imported.data(), static_cast<uint32_t>(imported.size()) };
    auto err = tsra_darc_tmk_import(ready.session, &params, &out);
    if (err == TSRA_STATUS_SUCCESS)
    {
        imported.resize(out.len);
    }
    return err;
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

    // Run `body` against every partition provisioned for DARC (DATA + POTA
    // anchored policy, initialized security domain).
    template <typename Body> void for_each_darc_ready(Body body)
    {
        part_list_.for_each_part([&body](std::vector<tsra_char> &path) {
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
            body(ready);
        });
    }
};

namespace
{
/// Prove two masked TMKs hold the same key: a P-256 signing key wrapped
/// under `source_tmk` unwraps under `target_tmk`, and a signature from the
/// recovered key verifies against the original public key.
void expect_same_tmk(
    tsra_handle session,
    std::vector<uint8_t> &source_tmk,
    std::vector<uint8_t> &target_tmk
)
{
    tsra_buffer source_buf{ source_tmk.data(), static_cast<uint32_t>(source_tmk.size()) };
    tsra_buffer target_buf{ target_tmk.data(), static_cast<uint32_t>(target_tmk.size()) };

    auto_key source_priv;
    auto_key source_pub;
    ASSERT_EQ(
        generate_ecc_keypair(
            session,
            TSRA_ECC_CURVE_P256,
            /*session_key=*/false,
            source_priv.get_ptr(),
            source_pub.get_ptr()
        ),
        TSRA_STATUS_SUCCESS
    );

    tsra_darc_key_wrap_params wrap_params{ source_priv.get(), &source_buf };
    std::vector<uint8_t> wrapped(kWrapWrappedKeyMaxLen);
    tsra_buffer wrapped_buf{ wrapped.data(), static_cast<uint32_t>(wrapped.size()) };
    ASSERT_EQ(tsra_darc_key_wrap(session, &wrap_params, &wrapped_buf), TSRA_STATUS_SUCCESS);
    wrapped.resize(wrapped_buf.len);
    tsra_buffer wrapped_in_buf{ wrapped.data(), static_cast<uint32_t>(wrapped.size()) };

    // The transferred key is persistent (local scope), so pin the recovered
    // key pair to local scope to match the wrapped source key.
    DefaultEccPrivKeyProps priv_props;
    DefaultEccPubKeyProps pub_props;
    priv_props.is_session = 0;
    pub_props.is_session = 0;
    tsra_key_prop_list priv_prop_list = priv_props.get_prop_list();
    tsra_key_prop_list pub_prop_list = pub_props.get_prop_list();
    tsra_darc_key_unwrap_params unwrap_params{
        &target_buf,
        &wrapped_in_buf,
        &priv_prop_list,
        &pub_prop_list,
    };
    auto_key recovered_priv;
    auto_key recovered_pub;
    ASSERT_EQ(
        tsra_darc_key_unwrap(
            session,
            &unwrap_params,
            recovered_priv.get_ptr(),
            recovered_pub.get_ptr()
        ),
        TSRA_STATUS_SUCCESS
    );

    std::vector<uint8_t> message = { 't', 'r', 'a', 'n', 's', 'f', 'e', 'r' };
    EcdsaRoundtripResult roundtrip =
        run_ecdsa_sign_verify_roundtrip(recovered_priv.get(), source_pub.get(), message);
    ASSERT_EQ(roundtrip.status, TSRA_STATUS_SUCCESS)
        << "round-trip failed at " << roundtrip.step << ": " << roundtrip.detail;
}
} // namespace

// Full DARC TMK transfer for every KEM: create a TMK, mint and attest the
// target recipient key, seal the TMK to it (DATA-anchored target PID chain
// plus KEX key report), re-open it (POTA-anchored source PID chain), and
// prove the recovered TMK is the original by transferring a signing key.
TEST_F(tsra_darc_transfer_test, tmk_export_import_roundtrip)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
        DarcCertChainHolder target_chain = darc_make_chain(ready.data_key, ready.pid_pub);
        DarcCertChainHolder source_chain = darc_make_chain(ready.pota_key, ready.pid_pub);

        for (const KemCase &c : kKemCases)
        {
            SCOPED_TRACE(c.name);
            std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
            ASSERT_EQ(masked_tmk.size(), kMaskedTmkLen);
            KexKey kex = mint_kex(ready.session, c.kem);
            ASSERT_EQ(kex.masked.size(), c.masked_len);
            ASSERT_FALSE(kex.report.empty());

            // Probe: both outputs report their maximum sizes.
            {
                std::vector<uint8_t> policy = ready.policy;
                tsra_buffer tmk_buf{ masked_tmk.data(), static_cast<uint32_t>(masked_tmk.size()) };
                tsra_buffer policy_buf{ policy.data(), static_cast<uint32_t>(policy.size()) };
                tsra_buffer report_in{ kex.report.data(),
                                       static_cast<uint32_t>(kex.report.size()) };
                tsra_darc_tmk_export_params params{
                    &tmk_buf,
                    &policy_buf,
                    target_chain.get(),
                    &report_in,
                };
                tsra_buffer sealed_probe{ nullptr, 0 };
                tsra_buffer report_probe{ nullptr, 0 };
                ASSERT_EQ(
                    tsra_darc_tmk_export(ready.session, &params, &sealed_probe, &report_probe),
                    TSRA_STATUS_BUFFER_TOO_SMALL
                );
                ASSERT_EQ(sealed_probe.len, kSealedTmkMaxLen);
                ASSERT_EQ(report_probe.len, kReportMaxLen);
            }

            ExportResult exp = export_tmk(ready, masked_tmk, target_chain, kex.report);
            ASSERT_EQ(exp.status, TSRA_STATUS_SUCCESS);
            ASSERT_EQ(exp.sealed.size(), c.sealed_len);
            ASSERT_FALSE(exp.report.empty());

            std::vector<uint8_t> imported;
            ASSERT_EQ(
                import_tmk(ready, kex.masked, exp.sealed, exp.report, source_chain, imported),
                TSRA_STATUS_SUCCESS
            );
            ASSERT_EQ(imported.size(), kMaskedTmkLen);
            expect_same_tmk(ready.session, masked_tmk, imported);
        }
    });
}

// Each export draws fresh HPKE randomness: two seals of the same TMK to the
// same recipient differ.
TEST_F(tsra_darc_transfer_test, tmk_export_is_freshly_sealed)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
        DarcCertChainHolder target_chain = darc_make_chain(ready.data_key, ready.pid_pub);
        for (const KemCase &c : kKemCases)
        {
            SCOPED_TRACE(c.name);
            std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
            KexKey kex = mint_kex(ready.session, c.kem);
            ExportResult first = export_tmk(ready, masked_tmk, target_chain, kex.report);
            ExportResult second = export_tmk(ready, masked_tmk, target_chain, kex.report);
            ASSERT_EQ(first.status, TSRA_STATUS_SUCCESS);
            ASSERT_EQ(second.status, TSRA_STATUS_SUCCESS);
            ASSERT_NE(first.sealed, second.sealed);
            ASSERT_NE(first.report, second.report);
        }
    });
}

// The key-exchange and TMK generation primitives return well-formed,
// non-zero envelopes of the pinned wire lengths for every KEM, each mint is
// fresh, and an unknown KEM is rejected.
TEST_F(tsra_darc_transfer_test, kex_and_tmk_gen_smoke)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
        for (const KemCase &c : kKemCases)
        {
            SCOPED_TRACE(c.name);
            KexKey first = mint_kex(ready.session, c.kem);
            KexKey second = mint_kex(ready.session, c.kem);
            ASSERT_EQ(first.masked.size(), c.masked_len);
            ASSERT_EQ(first.pub.size(), c.pub_len);
            ASSERT_TRUE(any_nonzero(first.masked));
            ASSERT_TRUE(any_nonzero(first.pub));
            ASSERT_NE(first.masked, second.masked) << "each DarcKexKeyGen must mint a fresh key";
            ASSERT_NE(first.pub, second.pub);
        }

        // Probe reports the KEM-independent maximum sizes.
        tsra_buffer masked_probe{ nullptr, 0 };
        tsra_buffer pub_probe{ nullptr, 0 };
        ASSERT_EQ(
            tsra_darc_kex_key_gen(
                ready.session,
                kKeyScopeLocal,
                TSRA_TRANSFER_KEM_P384,
                &masked_probe,
                &pub_probe
            ),
            TSRA_STATUS_BUFFER_TOO_SMALL
        );
        ASSERT_EQ(masked_probe.len, kMaskedKexKeyMaxLen);
        ASSERT_EQ(pub_probe.len, kKexPubKeyMaxLen);

        std::vector<uint8_t> masked(kMaskedKexKeyMaxLen);
        std::vector<uint8_t> pub(kKexPubKeyMaxLen);
        tsra_buffer masked_buf{ masked.data(), static_cast<uint32_t>(masked.size()) };
        tsra_buffer pub_buf{ pub.data(), static_cast<uint32_t>(pub.size()) };
        ASSERT_EQ(
            tsra_darc_kex_key_gen(ready.session, kKeyScopeLocal, 3, &masked_buf, &pub_buf),
            TSRA_STATUS_INVALID_ARGUMENT
        );

        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        ASSERT_EQ(masked_tmk.size(), kMaskedTmkLen);
        ASSERT_TRUE(any_nonzero(masked_tmk)) << "masked TMK must not be all-zero";
    });
}

// `tsra_darc_kex_key_report` rejects malformed report data.
TEST_F(tsra_darc_transfer_test, kex_key_report_rejects_bad_report_data)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
        KexKey kex = mint_kex(ready.session, TSRA_TRANSFER_KEM_MLKEM1024);
        ASSERT_FALSE(kex.report.empty());
        std::vector<uint8_t> short_data(kKeyReportDataLen - 1, 0);
        std::vector<uint8_t> report(kReportMaxLen);
        tsra_buffer masked_buf{ kex.masked.data(), static_cast<uint32_t>(kex.masked.size()) };
        tsra_buffer data_buf{ short_data.data(), static_cast<uint32_t>(short_data.size()) };
        tsra_buffer report_buf{ report.data(), static_cast<uint32_t>(report.size()) };
        ASSERT_EQ(
            tsra_darc_kex_key_report(ready.session, &masked_buf, &data_buf, &report_buf),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

// The public wrap/unwrap surface performs a full DARC key transfer: an ECC
// signing key wrapped under a TMK unwraps to a usable key on the same
// partition (acting as both endpoints), and a signature from the recovered
// key verifies against the original public key.
TEST_F(tsra_darc_transfer_test, key_wrap_unwrap_sign_round_trip)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        ASSERT_EQ(masked_tmk.size(), kMaskedTmkLen);
        expect_same_tmk(ready.session, masked_tmk, masked_tmk);
    });
}

// A bogus wrapped envelope fails the AES-KWP integrity check under a (valid)
// TMK, proving the ABI marshals the payload through to the on-device crypto
// rather than accepting it blindly.
TEST_F(tsra_darc_transfer_test, key_unwrap_rejects_bogus_envelope)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
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

// A target PID chain that does not chain up to the policy DATA anchor
// (foreign CA, or the POTA anchor) is rejected with `INVALID_ARGUMENT`.
TEST_F(tsra_darc_transfer_test, tmk_export_rejects_unanchored_target_chain)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        KexKey kex = mint_kex(ready.session, TSRA_TRANSFER_KEM_P384);
        std::shared_ptr<CaKey> rogue_ca = darc_generate_ca();
        ASSERT_TRUE(rogue_ca != nullptr);
        DarcCertChainHolder rogue_chain = darc_make_chain(rogue_ca, ready.pid_pub);
        DarcCertChainHolder pota_chain = darc_make_chain(ready.pota_key, ready.pid_pub);

        ASSERT_EQ(
            export_tmk(ready, masked_tmk, rogue_chain, kex.report).status,
            TSRA_STATUS_INVALID_ARGUMENT
        );
        ASSERT_EQ(
            export_tmk(ready, masked_tmk, pota_chain, kex.report).status,
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}

// Only a report over a generated DARC KEX key authenticates the recipient:
// an SD sealing key's report (from either report entry point) is rejected.
TEST_F(tsra_darc_transfer_test, tmk_export_rejects_non_darc_key_report)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
        DarcCertChainHolder target_chain = darc_make_chain(ready.data_key, ready.pid_pub);
        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        SealingKeyMaterial sealing = sealing_key_and_report(ready.session);
        ASSERT_FALSE(sealing.report.empty());
        std::vector<uint8_t> via_darc = kex_report(ready.session, sealing.masked);
        ASSERT_FALSE(via_darc.empty());

        ASSERT_NE(
            export_tmk(ready, masked_tmk, target_chain, sealing.report).status,
            TSRA_STATUS_SUCCESS
        );
        ASSERT_NE(
            export_tmk(ready, masked_tmk, target_chain, via_darc).status,
            TSRA_STATUS_SUCCESS
        );
    });
}

// Import rejects a tampered envelope or report and the wrong recipient key,
// without touching the output buffer.
TEST_F(tsra_darc_transfer_test, tmk_import_rejects_tampering_and_wrong_key)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
        DarcCertChainHolder target_chain = darc_make_chain(ready.data_key, ready.pid_pub);
        DarcCertChainHolder source_chain = darc_make_chain(ready.pota_key, ready.pid_pub);
        for (const KemCase &c : kKemCases)
        {
            SCOPED_TRACE(c.name);
            std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
            KexKey kex = mint_kex(ready.session, c.kem);
            ExportResult exp = export_tmk(ready, masked_tmk, target_chain, kex.report);
            ASSERT_EQ(exp.status, TSRA_STATUS_SUCCESS);
            std::vector<uint8_t> imported;

            std::vector<uint8_t> bad_sealed = exp.sealed;
            bad_sealed[bad_sealed.size() / 2] ^= 1;
            ASSERT_NE(
                import_tmk(ready, kex.masked, bad_sealed, exp.report, source_chain, imported),
                TSRA_STATUS_SUCCESS
            );

            std::vector<uint8_t> bad_report = exp.report;
            bad_report.back() ^= 1;
            ASSERT_EQ(
                import_tmk(ready, kex.masked, exp.sealed, bad_report, source_chain, imported),
                TSRA_STATUS_INVALID_ARGUMENT
            );
            ASSERT_TRUE(std::all_of(imported.begin(), imported.end(), [](uint8_t value) {
                return value == 0xA5;
            })) << "a failed import must not write the output";

            KexKey other = mint_kex(ready.session, c.kem);
            ASSERT_NE(
                import_tmk(ready, other.masked, exp.sealed, exp.report, source_chain, imported),
                TSRA_STATUS_SUCCESS
            );

            ASSERT_EQ(
                import_tmk(ready, kex.masked, exp.sealed, exp.report, source_chain, imported),
                TSRA_STATUS_SUCCESS
            );
        }
    });
}

// Malformed lengths are rejected at the ABI with `INVALID_ARGUMENT`.
TEST_F(tsra_darc_transfer_test, tmk_export_import_reject_invalid_lengths)
{
    if (!api_rev_at_least(1, 1))
    {
        return;
    }
    for_each_darc_ready([](DarcReadyContext &ready) {
        DarcCertChainHolder target_chain = darc_make_chain(ready.data_key, ready.pid_pub);
        DarcCertChainHolder source_chain = darc_make_chain(ready.pota_key, ready.pid_pub);
        std::vector<uint8_t> masked_tmk = mint_tmk(ready.session);
        KexKey kex = mint_kex(ready.session, TSRA_TRANSFER_KEM_P384);
        ExportResult exp = export_tmk(ready, masked_tmk, target_chain, kex.report);
        ASSERT_EQ(exp.status, TSRA_STATUS_SUCCESS);

        std::vector<uint8_t> short_tmk(masked_tmk.begin(), masked_tmk.end() - 1);
        ASSERT_EQ(
            export_tmk(ready, short_tmk, target_chain, kex.report).status,
            TSRA_STATUS_INVALID_ARGUMENT
        );
        std::vector<uint8_t> oversized_report(kReportMaxLen + 1, 0);
        ASSERT_EQ(
            export_tmk(ready, masked_tmk, target_chain, oversized_report).status,
            TSRA_STATUS_INVALID_ARGUMENT
        );

        std::vector<uint8_t> imported;
        std::vector<uint8_t> short_sealed(exp.sealed.begin(), exp.sealed.end() - 1);
        ASSERT_EQ(
            import_tmk(ready, kex.masked, short_sealed, exp.report, source_chain, imported),
            TSRA_STATUS_INVALID_ARGUMENT
        );
        std::vector<uint8_t> short_kex(kex.masked.begin(), kex.masked.end() - 1);
        ASSERT_EQ(
            import_tmk(ready, short_kex, exp.sealed, exp.report, source_chain, imported),
            TSRA_STATUS_INVALID_ARGUMENT
        );
    });
}
