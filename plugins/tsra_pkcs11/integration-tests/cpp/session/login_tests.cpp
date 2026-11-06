// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file login_tests.cpp
///
/// C_Login on a token with one user, positive and
/// negative: the PIN rules, the default PIN, the user types, the token flags,
/// the owner backup key read at every login and the token-wide login state.
/// The first login of a process provisions the emulated partition with its PIN,
/// so a case that got past the PIN rules with another PIN would change the
/// credential for the rest of its process. Each case therefore runs its body
/// as login_child.<case> in a process of its own (SubprocessModule).

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "tsra_pkcs11_config.h"
#include "utils/aes_helpers.hpp"
#include "utils/module.hpp"
#include "utils/subprocess.hpp"

namespace
{

/// Run login_child.<name> in a fresh process with `env` added.
void run_child(const std::string &name, const std::vector<std::string> &env = {})
{
    SubprocessModule::Result child = SubprocessModule::run("login_child." + name, env);
    EXPECT_EQ("1", child.values["ran"]) << "login_child." << name << " did not run";
    EXPECT_EQ(0, child.exit_code) << "login_child." << name << " failed, its output is above";
}

/// C_Login as CKU_USER with exactly the bytes of `pin`.
CK_RV login_with(CK_SESSION_HANDLE s, const std::string &pin)
{
    return p11()->C_Login(
        s,
        CKU_USER,
        reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char *>(pin.data())),
        static_cast<CK_ULONG>(pin.size())
    );
}

CK_FLAGS token_flags()
{
    CK_TOKEN_INFO info{};
    EXPECT_CKR_OK(p11()->C_GetTokenInfo(kSlot, &info));
    return info.flags;
}

} // namespace

class login : public ::testing::Test
{
};

class login_child : public PublicSession
{
};

TEST_F(login, empty_pin_is_pin_len_range)
{
    run_child("empty_pin_is_pin_len_range");
}

TEST_F(login_child, empty_pin_is_pin_len_range)
{
    SUBPROCESS_ONLY();
    EXPECT_EQ(0u, token_flags() & CKF_PROTECTED_AUTHENTICATION_PATH) << "no default PIN";
    EXPECT_CKR(CKR_PIN_LEN_RANGE, p11()->C_Login(s_, CKU_USER, nullptr, 0));
    CK_UTF8CHAR empty[] = "";
    EXPECT_CKR(CKR_PIN_LEN_RANGE, p11()->C_Login(s_, CKU_USER, empty, 0));
    EXPECT_CKR_OK(login_user(s_)) << "the refused logins provisioned nothing";
}

TEST_F(login, three_char_pin_is_pin_len_range)
{
    run_child("three_char_pin_is_pin_len_range");
}

TEST_F(login_child, three_char_pin_is_pin_len_range)
{
    SUBPROCESS_ONLY();
    EXPECT_CKR(CKR_PIN_LEN_RANGE, login_with(s_, "123"));
    EXPECT_CKR(CKR_PIN_LEN_RANGE, login_with(s_, std::string(17, '7')));
    EXPECT_CKR(CKR_ARGUMENTS_BAD, p11()->C_Login(s_, CKU_USER, nullptr, 4));
    EXPECT_CKR_OK(login_user(s_)) << "the refused logins provisioned nothing";
}

TEST_F(login, pin_with_a_nul_byte_is_pin_invalid)
{
    run_child("pin_with_a_nul_byte_is_pin_invalid");
}

TEST_F(login_child, pin_with_a_nul_byte_is_pin_invalid)
{
    SUBPROCESS_ONLY();
    EXPECT_CKR(
        CKR_PIN_INVALID,
        login_with(
            s_,
            std::string(
                "12\0"
                "4",
                4
            )
        )
    );
    // Zero padding would make this the credential of "1234".
    EXPECT_CKR(CKR_PIN_INVALID, login_with(s_, std::string("1234\0\0", 6)));
    EXPECT_CKR_OK(login_user(s_)) << "the refused logins provisioned nothing";
}

TEST_F(login, wrong_pin_after_first_login_is_function_failed_today)
{
    run_child("wrong_pin_after_first_login_is_function_failed_today");
}

TEST_F(login_child, wrong_pin_after_first_login_is_function_failed_today)
{
    SUBPROCESS_ONLY();
    ASSERT_CKR_OK(login_user(s_)) << "the first login provisions the partition";
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    // The SDK reports a rejected credential as a generic failure (SDK issue
    // #53). This flips to CKR_PIN_INCORRECT once the SDK names the status.
    std::string wrong = Pkcs11Module::pin();
    wrong.back() ^= 1;
    EXPECT_CKR(CKR_FUNCTION_FAILED, login_with(s_, wrong));
    CK_SESSION_INFO info{};
    ASSERT_CKR_OK(p11()->C_GetSessionInfo(s_, &info));
    EXPECT_EQ(static_cast<CK_STATE>(CKS_RW_PUBLIC_SESSION), info.state);
    EXPECT_CKR_OK(login_user(s_)) << "the right PIN still logs in";
}

TEST_F(login, so_user_type_invalid)
{
    run_child("so_user_type_invalid");
}

TEST_F(login_child, so_user_type_invalid)
{
    SUBPROCESS_ONLY();
    std::string pin = Pkcs11Module::pin();
    auto *p = reinterpret_cast<CK_UTF8CHAR_PTR>(pin.data());
    auto n = static_cast<CK_ULONG>(pin.size());
    EXPECT_CKR(CKR_USER_TYPE_INVALID, p11()->C_Login(s_, CKU_SO, p, n));
    EXPECT_CKR(CKR_USER_TYPE_INVALID, p11()->C_Login(s_, 99, p, n));
    EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, p11()->C_Login(s_, CKU_CONTEXT_SPECIFIC, p, n))
        << "no operation asks for re-authentication";
    // No Security Officer and no PIN change on the V1 device session.
    CK_UTF8CHAR label[32];
    std::memset(label, ' ', sizeof(label));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_InitToken(kSlot, p, n, label));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_InitPIN(s_, p, n));
    EXPECT_CKR(CKR_FUNCTION_NOT_SUPPORTED, p11()->C_SetPIN(s_, p, n, p, n));
    EXPECT_CKR_OK(login_user(s_)) << "the user role still logs in";
}

TEST_F(login, second_session_login_already_logged_in)
{
    run_child("second_session_login_already_logged_in");
}

TEST_F(login_child, second_session_login_already_logged_in)
{
    SUBPROCESS_ONLY();
    CK_SESSION_HANDLE ro = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &ro));
    ASSERT_CKR_OK(login_user(s_));
    EXPECT_CKR(CKR_USER_ALREADY_LOGGED_IN, login_user(ro)) << "the login is token-wide";
    CK_SESSION_INFO info{};
    ASSERT_CKR_OK(p11()->C_GetSessionInfo(ro, &info));
    EXPECT_EQ(static_cast<CK_STATE>(CKS_RO_USER_FUNCTIONS), info.state);
    EXPECT_CKR(CKR_PIN_LEN_RANGE, login_with(ro, "123")) << "the PIN rules come first";
    ASSERT_CKR_OK(p11()->C_CloseSession(ro));
}

TEST_F(login, logout_in_a_terminates_b_stream)
{
    run_child("logout_in_a_terminates_b_stream");
}

TEST_F(login_child, logout_in_a_terminates_b_stream)
{
    SUBPROCESS_ONLY();
    CK_SESSION_HANDLE b = 0;
    ASSERT_CKR_OK(
        p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &b)
    );
    ASSERT_CKR_OK(login_user(s_));
    CK_OBJECT_HANDLE key = 0;
    ASSERT_CKR_OK(gen_aes_key(b, 32, CK_TRUE, CK_TRUE, "stream", &key));
    CK_BYTE iv[kAesBlock] = { 0 };
    CK_MECHANISM cbc = { CKM_AES_CBC_PAD, iv, sizeof(iv) };
    std::vector<CK_BYTE> in(2 * kAesBlock, 0x42), out(3 * kAesBlock);
    CK_ULONG n = static_cast<CK_ULONG>(out.size());
    ASSERT_CKR_OK(p11()->C_EncryptInit(b, &cbc, key));
    ASSERT_CKR_OK(p11()->C_EncryptUpdate(b, in.data(), kAesBlock, out.data(), &n));

    ASSERT_CKR_OK(p11()->C_Logout(s_));
    n = static_cast<CK_ULONG>(out.size());
    EXPECT_CKR(
        CKR_OPERATION_NOT_INITIALIZED,
        p11()->C_EncryptUpdate(b, in.data(), kAesBlock, out.data(), &n)
    ) << "the device key of B's stream belonged to the device session A ended";
    ASSERT_CKR_OK(p11()->C_CloseSession(b));
}

TEST_F(login, token_flags_match_policy)
{
    run_child("token_flags_match_policy");
}

TEST_F(login_child, token_flags_match_policy)
{
    SUBPROCESS_ONLY();
    const CK_FLAGS unset = CKF_PROTECTED_AUTHENTICATION_PATH | CKF_RNG |
                           CKF_USER_PIN_TO_BE_CHANGED | CKF_USER_PIN_LOCKED |
                           CKF_USER_PIN_FINAL_TRY | CKF_SO_PIN_TO_BE_CHANGED | CKF_SO_PIN_LOCKED |
                           CKF_SO_PIN_COUNT_LOW;
    const CK_FLAGS set = CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
    // The first login provisions the partition; the flags say the same before
    // and after it.
    for (int round = 0; round < 2; round++)
    {
        SCOPED_TRACE(round == 0 ? "before the first login" : "after it");
        CK_TOKEN_INFO info{};
        ASSERT_CKR_OK(p11()->C_GetTokenInfo(kSlot, &info));
        EXPECT_EQ(set, info.flags & set);
        EXPECT_EQ(0u, info.flags & unset);
        EXPECT_EQ(static_cast<CK_ULONG>(TSRA_PKCS11_MIN_PIN_LEN), info.ulMinPinLen);
        EXPECT_EQ(static_cast<CK_ULONG>(TSRA_PKCS11_MAX_PIN_LEN), info.ulMaxPinLen);
        if (round == 0)
        {
            ASSERT_CKR_OK(login_user(s_));
        }
    }
}

TEST_F(login, default_pin_logs_in_without_a_pin)
{
    // The test PIN as the 16-byte credential PIN: zero-padded, in hex.
    std::string pin = Pkcs11Module::pin();
    ASSERT_LE(pin.size(), static_cast<size_t>(P11_CREDS_PIN_LEN));
    pin.resize(P11_CREDS_PIN_LEN, '\0');
    std::string hex;
    for (char c : pin)
    {
        char byte[3];
        std::snprintf(byte, sizeof(byte), "%02x", static_cast<unsigned char>(c));
        hex += byte;
    }
    run_child(
        "default_pin_logs_in_without_a_pin",
        { std::string(TSRA_PKCS11_ENV_PIN) + "=" + hex }
    );
}

TEST_F(login_child, default_pin_logs_in_without_a_pin)
{
    SUBPROCESS_ONLY();
    EXPECT_NE(0u, token_flags() & CKF_PROTECTED_AUTHENTICATION_PATH);
    ASSERT_CKR_OK(p11()->C_Login(s_, CKU_USER, nullptr, 0)) << "the configured default PIN";
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR_OK(login_user(s_)) << "it is the credential the typed test PIN makes";
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR(CKR_PIN_LEN_RANGE, login_with(s_, "123")) << "a typed PIN keeps its rules";
}

TEST_F(login, sixteen_byte_pin_logs_in)
{
    EMU_ONLY("the first login after power-on chooses the credential");
    run_child("sixteen_byte_pin_logs_in");
}

TEST_F(login_child, sixteen_byte_pin_logs_in)
{
    SUBPROCESS_ONLY();
    const std::string pin = "0123456789abcdef";
    ASSERT_CKR_OK(login_with(s_, pin)) << "provisions the partition with all 16 bytes";
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR_OK(login_with(s_, pin));
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    EXPECT_CKR(CKR_FUNCTION_FAILED, login_with(s_, pin.substr(0, 15))) << "another credential";
}

TEST_F(login, every_login_reads_the_owner_backup_key)
{
    EMU_ONLY("the first login provisions the partition with a test owner backup key");
    run_child("every_login_reads_the_owner_backup_key");
}

TEST_F(login_child, every_login_reads_the_owner_backup_key)
{
    SUBPROCESS_ONLY();
    std::string tmpl = (std::filesystem::temp_directory_path() / "tsra-pkcs11-obk.XXXXXX");
    ASSERT_NE(nullptr, mkdtemp(tmpl.data()));
    const std::filesystem::path dir = tmpl;
    auto key_file = [&](const char *name, size_t len) {
        std::ofstream(dir / name, std::ios::binary) << std::string(len, '\x5a');
        return (dir / name).string();
    };
    const std::string good = key_file("good.bin", P11_OBK_LEN);
    const std::string short_key = key_file("short.bin", P11_OBK_LEN - 1);
    const std::string long_key = key_file("long.bin", P11_OBK_LEN + 1);
    const std::string link = (dir / "link.bin").string();
    std::filesystem::create_symlink(good, link);
    auto login_reading = [&](const std::string &obk) {
        setenv(TSRA_PKCS11_ENV_OBK_PATH, obk.c_str(), 1);
        return login_user(s_);
    };

    EXPECT_CKR(CKR_FUNCTION_FAILED, login_reading(short_key)) << "nothing provisioned yet";
    ASSERT_CKR_OK(login_reading(good)) << "provisions the partition with the file's key";
    ASSERT_CKR_OK(p11()->C_Logout(s_));
    for (const std::string &bad :
         { short_key, long_key, (dir / "missing.bin").string(), link, dir.string() })
    {
        SCOPED_TRACE(bad);
        EXPECT_CKR(CKR_FUNCTION_FAILED, login_reading(bad)) << "the partition is provisioned";
    }
    CK_SESSION_INFO info{};
    ASSERT_CKR_OK(p11()->C_GetSessionInfo(s_, &info));
    EXPECT_EQ(static_cast<CK_STATE>(CKS_RW_PUBLIC_SESSION), info.state);
    EXPECT_CKR_OK(login_reading(good)) << "a good file logs in again";
    std::filesystem::remove_all(dir);
}
