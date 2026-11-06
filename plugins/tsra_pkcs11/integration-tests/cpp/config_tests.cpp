// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// @file config_tests.cpp
///
/// The configuration as C_Initialize sees it: a bad TSRA_PKCS11_STORE_DIR
/// fails closed instead of falling back to the default directory, a store
/// directory others can access is refused, the file TSRA_PKCS11_CONF names
/// is applied with the environment winning over it, a bad file fails
/// C_Initialize with the reason on the debug trace, and the owner backup key
/// file is read at C_Login, not at C_Initialize. Each case finalizes the
/// module, initializes it under its own environment and leaves it initialized
/// again under the original one.

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "tsra_pkcs11_config.h"
#include "utils/module.hpp"

class config : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        ASSERT_NE(p11(), nullptr) << "module not loaded";
        for (const char *name : kVars)
        {
            saved_.push_back(saved(name));
        }
        ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
    }

    void TearDown() override
    {
        (void)p11()->C_Finalize(nullptr);
        for (size_t i = 0; i < saved_.size(); i++)
        {
            restore(kVars[i], saved_[i]);
        }
        EXPECT_CKR_OK(p11()->C_Initialize(nullptr));
        if (!temp_.empty())
        {
            std::filesystem::remove_all(temp_);
        }
    }

    /// C_Initialize under the given store settings.
    static CK_RV init_with(const char *dir, const char *persist)
    {
        setenv(TSRA_PKCS11_ENV_STORE_DIR, dir, 1);
        setenv(TSRA_PKCS11_ENV_PERSIST, persist, 1);
        return p11()->C_Initialize(nullptr);
    }

    /// A fresh directory under TMPDIR, removed after the case.
    std::string temp_dir()
    {
        const char *tmp = std::getenv("TMPDIR");
        std::string tmpl = std::string((tmp != nullptr) && (*tmp != '\0') ? tmp : "/tmp") +
                           "/tsra_pkcs11_config_test.XXXXXX";
        if (mkdtemp(tmpl.data()) == nullptr)
        {
            ADD_FAILURE() << "mkdtemp";
            return "/nonexistent";
        }
        temp_ = tmpl;
        return temp_;
    }

  private:
    static constexpr const char *kVars[] = {
        TSRA_PKCS11_ENV_STORE_DIR, TSRA_PKCS11_ENV_PERSIST,  TSRA_PKCS11_ENV_CONF,
        TSRA_PKCS11_ENV_DEBUG,     TSRA_PKCS11_ENV_OBK_PATH,
    };

    static std::optional<std::string> saved(const char *name)
    {
        const char *v = std::getenv(name);
        return (v != nullptr) ? std::optional<std::string>(v) : std::nullopt;
    }

    static void restore(const char *name, const std::optional<std::string> &value)
    {
        if (value)
        {
            setenv(name, value->c_str(), 1);
        }
        else
        {
            unsetenv(name);
        }
    }

    std::vector<std::optional<std::string>> saved_;
    std::string temp_;
};

TEST_F(config, unsafe_store_dir_fails_initialize)
{
    const std::string overlong = "/" + std::string(TSRA_PKCS11_PATH_LEN, 'a');
    for (const char *dir : { "", "file:", "/tmp/../tmp", overlong.c_str() })
    {
        SCOPED_TRACE(
            ::testing::Message() << "store dir '" << std::string(dir).substr(0, 16) << "'"
        );
        // The memory store does not use the directory; a bad setting still fails.
        EXPECT_CKR(CKR_GENERAL_ERROR, init_with(dir, "0"));
        EXPECT_CKR(CKR_GENERAL_ERROR, init_with(dir, "1"));
        EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, p11()->C_Finalize(nullptr))
            << "the failed C_Initialize left the module uninitialized";
    }
}

TEST_F(config, store_dir_others_can_access_is_refused)
{
    const char *tmp = std::getenv("TMPDIR");
    std::string tmpl = std::string((tmp != nullptr) && (*tmp != '\0') ? tmp : "/tmp") +
                       "/tsra_pkcs11_config_test.XXXXXX";
    ASSERT_NE(nullptr, mkdtemp(tmpl.data()));
    const std::string dir = tmpl;

    ASSERT_EQ(0, chmod(dir.c_str(), 0775));
    EXPECT_NE(CKR_OK, init_with(dir.c_str(), "1")) << "a group-writable store dir is refused";
    EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, p11()->C_Finalize(nullptr));

    ASSERT_EQ(0, chmod(dir.c_str(), 0700));
    EXPECT_CKR_OK(init_with(dir.c_str(), "1")) << "the same directory at 0700 is accepted";
    EXPECT_CKR_OK(p11()->C_Finalize(nullptr));
    EXPECT_EQ(0, rmdir(dir.c_str())) << "initialization alone writes nothing into the store";
}

TEST_F(config, config_file_sets_the_store_and_the_environment_wins)
{
    const std::string root = temp_dir();
    const std::string conf = root + "/pkcs11.conf";
    std::ofstream(conf) << "# test configuration\npersist = 1\nstore_dir = " << root
                        << "/from-file\n";
    unsetenv(TSRA_PKCS11_ENV_PERSIST);
    unsetenv(TSRA_PKCS11_ENV_STORE_DIR);
    setenv(TSRA_PKCS11_ENV_CONF, conf.c_str(), 1);
    struct stat st = {};

    ASSERT_CKR_OK(p11()->C_Initialize(nullptr));
    EXPECT_EQ(0, stat((root + "/from-file").c_str(), &st)) << "the file chose the file store";
    ASSERT_CKR_OK(p11()->C_Finalize(nullptr));

    setenv(TSRA_PKCS11_ENV_STORE_DIR, (root + "/from-env").c_str(), 1);
    ASSERT_CKR_OK(p11()->C_Initialize(nullptr));
    EXPECT_EQ(0, stat((root + "/from-env").c_str(), &st)) << "the environment won";
    ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
}

TEST_F(config, bad_config_file_fails_initialize_with_a_debug_line)
{
    const std::string root = temp_dir();
    const std::string conf = root + "/pkcs11.conf";
    std::ofstream(conf) << "persist = 0\npin = 1234\n";
    setenv(TSRA_PKCS11_ENV_CONF, conf.c_str(), 1);
    setenv(TSRA_PKCS11_ENV_DEBUG, "1", 1);

    ::testing::internal::CaptureStderr();
    CK_RV rv = p11()->C_Initialize(nullptr);
    std::string trace = ::testing::internal::GetCapturedStderr();
    EXPECT_CKR(CKR_GENERAL_ERROR, rv) << "credentials are never read from the file";
    EXPECT_NE(std::string::npos, trace.find("line 2")) << trace;
    EXPECT_EQ(std::string::npos, trace.find("1234")) << "the trace never repeats a value";

    setenv(TSRA_PKCS11_ENV_CONF, (root + "/missing.conf").c_str(), 1);
    EXPECT_CKR(CKR_GENERAL_ERROR, p11()->C_Initialize(nullptr)) << "a missing file";
    EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, p11()->C_Finalize(nullptr));
}

TEST_F(config, owner_backup_key_is_read_at_login_not_at_initialize)
{
    const std::string missing = temp_dir() + "/missing.bin";
    setenv(TSRA_PKCS11_ENV_OBK_PATH, missing.c_str(), 1);
    ASSERT_CKR_OK(p11()->C_Initialize(nullptr)) << "C_Initialize only takes the name";
    CK_SESSION_HANDLE s = 0;
    ASSERT_CKR_OK(p11()->C_OpenSession(kSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &s));
    EXPECT_CKR(CKR_FUNCTION_FAILED, login_user(s)) << "C_Login reads the file";
    EXPECT_CKR_OK(p11()->C_CloseSession(s));
}
