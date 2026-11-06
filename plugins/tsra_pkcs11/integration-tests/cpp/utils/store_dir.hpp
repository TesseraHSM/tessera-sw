// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// StoreDirFixture: a UserSession on a file object store of its own.
///
/// SetUp re-initializes the module with TSRA_PKCS11_PERSIST=1 and
/// TSRA_PKCS11_STORE_DIR naming a directory that does not exist yet, so the
/// module has to create it, and asserts it did so owner-only (0700). TearDown
/// removes the store and re-initializes the module on the environment the
/// process started with, so the rest of a single-process run is unaffected.

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <vector>

#include "utils/module.hpp"

class StoreDirFixture : public UserSession
{
  protected:
    void SetUp() override
    {
        ASSERT_NE(p11(), nullptr) << "module not loaded";
        std::string tmpl = (std::filesystem::temp_directory_path() / "tsra-pkcs11-store.XXXXXX");
        ASSERT_NE(nullptr, mkdtemp(tmpl.data()));
        root_ = tmpl;
        dir_ = root_ + "/store";
        saved_persist_ = getenv_opt(kPersist);
        saved_dir_ = getenv_opt(kStoreDir);

        ASSERT_CKR_OK(p11()->C_Finalize(nullptr));
        reinit_ = true;
        setenv(kPersist, "1", 1);
        setenv(kStoreDir, dir_.c_str(), 1);
        ASSERT_CKR_OK(p11()->C_Initialize(nullptr));
        struct stat st = {};
        ASSERT_EQ(0, stat(dir_.c_str(), &st)) << "C_Initialize created " << dir_;
        EXPECT_EQ(0700u, st.st_mode & 07777) << "the store directory is owner-only";

        UserSession::SetUp();
    }

    void TearDown() override
    {
        UserSession::TearDown();
        if (reinit_)
        {
            (void)p11()->C_Finalize(nullptr);
            restore(kPersist, saved_persist_);
            restore(kStoreDir, saved_dir_);
            EXPECT_CKR_OK(p11()->C_Initialize(nullptr));
        }
        if (!root_.empty())
        {
            std::filesystem::remove_all(root_);
        }
    }

    /// The environment that points a second process at this store.
    std::vector<std::string> store_env() const
    {
        return { std::string(kPersist) + "=1", std::string(kStoreDir) + "=" + dir_ };
    }

    /// Whether any file in the store holds `bytes` verbatim.
    bool store_contains(const std::vector<CK_BYTE> &bytes) const
    {
        for (const auto &f : std::filesystem::recursive_directory_iterator(dir_))
        {
            if (!f.is_regular_file())
            {
                continue;
            }
            std::ifstream in(f.path(), std::ios::binary);
            std::vector<CK_BYTE> data(
                (std::istreambuf_iterator<char>(in)),
                std::istreambuf_iterator<char>()
            );
            if (std::search(data.begin(), data.end(), bytes.begin(), bytes.end()) != data.end())
            {
                return true;
            }
        }
        return false;
    }

    std::string dir_;

  private:
    static constexpr const char *kPersist = "TSRA_PKCS11_PERSIST";
    static constexpr const char *kStoreDir = "TSRA_PKCS11_STORE_DIR";

    static std::optional<std::string> getenv_opt(const char *name)
    {
        const char *v = std::getenv(name);
        return (v != nullptr) ? std::optional<std::string>(v) : std::nullopt;
    }

    static void restore(const char *name, const std::optional<std::string> &value)
    {
        if (value.has_value())
        {
            setenv(name, value->c_str(), 1);
        }
        else
        {
            unsetenv(name);
        }
    }

    std::string root_;
    std::optional<std::string> saved_persist_;
    std::optional<std::string> saved_dir_;
    bool reinit_ = false;
};
