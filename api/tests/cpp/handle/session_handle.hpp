// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef SESSION_HANDLE_HPP
#define SESSION_HANDLE_HPP

#include <cstring>
#include <stdexcept>
#include <string>
#include <tsra_api.h>

#include "../utils/utils.hpp"
#include "test_creds.hpp"

class SessionHandle
{
  public:
    SessionHandle(tsra_handle part_handle) : handle_(0)
    {
        tsra_credentials creds{};
        std::memcpy(creds.id, TEST_CRED_ID, sizeof(TEST_CRED_ID));
        std::memcpy(creds.pin, TEST_CRED_PIN, sizeof(TEST_CRED_PIN));

        auto err = tsra_sess_open(part_handle, &creds, nullptr, &handle_);
        if (err != TSRA_STATUS_SUCCESS)
        {
            throw std::runtime_error("Failed to open session. Error: " + std::to_string(err));
        }
    }

    ~SessionHandle() noexcept
    {
        if (handle_ != 0)
        {
            auto err = tsra_sess_close(handle_);
            if (err != TSRA_STATUS_SUCCESS)
            {
                printf("Warning: Failed to close session handle %u. Error: %d\n", handle_, err);
            }
        }
    }

    SessionHandle(const SessionHandle &) = delete;
    SessionHandle &operator=(const SessionHandle &) = delete;

    SessionHandle(SessionHandle &&other) noexcept : handle_(other.handle_)
    {
        other.handle_ = 0;
    }

    SessionHandle &operator=(SessionHandle &&other) noexcept
    {
        if (this != &other)
        {
            if (handle_ != 0)
            {
                auto err = tsra_sess_close(handle_);
                if (err != TSRA_STATUS_SUCCESS)
                {
                    printf("Warning: Failed to close session handle %u. Error: %d\n", handle_, err);
                }
            }
            handle_ = other.handle_;
            other.handle_ = 0;
        }
        return *this;
    }

    tsra_handle get() const noexcept
    {
        return handle_;
    }

    tsra_handle release() noexcept
    {
        tsra_handle temp = handle_;
        handle_ = 0;
        return temp;
    }

    explicit operator bool() const noexcept
    {
        return handle_ != 0;
    }

  private:
    tsra_handle handle_;
};

#endif // SESSION_HANDLE_HPP