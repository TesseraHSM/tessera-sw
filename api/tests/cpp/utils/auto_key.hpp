// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <tsra_api.h>

// Generic RAII wrapper for managing an existing HSM key with automatic cleanup
struct auto_key
{
    tsra_handle handle = 0;

    auto_key() = default;

    // Prevent copying
    auto_key(const auto_key &) = delete;
    auto_key &operator=(const auto_key &) = delete;

    // Allow moving
    auto_key(auto_key &&other) noexcept : handle(other.handle)
    {
        other.handle = 0;
    }

    auto_key &operator=(auto_key &&other) noexcept
    {
        if (this != &other)
        {
            if (handle != 0)
            {
                tsra_key_delete(handle);
            }
            handle = other.handle;
            other.handle = 0;
        }
        return *this;
    }

    ~auto_key()
    {
        if (handle != 0)
        {
            tsra_key_delete(handle);
        }
    }

    tsra_handle get() const
    {
        return handle;
    }

    tsra_handle *get_ptr()
    {
        return &handle;
    }

    // Allow implicit conversion to tsra_handle for convenience
    operator tsra_handle() const
    {
        return handle;
    }

    tsra_handle release()
    {
        tsra_handle temp = handle;
        handle = 0;
        return temp;
    }
};