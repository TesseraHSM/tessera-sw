// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// PrivateSimulator: a ddi_sock_server of its own, for a case that needs a
/// freshly powered-on HSM (e.g. the first login chooses the credential) while
/// the rest of the suite shares the one named by TSRA_DDI_ARGS (sock=).
///
/// The server binary is named by server_bin= in TSRA_TEST_ARGS. It is started
/// on an ephemeral loopback port and stopped when the object goes out of
/// scope; pass env() to SubprocessModule::run() so the child talks to it.

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

class PrivateSimulator
{
  public:
    PrivateSimulator()
    {
        std::string exe = server_bin();
        if (exe.empty())
        {
            return;
        }
        int fds[2];
        if (pipe(fds) != 0)
        {
            return;
        }
        std::string path(exe);
        std::string address("tcp://127.0.0.1:0");
        char *argv[] = { path.data(), address.data(), nullptr };
        pid_ = fork();
        if (pid_ == 0)
        {
            dup2(fds[1], STDOUT_FILENO);
            close(fds[0]);
            close(fds[1]);
            execv(path.c_str(), argv);
            _exit(127);
        }
        close(fds[1]);
        if (pid_ < 0)
        {
            close(fds[0]);
            return;
        }
        // The server announces "... listening on tcp://HOST:PORT; ..." once
        // its partition is set up and it accepts clients.
        std::string line;
        char c = 0;
        while ((read(fds[0], &c, 1) == 1) && (c != '\n'))
        {
            line.push_back(c);
        }
        close(fds[0]);
        size_t start = line.find("tcp://");
        size_t end = line.find(';', start);
        if ((start != std::string::npos) && (end != std::string::npos))
        {
            endpoint_ = line.substr(start, end - start);
        }
    }

    ~PrivateSimulator()
    {
        if (pid_ > 0)
        {
            kill(pid_, SIGTERM);
            waitpid(pid_, nullptr, 0);
        }
    }

    PrivateSimulator(const PrivateSimulator &) = delete;
    PrivateSimulator &operator=(const PrivateSimulator &) = delete;

    /// Whether the server is up.
    bool ok() const
    {
        return !endpoint_.empty();
    }

    /// The environment entries that point a child process at this server.
    std::vector<std::string> env() const
    {
        return { "TSRA_DDI_ARGS=transport=sock;sock=" + endpoint_ };
    }

    /// The server_bin= value of TSRA_TEST_ARGS, or "" if unset.
    static std::string server_bin()
    {
        const char *args = std::getenv(kArgsVar);
        std::string rest = (args != nullptr) ? args : "";
        while (!rest.empty())
        {
            size_t semi = rest.find(';');
            std::string pair = rest.substr(0, semi);
            rest = (semi == std::string::npos) ? "" : rest.substr(semi + 1);
            size_t eq = pair.find('=');
            if ((eq != std::string::npos) && (trim(pair.substr(0, eq)) == "server_bin"))
            {
                return trim(pair.substr(eq + 1));
            }
        }
        return "";
    }

    static constexpr const char *kArgsVar = "TSRA_TEST_ARGS";

  private:
    static std::string trim(const std::string &s)
    {
        size_t b = s.find_first_not_of(" \t");
        size_t e = s.find_last_not_of(" \t");
        return (b == std::string::npos) ? "" : s.substr(b, e - b + 1);
    }

    pid_t pid_ = -1;
    std::string endpoint_;
};
