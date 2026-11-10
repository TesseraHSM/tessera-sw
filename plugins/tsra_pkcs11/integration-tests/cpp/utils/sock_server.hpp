// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// PrivateSimulator: a ddi_sock_server of its own, for a case that needs a
/// freshly powered-on HSM (e.g. the first login chooses the credential) while
/// the rest of the suite shares the one named by TSRA_DDI_SOCK.
///
/// The server binary is named by TSRA_DDI_SOCK_SERVER. It is started on an
/// ephemeral loopback port and stopped when the object goes out of scope;
/// pass env() to SubprocessModule::run() so the child talks to it.

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
        const char *exe = std::getenv(kServerVar);
        if ((exe == nullptr) || (*exe == '\0'))
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
        return { std::string("TSRA_DDI_SOCK=") + endpoint_ };
    }

    static constexpr const char *kServerVar = "TSRA_DDI_SOCK_SERVER";

  private:
    pid_t pid_ = -1;
    std::string endpoint_;
};
