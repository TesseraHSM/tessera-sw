// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/// SubprocessModule: one test case of this binary run in a fresh process.
///
/// run() forks and execs the test binary with --gtest_filter=<case> and extra
/// environment variables, so the child loads and initializes the module from
/// scratch, as a second application would. The child case starts with
/// SUBPROCESS_ONLY(), which skips it in a normal run, and hands values back
/// with report(); they travel as name=value lines through a file named by
/// TSRA_PKCS11_SUBPROCESS_OUT.

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

extern char **environ;

class SubprocessModule
{
  public:
    struct Result
    {
        int exit_code = -1; /* the child's exit status, 128 + signal if it was killed */
        std::map<std::string, std::string> values; /* what the child reported */
    };

    /// Run `test_case` (Suite.Name) in a child process with `env` (NAME=value
    /// entries) added to this process's environment, and wait for it.
    static Result run(const std::string &test_case, const std::vector<std::string> &env)
    {
        Result result;
        std::string out_tmpl =
            (std::filesystem::temp_directory_path() / "tsra-pkcs11-subprocess.XXXXXX");
        int fd = mkstemp(out_tmpl.data());
        if (fd < 0)
        {
            return result;
        }
        close(fd);

        // Everything the child needs is built before fork(): between fork and
        // exec only async-signal-safe calls are allowed.
        std::vector<std::string> child_env = env;
        child_env.push_back(std::string(kOutVar) + "=" + out_tmpl);
        for (char **e = environ; *e != nullptr; e++)
        {
            std::string entry(*e);
            std::string name = entry.substr(0, entry.find('='));
            // The child runs exactly its one case: no sharding or output file
            // settings of this run.
            bool drop = (name.rfind("GTEST_", 0) == 0);
            for (const std::string &x : child_env)
            {
                drop = drop || (x.compare(0, name.size() + 1, name + "=") == 0);
            }
            if (!drop)
            {
                child_env.push_back(entry);
            }
        }
        std::string exe = std::filesystem::read_symlink("/proc/self/exe");
        std::string filter = "--gtest_filter=" + test_case;
        std::vector<char *> argv = { exe.data(), filter.data(), nullptr };
        std::vector<char *> envp;
        for (std::string &x : child_env)
        {
            envp.push_back(x.data());
        }
        envp.push_back(nullptr);

        pid_t pid = fork();
        if (pid == 0)
        {
            execve(exe.c_str(), argv.data(), envp.data());
            _exit(127);
        }
        int status = 0;
        if ((pid > 0) && (waitpid(pid, &status, 0) == pid))
        {
            result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : (128 + WTERMSIG(status));
        }

        std::ifstream in(out_tmpl);
        for (std::string line; std::getline(in, line);)
        {
            size_t eq = line.find('=');
            if (eq != std::string::npos)
            {
                result.values[line.substr(0, eq)] = line.substr(eq + 1);
            }
        }
        std::remove(out_tmpl.c_str());
        return result;
    }

    /// Whether this process is a child that run() started.
    static bool in_child()
    {
        return std::getenv(kOutVar) != nullptr;
    }

    /// In the child: hand `value` back to the parent under `name`.
    static void report(const std::string &name, const std::string &value)
    {
        const char *path = std::getenv(kOutVar);
        if (path == nullptr)
        {
            return;
        }
        std::ofstream out(path, std::ios::app);
        out << name << '=' << value << '\n';
    }

  private:
    static constexpr const char *kOutVar = "TSRA_PKCS11_SUBPROCESS_OUT";
};

/// The first statement of a case that only runs as SubprocessModule's child.
/// In the child it reports ran=1: a filter that matches no case exits 0 too,
/// so a parent checks that value to know the case ran at all.
#define SUBPROCESS_ONLY()                                                                          \
    do                                                                                             \
    {                                                                                              \
        if (!SubprocessModule::in_child())                                                         \
        {                                                                                          \
            GTEST_SKIP() << "runs only as the second process of another case";                     \
        }                                                                                          \
        SubprocessModule::report("ran", "1");                                                      \
    } while (0)
