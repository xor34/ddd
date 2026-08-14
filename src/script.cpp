#include "script.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <vector>

#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>

namespace ddd {
namespace {

constexpr size_t kChunk = 65536;

} // namespace

std::vector<std::string> interpreter_for(const std::string &path) {
  if (std::filesystem::path(path).extension() == ".py")
    return {"python3", path};
  return {path};
}

ScriptResult run_script(const std::vector<std::string> &command,
                        const std::vector<uint8_t> &input) {
  ScriptResult result;
  if (command.empty()) {
    result.error = "empty command";
    return result;
  }

  int to_child[2];
  int from_child[2];
  if (pipe(to_child) != 0) {
    result.error = std::strerror(errno);
    return result;
  }
  if (pipe(from_child) != 0) {
    result.error = std::strerror(errno);
    close(to_child[0]);
    close(to_child[1]);
    return result;
  }

  pid_t pid = fork();
  if (pid < 0) {
    result.error = std::strerror(errno);
    return result;
  }

  if (pid == 0) {
    dup2(to_child[0], STDIN_FILENO);
    dup2(from_child[1], STDOUT_FILENO);
    close(to_child[0]);
    close(to_child[1]);
    close(from_child[0]);
    close(from_child[1]);

    std::vector<char *> argv;
    argv.reserve(command.size() + 1);
    for (const std::string &arg : command)
      argv.push_back(const_cast<char *>(arg.c_str()));
    argv.push_back(nullptr);

    execvp(argv[0], argv.data());
    _exit(127); // exec failed; the parent sees it as a non-zero status
  }

  close(to_child[0]);
  close(from_child[1]);

  // The child can block writing before we finish writing to it, so ignore
  // SIGPIPE and read whatever arrives after a short write rather than dying.
  struct sigaction ignore{};
  struct sigaction previous{};
  ignore.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &ignore, &previous);

  // Interleave writing stdin with draining stdout: a script that echoes as it
  // reads can fill the stdout pipe buffer before we finish writing, and with
  // both ends unbuffered that is a deadlock (we block writing while it blocks
  // writing to us) unless something keeps reading in the meantime.
  size_t written = 0;
  bool stdin_open = true;
  bool stdout_open = true;
  std::vector<uint8_t> buffer(kChunk);

  while (stdin_open || stdout_open) {
    struct pollfd fds[2];
    int nfds = 0;
    int stdin_slot = -1, stdout_slot = -1;

    if (stdin_open) {
      stdin_slot = nfds;
      fds[nfds].fd = to_child[1];
      fds[nfds].events = POLLOUT;
      fds[nfds].revents = 0;
      ++nfds;
    }
    if (stdout_open) {
      stdout_slot = nfds;
      fds[nfds].fd = from_child[0];
      fds[nfds].events = POLLIN;
      fds[nfds].revents = 0;
      ++nfds;
    }

    if (poll(fds, static_cast<nfds_t>(nfds), -1) < 0) {
      if (errno == EINTR)
        continue;
      break;
    }

    if (stdout_slot >= 0 &&
        (fds[stdout_slot].revents & (POLLIN | POLLHUP | POLLERR))) {
      ssize_t n = read(from_child[0], buffer.data(), buffer.size());
      if (n > 0) {
        result.output.insert(result.output.end(), buffer.begin(),
                             buffer.begin() + n);
      } else {
        close(from_child[0]);
        stdout_open = false;
      }
    }

    if (stdin_slot >= 0 && (fds[stdin_slot].revents & (POLLOUT | POLLERR))) {
      if (written < input.size()) {
        ssize_t n = write(to_child[1], input.data() + written,
                          input.size() - written);
        if (n > 0) {
          written += static_cast<size_t>(n);
        } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
          close(to_child[1]);
          stdin_open = false;
        }
      }
      if (stdin_open && written >= input.size()) {
        close(to_child[1]);
        stdin_open = false;
      }
    }
  }

  if (stdin_open)
    close(to_child[1]);
  if (stdout_open)
    close(from_child[0]);

  int status = 0;
  waitpid(pid, &status, 0);
  sigaction(SIGPIPE, &previous, nullptr);

  if (!WIFEXITED(status)) {
    result.error = "script did not exit normally";
    return result;
  }
  if (WEXITSTATUS(status) != 0) {
    result.error =
        "script exited with status " + std::to_string(WEXITSTATUS(status));
    return result;
  }

  result.ok = true;
  return result;
}

} // namespace ddd
