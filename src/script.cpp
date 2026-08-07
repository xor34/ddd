#include "script.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <vector>

#include <sys/wait.h>
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

  size_t written = 0;
  while (written < input.size()) {
    ssize_t n =
        write(to_child[1], input.data() + written, input.size() - written);
    if (n <= 0)
      break;
    written += static_cast<size_t>(n);
  }
  close(to_child[1]);

  std::vector<uint8_t> buffer(kChunk);
  while (true) {
    ssize_t n = read(from_child[0], buffer.data(), buffer.size());
    if (n <= 0)
      break;
    result.output.insert(result.output.end(), buffer.begin(),
                         buffer.begin() + n);
  }
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
