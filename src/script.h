// script.h -- running an external script over a subprocess.
//
// Python is the right language for the things people actually want to plug in
// here -- a vendor's decryption routine, an obfuscation-specific naming rule,
// a one-off unpacker -- and none of them justify embedding CPython. A pipe
// costs one process per invocation and keeps the script's dependencies,
// crashes and licence entirely outside this binary.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ddd {

struct ScriptResult {
  bool ok = false;
  std::vector<uint8_t> output;
  std::string error;
};

// Runs `command` (argv, not a shell string), writes `input` to its stdin, and
// collects stdout. stderr is passed through to this process's stderr so a
// script's own diagnostics stay visible.
ScriptResult run_script(const std::vector<std::string> &command,
                        const std::vector<uint8_t> &input);

// argv for a script: the interpreter is chosen from the file's extension, so
// `.py` runs under python3 and anything executable runs directly.
std::vector<std::string> interpreter_for(const std::string &path);

} // namespace ddd
