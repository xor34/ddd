// target.h -- the instruction set and calling convention in force at a
// particular place in the image.
//
// Neither is a property of the file. A BIOS runs the same instruction set in
// real and long mode with different context and different conventions; a
// firmware image can carry a blob for an entirely different architecture. So
// a Target is per-region, and the analysis of one function carries the Target
// that region resolved to.
//
// TargetSet owns the Sleigh instances. Two regions that agree on spec *and*
// context share one; differing context gets its own, because a Sleigh holds a
// pointer to the context it decodes against.
#pragma once

#include "abi.h"
#include "image.h"
#include "pcode.h"

#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {
class Sleigh;
class ContextInternal;
} // namespace ghidra

namespace ddd {

struct Target {
  std::string name; // display name, e.g. "AARCH64" or "x86:real"
  std::string spec; // path to the .sla
  std::vector<std::string> context; // NAME=VALUE, as passed to Sleigh
  ghidra::Sleigh *translator = nullptr;
  const CallingConvention *abi = nullptr;
  Storage stack_pointer; // zeroed if unknown
};

class TargetSet {
public:
  explicit TargetSet(const Image &image);
  ~TargetSet();

  // Loads `spec` if needed and returns a Target for it. `abi` and
  // `stack_pointer` may be empty, in which case they are guessed from the
  // spec. Returns null (and explains on stderr) if the spec will not load.
  Target *acquire(const std::string &spec, const std::string &abi = "",
                  const std::string &stack_pointer = "",
                  const std::vector<std::string> &context = {},
                  const std::string &name = "");

  const std::deque<Target> &targets() const { return targets_; }

private:
  struct Instance;

  Instance *instance_for(const std::string &spec,
                         const std::vector<std::string> &context);

  const Image &image_;
  std::unique_ptr<ImageLoader> loader_;
  std::vector<std::unique_ptr<Instance>> instances_;
  std::deque<Target> targets_;
};

enum class RegionKind { Code, Data, Unknown };

// A stretch of the image, and what it is.
struct Region {
  uint64_t begin = 0;
  uint64_t end = 0;
  std::string name;
  RegionKind kind = RegionKind::Unknown;
  Target *target = nullptr; // null for data, or code whose ISA is unknown
};

// Parses one region of the --region flag:
//
//   BEGIN:END:SPEC[:ABI[:SP[:CTX]]]
//
// CTX is NAME=VALUE, joined with '+' for more than one -- that is what makes
// a mode switch expressible, since real mode and long mode are the same spec
// under different context. ('+' rather than ',' because --region itself is
// comma-separated, and rather than ';' because that would need shell quoting.)
//
// Addresses are absolute and accept 0x prefixes. Returns false and explains on
// stderr if it does not parse or the spec will not load.
bool parse_region(const std::string &text, TargetSet &targets,
                  const std::string &spec_dir, Region &out);

} // namespace ddd
