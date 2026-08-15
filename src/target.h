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
//
// It also owns the copies the sweeps run on threads with. A Sleigh caches the
// instruction it last parsed, so one cannot be decoded through by two threads
// at once; the answer here is a private one per worker rather than a lock,
// because a lock around decoding is a lock around all of the work.
#pragma once

#include "abi.h"
#include "image.h"
#include "pcode.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
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

  // This one is a worker's copy, and may only be used to sweep bytes for what
  // is at an address: where the instructions are, what they refer to, where
  // control flow stops.
  //
  // Not for anything the pass pipeline sees. Every Sleigh instance builds its
  // own AddrSpaces, so `RAX` decoded through a copy is a different pointer
  // from `RAX` looked up through the original -- and Storage identity, which
  // is what SSA renames on and what every pass compares against the argument
  // and stack-pointer registers, is that pointer. The two would silently fail
  // to match. Addresses are plain integers and have no such problem, which is
  // why the threaded stages hand back addresses and nothing else.
  bool decode_only = false;
};

class TargetSet {
public:
  // A ceiling on worker slots, so the table of them can be sized once and
  // never move: publishing one must not shift another a thread is reading.
  static constexpr int kMaxWorkers = 64;

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

  // ---- decoding on more than one thread ---------------------------------
  //
  // Loading a spec takes a noticeable fraction of a second and a worker needs
  // its own copy of every one in use, so asking for them is not something that
  // can happen in front of the person waiting for the window. `warm` says how
  // many are wanted and returns; they are built on a thread of their own, one
  // at a time, and `ready_workers` reports how many are usable *now*.
  //
  // So the analysis starts on one thread and widens as the copies arrive,
  // rather than stopping to load anything.
  void warm(int workers);

  // How many worker slots can decode at this moment. Always at least one:
  // slot zero is the caller's own thread, decoding through the original.
  int ready_workers() const { return ready_.load(std::memory_order_acquire); }

  // The Target `slot` is to decode `target` with. Slot zero is `target`
  // itself; the rest are decode-only copies of it. Null if that slot is not
  // ready, which a caller avoids by staying below ready_workers().
  Target *decoder(Target &target, int slot);

  // Sleigh instances built so far, worker copies included -- what a report of
  // where the memory went is made of.
  int instance_count() const;

private:
  struct Instance;
  struct Worker;

  Instance *instance_for(const std::string &spec,
                         const std::vector<std::string> &context);
  std::unique_ptr<Instance> load(const std::string &spec,
                                 const std::vector<std::string> &context);
  void build_workers();

  std::unique_ptr<ImageLoader> loader_;
  std::vector<std::unique_ptr<Instance>> instances_;
  std::deque<Target> targets_;

  // Held while a spec is parsed, by whichever thread is doing it: Sleigh's XML
  // reader keeps the scanner and the content handler in globals, so two
  // documents cannot be read at once however separate the results are.
  mutable std::mutex loading_;

  // Only ever held briefly: what the warming thread and whoever asks it for
  // more agree about, and what keeps `instances_` and `targets_` from being
  // read while they are being added to.
  mutable std::mutex state_;
  std::condition_variable wake_;
  int wanted_ = 1;
  bool stopping_ = false;

  // Filled by the warming thread, read without a lock by the workers.
  //
  // What makes that safe is that the only slot ever written is the one at
  // `ready_`, and nothing reads a slot at or above `ready_`; publishing is the
  // store to `ready_` itself, which is what orders the writes before it
  // against the reads after it.
  std::vector<std::unique_ptr<Worker>> workers_;
  std::atomic<int> ready_{1};
  std::thread warming_;
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
