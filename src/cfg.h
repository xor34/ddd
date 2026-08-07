// cfg.h -- basic blocks of p-code, with dense integer ids.
//
// There is exactly one CFG type in this library. Blocks are identified by a
// dense index in [0, size()), so every downstream algorithm (dominance, SSA,
// dataflow) can use plain vectors indexed by block id -- no pointer maps, no
// "remap sparse ids to dense ids" step, no traits class.
#pragma once

#include "pcode.h"

#include <string>
#include <vector>

namespace ghidra {
class Sleigh;
}

namespace ddd {

struct Edge {
  int target = -1;
  // True for the "taken" edge out of a CBRANCH. The matching fall-through
  // edge is false, as is every unconditional edge.
  bool conditional = false;
};

struct BasicBlock {
  int id = -1;
  Address start;        // address of the first instruction in the block
  Address end;          // one past the last instruction
  std::vector<PcodeOp> ops;
  std::vector<Edge> succs;
  std::vector<int> preds;

  bool ends_in_call = false;
  bool ends_in_return = false;
  bool ends_in_branch = false;

  const PcodeOp *terminator() const {
    return ops.empty() ? nullptr : &ops.back();
  }
};

struct Cfg {
  int entry = -1;
  std::vector<BasicBlock> blocks;

  int size() const { return static_cast<int>(blocks.size()); }
  bool empty() const { return blocks.empty(); }

  BasicBlock &operator[](int id) { return blocks[id]; }
  const BasicBlock &operator[](int id) const { return blocks[id]; }

  // Recomputes every block's `preds` from its `succs`. The builder calls
  // this; call it yourself after any structural edit.
  void refresh_preds();
};

// How far build_cfg() is allowed to walk.
struct SweepLimits {
  int max_instructions = 100000;
  // Stop when the sweep passes this address. Leave invalid to only bound by
  // max_instructions.
  Address end;
};

// Linear sweep from `start`, splitting at p-code-op granularity.
//
// Block boundaries are per p-code op, not per instruction: one machine
// instruction can lower to several ops with BRANCH/CBRANCH among them
// (Sleigh's p-code-relative intra-instruction branches, used for x86 REP
// string ops and similar), and those are real block boundaries too.
//
// Returns an empty Cfg if nothing could be disassembled.
Cfg build_cfg(ghidra::Sleigh &translator, const Address &start,
              const SweepLimits &limits);

// Human-readable dump, used by --dump=cfg.
std::string to_string(const Cfg &cfg);

} // namespace ddd
