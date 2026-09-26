// cfg.h -- basic blocks of p-code, with dense integer ids.
//
// There is exactly one CFG type in this library. Blocks are identified by a
// dense index in [0, size()), so every downstream algorithm (dominance, SSA,
// dataflow) can use plain vectors indexed by block id -- no pointer maps, no
// "remap sparse ids to dense ids" step, no traits class.
#pragma once

#include "id.h"
#include "pcode.h"

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ghidra {
class Sleigh;
}

namespace ddd {

// One machine instruction, kept so every p-code op (and every SSA op lifted
// from it) can be traced back to the line of assembly it came from. `addr` is
// an offset in the Cfg's code space, like every address a sweep produces.
struct Instruction {
  uint64_t addr = 0;
  int length = 0;
  std::string text; // "mov x0, #0x5"
};

struct Edge {
  BlockId target;
  // True for the "taken" edge out of a CBRANCH. The matching fall-through
  // edge is false, as is every unconditional edge.
  bool conditional = false;
};

struct BasicBlock {
  BlockId id;
  uint64_t start = 0; // offset, in the Cfg's code space, of the first
                      // instruction in the block
  uint64_t end = 0;   // one past the last, in the same space
  std::vector<PcodeOp> ops;
  std::vector<Edge> succs;
  std::vector<BlockId> preds;

  bool ends_in_call = false;
  bool ends_in_return = false;
  bool ends_in_branch = false;

  // Where this block's branch goes when no block here covers it: a tail call,
  // or a jump into the middle of a neighbour. There is no successor to record
  // -- the destination is not part of this function -- but the address is
  // known, and it is the whole content of the instruction. Without it the
  // branch is a dead end that everything downstream has to describe as one,
  // which is how a tail call ends up printed as `goto -1`.
  //
  // A full Addr, not an offset: a branch names its destination as a varnode
  // whose space is the space it branches *into*, which need not be the one
  // this function was swept in (segmented memory, bank switching, a far
  // jump). Not a location (kNoSpace) when the block does not end in a branch,
  // or when the destination is computed (a jump table) and there is nothing
  // static to say.
  Addr leaves_to;

  const PcodeOp *terminator() const {
    return ops.empty() ? nullptr : &ops.back();
  }
};

struct Cfg {
  // The block control enters, when there is one: an empty Cfg (nothing
  // disassembled, or a hand-built one) has none.
  std::optional<BlockId> entry;
  std::vector<BasicBlock> blocks;

  // Where every varnode in this Cfg lives, and the names/kinds to print it
  // with. Owned by the TargetSet the decode went through, so two Cfgs from
  // the same image agree on space identity and their storages compare equal.
  const Spaces *spaces = nullptr;

  // The one space the sweep ran in. Every address a sweep produces --
  // Instruction::addr, block start/end, PcodeOp::addr, code_begin/end -- is
  // an offset in it, which is why those can stay plain integers. The
  // destinations are the exception: those can name another space, so they
  // carry one (BasicBlock::leaves_to).
  SpaceId code_space = kNoSpace;

  // Every instruction the sweep decoded, by address offset.
  std::map<uint64_t, Instruction> instructions;
  uint64_t code_begin = 0;
  uint64_t code_end = 0;

  int size() const { return static_cast<int>(blocks.size()); }
  bool empty() const { return blocks.empty(); }

  BasicBlock &operator[](BlockId id) { return blocks[id]; }
  const BasicBlock &operator[](BlockId id) const { return blocks[id]; }

  // The instruction an op came from, or null if it was never decoded.
  const Instruction *instruction_at(uint64_t addr) const;

  // Recomputes every block's `preds` from its `succs`. The builder calls
  // this; call it yourself after any structural edit.
  void refresh_preds();
};

// How far build_cfg() is allowed to walk.
struct SweepLimits {
  int max_instructions = 100000;
  // Keep the disassembly text for each instruction. Costs a second decode
  // per instruction; turn it off if nothing is going to display it.
  bool disassemble = true;
  // Stop when the sweep passes this address. Leave unset to only bound by
  // max_instructions.
  std::optional<uint64_t> end;

  // Bytes somebody has said are not code. A sweep that walks into a jump
  // table disassembles it, and the result is a function with the table's
  // contents as instructions in the middle of it -- so "this is not code" has
  // to be able to stop the disassembler, or it is only a note.
  //
  // Returns true for an address the sweep must not decode. Empty by default.
  std::function<bool(uint64_t)> is_data;
};

// Linear sweep from `start`, splitting at p-code-op granularity.
//
// Block boundaries are per p-code op, not per instruction: one machine
// instruction can lower to several ops with BRANCH/CBRANCH among them
// (Sleigh's p-code-relative intra-instruction branches, used for x86 REP
// string ops and similar), and those are real block boundaries too.
//
// Interns every space the decode names into `spaces`, which the returned Cfg
// points at. Returns an empty Cfg if nothing could be disassembled.
Cfg build_cfg(ghidra::Sleigh &translator, uint64_t start, Spaces &spaces,
              const SweepLimits &limits);

// Human-readable dump, used by --dump=cfg.
std::string to_string(const Cfg &cfg);

} // namespace ddd
