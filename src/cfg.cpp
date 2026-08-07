// cfg.cpp
//
// Linear sweep + leader-set block splitting, at p-code-op granularity:
//   1. Sweep [start, limit), capturing every instruction's p-code into one
//      flat array. Remember which instruction each op came from (needed for
//      p-code-relative branches, whose offset is relative to the op's index
//      *within its own instruction*) and which op each address starts at
//      (needed for absolute branches).
//   2. Mark leaders: op 0; the op after any terminator; the target of every
//      statically resolvable BRANCH/CBRANCH.
//   3. One block per [leader, next leader) run.
//   4. Successor edges from each block's last op.
//
// Not resolved, on purpose: indirect branches (BRANCHIND -- needs jump table
// recovery), indirect call targets, CALLOTHER semantics (userop-table
// specific, treated as a plain op), delay slots, and anything whose target
// falls outside the swept range (no recursive descent).
#include "cfg.h"

#include "error.hh"
#include "sleigh.hh"

#include <algorithm>
#include <set>
#include <sstream>
#include <unordered_map>

namespace ddd {
namespace {

struct Instruction {
  Address addr;
  ghidra::int4 length = 1;
  size_t first_op = 0;
  size_t op_count = 0;
};

// Everything the sweep learned, in one place, so the leader/block/edge steps
// below stay readable.
struct Sweep {
  std::vector<PcodeOp> ops;
  std::vector<Instruction> instructions;
  std::vector<size_t> op_to_instruction;
  // Instruction start offset -> index of its first op. An instruction that
  // lowered to no p-code at all (x86 NOP, for instance) maps to the next
  // instruction's first op, which is exactly where control resumes.
  std::unordered_map<uint64_t, size_t> offset_to_op;
};

Sweep sweep_instructions(ghidra::Sleigh &translator, const Address &start,
                         const SweepLimits &limits) {
  Sweep sweep;
  Address addr = start;

  for (int count = 0; count < limits.max_instructions; ++count) {
    if (!limits.end.isInvalid() && !(addr < limits.end)) break;

    PcodeCapture capture;
    ghidra::int4 length = 1;
    try {
      length = translator.oneInstruction(capture, addr);
    } catch (ghidra::LowlevelError &) {
      // Undecodable byte: skip it, contribute no p-code.
      length = 1;
      capture.ops.clear();
    }
    if (length <= 0) length = 1;

    Instruction instr;
    instr.addr = addr;
    instr.length = length;
    instr.first_op = sweep.ops.size();
    instr.op_count = capture.ops.size();

    sweep.offset_to_op[addr.getOffset()] = instr.first_op;
    sweep.instructions.push_back(instr);

    for (PcodeOp &op : capture.ops) sweep.ops.push_back(std::move(op));

    addr = addr + length;
  }

  sweep.op_to_instruction.assign(sweep.ops.size(), 0);
  for (size_t i = 0; i < sweep.instructions.size(); ++i)
    for (size_t k = 0; k < sweep.instructions[i].op_count; ++k)
      sweep.op_to_instruction[sweep.instructions[i].first_op + k] = i;

  return sweep;
}

// Resolves a branch destination varnode to an index into sweep.ops, or -1 if
// it can't be resolved statically (dynamic target, or outside the sweep).
long long resolve_target(const Sweep &sweep, size_t op_index,
                         const VarnodeData &dest) {
  if (is_constant(dest)) {
    // p-code-relative: signed offset from this op's index within its own
    // instruction's op list.
    const Instruction &instr = sweep.instructions[sweep.op_to_instruction[op_index]];
    long long local = static_cast<long long>(op_index - instr.first_op);
    long long target = local + static_cast<long long>(static_cast<int64_t>(dest.offset));
    if (target < 0 || static_cast<size_t>(target) >= instr.op_count) return -1;
    return static_cast<long long>(instr.first_op + static_cast<size_t>(target));
  }

  auto it = sweep.offset_to_op.find(static_cast<uint64_t>(dest.offset));
  if (it == sweep.offset_to_op.end()) return -1;
  if (it->second >= sweep.ops.size()) return -1; // fell off the end of the sweep
  return static_cast<long long>(it->second);
}

std::vector<size_t> find_leaders(const Sweep &sweep) {
  std::set<size_t> leaders{0};

  for (size_t i = 0; i < sweep.ops.size(); ++i) {
    const PcodeOp &op = sweep.ops[i];
    if (!is_terminator(op.opc)) continue;

    if (i + 1 < sweep.ops.size()) leaders.insert(i + 1);

    if ((op.opc == ghidra::CPUI_BRANCH || op.opc == ghidra::CPUI_CBRANCH) &&
        !op.inputs.empty()) {
      long long target = resolve_target(sweep, i, op.inputs[0]);
      if (target >= 0) leaders.insert(static_cast<size_t>(target));
    }
  }

  return std::vector<size_t>(leaders.begin(), leaders.end());
}

} // namespace

void Cfg::refresh_preds() {
  for (BasicBlock &b : blocks) b.preds.clear();
  for (const BasicBlock &b : blocks)
    for (const Edge &e : b.succs)
      blocks[e.target].preds.push_back(b.id);
}

Cfg build_cfg(ghidra::Sleigh &translator, const Address &start,
              const SweepLimits &limits) {
  Cfg cfg;

  Sweep sweep = sweep_instructions(translator, start, limits);
  if (sweep.ops.empty()) return cfg;

  std::vector<size_t> leaders = find_leaders(sweep);

  // op index -> block id
  auto block_of_op = [&](size_t op_index) {
    auto it = std::upper_bound(leaders.begin(), leaders.end(), op_index);
    return static_cast<int>(std::distance(leaders.begin(), it)) - 1;
  };

  struct Range { size_t begin, end; };
  std::vector<Range> ranges;

  for (size_t i = 0; i < leaders.size(); ++i) {
    size_t begin = leaders[i];
    size_t end = (i + 1 < leaders.size()) ? leaders[i + 1] : sweep.ops.size();
    if (begin >= end) continue;

    BasicBlock block;
    block.id = cfg.size();
    block.start = sweep.ops[begin].addr;
    const Instruction &last = sweep.instructions[sweep.op_to_instruction[end - 1]];
    block.end = last.addr + last.length;
    block.ops.assign(sweep.ops.begin() + begin, sweep.ops.begin() + end);

    ranges.push_back({begin, end});
    cfg.blocks.push_back(std::move(block));
  }
  if (cfg.empty()) return cfg;
  cfg.entry = 0;

  for (size_t i = 0; i < ranges.size(); ++i) {
    BasicBlock &block = cfg.blocks[i];
    const Range &range = ranges[i];
    const PcodeOp &last = sweep.ops[range.end - 1];

    auto fallthrough = [&]() -> int {
      if (range.end >= sweep.ops.size()) return -1;
      return block_of_op(range.end);
    };
    auto branch_target = [&]() -> int {
      if (last.inputs.empty()) return -1;
      long long target = resolve_target(sweep, range.end - 1, last.inputs[0]);
      return target < 0 ? -1 : block_of_op(static_cast<size_t>(target));
    };

    switch (last.opc) {
    case ghidra::CPUI_RETURN:
      block.ends_in_return = true;
      break;

    case ghidra::CPUI_BRANCH:
      block.ends_in_branch = true;
      if (int t = branch_target(); t >= 0) block.succs.push_back({t, false});
      break;

    case ghidra::CPUI_CBRANCH:
      block.ends_in_branch = true;
      if (int t = branch_target(); t >= 0) block.succs.push_back({t, true});
      if (int f = fallthrough(); f >= 0) block.succs.push_back({f, false});
      break;

    case ghidra::CPUI_BRANCHIND:
      block.ends_in_branch = true;
      // Jump table: destination is a runtime value. No static successors.
      break;

    case ghidra::CPUI_CALL:
    case ghidra::CPUI_CALLIND:
      block.ends_in_call = true;
      // Assume the callee returns; there is no interprocedural noreturn
      // analysis here.
      if (int f = fallthrough(); f >= 0) block.succs.push_back({f, false});
      break;

    default:
      // The block ended here because something else branches to the next op,
      // not because `last` is a control-flow op: plain fall-through.
      if (int f = fallthrough(); f >= 0) block.succs.push_back({f, false});
      break;
    }
  }

  cfg.refresh_preds();
  return cfg;
}

std::string to_string(const Cfg &cfg) {
  std::ostringstream os;

  for (const BasicBlock &block : cfg.blocks) {
    os << "block " << block.id << "  [0x" << std::hex << block.start.getOffset()
       << ", 0x" << block.end.getOffset() << ")" << std::dec;
    if (block.id == cfg.entry) os << " entry";
    if (block.ends_in_call) os << " call";
    if (block.ends_in_return) os << " return";
    if (block.ends_in_branch) os << " branch";
    os << "\n";

    for (const PcodeOp &op : block.ops) {
      os << "    ";
      if (op.has_output) os << to_string(op.output) << " = ";
      os << ghidra::get_opname(op.opc);
      for (const VarnodeData &in : op.inputs) os << ' ' << to_string(in);
      os << "\n";
    }

    os << "  -> ";
    if (block.succs.empty()) {
      os << "(none)";
    } else {
      for (size_t i = 0; i < block.succs.size(); ++i) {
        if (i) os << ", ";
        os << block.succs[i].target;
        if (block.succs[i].conditional) os << " (taken)";
      }
    }
    os << "\n";
  }

  return os.str();
}

} // namespace ddd
