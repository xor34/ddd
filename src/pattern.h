// pattern.h -- a small matcher over the SSA graph, for recognising idioms.
//
//   using namespace ddd::pat;
//   Pattern zeroing = op(CPUI_INT_XOR, val(0), val(0));  // same value twice
//
//   Match m;
//   if (zeroing.match(some_op, m)) ...  // m.values[0] is what got zeroed
//
// Slots are how a pattern says "the same thing twice": val(0) appearing twice
// only matches if both operands are the identical SSA value, and after a match
// the slot holds it. cst(n) does the same for constants.
//
// Descending through an operand follows COPY chains, because Sleigh's lowering
// is full of them -- an AArch64 compare reaches its flags through four COPYs,
// and no useful pattern should have to spell those out.
//
// What this deliberately is not: no backtracking beyond commutative operand
// swapping, no matching across blocks, no rewriting. It recognises shapes; the
// pass decides what to say about them.
#pragma once

#include "ssa.h"

#include <cstdint>
#include <vector>

namespace ddd {

struct Match {
  static constexpr int kSlots = 8;

  SsaValue *values[kSlots] = {};
  uint64_t constants[kSlots] = {};
  bool bound_constant[kSlots] = {};

  void clear();
};

class Pattern {
public:
  enum class Kind { Any, Value, Constant, ConstantSlot, Op };

  Pattern() = default;

  bool match(const SsaOp &op, Match &m) const;
  bool match(const SsaOperand &operand, Match &m) const;

private:
  friend Pattern make_pattern(Kind, OpCode, uint64_t, int, std::vector<Pattern>, bool);

  bool match_operands(const SsaOp &op, Match &m) const;

  Kind kind_ = Kind::Any;
  OpCode opc_ = ghidra::CPUI_COPY;
  uint64_t constant_ = 0;
  int slot_ = -1;
  bool commutative_ = false;
  std::vector<Pattern> ins_;
};

namespace pat {

Pattern any();                                    // anything at all
Pattern val(int slot);                            // any SSA value, remembered in `slot`
Pattern imm(uint64_t value);                      // exactly this constant
Pattern cst(int slot);                            // any constant, remembered in `slot`
Pattern op(OpCode opc, std::vector<Pattern> ins); // an op with these operands

// Same as op(), but also matches with the two operands swapped.
Pattern comm(OpCode opc, Pattern left, Pattern right);

} // namespace pat
} // namespace ddd
