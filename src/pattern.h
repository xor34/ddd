// pattern.h -- a small matcher over the SSA graph, for recognising idioms.
//
//   using namespace ddd::pat;
//   Pattern zeroing = op(CPUI_INT_XOR, val(0), val(0));  // same value twice
//
//   Match m;
//   if (zeroing.match(some_op, m)) ...  // m.value(0) is what got zeroed
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
// caller decides what to say about them.
#pragma once

#include "ssa.h"

#include <cstdint>
#include <initializer_list>
#include <vector>

namespace ddd {

// What a successful match captured. Slots are small integers chosen by the
// pattern; there are deliberately few.
struct Match {
  static constexpr int kSlots = 8;

  SsaValue *values[kSlots] = {};
  uint64_t constants[kSlots] = {};
  bool bound[kSlots] = {};

  SsaValue *value(int slot) const { return values[slot]; }
  uint64_t constant(int slot) const { return constants[slot]; }
};

// A plain tree. The fields are public because a Pattern is data, not an
// abstraction with an invariant to protect -- the pat:: helpers below are
// simply the readable way to write one.
struct Pattern {
  enum class Kind {
    Value,    // any SSA value, captured in `slot`
    Constant, // this exact constant
    AnyConst, // any constant, captured in `slot`
    Op,       // `opc` applied to `ins`
  };

  Kind kind = Kind::Value;
  OpCode opc = ghidra::CPUI_COPY;
  uint64_t constant = 0;
  int slot = 0;
  bool commutative = false;
  std::vector<Pattern> ins;

  // Both return false without disturbing `m` when they do not match.
  bool match(const SsaOp &op, Match &m) const;
  bool match(const SsaOperand &operand, Match &m) const;
};

namespace pat {

inline Pattern val(int slot) { return {Pattern::Kind::Value, {}, 0, slot, false, {}}; }
inline Pattern imm(uint64_t value) { return {Pattern::Kind::Constant, {}, value, 0, false, {}}; }
inline Pattern cst(int slot) { return {Pattern::Kind::AnyConst, {}, 0, slot, false, {}}; }

inline Pattern op(OpCode opc, std::initializer_list<Pattern> ins) {
  return {Pattern::Kind::Op, opc, 0, 0, false, ins};
}

// Same as op(), but also matches with the two operands swapped.
inline Pattern comm(OpCode opc, Pattern left, Pattern right) {
  return {Pattern::Kind::Op, opc, 0, 0, true, {std::move(left), std::move(right)}};
}

} // namespace pat
} // namespace ddd
