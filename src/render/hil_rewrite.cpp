#include "render/hil_rewrite.h"

#include "render/hil_expr.h"
#include "ir/pattern.h"

#include <vector>

namespace ddd {
namespace {

// ---- what a rule builds --------------------------------------------------

// One side of a comparison a rule builds, naming where it comes from: a value
// the pattern captured, or a literal zero.
//
// The zero is not a capture. In `!(x == 0)` the zero is part of the idiom --
// the pattern matched it with `imm(0)`, which binds no slot, and the rule has
// to put one back. Saying so explicitly is what keeps the two kinds of operand
// distinguishable when reading a rule.
struct Side {
  int slot = 0;
  bool literal_zero = false;
};

constexpr Side captured(int slot) { return Side{slot, false}; }
constexpr Side literal_zero() { return Side{0, true}; }

// The replacement expression.
struct RewriteAs {
  enum class Kind {
    Value,   // a captured value, as it stands
    Zero,    // a constant zero as wide as the op's own result
    Compare, // two sides compared
  };

  Kind kind = Kind::Value;
  int slot = 0;             // Value
  const char *op = nullptr; // Compare
  int precedence = 0;
  Side left, right;

  static RewriteAs value(int slot) { return {Kind::Value, slot}; }
  static RewriteAs zero() { return {Kind::Zero, 0}; }
  static RewriteAs compare(const char *op, int precedence, Side left, Side right) {
    return {Kind::Compare, 0, op, precedence, left, right};
  }
};

ExprRef build_side(const Side &side, const Match &m, int depth,
                   RewriteSink &sink) {
  if (side.literal_zero) return sink.constant(0, 0);
  return sink.value_of(*m.value(side.slot), depth + 1);
}

ExprRef build(const RewriteAs &as, const Match &m, const SsaOp &op, int depth,
              RewriteSink &sink) {
  switch (as.kind) {
  case RewriteAs::Kind::Value:
    return sink.value_of(*m.value(as.slot), depth + 1);

  case RewriteAs::Kind::Zero:
    // As wide as whatever the operation produced, so `xor x0, x0` zeroes all
    // 64 bits of x0 and not a byte of it.
    return sink.constant(0, op.out != nullptr ? op.out->storage.size : 0);

  case RewriteAs::Kind::Compare:
    return sink.binary(as.op, as.precedence, build_side(as.left, m, depth, sink),
                       build_side(as.right, m, depth, sink));
  }
  return nullptr;
}

// ---- the rules -----------------------------------------------------------

struct Rule {
  Pattern pattern;
  RewriteAs as;
};

// First match wins, so an ordering exists here: put the specific before the
// general. Nothing in the table depends on it today, and a rule added later
// that does will need the narrower one above it.
const std::vector<Rule> &rules() {
  using namespace ddd::pat;

  static const std::vector<Rule> table = {
      // The flag dance behind a signed compare: NG != OV over a subtraction.
      // Copy-skipping is what makes this expressible at all. Either operand
      // order: which flag lands on the left is an artefact of the lowering,
      // not of the comparison.
      {comm(Op::INT_NOTEQUAL, op(Op::INT_SLESS, {val(0), imm(0)}),
            op(Op::INT_SBORROW, {val(1), val(2)})),
       RewriteAs::compare("<s", kRelational, captured(1), captured(2))},

      // A comparison done by subtracting and testing the result.
      {op(Op::INT_EQUAL, {op(Op::INT_SUB, {val(0), val(1)}), imm(0)}),
       RewriteAs::compare("==", kEquality, captured(0), captured(1))},
      {op(Op::INT_NOTEQUAL, {op(Op::INT_SUB, {val(0), val(1)}), imm(0)}),
       RewriteAs::compare("!=", kEquality, captured(0), captured(1))},

      // !(x == 0) is x != 0.
      {op(Op::BOOL_NEGATE, {op(Op::INT_EQUAL, {val(0), imm(0)})}),
       RewriteAs::compare("!=", kEquality, captured(0), literal_zero())},

      // Self-cancelling arithmetic: the idiomatic register zeroing.
      {op(Op::INT_XOR, {val(0), val(0)}), RewriteAs::zero()},
      {op(Op::INT_SUB, {val(0), val(0)}), RewriteAs::zero()},
      {comm(Op::INT_AND, val(0), imm(0)), RewriteAs::zero()},
      {comm(Op::INT_MULT, val(0), imm(0)), RewriteAs::zero()},

      // Operations that are their own operand.
      {op(Op::INT_AND, {val(0), val(0)}), RewriteAs::value(0)},
      {op(Op::INT_OR, {val(0), val(0)}), RewriteAs::value(0)},
      {comm(Op::INT_ADD, val(0), imm(0)), RewriteAs::value(0)},
  };
  return table;
}

} // namespace

ExprRef rewrite_op(const SsaOp &op, int depth, RewriteSink &sink) {
  for (const Rule &rule : rules()) {
    Match m;
    if (!rule.pattern.match(op, m)) continue;
    return build(rule.as, m, op, depth, sink);
  }
  return nullptr;
}

} // namespace ddd
