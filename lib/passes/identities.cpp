// identities -- operations that compute nothing.
//
//     t158 = v25 + v25 * 0x1
//
// The multiply is an identity: whatever v25 is, v25 * 1 is v25, and the listing
// is carrying a variable that does not exist. Sleigh emits these itself -- a
// scaled index with scale 1, a sign extension written as a multiplication --
// and so does an optimizer that unrolled a loop.
//
// The rewrite is to a copy of the operand that survives, and nothing more:
//
//     t158 = COPY v25
//
// which is the truth about the value, and the form every other pass already
// knows how to reason about. `dce` removes the copy when nothing reads it, and
// what is left either folds into the use that does (`hil`) or keeps the name
// the value had. This pass therefore needs to know nothing about liveness --
// deciding "is this value still wanted" is dce's job and it does it once.
//
// Not to be confused with `idioms`, which is a workflow pass about the machine:
// it recognises a flag dance, a zeroing -- `x ^ x`, `x - x`, `x & 0` -- and says
// what they were in C. Those all *compute* something, a constant. The rules
// below are the ones that compute nothing at all, which is why they rewrite
// instead of annotating: there is nothing left to explain once the operand that
// survives is the whole of the answer.
//
// An identity is a claim about *all* values, so each rule below has to hold at
// the width the operation is being done at -- which is why the mask matters and
// why a rule is written per operation rather than as a table of opcode pairs.
//
// Widening and truncating are a separate question and are not here: a cast
// cancels against another cast, and the cancelling happens in the rewrite table
// the renderer applies, where it can see the pair.
#include "passes/pass.h"

#include <string>
#include <vector>

namespace ddd {
namespace {

class Identities final : public Pass {
public:
  std::string name() const override { return "identities"; }
  std::string description() const override {
    return "rewrite operations that compute nothing to a copy";
  }

  void run(SsaFunction &fn, PassContext &) override {
    rewritten_ = 0;

    fn.for_each_op([&](SsaOp &op) {
      if (op.is_phi || op.out == nullptr) return;

      const SsaOperand *surviving = surviving_operand(op);
      if (surviving == nullptr) return;

      // Copied first: the surviving operand is usually ins[1], and narrowing
      // the list drops it.
      const SsaOperand kept = *surviving;
      op.opc = Op::COPY;
      op.ins.assign(1, kept);
      ++rewritten_;
    });

    if (rewritten_ != 0) fn.rebuild_uses();
  }

  std::vector<std::string> report(const SsaFunction &,
                                  const PassContext &) const override {
    return {"rewrote " + std::to_string(rewritten_) + " identity op(s)"};
  }

private:
  // The operand this operation is a no-op on, or null when it computes
  // something after all.
  static const SsaOperand *surviving_operand(const SsaOp &op) {
    if (op.ins.size() < 2) return nullptr;

    const SsaOperand &left = op.ins[0];
    const SsaOperand &right = op.ins[1];

    switch (op.opc) {
    // The opcodes that commute, so the identity may be on either side: x + 0
    // and 0 + x, x | 0, x ^ 0, and x * 1 -- which is the shape a scaled index
    // with scale 1 lowers to, and the constant is on the left when it does.
    case Op::INT_ADD:
      if (is_zero(right)) return &left;
      if (is_zero(left)) return &right;
      return nullptr;
    case Op::INT_OR:
      if (same_value(left, right)) return &left; // x | x
      if (is_zero(right)) return &left;
      if (is_zero(left)) return &right;
      return nullptr;
    case Op::INT_XOR:
      if (is_zero(right)) return &left;
      if (is_zero(left)) return &right;
      return nullptr;
    case Op::INT_MULT:
      if (is_one(right)) return &left;
      if (is_one(left)) return &right;
      return nullptr;

    // The opcodes that do not: the identity is on the right or there is none.
    // x - 0, and a shift by nothing in either direction, signed or not. A
    // division by one, signed or not -- a division by *zero* is not an
    // identity and is left to say whatever it says.
    case Op::INT_SUB:
    case Op::INT_LEFT:
    case Op::INT_RIGHT:
    case Op::INT_SRIGHT:
      return is_zero(right) ? &left : nullptr;
    case Op::INT_DIV:
    case Op::INT_SDIV:
      return is_one(right) ? &left : nullptr;

    // x & x is x, and x & ~0 is x. The all-ones constant has to be the width
    // of the other operand: `x & 0xffffffff` is an identity at 32 bits and a
    // truncation at 64, and that difference is the whole reason this is not a
    // table of opcode pairs.
    case Op::INT_AND:
      if (same_value(left, right)) return &left;
      if (is_all_ones(right, operand_size(op, 0))) return &left;
      if (is_all_ones(left, operand_size(op, 1))) return &right;
      return nullptr;

    default:
      return nullptr;
    }
  }

  // Both sides are the same value -- `x & x`, `x | x`. Only renamed storage
  // can be compared this way; two constants that happen to be equal are
  // const-prop's business, and it gets there first.
  static bool same_value(const SsaOperand &left, const SsaOperand &right) {
    return left.is_tracked() && right.is_tracked() && left.value == right.value;
  }

  static bool is_zero(const SsaOperand &operand) {
    return operand.is_constant() && operand.constant() == 0;
  }

  static bool is_one(const SsaOperand &operand) {
    return operand.is_constant() && operand.constant() == 1;
  }

  static bool is_all_ones(const SsaOperand &operand, uint32_t width) {
    return operand.is_constant() && operand.constant() == mask_for(width);
  }

  int rewritten_ = 0;
};

DDD_REGISTER_PASS(Identities);

} // namespace
} // namespace ddd
