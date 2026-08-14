// simplify -- remove phis that are not really choices.
//
// Cytron's placement puts a phi wherever a storage is defined on more than one
// path, whether or not the paths disagree. In a function with any control flow
// that produces a great many of these:
//
//     t17 = phi(t19, t5, t19, t19, t19, t19, t19, t19, t19)
//     RSP_122 = phi(RSP_79, RSP_121)
//     RSP_123 = phi(RSP_79, RSP_122)
//
// A phi whose operands are all the same value is not a choice -- it *is* that
// value, and every use of it can read the original directly. Removing one
// often makes the next one trivial too (the chain above collapses end to end),
// so this runs to a fixed point.
//
// The self-reference rule matters as much: `x2 = phi(x1, x2)` is the shape a
// loop-carried value takes when the loop body never changes it, and ignoring
// the operand that refers back to the phi itself makes it trivial.
#include "../pass.h"

#include <ostream>

namespace ddd {
namespace {

class Simplify final : public Pass {
public:
  std::string name() const override { return "simplify"; }
  std::string description() const override {
    return "remove phis whose operands all agree";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    const int removed = remove_ops_to_fixpoint(
        fn,
        [&](SsaOp *phi) {
          SsaValue *replacement = trivial_result(*phi);
          if (replacement == nullptr) return false;

          replace_uses(fn, *phi->out, *replacement);
          return true;
        },
        {&SsaBlock::phis});

    if (ctx.verbose) ctx.stream() << "  removed " << removed << " trivial phi(s)\n";
  }

private:
  // The single value a phi always yields, or null if it is a real choice.
  static SsaValue *trivial_result(const SsaOp &phi) {
    if (phi.out == nullptr || phi.ins.empty()) return nullptr;

    SsaValue *only = nullptr;
    for (const SsaOperand &in : phi.ins) {
      // An untracked operand is an unknown, so the phi is not trivial.
      if (!in.is_tracked()) return nullptr;
      // A reference back to the phi's own result says nothing about what it
      // holds; skipping it is what collapses loop-carried copies.
      if (in.value == phi.out) continue;

      if (only == nullptr) only = in.value;
      else if (only != in.value) return nullptr;
    }

    return only;
  }

  static void replace_uses(SsaFunction &fn, const SsaValue &from, SsaValue &to) {
    fn.for_each_op([&](SsaOp &op) {
      for (SsaOperand &in : op.ins)
        if (in.value == &from) in.value = &to;
    });
  }
};

DDD_REGISTER_PASS(Simplify);

} // namespace
} // namespace ddd
