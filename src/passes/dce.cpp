// dce -- delete computations nobody reads.
//
// Sleigh models an instruction completely, which means every flag it writes
// whether or not the program looks at them. One x86 `add` lowers to eleven
// p-code ops, eight of which exist only to maintain CF/OF/SF/ZF/PF -- and the
// parity flag alone costs an AND, a POPCOUNT, another AND and a compare. On a
// real function that is most of the listing.
//
// SSA makes the removal decision local: a value with no uses is read nowhere,
// full stop, because SSA has already resolved every "which definition does
// this read see" question. So this is a worklist, not a dataflow analysis.
//
// The one thing SSA cannot tell you is what the *caller* still looks at. A
// function's last write to a preserved register has no uses inside the
// function and is exactly what the function is for, so the calling convention
// supplies those as roots. Without them this pass would delete the result.
#include "../pass.h"
#include "../reaching.h"

#include "opcodes.hh"

#include <ostream>
#include <set>

namespace ddd {
namespace {

class Dce final : public Pass {
public:
  std::string name() const override { return "dce"; }
  std::string description() const override {
    return "delete computations whose results are never read";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    const std::set<int> roots = observable_values(fn, ctx);
    if (roots.empty() && ctx.verbose)
      ctx.stream() << "  no calling convention: nothing is treated as live at exit\n";

    int removed = 0;

    // Removing one op can orphan the ops feeding it, so repeat to a fixed
    // point. The chains are short and each round is linear.
    for (bool changed = true; changed;) {
      changed = false;

      for (SsaBlock &block : fn.blocks()) {
        removed += sweep(block.phis, roots, changed);
        removed += sweep(block.ops, roots, changed);
      }

      if (changed) fn.rebuild_uses();
    }

    if (ctx.verbose) ctx.stream() << "  removed " << removed << " dead op(s)\n";
  }

private:
  static int sweep(std::vector<SsaOp *> &ops, const std::set<int> &roots, bool &changed) {
    auto dead = std::remove_if(ops.begin(), ops.end(), [&](const SsaOp *op) {
      return is_dead(*op, roots);
    });
    if (dead == ops.end()) return 0;

    int removed = static_cast<int>(std::distance(dead, ops.end()));
    ops.erase(dead, ops.end());
    changed = true;
    return removed;
  }

  static bool is_dead(const SsaOp &op, const std::set<int> &roots) {
    if (has_side_effects(op.opc)) return false;

    // A write to storage we chose not to rename (memory) is not tracked by
    // def-use chains, so there is no evidence it is unread.
    if (op.has_raw_output) return false;

    // Produces nothing and has no side effect: already nothing to keep, but
    // leave it be rather than guess at an opcode this does not model.
    if (op.out == nullptr) return false;

    if (!op.out->uses.empty()) return false;
    return roots.count(op.out->id) == 0;
  }
};

DDD_REGISTER_PASS(Dce);

} // namespace
} // namespace ddd
