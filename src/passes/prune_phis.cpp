// prune-phis -- drop phis nobody reads.
//
// Cytron's placement is based on def sites alone, so a function with many
// registers (x86 flags, say) ends up with a lot of phis that no later op
// ever uses. Removing them repeatedly, since dropping one phi can orphan
// another, gets close to pruned SSA for free.
//
// Limitation: a phi in a loop that only feeds itself keeps a use of its own
// result and survives. Catching those needs an SCC-based sweep, or real
// liveness-based (pruned) placement in build_ssa.
#include "../pass.h"

#include <algorithm>
#include <ostream>

namespace ddd {
namespace {

class PrunePhis final : public Pass {
public:
  std::string name() const override { return "prune-phis"; }
  std::string description() const override {
    return "remove phis whose result is unused";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    int removed = 0;

    for (bool changed = true; changed;) {
      changed = false;

      for (SsaBlock &block : fn.blocks()) {
        auto dead = std::remove_if(
            block.phis.begin(), block.phis.end(), [](const SsaOp *phi) {
              return phi->out != nullptr && phi->out->uses.empty();
            });
        if (dead == block.phis.end())
          continue;

        removed += static_cast<int>(std::distance(dead, block.phis.end()));
        block.phis.erase(dead, block.phis.end());
        changed = true;
      }

      if (changed)
        fn.rebuild_uses();
    }

    if (ctx.verbose)
      ctx.stream() << "  removed " << removed << " dead phi(s)\n";
  }
};

DDD_REGISTER_PASS(PrunePhis);

} // namespace
} // namespace ddd
