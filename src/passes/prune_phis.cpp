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
#include "../reaching.h"

#include <ostream>
#include <set>

namespace ddd {
namespace {

class PrunePhis final : public Pass {
public:
  std::string name() const override { return "prune-phis"; }
  std::string description() const override {
    return "remove phis whose result is unused";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    // A phi holding the value the caller will read has no uses inside the
    // function and is exactly what the function computes. `dce` learned this
    // the same way; without it, deleting the phi makes everything feeding it
    // dead too, and the function empties out.
    const std::set<int> roots = observable_values(fn, ctx);

    const int removed = remove_ops_to_fixpoint(
        fn,
        [&roots](const SsaOp *phi) {
          return phi->out != nullptr && phi->out->uses.empty() &&
                 roots.count(phi->out->id) == 0;
        },
        {&SsaBlock::phis});

    if (ctx.verbose)
      ctx.stream() << "  removed " << removed << " dead phi(s)\n";
  }
};

DDD_REGISTER_PASS(PrunePhis);

} // namespace
} // namespace ddd
