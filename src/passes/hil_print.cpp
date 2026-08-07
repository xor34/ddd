// hil -- print the folded expression IL instead of one line per p-code op.
//
// Run it last, in place of print-ssa. Everything the earlier passes recorded
// still shows: block comments, op comments, and the names stack-vars and
// rename gave to values that survive as variables.
#include "../hil.h"
#include "../pass.h"

#include <ostream>

namespace ddd {
namespace {

class HilPrint final : public Pass {
public:
  std::string name() const override { return "hil"; }
  std::string description() const override {
    return "print expressions folded from def-use chains, instead of raw p-code";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    Hil hil = build_hil(fn, ctx);

    if (ctx.verbose)
      ctx.stream() << "  folded " << hil.folded() << " value(s), rewrote "
                   << hil.rewritten() << " idiom(s)\n";

    ctx.stream() << to_string(hil, fn, ctx);
  }
};

DDD_REGISTER_PASS(HilPrint);

} // namespace
} // namespace ddd
