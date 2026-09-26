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
    folded_ = hil.folded();
    rewritten_ = hil.rewritten();

    // The listing is this pass's output, not a report about it: it goes to
    // the stream whatever the caller asked for, and is the only thing here
    // that does.
    ctx.stream() << to_string(hil, fn, ctx);
  }

  std::vector<std::string> report(const SsaFunction &,
                                  const PassContext &) const override {
    return {"folded " + std::to_string(folded_) + " value(s), rewrote " +
            std::to_string(rewritten_) + " idiom(s)"};
  }

private:
  int folded_ = 0;
  int rewritten_ = 0;
};

DDD_REGISTER_PASS(HilPrint);

} // namespace
} // namespace ddd
