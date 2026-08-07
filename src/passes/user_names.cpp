// user-names -- the names a person chose beat the ones this tool invented.
//
// Runs after name-vars, so it sees the generated names and can override them.
// That ordering is also what makes the project file stable: the user renames
// `var_1c` to `count`, and `var_1c` is what the analysis will call it again
// next time, so the mapping still applies.
#include "../pass.h"
#include "../project.h"

#include <ostream>

namespace ddd {
namespace {

class UserNames final : public Pass {
public:
  std::string name() const override { return "user-names"; }
  std::string description() const override {
    return "apply renames and comments from the project";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    if (ctx.project == nullptr || ctx.annotations == nullptr) return;

    const uint64_t function = fn.cfg().code_begin;
    int applied = 0;

    if (const std::string *renamed = ctx.project->function_name(function)) {
      ctx.annotations->comment_block(fn.cfg().entry, "name: " + *renamed);
      ++applied;
    }

    for (int i = 0; i < fn.value_count(); ++i) {
      SsaValue &value = fn.value(i);
      if (!ctx.annotations->has_display_name(value)) continue;

      // A stack slot is displayed as `var_c` but held internally as the
      // address `&var_c`, so look up what the user actually saw and typed.
      const std::string generated = ctx.annotations->display_name(value);
      const bool slot = generated.size() > 1 && generated[0] == '&';
      const std::string shown = slot ? generated.substr(1) : generated;

      if (const std::string *chosen = ctx.project->variable_name(function, shown)) {
        ctx.annotations->set_display_name(value, slot ? "&" + *chosen : *chosen);
        ++applied;
      }
    }

    // A comment is attached to every op of that instruction, not just the
    // first: an instruction lowers to several ops and the listing hides most
    // of them, so picking one would often pick a hidden one and lose the
    // comment. After dead-code elimination at most one of them usually
    // survives.
    fn.for_each_op([&](SsaOp &op) {
      if (const std::string *text = ctx.project->comment(op.addr.getOffset())) {
        ctx.annotations->comment(op, *text);
        ++applied;
      }
    });

    if (ctx.verbose) ctx.stream() << "  applied " << applied << " user name(s)\n";
  }

};

DDD_REGISTER_PASS(UserNames);

} // namespace
} // namespace ddd
