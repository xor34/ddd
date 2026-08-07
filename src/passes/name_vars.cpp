// name-vars -- give the surviving HIL variables real names.
//
// After folding, most SSA values have vanished into expressions. The ones left
// are the actual variables of the function, and `x0#3` / `sp-0x20#1` is a poor
// way to write them down. This names them from what the earlier passes worked
// out: stack slots, parameters, the return address, resolved string pointers.
//
// It builds the HIL to find out which values survive as variables, then writes
// names into the annotation table; the `hil` pass that follows renders them.
// Building twice is deliberate -- naming a value stops it folding, so the pass
// must only name values that were not going to fold anyway, and the only
// honest way to know that is to ask.
//
// Run it between `calling-conv` and `hil`.
#include "../hil.h"
#include "../pass.h"

#include <cctype>
#include <map>
#include <ostream>
#include <set>

namespace ddd {
namespace {

// "hello, world" -> "hello_world", so a string pointer can be named after what
// it points at.
std::string identifier_from(const std::string &text, size_t limit = 20) {
  std::string result;
  bool underscore = false;

  for (char c : text) {
    if (std::isalnum(static_cast<unsigned char>(c))) {
      result.push_back(c);
      underscore = false;
    } else if (!underscore && !result.empty()) {
      result.push_back('_');
      underscore = true;
    }
    if (result.size() >= limit) break;
  }

  while (!result.empty() && result.back() == '_') result.pop_back();
  return result;
}

class NameVars final : public Pass {
public:
  std::string name() const override { return "name-vars"; }
  std::string description() const override {
    return "name the variables that survive expression folding";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    if (ctx.annotations == nullptr) return;

    // A Pass object outlives one function: the manager holds it and runs it
    // against every function analysed. Anything kept in a member has to be
    // cleared here, or the second function inherits the first's numbering and
    // silently gets no names at all.
    counts_.clear();
    seen_.clear();
    return_address_ = Storage{};

    Hil hil = build_hil(fn, ctx);
    argument_registers(ctx);

    int named = 0;
    // Deterministic order: blocks, then statements, target before operands, so
    // the numbering follows the listing rather than SSA value ids.
    for (const HilBlock &block : hil.blocks()) {
      for (const Statement &statement : block.statements) {
        if (statement.target != nullptr) named += name_value(*statement.target, ctx);
        named += walk(statement.value, ctx);
        named += walk(statement.address, ctx);
      }
    }

    if (ctx.verbose) ctx.stream() << "  named " << named << " variable(s)\n";
  }

private:
  int walk(ExprRef expr, PassContext &ctx) {
    if (expr == nullptr) return 0;

    int named = 0;
    if (expr->kind == ExprKind::Variable && expr->value != nullptr)
      named += name_value(*expr->value, ctx);
    for (ExprRef operand : expr->operands) named += walk(operand, ctx);
    return named;
  }

  void argument_registers(const PassContext &ctx) {
    arguments_.clear();
    if (ctx.abi() == nullptr || ctx.translator() == nullptr) return;

    for (size_t i = 0; i < ctx.abi()->arguments.size(); ++i) {
      Storage storage = register_storage(*ctx.translator(), ctx.abi()->arguments[i]);
      if (storage.space != nullptr) arguments_[storage] = static_cast<int>(i);
    }

    if (!ctx.abi()->return_address_register.empty())
      return_address_ = register_storage(*ctx.translator(), ctx.abi()->return_address_register);
  }

  int name_value(const SsaValue &value, PassContext &ctx) {
    // An unlabelled Sleigh temporary is numbered by the printer; it is not a
    // variable of the program and a name would only dress it up. A labelled
    // one is different -- something worked out what it holds.
    if (is_temporary(value.storage) && !ctx.annotations->has_label(value)) return 0;
    if (!seen_.insert(value.id).second) return 0;

    const std::string name = choose(value, ctx);

    // `&var_1c` names a stack slot's address. The same slot gets its address
    // recomputed at every access, and those are all the one variable -- giving
    // them separate names would invent variables the program does not have.
    const bool is_slot_address = name.size() > 1 && name[0] == '&';
    ctx.annotations->set_display_name(value, is_slot_address ? name : unique(name));
    return 1;
  }

  std::string choose(const SsaValue &value, const PassContext &ctx) {
    // Whatever stack-vars, rename or calling-conv already decided stands: they
    // knew something about this value that its storage does not say.
    if (ctx.annotations->has_label(value)) return ctx.annotations->label(value);

    if (value.is_live_in()) {
      if (value.storage == return_address_ && return_address_.space != nullptr)
        return "retaddr";

      // A parameter is worth calling one; anything else read before it is
      // written keeps its register name, which is already the whole story.
      auto argument = arguments_.find(value.storage);
      if (argument != arguments_.end()) return "arg" + std::to_string(argument->second);
      return base_name(value, ctx);
    }

    // data-refs may have worked out that this value points at a string, which
    // is a far better name than the register it happens to live in.
    if (std::string from_data = name_from_data(value, ctx); !from_data.empty())
      return "str_" + from_data;

    return base_name(value, ctx);
  }

  // The register name without the SSA version.
  static std::string base_name(const SsaValue &value, const PassContext &ctx) {
    const std::string full = ctx.name_of(value);
    const size_t hash = full.rfind('#');
    return hash == std::string::npos ? full : full.substr(0, hash);
  }

  std::string name_from_data(const SsaValue &value, const PassContext &ctx) {
    if (value.def == nullptr) return {};

    for (const std::string &comment : ctx.annotations->comments(*value.def)) {
      const size_t quote = comment.find(" -> \"");
      if (quote == std::string::npos) continue;

      const size_t begin = quote + 5;
      const size_t end = comment.rfind('"');
      if (end <= begin) continue;

      std::string identifier = identifier_from(comment.substr(begin, end - begin));
      if (!identifier.empty()) return identifier;
    }

    return {};
  }

  // Distinct values must never print the same, so a repeated base gets a
  // counter -- x0, x0_2, x0_3 rather than x0#1, x0#4, x0#9.
  std::string unique(const std::string &base) {
    const int count = ++counts_[base];
    return count == 1 ? base : base + "_" + std::to_string(count);
  }

  std::map<Storage, int> arguments_;
  Storage return_address_;
  std::map<std::string, int> counts_;
  std::set<int> seen_;
};

DDD_REGISTER_PASS(NameVars);

} // namespace
} // namespace ddd
