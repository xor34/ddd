// rename -- give values names that come from what defines them.
//
// SSA is what makes this safe: a value has exactly one definition, so a name
// derived from that definition describes the value everywhere it is used, and
// can never be invalidated by a later write to the same register.
//
// The rules are deliberately few and each is one `if`. Run it after
// stack-vars, whose slot names are the most useful thing to propagate.
#include "../pass.h"

#include "opcodes.hh"

#include <ostream>
#include <sstream>

namespace ddd {
namespace {

class Rename final : public Pass {
public:
  std::string name() const override { return "rename"; }
  std::string description() const override {
    return "name values after their definitions";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    int named = 0;

    // Names flow forward along def-use edges, so repeat until it settles. The
    // chains are short; two or three rounds is typical.
    for (bool changed = true; changed;) {
      changed = false;
      fn.for_each_op([&](SsaOp &op) {
        if (op.out == nullptr || ctx.annotations->has_label(*op.out))
          return;

        std::string label = derive(op, *ctx.annotations);
        if (label.empty())
          return;

        ctx.annotations->set_label(*op.out, std::move(label));
        ++named;
        changed = true;
      });
    }

    named += name_conditions(fn, *ctx.annotations);

    if (ctx.verbose)
      ctx.stream() << "  named " << named << " value(s)\n";
  }

private:
  static std::string derive(const SsaOp &op, const Annotations &annotations) {
    // A copy is the same variable under another name.
    if (op.opc == ghidra::CPUI_COPY && op.ins.size() == 1 &&
        op.ins[0].is_tracked())
      return annotations.label(*op.ins[0].value);

    // Loading through a named address gives you that variable's contents.
    if (op.opc == ghidra::CPUI_LOAD && op.ins.size() >= 2 &&
        op.ins[1].is_tracked()) {
      const std::string &address = annotations.label(*op.ins[1].value);
      if (address.size() > 1 && address[0] == '&')
        return address.substr(1);
    }

    // A phi of values that all agree on a name keeps it.
    if (op.is_phi && !op.ins.empty()) {
      const SsaOperand &first = op.ins.front();
      if (!first.is_tracked() || !annotations.has_label(*first.value))
        return {};

      const std::string &shared = annotations.label(*first.value);
      for (const SsaOperand &in : op.ins)
        if (!in.is_tracked() || annotations.label(*in.value) != shared)
          return {};
      return shared;
    }

    return {};
  }

  // The one-bit value a conditional branch tests is worth naming wherever it
  // came from.
  static int name_conditions(SsaFunction &fn, Annotations &annotations) {
    int named = 0;

    fn.for_each_op([&](SsaOp &op) {
      if (op.opc != ghidra::CPUI_CBRANCH || op.ins.size() < 2)
        return;
      if (!op.ins[1].is_tracked() || annotations.has_label(*op.ins[1].value))
        return;

      annotations.set_label(*op.ins[1].value, "cond");
      ++named;
    });

    return named;
  }
};

DDD_REGISTER_PASS(Rename);

} // namespace
} // namespace ddd
