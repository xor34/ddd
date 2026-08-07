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
  std::string description() const override { return "name values after their definitions"; }

  void run(SsaFunction &fn, PassContext &ctx) override {
    int named = 0;

    // Names flow forward along def-use edges, so repeat until it settles. The
    // chains are short; two or three rounds is typical.
    for (bool changed = true; changed;) {
      changed = false;
      fn.for_each_op([&](SsaOp &op) {
        if (op.out == nullptr || !op.out->label.empty()) return;

        std::string label = derive(op);
        if (label.empty()) return;

        op.out->label = std::move(label);
        ++named;
        changed = true;
      });
    }

    named += name_conditions(fn);

    if (ctx.verbose) ctx.stream() << "  named " << named << " value(s)\n";
  }

private:
  static std::string derive(const SsaOp &op) {
    // A copy is the same variable under another name.
    if (op.opc == ghidra::CPUI_COPY && op.ins.size() == 1 && op.ins[0].is_tracked())
      return op.ins[0].value->label;

    // Loading through a named address gives you that variable's contents.
    if (op.opc == ghidra::CPUI_LOAD && op.ins.size() >= 2 && op.ins[1].is_tracked()) {
      const std::string &address = op.ins[1].value->label;
      if (address.size() > 1 && address[0] == '&') return address.substr(1);
    }

    // A phi of values that all agree on a name keeps it.
    if (op.is_phi && !op.ins.empty()) {
      const SsaOperand &first = op.ins.front();
      if (!first.is_tracked() || first.value->label.empty()) return {};

      for (const SsaOperand &in : op.ins)
        if (!in.is_tracked() || in.value->label != first.value->label) return {};
      return first.value->label;
    }

    return {};
  }

  // The one-bit value a conditional branch tests is worth naming wherever it
  // came from.
  static int name_conditions(SsaFunction &fn) {
    int named = 0;

    fn.for_each_op([&](SsaOp &op) {
      if (op.opc != ghidra::CPUI_CBRANCH || op.ins.size() < 2) return;
      if (!op.ins[1].is_tracked() || !op.ins[1].value->label.empty()) return;

      op.ins[1].value->label = "cond";
      ++named;
    });

    return named;
  }
};

DDD_REGISTER_PASS(Rename);

} // namespace
} // namespace ddd
