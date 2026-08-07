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
    int aliased = alias_copies(fn, *ctx.annotations);
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
      ctx.stream() << "  named " << named << " value(s), followed " << aliased
                   << " copy/copies\n";
  }

private:
  // A COPY produces the same variable under a new SSA name, so every use of
  // the result is really a use of the source.
  //
  // This is the one rule here that needs no other pass to have invented a
  // name first -- it comes straight out of the SSA graph. Without it `rename`
  // could only relay labels that stack-vars had already set, so a function
  // with no stack slots got nothing at all out of it.
  static int alias_copies(SsaFunction &fn, Annotations &annotations) {
    int aliased = 0;

    fn.for_each_op([&](SsaOp &op) {
      if (op.opc != ghidra::CPUI_COPY || op.ins.size() != 1)
        return;
      if (op.out == nullptr || !op.ins[0].is_tracked())
        return;

      // Only when the copy preserves width. A COPY between different sizes is
      // a truncation or an extension, and calling the result the same
      // variable would be a lie.
      if (op.out->storage.size != op.ins[0].value->storage.size)
        return;

      // Never trade a register for a Sleigh temporary. Following a copy is
      // supposed to make the listing easier to read, and `unique:0x23700:8#0`
      // is not an improvement on `x0#1` -- the temporaries are lowering
      // plumbing, not variables anyone wants to see. The other direction,
      // naming a temporary after the register it came from, is exactly what
      // this is for.
      if (is_temporary(op.ins[0].value->storage) && !is_temporary(op.out->storage))
        return;

      annotations.set_alias(*op.out, *op.ins[0].value);
      ++aliased;
    });

    return aliased;
  }

  static std::string derive(const SsaOp &op, const Annotations &annotations) {
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
