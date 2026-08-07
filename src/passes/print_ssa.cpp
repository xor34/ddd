// print-ssa -- dump the SSA form of a function.
#include "../pass.h"

#include "opcodes.hh"

#include <ostream>

namespace ddd {
namespace {

class PrintSsa final : public Pass {
public:
  std::string name() const override { return "print-ssa"; }
  std::string description() const override { return "dump the SSA form"; }

  void run(SsaFunction &fn, PassContext &ctx) override {
    std::ostream &os = ctx.stream();
    const Cfg &cfg = fn.cfg();

    for (const SsaBlock &block : fn.blocks()) {
      const BasicBlock &raw = cfg[block.id];

      os << "block " << block.id;
      if (block.id == cfg.entry) os << " (entry)";
      if (!fn.dominance().reachable(block.id)) os << " (unreachable)";
      os << "  preds:";
      if (raw.preds.empty()) os << " -";
      for (int p : raw.preds) os << ' ' << p;
      os << "  succs:";
      if (raw.succs.empty()) os << " -";
      for (const Edge &e : raw.succs) os << ' ' << e.target << (e.conditional ? "*" : "");
      os << "\n";

      for (const SsaOp *phi : block.phis) print_phi(os, ctx, *phi, raw);
      for (const SsaOp *op : block.ops) print_op(os, ctx, *op);
    }
  }

private:
  static void print_phi(std::ostream &os, const PassContext &ctx, const SsaOp &phi,
                        const BasicBlock &raw) {
    os << "    " << (phi.out != nullptr ? ctx.name_of(*phi.out) : "?") << " = phi";
    for (size_t i = 0; i < phi.ins.size(); ++i) {
      os << (i == 0 ? " " : ", ") << ctx.name_of(phi.ins[i]);
      if (i < raw.preds.size()) os << "@" << raw.preds[i];
    }
    os << "\n";
  }

  static void print_op(std::ostream &os, const PassContext &ctx, const SsaOp &op) {
    os << "    ";
    if (op.out != nullptr) {
      os << ctx.name_of(*op.out) << " = ";
    } else if (op.has_raw_output) {
      os << ctx.name_of(op.raw_output) << " = ";
    }
    os << ghidra::get_opname(op.opc);
    for (const SsaOperand &in : op.ins) os << ' ' << ctx.name_of(in);
    os << "\n";
  }
};

DDD_REGISTER_PASS(PrintSsa);

} // namespace
} // namespace ddd
