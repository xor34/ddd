// print-ssa -- dump the SSA form.
//
// Renders whatever the earlier passes left behind: the machine instruction
// each op was lifted from, block and op comments, and value labels. Run it
// last.
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
      print_header(os, fn, ctx, block);

      for (const SsaOp *phi : block.phis)
        print_phi(os, ctx, *phi, cfg[block.id]);

      // Group ops under the instruction they came from, so the listing reads
      // as annotated disassembly rather than a flat stream of p-code.
      uint64_t shown = ~uint64_t(0);
      for (const SsaOp *op : block.ops) {
        uint64_t at = static_cast<uint64_t>(op->addr.getOffset());
        if (at != shown) {
          shown = at;
          const Instruction *instr = cfg.instruction_at(op->addr);
          os << "  0x" << std::hex << at << std::dec << "  "
             << (instr != nullptr ? instr->text : "") << "\n";
        }
        print_op(os, ctx, *op);
      }
    }
  }

private:
  static void print_header(std::ostream &os, const SsaFunction &fn,
                           const PassContext &ctx, const SsaBlock &block) {
    const Cfg &cfg = fn.cfg();
    const BasicBlock &raw = cfg[block.id];

    os << "block " << block.id;
    if (block.id == cfg.entry)
      os << " (entry)";
    if (!fn.dominance().reachable(block.id))
      os << " (unreachable)";
    os << "  preds:";
    if (raw.preds.empty())
      os << " -";
    for (int p : raw.preds)
      os << ' ' << p;
    os << "  succs:";
    if (raw.succs.empty())
      os << " -";
    for (const Edge &e : raw.succs)
      os << ' ' << e.target << (e.conditional ? "*" : "");
    os << "\n";

    if (ctx.annotations != nullptr)
      for (const std::string &comment :
           ctx.annotations->block_comments(block.id))
        os << "  ; " << comment << "\n";
  }

  static void print_phi(std::ostream &os, const PassContext &ctx,
                        const SsaOp &phi, const BasicBlock &raw) {
    os << "      " << (phi.out != nullptr ? ctx.name_of(*phi.out) : "?")
       << " = phi";
    for (size_t i = 0; i < phi.ins.size(); ++i) {
      os << (i == 0 ? " " : ", ") << ctx.name_of(phi.ins[i]);
      if (i < raw.preds.size())
        os << "@" << raw.preds[i];
    }
    print_comments(os, ctx, phi);
  }

  static void print_op(std::ostream &os, const PassContext &ctx,
                       const SsaOp &op) {
    os << "      ";
    if (op.out != nullptr) {
      os << ctx.name_of(*op.out) << " = ";
    } else if (op.has_raw_output) {
      os << ctx.name_of(op.raw_output) << " = ";
    }
    os << ghidra::get_opname(op.opc);
    for (size_t i = 0; i < op.ins.size(); ++i)
      os << ' ' << ctx.name_of(op, i);
    print_comments(os, ctx, op);
  }

  static void print_comments(std::ostream &os, const PassContext &ctx,
                             const SsaOp &op) {
    static const std::vector<std::string> none;
    const std::vector<std::string> &comments =
        ctx.annotations != nullptr ? ctx.annotations->comments(op) : none;
    if (comments.empty()) {
      os << "\n";
      return;
    }

    os << "  ; " << comments.front() << "\n";
    for (size_t i = 1; i < comments.size(); ++i)
      os << "        ; " << comments[i] << "\n";
  }
};

DDD_REGISTER_PASS(PrintSsa);

} // namespace
} // namespace ddd
