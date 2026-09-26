// asm -- the machine instructions, with everything the analyses learned about
// them and nothing else.
//
// The other two renderers are for reading what the tool worked out. This one is
// for checking it: the instructions the sweep decoded, in the order it decoded
// them, each with whatever a pass had to say underneath. Nothing is folded
// away and nothing is elided, so a reader who does not trust an analysis can
// see exactly which instruction it was talking about -- and a pass that
// overreaches has nowhere to hide.
//
// It is not `disasm`, which is the pre-lift dump: no analyses have run there,
// and here every one of them has.
#include "render/view.h"

#include "decode/cfg.h"

#include <ostream>

namespace ddd {
namespace {

class AsmPrint final : public Pass {
public:
  std::string name() const override { return "asm"; }
  std::string description() const override {
    return "print the machine instructions with the analyses' notes";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    std::ostream &os = ctx.stream();
    const Cfg &cfg = fn.cfg();

    for (const SsaBlock &block : fn.blocks()) {
      // What nothing can reach is what the linear sweep walked into after this
      // function ended, not part of it. print-ssa shows those blocks and marks
      // them, because the analyses see them; this is a listing of a function.
      if (!fn.dominance().reachable(block.id))
        continue;

      const BasicBlock &raw = cfg[block.id];
      os << "block " << block.id << " @ 0x" << std::hex << raw.start << std::dec;
      if (block.id == cfg.entry)
        os << " (entry)";
      os << ":";
      if (!raw.preds.empty()) {
        os << "  from";
        for (BlockId p : raw.preds)
          os << ' ' << p;
      }
      os << "\n";

      if (ctx.knowledge != nullptr)
        for (const std::string &note : ctx.knowledge->block_comments(block.id))
          os << "  ; " << note << "\n";

      // A phi is not an instruction and gets no line here -- but the notes on
      // it are about this block's values, and dropping them is the one thing
      // this renderer does not do.
      for (const SsaOp *phi : block.phis)
        render_notes(os, ctx, *phi, "        ");

      print_body(os, ctx, cfg, block);
    }
  }

private:
  // The instructions of a block and the ops lifted from them, walked together
  // in address order.
  //
  // The text comes from the Cfg's own instruction table rather than being
  // copied onto each statement: one source for all three renderers, and no
  // chance of a listing disagreeing with the disassembly about what is at an
  // address.
  static void print_body(std::ostream &os, const PassContext &ctx,
                         const Cfg &cfg, const SsaBlock &block) {
    const BasicBlock &raw = cfg[block.id];
    constexpr uint64_t kNone = ~uint64_t(0);

    auto instr = cfg.instructions.lower_bound(raw.start);
    size_t next = 0;

    while (true) {
      const uint64_t op_at =
          next < block.ops.size() ? block.ops[next]->addr : kNone;
      uint64_t instr_at = kNone;
      if (instr != cfg.instructions.end() && instr->first < raw.end)
        instr_at = instr->first;

      if (op_at == kNone && instr_at == kNone)
        return;

      if (instr_at <= op_at) {
        os << "  0x" << std::hex << instr_at << std::dec << "  "
           << instr->second.text << "\n";
        ++instr;

        while (next < block.ops.size() && block.ops[next]->addr == instr_at)
          render_notes(os, ctx, *block.ops[next++], "        ");
        continue;
      }

      // An op the Cfg has no instruction behind -- a hand-built function, or
      // an address the sweep never decoded. Worth a line rather than a dropped
      // note.
      os << "  0x" << std::hex << op_at << std::dec << "  ?\n";
      while (next < block.ops.size() && block.ops[next]->addr == op_at)
        render_notes(os, ctx, *block.ops[next++], "        ");
    }
  }
};

DDD_REGISTER_PASS(AsmPrint);

} // namespace
} // namespace ddd
