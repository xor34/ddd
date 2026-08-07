// symbols -- use the names the file already carries.
//
// A call to 0x401136 says nothing; a call to `helper` says everything. When
// the container had a symbol table, this is the cheapest readability win
// available, and unlike every other naming pass here it is not a guess.
#include "../pass.h"

#include "opcodes.hh"

#include <ostream>

namespace ddd {
namespace {

class Symbols final : public Pass {
public:
  std::string name() const override { return "symbols"; }
  std::string description() const override {
    return "name calls and blocks from the container's symbol table";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    if (ctx.symbols == nullptr || ctx.symbols->empty()) {
      if (ctx.verbose) ctx.stream() << "  no symbol table\n";
      return;
    }

    int named = 0;

    // The function being looked at, if a symbol starts where it does.
    //
    // cfg.code_begin, not the entry block's start: a block's start is the
    // address of its first *p-code op*, and an instruction can lower to none
    // at all. An x86-64 function opening with `endbr64` has its entry block
    // starting four bytes in, which matches no symbol.
    if (const std::string *symbol = lookup(ctx, fn.cfg().code_begin)) {
      ctx.annotations->comment_block(fn.cfg().entry, "function: " + *symbol);
      ++named;
    }

    fn.for_each_op([&](SsaOp &op) {
      if (op.opc == ghidra::CPUI_CALL && !op.ins.empty()) {
        // A direct CALL's destination is an address in the code space, carried
        // as the operand's offset rather than as a constant.
        const VarnodeData &target = op.ins[0].raw;
        if (target.space != nullptr) {
          if (const std::string *symbol = lookup(ctx, target.offset)) {
            ctx.annotations->comment(op, "calls " + *symbol);
            ++named;
          }
        }
        return;
      }

      // A constant that lands on a function is a function pointer -- which is
      // how main reaches __libc_start_main, and how any callback is passed.
      for (size_t i = 0; i < op.ins.size(); ++i) {
        if (!op.ins[i].is_constant() || is_space_operand(op, i)) continue;

        const std::string *symbol = lookup(ctx, op.ins[i].constant());
        if (symbol == nullptr) continue;

        ctx.annotations->comment(op, "&" + *symbol);
        if (op.out != nullptr) ctx.annotations->set_label(*op.out, "&" + *symbol);
        ++named;
      }
    });

    if (ctx.verbose) ctx.stream() << "  resolved " << named << " symbol(s)\n";
  }

private:
  static const std::string *lookup(const PassContext &ctx, uint64_t address) {
    auto it = ctx.symbols->find(address);
    return it == ctx.symbols->end() ? nullptr : &it->second;
  }
};

DDD_REGISTER_PASS(Symbols);

} // namespace
} // namespace ddd
