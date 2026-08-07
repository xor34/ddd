// calling-conv -- say what a call is being passed, and what the function
// itself receives.
//
// In raw p-code a CALL carries only its destination; the arguments are in
// registers nobody named. ReachingValues answers "what was in x0 here?", and
// the calling convention says which registers to ask about.
//
// Argument *count* is not recoverable without prototypes, so this reports the
// contiguous run of argument registers that the function actually wrote before
// the call. That is a heuristic: a call passing (x0, x2) and leaving x1 alone
// will be reported as passing only x0.
#include "../pass.h"
#include "../reaching.h"

#include "opcodes.hh"

#include <ostream>
#include <sstream>

namespace ddd {
namespace {

class CallingConv final : public Pass {
public:
  std::string name() const override { return "calling-conv"; }
  std::string description() const override {
    return "annotate calls with their arguments, and the entry with its "
           "parameters";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    if (ctx.abi() == nullptr || ctx.translator() == nullptr) {
      if (ctx.verbose)
        ctx.stream() << "  no calling convention known, skipping\n";
      return;
    }

    std::vector<Storage> argument_registers;
    for (const std::string &reg : ctx.abi()->arguments) {
      Storage storage = register_storage(*ctx.translator(), reg);
      if (storage.space != nullptr)
        argument_registers.push_back(storage);
    }
    if (argument_registers.empty())
      return;

    ReachingValues reaching(fn);

    annotate_parameters(fn, ctx, argument_registers);
    int calls = annotate_calls(fn, ctx, reaching, argument_registers);

    if (ctx.verbose)
      ctx.stream() << "  annotated " << calls << " call(s)\n";
  }

private:
  // An argument register read before the function writes it is a parameter.
  static void annotate_parameters(SsaFunction &fn, const PassContext &ctx,
                                  const std::vector<Storage> &registers) {
    std::ostringstream os;
    int count = 0;

    for (size_t i = 0; i < registers.size(); ++i) {
      const SsaValue *live_in = find_live_in(fn, registers[i]);
      if (live_in == nullptr || live_in->uses.empty())
        break; // arguments run out here

      os << (count++ == 0 ? "" : ", ") << ctx.abi()->arguments[i];
    }

    if (count == 0)
      return;
    ctx.annotations->comment_block(
        fn.cfg().entry, "parameters (" + ctx.abi()->name + "): " + os.str());
  }

  static int annotate_calls(SsaFunction &fn, const PassContext &ctx,
                            const ReachingValues &reaching,
                            const std::vector<Storage> &registers) {
    int calls = 0;

    fn.for_each_op([&](SsaOp &op) {
      if (op.opc != ghidra::CPUI_CALL && op.opc != ghidra::CPUI_CALLIND)
        return;
      ++calls;

      std::ostringstream os;
      int count = 0;
      for (size_t i = 0; i < registers.size(); ++i) {
        SsaValue *value = reaching.before(op, registers[i]);
        if (value == nullptr)
          continue; // register never mentioned at all

        // Either the function put something there for this call, or it is
        // forwarding one of its own parameters. A register it neither wrote
        // nor read was not set up for this call -- skip it rather than stop,
        // so a gap does not hide the arguments after it.
        if (value->is_live_in() && value->uses.empty())
          continue;

        os << (count++ == 0 ? "" : ", ") << ctx.abi()->arguments[i] << "="
           << ctx.name_of(*value);
      }

      ctx.annotations->comment(op, count == 0 ? "no arguments detected"
                                              : "args: " + os.str());
      if (!ctx.abi()->result.empty())
        ctx.annotations->comment(op, "returns in " + ctx.abi()->result);
    });

    return calls;
  }

  static const SsaValue *find_live_in(const SsaFunction &fn,
                                      const Storage &storage) {
    for (int i = 0; i < fn.value_count(); ++i) {
      const SsaValue &value = fn.value(i);
      if (value.is_live_in() && value.storage == storage)
        return &value;
    }
    return nullptr;
  }
};

DDD_REGISTER_PASS(CallingConv);

} // namespace
} // namespace ddd
