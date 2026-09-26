// dce -- delete computations nobody reads.
//
// Sleigh models an instruction completely, which means every flag it writes
// whether or not the program looks at them. One x86 `add` lowers to eleven
// p-code ops, eight of which exist only to maintain CF/OF/SF/ZF/PF -- and the
// parity flag alone costs an AND, a POPCOUNT, another AND and a compare. On a
// real function that is most of the listing.
//
// SSA makes the removal decision local: a value with no uses is read nowhere,
// full stop, because SSA has already resolved every "which definition does
// this read see" question. So this is a worklist, not a dataflow analysis.
//
// The one thing SSA cannot tell you is what the *caller* still looks at. A
// function's last write to a preserved register has no uses inside the
// function and is exactly what the function is for, so the calling convention
// supplies those as roots. Without them this pass would delete the result.
#include "decode/abi.h"
#include "passes/pass.h"
#include "ir/reaching.h"

#include <set>
#include <string>
#include <vector>

namespace ddd {
namespace {

class Dce final : public Pass {
public:
  std::string name() const override { return "dce"; }
  std::string description() const override {
    return "delete computations whose results are never read";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    const std::set<ValueId> roots = observable_values(fn, ctx.target);
    annotations_ = ctx.annotations;
    collect_machine_flags(ctx);
    no_abi_ = roots.empty();

    // Removing one op can orphan the ops feeding it, so this repeats to a
    // fixed point. The chains are short and each round is linear.
    removed_ = remove_ops_to_fixpoint(
        fn, [&](const SsaOp *op) { return is_dead(*op, roots); });
  }

  std::vector<std::string> report(const SsaFunction &,
                                  const PassContext &) const override {
    std::vector<std::string> lines;
    // Without a convention there is nothing to say a register is still wanted
    // after the function returns, and this pass will happily delete the
    // function's own result -- which is worth saying out loud.
    if (no_abi_)
      lines.push_back("no calling convention: nothing is treated as live at exit");
    lines.push_back("removed " + std::to_string(removed_) + " dead op(s)");
    return lines;
  }

private:
  // A load whose address stack-vars resolved to a frame slot is an ordinary
  // read of the function's own memory. The blanket "a load might be a device
  // register" rule does not apply to it, and without this exception an
  // `add [rbp-0xc], eax` leaves half a dozen dead loads in the listing.
  bool is_stack_load(const SsaOp &op) const {
    if (op.opc != Op::LOAD || op.ins.size() < 2) return false;
    if (annotations_ == nullptr || !op.ins[1].is_tracked()) return false;

    return names_slot(annotations_->address_kind(*op.ins[1].value));
  }

  // Writing machine state is doing something, not computing something.
  //
  // Sleigh models `sti` as `IF = 1` and `cld` as `DF = 0`, and nothing in the
  // function reads either -- so the rule that is right about the arithmetic
  // flags deletes the whole instruction, and a line of firmware that enables
  // interrupts decompiles to nothing at all. Every one of these writes is
  // kept, not merely the last: two of them in a row are two events, and which
  // came first is the point.
  void collect_machine_flags(const PassContext &ctx) {
    flags_.clear();
    if (ctx.translator() == nullptr || ctx.spaces() == nullptr) return;

    for (const std::string &name : machine_flags()) {
      Varnode storage = register_storage(*ctx.translator(), *ctx.spaces(), name);
      if (storage.space != kNoSpace) flags_.insert(storage);
    }
  }

  bool writes_machine_flag(const SsaOp &op) const {
    if (op.out != nullptr) return flags_.count(op.out->storage) != 0;
    if (op.has_raw_output) return flags_.count(op.raw_output) != 0;
    return false;
  }

  bool is_dead(const SsaOp &op, const std::set<ValueId> &roots) const {
    if (has_side_effects(op.opc) && !is_stack_load(op)) return false;
    if (writes_machine_flag(op)) return false;

    // A write to storage we chose not to rename (memory) is not tracked by
    // def-use chains, so there is no evidence it is unread.
    if (op.has_raw_output) return false;

    // Produces nothing and has no side effect: already nothing to keep, but
    // leave it be rather than guess at an opcode this does not model.
    if (op.out == nullptr) return false;

    if (!op.out->uses.empty()) return false;
    return roots.count(op.out->id) == 0;
  }

  const Annotations *annotations_ = nullptr;
  std::set<Varnode> flags_;
  int removed_ = 0;
  bool no_abi_ = false;
};

DDD_REGISTER_PASS(Dce);

} // namespace
} // namespace ddd
