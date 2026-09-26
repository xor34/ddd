// mem-reads -- one machine read, one LOAD.
//
// `add dword ptr [rdi], eax` lowers to seven reads of the same address:
//
//     unique:0xd400:4#0 = LOAD ram RDI#in    CF = INT_CARRY(#0, EAX#in)
//     unique:0xd400:4#1 = LOAD ram RDI#in    OF = INT_SCARRY(#1, EAX#in)
//     unique:0xd400:4#2 = LOAD ram RDI#in    #3 = INT_ADD(#2, EAX#in) / STORE
//     unique:0xd400:4#4 = LOAD ram RDI#in    SF = INT_SLESS(#4, 0x0)
//     unique:0xd400:4#5 = LOAD ram RDI#in    ZF = INT_EQUAL(#5, 0x0)
//     unique:0xd400:4#6 = LOAD ram RDI#in    PF = ... popcount ... equal
//
// They are not seven reads. The address operand is the *same SSA value* in every
// one of them, so nothing can have changed it between them, and the machine
// performs a single access -- the count tracks the flags exactly, which is the
// proof: an instruction that sets no flags has one load, `lea` has none, and
// the ones here are Sleigh writing the operand once per flag it defines. P-code
// is functional and has no common subexpression elimination, so a mention of a
// load is a load.
//
// Unification is therefore the right fix, not deletion: the reads are real, and
// what is wrong is that there are seven of them. Deleting them outright would
// be the lie -- the six vanished reads are the ones a reader would want to
// check against the disassembly, and the seventh is the one that is missing.
//
// Everything here happens *within one instruction*, which is what makes it
// sound without a memory model. Across instructions the question "is this the
// same read" needs to know whether an address is volatile, and nothing in the
// image says; within one, the claim is only the machine's own -- one
// instruction, one access to one address -- and no assumption about memory is
// being made at all. (A call needs no special case for the same reason: it is
// one instruction, and this pass never looks at two of them at once.)
//
// One instruction, one read also settles the store: a load of an address this
// instruction has already written reads what was written, not what was there
// before it. In the listing above that is where the flags come from -- SF, ZF
// and PF are the result of the addition, which Sleigh spells as a reload of the
// address it has just stored through. Forwarding them to the stored value is
// the machine's own semantics, and it is what leaves `add [rdi], eax` reading
// as one read and one write.
#include "passes/pass.h"

#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace ddd {
namespace {

class MemReads final : public Pass {
public:
  std::string name() const override { return "mem-reads"; }
  std::string description() const override {
    return "unify the loads one machine read lowered to";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    redundant_.clear();
    unified_ = 0;
    forwarded_ = 0;

    for (SsaBlock &block : fn.blocks()) {
      // A block's ops are in address order, so one instruction is a run of
      // them sharing an address. That run *is* the scope of this pass.
      for (size_t begin = 0; begin < block.ops.size();) {
        const uint64_t addr = block.ops[begin]->addr;
        size_t end = begin;
        while (end < block.ops.size() && block.ops[end]->addr == addr) ++end;

        unify_instruction(fn, block.ops, begin, end);
        begin = end;
      }
    }

    if (redundant_.empty()) return;

    // The loads are not merely unlinked here: they are loads, so nothing else
    // would remove them -- a LOAD is assumed to have effects, and `dce` keeps
    // one that might be a device register. The claim that this one is not a
    // read the machine makes is exactly what this pass has just proven.
    remove_ops_to_fixpoint(fn, [&](const SsaOp *op) {
      return op->out != nullptr && redundant_.count(op->id) != 0;
    });
  }

  std::vector<std::string> report(const SsaFunction &,
                                  const PassContext &) const override {
    return {"merged " + std::to_string(unified_) + " duplicate load(s)",
            "forwarded " + std::to_string(forwarded_) +
                " read(s) of what the instruction wrote"};
  }

private:
  // What makes two loads the same read: the same space, the same address, and
  // the same width.
  //
  // The address is the SSA *value*, not its storage: two versions of RDI are
  // two different addresses, and only the very same value proves that nothing
  // could have changed it in between.
  struct Read {
    uint64_t space = 0;
    const SsaValue *address = nullptr;
    unsigned width = 0;

    bool operator<(const Read &other) const {
      return std::tie(space, address, width) <
             std::tie(other.space, other.address, other.width);
    }
  };

  // The address a load or store goes through, as a key. Nothing when it is not
  // an SSA value: an address this pass cannot prove the same from one mention
  // to the next is not one it will merge reads of, and a width of zero says
  // how much is read there is not known either.
  static std::optional<Read> address_of(const SsaOp &op, unsigned width) {
    if (width == 0) return std::nullopt;
    if (op.ins.size() < 2 || !op.ins[1].is_tracked()) return std::nullopt;
    if (!op.ins[0].is_constant()) return std::nullopt;

    return Read{op.ins[0].constant(), op.ins[1].value, width};
  }

  // How much a store writes. Taken from the value, which may be one this pass
  // cannot name -- a store of an untracked value still ends the reads that
  // came before it.
  static unsigned stored_width(const SsaOp &op) {
    if (op.ins.size() < 3) return 0;

    const SsaOperand &stored = op.ins[2];
    return stored.is_tracked() ? stored.value->storage.size : stored.raw.size;
  }

  void unify_instruction(SsaFunction &fn, std::vector<SsaOp *> &ops,
                         size_t begin, size_t end) {
    // The read this instruction has already made of each address, and what it
    // has written to each since.
    std::map<Read, SsaValue *> kept;
    std::map<Read, SsaValue *> written;
    bool opaque_store = false;

    for (size_t i = begin; i < end; ++i) {
      SsaOp &op = *ops[i];

      if (op.opc == Op::STORE) {
        if (opaque_store) continue;

        // A store to an address this pass cannot name ends its reasoning about
        // the instruction: what is written there might be either of the two
        // addresses it has been tracking, or one it never saw. An instruction
        // this rare is not worth guessing about.
        const std::optional<Read> key = address_of(op, stored_width(op));
        if (!key) {
          opaque_store = true;
          kept.clear();
          written.clear();
          continue;
        }

        written[*key] = op.ins.size() > 2 && op.ins[2].is_tracked()
                            ? op.ins[2].value
                            : nullptr;
        continue;
      }

      if (op.opc != Op::LOAD || op.out == nullptr) continue;

      const std::optional<Read> key = address_of(op, op.out->storage.size);
      if (!key) continue;

      // Read after write: this is the value that was stored. Forwarding is
      // only possible when that value is one we can name; when it is not, the
      // load stands on its own, because it is still not the read that fed the
      // store.
      const auto wrote = written.find(*key);
      if (wrote != written.end()) {
        if (wrote->second == nullptr) continue;

        replace_uses(*op.out, *wrote->second);
        redundant_.insert(op.id);
        ++forwarded_;
        continue;
      }

      const auto known = kept.find(*key);
      if (known == kept.end()) {
        kept[*key] = op.out;
        continue;
      }

      replace_uses(*op.out, *known->second);
      redundant_.insert(op.id);
      ++unified_;
    }
  }

  // Redirects the uses of one value to another, through the def-use chain the
  // SSA already has. The `!= from` guard is what lets this run while the
  // chains are being edited: a use this pass has already redirected no longer
  // points at `from`, and is left alone.
  static void replace_uses(SsaValue &from, SsaValue &to) {
    for (SsaOp *use : from.uses)
      for (SsaOperand &in : use->ins)
        if (in.value == &from) in.value = &to;
  }

  std::set<OpId> redundant_;
  int unified_ = 0;
  int forwarded_ = 0;
};

DDD_REGISTER_PASS(MemReads);

} // namespace
} // namespace ddd
