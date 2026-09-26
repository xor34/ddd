// ssa.h -- SSA form over a p-code Cfg.
//
// build_ssa() does the classic four steps:
//   1. copy the Cfg's p-code into per-block op lists
//   2. place phis at iterated dominance frontiers (Cytron et al. 1991)
//   3. rename defs and uses on a dominator-tree walk
//   4. build def-use chains
//
// Values and ops live in the SsaFunction and are addressed by dense ids
// (ValueId / OpId / BlockId), so an analysis can keep its per-value state
// in a plain vector.
#pragma once

#include "decode/abi.h"
#include "decode/cfg.h"
#include "ir/dominance.h"
#include "pcode/pcode.h"

#include <deque>
#include <functional>
#include <vector>

namespace ddd {

struct SsaOp;
struct Target;

// One versioned definition, e.g. RAX#3.
struct SsaValue {
  ValueId id;
  Varnode storage;
  int version = 0;
  BlockId block;        // block containing the definition
  SsaOp *def = nullptr; // null for a live-in (parameter / uninitialized read)
  std::vector<SsaOp *> uses;

  bool is_live_in() const { return def == nullptr; }
  bool is_phi() const;     // defined below, once SsaOp is complete
  bool is_clobber() const; // likewise
};

// An operand is either a renamed value or a raw varnode that was never
// tracked -- a constant, or storage excluded by SsaOptions::track.
struct SsaOperand {
  Varnode raw{};
  SsaValue *value = nullptr;

  bool is_tracked() const { return value != nullptr; }
  bool is_constant() const { return value == nullptr && ddd::is_constant(raw); }
  uint64_t constant() const { return raw.offset; }
};

struct SsaOp {
  OpId id;
  BlockId block;
  uint64_t addr = 0;
  Op opc = Op::COPY;
  // A phi is `is_phi`; its `opc` is meaningless and left at the default.
  bool is_phi = false;

  // A call destroying a register the convention does not preserve: what the
  // callee left there, which is not a computation and not the value that was
  // there before it. Like a phi it is not p-code -- Sleigh's CALL says
  // nothing about the caller's registers -- so it is a flag rather than an
  // opcode, and its `opc` is meaningless.
  bool is_clobber = false;

  // Exactly one of these describes the destination: `out` for tracked
  // storage, `raw_output` for storage we chose not to rename (memory), or
  // neither for ops that produce no value (STORE, BRANCH, ...).
  SsaValue *out = nullptr;
  bool has_raw_output = false;
  Varnode raw_output{};

  // For a phi: one operand per predecessor, in the same order as
  // cfg[block].preds.
  std::vector<SsaOperand> ins;
};

inline bool SsaValue::is_phi() const { return def != nullptr && def->is_phi; }
inline bool SsaValue::is_clobber() const {
  return def != nullptr && def->is_clobber;
}

// LOAD and STORE carry the address space they operate on as a constant in
// their first operand. That constant's offset *is* the SpaceId of the space
// it operates on, so it can be read as an integer and printed as a name.
inline bool is_space_operand(const SsaOp &op, size_t index) {
  return index == 0 && (op.opc == Op::LOAD || op.opc == Op::STORE);
}

// How wide an operand is read: the storage it names, or the width the constant
// carries. An operation's width is part of what it does -- `x * 1` is an
// identity at any width, `x & ~0` is not, because ~0 has to be the width of x
// -- so anything reasoning about an operation needs this, and reaching into
// either shape at each call site is how one of them gets forgotten.
inline uint32_t operand_size(const SsaOp &op, size_t index) {
  if (index >= op.ins.size()) return 8;

  const SsaOperand &operand = op.ins[index];
  if (operand.is_tracked()) return operand.value->storage.size;
  return operand.raw.space != kNoSpace ? operand.raw.size : 8;
}

struct SsaBlock {
  BlockId id;
  std::vector<SsaOp *> phis;
  std::vector<SsaOp *> ops;
};

// Decides which storage gets renamed. Constants are values rather than
// variables, and per-address SSA over memory is unsound without alias
// analysis, so the default tracks registers and Sleigh temporaries only.
bool default_track_filter(const Varnode &vn, const Spaces &spaces);

struct SsaOptions {
  // Empty means the default: registers and Sleigh temporaries. The spaces to
  // decide "is this a register" come from the Cfg.
  std::function<bool(const Varnode &)> track;

  // Storage the caller can still read once the function returns. Phi
  // placement is pruned by liveness, and without this the function's own
  // result looks dead at the exit -- so its phi is never placed and
  // everything computing it follows.
  std::vector<Varnode> live_at_exit;

  // What a call does to the caller's machine state. Sleigh's CALL spends only
  // the call itself, so the callee's effect on the caller -- the answer it
  // produced, the stack pointer it gave back, the registers it destroyed -- is
  // missing from the p-code and has to be supplied from the convention. See
  // call_effects(); a default-constructed one models nothing, which is what a
  // caller with no ABI gets.
  CallEffects calls;
};

// The options a Target implies. Both facts a calling convention contributes
// come from the same three things and are always wanted together, so a front
// end asks once rather than remembering to ask twice.
SsaOptions ssa_options(const Target &target);

// SSA form of one Cfg. Borrows the Cfg -- it must outlive the SsaFunction.
class SsaFunction {
public:
  const Cfg &cfg() const { return *cfg_; }
  const Dominance &dominance() const { return dom_; }
  const Spaces &spaces() const { return *cfg_->spaces; }

  int size() const { return static_cast<int>(blocks_.size()); }
  SsaBlock &operator[](BlockId block) { return blocks_[block]; }
  const SsaBlock &operator[](BlockId block) const { return blocks_[block]; }
  std::vector<SsaBlock> &blocks() { return blocks_; }
  const std::vector<SsaBlock> &blocks() const { return blocks_; }

  int op_count() const { return static_cast<int>(ops_.size()); }
  SsaOp &op(OpId id) { return ops_[id]; }
  const SsaOp &op(OpId id) const { return ops_[id]; }

  int value_count() const { return static_cast<int>(values_.size()); }
  SsaValue &value(ValueId id) { return values_[id]; }
  const SsaValue &value(ValueId id) const { return values_[id]; }

  // Recomputes every value's `uses` from the ops currently listed in the
  // blocks. Call after a pass adds or removes ops.
  void rebuild_uses();

  // Visits phis then ops of every block, in block-id order.
  void for_each_op(const std::function<void(SsaOp &)> &fn);
  void for_each_op(const std::function<void(const SsaOp &)> &fn) const;

private:
  friend SsaFunction build_ssa(const Cfg &, SsaOptions);

  SsaOp &new_op();
  SsaValue &new_value();

  const Cfg *cfg_ = nullptr;
  Dominance dom_;
  std::vector<SsaBlock> blocks_;
  // Deques: ids are indices and references must stay valid as more are added.
  std::deque<SsaOp> ops_;
  std::deque<SsaValue> values_;
};

SsaFunction build_ssa(const Cfg &cfg, SsaOptions options = {});

} // namespace ddd
