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

#include "cfg.h"
#include "dominance.h"
#include "pcode.h"

#include <deque>
#include <functional>
#include <vector>

namespace ddd {

struct SsaOp;

// One versioned definition, e.g. RAX#3.
struct SsaValue {
  ValueId id;
  Varnode storage;
  int version = 0;
  BlockId block;        // block containing the definition
  SsaOp *def = nullptr; // null for a live-in (parameter / uninitialized read)
  std::vector<SsaOp *> uses;

  bool is_live_in() const { return def == nullptr; }
  bool is_phi() const; // defined below, once SsaOp is complete
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

// LOAD and STORE carry the address space they operate on as a constant in
// their first operand. That constant's offset *is* the SpaceId of the space
// it operates on, so it can be read as an integer and printed as a name.
inline bool is_space_operand(const SsaOp &op, size_t index) {
  return index == 0 && (op.opc == Op::LOAD || op.opc == Op::STORE);
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
};

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
