#include "reaching.h"

namespace ddd {

ReachingValues::ReachingValues(const SsaFunction &fn) : fn_(fn) {
  entry_.resize(fn.size());

  const Dominance &dom = fn.dominance();
  const Cfg &cfg = fn.cfg();
  if (cfg.entry < 0)
    return;

  // Live-ins are defined by no op, so seed them at the entry: storage the
  // function only reads still has a value reaching every point in it.
  for (int i = 0; i < fn.value_count(); ++i) {
    const SsaValue &value = fn.value(i);
    if (value.is_live_in())
      entry_[cfg.entry][value.storage] = const_cast<SsaValue *>(&value);
  }

  // Preorder over the dominator tree. A block sees everything its dominator
  // defined, which is exactly the scoping build_ssa renamed under.
  std::vector<int> stack{cfg.entry};
  while (!stack.empty()) {
    int b = stack.back();
    stack.pop_back();

    std::unordered_map<Storage, SsaValue *, StorageHash> state = entry_[b];
    for (const SsaOp *phi : fn[b].phis)
      if (phi->out != nullptr)
        state[phi->out->storage] = phi->out;
    for (const SsaOp *op : fn[b].ops)
      if (op->out != nullptr)
        state[op->out->storage] = op->out;

    for (int child : dom.children[b]) {
      entry_[child] = state;
      stack.push_back(child);
    }
  }
}

SsaValue *ReachingValues::at_entry(int block, const Storage &storage) const {
  auto it = entry_[block].find(storage);
  return it == entry_[block].end() ? nullptr : it->second;
}

SsaValue *ReachingValues::before(const SsaOp &op,
                                 const Storage &storage) const {
  SsaValue *value = at_entry(op.block, storage);

  for (const SsaOp *phi : fn_[op.block].phis) {
    if (phi == &op)
      return value;
    if (phi->out != nullptr && phi->out->storage == storage)
      value = phi->out;
  }
  for (const SsaOp *earlier : fn_[op.block].ops) {
    if (earlier == &op)
      return value;
    if (earlier->out != nullptr && earlier->out->storage == storage)
      value = earlier->out;
  }

  return value;
}

} // namespace ddd
