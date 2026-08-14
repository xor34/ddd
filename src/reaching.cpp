#include "reaching.h"

#include "opcodes.hh"

namespace ddd {

std::set<int> observable_values(const SsaFunction &fn, const PassContext &ctx) {
  std::set<int> roots;

  const std::vector<Storage> storages =
      observable_storage(ctx.abi(), ctx.translator());
  if (storages.empty())
    return roots;

  ReachingValues reaching(fn);

  // What a callee will read. A p-code CALL carries only its destination, so
  // without this the argument setup looks dead and gets deleted -- taking the
  // call's arguments with it.
  //
  // Every argument register is included, not a guessed-at prefix: a live-in
  // has no defining op, so naming it a root keeps nothing alive, and anything
  // the function actually wrote there was plausibly written for the call.
  if (ctx.abi() != nullptr && ctx.translator() != nullptr) {
    std::vector<Storage> arguments;
    for (const std::string &name : ctx.abi()->arguments) {
      Storage storage = register_storage(*ctx.translator(), name);
      if (storage.space != nullptr)
        arguments.push_back(storage);
    }

    fn.for_each_op([&](const SsaOp &op) {
      if (op.opc != ghidra::CPUI_CALL && op.opc != ghidra::CPUI_CALLIND)
        return;
      for (const Storage &storage : arguments) {
        SsaValue *value = reaching.before(op, storage);
        if (value != nullptr)
          roots.insert(value->id);
      }
    });
  }

  for (const SsaBlock &block : fn.blocks()) {
    // Anything that hands control back: an explicit return, or a block with
    // nowhere to go -- a fragment running off the end, or a tail call that
    // could not be resolved.
    const BasicBlock &raw = fn.cfg()[block.id];
    if (!raw.ends_in_return && !raw.succs.empty())
      continue;
    if (!fn.dominance().reachable(block.id))
      continue;

    for (const Storage &storage : storages) {
      SsaValue *value = reaching.at_exit(block.id, storage);
      if (value != nullptr)
        roots.insert(value->id);
    }
  }

  return roots;
}

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

SsaValue *ReachingValues::at_exit(int block, const Storage &storage) const {
  SsaValue *value = at_entry(block, storage);

  for (const SsaOp *phi : fn_[block].phis)
    if (phi->out != nullptr && phi->out->storage == storage)
      value = phi->out;
  for (const SsaOp *op : fn_[block].ops)
    if (op->out != nullptr && op->out->storage == storage)
      value = op->out;

  return value;
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
