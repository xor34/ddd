#include "ssa.h"

#include <map>
#include <set>
#include <unordered_map>

namespace ddd {

bool default_track_filter(const VarnodeData &vn) {
  if (vn.space == nullptr) return false;
  switch (vn.space->getType()) {
  case ghidra::IPTR_INTERNAL:
    return true; // Sleigh temporaries
  case ghidra::IPTR_PROCESSOR:
    // "ram" and friends are also IPTR_PROCESSOR; per-address SSA over memory
    // needs alias analysis first, so only registers are renamed.
    return vn.space->getName() == "register";
  default:
    return false;
  }
}

std::string SsaValue::name() const {
  const std::string base = label.empty() ? to_string(storage) : label;
  if (is_live_in()) return base + "#in";
  return base + "#" + std::to_string(version);
}

void SsaFunction::annotate(const SsaOp &op, std::string comment) {
  op_comments_[op.id].push_back(std::move(comment));
}

void SsaFunction::annotate_block(int block, std::string comment) {
  block_comments_[block].push_back(std::move(comment));
}

const std::vector<std::string> &SsaFunction::comments(const SsaOp &op) const {
  static const std::vector<std::string> none;
  auto it = op_comments_.find(op.id);
  return it == op_comments_.end() ? none : it->second;
}

const std::vector<std::string> &SsaFunction::block_comments(int block) const {
  static const std::vector<std::string> none;
  auto it = block_comments_.find(block);
  return it == block_comments_.end() ? none : it->second;
}

SsaOp &SsaFunction::new_op() {
  ops_.emplace_back();
  ops_.back().id = static_cast<int>(ops_.size()) - 1;
  return ops_.back();
}

SsaValue &SsaFunction::new_value() {
  values_.emplace_back();
  values_.back().id = static_cast<int>(values_.size()) - 1;
  return values_.back();
}

void SsaFunction::for_each_op(const std::function<void(SsaOp &)> &fn) {
  for (SsaBlock &block : blocks_) {
    for (SsaOp *phi : block.phis) fn(*phi);
    for (SsaOp *op : block.ops) fn(*op);
  }
}

void SsaFunction::for_each_op(const std::function<void(const SsaOp &)> &fn) const {
  for (const SsaBlock &block : blocks_) {
    for (const SsaOp *phi : block.phis) fn(*phi);
    for (const SsaOp *op : block.ops) fn(*op);
  }
}

void SsaFunction::rebuild_uses() {
  for (SsaValue &value : values_) value.uses.clear();
  for_each_op([](SsaOp &op) {
    for (SsaOperand &in : op.ins)
      if (in.value != nullptr) in.value->uses.push_back(&op);
  });
}

SsaFunction build_ssa(const Cfg &cfg, SsaOptions options) {
  SsaFunction fn;
  fn.cfg_ = &cfg;
  fn.dom_ = compute_dominance(cfg);
  fn.blocks_.resize(cfg.size());
  for (int b = 0; b < cfg.size(); ++b) fn.blocks_[b].id = b;
  if (cfg.empty() || cfg.entry < 0) return fn;

  const Dominance &dom = fn.dom_;
  const auto &track = options.track;

  // Storage of an op's destination, valid while `renames_output` is set.
  // Kept beside the ops rather than inside them: it is build scaffolding,
  // not part of the IR.
  std::vector<Storage> output_storage;
  std::vector<char> renames_output;

  auto note_output = [&](const SsaOp &op, Storage storage, bool renamed) {
    output_storage.resize(op.id + 1);
    renames_output.resize(op.id + 1, 0);
    output_storage[op.id] = storage;
    renames_output[op.id] = renamed ? 1 : 0;
  };

  // ---- 1. copy the p-code in, and collect def sites per storage ----
  // Ordered containers throughout: phi placement order decides the order
  // values are numbered, so an unordered_map here would make the whole IR
  // differ between runs.
  std::map<Storage, std::set<int>> def_sites;

  for (int b = 0; b < cfg.size(); ++b) {
    for (const PcodeOp &raw : cfg[b].ops) {
      SsaOp &op = fn.new_op();
      op.block = b;
      op.addr = raw.addr;
      op.opc = raw.opc;
      for (const VarnodeData &in : raw.inputs) op.ins.push_back(SsaOperand{in, nullptr});

      bool renamed = raw.has_output && dom.reachable(b) && track(raw.output);
      if (raw.has_output && !renamed) {
        op.has_raw_output = true;
        op.raw_output = raw.output;
      }
      note_output(op, raw.has_output ? storage_of(raw.output) : Storage{}, renamed);
      if (renamed) def_sites[storage_of(raw.output)].insert(b);

      fn.blocks_[b].ops.push_back(&op);
    }
  }

  // ---- 2. phis at the iterated dominance frontier of each storage ----
  for (const auto &entry : def_sites) {
    const Storage &storage = entry.first;
    std::vector<int> worklist(entry.second.begin(), entry.second.end());
    std::set<int> queued(entry.second.begin(), entry.second.end());
    std::set<int> placed;

    while (!worklist.empty()) {
      int b = worklist.back();
      worklist.pop_back();

      for (int d : dom.frontier[b]) {
        if (!placed.insert(d).second) continue;

        SsaOp &phi = fn.new_op();
        phi.block = d;
        phi.addr = cfg[d].start;
        phi.opc = ghidra::CPUI_MULTIEQUAL;
        phi.is_phi = true;
        phi.ins.resize(cfg[d].preds.size()); // operands patched during renaming
        note_output(phi, storage, true);
        fn.blocks_[d].phis.push_back(&phi);

        if (queued.insert(d).second) worklist.push_back(d);
      }
    }
  }

  // ---- 3. rename on a dominator-tree walk ----
  std::unordered_map<Storage, std::vector<SsaValue *>, StorageHash> stacks;
  std::unordered_map<Storage, int, StorageHash> next_version;
  std::unordered_map<Storage, SsaValue *, StorageHash> live_ins;

  // A use with nothing on its stack reads a value defined before the
  // function: a parameter, or genuinely uninitialised storage. One live-in
  // per storage, pushed at the bottom of the stack and never popped, so
  // every path sees the same one.
  auto live_in = [&](const Storage &storage) -> SsaValue * {
    auto it = live_ins.find(storage);
    if (it != live_ins.end()) return it->second;

    SsaValue &value = fn.new_value();
    value.storage = storage;
    value.version = next_version[storage]++;
    value.block = cfg.entry;
    live_ins[storage] = &value;
    stacks[storage].push_back(&value);
    return &value;
  };

  auto current = [&](const Storage &storage) -> SsaValue * {
    std::vector<SsaValue *> &stack = stacks[storage];
    return stack.empty() ? live_in(storage) : stack.back();
  };

  struct Frame {
    int block;
    size_t next_child = 0;
    std::vector<Storage> pushed;
  };
  std::vector<Frame> walk{Frame{cfg.entry}};
  std::vector<bool> entered(cfg.size(), false);

  while (!walk.empty()) {
    int b = walk.back().block;

    if (!entered[b]) {
      entered[b] = true;

      auto define = [&](SsaOp *op) {
        const Storage &storage = output_storage[op->id];
        SsaValue &value = fn.new_value();
        value.storage = storage;
        value.version = next_version[storage]++;
        value.block = b;
        value.def = op;
        op->out = &value;
        stacks[storage].push_back(&value);
        walk.back().pushed.push_back(storage);
      };

      for (SsaOp *phi : fn.blocks_[b].phis) define(phi);

      for (SsaOp *op : fn.blocks_[b].ops) {
        for (SsaOperand &in : op->ins)
          if (track(in.raw)) in.value = current(storage_of(in.raw));
        if (renames_output[op->id]) define(op);
      }

      // Hand this block's current values to the phis of every successor.
      // A block can appear twice in preds (a CBRANCH whose taken target is
      // also its fall-through), so patch every matching slot.
      for (const Edge &edge : cfg[b].succs) {
        const BasicBlock &succ = cfg[edge.target];
        if (fn.blocks_[edge.target].phis.empty()) continue;

        for (size_t i = 0; i < succ.preds.size(); ++i) {
          if (succ.preds[i] != b) continue;
          for (SsaOp *phi : fn.blocks_[edge.target].phis)
            phi->ins[i].value = current(output_storage[phi->id]);
        }
      }
    }

    Frame &top = walk.back();
    if (top.next_child < dom.children[b].size()) {
      walk.push_back(Frame{dom.children[b][top.next_child++]});
      continue;
    }

    for (const Storage &storage : top.pushed) stacks[storage].pop_back();
    walk.pop_back();
  }

  // A phi slot can still be empty if that predecessor is unreachable; give
  // it the live-in so no operand is left dangling.
  for (SsaBlock &block : fn.blocks_)
    for (SsaOp *phi : block.phis)
      for (SsaOperand &in : phi->ins)
        if (in.value == nullptr) in.value = live_in(output_storage[phi->id]);

  // ---- 4. def-use chains ----
  fn.rebuild_uses();
  return fn;
}

} // namespace ddd
