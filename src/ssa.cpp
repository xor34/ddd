#include "ssa.h"

#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace ddd {

bool default_track_filter(const Varnode &vn, const Spaces &spaces) {
  if (vn.space == kNoSpace)
    return false;
  if (vn.space == kUniqueSpace)
    return true; // Sleigh temporaries
  // "ram" and friends are also real addressable memory; per-address SSA over
  // it needs alias analysis first, so only the register bank is renamed.
  return spaces.is_kind(vn.space, SpaceKind::Register);
}

SsaOp &SsaFunction::new_op() {
  ops_.emplace_back();
  ops_.back().id = OpId{static_cast<int>(ops_.size()) - 1};
  return ops_.back();
}

SsaValue &SsaFunction::new_value() {
  values_.emplace_back();
  values_.back().id = ValueId{static_cast<int>(values_.size()) - 1};
  return values_.back();
}

void SsaFunction::for_each_op(const std::function<void(SsaOp &)> &fn) {
  for (SsaBlock &block : blocks_) {
    for (SsaOp *phi : block.phis)
      fn(*phi);
    for (SsaOp *op : block.ops)
      fn(*op);
  }
}

void SsaFunction::for_each_op(
    const std::function<void(const SsaOp &)> &fn) const {
  for (const SsaBlock &block : blocks_) {
    for (const SsaOp *phi : block.phis)
      fn(*phi);
    for (const SsaOp *op : block.ops)
      fn(*op);
  }
}

void SsaFunction::rebuild_uses() {
  for (SsaValue &value : values_)
    value.uses.clear();
  for_each_op([](SsaOp &op) {
    for (SsaOperand &in : op.ins) {
      if (in.value != nullptr) {
        in.value->uses.push_back(&op);
      }
    }
  });
}

namespace {

// Storage live on entry to each block, for pruned SSA.
//
// Cytron's placement puts a phi wherever a storage is defined on two paths,
// whether or not anything downstream ever reads it. That is most of the phis
// in a real function: every condition flag, and every Sleigh temporary, is
// written on both arms of every branch and read by neither.
//
// A phi for a storage that is not live at the join defines a value nobody
// wants, and -- because a phi counts as a use of all its operands -- keeps the
// entire dead computation feeding it alive through dead-code elimination too.
// So compute liveness first and place phis only where they mean something.
std::vector<std::unordered_set<Varnode, VarnodeHash>>
live_in_storage(const Cfg &cfg,
                const std::function<bool(const Varnode &)> &track,
                const std::vector<Varnode> &live_at_exit) {
  const int n = cfg.size();
  std::vector<std::unordered_set<Varnode, VarnodeHash>> uses(n), defs(n),
      live(n);

  for (int b = 0; b < n; ++b) {
    for (const PcodeOp &op : cfg[BlockId{b}].ops) {
      // Read before written in this block: live in.
      for (const Varnode &in : op.inputs) {
        if (!track(in)) continue;
        if (defs[b].count(in) == 0) uses[b].insert(in);
      }
      if (op.has_output && track(op.output))
        defs[b].insert(op.output);
    }
    live[b] = uses[b];

    // Anything the caller reads is live where control leaves the function.
    if (cfg[BlockId{b}].ends_in_return || cfg[BlockId{b}].succs.empty())
      for (const Varnode &storage : live_at_exit)
        if (defs[b].count(storage) == 0) live[b].insert(storage);
  }

  // live_in[b] = uses[b] | (union of live_in[succ] - defs[b])
  for (bool changed = true; changed;) {
    changed = false;

    for (int b = n; b-- > 0;) {
      for (const Edge &edge : cfg[BlockId{b}].succs) {
        for (const Varnode &storage : live[edge.target]) {
          if (defs[b].count(storage) != 0) continue;
          if (live[b].insert(storage).second) changed = true;
        }
      }
    }
  }

  return live;
}

} // namespace

SsaFunction build_ssa(const Cfg &cfg, SsaOptions options) {
  SsaFunction fn;
  fn.cfg_ = &cfg;
  fn.dom_ = compute_dominance(cfg);
  fn.blocks_.resize(cfg.size());
  for (int b = 0; b < cfg.size(); ++b)
    fn.blocks_[b].id = BlockId{b};
  if (cfg.empty() || !cfg.entry)
    return fn;

  const Dominance &dom = fn.dom_;
  const Spaces &spaces = fn.spaces();
  const auto &track = options.track
                          ? options.track
                          : [&spaces](const Varnode &vn) {
                              return default_track_filter(vn, spaces);
                            };

  // Storage of an op's destination, valid while `renames_output` is set.
  // Kept beside the ops rather than inside them: it is build scaffolding,
  // not part of the IR.
  std::vector<Varnode> output_storage;
  std::vector<char> renames_output;

  auto note_output = [&](const SsaOp &op, Varnode storage, bool renamed) {
    output_storage.resize(static_cast<size_t>(op.id.index) + 1);
    renames_output.resize(static_cast<size_t>(op.id.index) + 1, 0);
    output_storage[op.id] = storage;
    renames_output[op.id] = renamed ? 1 : 0;
  };

  // ---- 1. copy the p-code in, and collect def sites per storage ----
  // Ordered containers throughout: phi placement order decides the order
  // values are numbered, so an unordered_map here would make the whole IR
  // differ between runs.
  std::map<Varnode, std::set<BlockId>> def_sites;

  for (int b = 0; b < cfg.size(); ++b) {
    for (const PcodeOp &raw : cfg[BlockId{b}].ops) {
      SsaOp &op = fn.new_op();
      op.block = BlockId{b};
      op.addr = raw.addr;
      op.opc = raw.opc;

      for (const Varnode &in : raw.inputs) {
        op.ins.push_back(SsaOperand{in, nullptr});
      }

      bool renamed = raw.has_output && dom.reachable(BlockId{b}) &&
                     track(raw.output);
      if (raw.has_output && !renamed) {
        op.has_raw_output = true;
        op.raw_output = raw.output;
      }

      // Plain storage identity, no extra scoping: Sleigh itself or's the
      // instruction's address bits into every unique-space offset it emits,
      // so a temporary already belongs to the instruction that wrote it, and
      // one reused offset does not become one function-wide variable that
      // every join gets a phi for.
      note_output(op, raw.has_output ? raw.output : Varnode{}, renamed);

      if (renamed) {
        def_sites[raw.output].insert(BlockId{b});
      }

      fn.blocks_[b].ops.push_back(&op);
    }
  }

  // ---- 2. phis at the iterated dominance frontier of each storage ----
  const std::vector<std::unordered_set<Varnode, VarnodeHash>> live =
      live_in_storage(cfg, track, options.live_at_exit);

  for (const auto &entry : def_sites) {
    const Varnode &storage = entry.first;
    std::vector<BlockId> worklist(entry.second.begin(), entry.second.end());
    std::set<BlockId> queued(entry.second.begin(), entry.second.end());
    std::set<BlockId> placed;

    while (!worklist.empty()) {
      BlockId b = worklist.back();
      worklist.pop_back();

      for (BlockId d : dom.frontier[b]) {
        // Pruned: no phi where the value is already dead.
        if (live[d].count(storage) == 0)
          continue;
        if (!placed.insert(d).second)
          continue;

        SsaOp &phi = fn.new_op();
        phi.block = d;
        phi.addr = cfg[d].start;
        phi.is_phi = true;
        phi.ins.resize(cfg[d].preds.size()); // operands patched during renaming
        note_output(phi, storage, true);
        fn.blocks_[d].phis.push_back(&phi);

        if (queued.insert(d).second)
          worklist.push_back(d);
      }
    }
  }

  // ---- 3. rename on a dominator-tree walk ----
  std::unordered_map<Varnode, std::vector<SsaValue *>, VarnodeHash> stacks;
  std::unordered_map<Varnode, int, VarnodeHash> next_version;
  std::unordered_map<Varnode, SsaValue *, VarnodeHash> live_ins;

  // A use with nothing on its stack reads a value defined before the
  // function: a parameter, or genuinely uninitialised storage. One live-in
  // per storage, pushed at the bottom of the stack and never popped, so
  // every path sees the same one.
  auto live_in = [&](const Varnode &storage) -> SsaValue * {
    auto it = live_ins.find(storage);
    if (it != live_ins.end())
      return it->second;

    SsaValue &value = fn.new_value();
    value.storage = storage;
    value.version = next_version[storage]++;
    value.block = *cfg.entry;
    live_ins[storage] = &value;
    stacks[storage].push_back(&value);
    return &value;
  };

  auto current = [&](const Varnode &storage) -> SsaValue * {
    std::vector<SsaValue *> &stack = stacks[storage];
    return stack.empty() ? live_in(storage) : stack.back();
  };

  struct Frame {
    BlockId block;
    size_t next_child = 0;
    std::vector<Varnode> pushed;
  };

  std::vector<Frame> walk{Frame{*cfg.entry}};
  std::vector<bool> entered(cfg.size(), false);

  while (!walk.empty()) {
    BlockId b = walk.back().block;

    if (!entered[b]) {
      entered[b] = true;

      auto define = [&](SsaOp *op) {
        const Varnode &storage = output_storage[op->id];
        SsaValue &value = fn.new_value();
        value.storage = storage;
        value.version = next_version[storage]++;
        value.block = b;
        value.def = op;
        op->out = &value;
        stacks[storage].push_back(&value);
        walk.back().pushed.push_back(storage);
      };

      for (SsaOp *phi : fn.blocks_[b].phis)
        define(phi);

      for (SsaOp *op : fn.blocks_[b].ops) {
        for (SsaOperand &in : op->ins)
          if (track(in.raw))
            in.value = current(in.raw);
        if (renames_output[op->id])
          define(op);
      }

      // Hand this block's current values to the phis of every successor.
      // A block can appear twice in preds (a CBRANCH whose taken target is
      // also its fall-through), so patch every matching slot.
      for (const Edge &edge : cfg[b].succs) {
        const BasicBlock &succ = cfg[edge.target];
        if (fn.blocks_[edge.target].phis.empty())
          continue;

        for (size_t i = 0; i < succ.preds.size(); ++i) {
          if (succ.preds[i] != b)
            continue;
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

    for (const Varnode &storage : top.pushed)
      stacks[storage].pop_back();
    walk.pop_back();
  }

  // A phi slot can still be empty if that predecessor is unreachable; give
  // it the live-in so no operand is left dangling.
  for (SsaBlock &block : fn.blocks_) {
    for (SsaOp *phi : block.phis) {
      for (SsaOperand &in : phi->ins) {
        if (in.value == nullptr) {
          in.value = live_in(output_storage[phi->id]);
        }
      }
    }
  }

  // ---- 4. def-use chains ----
  fn.rebuild_uses();
  return fn;
}

} // namespace ddd
