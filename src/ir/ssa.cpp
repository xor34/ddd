#include "ir/ssa.h"

#include "decode/target.h"

#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace ddd {

SsaOptions ssa_options(const Target &target) {
  SsaOptions options;
  if (target.spaces == nullptr)
    return options;

  options.live_at_exit =
      observable_storage(target.abi, target.translator, *target.spaces);
  options.calls = call_effects(target.abi, target.translator, *target.spaces);
  return options;
}

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

// A constant operand. Sleigh keeps a constant's value truncated to its own
// width, and everything downstream reads width from `size` and bits from
// `offset`, so this does the same rather than leaving a 64-bit negation under
// a one-byte name.
Varnode const_varnode(int64_t value, uint32_t size) {
  return Varnode{kConstantSpace, static_cast<uint64_t>(value) & mask_for(size),
                 size};
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

  // Liveness first: it is a property of the p-code, and both phi placement
  // below and the call effects just beneath want it.
  const std::vector<std::unordered_set<Varnode, VarnodeHash>> live =
      live_in_storage(cfg, track, options.live_at_exit);

  const CallEffects &calls = options.calls;
  const bool call_effects = calls.valid();

  // Every storage the function names anywhere. Two questions about a call are
  // about the whole function rather than the block it is in: which widths of
  // the result register it reads, and which registers it reads at all.
  std::set<Varnode> mentioned;
  if (call_effects) {
    for (const BasicBlock &block : cfg.blocks) {
      for (const PcodeOp &op : block.ops) {
        for (const Varnode &in : op.inputs)
          if (track(in)) mentioned.insert(in);
        if (op.has_output && track(op.output)) mentioned.insert(op.output);
      }
    }
  }

  // Whether the call instruction may destroy this storage and leave nothing
  // the listing can name. Everything is fair game except what the convention
  // promises back -- the same list `observable_storage` is built from -- and
  // the two things a call does model precisely: its own result, which it
  // defines rather than destroys, and the stack pointer, whose movement is
  // arithmetic and not an unknown.
  auto destroyed_by_a_call = [&](const Varnode &storage) {
    if (!spaces.is_kind(storage.space, SpaceKind::Register)) return false;
    if (same_register(storage, calls.result)) return false;
    if (storage == calls.stack_pointer) return false;
    for (const Varnode &kept : calls.preserved)
      if (same_register(kept, storage)) return false;
    return true;
  };

  // What a call may destroy that still matters: the storages something reads
  // after it, before anything writes them again. Sparse and per block -- an
  // entry only where a call is.
  //
  // Liveness on entry to a block is not this question and is not a safe
  // substitute for it. A register written earlier in the block and read after
  // the call is live at the call and is neither live-in here nor live-in to
  // any successor, so a test built out of those two goes blind on exactly the
  // shape a clobber is about:
  //
  //     ECX = 0x5      ; not live-in, ECX is defined right here
  //     CALL f
  //     ... read ECX   ; not live-in to any successor, the read is in this block
  //
  // So the question is asked by a backward pass over the block's own ops --
  // the only walk that sees the definition and the read in one place -- and
  // the answer is keyed by the call's op id, which both the placement below
  // and the renaming walk consult.
  std::map<OpId, std::set<Varnode>> live_after_a_call;

  // Read at or after this point, per block, for the pass to consult.
  std::vector<std::map<size_t, std::set<Varnode>>> after_a_call(cfg.size());

  if (call_effects) {
    for (int b = 0; b < cfg.size(); ++b) {
      const BasicBlock &block = cfg[BlockId{b}];

      std::set<Varnode> after;
      for (const Edge &edge : block.succs)
        after.insert(live[edge.target].begin(), live[edge.target].end());
      // Nowhere left to go means the function ends here, and what the caller
      // reads is read from there. `live[b]` cannot stand in: it leaves out
      // everything this block defines, which is the case that matters.
      if (block.succs.empty())
        after.insert(options.live_at_exit.begin(), options.live_at_exit.end());

      for (size_t i = block.ops.size(); i-- > 0;) {
        const PcodeOp &raw = block.ops[i];

        if (raw.opc == Op::CALL || raw.opc == Op::CALLIND) {
          std::set<Varnode> wanted;
          for (const Varnode &storage : after)
            if (destroyed_by_a_call(storage))
              wanted.insert(storage);
          after_a_call[b][i] = std::move(wanted);
        }

        // Undo this op: what it wrote stops being live here, what it read
        // starts.
        if (raw.has_output && track(raw.output)) after.erase(raw.output);
        for (const Varnode &in : raw.inputs)
          if (track(in)) after.insert(in);
      }
    }
  }

  // ---- 1. copy the p-code in, and collect def sites per storage ----
  // Ordered containers throughout: phi placement order decides the order
  // values are numbered, so an unordered_map here would make the whole IR
  // differ between runs.
  std::map<Varnode, std::set<BlockId>> def_sites;

  for (int b = 0; b < cfg.size(); ++b) {
    const std::vector<PcodeOp> &raw_ops = cfg[BlockId{b}].ops;
    for (size_t index = 0; index < raw_ops.size(); ++index) {
      const PcodeOp &raw = raw_ops[index];
      const bool is_call = raw.opc == Op::CALL || raw.opc == Op::CALLIND;

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

      // A call produces a value its own p-code says nothing about: the
      // convention's result register holds the callee's answer from the moment
      // control comes back. Everything else the call does is added after it
      // during renaming, where the state each effect starts from is known; the
      // def sites it makes are not, because phi placement has already been
      // decided by then. So the same set of effects has to be worked out here
      // as well, and the two have to agree -- a clobber the walk creates but
      // placement did not know about is a definition no join merges.
      if (call_effects && is_call && dom.reachable(BlockId{b})) {
        // Where the call's effects are needed, kept for the walk to read.
        auto found = after_a_call[b].find(index);
        if (found != after_a_call[b].end())
          live_after_a_call[op.id] = found->second;

        if (track(calls.result)) {
          note_output(op, calls.result, true);
          def_sites[calls.result].insert(BlockId{b});
        }

        // The narrower widths of the result register are the same arrival read
        // at a different width -- see the SUBPIECE added after the call during
        // renaming -- and they need a def site here for the same reason the
        // result does. Everything else the call may destroy is a def site only
        // where something reads it afterwards: a register nobody looks at
        // again is not worth a phi at the next join.
        for (const Varnode &storage : mentioned) {
          if (same_register(storage, calls.result)) {
            if (track(calls.result) && storage.size < calls.result.size)
              def_sites[storage].insert(BlockId{b});
          } else if (destroyed_by_a_call(storage) &&
                     live_after_a_call[op.id].count(storage) != 0) {
            def_sites[storage].insert(BlockId{b});
          }
        }

        // The stack pointer the call gives back is a definition of it like any
        // other, and a join where one path called and the other did not needs
        // to know that.
        if (calls.stack_delta != 0 && track(calls.stack_pointer))
          def_sites[calls.stack_pointer].insert(BlockId{b});
      }

      fn.blocks_[b].ops.push_back(&op);
    }
  }

  // ---- 2. phis at the iterated dominance frontier of each storage ----
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

      // What a call did to the caller, written down where it happened: right
      // after the call op, so that each effect reads the state the call left
      // -- the answer for the register's narrower widths, the pushed stack
      // pointer for the return -- and everything below sees what they defined.
      //
      // Appended while the loop walks, so the ops added here are renamed by it
      // in turn; hence the index rather than a range over a growing vector.
      auto call_effects_after = [&](const SsaOp &call) {
        const auto append = [&](Op opc, std::vector<SsaOperand> ins,
                                Varnode out, bool clobber) {
          SsaOp &effect = fn.new_op();
          effect.block = b;
          effect.addr = call.addr;
          effect.opc = opc;
          effect.is_clobber = clobber;
          effect.ins = std::move(ins);
          note_output(effect, out, true);
          fn.blocks_[b].ops.push_back(&effect);
        };

        const auto wanted = live_after_a_call.find(call.id);

        // The registers the callee is free to have destroyed. Only where
        // something reads the storage afterwards -- the same set the def sites
        // above were registered from -- and not where it already holds the
        // leftovers of an earlier call on this path, because redefining an
        // unknown only gives it a second name.
        if (wanted != live_after_a_call.end())
          for (const Varnode &storage : wanted->second) {
            if (current(storage)->is_clobber()) continue;
            append(Op::COPY, {}, storage, true);
          }

        // Reading EAX where the convention names RAX is reading the low bytes
        // of the same arrival: the width is the register's, and the renderer
        // reads through it the same way it reads through Sleigh's widening of
        // a 32-bit write. Without this the call's answer only reaches the one
        // width the ABI spells, and every 32-bit use of it reads whatever the
        // register held before the call -- which is how `f(x) + 1` came out as
        // `x + 1`.
        if (track(calls.result))
          for (const Varnode &storage : mentioned) {
            if (!same_register(storage, calls.result)) continue;
            if (storage.size >= calls.result.size) continue;
            append(Op::SUBPIECE,
                   {SsaOperand{calls.result, nullptr},
                    SsaOperand{const_varnode(0, calls.result.size), nullptr}},
                   storage, false);
          }

        // And the stack pointer, given back by the callee's return. This one
        // is arithmetic rather than an unknown, because it is the whole reason
        // a frame access after a call is at a different offset than a
        // frame-pointer-less function would compute.
        if (calls.stack_delta != 0 && track(calls.stack_pointer)) {
          append(Op::INT_ADD,
                 {SsaOperand{calls.stack_pointer, nullptr},
                  SsaOperand{const_varnode(calls.stack_delta,
                                           calls.stack_pointer.size),
                             nullptr}},
                 calls.stack_pointer, false);
        }
      };

      std::vector<SsaOp *> &ops = fn.blocks_[b].ops;
      for (size_t i = 0; i < ops.size(); ++i) {
        SsaOp *op = ops[i];
        for (SsaOperand &in : op->ins)
          if (track(in.raw))
            in.value = current(in.raw);
        if (renames_output[op->id])
          define(op);

        if (call_effects && (op->opc == Op::CALL || op->opc == Op::CALLIND))
          call_effects_after(*op);
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
