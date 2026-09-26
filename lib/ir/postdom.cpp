#include "ir/postdom.h"

namespace ddd {
namespace {

// Does control leave the function here?
//
// Either there is nowhere to go -- a return, the fall off the end, a computed
// jump nothing resolved -- or the branch names somewhere the sweep did not
// make a block of, which is where leaves_to is set and a tail call ends up.
// The second test is what a block with a successor can still be an exit on:
// the conditional tail call, whose other edge continues inside the function.
bool leaves(const Cfg &cfg, BlockId block) {
  return cfg[block].succs.empty() || cfg[block].leaves_to != Addr{};
}

} // namespace

PostDom::PostDom(const Cfg &cfg) : blocks_(cfg.size()) {
  // One past the last real block. Every block that can leave points at it, so
  // "which blocks can this one not get past" has an answer even for a function
  // with a dozen returns, and the answer is the same shaped answer as
  // dominance -- the same algorithm, on the reversed graph.
  exit_ = BlockId{blocks_};

  Cfg reversed;
  reversed.entry = exit_;
  reversed.spaces = cfg.spaces;
  reversed.code_space = cfg.code_space;
  reversed.blocks.resize(blocks_ + 1);
  for (int i = 0; i <= blocks_; ++i)
    reversed.blocks[i].id = BlockId{i};

  for (int i = 0; i < blocks_; ++i) {
    const BlockId block{i};
    for (const Edge &edge : cfg[block].succs)
      reversed[edge.target].succs.push_back(Edge{block, edge.conditional});

    if (leaves(cfg, block))
      reversed[exit_].succs.push_back(Edge{block, false});
  }

  reversed.refresh_preds();
  dom_ = compute_dominance(reversed);
}

bool PostDom::can_exit(BlockId block) const {
  if (block.index < 0 || block.index >= blocks_)
    return false;
  return dom_.reachable(block);
}

std::optional<BlockId> PostDom::ipdom(BlockId block) const {
  if (!can_exit(block) || !dom_.idom[block])
    return std::nullopt;

  // The virtual exit is not a block anything can be told to continue at, so
  // reaching it *is* the statement "this block leaves the function".
  if (*dom_.idom[block] == exit_)
    return std::nullopt;

  return dom_.idom[block];
}

bool PostDom::postdominates(BlockId dominator, BlockId block) const {
  // A block with no way out has no path for anything to be on -- including its
  // own. Answering true there would be the vacuous reading, and the vacuous
  // reading is the one that talks a structurizer into a join that never
  // happens.
  if (!can_exit(block))
    return false;

  for (std::optional<BlockId> at = block; at; at = ipdom(*at))
    if (*at == dominator)
      return true;

  return false;
}

} // namespace ddd
