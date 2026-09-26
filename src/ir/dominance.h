// dominance.h -- immediate dominators, dominator tree, dominance frontiers.
//
// Cooper/Harvey/Kennedy, "A Simple, Fast Dominance Algorithm" (2001). This is
// what SSA phi placement is built on; it is a pure graph algorithm and knows
// nothing about p-code.
#pragma once

#include "decode/cfg.h"

#include <optional>
#include <vector>

namespace ddd {

struct Dominance {
  // Immediate dominator, per block: nullopt for the entry and for
  // unreachable blocks -- "no immediate dominator" is the absence of a
  // BlockId, not a -1 somebody has to remember.
  std::vector<std::optional<BlockId>> idom;
  std::vector<std::vector<BlockId>> children; // dominator-tree children
  std::vector<std::vector<BlockId>> frontier; // DF(b), sorted and deduplicated
  std::vector<BlockId> rpo;    // reachable blocks, reverse postorder
  std::vector<int> rpo_index;  // position in rpo, -1 if unreachable

  bool reachable(BlockId block) const { return rpo_index[block] >= 0; }
};

Dominance compute_dominance(const Cfg &cfg);

} // namespace ddd
