// dominance.h -- immediate dominators, dominator tree, dominance frontiers.
//
// Cooper/Harvey/Kennedy, "A Simple, Fast Dominance Algorithm" (2001). This is
// what SSA phi placement is built on; it is a pure graph algorithm and knows
// nothing about p-code.
#pragma once

#include "cfg.h"

#include <vector>

namespace ddd {

struct Dominance {
  std::vector<int> idom;                    // -1 for the entry and for unreachable blocks
  std::vector<std::vector<int>> children;   // dominator-tree children
  std::vector<std::vector<int>> frontier;   // DF(b), sorted and deduplicated
  std::vector<int> rpo;                     // reachable blocks, reverse postorder
  std::vector<int> rpo_index;               // position in rpo, -1 if unreachable

  bool reachable(int block) const { return rpo_index[block] >= 0; }
};

Dominance compute_dominance(const Cfg &cfg);

} // namespace ddd
