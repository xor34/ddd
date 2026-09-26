// loops.h -- natural loops: back edges, the body each one encloses, and where
// it lets go.
//
// Forward dominators only, which is all a natural loop needs. A back edge is
// an edge t->h where h dominates t; the loop it closes is h together with
// everything that can reach t without passing through h. Single-entry by
// construction -- the header is the only way in -- so nothing here has to
// check for a second entrance, and a cycle whose back edge fails the dominator
// test is simply not a natural loop. That is the irreducible case, and it is
// not turned into a loop at all rather than turned into a wrong one.
//
// What the caller gets is the shape, not a decision about how to print it:
// which block opens the loop, which blocks close it, what is inside, and what
// it leaves to. Whether that becomes a `do-while`, a `while (1)` or a wall of
// labels is the listing's business.
#pragma once

#include "decode/cfg.h"
#include "ir/dominance.h"

#include <map>
#include <vector>

namespace ddd {

struct Loop {
  BlockId header;

  // The header and everything that can reach a latch without passing it.
  // Sorted, which is also the order a caller can walk it in and get a stable
  // listing.
  std::vector<BlockId> blocks;

  // The blocks whose edge back to the header closes the loop. Two back edges
  // into one header are one loop with two latches, not two loops: they enclose
  // the same header and would be printed as nested loops around it, which is
  // not what the CFG says.
  std::vector<BlockId> latches;

  // Every block outside the loop that a block inside it branches to, sorted
  // and deduplicated. Empty for a loop that never lets go -- one of the two
  // ways to be a loop with no follow, the other being a body that only ever
  // leaves the function.
  std::vector<BlockId> exits;

  // A bit per block rather than a search of `blocks`: containment is asked
  // once per edge as the listing walks, and a linear search of a vector is the
  // kind of thing that is fine until a function with a thousand blocks in one
  // loop turns up.
  std::vector<bool> contains_;

  bool contains(BlockId block) const {
    return block.index >= 0 && block.index < static_cast<int>(contains_.size())
               ? contains_[block]
               : false;
  }
};

class Loops {
public:
  // `dom` must be the dominance of the same Cfg -- the back edges are found
  // through it, and a mismatched pair would find edges that are not there.
  Loops(const Cfg &cfg, const Dominance &dom);

  // The loop this block opens, or null when it opens none. One loop per
  // header, which is what merging the back edges buys.
  const Loop *at_header(BlockId block) const;

  const std::vector<Loop> &all() const { return loops_; }

private:
  std::vector<Loop> loops_;
  std::map<BlockId, int> by_header_;
};

} // namespace ddd
