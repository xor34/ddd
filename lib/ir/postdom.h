// postdom.h -- postdominance: which blocks every way out has to pass through.
//
// This is dominance run on the reversed graph, with one virtual exit that
// every block able to leave the function points at. The construction is the
// whole of it: the reversed graph is a Cfg like any other, so
// compute_dominance needs no change, and BlockId{n} -- one past the last real
// block -- is a legitimate id the algorithm already sizes its vectors for.
//
// A separate type from Dominance rather than a second function on it, because
// the two are read in opposite directions and their traps are opposite too.
// Everything below is stated in terms of what a caller asks, never in terms of
// the reversed graph, which nothing outside this file should have to hold in
// its head:
//
//   * `can_exit(b)` is "b can reach an *exit*". It is **not** "b is
//     reachable". Membership in a function is still
//     `fn.dominance().reachable(b)` -- the reversed graph's entry is the
//     virtual exit, so what it reaches is a different question entirely, and
//     the two answers are unrelated for every block that is not the entry.
//   * `ipdom(b)` is absent when b *leaves the function*: its immediate
//     postdominator is the virtual exit, and "continue at the exit" is not
//     something a structurizer can be handed. Absent too when b cannot reach
//     an exit at all, where there is no join to name.
//
// An exit is a block with nowhere to go -- a return, the fall off the end --
// or one whose branch goes somewhere this function does not contain, whether
// that is a tail call or a computed jump the sweep never resolved. Both are
// read here, because a *conditional* tail call has a successor and a way out
// at once and both have to be counted.
#pragma once

#include "decode/cfg.h"
#include "ir/dominance.h"

#include <optional>

namespace ddd {

class PostDom {
public:
  explicit PostDom(const Cfg &cfg);

  // True when some path from this block reaches an exit.
  bool can_exit(BlockId block) const;

  // The first block every path out of this one meets, when they all meet one.
  // Absent when this block leaves the function, when it cannot reach an exit,
  // and for a Cfg with no entry at all.
  std::optional<BlockId> ipdom(BlockId block) const;

  // True when control leaving `block` must pass through `dominator`: every
  // path to an exit goes through it. Reflexive for a block that can reach an
  // exit, and false for one that cannot -- a block with no way out has no path
  // for anything to be on.
  bool postdominates(BlockId dominator, BlockId block) const;

private:
  // One past the last real block, in the reversed graph only.
  BlockId exit_;
  int blocks_ = 0;
  Dominance dom_;
};

} // namespace ddd
