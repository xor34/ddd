// reaching.h -- which SSA value of a given storage reaches a given point.
//
// SSA answers this for anything that appears as an operand, but not for
// storage an op never names. A CALL is the case that matters: in raw p-code it
// takes only its destination, so the argument registers are nowhere in its
// operand list, and a caller has to ask "what was in x0 here?".
//
// Answered by replaying build_ssa's dominator-tree walk once and keeping the
// map that was live at the top of each block.
#pragma once

#include "ir/ssa.h"

#include <set>
#include <unordered_map>
#include <vector>

namespace ddd {

struct Target;

class ReachingValues {
public:
  explicit ReachingValues(const SsaFunction &fn);

  // The value of `storage` just before `op` executes, or null if nothing
  // reaches it (unreachable block, or storage that is never defined or read).
  SsaValue *before(const SsaOp &op, const Varnode &storage) const;

  // The value of `storage` at the top of `block`.
  SsaValue *at_entry(BlockId block, const Varnode &storage) const;

  // The value of `storage` after everything in `block` has run.
  SsaValue *at_exit(BlockId block, const Varnode &storage) const;

private:
  const SsaFunction &fn_;
  std::vector<std::unordered_map<Varnode, SsaValue *, VarnodeHash>> entry_;
};

// Ids of the values something outside this function can see. Two sources,
// and the calling convention is the only thing that knows either:
//
//   * what the caller reads after we return -- the result register, the stack
//     pointer, the callee-saved registers
//   * what a callee reads when we call it -- the argument registers, which a
//     p-code CALL does not mention at all
//
// This is the part SSA cannot work out on its own: inside the function these
// values look unused. Dead-code elimination and expression folding both need
// it, for the same reason -- neither the function's own output nor the
// arguments it sets up must be mistaken for something nobody wanted.
//
// Empty when there is no calling convention to ask.
//
// Takes the Target rather than a PassContext: the convention, the translator
// and the spaces are the whole of what it needs from the machine, and asking
// for a context would make this analysis depend on the pass layer that calls
// it.
std::set<ValueId> observable_values(const SsaFunction &fn,
                                    const Target *target);

} // namespace ddd
