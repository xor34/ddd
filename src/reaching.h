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

#include "ssa.h"

#include <unordered_map>
#include <vector>

namespace ddd {

class ReachingValues {
public:
  explicit ReachingValues(const SsaFunction &fn);

  // The value of `storage` just before `op` executes, or null if nothing
  // reaches it (unreachable block, or storage that is never defined or read).
  SsaValue *before(const SsaOp &op, const Storage &storage) const;

  // The value of `storage` at the top of `block`.
  SsaValue *at_entry(int block, const Storage &storage) const;

private:
  const SsaFunction &fn_;
  std::vector<std::unordered_map<Storage, SsaValue *, StorageHash>> entry_;
};

} // namespace ddd
