// annotations.h -- what analysis concluded, kept out of the IR.
//
// Comments and display names are not part of SSA. An SsaOp computes the same
// thing whether or not anyone has written a sentence about it, and two
// analyses of one function should be able to disagree about naming without
// either mutating the other's IR. So they live here, in a side table the
// passes share, and SsaFunction stays a pure IR container.
//
// Keyed by SsaOp::id / SsaValue::id, not by address:
//   * ids are stable. build_ssa assigns them once and no pass renumbers or
//     reorders; the only structural edit any pass makes is prune-phis
//     unlinking a phi from its block, which correctly drops its comments from
//     the listing too.
//   * one machine instruction lowers to many p-code ops, so an address cannot
//     say which op a comment is about.
#pragma once

#include "ssa.h"

#include <map>
#include <string>
#include <vector>

namespace ddd {

class Annotations {
public:
  void comment(const SsaOp &op, std::string text);
  void comment_block(int block, std::string text);
  void set_label(const SsaValue &value, std::string label);

  // Record that `value` is the same variable as `source` -- what a COPY
  // means. Uses of `value` then display as `source`, which is the point:
  // `EAX#1 = INT_ADD EBX#in 0x1` says what the code does, where
  // `EAX#1 = INT_ADD EAX#0 0x1` makes you go and look up EAX#0.
  //
  // A definition is still printed under its own name, so the copy itself
  // stays visible.
  void set_alias(const SsaValue &value, const SsaValue &source);

  // Follows the alias chain to the value that should be displayed. Returns
  // `value` itself when it is not an alias.
  const SsaValue &canonical(const SsaValue &value) const;

  const std::vector<std::string> &comments(const SsaOp &op) const;
  const std::vector<std::string> &block_comments(int block) const;

  // Empty when the value has no label; callers fall back to its storage name.
  const std::string &label(const SsaValue &value) const;
  bool has_label(const SsaValue &value) const { return !label(value).empty(); }

  // A *complete* variable name, versions and all folded in -- what the
  // high-level listing calls this value.
  //
  // Separate from a label because the two views want different things. The SSA
  // listing needs `var_18#0` and `var_18#1` to stay distinguishable, so a
  // label names only the storage part and the version is still appended. The
  // folded listing has no versions in it, so its names must already be unique
  // on their own; `name-vars` is what makes them so.
  void set_display_name(const SsaValue &value, std::string name);
  const std::string &display_name(const SsaValue &value) const;
  bool has_display_name(const SsaValue &value) const {
    return !display_name(value).empty();
  }

  void clear();

private:
  std::map<int, std::vector<std::string>> op_comments_;
  std::map<int, std::vector<std::string>> block_comments_;
  std::map<int, std::string> labels_;
  std::map<int, const SsaValue *> aliases_;
  std::map<int, std::string> display_names_;
};

} // namespace ddd
