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

  const std::vector<std::string> &comments(const SsaOp &op) const;
  const std::vector<std::string> &block_comments(int block) const;

  // Empty when the value has no label; callers fall back to its storage name.
  const std::string &label(const SsaValue &value) const;
  bool has_label(const SsaValue &value) const { return !label(value).empty(); }

  void clear();

private:
  std::map<int, std::vector<std::string>> op_comments_;
  std::map<int, std::vector<std::string>> block_comments_;
  std::map<int, std::string> labels_;
};

} // namespace ddd
