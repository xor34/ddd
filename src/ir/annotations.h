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

#include "ir/ssa.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace ddd {

// What a label names, beyond the name itself.
//
// stack-vars labels the address of a frame slot (`&var_18`), and the address of
// the slot a preserved register is saved in (`&saved_RBX`). Both are addresses
// *of* something a reader cares about, and that is a fact about the value the
// analysis needs: a load or store through one is written as the slot itself,
// and the line computing the address stops being worth showing.
//
// Which one a label was used to be spelled into it -- a leading '&' -- and
// every reader had to agree on the character. A semantic fact carried by a
// string is a fact anyone can spell wrong, and a label set by a script that
// happened to start with '&' became a frame slot. It is a field now; the '&'
// in the label text is only that text's own spelling, so the SSA listing can
// still show `&var_18#1` where the folded listing shows `var_18`.
//
// Not everything stack-vars labels is here: `sp-0x14` names a temporary holding
// the stack pointer, which is a pointer a reader may well want to see, and it
// is not the address of a variable at all.
enum class AddressKind {
  None,          // a label naming a value, not the address of one
  FrameSlot,     // the address of a variable of the program, living in the frame
  SavedRegister, // the address of a preserved register's home in the frame
};

// The two are the same thing to every caller that asks this: a slot the
// listing has a name for.
inline bool names_slot(AddressKind kind) { return kind != AddressKind::None; }

class Annotations {
public:
  void comment(const SsaOp &op, std::string text);
  void comment_block(BlockId block, std::string text);

  // `kind` is for the labels that name the address of something rather than a
  // value; everything else leaves it None. Set by the pass that knows, not
  // inferred from the spelling by the pass that reads it.
  void set_label(const SsaValue &value, std::string label,
                 AddressKind kind = AddressKind::None);

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
  const std::vector<std::string> &block_comments(BlockId block) const;

  // Empty when the value has no label; callers fall back to its storage name.
  const std::string &label(const SsaValue &value) const;
  bool has_label(const SsaValue &value) const { return !label(value).empty(); }

  // What that label names. None for an unlabelled value as well as for a
  // label that names a value outright.
  AddressKind address_kind(const SsaValue &value) const;

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

  // Marks an op as machine bookkeeping rather than program logic: saving a
  // callee-saved register, restoring it, keeping the stack pointer up to
  // date. The high-level listing hides these; --show_machine_state puts them
  // back.
  //
  // Set by the pass that worked it out, not guessed at by the printer.
  void mark_plumbing(const SsaOp &op);
  bool is_plumbing(const SsaOp &op) const;

  void clear();

private:
  std::map<OpId, std::vector<std::string>> op_comments_;
  std::map<BlockId, std::vector<std::string>> block_comments_;
  std::map<ValueId, std::string> labels_;
  std::map<ValueId, AddressKind> address_kinds_;
  std::map<ValueId, const SsaValue *> aliases_;
  std::map<ValueId, std::string> display_names_;
  std::set<OpId> plumbing_;
};

} // namespace ddd
