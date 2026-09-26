// knowledge.h -- the store: what the analyses concluded about a function.
//
// An analysis records a typed fact. A renderer reads facts and states them.
// Prose is what is left when there is no fact -- and nothing may parse prose.
//
// The alternative is what this replaces: an analysis that has worked something
// out writes it down as a sentence, and the next analysis that wants to know it
// slices the sentence back apart. `stack-vars` knows a slot's identity as an
// offset and wrote `&var_18`; four consumers recovered the offset by parsing
// the name. A fact spelled as text is a fact anyone can spell wrong, and a
// label set by a script that happened to start with '&' became a frame slot.
//
// So knowledge is typed here, and the sentences are derived from it. The prose
// channel survives for what is genuinely prose -- a comment the person wrote, a
// note a script chose to leave -- and for nothing else.
//
// The store names no fact. A fact is a struct in this directory that says what
// it is keyed by:
//
//   // facts/slot.h
//   struct Slot { using Key = ValueId; int64_t offset; ... };
//
// and then set<Slot>(value.id, slot), get<Slot>(value.id), has<Slot>(...) all
// work without the store knowing what a Slot is. **Adding a fact is one new
// header here and no edit to this one** -- which is the point. This class used
// to declare every fact's fields, its own map, its entry in clear(), and its
// Lua binding, so a layer with no business knowing what an analysis concluded
// was the layer you had to edit to record a new conclusion.
//
// What stays here is what the *listing* does with those conclusions rather than
// a conclusion itself: a value's label, its display name, the alias walk that
// reads them, and the note channel. An analysis concludes `Slot`; "and here is
// how it is spelled" is the listing's business.
//
// None of this is part of SSA. An SsaOp computes the same thing whether or not
// anyone has concluded anything about it, and two analyses of one function
// should be able to disagree without either mutating the other's IR. So it
// lives here, in a side table the passes share, and SsaFunction stays a pure IR
// container.
//
// Keyed by SsaOp::id / SsaValue::id, not by address:
//   * ids are stable. build_ssa assigns them once and no pass renumbers or
//     reorders; the only structural edit any pass makes is prune-phis
//     unlinking a phi from its block, which correctly drops its comments from
//     the listing too.
//   * one machine instruction lowers to many p-code ops, so an address cannot
//     say which op a comment is about.
#pragma once

#include "facts/notes.h"
#include "ir/ssa.h"

#include <map>
#include <memory>
#include <set>
#include <string>
#include <typeindex>
#include <vector>

namespace ddd {

// A fact's rows with the fact's type erased away, so the store can hold facts
// it has never heard of. One map per fact type per function, allocated the
// first time that fact is recorded -- a function with no slots pays nothing
// for the capability.
class FactTable {
public:
  template <class F>
  void set(const typename F::Key &key, F fact) {
    rows<F>().by_key[key] = std::move(fact);
  }

  // Null when nothing was recorded under that key -- the absence says "no
  // analysis concluded this", which is what a caller wants to know.
  template <class F>
  const F *get(const typename F::Key &key) const {
    const Rows<F> *table = rows_if<F>();
    if (!table) return nullptr;

    auto it = table->by_key.find(key);
    return it == table->by_key.end() ? nullptr : &it->second;
  }

  template <class F>
  bool has(const typename F::Key &key) const {
    return get<F>(key) != nullptr;
  }

private:
  struct Base {
    virtual ~Base() = default;
  };

  template <class F>
  struct Rows final : Base {
    std::map<typename F::Key, F> by_key;
  };

  template <class F>
  Rows<F> &rows() {
    const std::type_index type(typeid(F));

    auto it = tables_.find(type);
    if (it == tables_.end())
      it = tables_.emplace(type, std::make_unique<Rows<F>>()).first;

    return static_cast<Rows<F> &>(*it->second);
  }

  template <class F>
  const Rows<F> *rows_if() const {
    auto it = tables_.find(std::type_index(typeid(F)));
    if (it == tables_.end()) return nullptr;
    return static_cast<const Rows<F> *>(it->second.get());
  }

  std::map<std::type_index, std::unique_ptr<Base>> tables_;
};

class Knowledge {
public:
  // Facts an analysis concluded. Which struct, and what it is keyed by, is the
  // fact's business -- see the file comment.
  template <class F>
  void set(const typename F::Key &key, F fact) {
    facts_.set<F>(key, std::move(fact));
  }

  template <class F>
  const F *get(const typename F::Key &key) const {
    return facts_.get<F>(key);
  }

  template <class F>
  bool has(const typename F::Key &key) const {
    return facts_.has<F>(key);
  }

  // Prose, and only prose: a sentence someone chose to write. What this tree
  // calls a note is the derived kind -- see notes() below.
  void comment(const SsaOp &op, std::string text);
  void comment_block(BlockId block, std::string text);

  // Everything there is to say about this op: the prose recorded against it,
  // and the sentences its facts imply, in the order they were recorded.
  //
  // One list, because a renderer should not have to know which kind of
  // knowledge a line came from. Every renderer prints through here, so a fact
  // that starts being recorded does not change a single renderer -- the same
  // sentence simply arrives from the fact instead of from a comment, and the
  // output does not move.
  //
  // Derived rather than stored, so it cannot fall out of step with the facts
  // it is derived from, and so an analysis that reads an op's notes is reading
  // the same thing a reader will.
  std::vector<std::string> notes(const SsaOp &op) const;

  // A points-at is about an *op* rather than about a value, so it is recorded
  // as a note and read back out of the note list. Recorded in the order found,
  // and every one of them is stated: one op can carry a resolved data
  // reference and the name of the function it hands that pointer to, and
  // dropping either would lose something the listing said.
  void set_points_at(const SsaOp &op, PointsAt what);
  // Derived from the notes rather than stored beside them: two tables holding
  // one fact are two tables that can disagree.
  std::vector<PointsAt> points_at(const SsaOp &op) const;

  // Where this call goes, named when the container had a name for it.
  //
  // Not a PointsAt, though the two read alike: a call's destination is not one
  // of its constants, and what it says is about the control flow rather than
  // about the value the call leaves behind. A reader of a call's *result* is
  // asking a different question, and answering it with the callee's name would
  // type every call as a function pointer.
  void set_callee(const SsaOp &call, std::string name);
  const std::string *callee(const SsaOp &call) const;

  // A name for a value, empty when it has none; callers fall back to its
  // storage name. Set by the pass that knows what the value is, never inferred
  // by the pass that reads it from how the name happens to be spelled.
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

  const std::vector<std::string> &block_comments(BlockId block) const;

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

  // Marks an op as machine bookkeeping rather than program logic: saving a
  // callee-saved register, restoring it, keeping the stack pointer up to
  // date. The high-level listing hides these; --show_machine_state puts them
  // back.
  //
  // Set by the pass that worked it out, not guessed at by the printer.
  void mark_plumbing(const SsaOp &op);
  bool is_plumbing(const SsaOp &op) const;

private:
  FactTable facts_;

  // Everything said about an op, prose and facts alike, in the order it was
  // said. See Note.
  std::map<OpId, std::vector<Note>> op_notes_;
  std::map<BlockId, std::vector<std::string>> block_comments_;
  std::map<ValueId, std::string> labels_;
  std::map<ValueId, const SsaValue *> aliases_;
  std::map<ValueId, std::string> display_names_;
  std::set<OpId> plumbing_;
};

} // namespace ddd
