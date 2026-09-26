// pass.h -- passes over an SsaFunction, and a registry to look them up by
// name.
//
// A pass is one class with a name, a description and a run(). Dropping
// DDD_REGISTER_PASS(MyPass) at the bottom of its .cpp makes it available to
// --passes on the command line; nothing else in the tree needs to change.
#pragma once

#include "base/registry.h"
#include "decode/abi.h"
#include "decode/target.h"
#include "image/image.h"
#include "ir/annotations.h"
#include "ir/ssa.h"

#include <algorithm>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <iosfwd>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {
class Sleigh;
}

namespace ddd {

class Project;

// Everything a pass needs besides the function itself.
//
// `target` is the one for *this* function, not for the file: an image can
// hold more than one instruction set, and one instruction set can be used
// under more than one convention.
struct PassContext {
  const Target *target = nullptr;     // ISA + ABI in force here; may be null
  const Image *image = nullptr;       // the bytes, code and data; may be null
  Annotations *annotations = nullptr; // where passes record what they found
  // Function addresses to names, when the container carried a symbol table.
  // The only naming in this tool that is not a guess.
  const std::map<uint64_t, std::string> *symbols = nullptr;
  // Names and comments the user chose; they override anything generated.
  const Project *project = nullptr;
  std::ostream *out = nullptr; // where passes report; defaults to stdout
  bool verbose = false;
  // Show the machine bookkeeping the high-level listing hides: stack-pointer
  // updates and the return-address push a call performs.
  bool show_machine_state = false;

  ghidra::Sleigh *translator() const;
  const CallingConvention *abi() const;
  Spaces *spaces() const;
  Varnode stack_pointer() const;

  std::ostream &stream() const;

  // ---- reporting ---------------------------------------------------------
  //
  // A pass does not print. What a pass found is a report, and the manager
  // decides whether the caller wants to see it -- the session is usually
  // drawing a screen, where a line of narration interleaved into the listing
  // is noise nobody asked for.
  //
  // A pass with one fact to state returns it from Pass::report(); one that is
  // discovering them as it goes appends here instead. Both end up in the same
  // place, printed the same way.
  void say(std::string line) { report_.push_back(std::move(line)); }

  // Hands back everything said since the last call. The manager's, not a
  // pass's: taking the buffer during run() would silently drop the lines.
  std::vector<std::string> take_report() { return std::move(report_); }

  // Display names. With a translator these come out as real register names
  // ("RAX#3") instead of raw storage ("register:0x0:8#3").
  //
  // name_of() follows aliases, so a use shows the variable it really is.
  // declaration_of() does not, so the line that defines a value still names
  // it -- otherwise a copy would print as `x = COPY x`.
  std::string name_of(const SsaValue &value) const;
  std::string declaration_of(const SsaValue &value) const;
  std::string name_of(const Varnode &vn) const;
  std::string name_of(const SsaOperand &operand) const;
  // Operand by position, so the address-space constant of a LOAD/STORE comes
  // out as a space name rather than an encoded pointer.
  std::string name_of(const SsaOp &op, size_t index) const;
  // name_of() without the trailing "#<version>" -- for contexts (a register
  // written only once in the function, a note about where a value lives)
  // where the version would be noise rather than information.
  std::string base_name_of(const SsaValue &value) const;

private:
  // Lines PassContext::say() has collected. Private because it is the
  // manager's to drain, not a pass's to read.
  std::vector<std::string> report_;
};

class Pass {
public:
  virtual ~Pass() = default;

  virtual std::string name() const = 0;
  virtual std::string description() const { return {}; }

  // Do the work. Anything a pass has to say about it goes through
  // PassContext::say() or report(), never onto a stream: the caller may be
  // drawing a screen, and has no way to interleave with a pass that writes
  // into the middle of it.
  virtual void run(SsaFunction &fn, PassContext &ctx) = 0;

  // What the pass wants said about what it did, one line each, read by the
  // manager once run() has returned. Empty by default -- most passes have
  // nothing to report but the listing they left behind.
  //
  // Called only when the caller asked for detail, which is the point of it
  // being a call and not a buffer run() fills: describing what happened means
  // naming values, and a pass that has to do real work to describe itself
  // should do that work here, where it is only done for someone who wants it.
  // A count costs nothing either way and can be kept in a member.
  //
  // The function and context are handed over because that naming needs both --
  // the same reason run() takes them.
  virtual std::vector<std::string> report(const SsaFunction &,
                                          const PassContext &) const {
    return {};
  }
};

// Passes are found the same way extractors are; see base/registry.h.
using PassRegistry = Registry<Pass>;

// Register a pass with the global registry. Put this at the bottom of the
// .cpp that defines it; name and description come from the pass itself.
#define DDD_REGISTER_PASS(Type) DDD_REGISTER(::ddd::Pass, Type)

// A pass that shells out to an external script (see passes/script_pass.cpp).
// Named by path at the point of use, so it is not in the registry.
std::unique_ptr<Pass> make_script_pass(const std::string &path);

// ---- the terminal stages -------------------------------------------------
//
// Everything before the last pass of a pipeline annotates; the last one states
// the listing. Which passes those are is a fact three separate things have to
// agree on -- the session's listing path, the command line, and `ending_in` in
// lua/ddd/workflow.lua, which strips them off a pipeline to swap one for
// another -- so it is named here, once, rather than spelled out at each.
//
// The three renderers are `asm`, `print-ssa` and `hil`; render/view.h is where
// they are described together. Adding another means adding it here and in
// `ending_in`.

// A pipeline ending in one of these has already stated the listing, so a
// caller asking for tokens as well must not have the folded listing appended
// on top of it.
bool is_terminal_pass(const std::string &name);

// The terminal stage whose output is the folded listing itself, and so is the
// one a caller building its own listing from tokens can reproduce: the session
// skips it rather than build the same Hil twice, and appends the result at the
// end instead. Not every terminal pass is one of these -- print-ssa states
// something tokens cannot rebuild.
bool is_folded_listing(const std::string &name);

// The "remove to a fixed point" shape shared by dce, prune-phis and simplify:
// sweep the chosen vector(s) of every block with `is_dead`, and repeat for as
// long as a round removes something, since deleting one op can be exactly
// what makes another dead (it fed it, or it was its last remaining use). SSA
// use lists are rebuilt after every round that changed anything, because a
// later round's predicate may depend on them.
//
// `is_dead` may mutate -- simplify decides an operand is dead by rewriting
// its uses first and returning true -- std::remove_if visits every element
// exactly once per round, so that is a well-defined place to do it.
//
// Defaults to sweeping both phis and ops, as dce needs; pass an explicit
// single-element list (e.g. {&SsaBlock::phis}) to sweep only one.
template <typename Predicate>
int remove_ops_to_fixpoint(
    SsaFunction &fn, Predicate &&is_dead,
    std::initializer_list<std::vector<SsaOp *> SsaBlock::*> selectors = {
        &SsaBlock::phis, &SsaBlock::ops}) {
  int removed = 0;
  for (bool changed = true; changed;) {
    changed = false;

    for (SsaBlock &block : fn.blocks()) {
      for (auto member : selectors) {
        std::vector<SsaOp *> &ops = block.*member;
        auto dead = std::remove_if(ops.begin(), ops.end(), is_dead);
        if (dead == ops.end()) continue;

        removed += static_cast<int>(std::distance(dead, ops.end()));
        ops.erase(dead, ops.end());
        changed = true;
      }
    }

    if (changed) fn.rebuild_uses();
  }
  return removed;
}

// Runs a sequence of passes in order.
class PassManager {
public:
  // Looks the pass up by name, or builds a script pass for a "py:<path>"
  // name. Returns false if there is no such pass.
  bool add(const std::string &name);
  void run(SsaFunction &fn, PassContext &ctx) const;

  bool empty() const { return passes_.empty(); }

private:
  std::vector<std::shared_ptr<Pass>> passes_;
};

} // namespace ddd
