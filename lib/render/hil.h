// hil.h -- an expression-tree IL built by folding SSA def-use chains.
//
// The SSA listing is one p-code op per line, which is the right shape for
// analysis and the wrong one for reading: `ebx = ebx + 1` arrives as four
// lines and a version number to chase. This rebuilds expressions out of it.
//
// Two things make it work, and both come straight from SSA:
//
//   * A value used exactly once can be folded into the place that uses it.
//     SSA guarantees the operands of its defining op are immutable, so the
//     only hazards left are ordering ones, not "did something reassign that
//     register in between".
//   * A value used more than once stays a named variable, assigned once.
//     That is not a heuristic -- it is what the use count says.
//
// On top of that sits a rewrite table matched against the def-use graph, which
// is what turns an architecture's flag dance back into the comparison it was
// compiled from.
#pragma once

#include "facts/knowledge.h"
#include "facts/slot.h"
#include "ir/ssa.h"
#include "passes/pass.h"

#include <deque>
#include <string>
#include <vector>

namespace ddd {

struct Expr;
using ExprRef = const Expr *;

enum class ExprKind {
  Constant,
  Variable, // a named SSA value: multi-use, live-in, labelled, or a phi
  Unary,
  Binary,
  Cast,
  Load,
  Unknown, // an opcode with no higher-level form: printed as OPNAME(a, b)
};

struct Expr {
  ExprKind kind = ExprKind::Unknown;
  std::string text; // operator, cast or opcode name
  uint64_t constant = 0;
  unsigned size = 0;
  const SsaValue *value = nullptr; // Variable
  std::vector<ExprRef> operands;
  int precedence = 0;

  // For a Variable: the fact that this value is the address of a frame slot,
  // null when it is not. A load or store through such an address is written as
  // the slot itself -- which is the one place the distinction is used, and it
  // is a fact about the value, not about the spelling of `text`.
  const Slot *slot = nullptr;

  // For a phi: which predecessor each operand arrives from, in the same order.
  // A phi without them says `phi(a, b)` and leaves the reader to work out which
  // branch produced which -- which is the only thing a phi is actually saying.
  std::vector<BlockId> operand_blocks;
};

enum class StatementKind {
  Assign,     // target = value
  Store,      // [address] = value
  Branch,     // goto
  CondBranch, // if (value) goto
  Call,
  Return,
  Effect, // a side effect with no result: an unmodelled op
};

struct Statement {
  StatementKind kind = StatementKind::Effect;
  uint64_t addr = 0;
  const SsaOp *op = nullptr;

  const SsaValue *target = nullptr; // Assign
  std::string target_text;          // how the target is displayed
  ExprRef value = nullptr;
  ExprRef address = nullptr;      // Store
  std::optional<BlockId> taken;   // Branch / CondBranch
  std::optional<BlockId> fallthrough; // CondBranch

  // Branch / CondBranch, when the taken edge leaves the function: the
  // location it goes to, space included (a branch can name another space than
  // the one this function lives in). A tail call is a branch out of the
  // function, and the function it lands in is the single most useful thing on
  // the line -- so it is carried here rather than being reduced to "no
  // block", which is what printing `goto -1` was saying.
  Addr leaves_to;
};

struct HilBlock {
  BlockId id;
  std::vector<Statement> statements;
};

namespace detail {
// Defined in hil_build.cpp. Named rather than left anonymous because Hil has to
// be able to befriend it: the arena it fills is not something a caller should
// be able to push into, and a friend declaration for a class with no name
// anywhere is a friend declaration nobody reading this can follow.
class HilBuilder;
} // namespace detail

class Hil {
public:
  const std::vector<HilBlock> &blocks() const { return blocks_; }
  int folded() const { return folded_; }
  int rewritten() const { return rewritten_; }

private:
  friend class detail::HilBuilder;

  std::deque<Expr> arena_; // stable addresses; ExprRef points in here
  std::vector<HilBlock> blocks_;
  int folded_ = 0;
  int rewritten_ = 0;
};

Hil build_hil(const SsaFunction &fn, const PassContext &ctx);

// ---- tokenised form, for a user interface -------------------------------
//
// A listing rendered to a string cannot be clicked on. Highlighting every
// occurrence of a variable the way IDA does needs each name to arrive with an
// identity attached, so the interface can match `var_c` here against `var_c`
// there without guessing at word boundaries -- which would be wrong anyway,
// since `RAX` appears inside `RAX_2`.

struct Token {
  std::string kind; // var, const, op, addr, punct, cast, keyword
  std::string text;
  std::string id;   // for kind=="var": what to highlight together
};

struct TokenLine {
  uint64_t addr = 0;
  std::vector<Token> tokens;
  std::vector<std::string> comments;

  // Where control goes from this line, for an interface that draws it. The
  // tokens say the same thing, but reading it back out of them means parsing
  // the printed form of a decision that was already made here -- and the
  // difference between the two edges of a condition is exactly what a reader
  // wants marked.
  std::optional<BlockId> taken;       // block id, for a branch
  std::optional<BlockId> fallthrough; // the other edge of a condition

  // An image address outside the function, for a tail call: set only when the
  // destination is in this function's own space, which is the only kind an
  // image address *is*. A destination in another space has no image address
  // to give -- the tokens on the line still spell it out, space and all.
  uint64_t leaves_to = 0;
};

struct TokenBlock {
  BlockId id;
  uint64_t addr = 0;
  bool entry = false;
  std::vector<BlockId> preds;
  std::vector<BlockId> succs;
  std::vector<std::string> comments;
  std::vector<TokenLine> lines;
};

std::vector<TokenBlock> tokenize(const Hil &hil, const SsaFunction &fn,
                                 const PassContext &ctx);

// Renders the whole function, with each statement under the instruction it
// came from and any comments the earlier passes left on it.
std::string to_string(const Hil &hil, const SsaFunction &fn, const PassContext &ctx);

} // namespace ddd
