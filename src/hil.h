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

#include "pass.h"
#include "reaching.h"
#include "ssa.h"

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

  // For a phi: which predecessor each operand arrives from, in the same order.
  // A phi without them says `phi(a, b)` and leaves the reader to work out which
  // branch produced which -- which is the only thing a phi is actually saying.
  std::vector<int> operand_blocks;
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
  Address addr;
  const SsaOp *op = nullptr;

  const SsaValue *target = nullptr; // Assign
  std::string target_text;          // how the target is displayed
  ExprRef value = nullptr;
  ExprRef address = nullptr; // Store
  int taken = -1;            // Branch / CondBranch
  int fallthrough = -1;      // CondBranch
};

struct HilBlock {
  int id = -1;
  std::vector<Statement> statements;
};

class Hil {
public:
  const std::vector<HilBlock> &blocks() const { return blocks_; }
  int folded() const { return folded_; }
  int rewritten() const { return rewritten_; }

private:
  friend class HilBuilder;

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
};

struct TokenBlock {
  int id = -1;
  uint64_t addr = 0;
  bool entry = false;
  std::vector<int> preds;
  std::vector<int> succs;
  std::vector<std::string> comments;
  std::vector<TokenLine> lines;
};

std::vector<TokenBlock> tokenize(const Hil &hil, const SsaFunction &fn,
                                 const PassContext &ctx);

// Renders the whole function, with each statement under the instruction it
// came from and any comments the earlier passes left on it.
std::string to_string(const Hil &hil, const SsaFunction &fn, const PassContext &ctx);

} // namespace ddd
