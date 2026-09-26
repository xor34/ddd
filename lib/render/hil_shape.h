// hil_shape.h -- the shape a function is printed in: branches, loops, and the
// gotos left over.
//
// The flat form is right for analysis and wrong for reading. `block 1 @ 0x8:
// from 0` and a `goto` on every edge make the reader reconstruct the control
// flow the CFG already knows, and what a reader came for is to see at a glance
// what is interesting in the function. So the blocks are arranged back into
// the control flow they came from -- indented, braced, fallthrough implicit --
// and where the CFG does not have a shape (an irreducible cycle, two arms that
// never meet again) it says so with a label and a `goto` rather than inventing
// one.
//
// The tree is explicit rather than a printer that decides and writes in one
// pass, for one decisive reason: whether a block needs a label depends on
// whether anything else jumps to it, and the jumps are only discovered as the
// walk goes. A tree makes that a short second pass over the parts, where
// printing as it went would mean splicing text into an already-written stream
// or a second walk that has to reproduce every decision of the first.
//
// Nothing here is a claim about the program. Every edge is one the CFG has;
// the only invention is which of them to leave unsaid.
#pragma once

#include "render/hil.h"

#include <optional>
#include <set>
#include <vector>

namespace ddd {

enum class ShapeKind {
  Statements, // one block's statements, less the branch the shape took over
  If,         // if (cond) { <body> } [else { <otherwise> }]
  Loop,       // while (1) { <body> }, or do { <body> } while (cond);
  Jump,       // goto / break / continue, guarded by a condition or not
};

struct Shape {
  ShapeKind kind = ShapeKind::Statements;

  // Statements: which block this is. Jump: where it goes. Loop: the block that
  // opens it, which is what a `continue` inside it means.
  BlockId block;

  // The statement this came out of: what decides an If or a Loop, and what a
  // Jump is guarded by. Null for a jump the walk invented -- an edge into the
  // join of an enclosing shape, which no instruction said.
  const Statement *statement = nullptr;

  // Jump: true when `statement`'s condition guards it.
  bool conditional = false;

  // Statements: what to print, in order. The branch the shape took over is not
  // among them; everything else is.
  std::vector<const Statement *> statements;

  // If: the then-arm. Loop: the body. Jump: empty.
  std::vector<Shape> body;
  // If: the else-arm, empty in the one-armed form.
  std::vector<Shape> otherwise;

  // If: the condition is printed negated, because the arm that says something
  // is the one the instruction did not take. The paths it is true of are the
  // same either way -- only the braces are the other way round.
  bool inverted = false;

  // Loop: where control goes when the loop is done -- what a `break` inside it
  // means. Absent for a loop that never lets go.
  std::optional<BlockId> follow;

  // Loop: the body ends by deciding whether to go round again, so the
  // condition belongs in a `while (...)` clause at the bottom.
  bool do_while = false;
};

// What a jump is spelled with, which depends on the loop it is written inside
// and on nothing else. Both of the special words name no block -- that is the
// whole reason to prefer them -- so this is also how the walk knows a label
// would be one nobody reads.
enum class JumpWord { Goto, Break, Continue };

// `inner` is the innermost loop the jump is printed inside, or null at the top
// level. Only a jump to a loop's follow can be a `break`, and only to the
// innermost loop's: an outer loop's follow is somewhere an inner `break` would
// not go. `continue` goes back to the innermost header, which is the only thing
// `continue` can mean.
inline JumpWord jump_word(BlockId target, const Shape *inner) {
  if (inner != nullptr) {
    if (inner->follow && target == *inner->follow)
      return JumpWord::Break;
    if (target == inner->block)
      return JumpWord::Continue;
  }
  return JumpWord::Goto;
}

struct HilShapes {
  std::vector<Shape> shapes;

  // Every block a `goto` names, and so every block that has to be labelled
  // where it is printed -- which is what makes a `goto` readable as well as
  // legal. A `break` or a `continue` names no block, so the block it goes to is
  // not in here on that account: a label nothing says `goto` to is a label for
  // the reader to hunt for.
  std::set<BlockId> labelled;
};

// Arranges one function. Only the text listing calls this; the tokenised form
// is the interface's own arrangement of the same statements and is built
// straight from the Hil.
HilShapes structure(const Hil &hil, const SsaFunction &fn);

} // namespace ddd
