// view.h -- the terminal stage of a pipeline: how a function is shown.
//
// Everything before a renderer annotates. A renderer states. Three of them
// exist and they are three levels of the same function, not three opinions
// about it:
//
//   asm        the machine instructions, and everything the analyses learned
//              about them. Elides nothing -- this is the ground truth the
//              other two are checked against.
//   print-ssa  one p-code op per line, under the instruction it came from.
//              Elides nothing: this is what the analyses actually operate on.
//   hil        expressions folded out of the def-use chains, and the control
//              flow they compute. Elides the machine's own bookkeeping --
//              the stack pointer kept up to date, a return address pushed, a
//              preserved register's trip through the stack -- which the same
//              listing summarises as `; frame:` and `; saves:`.
//
// The contract, and the reason the three are described together rather than
// each being self-describing:
//
//   what a renderer leaves out must be summarised in the same listing.
//
// A renderer that hides the save of a preserved register and says nothing about
// it has produced a function that does not exist, and a reader cannot tell that
// apart from a function that saves nothing. `hil` states what it omitted, in
// the entry block, always; nothing else may omit anything.
//
// The converse is a rule too, and it is the one the builder enforces
// (HilBuilder::plan_elisions, hil_build.cpp): a name may be printed only if the
// line defining it is printed. An elided value must not fold into a shown one,
// and a shown line must not read a value whose definition was elided -- if
// something the listing prints needs a save/restore, the whole pair comes back,
// because half of it is a listing that reads `RBX = saved_RBX` for a function
// that does nothing at all.
//
// Together those two are what make a listing checkable rather than merely
// plausible: everything missing is named, and everything named is defined.
//
// Adding a renderer means adding a pass registered under a name, and adding
// that name to `is_terminal_pass` (passes/pass.h) -- which is what the session
// and the command line agree on when they ask whether a pipeline has already
// stated the listing -- and to `ending_in` (lua/ddd/workflow.lua), which swaps
// one renderer for another at the end of a declared pipeline. A renderer that
// folds like `hil` and so can be reproduced from tokens also goes in
// `is_folded_listing`.
#pragma once

#include "ir/ssa.h"
#include "passes/pass.h"

#include <iosfwd>

namespace ddd {

// The notes the earlier passes left on an op, one to a line, indented under
// whatever line they are about.
//
// A note is commentary, not output: it never decides anything, and a pass that
// says nothing produces none. The indent is a parameter because what a note
// hangs under differs -- a p-code op is one level in from the instruction it
// came from, a statement of the folded listing is one level in from the block.
void render_notes(std::ostream &os, const PassContext &ctx, const SsaOp &op,
                  const char *indent);

} // namespace ddd
