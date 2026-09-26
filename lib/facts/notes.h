// notes.h -- one thing there is to say about an op, and which kind of thing it
// is.
//
// Two channels reach a reader, and they are not the same channel. The fact
// store (knowledge.h) holds conclusions about *values*: this is a frame slot,
// this is the same variable as that. A note is what there is to say about an
// *instruction* -- where this call goes, what this constant points at, a
// sentence someone chose to write -- and the order the notes were recorded in
// is part of what a reader reads.
//
// Which is why they are one list per op rather than one table per kind. A
// store says which slot it writes and what the value going into it points at,
// and the listing prints `; store var_10 [sp-0x10]` then
// `; 0x401128 -> "hello, world"` -- the order the two analyses worked them out
// in, not an order anything chose. Keeping the kinds in separate tables and
// printing the tables would state the same facts in a different order, which
// is a change to the listing for no reason a reader could see.
//
// A `Callee` note carries a name and nothing else, so there is no struct for
// it: what would be a one-field type is the `text` of the note.
#pragma once

#include "facts/points_at.h"

#include <string>

namespace ddd {

struct Note {
  enum class Kind {
    Prose,    // a sentence someone chose to write
    PointsAt, // a constant of this op, and what is at the end of it
    Callee,   // where this call goes
  };

  Kind kind = Kind::Prose;
  std::string text; // Prose: the sentence. Callee: the name.
  PointsAt fact;    // PointsAt.
};

} // namespace ddd
