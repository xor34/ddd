// slot.h -- a frame slot: somewhere in the function's own frame that a value
// lives.
//
// The offset is the identity, and that is the point of the type. `stack-vars`
// already works in those terms -- its analysis is "is this value entry_sp + k"
// -- and then used to throw the number away in favour of a name, leaving four
// consumers to recover it by parsing `&var_18` and `sp-0x14` back apart. A
// fact carried by its own spelling is a fact anyone can spell wrong, and a
// label a script happened to start with '&' became a frame slot.
//
// Two kinds of slot, which only a listing's spelling tells apart: a variable
// of the program, and the home a preserved register is kept in -- which is not
// a variable, because nothing the program asked for lives there. That
// distinction used to be an enum with a third member, None, for "there is no
// slot here". Which is what a null get<Slot>() already says.
#pragma once

#include "base/id.h"

#include <cstdint>
#include <string>

namespace ddd {

struct Slot {
  // Which value this is about. A fact says what it is keyed by, so the store
  // never has to be told -- and a new fact is a new struct and nothing else.
  using Key = ValueId;

  int64_t offset = 0; // from the stack pointer at entry
  bool saved_register = false;
  std::string name; // how it is written: "var_18", "arg_8", "RBX"
};

} // namespace ddd
