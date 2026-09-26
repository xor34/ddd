// frame_pointer.h -- the stack pointer at a known offset: `sp-0x14`, `sp`.
//
// The same arithmetic as a slot's address and a different fact: this is the
// register the machine keeps, mid-update, which a reader may well want to see.
// It is not the address of a variable, which is why it is not a Slot.
#pragma once

#include "base/id.h"

#include <cstdint>

namespace ddd {

struct FramePointer {
  using Key = ValueId;

  int64_t offset = 0;
};

} // namespace ddd
