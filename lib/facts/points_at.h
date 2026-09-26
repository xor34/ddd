// points_at.h -- a constant of an op that points into the image, and what is
// at the end of it.
//
// The sentence used to be the whole record -- `0x401128 -> "hello, world"`,
// written into the comment table and then sliced back apart by the two passes
// that wanted to know what it said, one looking for `" -> \""`, the other for
// a leading `&`. What they wanted was the last hop: is this a function, is it
// a string, and if so which. That is what is recorded; the sentence is
// rendered from it.
//
// No `Key`: a points-at is a statement about an *op*, so it is recorded
// through the note channel (see notes.h) rather than the fact store. Where
// facts are conclusions about a value, notes are what there is to say about an
// instruction, and a reader sees them in the order they were recorded.
#pragma once

#include <cstdint>
#include <string>

namespace ddd {

struct PointsAt {
  enum class Kind {
    Data,   // a number, or nothing readable there at all
    String, // printable bytes; `text` is their contents
    Code,   // a function; `text` is its name when the container had one
  };

  Kind kind = Kind::Data;
  uint64_t address = 0;

  // The string's contents *unescaped* -- what the analysis read, not how it is
  // written down. Or the function's name, empty when nothing named it.
  std::string text;

  // A literal pool entry: `address` holds a pointer and `kind` describes what
  // *that* points at. False when `address` is the thing itself, and false when
  // there was nothing readable at `address` to follow.
  bool word_read = false;
  uint64_t word = 0;
};

} // namespace ddd
