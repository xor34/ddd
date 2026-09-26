// text.h -- small text-parsing helpers shared by the project file reader,
// the target/region command-line parser, and the server's line protocol.
//
// All three read whitespace-separated tokens out of an istringstream and
// need the same two things: a number that may be "0x"-prefixed, and
// whatever text is left on the line after the fixed fields.
#pragma once

#include <cstdint>
#include <sstream>
#include <string>

namespace ddd {

// Parses a decimal or "0x"/"0X"-prefixed hexadecimal number, requiring the
// whole string to be consumed. Returns false on empty or malformed input,
// leaving `out` untouched.
inline bool parse_number(const std::string &text, uint64_t &out) {
  try {
    size_t consumed = 0;
    const int base = (text.size() > 2 && text[0] == '0' &&
                      (text[1] == 'x' || text[1] == 'X'))
                          ? 16
                          : 10;
    const uint64_t value = std::stoull(text, &consumed, base);
    if (consumed != text.size())
      return false;
    out = value;
    return true;
  } catch (...) {
    return false;
  }
}

// The rest of the line, with the leading space the extraction operator
// (`fields >> token`) left behind removed.
inline std::string rest_of_line(std::istringstream &fields) {
  std::string text;
  std::getline(fields, text);
  if (!text.empty() && text.front() == ' ')
    text.erase(0, 1);
  return text;
}

} // namespace ddd
