// endian.h -- assembling a big- or little-endian integer out of raw bytes.
//
// Image::read_int and elf::Reader::at both do this over otherwise unrelated
// byte sources (a loaded image vs. a raw file buffer) with different bounds
// checks, so only the byte-assembly itself is shared here.
#pragma once

#include <cstddef>
#include <cstdint>

namespace ddd {

// Reads `size` bytes (1-8) starting at `bytes` as a big- or little-endian
// integer. The caller is responsible for bounds-checking `bytes` first.
inline uint64_t read_endian(const uint8_t *bytes, unsigned size, bool big_endian) {
  uint64_t value = 0;
  if (big_endian) {
    for (unsigned i = 0; i < size; ++i)
      value = (value << 8) | bytes[i];
  } else {
    for (unsigned i = size; i-- > 0;)
      value = (value << 8) | bytes[i];
  }
  return value;
}

} // namespace ddd
