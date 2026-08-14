#include "image.h"
#include "endian.h"

#include <cctype>

namespace ddd {

std::optional<uint64_t> Image::read_int(uint64_t addr, unsigned size) const {
  if (size == 0 || size > 8 || !contains(addr, size))
    return std::nullopt;

  return read_endian(at(addr), size, big_endian_);
}

std::optional<std::string> Image::read_string(uint64_t addr,
                                              size_t max_length) const {
  if (!contains(addr))
    return std::nullopt;

  std::string text;
  for (uint64_t cursor = addr; cursor < limit() && text.size() <= max_length;
       ++cursor) {
    uint8_t byte = *at(cursor);
    if (byte == 0)
      return text.empty() ? std::nullopt : std::optional<std::string>(text);

    bool printable = std::isprint(byte) != 0 || byte == '\n' || byte == '\t';
    if (!printable)
      return std::nullopt;
    text.push_back(static_cast<char>(byte));
  }

  return std::nullopt; // unterminated, or longer than max_length
}

void ImageLoader::loadFill(ghidra::uint1 *dest, ghidra::int4 size,
                           const ghidra::Address &addr) {
  uint64_t start = addr.getOffset();
  for (ghidra::int4 i = 0; i < size; ++i) {
    const uint8_t *byte = image_.at(start + i);
    dest[i] = byte != nullptr ? *byte : 0;
  }
}

} // namespace ddd
