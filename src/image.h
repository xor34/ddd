// image.h -- the bytes we were handed, addressed the way the target sees them.
//
// A binary is not only code. Once the sweep has decided which range is
// instructions, everything else in the image is data, and passes want to
// reach it: a constant operand that lands in the image is a pointer worth
// resolving, not just a number.
#pragma once

#include "loadimage.hh"
#include "types.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ddd {

class Image {
public:
  Image() = default;
  Image(uint64_t base, std::vector<uint8_t> bytes, bool big_endian = false)
      : base_(base), bytes_(std::move(bytes)), big_endian_(big_endian) {}

  uint64_t base() const { return base_; }
  uint64_t limit() const { return base_ + bytes_.size(); }
  size_t size() const { return bytes_.size(); }
  bool empty() const { return bytes_.empty(); }

  void set_big_endian(bool big_endian) { big_endian_ = big_endian; }
  bool big_endian() const { return big_endian_; }

  bool contains(uint64_t addr, size_t length = 1) const {
    return addr >= base_ && length <= bytes_.size() &&
           addr - base_ <= bytes_.size() - length;
  }

  const uint8_t *at(uint64_t addr) const {
    return contains(addr) ? &bytes_[addr - base_] : nullptr;
  }

  // Integer of `size` bytes at `addr`, in the target's byte order.
  std::optional<uint64_t> read_int(uint64_t addr, unsigned size) const;

  // A NUL-terminated run of printable characters at `addr`. Nothing is
  // returned for an empty string or one that runs off the end of the image,
  // so this stays quiet on random data.
  std::optional<std::string> read_string(uint64_t addr,
                                         size_t max_length = 128) const;

  // The range the disassembler actually walked. Everything else in the image
  // is data as far as anything here knows.
  void set_code_range(uint64_t begin, uint64_t end) {
    code_begin_ = begin;
    code_end_ = end;
  }
  uint64_t code_begin() const { return code_begin_; }
  uint64_t code_end() const { return code_end_; }
  bool is_code(uint64_t addr) const {
    return addr >= code_begin_ && addr < code_end_;
  }
  bool is_data(uint64_t addr) const { return contains(addr) && !is_code(addr); }

private:
  uint64_t base_ = 0;
  std::vector<uint8_t> bytes_;
  bool big_endian_ = false;
  uint64_t code_begin_ = 0;
  uint64_t code_end_ = 0;
};

// Hands the image to Sleigh. Reads outside the image return zero, which is
// what the disassembler expects at the edges.
class ImageLoader final : public ghidra::LoadImage {
public:
  explicit ImageLoader(const Image &image)
      : LoadImage("image"), image_(image) {}

  void loadFill(ghidra::uint1 *dest, ghidra::int4 size,
                const ghidra::Address &addr) override;
  std::string getArchType() const override { return "image"; }
  void adjustVma(long) override {}

private:
  const Image &image_;
};

} // namespace ddd
