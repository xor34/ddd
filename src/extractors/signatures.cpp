// signatures -- magic-byte scan, the binwalk core.
//
// Reports where known formats start. It does not parse or unpack them: the
// point is to carve the image into stretches worth looking at separately, and
// unpacking is a transform (see transform.h), not a scan.
//
// Adding a format is one row in the table.
#include "../extract.h"

#include <cstring>
#include <ostream>
#include <sstream>

namespace ddd {
namespace {

struct Signature {
  std::string kind;
  std::vector<uint8_t> magic;
  std::string detail;
  // Some magics are short enough to appear constantly in ordinary data; this
  // is how much to believe a hit.
  double confidence;
};

const std::vector<Signature> &signatures() {
  static const std::vector<Signature> table = {
      {"gzip", {0x1f, 0x8b, 0x08}, "gzip stream", 0.9},
      {"zlib", {0x78, 0x9c}, "zlib stream (default compression)", 0.5},
      {"zlib", {0x78, 0xda}, "zlib stream (best compression)", 0.5},
      {"zlib", {0x78, 0x01}, "zlib stream (no compression)", 0.5},
      {"xz", {0xfd, '7', 'z', 'X', 'Z', 0x00}, "xz stream", 1.0},
      {"bzip2", {'B', 'Z', 'h'}, "bzip2 stream", 0.8},
      {"lzma", {0x5d, 0x00, 0x00}, "lzma stream", 0.4},
      {"lz4", {0x04, 0x22, 0x4d, 0x18}, "lz4 frame", 1.0},
      {"zstd", {0x28, 0xb5, 0x2f, 0xfd}, "zstd frame", 1.0},
      {"zip", {'P', 'K', 0x03, 0x04}, "zip archive", 1.0},
      {"7z", {'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, "7-zip archive", 1.0},
      {"cpio", {'0', '7', '0', '7', '0', '1'}, "cpio (newc) archive", 1.0},
      {"squashfs", {'h', 's', 'q', 's'}, "squashfs (little endian)", 1.0},
      {"squashfs", {'s', 'q', 's', 'h'}, "squashfs (big endian)", 1.0},
      {"jffs2", {0x19, 0x85}, "jffs2 node", 0.3},
      {"ubi", {'U', 'B', 'I', '#'}, "ubi erase block", 1.0},
      {"cramfs", {0x45, 0x3d, 0xcd, 0x28}, "cramfs", 1.0},
      {"romfs", {'-', 'r', 'o', 'm', '1', 'f', 's', '-'}, "romfs", 1.0},
      {"uimage", {0x27, 0x05, 0x19, 0x56}, "u-boot uImage header", 1.0},
      {"dtb", {0xd0, 0x0d, 0xfe, 0xed}, "flattened device tree", 1.0},
      {"elf", {0x7f, 'E', 'L', 'F'}, "ELF object", 1.0},
      {"pe", {'M', 'Z'}, "DOS/PE image", 0.3},
      {"png", {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, "PNG image", 1.0},
      {"jpeg", {0xff, 0xd8, 0xff}, "JPEG image", 0.8},
      {"pgp", {0x99, 0x01}, "PGP public key block", 0.2},
      {"x509", {0x30, 0x82}, "DER sequence (certificate or key)", 0.2},
  };
  return table;
}

class Signatures final : public Extractor {
public:
  std::string name() const override { return "signatures"; }
  std::string description() const override { return "scan for known format magic bytes"; }

  std::vector<Finding> scan(const Image &image, ExtractContext &ctx) override {
    std::vector<Finding> findings;
    if (image.empty()) return findings;

    for (uint64_t addr = image.base(); addr < image.limit(); ++addr) {
      for (const Signature &signature : signatures()) {
        if (!matches(image, addr, signature)) continue;

        Finding finding;
        finding.offset = addr;
        finding.kind = signature.kind;
        finding.detail = signature.detail;
        finding.confidence = signature.confidence;
        findings.push_back(std::move(finding));
      }
    }

    if (ctx.verbose) ctx.stream() << "  " << findings.size() << " signature hit(s)\n";
    return findings;
  }

private:
  static bool matches(const Image &image, uint64_t addr, const Signature &signature) {
    if (!image.contains(addr, signature.magic.size())) return false;
    return std::memcmp(image.at(addr), signature.magic.data(), signature.magic.size()) == 0;
  }
};

DDD_REGISTER_EXTRACTOR(Signatures);

} // namespace
} // namespace ddd
