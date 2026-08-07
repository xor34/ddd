// entropy -- where the image stops looking like code.
//
// Shannon entropy over a sliding window separates the three things a firmware
// image is usually made of: instructions (middling), compressed or encrypted
// blobs (very high), and padding or tables (very low). Adjacent windows with
// the same verdict are merged so the report is a handful of stretches rather
// than thousands of windows.
#include "../extract.h"

#include <cmath>
#include <ostream>
#include <sstream>

namespace ddd {
namespace {

constexpr uint64_t kWindow = 256;
constexpr double kHighEntropy = 7.2; // bits per byte, out of 8
constexpr double kLowEntropy = 1.5;

double entropy_of(const Image &image, uint64_t addr, uint64_t length) {
  unsigned counts[256] = {};
  for (uint64_t i = 0; i < length; ++i)
    ++counts[*image.at(addr + i)];

  double bits = 0.0;
  for (unsigned count : counts) {
    if (count == 0)
      continue;
    double p = static_cast<double>(count) / static_cast<double>(length);
    bits -= p * std::log2(p);
  }
  return bits;
}

const char *classify(double bits) {
  if (bits >= kHighEntropy)
    return "high-entropy";
  if (bits <= kLowEntropy)
    return "low-entropy";
  return nullptr; // ordinary; not worth reporting
}

class Entropy final : public Extractor {
public:
  std::string name() const override { return "entropy"; }
  std::string description() const override {
    return "find compressed/encrypted and padding regions by entropy";
  }

  std::vector<Finding> scan(const Image &image, ExtractContext &ctx) override {
    std::vector<Finding> findings;
    if (image.size() < kWindow)
      return findings;

    const char *run_kind = nullptr;
    uint64_t run_begin = 0;
    double run_total = 0.0;
    int run_windows = 0;

    auto flush = [&](uint64_t end) {
      if (run_kind == nullptr)
        return;

      std::ostringstream detail;
      detail << "mean " << (run_total / run_windows) << " bits/byte";
      if (std::string(run_kind) == "high-entropy")
        detail << " -- compressed or encrypted";
      else
        detail << " -- padding or sparse data";

      Finding finding;
      finding.offset = run_begin;
      finding.length = end - run_begin;
      finding.kind = run_kind;
      finding.detail = detail.str();
      findings.push_back(std::move(finding));
      run_kind = nullptr;
    };

    for (uint64_t addr = image.base(); addr + kWindow <= image.limit();
         addr += kWindow) {
      double bits = entropy_of(image, addr, kWindow);
      const char *kind = classify(bits);

      if (kind == nullptr ||
          (run_kind != nullptr && std::string(kind) != run_kind)) {
        flush(addr);
      }
      if (kind == nullptr)
        continue;

      if (run_kind == nullptr) {
        run_kind = kind;
        run_begin = addr;
        run_total = 0.0;
        run_windows = 0;
      }
      run_total += bits;
      ++run_windows;
    }
    flush(image.limit());

    if (ctx.verbose)
      ctx.stream() << "  " << findings.size() << " entropy region(s)\n";
    return findings;
  }
};

DDD_REGISTER_EXTRACTOR(Entropy);

} // namespace
} // namespace ddd
