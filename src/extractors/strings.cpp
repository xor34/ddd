// strings -- runs of printable ASCII.
//
// Cheap, and usually the fastest way to tell what an unknown blob is: version
// banners, paths, and error messages survive when nothing else is
// recognisable.
#include "../extract.h"

#include <cctype>
#include <ostream>

namespace ddd {
namespace {

constexpr size_t kMinimumLength = 6;
constexpr size_t kReportLength = 60;

class Strings final : public Extractor {
public:
  std::string name() const override { return "strings"; }
  std::string description() const override { return "runs of printable ASCII"; }

  std::vector<Finding> scan(const Image &image, ExtractContext &ctx) override {
    std::vector<Finding> findings;

    std::string run;
    uint64_t run_begin = 0;

    auto flush = [&] {
      if (run.size() >= kMinimumLength) {
        Finding finding;
        finding.offset = run_begin;
        finding.length = run.size();
        finding.kind = "string";
        finding.detail = "\"" + run.substr(0, kReportLength) +
                         (run.size() > kReportLength ? "..." : "") + "\"";
        findings.push_back(std::move(finding));
      }
      run.clear();
    };

    for (uint64_t addr = image.base(); addr < image.limit(); ++addr) {
      uint8_t byte = *image.at(addr);
      bool printable = std::isprint(byte) != 0 || byte == '\t';

      if (!printable) {
        flush();
        continue;
      }
      if (run.empty())
        run_begin = addr;
      run.push_back(static_cast<char>(byte));
    }
    flush();

    if (ctx.verbose)
      ctx.stream() << "  " << findings.size() << " string(s)\n";
    return findings;
  }
};

DDD_REGISTER_EXTRACTOR(Strings);

} // namespace
} // namespace ddd
