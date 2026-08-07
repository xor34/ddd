// arch-detect -- guess which instruction set a stretch of bytes is.
//
// This is the extractor that makes a foreign blob inside a firmware image
// usable: it names a spec, and that spec goes straight into a --region, which
// becomes the Target that region's functions are lifted with.
//
// Method: try each candidate spec over a sample of the image and score it by
// how far it gets. A spec that decodes every instruction and produces sane
// control flow is a better fit than one that throws on a third of them. This
// is a heuristic and it says so -- confidence is reported, not hidden.
//
// Cost is one Sleigh load per candidate, so `--try-specs` narrows it; without
// that it tries everything in the specs directory.
#include "../extract.h"
#include "../pcode.h"
#include "../target.h"

#include "error.hh"
#include "sleigh.hh"

#include <algorithm>
#include <filesystem>
#include <ostream>
#include <sstream>

namespace ddd {
namespace {

constexpr uint64_t kSampleBytes = 1024;
constexpr int kMaxInstructions = 256;
// Below this, the guess is not worth reporting at all.
constexpr double kMinimumScore = 0.55;

struct Score {
  std::string spec;
  double value = 0.0;
  int decoded = 0;
  int failed = 0;
};

// How well `translator` explains `length` bytes at `addr`.
//
// Decoding is only half of it: many specs will decode arbitrary bytes into
// *something*. What separates a real fit is that the result looks like a
// program -- instructions of plausible length, and control flow that stays
// inside the region.
Score score_spec(ghidra::Sleigh &translator, const Image &image, uint64_t addr,
                 uint64_t length) {
  Score score;
  ghidra::AddrSpace *code = translator.getDefaultCodeSpace();

  uint64_t cursor = addr;
  const uint64_t end = addr + length;
  int terminators = 0;

  for (int count = 0; count < kMaxInstructions && cursor < end; ++count) {
    PcodeCapture capture;
    ghidra::int4 size = 0;
    try {
      size = translator.oneInstruction(capture, ghidra::Address(code, cursor));
    } catch (ghidra::LowlevelError &) {
      ++score.failed;
      cursor += 1;
      continue;
    }

    if (size <= 0) {
      ++score.failed;
      cursor += 1;
      continue;
    }

    ++score.decoded;
    for (const PcodeOp &op : capture.ops)
      if (is_terminator(op.opc)) ++terminators;
    cursor += size;
  }

  int total = score.decoded + score.failed;
  if (total == 0) return score;

  double decode_rate = static_cast<double>(score.decoded) / total;

  // Real code branches and returns, but not constantly. A spec producing a
  // terminator per instruction is misreading data as control flow.
  double density = score.decoded > 0
                       ? static_cast<double>(terminators) / score.decoded
                       : 0.0;
  double flow = density > 0.0 && density < 0.5 ? 1.0 : 0.7;

  score.value = decode_rate * flow;
  return score;
}

std::vector<std::string> candidate_specs(const ExtractContext &ctx) {
  std::vector<std::string> specs;

  if (!ctx.candidate_specs.empty()) {
    for (const std::string &name : ctx.candidate_specs) {
      std::filesystem::path path = name;
      if (path.extension() != ".sla")
        path = std::filesystem::path(ctx.spec_dir) / (name + ".sla");
      specs.push_back(path.string());
    }
    return specs;
  }

  std::error_code error;
  for (const auto &entry : std::filesystem::directory_iterator(ctx.spec_dir, error))
    if (entry.path().extension() == ".sla") specs.push_back(entry.path().string());

  std::sort(specs.begin(), specs.end());
  return specs;
}

class ArchDetect final : public Extractor {
public:
  std::string name() const override { return "arch-detect"; }
  std::string description() const override {
    return "guess the instruction set by trial disassembly (slow; see --try_specs)";
  }

  std::vector<Finding> scan(const Image &image, ExtractContext &ctx) override {
    std::vector<Finding> findings;
    if (image.empty()) return findings;

    std::vector<std::string> specs = candidate_specs(ctx);
    if (specs.empty()) {
      if (ctx.verbose) ctx.stream() << "  no candidate specs in " << ctx.spec_dir << "\n";
      return findings;
    }

    // Each candidate needs its own Sleigh, and TargetSet already knows how to
    // build and cache those.
    TargetSet targets(image);
    uint64_t length = std::min<uint64_t>(kSampleBytes, image.size());

    std::vector<Score> scores;
    for (const std::string &spec : specs) {
      Target *target = targets.acquire(spec);
      if (target == nullptr) continue;

      Score score = score_spec(*target->translator, image, image.base(), length);
      score.spec = std::filesystem::path(spec).stem().string();
      if (ctx.verbose)
        ctx.stream() << "  " << score.spec << ": " << score.decoded << " decoded, "
                     << score.failed << " failed, score " << score.value << "\n";
      if (score.value >= kMinimumScore) scores.push_back(std::move(score));
    }

    std::stable_sort(scores.begin(), scores.end(),
                     [](const Score &a, const Score &b) { return a.value > b.value; });

    // Several specs of one family will score alike (every ARM variant decodes
    // ARM), so report the plausible ones rather than pretending to one answer.
    for (size_t i = 0; i < scores.size() && i < 5; ++i) {
      std::ostringstream detail;
      detail << scores[i].decoded << " instructions decoded, " << scores[i].failed
             << " failed";

      Finding finding;
      finding.offset = image.base();
      finding.length = length;
      finding.kind = "code";
      finding.detail = detail.str();
      finding.confidence = scores[i].value;
      finding.suggested_spec = scores[i].spec;
      findings.push_back(std::move(finding));
    }

    return findings;
  }
};

DDD_REGISTER_EXTRACTOR(ArchDetect);

} // namespace
} // namespace ddd
