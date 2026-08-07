// main.cc -- load an image, decide what is in it, and lift the code.
//
//   sleigh_poc --sla=specs/AARCH64.sla --bytes=...
//   sleigh_poc --file=firmware.bin --extract
//   sleigh_poc --file=firmware.bin --region=0:0x400:x86-64 --region=0x400:0x800:riscv64
#include "annotations.h"
#include "cfg.h"
#include "extract.h"
#include "image.h"
#include "pass.h"
#include "script.h"
#include "ssa.h"
#include "target.h"

#include "error.hh"
#include "sleigh.hh"

#include <cctype>
#include <cstdint>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/numbers.h"
#include "absl/strings/string_view.h"

ABSL_FLAG(std::string, sla, "", "SLA file for the whole image (see --region for mixed images)");
ABSL_FLAG(std::string, bytes, "", "Hex bytes");
ABSL_FLAG(std::string, file, "", "Read the image from this file instead of --bytes");
ABSL_FLAG(uint64_t, base, 0, "Address the image is loaded at");
ABSL_FLAG(uint64_t, entry, 0, "Address to start disassembling from (default: --base)");
ABSL_FLAG(int, max, 100000, "Maximum instructions per region");
ABSL_FLAG(uint64_t, code_end, 0, "Stop disassembling here; the rest of the image is data");
ABSL_FLAG(std::vector<std::string>, ctx, {}, "Context variables NAME=VALUE");
ABSL_FLAG(std::string, abi, "", "Calling convention (default: guessed from the spec)");
ABSL_FLAG(std::string, sp, "", "Stack pointer register (default: from the calling convention)");
ABSL_FLAG(std::string, specs, "specs", "Directory to resolve spec names in");

ABSL_FLAG(std::vector<std::string>, region, {},
          "Comma-separated BEGIN:END:SPEC[:ABI[:SP]] -- stretches of the image and how "
          "to read each. Every region is lifted with its own instruction set and "
          "calling convention, so one image can hold several. Note this is one "
          "comma-separated flag, not a repeated one.");

ABSL_FLAG(bool, extract, false, "Run extractors over the image and report what they find");
ABSL_FLAG(std::vector<std::string>, extractors, {}, "Only run these extractors");
ABSL_FLAG(std::vector<std::string>, try_specs, {},
          "Restrict arch-detect to these specs (it tries every spec otherwise)");
ABSL_FLAG(std::string, transform, "",
          "Run the image through this script before analysing it (decryption, unpacking)");

ABSL_FLAG(bool, disasm, false, "Print disassembly before lifting");
ABSL_FLAG(bool, cfg, false, "Print the raw p-code CFG before lifting");
ABSL_FLAG(bool, list_passes, false, "List the registered passes and extractors, then exit");
ABSL_FLAG(std::vector<std::string>, passes,
          std::vector<std::string>({"prune-phis", "stack-vars", "idioms", "data-refs",
                                    "rename", "calling-conv", "print-ssa"}),
          "Passes to run over each region. py:<path> runs an external script.");

namespace {

class AssemblyPrinter final : public ghidra::AssemblyEmit {
public:
  void dump(const ghidra::Address &addr, const std::string &mnem,
            const std::string &body) override {
    std::cout << "0x" << std::hex << addr.getOffset() << std::dec << ":\t" << mnem
              << ' ' << body << '\n';
  }
};

std::vector<uint8_t> parse_hex(absl::string_view input) {
  std::string clean;
  for (char c : input)
    if (std::isxdigit(static_cast<unsigned char>(c))) clean.push_back(c);
  if (clean.size() & 1) clean.pop_back();

  std::vector<uint8_t> result;
  result.reserve(clean.size() / 2);

  for (size_t i = 0; i < clean.size(); i += 2) {
    uint32_t value;
    if (!absl::SimpleHexAtoi(absl::string_view(clean).substr(i, 2), &value)) continue;
    result.push_back(static_cast<uint8_t>(value));
  }

  return result;
}

std::vector<uint8_t> read_file(const std::string &path, bool &ok) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    std::cerr << "cannot read " << path << '\n';
    ok = false;
    return {};
  }
  ok = true;
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
                              std::istreambuf_iterator<char>());
}

int list_passes() {
  std::cout << "passes:\n";
  for (const ddd::PassRegistry::Entry &entry : ddd::PassRegistry::instance().entries())
    std::cout << "  " << entry.name << "\t" << entry.description << '\n';
  std::cout << "  py:<path>\trun an external script pass\n";

  std::cout << "extractors:\n";
  for (const ddd::ExtractorRegistry::Entry &entry :
       ddd::ExtractorRegistry::instance().entries())
    std::cout << "  " << entry.name << "\t" << entry.description << '\n';
  return 0;
}

void print_disassembly(ghidra::Sleigh &translator, uint64_t begin, uint64_t end, int max) {
  AssemblyPrinter printer;
  ghidra::AddrSpace *code = translator.getDefaultCodeSpace();
  ghidra::Address addr(code, begin);
  ghidra::Address stop(code, end);

  for (int count = 0; addr < stop && count < max; ++count) {
    ghidra::int4 length = 1;
    try {
      length = translator.printAssembly(printer, addr);
    } catch (ghidra::LowlevelError &error) {
      std::cout << "0x" << std::hex << addr.getOffset() << std::dec << ":\t?? ("
                << error.explain << ")\n";
    }
    addr = addr + (length > 0 ? length : 1);
  }
}

int run_extractors(const ddd::Image &image) {
  ddd::ExtractContext ctx;
  ctx.spec_dir = absl::GetFlag(FLAGS_specs);
  ctx.candidate_specs = absl::GetFlag(FLAGS_try_specs);
  ctx.out = &std::cout;
  ctx.verbose = true;

  std::vector<ddd::Finding> findings =
      ddd::extract(image, ctx, absl::GetFlag(FLAGS_extractors));

  std::cout << "\n" << findings.size() << " finding(s)\n";
  for (const ddd::Finding &finding : findings)
    std::cout << "  " << ddd::to_string(finding) << '\n';
  return 0;
}

// One region, lifted. Heap-allocated because the SsaFunction borrows the Cfg
// sitting next to it.
struct Lifted {
  const ddd::Region *region = nullptr;
  ddd::Cfg cfg;
};

// Sweeps a region and returns what it decoded, or null if nothing did.
std::unique_ptr<Lifted> lift(const ddd::Region &region, uint64_t entry) {
  ghidra::Sleigh &translator = *region.target->translator;
  ghidra::Address start(translator.getDefaultCodeSpace(),
                        entry != 0 ? entry : region.begin);

  int max = absl::GetFlag(FLAGS_max);
  if (absl::GetFlag(FLAGS_disasm))
    print_disassembly(translator, start.getOffset(), region.end, max);

  ddd::SweepLimits limits;
  limits.max_instructions = max;
  limits.end = ghidra::Address(translator.getDefaultCodeSpace(), region.end);

  auto lifted = std::make_unique<Lifted>();
  lifted->region = &region;
  lifted->cfg = ddd::build_cfg(translator, start, limits);
  return lifted->cfg.empty() ? nullptr : std::move(lifted);
}

// Each region gets a fresh Annotations: what one region's analysis concluded
// says nothing about another's.
void analyse(const Lifted &lifted, const ddd::Image &image,
             const ddd::PassManager &manager) {
  const ddd::Region &region = *lifted.region;
  std::cout << "\n=== region 0x" << std::hex << region.begin << "-0x" << region.end
            << std::dec << "  " << region.name << " ===\n";

  if (absl::GetFlag(FLAGS_cfg)) std::cout << ddd::to_string(lifted.cfg);

  ddd::SsaFunction fn = ddd::build_ssa(lifted.cfg);
  ddd::Annotations annotations;

  ddd::PassContext ctx;
  ctx.target = region.target;
  ctx.image = &image;
  ctx.annotations = &annotations;
  ctx.out = &std::cout;
  ctx.verbose = true;
  manager.run(fn, ctx);
}

} // namespace

int main(int argc, char **argv) {
  absl::ParseCommandLine(argc, argv);

  if (absl::GetFlag(FLAGS_list_passes)) return list_passes();

  std::vector<uint8_t> bytes;
  const std::string path = absl::GetFlag(FLAGS_file);
  if (!path.empty()) {
    bool ok = false;
    bytes = read_file(path, ok);
    if (!ok) return 1;
  } else {
    bytes = parse_hex(absl::GetFlag(FLAGS_bytes));
  }

  if (bytes.empty()) {
    std::cerr << "usage: --sla=file.sla (--bytes=hex | --file=path) [--base=addr]\n"
                 "       --region=BEGIN:END:SPEC repeated, for images with more than one\n"
                 "       --extract to find out what is in an unknown image\n";
    return 2;
  }

  // A transform runs before anything looks at the bytes, so the rest of the
  // pipeline analyses the decrypted or unpacked image without knowing that is
  // what happened.
  const std::string transform = absl::GetFlag(FLAGS_transform);
  if (!transform.empty()) {
    ddd::ScriptResult result = ddd::run_script(ddd::interpreter_for(transform), bytes);
    if (!result.ok) {
      std::cerr << "transform " << transform << " failed: " << result.error << '\n';
      return 1;
    }
    // Reporting, not an error: goes where the rest of the tool's output goes.
    std::cout << "transform " << transform << ": " << bytes.size() << " -> "
              << result.output.size() << " bytes\n";
    bytes = std::move(result.output);
  }

  ghidra::AttributeId::initialize();
  ghidra::ElementId::initialize();

  const uint64_t base = absl::GetFlag(FLAGS_base);
  ddd::Image image(base, std::move(bytes));

  if (absl::GetFlag(FLAGS_extract)) return run_extractors(image);

  ddd::TargetSet targets(image);
  const std::string spec_dir = absl::GetFlag(FLAGS_specs);

  std::vector<ddd::Region> regions;
  for (const std::string &text : absl::GetFlag(FLAGS_region)) {
    ddd::Region region;
    if (!parse_region(text, targets, spec_dir, region)) return 2;
    regions.push_back(region);
  }

  // No explicit regions: the whole image is one, with --sla.
  if (regions.empty()) {
    const std::string spec = absl::GetFlag(FLAGS_sla);
    if (spec.empty()) {
      std::cerr << "need --sla, or one or more --region\n";
      return 2;
    }

    ddd::Region region;
    region.begin = base;
    region.end = absl::GetFlag(FLAGS_code_end);
    if (region.end == 0 || region.end > image.limit()) region.end = image.limit();
    region.kind = ddd::RegionKind::Code;
    region.target = targets.acquire(spec, absl::GetFlag(FLAGS_abi), absl::GetFlag(FLAGS_sp),
                                    absl::GetFlag(FLAGS_ctx));
    if (region.target == nullptr) return 1;
    region.name = region.target->name;
    regions.push_back(region);
  }

  image.set_big_endian(regions.front().target->translator->isBigEndian());

  ddd::PassManager manager;
  for (const std::string &name : absl::GetFlag(FLAGS_passes)) {
    if (name.empty()) continue;
    if (manager.add(name)) continue;

    std::cerr << "unknown pass: " << name << '\n';
    list_passes();
    return 2;
  }

  // Sweep everything first. What the sweeps actually covered -- not what the
  // regions nominally span -- is the code range, and the rest of the image is
  // the data that data-refs resolves pointers into. A region bounded by --max
  // stops well short of its own end.
  const uint64_t entry = absl::GetFlag(FLAGS_entry);
  std::vector<std::unique_ptr<Lifted>> lifted;

  for (const ddd::Region &region : regions) {
    if (region.kind == ddd::RegionKind::Data || region.target == nullptr) continue;

    std::unique_ptr<Lifted> one = lift(region, regions.size() == 1 ? entry : 0);
    if (one == nullptr) {
      std::cout << "nothing could be disassembled in " << region.name << '\n';
      continue;
    }
    lifted.push_back(std::move(one));
  }
  if (lifted.empty()) return 1;

  uint64_t code_begin = lifted.front()->cfg.code_begin;
  uint64_t code_end = lifted.front()->cfg.code_end;
  for (const std::unique_ptr<Lifted> &one : lifted) {
    code_begin = std::min(code_begin, one->cfg.code_begin);
    code_end = std::max(code_end, one->cfg.code_end);
  }
  image.set_code_range(code_begin, code_end);

  for (const std::unique_ptr<Lifted> &one : lifted) analyse(*one, image, manager);

  return 0;
}
