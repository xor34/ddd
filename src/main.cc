// main.cc -- disassemble a byte buffer with Sleigh, build a CFG, lift it to
// SSA, and run passes over it.
//
//   ./sleigh_poc --sla=specs/x86-64.sla --bytes=4889f8 --passes=print-ssa
#include "cfg.h"
#include "pass.h"
#include "ssa.h"

#include "error.hh"
#include "loadimage.hh"
#include "sleigh.hh"

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"

ABSL_FLAG(std::string, sla, "", "SLA file");
ABSL_FLAG(std::string, bytes, "", "Hex bytes");
ABSL_FLAG(uint64_t, base, 0, "Base address");
ABSL_FLAG(int, max, 100000, "Maximum instructions");
ABSL_FLAG(std::vector<std::string>, ctx, {}, "Context variables NAME=VALUE");
ABSL_FLAG(bool, disasm, false, "Print disassembly before lifting");
ABSL_FLAG(bool, cfg, false, "Print the raw p-code CFG before lifting");
ABSL_FLAG(bool, list_passes, false, "List the registered passes and exit");
ABSL_FLAG(std::vector<std::string>, passes, std::vector<std::string>({"prune-phis", "print-ssa"}),
          "Comma-separated passes to run over the SSA form");

namespace {

class BufferLoadImage final : public ghidra::LoadImage {
public:
  BufferLoadImage(uint64_t base, std::vector<ghidra::uint1> bytes)
      : LoadImage("buffer"), base_addr_(base), data_(std::move(bytes)) {}

  void loadFill(ghidra::uint1 *ptr, ghidra::int4 size,
                const ghidra::Address &addr) override {
    ghidra::uintb start = addr.getOffset();

    for (ghidra::int4 i = 0; i < size; ++i) {
      ghidra::uintb offset = start + i;

      if (offset < base_addr_ || offset >= base_addr_ + data_.size()) {
        ptr[i] = 0;
      } else {
        ptr[i] = data_[static_cast<size_t>(offset - base_addr_)];
      }
    }
  }

  std::string getArchType() const override { return "buffer"; }
  void adjustVma(long) override {}
  size_t size() const { return data_.size(); }

private:
  uint64_t base_addr_;
  std::vector<ghidra::uint1> data_;
};

class AssemblyPrinter final : public ghidra::AssemblyEmit {
public:
  void dump(const ghidra::Address &addr, const std::string &mnem,
            const std::string &body) override {
    std::cout << "0x" << std::hex << addr.getOffset() << std::dec << ":\t" << mnem
              << ' ' << body << '\n';
  }
};

std::vector<ghidra::uint1> parse_hex(absl::string_view input) {
  std::string clean;
  for (char c : input)
    if (std::isxdigit(static_cast<unsigned char>(c))) clean.push_back(c);
  if (clean.size() & 1) clean.pop_back();

  std::vector<ghidra::uint1> result;
  result.reserve(clean.size() / 2);

  for (size_t i = 0; i < clean.size(); i += 2) {
    uint32_t value;
    if (!absl::SimpleHexAtoi(absl::string_view(clean).substr(i, 2), &value)) continue;
    result.push_back(static_cast<ghidra::uint1>(value));
  }

  return result;
}

bool parse_context(const std::vector<std::string> &args, ghidra::ContextInternal &context) {
  for (const std::string &item : args) {
    std::vector<absl::string_view> parts = absl::StrSplit(item, '=');
    if (parts.size() != 2) {
      std::cerr << "bad ctx: " << item << '\n';
      return false;
    }

    uint64_t value;
    if (!absl::SimpleAtoi(parts[1], &value)) {
      std::cerr << "bad value: " << std::string(parts[1]) << '\n';
      return false;
    }

    try {
      context.setVariableDefault(std::string(parts[0]), value);
    } catch (ghidra::LowlevelError &error) {
      std::cerr << "unknown context variable " << std::string(parts[0]) << ": "
                << error.explain << '\n';
    }
  }

  return true;
}

bool load_spec(ghidra::Sleigh &translator, const std::string &path) {
  std::string absolute = std::filesystem::absolute(path).string();
  std::istringstream wrapper("<sleigh>" + absolute + "</sleigh>");

  ghidra::DocumentStorage storage;
  try {
    storage.registerTag(storage.parseDocument(wrapper)->getRoot());
  } catch (ghidra::DecoderError &error) {
    std::cerr << "failed parsing SLA wrapper: " << error.explain << '\n';
    return false;
  }

  try {
    translator.initialize(storage);
  } catch (ghidra::LowlevelError &error) {
    std::cerr << "failed loading SLA: " << error.explain << '\n';
    return false;
  }

  return true;
}

void print_disassembly(ghidra::Sleigh &translator, const ghidra::Address &start,
                       const ghidra::Address &end, int max) {
  AssemblyPrinter printer;
  ghidra::Address addr = start;

  for (int count = 0; addr < end && count < max; ++count) {
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

int list_passes() {
  for (const ddd::PassRegistry::Entry &entry : ddd::PassRegistry::instance().entries())
    std::cout << "  " << entry.name << "\t" << entry.description << '\n';
  return 0;
}

} // namespace

int main(int argc, char **argv) {
  absl::ParseCommandLine(argc, argv);

  if (absl::GetFlag(FLAGS_list_passes)) return list_passes();

  std::string sla_path = absl::GetFlag(FLAGS_sla);
  std::vector<ghidra::uint1> bytes = parse_hex(absl::GetFlag(FLAGS_bytes));
  if (sla_path.empty() || bytes.empty()) {
    std::cerr << "usage: --sla=file.sla --bytes=hex [--base=addr] [--passes=a,b]\n";
    return 2;
  }

  ghidra::AttributeId::initialize();
  ghidra::ElementId::initialize();

  uint64_t base = absl::GetFlag(FLAGS_base);
  BufferLoadImage loader(base, std::move(bytes));
  ghidra::ContextInternal context;
  ghidra::Sleigh translator(&loader, &context);

  if (!load_spec(translator, sla_path)) return 1;
  if (!parse_context(absl::GetFlag(FLAGS_ctx), context)) return 1;

  ghidra::AddrSpace *code = translator.getDefaultCodeSpace();
  ghidra::Address start(code, base);
  ghidra::Address end(code, base + loader.size());
  int max = absl::GetFlag(FLAGS_max);

  if (absl::GetFlag(FLAGS_disasm)) print_disassembly(translator, start, end, max);

  ddd::SweepLimits limits;
  limits.max_instructions = max;
  limits.end = end;

  ddd::Cfg cfg = ddd::build_cfg(translator, start, limits);
  if (cfg.empty()) {
    std::cerr << "nothing could be disassembled at 0x" << std::hex << base << '\n';
    return 1;
  }
  if (absl::GetFlag(FLAGS_cfg)) std::cout << ddd::to_string(cfg);

  ddd::SsaFunction fn = ddd::build_ssa(cfg);

  ddd::PassManager manager;
  for (const std::string &name : absl::GetFlag(FLAGS_passes)) {
    if (name.empty()) continue;
    if (manager.add(name)) continue;

    std::cerr << "unknown pass: " << name << "\n  known passes:\n";
    list_passes();
    return 2;
  }

  ddd::PassContext ctx;
  ctx.translator = &translator;
  ctx.out = &std::cout;
  ctx.verbose = true;
  manager.run(fn, ctx);

  return 0;
}
