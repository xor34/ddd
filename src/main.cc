// main.cc -- disassemble a byte buffer with Sleigh, build a CFG, lift it to
// SSA, and run passes over it.
//
//   ./sleigh_poc --sla=specs/AARCH64.sla --bytes=... --base=0x1000
#include "abi.h"
#include "cfg.h"
#include "image.h"
#include "pass.h"
#include "ssa.h"

#include "error.hh"
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
ABSL_FLAG(uint64_t, entry, 0, "Address to start disassembling from (default: --base)");
ABSL_FLAG(int, max, 100000, "Maximum instructions");
ABSL_FLAG(uint64_t, code_end, 0,
          "Stop disassembling here; the rest of the image is treated as data");
ABSL_FLAG(std::vector<std::string>, ctx, {}, "Context variables NAME=VALUE");
ABSL_FLAG(bool, disasm, false, "Print disassembly before lifting");
ABSL_FLAG(bool, cfg, false, "Print the raw p-code CFG before lifting");
ABSL_FLAG(bool, list_passes, false, "List the registered passes and exit");
ABSL_FLAG(std::string, abi, "", "Calling convention (default: guessed from the spec)");
ABSL_FLAG(std::string, sp, "", "Stack pointer register (default: from the calling convention)");
ABSL_FLAG(std::vector<std::string>, passes,
          std::vector<std::string>({"prune-phis", "stack-vars", "idioms", "data-refs",
                                    "rename", "calling-conv", "print-ssa"}),
          "Comma-separated passes to run over the SSA form");

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

// The calling convention supplies the stack pointer unless one was named
// explicitly; both may legitimately end up unset, and the passes that need
// them say so and skip.
void configure_target(ddd::PassContext &ctx, ghidra::Sleigh &translator) {
  const std::string requested = absl::GetFlag(FLAGS_abi);
  if (!requested.empty()) {
    ctx.abi = ddd::find_convention(requested);
    if (ctx.abi == nullptr) {
      std::cerr << "unknown abi: " << requested << "\n  known:";
      for (const ddd::CallingConvention &c : ddd::conventions()) std::cerr << ' ' << c.name;
      std::cerr << '\n';
    }
  } else {
    ctx.abi = ddd::guess_convention(translator);
  }

  std::string stack_pointer = absl::GetFlag(FLAGS_sp);
  if (stack_pointer.empty() && ctx.abi != nullptr) stack_pointer = ctx.abi->stack_pointer;
  if (!stack_pointer.empty()) {
    ctx.stack_pointer = ddd::register_storage(translator, stack_pointer);
    if (ctx.stack_pointer.space == nullptr)
      std::cerr << "no such register: " << stack_pointer << '\n';
  }
}

} // namespace

int main(int argc, char **argv) {
  absl::ParseCommandLine(argc, argv);

  if (absl::GetFlag(FLAGS_list_passes)) return list_passes();

  std::string sla_path = absl::GetFlag(FLAGS_sla);
  std::vector<uint8_t> bytes = parse_hex(absl::GetFlag(FLAGS_bytes));
  if (sla_path.empty() || bytes.empty()) {
    std::cerr << "usage: --sla=file.sla --bytes=hex [--base=addr] [--passes=a,b]\n";
    return 2;
  }

  ghidra::AttributeId::initialize();
  ghidra::ElementId::initialize();

  uint64_t base = absl::GetFlag(FLAGS_base);
  ddd::Image image(base, std::move(bytes));
  ddd::ImageLoader loader(image);

  ghidra::ContextInternal context;
  ghidra::Sleigh translator(&loader, &context);

  if (!load_spec(translator, sla_path)) return 1;
  if (!parse_context(absl::GetFlag(FLAGS_ctx), context)) return 1;
  image.set_big_endian(translator.isBigEndian());

  ghidra::AddrSpace *code = translator.getDefaultCodeSpace();
  uint64_t entry = absl::GetFlag(FLAGS_entry);
  if (entry == 0) entry = base;

  uint64_t code_end = absl::GetFlag(FLAGS_code_end);
  if (code_end == 0 || code_end > image.limit()) code_end = image.limit();

  ghidra::Address start(code, entry);
  ghidra::Address end(code, code_end);
  int max = absl::GetFlag(FLAGS_max);

  if (absl::GetFlag(FLAGS_disasm)) print_disassembly(translator, start, end, max);

  ddd::SweepLimits limits;
  limits.max_instructions = max;
  limits.end = end;

  ddd::Cfg cfg = ddd::build_cfg(translator, start, limits);
  if (cfg.empty()) {
    std::cerr << "nothing could be disassembled at 0x" << std::hex << entry << '\n';
    return 1;
  }
  // Whatever the sweep did not walk is data as far as the passes are
  // concerned.
  image.set_code_range(cfg.code_begin, cfg.code_end);

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
  ctx.image = &image;
  ctx.out = &std::cout;
  ctx.verbose = true;
  configure_target(ctx, translator);
  manager.run(fn, ctx);

  return 0;
}
