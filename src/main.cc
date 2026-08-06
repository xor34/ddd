#include "loadimage.hh"
#include "sleigh.hh"

#include <cctype>
#include <cstdint>
#include <iostream>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"

using namespace ghidra;

ABSL_FLAG(std::string, sla, "", "SLA file");
ABSL_FLAG(std::string, bytes, "", "Hex bytes");
ABSL_FLAG(uint64_t, base, 0, "Base address");
ABSL_FLAG(int, max, 100000, "Maximum instructions");
ABSL_FLAG(std::vector<std::string>, ctx, {}, "Context variables NAME=VALUE");

class BufferLoadImage final : public LoadImage {
  uint64_t base_addr;
  std::vector<uint1> data;

public:
  BufferLoadImage(uint64_t base, std::vector<uint1> bytes)
      : LoadImage("buffer"), base_addr(base), data(std::move(bytes)) {}

  void loadFill(uint1 *ptr, int4 size, const Address &addr) override {
    uintb start = addr.getOffset();

    for (int4 i = 0; i < size; ++i) {
      uintb offset = start + i;

      if (offset < base_addr || offset >= base_addr + data.size()) {
        ptr[i] = 0;
      } else {
        ptr[i] = data[static_cast<size_t>(offset - base_addr)];
      }
    }
  }

  std::string getArchType(void) const override { return "buffer"; }

  void adjustVma(long) override {}

  size_t size() const { return data.size(); }
};

class AssemblyPrinter final : public AssemblyEmit {
public:
  void dump(const Address &addr, const std::string &mnem,
            const std::string &body) override {
    std::cout << addr.getShortcut() << ":\t" << mnem << ' ' << body << '\n';
  }
};

static void print_varnode(std::ostream &os, const VarnodeData &varnode) {
  os << '(' << varnode.space->getName() << ',';

  varnode.space->printOffset(os, varnode.offset);

  os << ',' << std::dec << varnode.size << ')';
}

class PcodePrinter final : public PcodeEmit {
public:
  void dump(const Address &addr, OpCode opcode, VarnodeData *outvar,
            VarnodeData *vars, int4 input_size) override {
    std::cout << "    ";

    if (outvar) {
      print_varnode(std::cout, *outvar);
      std::cout << " = ";
    }

    std::cout << get_opname(opcode);

    for (int4 i = 0; i < input_size; ++i) {
      std::cout << ' ';
      print_varnode(std::cout, vars[i]);
    }

    std::cout << '\n';
  }
};

static std::vector<uint1> parse_hex(absl::string_view input) {
  std::string clean;

  for (char c : input) {
    if (std::isxdigit(static_cast<unsigned char>(c))) {
      clean.push_back(c);
    }
  }

  if (clean.size() & 1) {
    clean.pop_back();
  }

  std::vector<uint1> result;
  result.reserve(clean.size() / 2);

  for (size_t i = 0; i < clean.size(); i += 2) {
    uint32_t value;

    if (!absl::SimpleHexAtoi(absl::string_view(clean).substr(i, 2), &value)) {
      continue;
    }

    result.push_back(static_cast<uint1>(value));
  }

  return result;
}

static bool parse_context(const std::vector<std::string> &args,
                          ContextInternal &context) {
  for (const auto &item : args) {
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
    } catch (LowlevelError &error) {
      std::cerr << "unknown context variable " << std::string(parts[0]) << ": "
                << error.explain << '\n';
    }
  }

  return true;
}

int main(int argc, char **argv) {
  absl::ParseCommandLine(argc, argv);

  std::string sla_path = absl::GetFlag(FLAGS_sla);
  auto bytes = parse_hex(absl::GetFlag(FLAGS_bytes));

  if (sla_path.empty() || bytes.empty()) {
    std::cerr << "usage: --sla=file.sla --bytes=hex\n";
    return 2;
  }

  uint64_t base_addr = absl::GetFlag(FLAGS_base);

  AttributeId::initialize();
  ElementId::initialize();

  BufferLoadImage loader(base_addr, std::move(bytes));

  ContextInternal context;
  Sleigh translator(&loader, &context);

  std::string abs_path = std::filesystem::absolute(sla_path).string();

  std::istringstream wrapper("<sleigh>" + abs_path + "</sleigh>");

  DocumentStorage storage;
  Element *root;

  try {
    root = storage.parseDocument(wrapper)->getRoot();
  } catch (DecoderError &error) {
    std::cerr << "Failed XML loader: " << error.explain << '\n';
    return 1;
  }

  storage.registerTag(root);

  try {
    translator.initialize(storage);
  } catch (LowlevelError &error) {
    std::cerr << "Failed loading SLA: " << error.explain << '\n';
    return 1;
  }

  parse_context(absl::GetFlag(FLAGS_ctx), context);

  AssemblyPrinter asm_emit;
  PcodePrinter pcode_emit;

  Address addr(translator.getDefaultCodeSpace(), base_addr);

  Address end_addr(translator.getDefaultCodeSpace(), base_addr + loader.size());

  int count = 0;

  while (addr < end_addr && count < absl::GetFlag(FLAGS_max)) {
    int4 length = 1;

    try {
      length = translator.printAssembly(asm_emit, addr);
      translator.oneInstruction(pcode_emit, addr);
    } catch (LowlevelError &error) {
      std::cout << addr.getShortcut() << ":\t?? (" << error.explain << ")\n";

      length = 1;
    }

    if (length <= 0) {
      length = 1;
    }

    addr = addr + length;
    ++count;
  }

  return 0;
}
