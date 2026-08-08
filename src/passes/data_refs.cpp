// data-refs -- resolve constants that point at data.
//
// The sweep only decodes instructions, but the image it was given usually
// holds more than that. A constant operand landing inside the image, outside
// the range the sweep walked, is a pointer to data -- so say what is there
// instead of leaving a bare number.
#include "../pass.h"

#include "opcodes.hh"
#include "sleigh.hh"

#include <ostream>
#include <sstream>

namespace ddd {
namespace {

std::string escape(const std::string &text) {
  std::string out;
  for (char c : text) {
    switch (c) {
    case '\n':
      out += "\\n";
      break;
    case '\t':
      out += "\\t";
      break;
    case '"':
      out += "\\\"";
      break;
    case '\\':
      out += "\\\\";
      break;
    default:
      out.push_back(c);
    }
  }
  return out;
}

class DataRefs final : public Pass {
public:
  std::string name() const override { return "data-refs"; }
  std::string description() const override {
    return "resolve constants pointing into the image's data";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    if (ctx.image == nullptr || ctx.image->empty()) {
      if (ctx.verbose)
        ctx.stream() << "  no image, skipping\n";
      return;
    }

    int resolved = 0;
    fn.for_each_op([&](SsaOp &op) {
      // Branch and call destinations are code; they are already shown as
      // block edges and would only add noise here.
      if (op.opc == ghidra::CPUI_BRANCH || op.opc == ghidra::CPUI_CBRANCH ||
          op.opc == ghidra::CPUI_CALL)
        return;

      for (size_t i = 0; i < op.ins.size(); ++i) {
        const SsaOperand &in = op.ins[i];
        if (!in.is_constant())
          continue;
        // Some constant operands are not values at all: the address space of a
        // LOAD/STORE, the userop index of a CALLOTHER.
        if (is_space_operand(op, i))
          continue;
        if (op.opc == ghidra::CPUI_CALLOTHER && i == 0)
          continue;

        // A load names its own width, and the fact that the program read
        // the address as data is better evidence than any heuristic: an ARM
        // literal pool sits *inside* .text, where is_data() says no.
        const bool loaded = op.opc == ghidra::CPUI_LOAD && i == 1;
        unsigned width = pointer_width(ctx);
        if (loaded) {
          if (op.out != nullptr) width = op.out->storage.size;
          else if (op.has_raw_output) width = op.raw_output.size;
        }

        std::string described =
            describe(*ctx.image, in.constant(), width, loaded);
        if (described.empty())
          continue;

        ctx.annotations->comment(op, described);
        ++resolved;
      }
    });

    if (ctx.verbose)
      ctx.stream() << "  " << resolved << " data reference(s)\n";
  }

private:
  // A constant is only worth resolving if it points somewhere that is data.
  //
  // Reading a word always "succeeds" anywhere inside the image, so that on its
  // own is no evidence at all -- with a base of 0 every small immediate would
  // come back as a pointer. Two things separate a real reference:
  //
  //   * a NUL-terminated printable run is self-validating, and is reported
  //     wherever it is found
  //   * anything else has to point past the end of everything disassembled.
  //     Small integers alias with the low addresses; the trailing data area
  //     does not.
  static unsigned pointer_width(const PassContext &ctx) {
    if (ctx.target == nullptr || ctx.target->translator == nullptr)
      return 8;
    return ctx.target->translator->getDefaultCodeSpace()->getAddrSize();
  }

  static std::string describe(const Image &image, uint64_t address,
                              unsigned width, bool loaded) {
    if (loaded ? !image.contains(address) : !image.is_data(address))
      return {};
    if (width == 0 || width > 8)
      return {};

    std::ostringstream os;
    os << "0x" << std::hex << address << " -> ";

    if (std::optional<std::string> text = image.read_string(address)) {
      os << '"' << escape(*text) << '"';
      return os.str();
    }

    if (!loaded && address < image.code_end())
      return {};

    std::optional<uint64_t> word = image.read_int(address, width);
    if (!word) {
      os << "data";
      return os.str();
    }

    os << "0x" << std::hex << *word;

    // One more hop, and no further: a literal pool entry is a pointer, and
    // the thing worth reading is what it points at, not the pointer.
    if (std::optional<std::string> text = image.read_string(*word))
      os << " -> \"" << escape(*text) << '"';
    else if (image.is_code(*word) && *word != 0)
      os << " (code)";

    return os.str();
  }
};

DDD_REGISTER_PASS(DataRefs);

} // namespace
} // namespace ddd
