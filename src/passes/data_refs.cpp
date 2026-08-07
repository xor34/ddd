// data-refs -- resolve constants that point at data.
//
// The sweep only decodes instructions, but the image it was given usually
// holds more than that. A constant operand landing inside the image, outside
// the range the sweep walked, is a pointer to data -- so say what is there
// instead of leaving a bare number.
#include "../pass.h"

#include "opcodes.hh"

#include <ostream>
#include <sstream>

namespace ddd {
namespace {

std::string escape(const std::string &text) {
  std::string out;
  for (char c : text) {
    switch (c) {
    case '\n': out += "\\n"; break;
    case '\t': out += "\\t"; break;
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    default: out.push_back(c);
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
      if (ctx.verbose) ctx.stream() << "  no image, skipping\n";
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
        if (!in.is_constant()) continue;
        // Some constant operands are not values at all: the address space of a
        // LOAD/STORE, the userop index of a CALLOTHER.
        if (is_space_operand(op, i)) continue;
        if (op.opc == ghidra::CPUI_CALLOTHER && i == 0) continue;

        std::string described = describe(*ctx.image, in.constant());
        if (described.empty()) continue;

        ctx.annotations->comment(op, described);
        ++resolved;
      }
    });

    if (ctx.verbose) ctx.stream() << "  " << resolved << " data reference(s)\n";
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
  static std::string describe(const Image &image, uint64_t address) {
    if (!image.is_data(address)) return {};

    std::ostringstream os;
    os << "0x" << std::hex << address << " -> ";

    if (std::optional<std::string> text = image.read_string(address)) {
      os << '"' << escape(*text) << '"';
      return os.str();
    }

    if (address < image.code_end()) return {};

    if (std::optional<uint64_t> word = image.read_int(address, 8)) {
      os << "0x" << std::hex << *word << " (8 bytes)";
      return os.str();
    }
    if (std::optional<uint64_t> word = image.read_int(address, 4)) {
      os << "0x" << std::hex << *word << " (4 bytes)";
      return os.str();
    }

    os << "data";
    return os.str();
  }
};

DDD_REGISTER_PASS(DataRefs);

} // namespace
} // namespace ddd
