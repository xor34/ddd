#include "xrefs.h"

#include "opcodes.hh"

namespace ddd {

void Xrefs::add(const Cfg &cfg, const std::string &function) {
  auto record = [&](uint64_t from, uint64_t to, const char *kind) {
    Xref xref;
    xref.from = from;
    xref.to = to;
    xref.kind = kind;
    xref.in = function;
    incoming_[to].push_back(std::move(xref));
    ++count_;
  };

  for (const BasicBlock &block : cfg.blocks) {
    for (const PcodeOp &op : block.ops) {
      const uint64_t from = op.addr.getOffset();

      switch (op.opc) {
      case ghidra::CPUI_CALL:
        if (!op.inputs.empty()) record(from, op.inputs[0].offset, "call");
        break;

      case ghidra::CPUI_BRANCH:
      case ghidra::CPUI_CBRANCH:
        // Only branches leaving this function are worth indexing; the ones
        // inside it are the control flow the listing already draws.
        if (!op.inputs.empty() && !is_constant(op.inputs[0]) &&
            (op.inputs[0].offset < cfg.code_begin || op.inputs[0].offset >= cfg.code_end))
          record(from, op.inputs[0].offset, "branch");
        break;

      default:
        // A constant that is an address of anything is a reference: a string,
        // a table, a function pointer. Which of those it is, the caller
        // decides by looking at what lives there.
        for (const VarnodeData &in : op.inputs)
          if (is_constant(in) && in.offset != 0) record(from, in.offset, "data");
        break;
      }
    }
  }
}

std::vector<uint64_t> Xrefs::call_targets() const {
  std::vector<uint64_t> targets;

  // incoming_ is ordered, so this comes out sorted without sorting it.
  for (const auto &entry : incoming_) {
    for (const Xref &xref : entry.second) {
      if (xref.kind != "call")
        continue;
      targets.push_back(entry.first);
      break;
    }
  }

  return targets;
}

const std::vector<Xref> &Xrefs::to(uint64_t address) const {
  static const std::vector<Xref> none;
  auto it = incoming_.find(address);
  return it == incoming_.end() ? none : it->second;
}

} // namespace ddd
