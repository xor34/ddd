#include "pcode.h"

#include <sstream>

namespace ddd {

bool is_terminator(OpCode opc) {
  switch (opc) {
  case ghidra::CPUI_BRANCH:
  case ghidra::CPUI_CBRANCH:
  case ghidra::CPUI_BRANCHIND:
  case ghidra::CPUI_CALL:
  case ghidra::CPUI_CALLIND:
  case ghidra::CPUI_RETURN:
    return true;
  default:
    return false;
  }
}

bool has_side_effects(OpCode opc) {
  switch (opc) {
  case ghidra::CPUI_STORE:
  case ghidra::CPUI_LOAD: // may be a device register read
  case ghidra::CPUI_BRANCH:
  case ghidra::CPUI_CBRANCH:
  case ghidra::CPUI_BRANCHIND:
  case ghidra::CPUI_CALL:
  case ghidra::CPUI_CALLIND:
  case ghidra::CPUI_CALLOTHER: // opaque userop
  case ghidra::CPUI_RETURN:
    return true;
  default:
    return false;
  }
}

std::string to_string(const VarnodeData &vn) {
  if (vn.space == nullptr)
    return "<null>";

  std::ostringstream os;
  if (is_constant(vn)) {
    os << "0x" << std::hex << vn.offset << ":" << std::dec << vn.size;
    return os.str();
  }
  os << vn.space->getName() << ":0x" << std::hex << vn.offset << ":" << std::dec
     << vn.size;
  return os.str();
}

std::string to_string(const Storage &s) {
  if (s.space == nullptr)
    return "<null>";

  std::ostringstream os;
  os << s.space->getName() << ":0x" << std::hex << s.offset << ":" << std::dec
     << s.size;
  return os.str();
}

void PcodeCapture::dump(const Address &addr, OpCode opc, VarnodeData *outvar,
                        VarnodeData *vars, ghidra::int4 input_count) {
  PcodeOp op;
  op.addr = addr;
  op.opc = opc;
  if (outvar != nullptr) {
    op.has_output = true;
    op.output = *outvar;
  }
  op.inputs.assign(vars, vars + input_count);
  ops.push_back(std::move(op));
}

} // namespace ddd
