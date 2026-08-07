#include "abi.h"

#include "error.hh"
#include "sleigh.hh"

#include <algorithm>

namespace ddd {

const std::vector<CallingConvention> &conventions() {
  static const std::vector<CallingConvention> table = {
      {"aapcs64", "x0", {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}, "x0", "sp"},
      {"sysv-x86-64", "RDI", {"RDI", "RSI", "RDX", "RCX", "R8", "R9"}, "RAX", "RSP"},
      {"cdecl-x86", "ESP", {}, "EAX", "ESP"},
      {"aapcs32", "r0", {"r0", "r1", "r2", "r3"}, "r0", "sp"},
      {"mips-o32", "a0", {"a0", "a1", "a2", "a3"}, "v0", "sp"},
      {"ppc-sysv", "r3", {"r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"}, "r3", "r1"},
  };
  return table;
}

const CallingConvention *find_convention(const std::string &name) {
  const std::vector<CallingConvention> &table = conventions();
  auto it = std::find_if(table.begin(), table.end(),
                         [&](const CallingConvention &c) { return c.name == name; });
  return it == table.end() ? nullptr : &*it;
}

Storage register_storage(ghidra::Sleigh &translator, const std::string &name) {
  try {
    const VarnodeData &vn = translator.getRegister(name);
    return storage_of(vn);
  } catch (ghidra::LowlevelError &) {
    return Storage{};
  }
}

const CallingConvention *guess_convention(ghidra::Sleigh &translator) {
  for (const CallingConvention &convention : conventions()) {
    if (register_storage(translator, convention.signature_register).space == nullptr) continue;
    if (register_storage(translator, convention.stack_pointer).space == nullptr) continue;
    return &convention;
  }
  return nullptr;
}

} // namespace ddd
