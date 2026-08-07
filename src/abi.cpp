#include "abi.h"

#include "error.hh"
#include "sleigh.hh"

#include <algorithm>
#include <filesystem>

namespace ddd {

const std::vector<CallingConvention> &conventions() {
  static const std::vector<CallingConvention> table = {
      // name, signature, arguments, result, stack pointer,
      //   return address (register, offset, on stack), preserved
      {"aapcs64",
       "x0",
       {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"},
       "x0",
       "sp",
       "x30",
       0,
       false,
       {"x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
        "x29"}},

      // The call instruction pushes the return address, so it is at the entry
      // stack pointer rather than in a register.
      {"sysv-x86-64",
       "RDI",
       {"RDI", "RSI", "RDX", "RCX", "R8", "R9"},
       "RAX",
       "RSP",
       "",
       0,
       true,
       {"RBX", "RBP", "R12", "R13", "R14", "R15"}},

      {"cdecl-x86",
       "ESP",
       {},
       "EAX",
       "ESP",
       "",
       0,
       true,
       {"EBX", "ESI", "EDI", "EBP"}},

      {"aapcs32",
       "r0",
       {"r0", "r1", "r2", "r3"},
       "r0",
       "sp",
       "lr",
       0,
       false,
       {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"}},

      {"mips-o32",
       "a0",
       {"a0", "a1", "a2", "a3"},
       "v0",
       "sp",
       "ra",
       0,
       false,
       {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "gp", "fp"}},

      {"ppc-sysv",
       "r3",
       {"r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"},
       "r3",
       "r1",
       "lr",
       0,
       false,
       {"r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
        "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"}},
  };
  return table;
}

const CallingConvention *find_convention(const std::string &name) {
  const std::vector<CallingConvention> &table = conventions();
  auto it =
      std::find_if(table.begin(), table.end(),
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

std::vector<Storage> observable_storage(const CallingConvention *abi,
                                        ghidra::Sleigh *translator) {
  std::vector<Storage> result;
  if (abi == nullptr || translator == nullptr)
    return result;

  auto add = [&](const std::string &name) {
    if (name.empty())
      return;
    Storage storage = register_storage(*translator, name);
    if (storage.space != nullptr)
      result.push_back(storage);
  };

  add(abi->result);
  add(abi->stack_pointer);
  for (const std::string &name : abi->preserved)
    add(name);

  return result;
}

std::vector<std::string> default_context(const std::string &spec_path) {
  const std::string stem = std::filesystem::path(spec_path).stem().string();

  // opsize/addrsize are 0=16-bit, 1=32-bit, 2=64-bit.
  if (stem == "x86-64") return {"longMode=1", "addrsize=2", "opsize=1"};
  if (stem == "x86") return {"addrsize=1", "opsize=1"};
  return {};
}

const CallingConvention *guess_convention(ghidra::Sleigh &translator) {
  for (const CallingConvention &convention : conventions()) {
    if (register_storage(translator, convention.signature_register).space ==
        nullptr)
      continue;
    if (register_storage(translator, convention.stack_pointer).space == nullptr)
      continue;
    return &convention;
  }
  return nullptr;
}

} // namespace ddd
