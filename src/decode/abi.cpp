#include "decode/abi.h"

#include "pcode/pcode_in.h"

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

      // 32-bit x86 passes everything on the stack, in order, above the
      // return address the call pushed. Nothing is in a register, which is
      // why the stack fields below exist at all.
      {"cdecl-x86",
       "ESP",
       {},
       "EAX",
       "ESP",
       "",
       0,
       true,
       {"EBX", "ESI", "EDI", "EBP"},
       4,
       4,
       8},

      // The same argument passing; the difference is who pops them, which is
      // the callee's business and shows up as `ret 0x8` rather than `ret`.
      {"stdcall-x86",
       "ESP",
       {},
       "EAX",
       "ESP",
       "",
       0,
       true,
       {"EBX", "ESI", "EDI", "EBP"},
       4,
       4,
       8},

      // Microsoft's fastcall: the first two in registers and the rest on the
      // stack. Named rather than guessed -- it looks identical to cdecl until
      // you notice ECX and EDX are read without being written.
      {"fastcall-x86",
       "ECX",
       {"ECX", "EDX"},
       "EAX",
       "ESP",
       "",
       0,
       true,
       {"EBX", "ESI", "EDI", "EBP"},
       4,
       4,
       8},

      // A C++ member function: `this` in ECX, everything else on the stack.
      {"thiscall-x86",
       "ECX",
       {"ECX"},
       "EAX",
       "ESP",
       "",
       0,
       true,
       {"EBX", "ESI", "EDI", "EBP"},
       4,
       4,
       8},

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

const std::vector<std::string> &machine_flags() {
  // x86 first: the interrupt flag is what `sti` and `cli` are for, and the
  // direction flag is what `cld` and `std` are for -- both are machine state a
  // reader of firmware is looking for and neither is read by the code that
  // sets it. The rest are the flags an operating system writes deliberately.
  //
  // Then the Cortex-M interrupt masks, which `cpsid`/`cpsie` and `msr` write
  // for exactly the same reason.
  static const std::vector<std::string> names = {
      "IF", "DF", "TF", "AC", "NT", "IOPL", "VM",
      "PRIMASK", "FAULTMASK", "BASEPRI",
  };
  return names;
}

Varnode register_storage(ghidra::Sleigh &translator, Spaces &spaces,
                         const std::string &name) {
  try {
    const ghidra::VarnodeData &vn = translator.getRegister(name);
    SpaceCache cache;
    return to_varnode(vn, cache, spaces);
  } catch (ghidra::LowlevelError &) {
    return Varnode{};
  }
}

std::vector<Varnode> observable_storage(const CallingConvention *abi,
                                        ghidra::Sleigh *translator,
                                        Spaces &spaces) {
  std::vector<Varnode> result;
  if (abi == nullptr || translator == nullptr)
    return result;

  auto add = [&](const std::string &name) {
    if (name.empty())
      return;
    Varnode storage = register_storage(*translator, spaces, name);
    if (storage.space != kNoSpace)
      result.push_back(storage);
  };

  add(abi->result);
  add(abi->stack_pointer);
  for (const std::string &name : abi->preserved)
    add(name);

  return result;
}

CallEffects call_effects(const CallingConvention *abi,
                         ghidra::Sleigh *translator, Spaces &spaces) {
  CallEffects effects;
  if (abi == nullptr || translator == nullptr)
    return effects;

  effects.result = register_storage(*translator, spaces, abi->result);
  effects.stack_pointer = register_storage(*translator, spaces, abi->stack_pointer);

  // The call pushed the return address, so the stack pointer sits that much
  // lower for as long as the callee runs, and it is the callee's return that
  // puts it back -- which the caller's p-code does not contain. The width is
  // the register's own: a 32-bit x86 push spends four bytes, not eight.
  if (effects.stack_pointer.space != kNoSpace && abi->return_address_on_stack)
    effects.stack_delta = effects.stack_pointer.size;

  for (const std::string &name : abi->preserved) {
    const Varnode storage = register_storage(*translator, spaces, name);
    if (storage.space != kNoSpace)
      effects.preserved.push_back(storage);
  }

  return effects;
}

std::vector<std::string> default_context(const std::string &spec_path) {
  const std::string stem = std::filesystem::path(spec_path).stem().string();

  // opsize/addrsize are 0=16-bit, 1=32-bit, 2=64-bit.
  if (stem == "x86-64") return {"longMode=1", "addrsize=2", "opsize=1"};
  if (stem == "x86") return {"addrsize=1", "opsize=1"};
  return {};
}

const CallingConvention *guess_convention(ghidra::Sleigh &translator,
                                          Spaces &spaces) {
  for (const CallingConvention &convention : conventions()) {
    if (register_storage(translator, spaces, convention.signature_register)
            .space == kNoSpace)
      continue;
    if (register_storage(translator, spaces, convention.stack_pointer).space ==
        kNoSpace)
      continue;
    return &convention;
  }
  return nullptr;
}

} // namespace ddd
