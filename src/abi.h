// abi.h -- just enough of a calling convention to say what a call's arguments
// are.
//
// A .sla file describes the instruction set, not the ABI: that lives in
// Ghidra's .cspec, which this tool does not load. So conventions are a small
// hand-written table, picked by looking for a signature register in the
// loaded spec.
#pragma once

#include "pcode.h"

#include <string>
#include <vector>

namespace ghidra {
class Sleigh;
}

namespace ddd {

struct CallingConvention {
  std::string name;
  std::string signature_register;     // used to recognise the architecture
  std::vector<std::string> arguments; // integer/pointer args, in order
  std::string result;                 // where the return value comes back
  std::string stack_pointer;

  // Where the return address is when the function is entered. Architectures
  // split two ways: a link register (AArch64 x30, ARM lr, MIPS ra, PPC lr),
  // or pushed on the stack by the call instruction (x86). Without this, the
  // stack slot an x86 RET pops looks exactly like an incoming argument.
  std::string return_address_register; // empty when it is on the stack
  int64_t return_address_offset = 0;   // from the entry stack pointer
  bool return_address_on_stack = false;

  // Registers the caller may still rely on after the call returns. Together
  // with `result` and `stack_pointer` these are what is observable at exit,
  // which is what stops dead-code elimination from deleting the function's
  // own output.
  std::vector<std::string> preserved;
};

const std::vector<CallingConvention> &conventions();

// Exact lookup by name; null if there is no such convention.
const CallingConvention *find_convention(const std::string &name);

// First convention whose signature and argument registers all exist in the
// loaded spec. Null if none match.
const CallingConvention *guess_convention(ghidra::Sleigh &translator);

// Storage for a register by name, or a zeroed Storage if the spec has no such
// register.
Storage register_storage(ghidra::Sleigh &translator, const std::string &name);

// Context a spec needs before it decodes the way its name suggests.
//
// A .sla on its own has no default mode -- that lives in Ghidra's .ldefs,
// which this tool does not read -- so x86-64.sla decodes 16-bit real mode
// until told otherwise, and `mov eax, ebx` comes out as `MOV AX,BX`. This
// supplies the mode its name implies, and only when the caller named no
// context of its own.
std::vector<std::string> default_context(const std::string &spec_path);

} // namespace ddd
