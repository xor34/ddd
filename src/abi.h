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

} // namespace ddd
