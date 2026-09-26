// abi.h -- just enough of a calling convention to say what a call's arguments
// are.
//
// A .sla file describes the instruction set, not the ABI: that lives in
// Ghidra's .cspec, which this tool does not load. So conventions are a small
// hand-written table, picked by looking for a signature register in the
// loaded spec.
#pragma once

#include "pcode/pcode.h"

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

  // Arguments the caller leaves on the stack rather than in registers.
  //
  // Which is all of them on 32-bit x86, and that is not a detail: a convention
  // with no argument registers used to mean "nothing is known about this
  // call", so a cdecl binary got no parameters at its entry and no arguments
  // at any of its calls. `stack_offset` is where the first argument sits
  // relative to the stack pointer on entry -- 4 on x86, past the return
  // address the call instruction pushed -- and `stack_slot` is how much room
  // each one takes.
  int64_t stack_offset = 0;
  unsigned stack_slot = 0; // 0: this convention passes nothing on the stack
  int stack_count = 0;     // how many slots to look at before giving up

  bool passes_on_stack() const { return stack_slot != 0 && stack_count > 0; }
};

const std::vector<CallingConvention> &conventions();

// Exact lookup by name; null if there is no such convention.
const CallingConvention *find_convention(const std::string &name);

// First convention whose signature and argument registers all exist in the
// loaded spec. Null if none match.
const CallingConvention *guess_convention(ghidra::Sleigh &translator,
                                          Spaces &spaces);

// Storage for a register by name, or a zeroed Varnode if the spec has no such
// register.
Varnode register_storage(ghidra::Sleigh &translator, Spaces &spaces,
                         const std::string &name);

// Machine state a write to is a side effect rather than a computation.
//
// Sleigh models `sti` as a write to the interrupt flag and `cld` as a write to
// the direction flag, and nothing in the function reads either -- so dead-code
// elimination, which is right about the arithmetic flags, deletes the one
// instruction the line was there for. These are looked up by name and cost
// nothing on an architecture that has no register of that name.
const std::vector<std::string> &machine_flags();

// Storage the caller can still read after a function returns: the result
// register, the stack pointer and the callee-saved registers.
//
// Needed in three places that must agree -- phi placement, dead-code
// elimination and expression folding -- because all three otherwise mistake
// the function's own output for something nobody wanted.
std::vector<Varnode> observable_storage(const CallingConvention *abi,
                                        ghidra::Sleigh *translator,
                                        Spaces &spaces);

// What a CALL does to the caller's machine state, which the CALL's own p-code
// does not say.
//
// Sleigh spends only the call itself: push the return address, transfer.
// Everything the callee does on the way back is the callee's p-code, and none
// of it is here -- so the caller's stack pointer stays one push low for the
// rest of the function, the answer the call produced is nowhere, and every
// register the callee destroyed still reads as the value it had before the
// call, which is the most damaging of the three: a function that returns
// `f(x) + 1` reads as one that returns its own `x + 1`.
//
// Neither fact is in the instructions, and both are facts about the
// convention, so they are named here once and applied by SSA construction
// (see SsaOptions::calls).
struct CallEffects {
  // Where the callee's answer arrives. A call defines it: what the register
  // held before the call is dead, and what a read after the call gets is the
  // result.
  Varnode result;

  // How far the stack pointer moves over the whole call -- the return address
  // the CALL pushed, plus whatever the callee pops beyond it. Zero on a
  // convention that leaves the return address in a register, where the call
  // has already written the link register itself.
  //
  // A callee that pops the caller's arguments (`ret 0x8`, the stdcall family)
  // moves it further, by an amount only the callee's own prototype knows. That
  // is not modelled, and a listing of such a caller will show the stack
  // pointer low by the arguments.
  int64_t stack_delta = 0;

  // Storage a call leaves alone. Every other register is fair game for the
  // callee, so the destroyed set is everything else rather than a second list
  // that could disagree with this one.
  std::vector<Varnode> preserved;

  Varnode stack_pointer;

  bool valid() const { return result.space != kNoSpace; }
};

CallEffects call_effects(const CallingConvention *abi,
                         ghidra::Sleigh *translator, Spaces &spaces);

// Context a spec needs before it decodes the way its name suggests.
//
// A .sla on its own has no default mode -- that lives in Ghidra's .ldefs,
// which this tool does not read -- so x86-64.sla decodes 16-bit real mode
// until told otherwise, and `mov eax, ebx` comes out as `MOV AX,BX`. This
// supplies the mode its name implies, and only when the caller named no
// context of its own.
std::vector<std::string> default_context(const std::string &spec_path);

} // namespace ddd
