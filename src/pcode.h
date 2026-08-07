// pcode.h -- stored p-code ops and the storage identity SSA renames on.
//
// Sleigh hands out p-code through a push-style callback (PcodeEmit::dump).
// Everything downstream wants a random-access array instead, so PcodeCapture
// turns the push into a pull.
//
// Types from libsla (Address, VarnodeData, OpCode, AddrSpace) are used
// directly -- there is no wrapper layer and no traits indirection. This
// library is for Sleigh p-code; pretending otherwise only bought us
// templates.
#pragma once

#include "address.hh"
#include "opcodes.hh"
#include "pcoderaw.hh"
#include "translate.hh"
#include "types.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ddd {

using ghidra::Address;
using ghidra::AddrSpace;
using ghidra::OpCode;
using ghidra::VarnodeData;

// One p-code operation. `addr` is the address of the *machine instruction*
// this op was lowered from, so several ops can share it.
struct PcodeOp {
  Address addr;
  OpCode opc = ghidra::CPUI_COPY;
  bool has_output = false;
  VarnodeData output{};
  std::vector<VarnodeData> inputs;
};

// Storage identity. Two varnodes name the same variable iff they agree on
// space + offset + size, which is what SSA renaming is keyed on.
//
// Sub-register overlap is deliberately NOT modelled: writing AL and then
// reading AX are two different Storages here. Fixing that properly means a
// register-bank slicing pre-pass over the p-code before build_ssa() ever
// sees it; see README.md.
struct Storage {
  AddrSpace *space = nullptr;
  uint64_t offset = 0;
  uint32_t size = 0;

  bool operator==(const Storage &o) const {
    return space == o.space && offset == o.offset && size == o.size;
  }
  bool operator!=(const Storage &o) const { return !(*this == o); }

  // Ordered by the space's *index*, not its address: sorting on the pointer
  // would reorder under ASLR and make every downstream result -- phi
  // placement order, value numbering, printed output -- differ run to run.
  bool operator<(const Storage &o) const {
    int index = space != nullptr ? space->getIndex() : -1;
    int other = o.space != nullptr ? o.space->getIndex() : -1;
    if (index != other)
      return index < other;
    if (offset != o.offset)
      return offset < o.offset;
    return size < o.size;
  }
};

struct StorageHash {
  size_t operator()(const Storage &s) const noexcept {
    size_t h = std::hash<const void *>()(s.space);
    h ^= std::hash<uint64_t>()(s.offset) + 0x9e3779b97f4a7c15ULL + (h << 6) +
         (h >> 2);
    h ^= std::hash<uint32_t>()(s.size) + 0x9e3779b97f4a7c15ULL + (h << 6) +
         (h >> 2);
    return h;
  }
};

inline Storage storage_of(const VarnodeData &vn) {
  return Storage{vn.space, static_cast<uint64_t>(vn.offset),
                 static_cast<uint32_t>(vn.size)};
}

inline bool is_constant(const VarnodeData &vn) {
  return vn.space != nullptr && vn.space->getType() == ghidra::IPTR_CONSTANT;
}

// A temporary introduced by the Sleigh translation itself ("unique" space).
inline bool is_temporary(const VarnodeData &vn) {
  return vn.space != nullptr && vn.space->getType() == ghidra::IPTR_INTERNAL;
}

// Does this op end a basic block?
bool is_terminator(OpCode opc);

std::string to_string(const VarnodeData &vn);
std::string to_string(const Storage &s);

// PcodeEmit sink that stores ops instead of printing them.
class PcodeCapture final : public ghidra::PcodeEmit {
public:
  std::vector<PcodeOp> ops;

  void dump(const Address &addr, OpCode opc, VarnodeData *outvar,
            VarnodeData *vars, ghidra::int4 input_count) override;
};

// AssemblyEmit that throws the text away -- we only ever want the length
// that printAssembly()/oneInstruction() returns.
class NullAssembly final : public ghidra::AssemblyEmit {
public:
  void dump(const Address &, const std::string &,
            const std::string &) override {}
};

} // namespace ddd
