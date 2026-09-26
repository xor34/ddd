// pcode_in.cpp -- the Ghidra side of the boundary (see pcode_in.h).
//
// The two enum orders agree (this IR's Op lists the same operations in the
// same order Ghidra's CPUI_* does), minus the decompiler-internal pair
// Sleigh never emits, so conversion is arithmetic on the value rather than a
// 70-entry table to keep in step by hand.
#include "pcode_in.h"

#include "address.hh"
#include "space.hh"

#include <cassert>

namespace ddd {

// ghidra::OpCode value -> Op:
//   1..44  map straight (offset -1)
//   45     is unused in Ghidra's numbering
//   46..59 skip it (offset -2)
//   60,61  are MULTIEQUAL and INDIRECT, decompiler-internal, never lifted
//   62..74 skip all three holes (offset -4)
Op to_op(ghidra::OpCode opc) {
  const int v = static_cast<int>(opc);
  if (v >= 1 && v <= 44)
    return static_cast<Op>(v - 1);
  if (v >= 46 && v <= 59)
    return static_cast<Op>(v - 2);
  if (v >= 62 && v <= 74)
    return static_cast<Op>(v - 4);
  assert(false && "unexpected p-code opcode (decompiler-internal?)");
  return Op::COPY;
}

SpaceId SpaceCache::of(const ghidra::AddrSpace *space, Spaces &spaces) {
  if (space == nullptr)
    return kNoSpace;

  const int index = space->getIndex();
  if (index < 0)
    return kNoSpace;
  if (index >= static_cast<int>(by_ghidra_index.size()))
    by_ghidra_index.resize(index + 1, kNoSpace);

  SpaceId &slot = by_ghidra_index[index];
  if (slot == kNoSpace) {
    SpaceKind kind = SpaceKind::Other;
    switch (space->getType()) {
    case ghidra::IPTR_CONSTANT:
      kind = SpaceKind::Constant;
      break;
    case ghidra::IPTR_INTERNAL:
      kind = SpaceKind::Unique;
      break;
    default:
      // The register bank is a processor space like any other; what makes it
      // one is the name Sleigh gives it, which is what the default SSA track
      // filter and every "is this a register" question keys on.
      if (space->getName() == "register")
        kind = SpaceKind::Register;
      break;
    }
    slot = spaces.intern(space->getName(), kind);
  }
  return slot;
}

Varnode to_varnode(const ghidra::VarnodeData &vn, SpaceCache &cache,
                   Spaces &spaces) {
  Varnode out;
  out.space = cache.of(vn.space, spaces);
  out.offset = static_cast<uint64_t>(vn.offset);
  out.size = static_cast<uint32_t>(vn.size);
  return out;
}

void PcodeCapture::dump(const ghidra::Address &addr, ghidra::OpCode opc,
                        ghidra::VarnodeData *outvar, ghidra::VarnodeData *vars,
                        ghidra::int4 input_count) {
  PcodeOp op;
  op.addr = addr.getOffset();
  op.opc = to_op(opc);
  if (outvar != nullptr) {
    op.has_output = true;
    op.output = to_varnode(*outvar, *cache_, *spaces_);
  }

  op.inputs.reserve(static_cast<size_t>(input_count));
  for (ghidra::int4 i = 0; i < input_count; ++i) {
    // The first input of a LOAD or STORE names the address space it operates
    // on: a constant-space varnode whose offset is an *encoded AddrSpace
    // pointer*, not a number. It becomes the target space's SpaceId, so it
    // can be read as an integer and printed as a name -- neither of which the
    // pointer could be.
    if (i == 0 &&
        (opc == ghidra::CPUI_LOAD || opc == ghidra::CPUI_STORE)) {
      const auto *target =
          reinterpret_cast<const ghidra::AddrSpace *>(vars[0].offset);
      op.inputs.push_back(Varnode{
          cache_->of(vars[0].space, *spaces_),
          static_cast<uint64_t>(cache_->of(target, *spaces_)),
          static_cast<uint32_t>(vars[0].size)});
      continue;
    }
    op.inputs.push_back(to_varnode(vars[i], *cache_, *spaces_));
  }

  ops.push_back(std::move(op));
}

} // namespace ddd
