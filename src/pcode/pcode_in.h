// pcode_in.h -- the Sleigh side of the boundary: libsla types in, IR out.
//
// This is the only header in the tree that includes libsla. Everything the
// lifter hands downstream -- opcodes, varnodes, spaces, addresses -- leaves
// here already converted to the IR's own value types (pcode.h), so no
// decoder-instance state (an AddrSpace pointer, an Address's space) can leak
// into anything a second decoder's output has to be compared against.
#pragma once

#include "opcodes.hh"
#include "pcoderaw.hh"
#include "translate.hh"
#include "types.h"

#include "pcode/pcode.h"

#include <vector>

namespace ddd {

// ghidra::OpCode -> Op, by position: the two enums list the same operations in
// the same order, minus the decompiler-internal pair this IR has no use for.
// CPUI_MULTIEQUAL and CPUI_INDIRECT map to Op::COPY -- the lifter asserts
// they never arrive, since Sleigh does not emit them.
Op to_op(ghidra::OpCode opc);

// Space identity conversion. Interned by name into `spaces`, so two decoders
// of one spec produce the same ids. `cache` is indexed by the libsla space's
// own index and grows on demand; interning is a name lookup and a decode can
// ask about the same space a hundred thousand times.
struct SpaceCache {
  std::vector<SpaceId> by_ghidra_index;

  SpaceId of(const ghidra::AddrSpace *space, Spaces &spaces);
};

Varnode to_varnode(const ghidra::VarnodeData &vn, SpaceCache &cache,
                   Spaces &spaces);

// PcodeEmit sink that converts and stores ops instead of printing them.
class PcodeCapture final : public ghidra::PcodeEmit {
public:
  PcodeCapture(SpaceCache &cache, Spaces &spaces)
      : cache_(&cache), spaces_(&spaces) {}

  std::vector<PcodeOp> ops;

  void dump(const ghidra::Address &addr, ghidra::OpCode opc,
            ghidra::VarnodeData *outvar, ghidra::VarnodeData *vars,
            ghidra::int4 input_count) override;

private:
  SpaceCache *cache_ = nullptr;
  Spaces *spaces_ = nullptr;
};

// AssemblyEmit that throws the text away -- we only ever want the length
// that printAssembly()/oneInstruction() returns.
class NullAssembly final : public ghidra::AssemblyEmit {
public:
  void dump(const ghidra::Address &, const std::string &,
            const std::string &) override {}
};

} // namespace ddd
