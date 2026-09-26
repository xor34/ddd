// pcode.h -- the IR's own vocabulary: opcodes, spaces, varnodes.
//
// Sleigh used to be types-adjacent here: libsla's Address, VarnodeData, OpCode
// and AddrSpace pointers were the IR's own types, on the argument that this
// library is for Sleigh p-code so pretending otherwise bought nothing. What it
// did buy was a problem: every one of those types is per-decoder-instance.
// An AddrSpace pointer from one Sleigh is not the AddrSpace pointer from its
// worker copy, so storage identity -- the thing SSA renaming is keyed on --
// could not survive a thread boundary, which is why decoders had to be
// decode_only and hand back plain addresses and nothing else.
//
// So the boundary moved. The lifter (pcode_in.h) is the only code that sees
// libsla types; it converts at PcodeCapture::dump, and everything from here
// down is plain comparable values:
//
//   * Op            -- the p-code operation set, named without the CPUI_ prefix
//   * Spaces/SpaceId -- where a varnode lives, interned by *name*, so two
//                      decoders of the same spec agree on identity
//   * Varnode       -- space id + offset + size; also the storage identity SSA
//                      renames on, because with values instead of pointers the
//                      two are the same shape and one type is enough
//
// Addresses are plain uint64_t throughout, which is what the threaded stages
// always treated them as anyway.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace ddd {

// ---- opcodes --------------------------------------------------------------

// The p-code operation set. Same names and same order as Ghidra's CPUI_*
// (INT_ADD for CPUI_INT_ADD), minus the two the *decompiler* invents after
// lifting -- MULTIEQUAL and INDIRECT -- which Sleigh never emits and this IR
// has no use for.
enum class Op {
  COPY,
  LOAD,
  STORE,
  BRANCH,
  CBRANCH,
  BRANCHIND,
  CALL,
  CALLIND,
  CALLOTHER,
  RETURN,

  INT_EQUAL,
  INT_NOTEQUAL,
  INT_SLESS,
  INT_SLESSEQUAL,
  INT_LESS,
  INT_LESSEQUAL,
  INT_ZEXT,
  INT_SEXT,
  INT_ADD,
  INT_SUB,
  INT_CARRY,
  INT_SCARRY,
  INT_SBORROW,
  INT_2COMP,
  INT_NEGATE,
  INT_XOR,
  INT_AND,
  INT_OR,
  INT_LEFT,
  INT_RIGHT,
  INT_SRIGHT,
  INT_MULT,
  INT_DIV,
  INT_SDIV,
  INT_REM,
  INT_SREM,

  BOOL_NEGATE,
  BOOL_XOR,
  BOOL_AND,
  BOOL_OR,

  FLOAT_EQUAL,
  FLOAT_NOTEQUAL,
  FLOAT_LESS,
  FLOAT_LESSEQUAL,
  FLOAT_NAN,
  FLOAT_ADD,
  FLOAT_DIV,
  FLOAT_MULT,
  FLOAT_SUB,
  FLOAT_NEG,
  FLOAT_ABS,
  FLOAT_SQRT,
  FLOAT_INT2FLOAT,
  FLOAT_FLOAT2FLOAT,
  FLOAT_TRUNC,
  FLOAT_CEIL,
  FLOAT_FLOOR,
  FLOAT_ROUND,

  PIECE,
  SUBPIECE,
  CAST,
  PTRADD,
  PTRSUB,
  SEGMENTOP,
  CPOOLREF,
  NEW,
  INSERT,
  ZPULL,
  POPCOUNT,
  LZCOUNT,
  SPULL,

  // One past the last op, so a table indexed by Op has a size without a
  // second list to keep in step with this one. Not an operation: op_name()
  // returns null for it, and nothing should ever be lifted to it.
  kCount,
};

// The p-code name, as Sleigh spells it ("INT_ADD"). Null for an out-of-range
// value, so a caller that has been handed an unknown op can say so.
const char *op_name(Op op);

// The op a p-code name spells, or nothing when no op is called that. The
// inverse of op_name(), for reading patterns a user wrote down.
std::optional<Op> op_from_name(const std::string &name);

// Does this op end a basic block?
bool is_terminator(Op op);

// Does this op do something beyond producing its output?
//
// Only these may not be deleted when nobody reads their result. LOAD is on
// the list deliberately: this tool is pointed at firmware, where a load can
// be a device register read whose *occurrence* is the point, and silently
// dropping one would be misleading in exactly the situation it is for.
bool has_side_effects(Op op);

// ---- spaces ----------------------------------------------------------------

enum class SpaceKind {
  Constant, // offsets are literals, not locations
  Register, // the machine's register bank
  Unique,   // Sleigh's lowering temporaries
  Other,    // addressable memory and everything else: "ram", "DATA", io
};

// Where a varnode lives. Interned by name, so identity is value identity: the
// "register" space one Sleigh built and the "register" space its worker copy
// built get the same id, which is the whole point.
using SpaceId = int;

inline constexpr SpaceId kNoSpace = -1;

struct SpaceDesc {
  std::string name;
  SpaceKind kind = SpaceKind::Other;
};

class Spaces {
public:
  // The constant and unique spaces are the same everywhere -- every Sleigh
  // builds exactly one of each, with these names -- so they are seeded first
  // and their ids are fixed. "Is this varnode a constant" is then a pure
  // value test (below), not a table lookup.
  Spaces() {
    intern("const", SpaceKind::Constant);
    intern("unique", SpaceKind::Unique);
  }

  // The id for a space of this name, adding one if it has not been seen.
  SpaceId intern(std::string name, SpaceKind kind);

  // The id for a space of this name, or kNoSpace if it has not been seen.
  SpaceId find(const std::string &name) const;

  int size() const;

  // By value, not by reference: decode threads intern into this table
  // (which can reallocate it) at the same time as a reader is printing, and a
  // reference cannot be made to survive that.
  std::string name(SpaceId id) const;
  SpaceKind kind(SpaceId id) const;

  bool is_kind(SpaceId id, SpaceKind kind) const;

private:
  // Every decode interns through the one table its TargetSet owns, and
  // worker decodes run on their own threads -- so the table is shared and
  // this is the lock that makes that safe. Uncontended in practice: a spec
  // names a handful of spaces and intern only fires the first time each is
  // seen.
  mutable std::mutex mutex_;
  std::vector<SpaceDesc> spaces_;
  std::map<std::string, SpaceId> by_name_;
};

inline constexpr SpaceId kConstantSpace = 0;
inline constexpr SpaceId kUniqueSpace = 1;

// ---- varnodes ---------------------------------------------------------------

// A value: where it lives and how wide it is. Constants live in the constant
// space and carry their value in `offset`.
//
// This is also the storage identity SSA renaming is keyed on: two varnodes
// name the same variable iff they agree on all three fields, which is what
// the equality below says.
//
// Sub-register overlap is deliberately NOT modelled: writing AL and then
// reading AX are two different varnodes here. Fixing that properly means a
// register-bank slicing pre-pass over the p-code before build_ssa() ever sees
// it; see README.md.
struct Varnode {
  SpaceId space = kNoSpace;
  uint64_t offset = 0;
  uint32_t size = 0;

  bool operator==(const Varnode &o) const {
    return space == o.space && offset == o.offset && size == o.size;
  }
  bool operator!=(const Varnode &o) const { return !(*this == o); }

  // Ordered by space id, then offset, then size. Space ids are intern order,
  // which is fixed within a run, so every downstream result -- phi placement
  // order, value numbering, printed output -- is the same from run to run
  // where it was previously a coin flip under ASLR.
  bool operator<(const Varnode &o) const {
    if (space != o.space)
      return space < o.space;
    if (offset != o.offset)
      return offset < o.offset;
    return size < o.size;
  }
};

struct VarnodeHash {
  size_t operator()(const Varnode &v) const noexcept {
    size_t h = std::hash<SpaceId>()(v.space);
    h ^= std::hash<uint64_t>()(v.offset) + 0x9e3779b97f4a7c15ULL + (h << 6) +
         (h >> 2);
    h ^= std::hash<uint32_t>()(v.size) + 0x9e3779b97f4a7c15ULL + (h << 6) +
         (h >> 2);
    return h;
  }
};

inline bool is_constant(const Varnode &vn) {
  return vn.space == kConstantSpace;
}

// A temporary introduced by the Sleigh translation itself ("unique" space).
inline bool is_temporary(const Varnode &vn) { return vn.space == kUniqueSpace; }

// Human-readable in the p-code style: "register:0x0:8", "0x10:4".
std::string to_string(const Varnode &vn, const Spaces &spaces);

// ---- addresses ----------------------------------------------------------------

// A destination: which space, and where in it. Varnode says this about
// storage, with a width attached; Addr says it where there is no width to
// carry -- where a branch goes, what a call target or a reference points at.
//
// It exists because a bare offset is not a location. A p-code branch names its
// destination as a varnode whose *space is the space it branches into*, so
// collapsing it to an offset both resolves it against the wrong space (by
// offset collision, which is worse than failing) and reports it as though it
// were in this one.
//
// Not every address is an Addr, on purpose: sweeping a function walks bytes in
// one space, so everything a sweep produces (instruction addresses, block
// bounds, SsaOp::addr) is an *offset in Cfg::code_space*, which records which
// space that is once instead of repeating it per field. Addr appears exactly
// where a destination can name a different space than the code it sits in.
struct Addr {
  SpaceId space = kNoSpace; // kNoSpace: not a location at all
  uint64_t offset = 0;

  bool operator==(const Addr &o) const {
    return space == o.space && offset == o.offset;
  }
  bool operator!=(const Addr &o) const { return !(*this == o); }

  bool operator<(const Addr &o) const {
    if (space != o.space)
      return space < o.space;
    return offset < o.offset;
  }
};

struct AddrHash {
  size_t operator()(const Addr &a) const noexcept {
    size_t h = std::hash<SpaceId>()(a.space);
    h ^= std::hash<uint64_t>()(a.offset) + 0x9e3779b97f4a7c15ULL + (h << 6) +
         (h >> 2);
    return h;
  }
};

// "ram:0x1000", or "0x1000" when there is no space to name.
std::string to_string(const Addr &addr, const Spaces &spaces);

// The bits an integer of `size` bytes occupies, for masking a wider (64-bit)
// container down to it. size 0 or size >= 8 keeps everything -- there is
// nothing narrower to mask to.
inline uint64_t mask_for(uint32_t size) {
  return size >= 8 ? ~uint64_t(0) : (uint64_t(1) << (size * 8)) - 1;
}

// Reinterprets the low `from_size` bytes of `value` as a two's-complement
// signed integer of that width, sign-extended out to 64 bits. p-code hands
// values around as unsigned constants regardless of how the operation that
// produced them meant them, so anything that needs the signed reading --
// constant folding, a stack offset that is really negative -- goes through
// this rather than trusting the machine width of the surrounding uint64_t.
inline uint64_t sign_extend(uint64_t value, uint32_t from_size) {
  if (from_size == 0 || from_size >= 8)
    return value;
  const uint64_t sign_bit = uint64_t(1) << (from_size * 8 - 1);
  const uint64_t mask = mask_for(from_size);
  value &= mask;
  return (value & sign_bit) ? (value | ~mask) : value;
}

// ---- stored p-code ----------------------------------------------------------

// One p-code operation. `addr` is the address of the *machine instruction*
// this op was lowered from, so several ops can share it.
struct PcodeOp {
  uint64_t addr = 0;
  Op opc = Op::COPY;
  bool has_output = false;
  Varnode output{};
  std::vector<Varnode> inputs;
};

// LOAD and STORE carry the address space they operate on as a constant in
// their first operand. That constant's offset *is* the SpaceId of the target
// space -- the lifter interns it like any other space -- so it can be read as
// an integer and printed as a name, where the old encoded AddrSpace pointer
// could be neither.
inline bool is_space_operand(const PcodeOp &op, size_t index) {
  return index == 0 && (op.opc == Op::LOAD || op.opc == Op::STORE);
}

} // namespace ddd
