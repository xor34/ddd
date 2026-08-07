// const-prop -- sparse conditional-free constant propagation over SSA.
//
// An example of the sparse engine: the whole analysis is the lattice below
// plus the callbacks in build_analysis(). Nothing here knows about blocks or
// the CFG -- def-use edges carry everything.
#include "../pass.h"
#include "../sparse.h"

#include "opcodes.hh"

#include <ostream>

namespace ddd {
namespace {

// Top ("not reached yet") > Const(v) > Bottom ("not a single constant").
struct Const {
  enum State { Top, Known, Bottom } state = Top;
  uint64_t value = 0;

  static Const known(uint64_t v) { return Const{Known, v}; }
  static Const bottom() { return Const{Bottom, 0}; }

  bool operator==(const Const &o) const {
    return state == o.state && (state != Known || value == o.value);
  }
};

Const meet(const Const &a, const Const &b) {
  if (a.state == Const::Top) return b;
  if (b.state == Const::Top) return a;
  if (a.state == Const::Bottom || b.state == Const::Bottom) return Const::bottom();
  return a.value == b.value ? a : Const::bottom();
}

uint64_t mask_for(uint32_t size) {
  return size >= 8 ? ~uint64_t(0) : (uint64_t(1) << (size * 8)) - 1;
}

uint64_t sign_extend(uint64_t value, uint32_t from_size) {
  if (from_size == 0 || from_size >= 8) return value;
  uint64_t sign_bit = uint64_t(1) << (from_size * 8 - 1);
  uint64_t m = mask_for(from_size);
  value &= m;
  return (value & sign_bit) ? (value | ~m) : value;
}

// Byte width of an input, whether it was renamed or left raw.
uint32_t operand_size(const SsaOp &op, size_t i) {
  if (i >= op.ins.size()) return 8;
  const SsaOperand &operand = op.ins[i];
  if (operand.value != nullptr) return operand.value->storage.size;
  return operand.raw.space != nullptr ? static_cast<uint32_t>(operand.raw.size) : 8;
}

// Returns Bottom for anything not modelled -- the conservative direction.
Const evaluate(const SsaOp &op, const std::vector<Const> &in) {
  uint32_t out_size = op.out->storage.size;
  uint64_t out_mask = mask_for(out_size);
  auto truncated = [&](uint64_t v) { return Const::known(v & out_mask); };

  auto unary = [&](uint64_t &a) {
    if (in.size() < 1) return false;
    a = in[0].value;
    return true;
  };
  auto binary = [&](uint64_t &a, uint64_t &b) {
    if (in.size() < 2) return false;
    a = in[0].value;
    b = in[1].value;
    return true;
  };

  uint64_t a = 0, b = 0;
  switch (op.opc) {
  case ghidra::CPUI_COPY:
    return unary(a) ? truncated(a) : Const::bottom();

  case ghidra::CPUI_INT_ADD:
    return binary(a, b) ? truncated(a + b) : Const::bottom();
  case ghidra::CPUI_INT_SUB:
    return binary(a, b) ? truncated(a - b) : Const::bottom();
  case ghidra::CPUI_INT_MULT:
    return binary(a, b) ? truncated(a * b) : Const::bottom();
  case ghidra::CPUI_INT_AND:
    return binary(a, b) ? truncated(a & b) : Const::bottom();
  case ghidra::CPUI_INT_OR:
    return binary(a, b) ? truncated(a | b) : Const::bottom();
  case ghidra::CPUI_INT_XOR:
    return binary(a, b) ? truncated(a ^ b) : Const::bottom();
  case ghidra::CPUI_INT_NEGATE:
    return unary(a) ? truncated(~a) : Const::bottom();
  case ghidra::CPUI_INT_2COMP:
    return unary(a) ? truncated(~a + 1) : Const::bottom();

  case ghidra::CPUI_INT_LEFT:
    if (!binary(a, b)) return Const::bottom();
    return b >= 64 ? truncated(0) : truncated(a << b);
  case ghidra::CPUI_INT_RIGHT:
    if (!binary(a, b)) return Const::bottom();
    return b >= 64 ? truncated(0) : truncated((a & mask_for(operand_size(op, 0))) >> b);
  case ghidra::CPUI_INT_SRIGHT:
    if (!binary(a, b)) return Const::bottom();
    if (b >= 64) b = 63;
    return truncated(static_cast<uint64_t>(
        static_cast<int64_t>(sign_extend(a, operand_size(op, 0))) >> b));

  case ghidra::CPUI_INT_ZEXT:
    return unary(a) ? truncated(a & mask_for(operand_size(op, 0))) : Const::bottom();
  case ghidra::CPUI_INT_SEXT:
    return unary(a) ? truncated(sign_extend(a, operand_size(op, 0))) : Const::bottom();

  case ghidra::CPUI_INT_EQUAL:
    return binary(a, b) ? Const::known(a == b ? 1 : 0) : Const::bottom();
  case ghidra::CPUI_INT_NOTEQUAL:
    return binary(a, b) ? Const::known(a != b ? 1 : 0) : Const::bottom();
  case ghidra::CPUI_INT_LESS:
    return binary(a, b) ? Const::known(a < b ? 1 : 0) : Const::bottom();
  case ghidra::CPUI_INT_LESSEQUAL:
    return binary(a, b) ? Const::known(a <= b ? 1 : 0) : Const::bottom();
  case ghidra::CPUI_INT_SLESS:
    if (!binary(a, b)) return Const::bottom();
    return Const::known(static_cast<int64_t>(sign_extend(a, operand_size(op, 0))) <
                                static_cast<int64_t>(sign_extend(b, operand_size(op, 1)))
                            ? 1
                            : 0);

  case ghidra::CPUI_BOOL_NEGATE:
    return unary(a) ? Const::known(a ? 0 : 1) : Const::bottom();
  case ghidra::CPUI_BOOL_AND:
    return binary(a, b) ? Const::known((a && b) ? 1 : 0) : Const::bottom();
  case ghidra::CPUI_BOOL_OR:
    return binary(a, b) ? Const::known((a || b) ? 1 : 0) : Const::bottom();
  case ghidra::CPUI_BOOL_XOR:
    return binary(a, b) ? Const::known((!!a != !!b) ? 1 : 0) : Const::bottom();

  case ghidra::CPUI_SUBPIECE:
    if (!binary(a, b)) return Const::bottom();
    return truncated(b >= 8 ? 0 : (a >> (b * 8)));

  default:
    return Const::bottom();
  }
}

SparseAnalysis<Const> build_analysis() {
  SparseAnalysis<Const> analysis;

  analysis.init = [] { return Const{}; };

  // Constants are where facts enter the analysis; anything else we chose not
  // to rename (memory) is unknown.
  analysis.raw = [](const VarnodeData &vn) {
    return is_constant(vn) ? Const::known(vn.offset) : Const::bottom();
  };

  // A value defined before the function starts is unknown, not Top --
  // otherwise it would optimistically stay constant forever.
  analysis.live_in = [](const SsaValue &) { return Const::bottom(); };

  analysis.merge = meet;

  analysis.transform = [](const SsaOp &op, const ValueMap<Const> &values) {
    std::vector<Const> in;
    in.reserve(op.ins.size());
    for (const SsaOperand &operand : op.ins) in.push_back(values(operand));

    // Stay optimistic while any operand is still Top, give up as soon as one
    // is known not to be constant.
    for (const Const &c : in)
      if (c.state == Const::Top) return Const{};
    for (const Const &c : in)
      if (c.state == Const::Bottom) return Const::bottom();

    return evaluate(op, in);
  };

  return analysis;
}

class ConstProp final : public Pass {
public:
  std::string name() const override { return "const-prop"; }
  std::string description() const override {
    return "sparse constant propagation over def-use chains";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    SparseAnalysis<Const> analysis = build_analysis();
    SparseResult<Const> result = solve(fn, analysis);

    std::ostream &os = ctx.stream();
    int constants = 0;

    fn.for_each_op([&](const SsaOp &op) {
      if (op.out == nullptr) return;
      const Const &value = result[*op.out];
      if (value.state != Const::Known) return;

      ++constants;
      os << "    " << ctx.name_of(*op.out) << " = 0x" << std::hex << value.value
         << std::dec << "  (block " << op.block << ")\n";
    });

    os << "  " << constants << " constant value(s) of " << fn.value_count() << "\n";
  }
};

DDD_REGISTER_PASS(ConstProp);

} // namespace
} // namespace ddd
