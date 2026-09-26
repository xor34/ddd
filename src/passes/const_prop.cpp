// const-prop -- sparse conditional-free constant propagation over SSA.
//
// An example of the sparse engine: the whole analysis is the lattice below
// plus the callbacks in build_analysis(). Nothing here knows about blocks or
// the CFG -- def-use edges carry everything.
//
// Solving the lattice *is* the propagation, and what it says is put back into
// the IR: a value the analysis knows is a constant is replaced by that constant
// wherever it is read. `t186 = 0xb81fa808 - 0x37f747e1` is folded not because
// anything folded it but because the subtraction was found to be one of two
// constants -- the same fact, and the listing is where it starts to matter.
//
// The definitions are left where they are. They are dead once nothing reads
// them, and `dce` is the pass that decides that; deciding it here as well would
// be two passes with the same opinion, which is one too many.
//
// It runs on the sparse engine's own terms: a value is Known only if the
// lattice converged to one constant for it, which the meet at every phi is what
// earns. An operand the analysis never renamed -- a constant already, or
// memory -- is left alone, which is the conservative direction.
#include "passes/pass.h"
#include "ir/sparse.h"

#include <sstream>

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
  if (a.state == Const::Top)
    return b;
  if (b.state == Const::Top)
    return a;
  if (a.state == Const::Bottom || b.state == Const::Bottom)
    return Const::bottom();
  return a.value == b.value ? a : Const::bottom();
}

// Returns Bottom for anything not modelled -- the conservative direction.
Const evaluate(const SsaOp &op, const std::vector<Const> &in) {
  uint32_t out_size = op.out->storage.size;
  uint64_t out_mask = mask_for(out_size);
  auto truncated = [&](uint64_t v) { return Const::known(v & out_mask); };

  auto unary = [&](uint64_t &a) {
    if (in.size() < 1)
      return false;
    a = in[0].value;
    return true;
  };
  auto binary = [&](uint64_t &a, uint64_t &b) {
    if (in.size() < 2)
      return false;
    a = in[0].value;
    b = in[1].value;
    return true;
  };

  uint64_t a = 0, b = 0;
  switch (op.opc) {
  case Op::COPY:
    return unary(a) ? truncated(a) : Const::bottom();

  case Op::INT_ADD:
    return binary(a, b) ? truncated(a + b) : Const::bottom();
  case Op::INT_SUB:
    return binary(a, b) ? truncated(a - b) : Const::bottom();
  case Op::INT_MULT:
    return binary(a, b) ? truncated(a * b) : Const::bottom();
  case Op::INT_AND:
    return binary(a, b) ? truncated(a & b) : Const::bottom();
  case Op::INT_OR:
    return binary(a, b) ? truncated(a | b) : Const::bottom();
  case Op::INT_XOR:
    return binary(a, b) ? truncated(a ^ b) : Const::bottom();
  case Op::INT_NEGATE:
    return unary(a) ? truncated(~a) : Const::bottom();
  case Op::INT_2COMP:
    return unary(a) ? truncated(~a + 1) : Const::bottom();

  case Op::INT_LEFT:
    if (!binary(a, b))
      return Const::bottom();
    return b >= 64 ? truncated(0) : truncated(a << b);
  case Op::INT_RIGHT:
    if (!binary(a, b))
      return Const::bottom();
    return b >= 64 ? truncated(0)
                   : truncated((a & mask_for(operand_size(op, 0))) >> b);
  case Op::INT_SRIGHT:
    if (!binary(a, b))
      return Const::bottom();
    if (b >= 64)
      b = 63;
    return truncated(static_cast<uint64_t>(
        static_cast<int64_t>(sign_extend(a, operand_size(op, 0))) >> b));

  case Op::INT_ZEXT:
    return unary(a) ? truncated(a & mask_for(operand_size(op, 0)))
                    : Const::bottom();
  case Op::INT_SEXT:
    return unary(a) ? truncated(sign_extend(a, operand_size(op, 0)))
                    : Const::bottom();

  case Op::INT_EQUAL:
    return binary(a, b) ? Const::known(a == b ? 1 : 0) : Const::bottom();
  case Op::INT_NOTEQUAL:
    return binary(a, b) ? Const::known(a != b ? 1 : 0) : Const::bottom();
  case Op::INT_LESS:
    return binary(a, b) ? Const::known(a < b ? 1 : 0) : Const::bottom();
  case Op::INT_LESSEQUAL:
    return binary(a, b) ? Const::known(a <= b ? 1 : 0) : Const::bottom();
  case Op::INT_SLESS:
    if (!binary(a, b))
      return Const::bottom();
    return Const::known(
        static_cast<int64_t>(sign_extend(a, operand_size(op, 0))) <
                static_cast<int64_t>(sign_extend(b, operand_size(op, 1)))
            ? 1
            : 0);

  case Op::BOOL_NEGATE:
    return unary(a) ? Const::known(a ? 0 : 1) : Const::bottom();
  case Op::BOOL_AND:
    return binary(a, b) ? Const::known((a && b) ? 1 : 0) : Const::bottom();
  case Op::BOOL_OR:
    return binary(a, b) ? Const::known((a || b) ? 1 : 0) : Const::bottom();
  case Op::BOOL_XOR:
    return binary(a, b) ? Const::known((!!a != !!b) ? 1 : 0) : Const::bottom();

  case Op::SUBPIECE:
    if (!binary(a, b))
      return Const::bottom();
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
  analysis.raw = [](const Varnode &vn) {
    return is_constant(vn) ? Const::known(vn.offset) : Const::bottom();
  };

  // A value defined before the function starts is unknown, not Top --
  // otherwise it would optimistically stay constant forever.
  analysis.live_in = [](const SsaValue &) { return Const::bottom(); };

  analysis.merge = meet;

  analysis.transform = [](const SsaOp &op, const ValueMap<Const> &values) {
    std::vector<Const> in;
    in.reserve(op.ins.size());
    for (const SsaOperand &operand : op.ins)
      in.push_back(values(operand));

    // Stay optimistic while any operand is still Top, give up as soon as one
    // is known not to be constant.
    for (const Const &c : in)
      if (c.state == Const::Top)
        return Const{};
    for (const Const &c : in)
      if (c.state == Const::Bottom)
        return Const::bottom();

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

  void run(SsaFunction &fn, PassContext &) override {
    result_ = solve(fn, build_analysis());
    replaced_ = propagate(fn);
  }

  // Walked again rather than collected during run(): the lattice is what the
  // pass computes, the lines are a description of it, and a description is
  // only worth building for someone reading one.
  std::vector<std::string> report(const SsaFunction &fn,
                                  const PassContext &ctx) const override {
    std::vector<std::string> lines;
    int constants = 0;

    fn.for_each_op([&](const SsaOp &op) {
      if (op.out == nullptr) return;
      const Const &value = result_[*op.out];
      if (value.state != Const::Known) return;

      ++constants;

      // The block is on the line because a value is only constant where the
      // lattice says so, and which block this def sits in is how the two are
      // checked against each other.
      std::ostringstream line;
      line << ctx.name_of(*op.out) << " = 0x" << std::hex << value.value
           << std::dec << "  (block " << op.block << ")";
      lines.push_back(line.str());
    });

    lines.push_back(std::to_string(constants) + " constant value(s) of " +
                    std::to_string(fn.value_count()));
    lines.push_back("folded " + std::to_string(replaced_) + " operand(s) in " +
                    std::to_string(folded_) + " op(s)");
    return lines;
  }

private:
  // Puts the lattice back into the IR, in two steps that have to be in this
  // order.
  //
  // First every operand that reads a value known to be a constant reads the
  // constant itself. The constant carries the width of the value it replaces,
  // so a read that was eight bytes wide still is -- the width is part of the
  // operand, and a substitution that dropped it would change what an operation
  // is.
  //
  // Then an operation left with constants on every side is replaced by its own
  // result. That is what turns `t186 = 0xb81fa808 - 0x37f747e1` into
  // `t186 = 0x80326027`: after the first step the subtraction is one of two
  // constants, and the analysis already knows what it comes to. Folding at the
  // use sites alone would not do it -- this value is live at exit, so it has a
  // definition of its own that the listing prints.
  //
  // The definition is left in place either way. It is dead once nothing reads
  // it, and `dce` is the pass that decides that.
  int propagate(SsaFunction &fn) {
    int replaced = 0;

    fn.for_each_op([&](SsaOp &op) {
      for (SsaOperand &in : op.ins) {
        // Untracked operands are constants and memory the analysis never
        // renamed; it has no fact about them, and a constant that is already
        // one needs no replacing.
        if (!in.is_tracked()) continue;

        const Const &value = result_[*in.value];
        if (value.state != Const::Known) continue;

        in.raw = Varnode{kConstantSpace, value.value, in.value->storage.size};
        in.value = nullptr;
        ++replaced;
      }
    });

    // The chains still name the uses the walk above has just taken away.
    if (replaced != 0) fn.rebuild_uses();

    folded_ = fold(fn);
    return replaced;
  }

  // Rewrites an operation whose operands are all constants into a copy of the
  // constant the analysis says it comes to.
  //
  // A phi is left alone: its operands are one per predecessor, and they are
  // the one thing here that position carries meaning in. A phi all of whose
  // predecessors agree is trivial, which `simplify` decides and does.
  int fold(SsaFunction &fn) {
    int folded = 0;

    fn.for_each_op([&](SsaOp &op) {
      if (op.is_phi || op.out == nullptr || op.ins.empty()) return;

      const Const &result = result_[*op.out];
      if (result.state != Const::Known) return;

      for (const SsaOperand &in : op.ins)
        if (in.is_tracked() || !is_constant(in.raw)) return;

      op.opc = Op::COPY;
      op.ins.resize(1);
      op.ins[0] =
          SsaOperand{Varnode{kConstantSpace, result.value, op.out->storage.size},
                     nullptr};
      ++folded;
    });

    return folded;
  }

  SparseResult<Const> result_;
  int replaced_ = 0;
  int folded_ = 0;
};

DDD_REGISTER_PASS(ConstProp);

} // namespace
} // namespace ddd
