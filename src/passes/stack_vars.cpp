// stack-vars -- find stack slots and give them names.
//
// Two steps, both on the sparse engine:
//   1. propagate "this value is entry_sp + k" along def-use edges
//   2. every LOAD/STORE whose address is entry_sp + k is a stack slot
//
// Slots below the entry stack pointer are locals (var_10), slots at or above
// it were put there by the caller (arg_8). That is the usual convention for a
// downward-growing stack, which is every architecture this ships a calling
// convention for.
#include "../pass.h"
#include "../sparse.h"

#include "opcodes.hh"

#include <map>
#include <ostream>
#include <sstream>

namespace ddd {
namespace {

// Const-propagation with one extra point in the lattice: a value can be a
// known offset from the stack pointer on entry.
struct StackValue {
  enum State { Top, Number, Frame, Bottom } state = Top;
  int64_t value = 0; // the number, or the offset from entry_sp

  static StackValue number(int64_t v) { return {Number, v}; }
  static StackValue frame(int64_t offset) { return {Frame, offset}; }
  static StackValue bottom() { return {Bottom, 0}; }

  bool operator==(const StackValue &o) const {
    return state == o.state && (state == Top || state == Bottom || value == o.value);
  }
};

StackValue meet(const StackValue &a, const StackValue &b) {
  if (a.state == StackValue::Top) return b;
  if (b.state == StackValue::Top) return a;
  if (a.state != b.state || a.value != b.value) return StackValue::bottom();
  return a;
}

StackValue evaluate(const SsaOp &op, const StackValue &a, const StackValue &b) {
  const bool a_frame = a.state == StackValue::Frame;
  const bool b_frame = b.state == StackValue::Frame;
  const bool a_num = a.state == StackValue::Number;
  const bool b_num = b.state == StackValue::Number;

  switch (op.opc) {
  case ghidra::CPUI_COPY:
  case ghidra::CPUI_INT_ZEXT:
  case ghidra::CPUI_INT_SEXT:
    return a;

  case ghidra::CPUI_INT_ADD:
    if (a_frame && b_num) return StackValue::frame(a.value + b.value);
    if (a_num && b_frame) return StackValue::frame(a.value + b.value);
    if (a_num && b_num) return StackValue::number(a.value + b.value);
    return StackValue::bottom();

  case ghidra::CPUI_INT_SUB:
    if (a_frame && b_num) return StackValue::frame(a.value - b.value);
    if (a_num && b_num) return StackValue::number(a.value - b.value);
    return StackValue::bottom();

  default:
    return StackValue::bottom();
  }
}

SparseAnalysis<StackValue> build_analysis(const Storage &stack_pointer) {
  SparseAnalysis<StackValue> analysis;

  analysis.init = [] { return StackValue{}; };

  analysis.raw = [](const VarnodeData &vn) {
    if (!is_constant(vn)) return StackValue::bottom();
    // Stack offsets arrive as unsigned constants that are really negative in
    // the pointer's width, so sign-extend before doing arithmetic with them.
    int64_t value = static_cast<int64_t>(vn.offset);
    if (vn.size > 0 && vn.size < 8) {
      uint64_t sign = uint64_t(1) << (vn.size * 8 - 1);
      uint64_t mask = (uint64_t(1) << (vn.size * 8)) - 1;
      uint64_t bits = vn.offset & mask;
      value = static_cast<int64_t>((bits & sign) ? (bits | ~mask) : bits);
    }
    return StackValue::number(value);
  };

  // The stack pointer on entry is the origin of the frame; every other
  // pre-existing value is unknown.
  analysis.live_in = [stack_pointer](const SsaValue &value) {
    return value.storage == stack_pointer ? StackValue::frame(0) : StackValue::bottom();
  };

  analysis.merge = meet;

  analysis.transform = [](const SsaOp &op, const ValueMap<StackValue> &values) {
    StackValue a = op.ins.size() > 0 ? values(op.ins[0]) : StackValue::bottom();
    StackValue b = op.ins.size() > 1 ? values(op.ins[1]) : StackValue::bottom();
    if (a.state == StackValue::Top || (op.ins.size() > 1 && b.state == StackValue::Top))
      return StackValue{};
    return evaluate(op, a, b);
  };

  return analysis;
}

std::string slot_name(int64_t offset) {
  std::ostringstream os;
  if (offset < 0) {
    os << "var_" << std::hex << -offset;
  } else {
    os << "arg_" << std::hex << offset;
  }
  return os.str();
}

std::string frame_expression(int64_t offset) {
  if (offset == 0) return "sp";

  std::ostringstream os;
  os << "sp" << (offset < 0 ? "-" : "+") << "0x" << std::hex
     << (offset < 0 ? -offset : offset);
  return os.str();
}

class StackVars final : public Pass {
public:
  std::string name() const override { return "stack-vars"; }
  std::string description() const override {
    return "name stack slots from stack-pointer-relative accesses";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    if (ctx.stack_pointer().space == nullptr) {
      if (ctx.verbose) ctx.stream() << "  no stack pointer known, skipping\n";
      return;
    }

    SparseResult<StackValue> result = solve(fn, build_analysis(ctx.stack_pointer()));

    // offset -> widest access seen there
    std::map<int64_t, unsigned> slots;

    fn.for_each_op([&](SsaOp &op) {
      // LOAD: out = *ins[1]. STORE: *ins[1] = ins[2]. ins[0] is the space id.
      const bool load = op.opc == ghidra::CPUI_LOAD;
      const bool store = op.opc == ghidra::CPUI_STORE;
      if (!load && !store) {
        label_frame_pointer(ctx, op, result);
        return;
      }
      if (op.ins.size() < 2 || !op.ins[1].is_tracked()) return;

      const StackValue &address = result[*op.ins[1].value];
      if (address.state != StackValue::Frame) return;

      unsigned width = load ? (op.out != nullptr ? op.out->storage.size : 0)
                            : (op.ins.size() > 2 ? op.ins[2].raw.size : 0);
      unsigned &recorded = slots[address.value];
      recorded = std::max(recorded, width);

      const std::string name = slot_name(address.value);
      ctx.annotations->set_label(*op.ins[1].value, "&" + name);
      ctx.annotations->comment(op, (load ? "load " : "store ") + name + " [" +
                          frame_expression(address.value) + "]");
    });

    report(fn, ctx, slots);
  }

private:
  // A value that is a pure frame offset but never dereferenced is still worth
  // naming -- that is what a frame pointer looks like.
  static void label_frame_pointer(PassContext &ctx, SsaOp &op,
                                  const SparseResult<StackValue> &result) {
    if (op.out == nullptr || ctx.annotations->has_label(*op.out)) return;

    const StackValue &value = result[*op.out];
    if (value.state != StackValue::Frame) return;
    ctx.annotations->set_label(*op.out, frame_expression(value.value));
  }

  static void report(const SsaFunction &fn, PassContext &ctx,
                     const std::map<int64_t, unsigned> &slots) {
    if (slots.empty()) {
      if (ctx.verbose) ctx.stream() << "  no stack slots found\n";
      return;
    }

    std::ostringstream layout;
    layout << "frame:";
    for (const auto &slot : slots) {
      layout << " " << slot_name(slot.first) << "[" << slot.second << "]";
    }
    ctx.annotations->comment_block(fn.cfg().entry, layout.str());

    if (ctx.verbose)
      ctx.stream() << "  " << slots.size() << " stack slot(s)\n";
  }
};

DDD_REGISTER_PASS(StackVars);

} // namespace
} // namespace ddd
