#include "pattern.h"

namespace ddd {
namespace {

// Sleigh lowers almost everything through temporaries, so a flag test is
// typically three or four COPYs away from the comparison that produced it.
// Patterns describe the computation, not the copies.
const SsaOp *skip_copies(const SsaValue *value) {
  const SsaOp *def = value != nullptr ? value->def : nullptr;

  for (int guard = 0; def != nullptr && guard < 64; ++guard) {
    if (def->opc != ghidra::CPUI_COPY || def->ins.size() != 1)
      return def;
    if (!def->ins[0].is_tracked())
      return def;
    def = def->ins[0].value->def;
  }

  return def;
}

} // namespace

void Match::clear() { *this = Match{}; }

Pattern make_pattern(Pattern::Kind kind, OpCode opc, uint64_t constant,
                     int slot, std::vector<Pattern> ins, bool commutative) {
  Pattern pattern;
  pattern.kind_ = kind;
  pattern.opc_ = opc;
  pattern.constant_ = constant;
  pattern.slot_ = slot;
  pattern.ins_ = std::move(ins);
  pattern.commutative_ = commutative;
  return pattern;
}

bool Pattern::match(const SsaOperand &operand, Match &m) const {
  switch (kind_) {
  case Kind::Any:
    return true;

  case Kind::Value:
    if (!operand.is_tracked())
      return false;
    if (m.values[slot_] == nullptr) {
      m.values[slot_] = operand.value;
      return true;
    }
    return m.values[slot_] == operand.value;

  case Kind::Constant:
    return operand.is_constant() && operand.constant() == constant_;

  case Kind::ConstantSlot:
    if (!operand.is_constant())
      return false;
    if (!m.bound_constant[slot_]) {
      m.constants[slot_] = operand.constant();
      m.bound_constant[slot_] = true;
      return true;
    }
    return m.constants[slot_] == operand.constant();

  case Kind::Op: {
    if (!operand.is_tracked())
      return false;
    const SsaOp *def = skip_copies(operand.value);
    return def != nullptr && match(*def, m);
  }
  }

  return false;
}

bool Pattern::match_operands(const SsaOp &op, Match &m) const {
  for (size_t i = 0; i < ins_.size(); ++i)
    if (!ins_[i].match(op.ins[i], m))
      return false;
  return true;
}

bool Pattern::match(const SsaOp &op, Match &m) const {
  if (kind_ != Kind::Op)
    return false;
  if (op.opc != opc_ || op.ins.size() != ins_.size())
    return false;

  Match attempt = m;
  if (match_operands(op, attempt)) {
    m = attempt;
    return true;
  }

  if (!commutative_ || ins_.size() != 2)
    return false;

  attempt = m;
  if (ins_[0].match(op.ins[1], attempt) && ins_[1].match(op.ins[0], attempt)) {
    m = attempt;
    return true;
  }

  return false;
}

namespace pat {

Pattern any() {
  return make_pattern(Pattern::Kind::Any, ghidra::CPUI_COPY, 0, -1, {}, false);
}

Pattern val(int slot) {
  return make_pattern(Pattern::Kind::Value, ghidra::CPUI_COPY, 0, slot, {},
                      false);
}

Pattern imm(uint64_t value) {
  return make_pattern(Pattern::Kind::Constant, ghidra::CPUI_COPY, value, -1, {},
                      false);
}

Pattern cst(int slot) {
  return make_pattern(Pattern::Kind::ConstantSlot, ghidra::CPUI_COPY, 0, slot,
                      {}, false);
}

Pattern op(OpCode opc, std::vector<Pattern> ins) {
  return make_pattern(Pattern::Kind::Op, opc, 0, -1, std::move(ins), false);
}

Pattern comm(OpCode opc, Pattern left, Pattern right) {
  return make_pattern(Pattern::Kind::Op, opc, 0, -1,
                      {std::move(left), std::move(right)}, true);
}

} // namespace pat
} // namespace ddd
