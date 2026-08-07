#include "pattern.h"

namespace ddd {
namespace {

// Sleigh lowers almost everything through temporaries, so a flag test is
// typically three or four COPYs away from the comparison that produced it.
// Patterns describe the computation, not the copies.
const SsaOp *skip_copies(const SsaValue *value) {
  const SsaOp *def = value != nullptr ? value->def : nullptr;

  for (int guard = 0; def != nullptr && guard < 64; ++guard) {
    if (def->opc != ghidra::CPUI_COPY || def->ins.size() != 1) return def;
    if (!def->ins[0].is_tracked()) return def;
    def = def->ins[0].value->def;
  }

  return def;
}

} // namespace

bool Pattern::match(const SsaOperand &operand, Match &m) const {
  switch (kind) {
  case Kind::Value:
    if (!operand.is_tracked()) return false;
    if (m.values[slot] == nullptr) m.values[slot] = operand.value;
    return m.values[slot] == operand.value;

  case Kind::Constant:
    return operand.is_constant() && operand.constant() == constant;

  case Kind::AnyConst:
    if (!operand.is_constant()) return false;
    if (!m.bound[slot]) {
      m.bound[slot] = true;
      m.constants[slot] = operand.constant();
    }
    return m.constants[slot] == operand.constant();

  case Kind::Op: {
    if (!operand.is_tracked()) return false;
    const SsaOp *def = skip_copies(operand.value);
    return def != nullptr && match(*def, m);
  }
  }

  return false;
}

bool Pattern::match(const SsaOp &op, Match &m) const {
  if (kind != Kind::Op || op.opc != opc || op.ins.size() != ins.size()) return false;

  // Match into a copy so a half-finished attempt cannot leave slots bound --
  // which is also what makes trying the commuted order safe.
  auto attempt = [&](bool swapped) {
    Match trial = m;
    for (size_t i = 0; i < ins.size(); ++i) {
      const size_t j = swapped ? ins.size() - 1 - i : i;
      if (!ins[i].match(op.ins[j], trial)) return false;
    }
    m = trial;
    return true;
  };

  if (attempt(false)) return true;
  return commutative && ins.size() == 2 && attempt(true);
}

} // namespace ddd
