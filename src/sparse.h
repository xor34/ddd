// sparse.h -- sparse dataflow over the SSA def-use graph.
//
// One fact per SSA value instead of one per block. Def-use chains *are* the
// propagation graph, so a change re-examines only the ops that actually read
// the changed value. This is the natural shape for constant propagation,
// value ranges, taint, and similar SSA-native analyses.
//
// The callbacks split the work the way SSA already does:
//   * phis are handled by `merge` -- that is exactly what a phi is
//   * every other op is handled by `transform`
//   * `raw` supplies the fact for an operand that was never renamed, which
//     in practice is where constants enter the analysis
//   * `live_in` supplies the fact for values defined before the function
#pragma once

#include "ssa.h"

#include <deque>
#include <functional>
#include <utility>
#include <vector>

namespace ddd {

template <typename Value> struct SparseAnalysis;

// Operand -> fact lookup handed to transform().
template <typename Value> class ValueMap {
public:
  ValueMap(const std::vector<Value> &values,
           const SparseAnalysis<Value> &analysis)
      : values_(values), analysis_(analysis) {}

  Value operator()(const SsaValue *value) const {
    return value == nullptr ? analysis_.init() : values_[value->id];
  }

  Value operator()(const SsaOperand &operand) const {
    if (operand.value != nullptr)
      return values_[operand.value->id];
    return analysis_.raw ? analysis_.raw(operand.raw) : analysis_.init();
  }

private:
  const std::vector<Value> &values_;
  const SparseAnalysis<Value> &analysis_;
};

template <typename Value> struct SparseAnalysis {
  // The "nothing known yet" fact, and the identity for merge.
  std::function<Value()> init;
  // Fact for an operand that was not SSA-renamed (constants, memory).
  // Defaults to init().
  std::function<Value(const VarnodeData &)> raw;
  // Fact for a value defined before the function (parameter / uninitialised
  // read). Defaults to init(); most analyses want bottom here.
  std::function<Value(const SsaValue &)> live_in;
  // Confluence -- used for phi nodes.
  std::function<Value(const Value &, const Value &)> merge;
  // Everything that isn't a phi.
  std::function<Value(const SsaOp &, const ValueMap<Value> &)> transform;
  // Fixed point test. Defaults to ==.
  std::function<bool(const Value &, const Value &)> equal =
      [](const Value &a, const Value &b) { return a == b; };
};

template <typename Value> struct SparseResult {
  std::vector<Value> values; // indexed by SsaValue::id

  const Value &operator[](const SsaValue &value) const {
    return values[value.id];
  }
  const Value &operator[](const SsaValue *value) const {
    return values[value->id];
  }
};

template <typename Value>
SparseResult<Value> solve(const SsaFunction &fn,
                          const SparseAnalysis<Value> &analysis) {
  SparseResult<Value> result;
  result.values.assign(fn.value_count(), analysis.init());
  ValueMap<Value> values(result.values, analysis);

  for (int i = 0; i < fn.value_count(); ++i) {
    const SsaValue &value = fn.value(i);
    if (value.is_live_in() && analysis.live_in)
      result.values[i] = analysis.live_in(value);
  }

  std::deque<const SsaOp *> worklist;
  std::vector<bool> queued(fn.op_count(), false);
  fn.for_each_op([&](const SsaOp &op) {
    if (op.out == nullptr)
      return;
    worklist.push_back(&op);
    queued[op.id] = true;
  });

  while (!worklist.empty()) {
    const SsaOp *op = worklist.front();
    worklist.pop_front();
    queued[op->id] = false;
    if (op->out == nullptr)
      continue;

    Value next = analysis.init();
    if (op->is_phi) {
      bool first = true;
      for (const SsaOperand &in : op->ins) {
        Value operand = values(in);
        next = first ? std::move(operand) : analysis.merge(next, operand);
        first = false;
      }
    } else {
      next = analysis.transform(*op, values);
    }

    Value &slot = result.values[op->out->id];
    if (analysis.equal(slot, next))
      continue;
    slot = std::move(next);

    for (const SsaOp *user : op->out->uses) {
      if (queued[user->id])
        continue;
      queued[user->id] = true;
      worklist.push_back(user);
    }
  }

  return result;
}

} // namespace ddd
