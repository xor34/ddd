// dataflow.h -- block-level monotone dataflow engine.
//
// An analysis is a fact type plus a few callbacks. There is no base class to
// inherit and no CRTP: fill in the fields of BlockAnalysis<Fact> and call
// solve().
//
//   forward:   in[b]  = merge over preds of out[p];  out[b] = transform(b, in[b])
//   backward:  out[b] = merge over succs of in[s];   in[b]  = transform(b, out[b])
//
// Use this for the classic whole-block analyses (liveness, available
// expressions, reaching definitions). For anything that wants one fact per
// SSA value, use the sparse engine in sparse.h instead -- same callback
// shape, propagation along def-use edges.
#pragma once

#include "ssa.h"

#include <algorithm>
#include <deque>
#include <functional>
#include <utility>
#include <vector>

namespace ddd {

enum class Direction { Forward, Backward };

template <typename Fact>
struct BlockAnalysis {
  Direction direction = Direction::Forward;

  // The "nothing known yet" fact, and the identity for merge.
  std::function<Fact()> init;
  // Confluence at a join point.
  std::function<Fact(const Fact &, const Fact &)> merge;
  // Transfer over one block: fold the incoming fact through block.phis and
  // block.ops and return the outgoing one.
  std::function<Fact(const SsaBlock &, const Fact &)> transform;
  // Fixed point test. Defaults to ==; override if Fact has no operator==.
  std::function<bool(const Fact &, const Fact &)> equal =
      [](const Fact &a, const Fact &b) { return a == b; };
};

template <typename Fact>
struct BlockResult {
  std::vector<Fact> in;
  std::vector<Fact> out;
};

template <typename Fact>
BlockResult<Fact> solve(const SsaFunction &fn, const BlockAnalysis<Fact> &analysis) {
  const Cfg &cfg = fn.cfg();
  const Dominance &dom = fn.dominance();
  const bool forward = analysis.direction == Direction::Forward;
  const int n = cfg.size();

  BlockResult<Fact> result;
  result.in.assign(n, analysis.init());
  result.out.assign(n, analysis.init());
  if (n == 0) return result;

  // Reverse postorder converges fastest forwards, its reverse backwards.
  // Unreachable blocks are not in the rpo, so append them.
  std::vector<int> order = dom.rpo;
  for (int b = 0; b < n; ++b)
    if (!dom.reachable(b)) order.push_back(b);
  if (!forward) std::reverse(order.begin(), order.end());

  std::deque<int> worklist(order.begin(), order.end());
  std::vector<bool> queued(n, true);

  while (!worklist.empty()) {
    int b = worklist.front();
    worklist.pop_front();
    queued[b] = false;

    Fact incoming = analysis.init();
    bool first = true;
    if (forward) {
      for (int p : cfg[b].preds) {
        incoming = first ? result.out[p] : analysis.merge(incoming, result.out[p]);
        first = false;
      }
    } else {
      for (const Edge &e : cfg[b].succs) {
        incoming = first ? result.in[e.target] : analysis.merge(incoming, result.in[e.target]);
        first = false;
      }
    }

    (forward ? result.in[b] : result.out[b]) = incoming;

    Fact outgoing = analysis.transform(fn[b], incoming);
    Fact &slot = forward ? result.out[b] : result.in[b];
    if (analysis.equal(slot, outgoing)) continue;
    slot = std::move(outgoing);

    auto enqueue = [&](int next) {
      if (queued[next]) return;
      queued[next] = true;
      worklist.push_back(next);
    };
    if (forward) {
      for (const Edge &e : cfg[b].succs) enqueue(e.target);
    } else {
      for (int p : cfg[b].preds) enqueue(p);
    }
  }

  return result;
}

} // namespace ddd
