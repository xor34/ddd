#include "ir/dominance.h"

#include <algorithm>

namespace ddd {
namespace {

// Iterative, because a linear sweep over a large function can easily produce
// a CFG deeper than the stack can take recursively.
std::vector<BlockId> postorder_from(const Cfg &cfg, BlockId entry) {
  std::vector<BlockId> order;
  if (!entry.valid())
    return order;

  std::vector<bool> visited(cfg.size(), false);

  struct Frame {
    BlockId block;
    size_t next_succ;
  };

  std::vector<Frame> stack{{entry, 0}};
  visited[entry] = true;

  while (!stack.empty()) {
    Frame &top = stack.back();
    const std::vector<Edge> &succs = cfg[top.block].succs;

    if (top.next_succ < succs.size()) {
      BlockId next = succs[top.next_succ++].target;
      if (!visited[next]) {
        visited[next] = true;
        stack.push_back({next, 0});
      }
      continue;
    }

    order.push_back(top.block);
    stack.pop_back();
  }

  return order;
}

BlockId intersect(const std::vector<std::optional<BlockId>> &idom,
                  const std::vector<int> &rpo_index, BlockId a, BlockId b) {
  while (a != b) {
    while (rpo_index[a] > rpo_index[b])
      a = *idom[a];
    while (rpo_index[b] > rpo_index[a])
      b = *idom[b];
  }
  return a;
}

} // namespace

Dominance compute_dominance(const Cfg &cfg) {
  Dominance dom;
  int n = cfg.size();
  dom.idom.assign(n, std::nullopt);
  dom.children.assign(n, {});
  dom.frontier.assign(n, {});
  dom.rpo_index.assign(n, -1);
  if (n == 0 || !cfg.entry)
    return dom;

  std::vector<BlockId> postorder = postorder_from(cfg, *cfg.entry);
  dom.rpo.assign(postorder.rbegin(), postorder.rend());
  for (size_t i = 0; i < dom.rpo.size(); ++i)
    dom.rpo_index[dom.rpo[i]] = static_cast<int>(i);

  // Unreachable blocks keep idom == nullopt and never participate. The
  // entry's slot is seeded with itself so the intersection walk cannot run
  // off the top of the tree; it is cleared again afterwards.
  dom.idom[*cfg.entry] = *cfg.entry;
  for (bool changed = true; changed;) {
    changed = false;
    for (BlockId b : dom.rpo) {
      if (b == *cfg.entry)
        continue;

      std::optional<BlockId> candidate;
      for (BlockId p : cfg[b].preds) {
        if (!dom.idom[p])
          continue; // not processed yet, or unreachable
        candidate = candidate
                        ? intersect(dom.idom, dom.rpo_index, *candidate, p)
                        : p;
      }
      if (candidate && dom.idom[b] != candidate) {
        dom.idom[b] = candidate;
        changed = true;
      }
    }
  }
  dom.idom[*cfg.entry] = std::nullopt; // the entry has no immediate dominator

  for (BlockId b : dom.rpo)
    if (b != *cfg.entry)
      dom.children[*dom.idom[b]].push_back(b);

  // DF(b) is only ever non-empty at join points: from each predecessor of a
  // join, walk up the dominator tree until we reach the join's own idom.
  for (BlockId b : dom.rpo) {
    if (cfg[b].preds.size() < 2)
      continue;
    for (BlockId p : cfg[b].preds) {
      if (!dom.reachable(p))
        continue;
      for (BlockId runner = p; dom.idom[runner] && runner != dom.idom[b];
           runner = *dom.idom[runner])
        dom.frontier[runner].push_back(b);
    }
  }
  for (std::vector<BlockId> &df : dom.frontier) {
    std::sort(df.begin(), df.end());
    df.erase(std::unique(df.begin(), df.end()), df.end());
  }

  return dom;
}

} // namespace ddd
