#include "dominance.h"

#include <algorithm>

namespace ddd {
namespace {

// Iterative, because a linear sweep over a large function can easily produce
// a CFG deeper than the stack can take recursively.
std::vector<int> postorder_from(const Cfg &cfg, int entry) {
  std::vector<int> order;
  if (entry < 0) return order;

  std::vector<bool> visited(cfg.size(), false);
  struct Frame { int block; size_t next_succ; };
  std::vector<Frame> stack{{entry, 0}};
  visited[entry] = true;

  while (!stack.empty()) {
    Frame &top = stack.back();
    const std::vector<Edge> &succs = cfg[top.block].succs;

    if (top.next_succ < succs.size()) {
      int next = succs[top.next_succ++].target;
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

int intersect(const std::vector<int> &idom, const std::vector<int> &rpo_index,
              int a, int b) {
  while (a != b) {
    while (rpo_index[a] > rpo_index[b]) a = idom[a];
    while (rpo_index[b] > rpo_index[a]) b = idom[b];
  }
  return a;
}

} // namespace

Dominance compute_dominance(const Cfg &cfg) {
  Dominance dom;
  int n = cfg.size();
  dom.idom.assign(n, -1);
  dom.children.assign(n, {});
  dom.frontier.assign(n, {});
  dom.rpo_index.assign(n, -1);
  if (n == 0 || cfg.entry < 0) return dom;

  std::vector<int> postorder = postorder_from(cfg, cfg.entry);
  dom.rpo.assign(postorder.rbegin(), postorder.rend());
  for (size_t i = 0; i < dom.rpo.size(); ++i) dom.rpo_index[dom.rpo[i]] = static_cast<int>(i);

  // Unreachable blocks keep idom == -1 and never participate.
  dom.idom[cfg.entry] = cfg.entry;
  for (bool changed = true; changed;) {
    changed = false;
    for (int b : dom.rpo) {
      if (b == cfg.entry) continue;

      int candidate = -1;
      for (int p : cfg[b].preds) {
        if (dom.idom[p] == -1) continue; // not processed yet, or unreachable
        candidate = (candidate == -1) ? p : intersect(dom.idom, dom.rpo_index, candidate, p);
      }
      if (candidate != -1 && dom.idom[b] != candidate) {
        dom.idom[b] = candidate;
        changed = true;
      }
    }
  }
  dom.idom[cfg.entry] = -1; // the entry has no immediate dominator

  for (int b : dom.rpo)
    if (b != cfg.entry) dom.children[dom.idom[b]].push_back(b);

  // DF(b) is only ever non-empty at join points: from each predecessor of a
  // join, walk up the dominator tree until we reach the join's own idom.
  for (int b : dom.rpo) {
    if (cfg[b].preds.size() < 2) continue;
    for (int p : cfg[b].preds) {
      if (!dom.reachable(p)) continue;
      for (int runner = p; runner != -1 && runner != dom.idom[b];
           runner = dom.idom[runner])
        dom.frontier[runner].push_back(b);
    }
  }
  for (std::vector<int> &df : dom.frontier) {
    std::sort(df.begin(), df.end());
    df.erase(std::unique(df.begin(), df.end()), df.end());
  }

  return dom;
}

} // namespace ddd
