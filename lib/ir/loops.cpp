#include "ir/loops.h"

#include <algorithm>
#include <set>

namespace ddd {
namespace {

// The header and everything that can reach `latch` without passing it.
//
// Backwards from the latch, stopping at the header rather than stepping
// through it: a block that only gets to the latch by going round the loop
// again is not part of this loop, it is the rest of the function. The header
// is included and not expanded, which is what makes the body enclose it.
std::set<BlockId> body_of(const Cfg &cfg, const Dominance &dom, BlockId header,
                          BlockId latch) {
  std::set<BlockId> found{header};
  std::vector<BlockId> work{latch};

  if (found.insert(latch).second)
    for (int guard = 0; !work.empty();) {
      if (++guard > 4 * cfg.size() + 16)
        break; // a malformed Cfg should not hang the listing

      BlockId block = work.back();
      work.pop_back();

      for (BlockId pred : cfg[block].preds) {
        if (!dom.reachable(pred))
          continue;
        if (pred == header)
          continue; // it is in already, and nothing past it is
        if (found.insert(pred).second)
          work.push_back(pred);
      }
    }

  return found;
}

} // namespace

Loops::Loops(const Cfg &cfg, const Dominance &dom) {
  // Every back edge, grouped by the header it closes on. Grouping first is
  // what makes two latches into one loop rather than two loops that happen to
  // share a header -- and a header's body is the union of what its back edges
  // enclose, which is why the union is taken below rather than the first.
  std::map<BlockId, std::set<BlockId>> bodies;
  std::map<BlockId, std::vector<BlockId>> latches;

  for (int i = 0; i < cfg.size(); ++i) {
    const BlockId tail{i};
    if (!dom.reachable(tail))
      continue;

    for (const Edge &edge : cfg[tail].succs) {
      const BlockId header = edge.target;
      if (!dominates(dom, header, tail))
        continue;

      latches[header].push_back(tail);
      std::set<BlockId> body = body_of(cfg, dom, header, tail);
      bodies[header].insert(body.begin(), body.end());
    }
  }

  loops_.reserve(bodies.size());
  for (auto &entry : bodies) {
    Loop loop;
    loop.header = entry.first;
    loop.blocks.assign(entry.second.begin(), entry.second.end());
    loop.latches = latches[loop.header];
    std::sort(loop.latches.begin(), loop.latches.end());

    loop.contains_.assign(cfg.size(), false);
    for (BlockId block : loop.blocks)
      loop.contains_[block] = true;

    // What the loop leaves to. Everything outside the body that a block inside
    // it branches to, whether or not that is where control ends up: a loop
    // with two ways out has two exits, and calling one of them "the" exit is
    // how a `break` ends up printed on the edge that was not taken.
    std::set<BlockId> exits;
    for (BlockId block : loop.blocks)
      for (const Edge &edge : cfg[block].succs)
        if (!loop.contains(edge.target))
          exits.insert(edge.target);
    loop.exits.assign(exits.begin(), exits.end());

    by_header_[loop.header] = static_cast<int>(loops_.size());
    loops_.push_back(std::move(loop));
  }
}

const Loop *Loops::at_header(BlockId block) const {
  auto it = by_header_.find(block);
  return it == by_header_.end() ? nullptr : &loops_[it->second];
}

} // namespace ddd
