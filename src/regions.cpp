#include "regions.h"

#include <algorithm>

namespace ddd {

void RegionTree::reset(uint64_t base, uint64_t size, std::string name) {
  nodes_.clear();
  dead_.clear();

  RegionNode root;
  root.id = 0;
  root.parent = -1;
  root.offset = base;
  root.size = size;
  root.kind = region_kind::kImage;
  root.name = std::move(name);

  nodes_.push_back(std::move(root));
  dead_.push_back(false);
  root_ = 0;
}

uint64_t RegionTree::address(int id) const {
  uint64_t total = 0;
  for (int at = id; at >= 0; at = nodes_[at].parent)
    total += nodes_[at].offset;
  return total;
}

// The deepest region that could hold this extent, searching down from `from`.
int RegionTree::fit(uint64_t address, uint64_t size, int from) const {
  if (!valid(from))
    return -1;
  if (address < this->address(from) || address + size > end(from))
    return -1;

  for (int child : nodes_[from].children) {
    if (!valid(child))
      continue;
    const int deeper = fit(address, size, child);
    if (deeper >= 0)
      return deeper;
  }
  return from;
}

int RegionTree::add(uint64_t address, uint64_t size, const std::string &kind,
                    const std::string &name, int parent) {
  if (root_ < 0 || size == 0)
    return -1;

  // Where it goes: under what was named, or under the deepest thing that can
  // hold it. A block lands inside its function without anyone saying so.
  int under = parent >= 0 ? parent : fit(address, size, root_);
  if (under < 0)
    return -1;

  // The same extent and kind again is the same region. Discovery runs more
  // than once and a project file replays what it already said.
  for (int child : nodes_[under].children) {
    if (!valid(child))
      continue;
    if (this->address(child) == address && nodes_[child].size == size &&
        nodes_[child].kind == kind) {
      if (!name.empty())
        nodes_[child].name = name;
      return child;
    }
  }

  RegionNode added;
  added.id = static_cast<int>(nodes_.size());
  added.parent = under;
  added.offset = address - this->address(under);
  added.size = size;
  added.kind = kind;
  added.name = name;

  // Anything already inside the new region belongs to it now: defining a
  // function around blocks that were floating in a segment adopts them.
  std::vector<int> adopted;
  for (int child : nodes_[under].children) {
    if (!valid(child))
      continue;
    if (this->address(child) >= address && end(child) <= address + size)
      adopted.push_back(child);
  }

  nodes_.push_back(std::move(added));
  dead_.push_back(false);
  const int id = static_cast<int>(nodes_.size()) - 1;

  auto &siblings = nodes_[under].children;
  for (int child : adopted) {
    siblings.erase(std::remove(siblings.begin(), siblings.end(), child),
                   siblings.end());
    nodes_[child].parent = id;
    nodes_[child].offset = this->address(child) - address;
    nodes_[id].children.push_back(child);
  }

  nodes_[under].children.push_back(id);
  return id;
}

void RegionTree::set_isa(int id, int isa) {
  if (valid(id))
    nodes_[id].isa = isa;
}

int RegionTree::isa_of(int id) const {
  for (int at = id; at >= 0; at = nodes_[at].parent)
    if (nodes_[at].isa >= 0)
      return nodes_[at].isa;
  return -1;
}

void RegionTree::set_name(int id, std::string name) {
  if (valid(id))
    nodes_[id].name = std::move(name);
}

void RegionTree::set_user_defined(int id, bool user_defined) {
  if (valid(id))
    nodes_[id].user_defined = user_defined;
}

void RegionTree::resize(int id, uint64_t size) {
  if (!valid(id) || size == 0)
    return;

  nodes_[id].size = size;
  const uint64_t end = address(id) + size;

  std::vector<int> orphaned;
  for (int child : nodes_[id].children)
    if (valid(child) && this->end(child) > end)
      orphaned.push_back(child);

  for (int child : orphaned) {
    detach(child);
    // The detached child's own descendants would otherwise keep pointing at
    // a dead parent and never get marked dead themselves, so recurse through
    // the subtree the same way clear_children() does.
    clear_children(child);
    dead_[child] = true;
  }
}

void RegionTree::detach(int id) {
  const int parent = nodes_[id].parent;
  if (parent < 0)
    return;

  auto &siblings = nodes_[parent].children;
  siblings.erase(std::remove(siblings.begin(), siblings.end(), id),
                 siblings.end());
}

bool RegionTree::remove(int id) {
  if (!valid(id) || id == root_)
    return false;

  const int parent = nodes_[id].parent;
  const uint64_t here = address(id);
  const uint64_t there = address(parent);

  // The children are still there; they were never a property of this region.
  // Undefining a function does not undefine its blocks, it stops calling that
  // stretch of bytes a function.
  for (int child : nodes_[id].children) {
    if (!valid(child))
      continue;
    nodes_[child].parent = parent;
    nodes_[child].offset = here + nodes_[child].offset - there;
    nodes_[parent].children.push_back(child);
  }

  detach(id);
  dead_[id] = true;
  return true;
}

void RegionTree::clear_children(int id) {
  if (!valid(id))
    return;

  std::vector<int> pending = nodes_[id].children;
  nodes_[id].children.clear();

  while (!pending.empty()) {
    const int child = pending.back();
    pending.pop_back();
    if (!valid(child))
      continue;

    for (int grandchild : nodes_[child].children)
      pending.push_back(grandchild);
    nodes_[child].children.clear();
    dead_[child] = true;
  }
}

int RegionTree::innermost(uint64_t address) const {
  if (root_ < 0 || !contains(root_, address))
    return -1;

  int at = root_;
  for (bool descended = true; descended;) {
    descended = false;
    for (int child : nodes_[at].children) {
      if (!valid(child) || !contains(child, address))
        continue;
      at = child;
      descended = true;
      break;
    }
  }
  return at;
}

std::vector<int> RegionTree::path(uint64_t address) const {
  std::vector<int> found;
  for (int at = innermost(address); at >= 0; at = nodes_[at].parent)
    found.push_back(at);
  std::reverse(found.begin(), found.end());
  return found;
}

int RegionTree::enclosing(uint64_t address, const std::string &kind) const {
  for (int at = innermost(address); at >= 0; at = nodes_[at].parent)
    if (nodes_[at].kind == kind)
      return at;
  return -1;
}

std::vector<int> RegionTree::children_of(int id) const {
  std::vector<int> found;
  if (!valid(id))
    return found;

  for (int child : nodes_[id].children)
    if (valid(child))
      found.push_back(child);

  std::sort(found.begin(), found.end(), [this](int a, int b) {
    return address(a) < address(b);
  });
  return found;
}

std::vector<int> RegionTree::all_of_kind(const std::string &kind) const {
  std::vector<int> found;
  for (size_t i = 0; i < nodes_.size(); ++i)
    if (!dead_[i] && nodes_[i].kind == kind)
      found.push_back(static_cast<int>(i));

  std::sort(found.begin(), found.end(), [this](int a, int b) {
    return address(a) < address(b);
  });
  return found;
}

} // namespace ddd
