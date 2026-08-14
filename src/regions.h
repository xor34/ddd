// regions.h -- the one structure the whole image is described with.
//
// A function is a region. So is a basic block inside it, a segment, a jump
// table, a string, and a single four-byte integer in the middle of one. They
// are all the same thing at different scales: a stretch of the image, of some
// kind, with a name, sitting inside a bigger stretch.
//
// So there is one tree rather than a list of functions beside a list of data
// ranges beside a list of instruction-set regions. That buys three things:
//
//   * a child is positioned relative to its parent, so moving or resizing a
//     function does not invalidate what is inside it
//   * "what am I looking at" has one answer at every scale at once -- image,
//     segment, function, block -- which is what a breadcrumb shows and what
//     undefining walks up
//   * a plugin can invent a kind. Nothing here enumerates them; `kind` is a
//     string because the set of things worth marking in a binary is not
//     something this file gets to decide.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ddd {

// The kinds this tool creates itself. A plugin may use any string it likes.
namespace region_kind {
inline constexpr const char *kImage = "image";
inline constexpr const char *kCode = "code";
inline constexpr const char *kData = "data";
inline constexpr const char *kFunction = "function";
inline constexpr const char *kBlock = "block";
inline constexpr const char *kItem = "item";
inline constexpr const char *kString = "string";
} // namespace region_kind

struct RegionNode {
  int id = -1;
  int parent = -1;
  std::vector<int> children;

  // From the start of the parent. The root's offset is the image's base
  // address, so every absolute address in the tree is a sum down one path.
  uint64_t offset = 0;
  uint64_t size = 0;

  std::string kind;
  std::string name;

  // Which instruction set reads this, as an index into the session's list.
  // Inherited from the parent when -1, which is how a function knows what it
  // is written in without being told.
  int isa = -1;

  bool user_defined = false; // a person said so, rather than an analysis
};

class RegionTree {
public:
  RegionTree() = default;

  // Starts over with one region covering the whole image.
  void reset(uint64_t base, uint64_t size, std::string name = "image");

  int root() const { return root_; }
  bool valid(int id) const {
    return id >= 0 && id < static_cast<int>(nodes_.size()) && !dead_[id];
  }
  const RegionNode &node(int id) const { return nodes_[id]; }
  size_t size() const { return nodes_.size(); }

  uint64_t address(int id) const;
  uint64_t end(int id) const { return address(id) + nodes_[id].size; }
  bool contains(int id, uint64_t addr) const {
    return addr >= address(id) && addr < end(id);
  }

  // Adds a region at an absolute address, under whichever region already
  // contains it -- or under `parent` when one is named. Returns -1 if it does
  // not fit anywhere, and reuses an existing region of the same extent and
  // kind rather than stacking duplicates.
  int add(uint64_t address, uint64_t size, const std::string &kind,
          const std::string &name, int parent = -1);

  // Which instruction set reads this region. Set on the top-level code
  // regions; everything inside one inherits it by looking up the tree.
  void set_isa(int id, int isa);
  int isa_of(int id) const;

  void set_name(int id, std::string name);
  void set_user_defined(int id, bool user_defined);

  // Removes a region. Its children move up to its parent, because they are
  // still there -- undefining a function does not undefine its blocks, it
  // stops calling that stretch a function.
  bool remove(int id);

  // Removes every child of a region, and their descendants.
  void clear_children(int id);

  // The deepest region containing `address`, or -1.
  int innermost(uint64_t address) const;

  // Root first, innermost last. What a breadcrumb reads out, and what
  // undefining walks up one step at a time.
  std::vector<int> path(uint64_t address) const;

  // The deepest region of this kind containing `address`, or -1.
  int enclosing(uint64_t address, const std::string &kind) const;

  // Direct children, in address order.
  std::vector<int> children_of(int id) const;

  // Every live region of a kind, in address order.
  std::vector<int> all_of_kind(const std::string &kind) const;

private:
  int fit(uint64_t address, uint64_t size, int from) const;
  void detach(int id);

  std::vector<RegionNode> nodes_;
  std::vector<bool> dead_;
  int root_ = -1;
};

} // namespace ddd
