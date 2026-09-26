// id.h -- typed dense ids: how the IR names its blocks, ops and values.
//
// Ids are how this IR names things without pointers: dense indices into the
// object that owns the entities, so an analysis keeps its per-block or
// per-value state in a plain vector and nothing moves when a container
// reallocates. That is the design, and it stays.
//
// What a bare `int` could not do is say *which kind* of thing it names, and
// what a `-1` could not do is say "none" without a comment promising it. So:
// one type per kind -- a BlockId will not compile where a ValueId is wanted --
// and absence as std::optional<BlockId> rather than a magic number.
//
// The index is still reachable, on purpose: `operator size_t` makes
// `per_state[block_id]` work, and indexing vectors by these ids is the
// intended use -- the ceremony of a named accessor at every index would buy
// no safety. What is deliberately absent is the other direction: no implicit
// conversion *from* int, and integer comparisons are deleted, so `-1` and
// its friends cannot quietly come back.
#pragma once

#include <cstddef>
#include <functional>

namespace ddd {

template <typename Tag>
struct Id {
  int index = -1; // dense index; -1 only as "not assigned yet", never as "none"

  constexpr Id() = default;
  constexpr explicit Id(int i) : index(i) {}

  constexpr bool valid() const { return index >= 0; }

  // Indexing: a vector of per-entity state is addressed by its id.
  constexpr operator size_t() const { return static_cast<size_t>(index); }

  constexpr bool operator==(const Id &o) const { return index == o.index; }
  constexpr bool operator!=(const Id &o) const { return index != o.index; }
  constexpr bool operator<(const Id &o) const { return index < o.index; }
  constexpr bool operator<=(const Id &o) const { return index <= o.index; }
  constexpr bool operator>(const Id &o) const { return index > o.index; }
  constexpr bool operator>=(const Id &o) const { return index >= o.index; }

  constexpr Id &operator++() {
    ++index;
    return *this;
  }
  constexpr Id operator++(int) {
    Id was = *this;
    ++index;
    return was;
  }

  // Deleted so an id compared with a raw integer is a compile error rather
  // than a silent comparison against something it was never meant to be.
  // (The built-in path this blocks is the dangerous one: `id == -1` through
  // size_t would always be false, and look exactly like working code.)
  bool operator==(int) const = delete;
  bool operator!=(int) const = delete;
  bool operator<(int) const = delete;
  bool operator>(int) const = delete;
  bool operator<=(int) const = delete;
  bool operator>=(int) const = delete;
};

struct BlockTag {};
struct OpTag {};
struct ValueTag {};

using BlockId = Id<BlockTag>;
using OpId = Id<OpTag>;
using ValueId = Id<ValueTag>;

} // namespace ddd

namespace std {

template <typename Tag>
struct hash<ddd::Id<Tag>> {
  size_t operator()(const ddd::Id<Tag> &id) const noexcept {
    return hash<int>()(id.index);
  }
};

} // namespace std
