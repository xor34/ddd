// index.cpp -- what refers to what, and keeping that true through edits.
//
// The index is a map from an address to everything that names it, and it costs
// a sweep of every code region to build. Two things make that affordable:
//
//  * it is built a slice at a time (`analyse_step`, scheduler.cpp) while the
//    old one keeps answering, and swapped in in one step when it is finished,
//    so nothing ever sees a half-built one;
//  * an edit does not rebuild it, it *repairs* it -- `reindex` forgets what was
//    found over the stretch that changed and sweeps only that again. Marking
//    bytes as data changes what those bytes refer to and nothing else.
//
// `xrefs_to` is the one place an image address becomes a location: references
// are keyed by space as well as offset, because an image can hold more than one
// instruction set and an offset means different bytes in each.
#include "app/session.h"

#include <algorithm>

namespace ddd {
namespace {

const std::vector<Xref> &no_xrefs() {
  static const std::vector<Xref> empty;
  return empty;
}

} // namespace

// Marking an edit rather than undoing the work.
//
// Changing what is code changes what refers to what, so the index is wrong --
// but the version that is already built is far better than nothing while a new
// one is made, and throwing it away means the next question about references
// rebuilds the whole thing on the spot, with the window waiting.
void Session::invalidate_index() {
  pending_xrefs_ = std::make_unique<Xrefs>();
  index_region_ = 0;
  index_at_ = 0;
  indexed_ = false;

  // Function discovery rests on the index, so it is out of date too -- but the
  // functions already found stay until better ones replace them. Every extent
  // is a candidate again: this is the version for a change that could have
  // moved anything.
  discovered_ = false;
  bounded_.clear();
}

void Session::reindex(uint64_t begin, uint64_t end) {
  if (xrefs_ == nullptr || end <= begin)
    return;

  xrefs_->forget(begin, end);

  for (const ImageRange &region : regions_) {
    if (region.target == nullptr)
      continue;

    const uint64_t from = std::max(begin, region.begin);
    const uint64_t to = std::min(end, region.end);
    if (to <= from)
      continue;

    // The same run-up the chunked sweep takes, and for the same reason: on an
    // instruction set of varying length, starting in the middle of the stretch
    // means starting in the middle of an instruction until the decoder falls
    // back into step. What it reads before `from` is not reported.
    const uint64_t at = resync_from(region, from);

    ImageRange slice = region;
    slice.begin = at;
    slice.end = to;

    if (std::unique_ptr<Lifted> lifted =
            lift(slice, at, static_cast<int>(to - at), image_,
                 /*disassemble=*/false))
      xrefs_->add(lifted->cfg, "", from, to, region.begin, region.end);
  }

  // A function that runs into the stretch may end somewhere else now, so it
  // goes back on the list as well as anything starting inside it.
  uint64_t first = begin;
  if (auto it = found_.upper_bound(begin); it != found_.begin()) {
    --it;
    if (it->second.end > begin)
      first = it->first;
  }
  bounded_.erase(bounded_.lower_bound(first), bounded_.lower_bound(end));

  // What the references say about where the functions are has changed with
  // them: a call nobody had decoded before is a function nobody had found.
  // Discovery runs again over the new list, and skips everything on it that is
  // already bounded -- which after an edit is all of it but the few addresses
  // this just forgot.
  collect_starts();
  discovered_ = false;
}

void Session::build_xrefs() {
  // An index that exists answers now, even if an edit has made it stale: the
  // replacement is being built in the background, and blocking a question
  // about references on a sweep of the image is the thing this is for.
  if (xrefs_ != nullptr)
    return;

  // Nothing at all to answer with, so it runs to completion here.
  // analyse_step() is the version that yields, for a caller with a window to
  // keep drawing.
  while (!indexed_)
    analyse_step();
}

const std::vector<Xref> &Session::xrefs_to(uint64_t address) {
  if (xrefs_ == nullptr)
    return no_xrefs();

  // References are keyed by location -- space as well as offset -- so an
  // image address has to become one before it can be looked up: the space of
  // the region it sits in, or, for data no region decodes, the image's
  // default reading.
  Addr key{kNoSpace, address};
  for (const ImageRange &region : regions_)
    if (address >= region.begin && address < region.end &&
        region.target != nullptr)
      key.space = region.target->code_space;
  if (key.space == kNoSpace && prototype_.target != nullptr)
    key.space = prototype_.target->code_space;

  return xrefs_->to(key);
}

} // namespace ddd
