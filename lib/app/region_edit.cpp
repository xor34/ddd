// region_edit.cpp -- correcting what the analyses decided.
//
// Everything above is inference, and inference is wrong sometimes. These are
// how a person overrules it, and they all write what they were told into the
// project, so the correction survives the next run.
//
// Two rules run through all of it:
//
//  * Saying a thing *is* something is a claim about bytes, and the claim has to
//    reach the disassembler, not just a table -- or it changes nothing you can
//    see. That is why every one of these ends in a `reindex`.
//  * An edit makes a smaller hole than it looks like it does. A jump table with
//    one routine wrongly in the middle of it is still a jump table on both
//    sides, and losing the marking on all of it because one part was corrected
//    is the sort of thing that makes people stop correcting anything.
#include "app/session.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <sstream>

namespace ddd {

void Session::define_function(uint64_t begin, uint64_t end, std::string name) {
  ElfRange range;
  range.begin = begin;
  range.end = end;
  range.name = name;
  range.executable = true;
  found_[begin] = std::move(range);

  // A function that starts inside another one ends it: those bytes are this
  // function's now. Shrinking the old region first is also what stops the new
  // one being filed *inside* it, which would leave the breadcrumb saying you
  // are in the function you just replaced -- and take its stale blocks with
  // it, since they describe control flow that is no longer being claimed.
  const int enclosing = tree_.enclosing(begin, region_kind::kFunction);
  if (enclosing >= 0 && tree_.address(enclosing) < begin)
    tree_.resize(enclosing, begin - tree_.address(enclosing));

  tree_.add(begin, end - begin, region_kind::kFunction, std::move(name));
}

std::string Session::undefine_at(uint64_t address, int levels) {
  std::vector<int> path = tree_.path(address);
  if (path.empty())
    return {};

  // Innermost first, so `levels` counts outwards: undefining again in the same
  // place undefines the thing the last one was in.
  std::reverse(path.begin(), path.end());

  const size_t wanted = static_cast<size_t>(std::max(0, levels));
  if (wanted >= path.size())
    return {};

  const int id = path[wanted];
  // The image itself is not a decision anyone made, and the instruction-set
  // regions are removed by their own command -- they are what makes the bytes
  // readable at all.
  if (id == tree_.root() || tree_.node(id).kind == region_kind::kCode)
    return {};

  const std::string kind = tree_.node(id).kind;
  const uint64_t begin = tree_.address(id);
  const uint64_t finish = tree_.end(id);

  if (kind == region_kind::kFunction) {
    found_.erase(begin);
    project_.undefine_function(begin);
    tree_.remove(id);

  } else if (kind == region_kind::kBlock) {
    // A block is code that something branches to, so undefining one has to
    // say what it is instead -- otherwise the function is lifted from its own
    // start as before and the listing does not change, which looks exactly
    // like nothing happened. It is not code, and marking it stops the sweep.
    tree_.remove(id);
    define_data(begin, finish);
    return kind;

  } else if (kind == region_kind::kData || kind == region_kind::kString ||
             kind == region_kind::kItem) {
    // Undefining data is saying it is not data, which puts the bytes back in
    // play for the disassembler.
    tree_.remove(id);
    image_->unmark_data(begin, finish);
    project_.unmark_data(begin, finish);
    project_.remove_marks(begin, finish);
    reindex(begin, finish);

  } else {
    tree_.remove(id);
  }

  save_project();
  return kind;
}

bool Session::sweep_region(uint64_t address, ImageRange &out) const {
  for (const ImageRange &region : regions_) {
    if (address < region.begin || address >= region.end)
      continue;
    out = region;
    out.begin = address;
    return out.target != nullptr;
  }
  return false;
}

// The stretches marked as data that cover an address.
//
// Captured before the marks are cleared, so that what the new code does not
// cover can be put back around it.
std::vector<std::pair<uint64_t, uint64_t>>
Session::data_over(uint64_t address) const {
  std::vector<std::pair<uint64_t, uint64_t>> found;
  for (const auto &range : project_.data_ranges())
    if (address >= range.first && address < range.second)
      found.emplace_back(range.first, range.second);
  return found;
}

// Marks a stretch as data without disturbing anything else. What `define_data`
// does minus the part that decides nothing in there is a function -- because
// this is used to rebuild the parts of a region that a new function did not
// take, and the function is the thing that must survive.
void Session::mark_data_region(uint64_t begin, uint64_t end) {
  if (end <= begin)
    return;

  image_->mark_data(begin, end);
  project_.mark_data(begin, end);
  tree_.set_user_defined(
      tree_.add(begin, end - begin, region_kind::kData, "data"), true);
}

// Defining code inside a stretch of data splits it, rather than deleting it: a
// jump table with one routine wrongly in the middle of it is still a jump
// table on both sides, and losing the marking on all of it because one part
// was corrected is the sort of thing that makes people stop correcting
// anything.
void Session::restore_data_around(
    const std::vector<std::pair<uint64_t, uint64_t>> &ranges, uint64_t begin,
    uint64_t end) {
  for (const auto &range : ranges) {
    if (range.first < begin)
      mark_data_region(range.first, begin);
    if (range.second > end)
      mark_data_region(end, range.second);
  }
}

// Puts the bytes back in play: drops the marks that said they were not code,
// and everything that was built on top of them.
void Session::clear_data_over(uint64_t begin, uint64_t end) {
  image_->unmark_data(begin, end);
  project_.unmark_data(begin, end);
  project_.remove_marks(begin, end);

  for (const char *kind : {region_kind::kData, region_kind::kString,
                           region_kind::kItem}) {
    for (int id : tree_.all_of_kind(kind)) {
      const uint64_t at = tree_.address(id);
      if (at < end && tree_.end(id) > begin)
        tree_.remove(id);
    }
  }

  reindex(begin, end);
}

uint64_t Session::define_code(uint64_t address) {
  ImageRange region;
  if (!sweep_region(address, region))
    return 0;

  // Anything saying these bytes are not code has to go before the sweep is
  // asked to read them, since that is exactly what it stops on -- but only the
  // part the block turns out to occupy.
  const std::vector<std::pair<uint64_t, uint64_t>> covering = data_over(address);
  clear_data_over(address, address + 1);

  std::unique_ptr<Lifted> lifted =
      lift(region, address, max_instructions_, image_);
  if (lifted == nullptr || lifted->cfg.empty() || !lifted->cfg.entry)
    return 0;

  // The first block, which is what "this is code" actually establishes: it
  // runs from here to the branch, call or return that ends it.
  const BasicBlock &first = lifted->cfg.blocks[*lifted->cfg.entry];
  const uint64_t end = first.end;
  if (end <= address)
    return 0;

  std::ostringstream name;
  name << "loc_" << std::hex << address;
  define_region(address, end - address, region_kind::kBlock, name.str());

  restore_data_around(covering, address, end);

  save_project();
  return end;
}

uint64_t Session::define_function_at(uint64_t address) {
  ImageRange region;
  if (!sweep_region(address, region))
    return 0;

  const std::vector<std::pair<uint64_t, uint64_t>> covering = data_over(address);
  clear_data_over(address, address + 1);
  // It may have been undefined before; saying it is a function is saying that
  // was wrong.
  project_.define_function_again(address);

  // Bounded by the next function that is already known, then by control flow
  // -- the same two steps discovery takes, for the same reasons.
  for (const auto &entry : found_)
    if (entry.first > address && entry.first < region.end)
      region.end = entry.first;
  for (const auto &entry : elf_->functions)
    if (entry.second.begin > address && entry.second.begin < region.end)
      region.end = entry.second.begin;

  std::unique_ptr<Lifted> lifted =
      lift(region, address, max_instructions_, image_);
  if (lifted == nullptr)
    return 0;

  uint64_t end = reachable_end(lifted->cfg);
  if (end <= address)
    end = region.end;

  // A name someone else already wrote down beats sub_401234.
  std::string name;
  if (auto symbol = elf_->symbols.find(address); symbol != elf_->symbols.end()) {
    name = symbol->second;
  } else {
    std::ostringstream generated;
    generated << "sub_" << std::hex << address;
    name = generated.str();
  }

  define_function(address, end, name);

  // Whatever of the data region the function did not take is still data.
  restore_data_around(covering, address, end);

  // Recorded, because this one is a decision rather than a finding: discovery
  // will not produce it again next time -- nothing calls it, or it would have
  // been found already -- so without this it is gone on reload.
  project_.add_mark(
      Project::Mark{address, end, region_kind::kFunction, std::move(name)});

  save_project();
  return end;
}

int Session::define_region(uint64_t address, uint64_t size,
                           const std::string &kind, const std::string &name) {
  // A function is not only a region: the listing is cut up by the function
  // table, so marking one as a region and nothing else would put it in the
  // breadcrumb and nowhere else.
  if (kind == region_kind::kFunction) {
    define_function(address, address + size, name);
    project_.add_mark(Project::Mark{address, address + size, kind, name});
    save_project();
    return tree_.enclosing(address, region_kind::kFunction);
  }

  const int id = tree_.add(address, size, kind, name);
  if (id < 0)
    return -1;

  tree_.set_user_defined(id, true);
  project_.add_mark(Project::Mark{address, address + size, kind, name});
  save_project();
  return id;
}

uint64_t Session::define_string(uint64_t address) {
  std::optional<std::string> text = image_->read_string(address);
  if (!text || text->empty())
    return 0;

  const uint64_t size = text->size() + 1; // the NUL is part of it
  define_data(address, address + size);

  const int id = tree_.add(address, size, region_kind::kString,
                           "\"" + *text + "\"");
  tree_.set_user_defined(id, true);

  project_.add_mark(Project::Mark{address, address + size,
                                  region_kind::kString, "\"" + *text + "\""});
  save_project();
  return size;
}

void Session::undefine_function(uint64_t address) {
  found_.erase(address);

  if (const int id = tree_.enclosing(address, region_kind::kFunction); id >= 0)
    tree_.remove(id);

  project_.undefine_function(address);
  save_project();
}

void Session::define_data(uint64_t begin, uint64_t end) {
  if (end <= begin)
    return;

  image_->mark_data(begin, end);
  project_.mark_data(begin, end);

  // Whatever was called a function in there is not one. The references index
  // is stale too -- it was built by disassembling bytes that are not code.
  for (auto it = found_.lower_bound(begin); it != found_.end() && it->first < end;)
    it = found_.erase(it);

  // Including the ones the symbol table named. A symbol is evidence and this
  // is a person; leaving them would put functions in the list that cannot be
  // disassembled, since the sweep now stops at their first byte.
  for (const auto &entry : elf_->functions) {
    if (entry.first != entry.second.name)
      continue;
    if (entry.second.begin >= begin && entry.second.begin < end)
      project_.undefine_function(entry.second.begin);
  }

  for (int id : tree_.all_of_kind(region_kind::kFunction)) {
    const uint64_t at = tree_.address(id);
    if (at >= begin && at < end)
      tree_.remove(id);
  }

  const int id = tree_.add(begin, end - begin, region_kind::kData, "data");
  tree_.set_user_defined(id, true);
  tree_.clear_children(id);

  // Only what those bytes referred to has changed, and they refer to nothing
  // now: the disassembler will not read them at all.
  reindex(begin, end);

  save_project();
}

} // namespace ddd
