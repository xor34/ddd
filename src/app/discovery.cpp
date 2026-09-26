// discovery.cpp -- where the functions are, in a file that does not say.
//
// The evidence that survives stripping is calls: something calls a function,
// and the entry point is one. Each candidate start is bounded by the next one,
// which is what a linear sweep can support without a full recovery pass, and
// then by control flow -- see `reachable_end` in decode/cfg.h.
//
// Two shapes of the same walk. `discover_functions` runs it to completion,
// which is what a script or the protocol wants; `analyse_step` (scheduler.cpp)
// does it a slice at a time so a window stays answerable while it runs. The
// per-candidate work both of them do is `bound_start`, which deliberately
// writes nothing down: everything it reads is settled before a batch goes out,
// which is what lets a worker run it while fifteen others run it for fifteen
// other addresses.
#include "app/session.h"

#include <algorithm>
#include <sstream>

namespace ddd {

void Session::set_entry(uint64_t address) {
  elf_->entry = address;
  project_.set_entry(address);
  save_project();

  // It is a function start now, and the list of them is what discovery works
  // through -- so it goes back on the list, and only it.
  bounded_.erase(address);
  collect_starts();
  discovered_ = false;
}

// Everything anything calls, plus the entry point, plus whatever the symbol
// table did know -- a partially stripped file has some of each.
void Session::collect_starts() {
  starts_.clear();
  start_at_ = 0;

  // A call target is a location -- space as well as offset -- and a start is
  // an image address, so the two agree only where a region reads that space.
  // A call into a region decoded with a different spec names that region's
  // space, and folding its offset in here would start a function at whatever
  // bytes happen to sit at the same offset in this one.
  if (xrefs_ != nullptr) {
    for (const Addr &target : xrefs_->call_targets()) {
      if (target.space == kNoSpace)
        continue;
      for (const ImageRange &region : regions_)
        if (region.target != nullptr &&
            target.space == region.target->code_space) {
          starts_.push_back(target.offset);
          break;
        }
    }
  }
  if (elf_->entry != 0)
    starts_.push_back(elf_->entry);
  for (const auto &entry : elf_->functions)
    if (entry.first == entry.second.name)
      starts_.push_back(entry.second.begin);
  for (const ImageRange &region : regions_)
    starts_.push_back(region.begin);

  std::sort(starts_.begin(), starts_.end());
  starts_.erase(std::unique(starts_.begin(), starts_.end()), starts_.end());
}

// One candidate start: bound it, work out where it really ends, name it.
//
// Nothing here writes anything down. Everything it reads -- the regions, the
// starts, the image, what the project says is not a function -- is settled
// before the batch goes out and not touched until it comes back, which is what
// lets a worker run this while fifteen others run it for fifteen other
// addresses. What comes back is an address, an extent and a name; the caller
// records those, in order.
Session::Bounded Session::bound_start(size_t index, int slot) const {
  Bounded bounded;
  const uint64_t address = starts_[index];

  // Already bounded, and nothing has happened to these bytes since it was.
  // Discovery runs again whenever the references change -- a call nobody had
  // decoded is a function nobody had found -- and without this that means
  // lifting every function in the image to be told what it already knew.
  if (bounded_.count(address) != 0)
    return bounded;

  const ImageRange *region = nullptr;
  for (const ImageRange &candidate : regions_)
    if (address >= candidate.begin && address < candidate.end)
      region = &candidate;
  if (region == nullptr)
    return bounded;

  // Something the user has already said is not a function.
  if (project_.is_undefined(address))
    return bounded;

  // The next start is an upper bound: whatever this function is, it stops
  // before the next thing anybody calls.
  uint64_t end = region->end;
  if (index + 1 < starts_.size() && starts_[index + 1] > address &&
      starts_[index + 1] < end)
    end = starts_[index + 1];
  if (end <= address)
    return bounded;

  // And then control flow says where it really stops. A linear sweep runs
  // straight past a `ret` into whatever was laid out next, and everything it
  // picks up that way is unreachable from the entry -- so the last address
  // reachable from the entry is the end of the function.
  ImageRange span = *region;
  span.begin = address;
  span.end = end;
  span.target = targets_->decoder(*region->target, slot);
  if (span.target == nullptr)
    span.target = region->target; // the copy is not ready; slot zero's own

  // No disassembly text: this asks where the function stops, and nothing here
  // ever looks at what the instructions say.
  if (std::unique_ptr<Lifted> lifted =
          lift(span, address, max_instructions_, image_, false)) {
    if (uint64_t reached = reachable_end(lifted->cfg); reached > address)
      end = reached;
  }

  std::ostringstream name;
  auto symbol = elf_->symbols.find(address);
  if (symbol != elf_->symbols.end())
    name << symbol->second;
  else
    name << "sub_" << std::hex << address;

  bounded.ok = true;
  bounded.address = address;
  bounded.end = end;
  bounded.name = name.str();
  return bounded;
}

void Session::discover_functions() {
  // The same work, without yielding: what a script or the protocol wants,
  // where there is no window to keep answering.
  while (!analyse_step().finished) {
  }
}

// The next function that starts after `address`, or `limit`.
//
// A function's listing stops where the next one begins, whatever its own
// recorded extent says: those bytes belong to the function that starts there.
uint64_t Session::next_function_after(uint64_t address, uint64_t limit) const {
  for (auto it = found_.upper_bound(address);
       it != found_.end() && it->first < limit; ++it) {
    if (project_.is_undefined(it->first))
      continue;
    limit = it->first;
    break;
  }

  for (const auto &entry : elf_->functions) {
    if (entry.first != entry.second.name)
      continue;
    if (project_.is_undefined(entry.second.begin))
      continue;
    if (entry.second.begin > address && entry.second.begin < limit)
      limit = entry.second.begin;
  }

  return limit;
}

} // namespace ddd
