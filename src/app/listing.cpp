// listing.cpp -- naming a place, and showing what is there.
//
// The last step of everything a front end asks for: `functions` and
// `function_at` say what is in the image, `range_at` turns an address into the
// stretch to lift there, and `listing` runs the pipeline over it and returns
// the result as text and as tokens.
//
// Two things live here rather than in the front ends, and both are the same
// rule. The function's own result is worked out from the calling convention and
// handed to SSA, because phi placement is pruned by liveness and cannot know
// what the caller still reads. And a pass's output is *captured*, never
// printed: a front end drawing a screen has no way to interleave with a pass
// that writes into the middle of it.
//
// The blocks a function is made of are added to the region tree here as well,
// because this is where control flow is known -- and only for functions
// somebody actually looked at, which is what keeps the tree the size of the
// work done rather than the size of the binary.
#include "app/session.h"

#include <algorithm>
#include <sstream>

namespace ddd {

std::vector<FunctionInfo> Session::functions(const std::string &pattern) const {
  // By address, so a function that is both in the symbol table and reachable
  // by a call is listed once. Symbols are added second and overwrite, because
  // a symbol's extent is exact where a discovered one is a guess.
  std::map<uint64_t, FunctionInfo> by_address;

  for (const auto &entry : found_) {
    FunctionInfo info;
    info.addr = entry.second.begin;
    info.end = entry.second.end;
    info.name = entry.second.name;
    by_address[info.addr] = std::move(info);
  }

  for (const auto &entry : elf_->functions) {
    // A C++ function is registered under both its mangled and its demangled
    // spelling so either selects it, but listing both would double the output
    // and show the unreadable one for no reason.
    if (entry.first != entry.second.name)
      continue;
    // A symbol is evidence, not proof. Someone who has looked at the bytes and
    // said this is not a function outranks it -- otherwise undefining anything
    // in a binary that still has its symbol table does nothing at all.
    if (project_.is_undefined(entry.second.begin))
      continue;

    FunctionInfo info;
    info.addr = entry.second.begin;
    info.end = entry.second.end;
    info.name = entry.first;
    info.symbol = entry.first;
    by_address[info.addr] = std::move(info);
  }

  std::vector<FunctionInfo> found;
  for (auto &entry : by_address) {
    FunctionInfo &info = entry.second;

    if (const std::string *renamed = project_.function_name(info.addr))
      info.name = *renamed;

    if (!pattern.empty() && info.name.find(pattern) == std::string::npos &&
        info.symbol.find(pattern) == std::string::npos)
      continue;

    found.push_back(info);
  }

  return found;
}

const ElfRange *Session::function_at(uint64_t address) const {
  // The most specific one wins: of every function containing this address, the
  // one that starts latest.
  //
  // Not "the symbol table first". Defining a function part-way into one that
  // already exists is a deliberate statement about those bytes -- a tail call
  // landed in the middle of something, or a symbol covers two functions -- and
  // an answer of "you are in the outer one" makes the new function invisible
  // everywhere it matters: the listing shows the outer one's body, the SSA
  // view lists the outer one, and nothing appears to have happened.
  const ElfRange *best = nullptr;

  auto it = found_.upper_bound(address);
  if (it != found_.begin()) {
    --it;
    if (address >= it->second.begin && address < it->second.end)
      best = &it->second;
  }

  for (const auto &entry : elf_->functions) {
    if (entry.first != entry.second.name)
      continue; // skip the mangled alias
    if (project_.is_undefined(entry.second.begin))
      continue; // and what a person said is not one
    if (address < entry.second.begin || address >= entry.second.end)
      continue;

    if (best == nullptr || entry.second.begin > best->begin)
      best = &entry.second;
  }

  return best;
}

std::string Session::function_name_at(uint64_t address) const {
  const ElfRange *range = function_at(address);
  if (range == nullptr)
    return {};

  const std::string *renamed = project_.function_name(range->begin);
  return renamed != nullptr ? *renamed : range->name;
}

bool Session::range_at(uint64_t address, ElfRange &out) const {
  if (const ElfRange *known = function_at(address)) {
    out = *known;
    if (const std::string *renamed = project_.function_name(known->begin))
      out.name = *renamed;
    return true;
  }

  for (const ImageRange &region : regions_) {
    if (address < region.begin || address >= region.end)
      continue;

    out.begin = address;
    // Bounded by the next thing that is known, not by the end of the region:
    // sweeping from an unattributed address to the end of .text produces one
    // "function" containing every function after it, and every analysis
    // downstream is per-function.
    //
    // Three bounds, cheapest first, because this is asked before discovery has
    // run -- an interface draws its first listing while the sweep that would
    // answer this properly is still going.
    out.end = region.end;

    if (auto next = found_.upper_bound(address);
        next != found_.end() && next->first < out.end)
      out.end = next->first;

    // The symbol table costs nothing to consult and is usually right.
    if (auto next = elf_->symbols.upper_bound(address);
        next != elf_->symbols.end() && next->first < out.end)
      out.end = next->first;

    // And a limit, for a stripped image with nothing to go on yet. A function
    // longer than this is rare; one that looks longer than this is usually the
    // rest of the segment.
    constexpr uint64_t kUnknownFunctionLimit = 4096;
    if (out.end - address > kUnknownFunctionLimit)
      out.end = address + kUnknownFunctionLimit;

    out.executable = true;

    if (const std::string *renamed = project_.function_name(address)) {
      out.name = *renamed;
    } else {
      std::ostringstream name;
      name << "sub_" << std::hex << address;
      out.name = name.str();
    }
    return true;
  }

  return false;
}

Listing Session::listing(const ElfRange &range, const ListingRequest &request) {
  Listing listing;
  listing.name = range.name;
  listing.addr = range.begin;
  listing.end = range.end;

  ImageRange region = prototype_;
  region.begin = range.begin;
  region.end = range.end;
  if (region.target == nullptr) {
    listing.error = "no instruction set for this address";
    return listing;
  }
  // Stop where the next function begins. Defining one part-way into this one
  // is what makes that differ from its recorded extent, and without this both
  // would be listed, each showing the other's code.
  region.end = next_function_after(range.begin, region.end);
  listing.end = region.end;

  region.name = range.name + " (" + region.target->name + ")";
  listing.target = region.target->name;

  std::unique_ptr<Lifted> lifted = lift(region, range.begin, max_instructions_, image_);
  if (lifted == nullptr) {
    listing.error = "nothing disassembles there";
    return listing;
  }

  const std::vector<std::string> &names =
      request.passes.empty() ? passes_ : request.passes;

  PassManager manager;
  for (const std::string &name : names) {
    if (name.empty())
      continue;
    // With tokens wanted the caller renders the listing itself, and the folded
    // listing is the one it can rebuild from them -- this function appends
    // exactly that at the end -- so running it here would build the same Hil
    // twice. A pipeline that ends in print-ssa is stating something tokens
    // cannot rebuild, so it runs.
    if (request.tokens && is_folded_listing(name))
      continue;
    // A name nobody registered is a mistake in the caller's pipeline, not
    // something to paper over by printing the folded listing instead. The
    // command line refuses the same input outright (main.cc), and the two have
    // to agree about what a pipeline means.
    if (!manager.add(name)) {
      listing.error = "no pass called \"" + name + "\"";
      return listing;
    }
  }

  // Phi placement is pruned by liveness, so it has to be told what the caller
  // still reads, and a call has to be told what it does to the caller's
  // machine state; both come from the same convention.
  SsaFunction fn =
      build_ssa(lifted->cfg, ssa_options(*region.target));

  // The blocks of a function are regions inside it, the same way the function
  // is a region inside a segment. They are added here rather than by discovery
  // because this is where control flow is known -- and only for functions
  // somebody actually looked at, which is what keeps the tree the size of the
  // work done rather than the size of the binary.
  const int function_id =
      tree_.enclosing(range.begin, region_kind::kFunction);
  if (function_id >= 0) {
    for (const BasicBlock &block : lifted->cfg.blocks) {
      if (!fn.dominance().reachable(block.id))
        continue;

      const uint64_t begin = block.start;
      const uint64_t end = block.end;
      if (end <= begin)
        continue;

      std::ostringstream name;
      name << "loc_" << std::hex << begin;
      tree_.add(begin, end - begin, region_kind::kBlock, name.str(),
                function_id);
    }
  }

  // Everything the passes say goes into the listing's text, never onto a
  // stream the caller did not ask for: a front end that is drawing a screen
  // cannot have a pass print into the middle of it.
  std::ostringstream captured;

  Annotations annotations;
  PassContext ctx;
  ctx.target = region.target;
  ctx.image = image_;
  ctx.annotations = &annotations;
  ctx.symbols = &elf_->symbols;
  ctx.project = &project_;
  ctx.out = &captured;
  ctx.verbose = request.verbose;
  ctx.show_machine_state = request.machine;
  manager.run(fn, ctx);

  listing.text = captured.str();

  if (request.tokens) {
    Hil hil = build_hil(fn, ctx);
    listing.blocks = tokenize(hil, fn, ctx);

    // A pipeline ending in a terminal pass has already stated the listing the
    // caller wanted; anything else gets the folded listing to go with its
    // tokens.
    const bool printed =
        std::any_of(names.begin(), names.end(), [](const std::string &name) {
          return is_terminal_pass(name);
        });
    if (!printed)
      listing.text += to_string(hil, fn, ctx);
  }

  listing.ok = true;
  return listing;
}

Listing Session::listing_at(uint64_t address, const ListingRequest &request) {
  ElfRange range;
  if (!range_at(address, range)) {
    Listing listing;
    listing.addr = address;
    listing.error = "no code there";
    return listing;
  }
  return listing(range, request);
}

} // namespace ddd
