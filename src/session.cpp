#include "session.h"

#include "sleigh.hh"

#include <algorithm>
#include <filesystem>
#include <iostream>
#include <limits>
#include <sstream>

namespace ddd {
namespace {

const std::vector<Xref> &no_xrefs() {
  static const std::vector<Xref> empty;
  return empty;
}

// A pipeline that ends in a printer prints; a caller who wants tokens is
// building the listing itself and only wants what the earlier passes recorded.
bool is_printer(const std::string &pass) {
  return pass == "hil" || pass == "print-ssa";
}

// The address one past the last instruction reachable from the entry.
//
// The sweep is linear, so it decodes whatever was laid out after the function
// as well; none of it is reachable, and where the reachable part stops is where
// the function does.
uint64_t reachable_end(const Cfg &cfg) {
  if (cfg.empty() || cfg.entry < 0)
    return 0;

  std::vector<bool> seen(cfg.blocks.size(), false);
  std::vector<int> pending{cfg.entry};
  seen[cfg.entry] = true;

  uint64_t end = 0;
  while (!pending.empty()) {
    const int id = pending.back();
    pending.pop_back();

    const BasicBlock &block = cfg.blocks[id];
    end = std::max(end, block.end.getOffset());

    for (const Edge &edge : block.succs) {
      if (edge.target < 0 || edge.target >= static_cast<int>(cfg.blocks.size()))
        continue;
      if (seen[edge.target])
        continue;
      seen[edge.target] = true;
      pending.push_back(edge.target);
    }
  }

  return end;
}

} // namespace

std::unique_ptr<Lifted> lift(const Region &region, uint64_t entry,
                             int max_instructions, const Image *image) {
  if (region.target == nullptr || region.target->translator == nullptr)
    return nullptr;

  ghidra::Sleigh &translator = *region.target->translator;
  ghidra::Address start(translator.getDefaultCodeSpace(),
                        entry != 0 ? entry : region.begin);

  SweepLimits limits;
  limits.max_instructions = max_instructions;
  limits.end = ghidra::Address(translator.getDefaultCodeSpace(), region.end);

  // What somebody said is not code stops the sweep, so that saying it has an
  // effect on the listing rather than only on a side table.
  if (image != nullptr) {
    limits.is_data = [image](uint64_t address) {
      return image->marked_data(address);
    };
  }

  auto lifted = std::make_unique<Lifted>();
  lifted->region = region;
  lifted->cfg = build_cfg(translator, start, limits);
  return lifted->cfg.empty() ? nullptr : std::move(lifted);
}

Session::Session(ElfInfo &elf, Image &image, TargetSet &targets)
    : elf_(&elf), image_(&image), targets_(&targets) {
  // Every byte is data until something is disassembled, so tell the image what
  // the container said is code before any listing is produced -- otherwise the
  // first function looked at is the only code in the file as far as anything
  // here knows.
  uint64_t code_begin = image.limit();
  uint64_t code_end = image.base();
  for (const ElfRange &range : elf.ranges) {
    if (!range.executable)
      continue;
    code_begin = std::min(code_begin, range.begin);
    code_end = std::max(code_end, range.end);
  }
  if (code_end > code_begin)
    image.set_code_range(code_begin, code_end);

  tree_.reset(image.base(), image.size(), "image");
}

void Session::set_regions(std::vector<Region> regions) {
  regions_ = std::move(regions);
  if (!regions_.empty())
    prototype_ = regions_.front();

  // The instruction-set regions are the top level of the tree: everything
  // else -- a function, a block, a jump table -- is inside one of them, and
  // inherits what it is written in from the one it is inside.
  for (size_t i = 0; i < regions_.size(); ++i) {
    const Region &region = regions_[i];
    const int id = tree_.add(region.begin, region.end - region.begin,
                             region_kind::kCode, region.name);
    tree_.set_isa(id, static_cast<int>(i));
  }
}

std::ostream &Session::log() const {
  return log_ != nullptr ? *log_ : std::cout;
}

bool Session::resolve(const std::string &what, uint64_t &out) const {
  auto named = elf_->functions.find(what);
  if (named != elf_->functions.end()) {
    out = named->second.begin;
    return true;
  }

  // A name the user chose, which is not in the container's symbol table.
  for (const auto &entry : project_.functions()) {
    if (entry.second == what) {
      out = entry.first;
      return true;
    }
  }

  try {
    size_t consumed = 0;
    out = std::stoull(what, &consumed, 0);
    return consumed == what.size();
  } catch (...) {
    return false;
  }
}

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

void Session::define_function(uint64_t begin, uint64_t end, std::string name) {
  ElfRange range;
  range.begin = begin;
  range.end = end;
  range.name = name;
  range.executable = true;
  found_[begin] = std::move(range);

  tree_.add(begin, end - begin, region_kind::kFunction, std::move(name));
}

void Session::discover_functions() {
  if (discovered_)
    return;
  discovered_ = true;

  build_xrefs();

  // Everything anything calls, plus the entry point, plus whatever the symbol
  // table did know -- a partially stripped file has some of each.
  std::vector<uint64_t> starts = xrefs_ != nullptr ? xrefs_->call_targets()
                                                   : std::vector<uint64_t>();
  if (elf_->entry != 0)
    starts.push_back(elf_->entry);
  for (const auto &entry : elf_->functions)
    if (entry.first == entry.second.name)
      starts.push_back(entry.second.begin);
  for (const Region &region : regions_)
    starts.push_back(region.begin);

  // Only starts that are in something we know how to lift.
  auto region_of = [&](uint64_t address) -> const Region * {
    for (const Region &region : regions_)
      if (address >= region.begin && address < region.end)
        return &region;
    return nullptr;
  };

  std::sort(starts.begin(), starts.end());
  starts.erase(std::unique(starts.begin(), starts.end()), starts.end());

  int found = 0;
  for (size_t i = 0; i < starts.size(); ++i) {
    const Region *region = region_of(starts[i]);
    if (region == nullptr)
      continue;

    // The next start is an upper bound: whatever this function is, it stops
    // before the next thing anybody calls.
    uint64_t end = region->end;
    if (i + 1 < starts.size() && starts[i + 1] > starts[i] &&
        starts[i + 1] < end)
      end = starts[i + 1];

    if (end <= starts[i])
      continue;
    // Something the user has already said is not a function.
    if (project_.is_undefined(starts[i]))
      continue;

    // And then control flow says where it really stops. A linear sweep runs
    // straight past a `ret` into whatever was laid out next, and everything it
    // picks up that way is unreachable from the entry -- so the last address
    // reachable from the entry is the end of the function.
    Region bounded = *region;
    bounded.begin = starts[i];
    bounded.end = end;
    if (std::unique_ptr<Lifted> lifted =
            lift(bounded, starts[i], max_instructions_, image_)) {
      if (uint64_t reached = reachable_end(lifted->cfg); reached > starts[i])
        end = reached;
    }

    std::ostringstream name;
    auto symbol = elf_->symbols.find(starts[i]);
    if (symbol != elf_->symbols.end())
      name << symbol->second;
    else
      name << "sub_" << std::hex << starts[i];

    define_function(starts[i], end, name.str());
    ++found;
  }

  log() << found << " function(s) found\n";
}

const ElfRange *Session::function_at(uint64_t address) const {
  // A symbol says exactly where a function begins and ends; nothing worked out
  // from references beats that, so it is asked first.
  for (const auto &entry : elf_->functions) {
    if (entry.first != entry.second.name)
      continue; // skip the mangled alias
    if (project_.is_undefined(entry.second.begin))
      continue; // and what a person said is not one
    if (address >= entry.second.begin && address < entry.second.end)
      return &entry.second;
  }

  // The last discovered start at or before the address, if the extent it was
  // given covers it.
  auto it = found_.upper_bound(address);
  if (it != found_.begin()) {
    --it;
    if (address >= it->second.begin && address < it->second.end)
      return &it->second;
  }

  return nullptr;
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

  for (const Region &region : regions_) {
    if (address < region.begin || address >= region.end)
      continue;

    out.begin = address;
    // Bounded by the next function that *is* known, not by the end of the
    // region: sweeping from an unattributed address to the end of .text
    // produces one "function" containing every function after it, and every
    // analysis downstream is per-function.
    out.end = region.end;
    if (auto next = found_.upper_bound(address);
        next != found_.end() && next->first < out.end)
      out.end = next->first;

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

  Region region = prototype_;
  region.begin = range.begin;
  region.end = range.end;
  if (region.target == nullptr) {
    listing.error = "no instruction set for this address";
    return listing;
  }
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
    // With tokens wanted the caller renders the listing itself, so running the
    // printer would only mean building the same Hil twice.
    if (request.tokens && name == "hil")
      continue;
    manager.add(name);
  }

  // Phi placement is pruned by liveness, so it has to be told what the caller
  // still reads -- otherwise the function's own result looks dead at the exit.
  SsaOptions options;
  options.live_at_exit =
      observable_storage(region.target->abi, region.target->translator);
  SsaFunction fn = build_ssa(lifted->cfg, options);

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

      const uint64_t begin = block.start.getOffset();
      const uint64_t end = block.end.getOffset();
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

    // A pipeline ending in print-ssa has already produced the text the caller
    // wanted; anything else gets the folded listing to go with its tokens.
    const bool printed =
        std::any_of(names.begin(), names.end(), [](const std::string &name) {
          return is_printer(name);
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

void Session::build_xrefs() {
  if (xrefs_ != nullptr)
    return;

  xrefs_ = std::make_unique<Xrefs>();
  log() << "analysing all references..." << std::flush;

  // Every code region, not the ELF's ranges: a flat image has no ELF ranges
  // and its code is exactly what --region said it was.
  for (const Region &region : regions_) {
    // The whole range, not the per-run limit: an index that stops a third of
    // the way through .text reports "no references" for everything past the
    // cut, which is worse than not having one.
    std::unique_ptr<Lifted> lifted =
        lift(region, region.begin, std::numeric_limits<int>::max(), image_);
    if (lifted == nullptr)
      continue;
    xrefs_->add(lifted->cfg, "");
  }

  log() << " " << xrefs_->size() << " reference(s)\n";
}

const std::vector<Xref> &Session::xrefs_to(uint64_t address) {
  if (xrefs_ == nullptr)
    return no_xrefs();
  return xrefs_->to(address);
}

DataView Session::data(uint64_t address, uint64_t count) {
  DataView view;
  view.addr = address;
  view.code = image_->is_code(address);

  if (count == 0 || count > 512)
    count = 64;

  build_xrefs();

  // Pointer width decides the natural item size: a literal pool on a 32-bit
  // target is words, on a 64-bit one it is doublewords.
  unsigned word = 4;
  if (prototype_.target != nullptr && prototype_.target->translator != nullptr)
    word = prototype_.target->translator->getDefaultCodeSpace()->getAddrSize();
  if (word != 4 && word != 8)
    word = 4;

  uint64_t at = address;
  for (uint64_t i = 0; i < count && image_->contains(at); ++i) {
    DataItem item;
    item.addr = at;

    // A symbol here names the item whatever else it turns out to be.
    auto symbol = elf_->symbols.find(at);
    if (symbol != elf_->symbols.end())
      item.label = symbol->second;

    item.xrefs = xrefs_to(at);

    // A readable string is the strongest reading, and it sets its own extent.
    if (std::optional<std::string> text = image_->read_string(at);
        text && text->size() >= 4) {
      item.kind = "string";
      item.size = static_cast<unsigned>(text->size() + 1);
      item.text = *text;
      at += text->size() + 1;
      view.items.push_back(std::move(item));
      continue;
    }

    std::optional<uint64_t> value = image_->read_int(at, word);
    if (!value)
      break;

    item.kind = "word";
    item.size = word;
    item.value = *value;

    // The point of a literal pool: what does this word point at?
    if (auto target = elf_->symbols.find(*value);
        target != elf_->symbols.end()) {
      item.points = "code";
      item.target = target->second;
    } else if (std::optional<std::string> text = image_->read_string(*value)) {
      item.points = "string";
      item.target = *text;
    } else if (image_->contains(*value) && *value != 0) {
      item.points = image_->is_code(*value) ? "code" : "data";
    }

    at += word;
    view.items.push_back(std::move(item));
  }

  view.end = at;
  return view;
}

HexView Session::hex(uint64_t address, uint64_t length) {
  HexView view;
  view.addr = address;
  view.code = image_->is_code(address);

  if (length == 0 || length > 4096)
    length = 256;

  for (uint64_t i = 0; i < length; ++i) {
    const uint8_t *byte = image_->at(address + i);
    if (byte == nullptr)
      break;
    view.bytes.push_back(*byte);
  }

  for (uint64_t i = 0; i < length; ++i) {
    if (std::optional<std::string> text = image_->read_string(address + i)) {
      view.strings.emplace_back(address + i, *text);
      i += text->size();
    }
  }

  return view;
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
    xrefs_.reset();

  } else {
    tree_.remove(id);
  }

  save_project();
  return kind;
}

bool Session::sweep_region(uint64_t address, Region &out) const {
  for (const Region &region : regions_) {
    if (address < region.begin || address >= region.end)
      continue;
    out = region;
    out.begin = address;
    return out.target != nullptr;
  }
  return false;
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

  xrefs_.reset();
}

uint64_t Session::define_code(uint64_t address) {
  Region region;
  if (!sweep_region(address, region))
    return 0;

  // Anything saying these bytes are not code has to go before the sweep is
  // asked to read them, since that is exactly what it stops on.
  clear_data_over(address, address + 1);

  std::unique_ptr<Lifted> lifted =
      lift(region, address, max_instructions_, image_);
  if (lifted == nullptr || lifted->cfg.empty() || lifted->cfg.entry < 0)
    return 0;

  // The first block, which is what "this is code" actually establishes: it
  // runs from here to the branch, call or return that ends it.
  const BasicBlock &first = lifted->cfg.blocks[lifted->cfg.entry];
  const uint64_t end = first.end.getOffset();
  if (end <= address)
    return 0;

  std::ostringstream name;
  name << "loc_" << std::hex << address;
  define_region(address, end - address, region_kind::kBlock, name.str());

  save_project();
  return end;
}

uint64_t Session::define_function_at(uint64_t address) {
  Region region;
  if (!sweep_region(address, region))
    return 0;

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

  define_function(address, end, std::move(name));
  save_project();
  return end;
}

int Session::define_region(uint64_t address, uint64_t size,
                           const std::string &kind, const std::string &name) {
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

  for (int id : tree_.all_of_kind(region_kind::kFunction)) {
    const uint64_t at = tree_.address(id);
    if (at >= begin && at < end)
      tree_.remove(id);
  }

  const int id = tree_.add(begin, end - begin, region_kind::kData, "data");
  tree_.set_user_defined(id, true);
  tree_.clear_children(id);

  xrefs_.reset();

  save_project();
}

bool Session::add_region(uint64_t begin, uint64_t end, const std::string &spec,
                         const std::string &abi,
                         const std::string &stack_pointer) {
  if (end <= begin || targets_ == nullptr)
    return false;

  const std::string path =
      spec.size() >= 4 && spec.compare(spec.size() - 4, 4, ".sla") == 0
          ? spec
          : spec_dir_ + "/" + spec + ".sla";

  Target *target = targets_->acquire(path, abi, stack_pointer);
  if (target == nullptr)
    return false;

  Region region;
  region.begin = begin;
  region.end = end;
  region.kind = RegionKind::Code;
  region.target = target;
  region.name = target->name;
  regions_.push_back(region);
  if (prototype_.target == nullptr)
    prototype_ = region;

  // A new stretch of code is new places to find functions and new references.
  discovered_ = false;
  xrefs_.reset();

  Project::RegionSpec recorded;
  recorded.begin = begin;
  recorded.end = end;
  recorded.spec = spec;
  recorded.abi = abi;
  recorded.stack_pointer = stack_pointer;
  project_.add_region(std::move(recorded));
  save_project();

  return true;
}

std::vector<std::string> Session::available_specs() const {
  std::vector<std::string> found;

  std::error_code ignored;
  if (!std::filesystem::is_directory(spec_dir_, ignored))
    return found;

  for (const auto &entry : std::filesystem::directory_iterator(spec_dir_)) {
    if (entry.path().extension() == ".sla")
      found.push_back(entry.path().stem().string());
  }

  std::sort(found.begin(), found.end());
  return found;
}

void Session::apply_project() {
  for (const auto &range : project_.data_ranges())
    image_->mark_data(range.first, range.second);

  // Everything someone marked out by hand goes back into the tree. Order
  // matters only in that a mark inside another has to be added after it, and
  // the tree works that out from the extents.
  for (const Project::Mark &mark : project_.marks())
    tree_.set_user_defined(
        tree_.add(mark.begin, mark.end - mark.begin, mark.kind, mark.name),
        true);

  for (const Project::RegionSpec &region : project_.regions()) {
    // Already there if the command line named the same stretch.
    bool known = false;
    for (const Region &existing : regions_)
      known = known || (existing.begin == region.begin && existing.end == region.end);
    if (known)
      continue;

    add_region(region.begin, region.end, region.spec, region.abi,
               region.stack_pointer);
  }
}

void Session::open_project(std::string path) {
  project_path_ = std::move(path);
  if (!project_path_.empty())
    project_.load(project_path_);
  apply_project();
}

bool Session::save_project() {
  if (project_path_.empty())
    return false;
  return project_.save(project_path_);
}

} // namespace ddd
