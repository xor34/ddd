// session.cpp -- one loaded image: what it is, what is in it, and where.
//
// The front ends -- the JSON server, the Lua interfaces, the batch listing --
// want the same handful of answers, and they are answered in structures. A
// front end formats them: the server as JSON, a Lua plugin as tables, the
// terminal as text. Nothing here knows which.
//
// This file holds the session itself: construction, the regions and the specs
// they are read with, mapping in more files, reading data and hex out of the
// image, and what the project remembers. The rest of the class is elsewhere,
// one file per job, all of them sharing session.h:
//
//   discovery.cpp     where the functions are, in a file that does not say
//   index.cpp         what refers to what, and repairing that after an edit
//   scheduler.cpp     those two sweeps, a slice at a time, on threads
//   region_edit.cpp   saying a stretch is code, or data, or neither
//   listing.cpp       naming a place, and showing what is there
//
// The two primitives every sweep is built on -- `lift` and `resync_from` -- are
// here, because everything above uses them and they belong to no one of them.
#include "app/session.h"

#include "extract/extract.h"

#include "sleigh.hh"

#include <algorithm>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>

namespace ddd {
namespace {

// How far before its chunk a sweep starts.
//
// x86 recovers within a few bytes. See `resync_from` for what this is for.
constexpr uint64_t kResync = 64;

// Whole file, as bytes. Nothing here knows or cares what format it is: an
// object mapped into an image at an address is bytes at an address, and a
// header that says otherwise is the loader's business, not this one's.
std::vector<uint8_t> read_object(const std::string &path, bool &ok) {
  std::ifstream file(path, std::ios::binary);
  ok = static_cast<bool>(file);
  if (!ok)
    return {};

  return std::vector<uint8_t>(std::istreambuf_iterator<char>(file),
                              std::istreambuf_iterator<char>());
}

} // namespace

std::unique_ptr<Lifted> lift(const ImageRange &region, uint64_t entry,
                             int max_instructions, const Image *image,
                             bool disassemble) {
  if (region.target == nullptr || region.target->translator == nullptr)
    return nullptr;

  ghidra::Sleigh &translator = *region.target->translator;
  const uint64_t start = entry != 0 ? entry : region.begin;

  SweepLimits limits;
  limits.max_instructions = max_instructions;
  limits.disassemble = disassemble;
  limits.end = region.end;

  // What somebody said is not code stops the sweep, so that saying it has an
  // effect on the listing rather than only on a side table.
  if (image != nullptr) {
    limits.is_data = [image](uint64_t address) {
      return image->marked_data(address);
    };
  }

  auto lifted = std::make_unique<Lifted>();
  lifted->region = region;
  lifted->cfg = build_cfg(translator, start, *region.target->spaces, limits);
  return lifted->cfg.empty() ? nullptr : std::move(lifted);
}

uint64_t resync_from(const ImageRange &region, uint64_t from) {
  if (region.target == nullptr || region.target->translator == nullptr)
    return from;

  // An aligned instruction set needs no run-up: a chunk boundary that is a
  // multiple of the alignment already is an instruction boundary.
  if (region.target->translator->getAlignment() > 1)
    return from;

  return from > region.begin ? std::max(region.begin, from - kResync) : from;
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

void Session::set_regions(std::vector<ImageRange> regions) {
  regions_ = std::move(regions);
  if (!regions_.empty())
    prototype_ = regions_.front();

  // The instruction-set regions are the top level of the tree: everything
  // else -- a function, a block, a jump table -- is inside one of them, and
  // inherits what it is written in from the one it is inside.
  for (size_t i = 0; i < regions_.size(); ++i) {
    const ImageRange &region = regions_[i];
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

DataView Session::data(uint64_t address, uint64_t count) {
  DataView view;
  view.addr = address;
  view.code = image_->is_code(address);

  if (count == 0 || count > 512)
    count = 64;

  // Whatever references are already indexed; this does not wait for the sweep
  // that would find the rest, so opening a data view is instant.
  //
  // Pointer width decides the natural item size: a literal pool on a 32-bit
  // target is words, on a 64-bit one it is doublewords.
  unsigned word = prototype_.target == nullptr
                      ? 0
                      : prototype_.target->pointer_size();
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

  // No small ceiling: a listing that shows a data region shows all of it, and
  // the caller has already decided how much that is. Reads stop at the edge of
  // the image regardless.
  if (length == 0)
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

bool Session::load_object(const std::string &path, uint64_t at,
                          const std::string &spec, const std::string &abi,
                          const std::string &stack_pointer) {
  bool ok = false;
  const std::vector<uint8_t> bytes = read_object(path, ok);
  if (!ok || bytes.empty())
    return false;

  // Below the base would move every address in the image, and with them every
  // note anybody has taken about one.
  if (!image_->map(at, bytes))
    return false;

  // An object is a stretch of code until something says otherwise, and it has
  // to be one for anything to disassemble it: regions are what carry the
  // instruction set. The one the rest of the image uses is the default, since
  // two objects of the same firmware are usually the same machine.
  std::string wanted = spec;
  if (wanted.empty() && prototype_.target != nullptr)
    wanted = prototype_.target->name;

  if (!add_region(at, at + bytes.size(), wanted, abi, stack_pointer))
    return false;

  // Recorded, so that opening the project again opens the same image rather
  // than a region of zeroes where the second file used to be.
  project_.add_object(Project::Object{path, at});
  save_project();

  log() << "mapped " << path << " (" << bytes.size() << " bytes) at 0x"
        << std::hex << at << std::dec << "\n";
  return true;
}

bool Session::add_region(uint64_t begin, uint64_t end, const std::string &spec,
                         const std::string &abi,
                         const std::string &stack_pointer,
                         const std::vector<std::string> &context) {
  if (end <= begin || targets_ == nullptr)
    return false;

  const std::string path =
      spec.size() >= 4 && spec.compare(spec.size() - 4, 4, ".sla") == 0
          ? spec
          : spec_dir_ + "/" + spec + ".sla";

  Target *target = targets_->acquire(path, abi, stack_pointer, context);
  if (target == nullptr)
    return false;

  ImageRange region;
  region.begin = begin;
  region.end = end;
  region.kind = ImageRangeKind::Code;
  region.target = target;
  region.name = target->name;
  regions_.push_back(region);
  if (prototype_.target == nullptr)
    prototype_ = region;

  // A new stretch of code is new places to find functions and new references.
  discovered_ = false;
  invalidate_index();

  Project::RegionSpec recorded;
  recorded.begin = begin;
  recorded.end = end;
  recorded.spec = spec;
  recorded.abi = abi;
  recorded.stack_pointer = stack_pointer;
  recorded.context = context;
  project_.add_region(std::move(recorded));
  save_project();

  return true;
}

std::vector<Session::SpecGuess> Session::detect_specs(int limit) {
  std::vector<SpecGuess> found;
  if (image_ == nullptr || image_->empty())
    return found;

  ExtractContext ctx;
  ctx.spec_dir = spec_dir_;
  ctx.out = log_;

  for (const Finding &finding : extract(*image_, ctx, {"arch-detect"})) {
    if (finding.suggested_spec.empty())
      continue;

    found.push_back(
        SpecGuess{finding.suggested_spec, finding.confidence, finding.detail});
    if (static_cast<int>(found.size()) >= limit)
      break;
  }

  return found;
}

bool Session::retarget(uint64_t begin, const std::string &spec,
                       const std::vector<std::string> &context,
                       const std::string &abi,
                       const std::string &stack_pointer) {
  if (targets_ == nullptr || regions_.empty())
    return false;

  const std::string path =
      spec.size() >= 4 && spec.compare(spec.size() - 4, 4, ".sla") == 0
          ? spec
          : spec_dir_ + "/" + spec + ".sla";

  Target *target = targets_->acquire(path, abi, stack_pointer, context);
  if (target == nullptr)
    return false;

  bool changed = false;
  for (ImageRange &region : regions_) {
    if (region.kind != ImageRangeKind::Code)
      continue;
    if (begin != 0 && !(begin >= region.begin && begin < region.end))
      continue;

    region.target = target;
    region.name = target->name;
    changed = true;

    Project::RegionSpec recorded;
    recorded.begin = region.begin;
    recorded.end = region.end;
    recorded.spec = spec;
    recorded.abi = abi;
    recorded.stack_pointer = stack_pointer;
    recorded.context = context;
    project_.add_region(std::move(recorded));
  }

  if (!changed)
    return false;

  prototype_ = regions_.front();

  // Everything known about these bytes was worked out by reading them the
  // other way: the functions, the references, the extents. None of it survives
  // being told the instruction set was wrong.
  found_.clear();
  bounded_.clear();
  starts_.clear();
  discovered_ = false;
  xrefs_.reset();
  invalidate_index();

  save_project();

  log() << "reading as " << std::filesystem::path(path).stem().string();
  if (!context.empty()) {
    log() << " (";
    for (size_t i = 0; i < context.size(); ++i)
      log() << (i ? " " : "") << context[i];
    log() << ")";
  }
  log() << '\n';

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
  if (project_.entry() != 0)
    elf_->entry = project_.entry();

  // The other files first: everything below is about addresses, and half of
  // them are not in the image until the object that holds them is.
  for (const Project::Object &object : project_.objects()) {
    bool ok = false;
    const std::vector<uint8_t> bytes = read_object(object.path, ok);
    if (!ok) {
      log() << "cannot read " << object.path << ", mapped at 0x" << std::hex
            << object.at << std::dec << " by the project\n";
      continue;
    }
    image_->map(object.at, bytes);
  }

  for (const auto &range : project_.data_ranges())
    image_->mark_data(range.first, range.second);

  // Everything someone marked out by hand goes back. Order matters only in
  // that a mark inside another has to be added after it, and the tree works
  // that out from the extents.
  for (const Project::Mark &mark : project_.marks()) {
    // A function is more than a region: it is what the listing is cut up by,
    // so it goes back into the function table as well as the tree.
    if (mark.kind == region_kind::kFunction) {
      define_function(mark.begin, mark.end, mark.name);
      continue;
    }

    tree_.set_user_defined(
        tree_.add(mark.begin, mark.end - mark.begin, mark.kind, mark.name),
        true);
  }

  for (const Project::RegionSpec &region : project_.regions()) {
    // Already there if the command line named the same stretch -- unless the
    // project says to read it differently, which is a decision and outranks
    // whatever the container claimed.
    bool known = false;
    for (const ImageRange &existing : regions_)
      known = known || (existing.begin == region.begin && existing.end == region.end);

    if (known) {
      retarget(region.begin, region.spec, region.context, region.abi,
               region.stack_pointer);
      continue;
    }

    add_region(region.begin, region.end, region.spec, region.abi,
               region.stack_pointer, region.context);
  }
}

std::vector<double> Session::entropy(size_t buckets) const {
  std::vector<double> result;
  if (buckets == 0 || image_->empty())
    return result;

  result.reserve(buckets);
  const uint64_t base = image_->base();
  const uint64_t span = image_->limit() - base;

  for (size_t i = 0; i < buckets; ++i) {
    const uint64_t from = base + span * i / buckets;
    const uint64_t to = base + span * (i + 1) / buckets;

    unsigned counts[256] = {};
    uint64_t total = 0;
    for (uint64_t at = from; at < to; ++at) {
      const uint8_t *byte = image_->at(at);
      if (byte == nullptr)
        break;
      ++counts[*byte];
      ++total;
    }

    if (total == 0) {
      result.push_back(0.0);
      continue;
    }

    double bits = 0.0;
    for (unsigned count : counts) {
      if (count == 0)
        continue;
      const double p = static_cast<double>(count) / static_cast<double>(total);
      bits -= p * std::log2(p);
    }
    result.push_back(bits);
  }

  return result;
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
