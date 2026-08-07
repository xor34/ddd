#include "target.h"

#include "error.hh"
#include "globalcontext.hh"
#include "sleigh.hh"

#include <filesystem>
#include <iostream>
#include <sstream>

namespace ddd {
namespace {

bool parse_number(const std::string &text, uint64_t &out) {
  if (text.empty())
    return false;
  try {
    size_t consumed = 0;
    int base = (text.size() > 2 && text[0] == '0' &&
                (text[1] == 'x' || text[1] == 'X'))
                   ? 16
                   : 10;
    out = std::stoull(text, &consumed, base);
    return consumed == text.size();
  } catch (...) {
    return false;
  }
}

bool ends_with(const std::string &text, const std::string &suffix) {
  return text.size() >= suffix.size() &&
         text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::vector<std::string> split(const std::string &text, char separator) {
  std::vector<std::string> parts;
  std::istringstream stream(text);
  std::string part;
  while (std::getline(stream, part, separator))
    parts.push_back(part);
  return parts;
}

} // namespace

struct TargetSet::Instance {
  std::string spec;
  std::vector<std::string> context;
  std::unique_ptr<ghidra::ContextInternal> ghidra_context;
  std::unique_ptr<ghidra::Sleigh> sleigh;
};

TargetSet::TargetSet(const Image &image)
    : image_(image), loader_(std::make_unique<ImageLoader>(image)) {}

TargetSet::~TargetSet() = default;

TargetSet::Instance *
TargetSet::instance_for(const std::string &spec,
                        const std::vector<std::string> &context) {
  for (const std::unique_ptr<Instance> &instance : instances_)
    if (instance->spec == spec && instance->context == context)
      return instance.get();

  auto instance = std::make_unique<Instance>();
  instance->spec = spec;
  instance->context = context;
  instance->ghidra_context = std::make_unique<ghidra::ContextInternal>();
  instance->sleigh = std::make_unique<ghidra::Sleigh>(
      loader_.get(), instance->ghidra_context.get());

  std::string absolute = std::filesystem::absolute(spec).string();
  std::istringstream wrapper("<sleigh>" + absolute + "</sleigh>");

  ghidra::DocumentStorage storage;
  try {
    storage.registerTag(storage.parseDocument(wrapper)->getRoot());
    instance->sleigh->initialize(storage);
  } catch (ghidra::DecoderError &error) {
    std::cerr << "cannot read spec " << spec << ": " << error.explain << '\n';
    return nullptr;
  } catch (ghidra::LowlevelError &error) {
    std::cerr << "cannot load spec " << spec << ": " << error.explain << '\n';
    return nullptr;
  }

  // Context variables select the decoding mode -- this is what makes one
  // spec able to serve, say, both real-mode and long-mode x86.
  for (const std::string &setting : context) {
    std::vector<std::string> parts = split(setting, '=');
    uint64_t value = 0;
    if (parts.size() != 2 || !parse_number(parts[1], value)) {
      std::cerr << "bad context setting: " << setting << '\n';
      continue;
    }
    try {
      instance->ghidra_context->setVariableDefault(parts[0], value);
    } catch (ghidra::LowlevelError &error) {
      std::cerr << "unknown context variable " << parts[0] << ": "
                << error.explain << '\n';
    }
  }

  instances_.push_back(std::move(instance));
  return instances_.back().get();
}

Target *TargetSet::acquire(const std::string &spec, const std::string &abi,
                           const std::string &stack_pointer,
                           const std::vector<std::string> &context,
                           const std::string &name) {
  // Only fall back to the spec's implied mode when the caller named none:
  // an explicit context is the whole point of a mode switch and must win.
  const std::vector<std::string> effective =
      context.empty() ? default_context(spec) : context;

  Instance *instance = instance_for(spec, effective);
  if (instance == nullptr)
    return nullptr;

  Target target;
  target.spec = spec;
  target.context = effective;
  target.translator = instance->sleigh.get();

  target.abi =
      abi.empty() ? guess_convention(*target.translator) : find_convention(abi);
  if (!abi.empty() && target.abi == nullptr) {
    std::cerr << "unknown abi: " << abi << "\n  known:";
    for (const CallingConvention &c : conventions())
      std::cerr << ' ' << c.name;
    std::cerr << '\n';
  }

  std::string sp = stack_pointer;
  if (sp.empty() && target.abi != nullptr)
    sp = target.abi->stack_pointer;
  if (!sp.empty()) {
    target.stack_pointer = register_storage(*target.translator, sp);
    if (target.stack_pointer.space == nullptr)
      std::cerr << "no such register: " << sp << '\n';
  }

  if (!name.empty()) {
    target.name = name;
  } else {
    target.name = std::filesystem::path(spec).stem().string();
    if (!context.empty())
      target.name += ":" + context.front();
  }

  targets_.push_back(std::move(target));
  return &targets_.back();
}

bool parse_region(const std::string &text, TargetSet &targets,
                  const std::string &spec_dir, Region &out) {
  std::vector<std::string> parts = split(text, ':');
  if (parts.size() < 3) {
    std::cerr << "bad region (want BEGIN:END:SPEC[:ABI[:SP[:CTX]]]): " << text
              << '\n';
    return false;
  }

  if (!parse_number(parts[0], out.begin) || !parse_number(parts[1], out.end)) {
    std::cerr << "bad region bounds: " << text << '\n';
    return false;
  }
  if (out.end <= out.begin) {
    std::cerr << "empty region: " << text << '\n';
    return false;
  }

  // A bare name is resolved in the specs directory; a path is taken as given.
  std::string spec = parts[2];
  if (!ends_with(spec, ".sla"))
    spec = (std::filesystem::path(spec_dir) / (spec + ".sla")).string();

  const std::string abi = parts.size() > 3 ? parts[3] : "";
  const std::string sp = parts.size() > 4 ? parts[4] : "";

  std::vector<std::string> context;
  if (parts.size() > 5 && !parts[5].empty())
    context = split(parts[5], '+');

  out.target = targets.acquire(spec, abi, sp, context);
  if (out.target == nullptr)
    return false;

  out.kind = RegionKind::Code;
  out.name = out.target->name;
  return true;
}

} // namespace ddd
