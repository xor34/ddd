#include "decode/target.h"
#include "base/text.h"

#include "error.hh"
#include "globalcontext.hh"
#include "sleigh.hh"

#include <filesystem>
#include <iostream>
#include <sstream>

namespace ddd {
namespace {

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

// A context database that remembers what the spec asked it to hold.
//
// Which context variables a spec has is not a question Sleigh answers: the
// names live in the .sla and the database keeps them privately. But it is told
// each one as the spec is read -- that is what registerVariable is -- so
// listening is enough, and an interface can then offer `longMode` and
// `addrsize` by name instead of expecting them to be known already.
class RecordingContext final : public ghidra::ContextInternal {
public:
  void registerVariable(const std::string &name, ghidra::int4 sbit,
                        ghidra::int4 ebit) override {
    ghidra::ContextInternal::registerVariable(name, sbit, ebit);
    names_.push_back(name);
  }

  const std::vector<std::string> &names() const { return names_; }

private:
  std::vector<std::string> names_;
};

} // namespace

struct TargetSet::Instance {
  std::string spec;
  std::vector<std::string> context;
  std::unique_ptr<RecordingContext> ghidra_context;
  std::unique_ptr<ghidra::Sleigh> sleigh;
};

// One worker's private set: a copy of every instance, and a decode-only view
// of every Target pointing into the copy rather than the original.
struct TargetSet::Worker {
  std::vector<std::unique_ptr<Instance>> instances; // as instances_
  std::deque<Target> views;                         // as targets_
};

TargetSet::TargetSet(const Image &image)
    : loader_(std::make_unique<ImageLoader>(image)) {
  // Sized once, so that publishing a worker never moves one another thread is
  // already reading. Slot zero is the caller's own, and has no entry.
  workers_.resize(kMaxWorkers - 1);
}

TargetSet::~TargetSet() {
  {
    std::lock_guard<std::mutex> lock(state_);
    stopping_ = true;
  }
  wake_.notify_all();
  if (warming_.joinable())
    warming_.join();
}

// Reading a spec, which is the expensive half of acquiring a target and the
// half a worker has to repeat.
std::unique_ptr<TargetSet::Instance>
TargetSet::load(const std::string &spec,
                const std::vector<std::string> &context) {
  auto instance = std::make_unique<Instance>();
  instance->spec = spec;
  instance->context = context;
  instance->ghidra_context = std::make_unique<RecordingContext>();
  instance->sleigh = std::make_unique<ghidra::Sleigh>(
      loader_.get(), instance->ghidra_context.get());

  std::string absolute = std::filesystem::absolute(spec).string();
  std::istringstream wrapper("<sleigh>" + absolute + "</sleigh>");

  // Sleigh's XML reader is not reentrant -- the scanner and the content
  // handler are file-scope globals in xml.cc -- so however many threads are
  // asking, exactly one document is read at a time.
  std::lock_guard<std::mutex> lock(loading_);

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

  return instance;
}

TargetSet::Instance *
TargetSet::instance_for(const std::string &spec,
                        const std::vector<std::string> &context) {
  for (const std::unique_ptr<Instance> &instance : instances_)
    if (instance->spec == spec && instance->context == context)
      return instance.get();

  std::unique_ptr<Instance> instance = load(spec, context);
  if (instance == nullptr)
    return nullptr;

  instances_.push_back(std::move(instance));
  return instances_.back().get();
}

// ---- decoding on more than one thread -----------------------------------

void TargetSet::warm(int workers) {
  if (workers > kMaxWorkers)
    workers = kMaxWorkers;

  {
    std::lock_guard<std::mutex> lock(state_);
    if (workers <= wanted_)
      return;
    wanted_ = workers;

    // Started on the first ask rather than in the constructor: a run that only
    // prints one function never wants a copy of anything, and should not pay
    // for a thread to decide that.
    if (!warming_.joinable())
      warming_ = std::thread([this] { build_workers(); });
  }

  wake_.notify_all();
}

// The warming thread, from here to the end of the process.
//
// One slot at a time, in order, publishing each before starting the next --
// which is what lets the analysis widen as they arrive instead of waiting for
// the last one.
void TargetSet::build_workers() {
  while (true) {
    std::vector<std::pair<std::string, std::vector<std::string>>> specs;
    std::vector<Target> shape;
    int slot = 0;

    {
      std::unique_lock<std::mutex> lock(state_);
      wake_.wait(lock, [this] {
        return stopping_ || ready_.load(std::memory_order_relaxed) < wanted_;
      });
      if (stopping_)
        return;

      slot = ready_.load(std::memory_order_relaxed);
      for (const std::unique_ptr<Instance> &instance : instances_)
        specs.emplace_back(instance->spec, instance->context);
      shape.assign(targets_.begin(), targets_.end());
    }

    auto worker = std::make_unique<Worker>();
    for (const auto &[spec, context] : specs) {
      std::unique_ptr<Instance> instance = load(spec, context);
      if (instance == nullptr) {
        // A spec that loaded once and will not load again is not something to
        // keep retrying on a thread nobody is watching.
        std::lock_guard<std::mutex> lock(state_);
        wanted_ = ready_.load(std::memory_order_relaxed);
        worker.reset();
        break;
      }
      worker->instances.push_back(std::move(instance));
    }
    if (worker == nullptr)
      continue;

    // A view per Target, pointing into this worker's copy of whichever
    // instance the original was made from.
    for (const Target &original : shape) {
      Target view = original;
      view.decode_only = true;
      view.translator = nullptr;
      // Nothing a sweep needs, and everything that would mislead anything
      // else: a worker's translator is this worker's own, and the pipeline
      // should read conventions and register names from the original. See
      // the comment on Target::decode_only.
      view.abi = nullptr;
      view.stack_pointer = Varnode{};

      for (size_t i = 0; i < specs.size(); ++i) {
        if (specs[i].first != original.spec || specs[i].second != original.context)
          continue;
        view.translator = worker->instances[i]->sleigh.get();
        break;
      }
      worker->views.push_back(std::move(view));
    }

    std::lock_guard<std::mutex> lock(state_);

    // Something was acquired while this was being built, so the slot does not
    // cover everything after all. Build it again against what is there now.
    if (specs.size() != instances_.size() || shape.size() != targets_.size())
      continue;
    if (slot != ready_.load(std::memory_order_relaxed) || slot >= kMaxWorkers)
      continue;

    workers_[static_cast<size_t>(slot) - 1] = std::move(worker);
    ready_.store(slot + 1, std::memory_order_release);
  }
}

Target *TargetSet::decoder(Target &target, int slot) {
  if (slot <= 0)
    return &target;
  if (slot >= ready_.load(std::memory_order_acquire))
    return nullptr;

  Worker *worker = workers_[static_cast<size_t>(slot) - 1].get();
  if (worker == nullptr)
    return nullptr;

  // Which Target this is, by where it sits: the views were built from the same
  // sequence, so the answer is the same index.
  size_t index = 0;
  for (const Target &candidate : targets_) {
    if (&candidate == &target)
      return index < worker->views.size() ? &worker->views[index] : nullptr;
    ++index;
  }
  return nullptr;
}

int TargetSet::instance_count() const {
  std::lock_guard<std::mutex> lock(state_);
  int count = static_cast<int>(instances_.size());
  for (const std::unique_ptr<Worker> &worker : workers_)
    if (worker != nullptr)
      count += static_cast<int>(worker->instances.size());
  return count;
}

Target *TargetSet::acquire(const std::string &spec, const std::string &abi,
                           const std::string &stack_pointer,
                           const std::vector<std::string> &context,
                           const std::string &name) {
  // Only fall back to the spec's implied mode when the caller named none:
  // an explicit context is the whole point of a mode switch and must win.
  const std::vector<std::string> effective =
      context.empty() ? default_context(spec) : context;

  // Held across the whole of this: what the warming thread copies is
  // `instances_` and `targets_`, and a worker is only usable when it covers
  // all of both.
  std::lock_guard<std::mutex> lock(state_);

  Instance *instance = instance_for(spec, effective);
  if (instance == nullptr)
    return nullptr;

  Target target;
  target.spec = spec;
  target.context = effective;
  target.context_variables = instance->ghidra_context->names();
  target.translator = instance->sleigh.get();
  target.spaces = &spaces_;
  target.code_space = spaces_.intern(
      target.translator->getDefaultCodeSpace()->getName(), SpaceKind::Other);

  target.abi = abi.empty() ? guess_convention(*target.translator, spaces_)
                           : find_convention(abi);
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
    target.stack_pointer = register_storage(*target.translator, spaces_, sp);
    if (target.stack_pointer.space == kNoSpace)
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

  // A target the workers were not built to cover. They go back to being
  // unusable until the warming thread has caught up, rather than one of them
  // decoding through an instance another thread is already inside.
  ready_.store(1, std::memory_order_release);
  wake_.notify_all();

  return &targets_.back();
}

uint32_t Target::pointer_size() const {
  if (translator == nullptr)
    return 0;
  return translator->getDefaultCodeSpace()->getAddrSize();
}

bool parse_region(const std::string &text, TargetSet &targets,
                  const std::string &spec_dir, ImageRange &out) {
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

  out.kind = ImageRangeKind::Code;
  out.name = out.target->name;
  return true;
}

} // namespace ddd
