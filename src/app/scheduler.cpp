// scheduler.cpp -- the two whole-image sweeps, a slice at a time, on as many
// threads as they can have.
//
// An interface that calls a sweep has no window until it returns. Two things
// are done about that, and they are not alternatives: the work yields, and the
// work is spread.
//
// *Yielding* is what keeps the window answering. Each call does a bounded
// amount of work and says where it got to; a caller runs it until `finished`,
// on an idle handler, and stays answerable in between. That is still true with
// threads: a step fans its slice out, joins, and returns.
//
// *Spreading* is what makes the work finish. Both stages are a decode and
// nothing else, and every answer either produces is an address. Addresses are
// integers, so the results merge whichever thread found them, in the order the
// batch went out, which is what keeps the index and the function list identical
// to the ones a single thread would have built.
//
// The boundaries are fixed, and derived from neither the number of threads nor
// the caller's budget, because they decide where one sweep stops and the next
// begins. A boundary that moved with the machine, or with whether a window or a
// script was asking, would move which instructions were decoded from where --
// and an index that differs run to run is one that cannot be tested and cannot
// be trusted. What the budget decides is only how many chunks one call does.
#include "app/session.h"

#include <algorithm>
#include <memory>

namespace ddd {
namespace {

// The grid the reference index is swept on.
constexpr uint64_t kIndexChunk = 8192;

// Below this much code, threads are not worth a copy of the decoder each --
// the copy takes longer to read than the sweep takes to run.
constexpr uint64_t kThreadsFrom = 128 * 1024;

} // namespace

// How many threads this step gets, and asking for what they need.
//
// Auto only turns them on for an image with enough code in it to be worth a
// decoder per thread; an explicit --threads is taken as meant. Either way the
// answer is bounded by how many copies of the decoder have actually been read
// so far, which is what lets the first steps run while the rest are loading.
int Session::analysis_threads() {
  int wanted = threads_;
  if (wanted == 0) {
    uint64_t code = 0;
    for (const ImageRange &region : regions_)
      if (region.target != nullptr && region.end > region.begin)
        code += region.end - region.begin;
    wanted = code >= kThreadsFrom ? default_thread_count() : 1;
  }

  wanted = std::max(1, std::min(wanted, TargetSet::kMaxWorkers));
  if (wanted == 1)
    return 1;

  targets_->warm(wanted);
  if (pool_ == nullptr)
    pool_ = std::make_unique<Pool>(wanted);

  const int usable = std::min(wanted, targets_->ready_workers());
  if (usable > announced_threads_) {
    announced_threads_ = usable;
    log() << "sweeping on " << usable << " thread(s)\n";
  }
  return usable;
}

void Session::in_parallel(
    size_t count, const std::function<void(size_t index, int slot)> &body) {
  const int slots = analysis_threads();
  if (pool_ == nullptr || slots == 1) {
    for (size_t index = 0; index < count; ++index)
      body(index, 0);
    return;
  }
  pool_->run(count, body, slots);
}

Session::AnalysisStep Session::analyse_step(int budget) {
  AnalysisStep step;
  const int slots = analysis_threads();
  step.threads = slots;

  if (xrefs_ == nullptr && pending_xrefs_ == nullptr) {
    pending_xrefs_ = std::make_unique<Xrefs>();
    index_region_ = 0;
    index_at_ = 0;
    indexed_ = false;
  }

  // Stage one: index the references, a slice of the image at a time, each
  // slice cut into chunks that go out to the threads together.
  //
  // The chunks are a fixed grid over the region, so a chunk covers the same
  // bytes whoever sweeps it and however many are sweeping. What the budget
  // decides is only how many of them one call does -- which is the yielding,
  // and is why a window can ask for a frame's worth and a script for a
  // hundred times that.
  if (!indexed_) {
    step.stage = "references";

    while (index_region_ < regions_.size()) {
      const ImageRange &region = regions_[index_region_];
      const uint64_t from = index_at_ != 0 ? index_at_ : region.begin;

      if (region.target == nullptr || from >= region.end) {
        ++index_region_;
        index_at_ = 0;
        continue;
      }

      // At least one chunk per thread, so none of them stands idle, and more
      // when the caller asked for more. `budget` is in instructions and this
      // is in bytes: eight is a generous instruction.
      const uint64_t asked = (static_cast<uint64_t>(std::max(1, budget)) * 8 +
                              kIndexChunk - 1) / kIndexChunk;
      const uint64_t left =
          (region.end - from + kIndexChunk - 1) / kIndexChunk;
      const size_t chunks = static_cast<size_t>(
          std::min(left, std::max<uint64_t>(asked, static_cast<uint64_t>(slots))));

      // The chunks are a multiple of every alignment there is, so on an
      // aligned instruction set each of them already begins where an
      // instruction does and `resync_from` hands back its own start.
      std::vector<std::unique_ptr<Lifted>> swept(chunks);
      in_parallel(chunks, [&](size_t index, int slot) {
        const uint64_t begin = from + index * kIndexChunk;
        const uint64_t end = std::min(begin + kIndexChunk, region.end);
        const uint64_t at = resync_from(region, begin);

        ImageRange chunk = region;
        chunk.begin = at;
        chunk.end = end;
        chunk.target = targets_->decoder(*region.target, slot);
        if (chunk.target == nullptr)
          chunk.target = region.target; // only slot zero, and that is its own

        // One instruction per byte is the most there can be, so this cannot
        // cut the chunk short; the end address is what bounds it.
        swept[index] = lift(chunk, at, static_cast<int>(end - at), image_,
                            /*disassemble=*/false);
      });

      // Merged in chunk order, on this thread: the index is a list per address
      // and the order things were found in is the order they are shown in.
      uint64_t next = from;
      for (size_t index = 0; index < chunks; ++index) {
        const uint64_t begin = from + index * kIndexChunk;
        const uint64_t end = std::min(begin + kIndexChunk, region.end);
        next = end;

        if (swept[index] == nullptr)
          continue;
        // Only what this chunk is responsible for -- the run-up decoded the
        // bytes before it to get in step, not to report them -- and "inside"
        // is the region, not the chunk, or every branch across a boundary
        // would look like one leaving.
        pending_xrefs_->add(swept[index]->cfg, "", begin, end, region.begin,
                            region.end);
      }

      index_at_ = next;
      step.done = index_at_ - region.begin;
      step.total = region.end - region.begin;
      return step;
    }

    // Finished: the new index replaces the old one in one step, so nothing
    // ever sees a half-built one.
    indexed_ = true;
    xrefs_ = std::move(pending_xrefs_);

    log() << xrefs_->size() << " reference(s)\n";
    collect_starts();
    step.done = 0;
    step.total = starts_.size();
    return step;
  }

  // Stage two: bound each candidate. One lift each, and they know nothing
  // about each other, so a batch of them is the easiest thing here to spread
  // -- what comes back is recorded in the order it went out.
  if (!discovered_) {
    step.stage = "functions";
    step.total = starts_.size();

    const size_t count =
        std::min<size_t>(static_cast<size_t>(8) * slots,
                         starts_.size() - start_at_);

    std::vector<Bounded> bounded(count);
    in_parallel(count, [&](size_t index, int slot) {
      bounded[index] = bound_start(start_at_ + index, slot);
    });

    for (const Bounded &one : bounded)
      if (one.ok) {
        define_function(one.address, one.end, one.name);
        bounded_.insert(one.address);
      }
    start_at_ += count;

    step.done = start_at_;
    if (start_at_ < starts_.size())
      return step;

    discovered_ = true;
    log() << found_.size() << " function(s) found\n";
  }

  step.stage = "done";
  step.done = found_.size();
  step.total = found_.size();
  step.finished = true;
  return step;
}

} // namespace ddd
