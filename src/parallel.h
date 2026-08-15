// parallel.h -- a fixed set of worker threads, and a loop over a batch.
//
// One pool, made once and kept, because the work this is for arrives as a long
// run of small batches -- a slice of the image, then the next -- and starting a
// thread per batch would cost more than the batch.
//
// The loop hands each item an index and a *slot*: a number in [0, workers)
// that is the caller's to key per-thread resources on. That is the whole
// synchronisation strategy here. Nothing in this library locks around the
// things a sweep touches; instead each slot gets its own decoder, and the
// results are merged afterwards, in item order, by the thread that asked. The
// order matters: an index built by threads has to come out in the same order
// as one built without them, or the analysis stops being reproducible and the
// tests stop meaning anything.
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace ddd {

// What to use when nobody said. Bounded well below a big machine's core count
// on purpose: every worker holds a decoder of its own, and those are tens of
// megabytes each, so the last few threads buy less than they cost.
int default_thread_count();

class Pool {
public:
  // `workers` counts the calling thread, which works too -- so a pool of one
  // starts no threads at all and runs everything inline. Values below one are
  // read as one.
  explicit Pool(int workers);
  ~Pool();

  Pool(const Pool &) = delete;
  Pool &operator=(const Pool &) = delete;

  int workers() const { return workers_; }

  // Runs `body(index, slot)` for every index below `count` and returns when
  // all of them have finished. Items are claimed rather than dealt out, since
  // what this runs -- lifting a function, sweeping a slice -- varies by an
  // order of magnitude between one item and the next.
  //
  // `slots` caps which slots take part: with three, the batch runs on slots 0,
  // 1 and 2 however many threads the pool has. That is for a caller whose
  // per-slot resource is not ready for all of them yet -- it can use what it
  // has without the others touching what they have not got. Zero means all.
  //
  // An exception thrown by `body` stops the batch being abandoned quietly: the
  // first one is re-thrown here, on the calling thread, once the others have
  // stopped.
  void run(size_t count, const std::function<void(size_t index, int slot)> &body,
           int slots = 0);

private:
  void loop(int slot);
  void claim(int slot);

  int workers_ = 1;
  std::vector<std::thread> threads_;

  std::mutex mutex_;
  std::condition_variable ready_;
  std::condition_variable done_;

  const std::function<void(size_t, int)> *body_ = nullptr;
  size_t count_ = 0;
  int slots_ = 0;
  std::atomic<size_t> next_{0};
  size_t running_ = 0;
  uint64_t generation_ = 0;
  bool stopping_ = false;
  std::exception_ptr failure_;
};

} // namespace ddd
