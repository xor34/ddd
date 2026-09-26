#include "base/parallel.h"

#include <algorithm>

namespace ddd {

int default_thread_count() {
  const unsigned hardware = std::thread::hardware_concurrency();
  if (hardware == 0)
    return 1;
  return static_cast<int>(std::min<unsigned>(hardware, 8));
}

Pool::Pool(int workers) : workers_(std::max(1, workers)) {
  threads_.reserve(static_cast<size_t>(workers_) - 1);
  for (int slot = 1; slot < workers_; ++slot)
    threads_.emplace_back([this, slot] { loop(slot); });
}

Pool::~Pool() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    stopping_ = true;
  }
  ready_.notify_all();
  for (std::thread &thread : threads_)
    thread.join();
}

void Pool::loop(int slot) {
  uint64_t seen = 0;
  while (true) {
    {
      std::unique_lock<std::mutex> lock(mutex_);
      ready_.wait(lock, [&] { return stopping_ || generation_ != seen; });
      if (stopping_)
        return;
      seen = generation_;
    }

    // A slot the caller has capped out of this batch still has to arrive at
    // the count below, or the batch never finishes.
    if (slots_ == 0 || slot < slots_)
      claim(slot);

    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (--running_ == 0)
        done_.notify_all();
    }
  }
}

// The whole of a worker's work: take the next index until there are none left.
void Pool::claim(int slot) {
  while (true) {
    const size_t index = next_.fetch_add(1);
    if (index >= count_)
      return;

    try {
      (*body_)(index, slot);
    } catch (...) {
      // Whatever went wrong belongs to the thread that asked for the batch,
      // not to a worker nobody is watching. The rest of the batch still runs:
      // stopping it early would leave the caller's results half-filled in a
      // way that depends on timing.
      std::lock_guard<std::mutex> lock(mutex_);
      if (!failure_)
        failure_ = std::current_exception();
    }
  }
}

void Pool::run(size_t count, const std::function<void(size_t, int)> &body,
               int slots) {
  if (count == 0)
    return;

  if (workers_ == 1 || slots == 1) {
    for (size_t index = 0; index < count; ++index)
      body(index, 0);
    return;
  }

  {
    std::lock_guard<std::mutex> lock(mutex_);
    body_ = &body;
    count_ = count;
    slots_ = slots;
    next_.store(0);
    running_ = threads_.size();
    failure_ = nullptr;
    ++generation_;
  }
  ready_.notify_all();

  // The caller is slot zero. Having it work rather than wait is what makes a
  // batch of one item cost what it did before there were any threads.
  claim(0);

  std::exception_ptr failure;
  {
    std::unique_lock<std::mutex> lock(mutex_);
    done_.wait(lock, [&] { return running_ == 0; });
    body_ = nullptr;
    count_ = 0;
    failure = failure_;
    failure_ = nullptr;
  }

  if (failure)
    std::rethrow_exception(failure);
}

} // namespace ddd
