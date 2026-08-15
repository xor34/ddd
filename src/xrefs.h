// xrefs.h -- who refers to what.
//
// The single question an interactive session asks most often, and the one the
// per-function view cannot answer: a listing shows what a function calls, and
// never what calls it. That needs a sweep of everything else.
#pragma once

#include "cfg.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ddd {

struct Xref {
  uint64_t from = 0;   // the instruction that refers
  uint64_t to = 0;     // what it refers to
  std::string kind;    // "call", "branch", "data"
  std::string in;      // the function containing `from`
};

class Xrefs {
public:
  // Adds every reference made by one lifted function.
  //
  // `from`/`to` bound which instructions count. A sweep may have decoded more
  // than it is reporting -- a chunk of the image that started a little way
  // back to be in step by the time it reached its own bytes -- and what it
  // decoded before `from` is somebody else's to report.
  //
  // `inside` is what a branch has to leave to be worth indexing: a branch
  // within it is the control flow the listing already draws. It defaults to
  // what the sweep covered, which is right for a whole function and wrong for
  // a slice of one -- a slice would call every branch across its own edge a
  // reference, and which branches those were would depend on where the slices
  // happened to fall.
  void add(const Cfg &cfg, const std::string &function, uint64_t from = 0,
           uint64_t to = UINT64_MAX, uint64_t inside_begin = 0,
           uint64_t inside_end = 0);

  // References *to* an address, in the order they were found.
  const std::vector<Xref> &to(uint64_t address) const;

  // Everything something calls, in address order. In a stripped binary this is
  // most of what is known about where the functions are: nothing else in the
  // file says so, but a call instruction is evidence that survives stripping.
  std::vector<uint64_t> call_targets() const;

  size_t size() const { return count_; }

private:
  std::map<uint64_t, std::vector<Xref>> incoming_;
  size_t count_ = 0;
};

} // namespace ddd
