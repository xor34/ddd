#include "xrefs.h"

namespace ddd {
namespace {

// What a destination varnode names. A branch or call names the space it goes
// into outright; a constant is a raw value, and reading one as a reference is
// reading it as an address in the space the code itself lives in -- which is
// the only space a flat image address has ever meant.
Addr destination(const Cfg &cfg, const Varnode &vn) {
  if (is_constant(vn))
    return {cfg.code_space, vn.offset};
  return {vn.space, vn.offset};
}

} // namespace

void Xrefs::add(const Cfg &cfg, const std::string &function, uint64_t first,
                uint64_t last, uint64_t inside_begin, uint64_t inside_end) {
  if (inside_end <= inside_begin) {
    inside_begin = cfg.code_begin;
    inside_end = cfg.code_end;
  }

  auto record = [&](uint64_t from, const Addr &to, const char *kind) {
    Xref xref;
    xref.from = from;
    xref.to = to;
    xref.kind = kind;
    xref.in = function;
    incoming_[to].push_back(std::move(xref));
    ++count_;
  };

  for (const BasicBlock &block : cfg.blocks) {
    for (const PcodeOp &op : block.ops) {
      const uint64_t from = op.addr;
      if (from < first || from >= last)
        continue;

      switch (op.opc) {
      case Op::CALL:
        if (!op.inputs.empty())
          record(from, destination(cfg, op.inputs[0]), "call");
        break;

      case Op::BRANCH:
      case Op::CBRANCH: {
        // Only branches leaving this function are worth indexing; the ones
        // inside it are the control flow the listing already draws. Leaving
        // means leaving the swept range *in the space it was swept in* -- the
        // same offset in another space is a different place, and is worth
        // indexing even when the offset happens to fall inside it.
        if (op.inputs.empty() || is_constant(op.inputs[0]))
          break; // p-code-relative: an intra-instruction branch, which cannot leave
        const Addr to = destination(cfg, op.inputs[0]);
        if (to.space == cfg.code_space && to.offset >= inside_begin &&
            to.offset < inside_end)
          break;
        record(from, to, "branch");
        break;
      }

      default:
        // A constant that is an address of anything is a reference: a string,
        // a table, a function pointer. Which of those it is, the caller
        // decides by looking at what lives there.
        for (const Varnode &in : op.inputs)
          if (is_constant(in) && in.offset != 0)
            record(from, destination(cfg, in), "data");
        break;
      }
    }
  }
}

void Xrefs::forget(uint64_t begin, uint64_t end) {
  if (end <= begin)
    return;

  // By `from`, which is not what this is keyed by: what a stretch of bytes
  // refers to is scattered across the map, one entry per thing referred to.
  // The alternative is a second index kept in step for the sake of an
  // operation that happens when somebody presses a key, so this walks.
  for (auto entry = incoming_.begin(); entry != incoming_.end();) {
    std::vector<Xref> &refs = entry->second;

    for (auto ref = refs.begin(); ref != refs.end();) {
      if (ref->from >= begin && ref->from < end) {
        ref = refs.erase(ref);
        --count_;
      } else {
        ++ref;
      }
    }

    entry = refs.empty() ? incoming_.erase(entry) : std::next(entry);
  }
}

std::vector<Addr> Xrefs::call_targets() const {
  std::vector<Addr> targets;

  // incoming_ is ordered, so this comes out sorted without sorting it.
  for (const auto &entry : incoming_) {
    for (const Xref &xref : entry.second) {
      if (xref.kind != "call")
        continue;
      targets.push_back(entry.first);
      break;
    }
  }

  return targets;
}

const std::vector<Xref> &Xrefs::to(const Addr &address) const {
  static const std::vector<Xref> none;
  auto it = incoming_.find(address);
  return it == incoming_.end() ? none : it->second;
}

} // namespace ddd
