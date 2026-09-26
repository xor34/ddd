// liveness -- backward, block-level live-value analysis.
//
// An example of the block engine: the fact is a set of live SSA value ids,
// merge is union, and transform walks one block's ops in reverse.
//
// Phi operands are handled the way SSA requires: a phi operand is live at
// the *end of the matching predecessor*, not at the top of the block holding
// the phi. The transform callback captures the function, so it can look at
// its successors' phis to add those -- the engine itself stays oblivious.
#include "../dataflow.h"
#include "../pass.h"

#include <algorithm>
#include <set>
#include <sstream>

namespace ddd {
namespace {

using LiveSet = std::set<ValueId>;

BlockAnalysis<LiveSet> build_analysis(const SsaFunction &fn) {
  BlockAnalysis<LiveSet> analysis;
  analysis.direction = Direction::Backward;
  analysis.init = [] { return LiveSet{}; };

  analysis.merge = [](const LiveSet &a, const LiveSet &b) {
    LiveSet result = a;
    result.insert(b.begin(), b.end());
    return result;
  };

  analysis.transform = [&fn](const SsaBlock &block, const LiveSet &live_out) {
    LiveSet live = live_out;
    const Cfg &cfg = fn.cfg();

    // Values this block hands to its successors' phis are live on the way out.
    for (const Edge &edge : cfg[block.id].succs) {
      const SsaBlock &succ = fn[edge.target];
      if (succ.phis.empty())
        continue;

      const std::vector<BlockId> &preds = cfg[edge.target].preds;
      for (size_t i = 0; i < preds.size(); ++i) {
        if (preds[i] != block.id)
          continue;
        for (const SsaOp *phi : succ.phis)
          if (phi->ins[i].value != nullptr)
            live.insert(phi->ins[i].value->id);
      }
    }

    for (auto it = block.ops.rbegin(); it != block.ops.rend(); ++it) {
      const SsaOp &op = **it;
      if (op.out != nullptr)
        live.erase(op.out->id);
      for (const SsaOperand &in : op.ins)
        if (in.value != nullptr)
          live.insert(in.value->id);
    }

    // A phi defines at the top of the block; its operands were already
    // accounted for in the predecessors above.
    for (const SsaOp *phi : block.phis)
      if (phi->out != nullptr)
        live.erase(phi->out->id);

    return live;
  };

  return analysis;
}

// Report in register-file order (space, offset, then version) rather than by
// value id. Ids fall out of the order the builder happened to create values
// in, which is an implementation detail nothing should be reading.
std::vector<ValueId> ordered(const SsaFunction &fn, const LiveSet &live) {
  std::vector<ValueId> ids(live.begin(), live.end());
  std::sort(ids.begin(), ids.end(), [&fn](ValueId a, ValueId b) {
    const SsaValue &left = fn.value(a);
    const SsaValue &right = fn.value(b);
    if (left.storage != right.storage)
      return left.storage < right.storage;
    return left.version < right.version;
  });
  return ids;
}

class Liveness final : public Pass {
public:
  std::string name() const override { return "liveness"; }
  std::string description() const override {
    return "backward live-value sets per block";
  }

  void run(SsaFunction &fn, PassContext &) override {
    result_ = solve(fn, build_analysis(fn));
  }

  // The live sets are kept as they came out of the solver and spelled out
  // here, because spelling them out means naming every value in them and that
  // is not work to do for a caller who asked for nothing.
  std::vector<std::string> report(const SsaFunction &fn,
                                  const PassContext &ctx) const override {
    std::vector<std::string> lines;
    for (const SsaBlock &block : fn.blocks()) {
      std::ostringstream line;
      line << "block " << block.id << " live-in:";
      if (result_.in[block.id].empty()) line << " -";
      for (ValueId id : ordered(fn, result_.in[block.id]))
        line << ' ' << ctx.name_of(fn.value(id));
      lines.push_back(line.str());
    }
    return lines;
  }

private:
  BlockResult<LiveSet> result_;
};

DDD_REGISTER_PASS(Liveness);

} // namespace
} // namespace ddd
