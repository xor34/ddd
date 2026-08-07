// idioms -- recognise common instruction-selection shapes and say what they
// mean.
//
// Compilers say "zero this register" by xoring it with itself and "is x
// signed-less-than y" by comparing two flag bits. Those read as noise in
// p-code. Each rule below is a pattern plus a sentence; matching one attaches
// the sentence to the op.
//
// Adding a rule means adding one line to the table. Nothing else changes.
#include "../pass.h"
#include "../pattern.h"

#include "opcodes.hh"

#include <ostream>
#include <sstream>

namespace ddd {
namespace {

using namespace ddd::pat;

using Describe = std::function<std::string(const SsaOp &, const Match &, const PassContext &)>;

struct Rule {
  std::string name;
  Pattern pattern;
  Describe describe;
};

Describe says(std::string text) {
  return [text](const SsaOp &, const Match &, const PassContext &) { return text; };
}

const std::vector<Rule> &rules() {
  using namespace ghidra;

  static const std::vector<Rule> table = {
      {"zero-self-xor", op(CPUI_INT_XOR, {val(0), val(0)}),
       says("always 0 -- idiomatic register zeroing")},

      {"zero-self-sub", op(CPUI_INT_SUB, {val(0), val(0)}), says("always 0")},

      {"zero-mult", comm(CPUI_INT_MULT, val(0), imm(0)), says("always 0")},

      {"zero-and", comm(CPUI_INT_AND, val(0), imm(0)), says("always 0")},

      {"identity-and", op(CPUI_INT_AND, {val(0), val(0)}), says("no-op (x & x)")},

      {"identity-or", op(CPUI_INT_OR, {val(0), val(0)}), says("no-op (x | x)")},

      {"identity-add", comm(CPUI_INT_ADD, val(0), imm(0)), says("no-op (x + 0)")},

      {"always-equal", op(CPUI_INT_EQUAL, {val(0), val(0)}), says("always true")},

      {"truncate-32",
       comm(CPUI_INT_AND, val(0), imm(0xffffffffULL)),
       says("truncate to 32 bits")},

      // The flag dance behind a signed compare: NG != OV, where NG is the sign
      // of the subtraction and OV is its signed borrow. Copy-skipping in the
      // matcher is what makes this expressible at all.
      {"signed-less-than",
       op(CPUI_INT_NOTEQUAL, {op(CPUI_INT_SLESS, {val(0), imm(0)}),
                              op(CPUI_INT_SBORROW, {val(1), val(2)})}),
       says("signed <  (NG != OV)")},

      {"nonzero-test", op(CPUI_BOOL_NEGATE, {op(CPUI_INT_EQUAL, {val(0), imm(0)})}),
       says("x != 0")},

      // A shift by a constant is a multiply or divide by a power of two; worth
      // spelling out because the constant is the interesting part.
      {"shift-left-const", op(CPUI_INT_LEFT, {val(0), cst(0)}),
       [](const SsaOp &, const Match &m, const PassContext &) {
         std::ostringstream os;
         os << "x * " << (1ULL << (m.constants[0] & 63));
         return os.str();
       }},

      {"shift-right-const", op(CPUI_INT_RIGHT, {val(0), cst(0)}),
       [](const SsaOp &, const Match &m, const PassContext &) {
         std::ostringstream os;
         os << "x / " << (1ULL << (m.constants[0] & 63)) << " (unsigned)";
         return os.str();
       }},
  };

  return table;
}

class Idioms final : public Pass {
public:
  std::string name() const override { return "idioms"; }
  std::string description() const override {
    return "recognise idiomatic instruction sequences";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    int matched = 0;

    fn.for_each_op([&](SsaOp &op) {
      for (const Rule &rule : rules()) {
        Match m;
        if (!rule.pattern.match(op, m)) continue;

        fn.annotate(op, rule.describe(op, m, ctx));
        ++matched;
        break; // first rule wins; the table is ordered most-specific first
      }
    });

    if (ctx.verbose) ctx.stream() << "  " << matched << " idiom(s) recognised\n";
  }
};

DDD_REGISTER_PASS(Idioms);

} // namespace
} // namespace ddd
