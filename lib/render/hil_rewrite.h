// hil_rewrite.h -- recognising an architecture's idiom and writing it back as
// the expression it was lowered from.
//
// `x0 = INT_SLESS(flags, 0)` ... `flags = INT_SBORROW(a, b)` ... `ng != ov` is
// three lines of flag arithmetic standing for `a <s b`. Getting from one to the
// other is a question about the *shape of the def-use graph*, not about the
// opcodes in any one line: the compare is four COPYs and two flag writes away
// from anything that looks like a comparison.
//
// So a rule is a Pattern (see pattern.h) matched against the graph, plus a
// description of what to build in its place. The pattern side already follows
// COPY chains and can match either operand order, which is what lets a rule be
// written as the computation rather than the lowering.
//
// The building side is deliberately small: a rule may hand back one of the
// values it captured, a constant zero, or a comparison of two of them. That
// covers every rule here. A rule needing a fourth shape is not a pattern -- it
// belongs in the builder's expression_for(), where the lowering is visible and
// a reader can see what it is doing.
#pragma once

#include "render/hil.h"

namespace ddd {

// What a rule is allowed to ask of the builder while constructing a
// replacement. The three operations are exactly the ones the builder uses on
// its own, so a rule cannot smuggle in reasoning that belongs to it.
//
// `depth` threads the fold budget: a replacement is built from further down the
// def-use chain than the op it replaces, and the sink enforces the limit.
class RewriteSink {
public:
  virtual ~RewriteSink() = default;

  // The value in a slot a pattern captured, folded into an expression if the
  // builder folds it. Never null for a slot the pattern bound.
  virtual ExprRef value_of(const SsaValue &value, int depth) = 0;
  virtual ExprRef constant(uint64_t value, unsigned size) = 0;
  virtual ExprRef binary(const char *op, int precedence, ExprRef left,
                         ExprRef right) = 0;
};

// The expression `op` is a written-out form of, or null when no rule applies.
// Exactly one rule can apply: the first match wins, so a narrower rule must
// come before a broader one in the table.
ExprRef rewrite_op(const SsaOp &op, int depth, RewriteSink &sink);

} // namespace ddd
