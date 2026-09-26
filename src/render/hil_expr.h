// hil_expr.h -- how an expression is spelled, and the vocabulary it is spelled
// from.
//
// The operator tables and the two renderers live together because they have to
// agree: an operator whose precedence is wrong here parenthesises wrongly in
// both walks, and a reader comparing the two would have to hold them in their
// head at once. The builder reads the same tables to decide how to parenthesise
// what it constructs.
#pragma once

#include "render/hil.h"

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ddd {

// C's table, so the parenthesising matches what a reader expects. Sits in a
// header rather than beside the tables because Expr::precedence is one of
// these -- without the names it is an untyped int, and the renderers' `+ 1` on
// the right-hand operand means nothing on its own.
enum Precedence {
  kLowest = 0,
  kLogicalOr = 1,
  kLogicalAnd = 2,
  kBitOr = 3,
  kBitXor = 4,
  kBitAnd = 5,
  kEquality = 6,
  kRelational = 7,
  kShift = 8,
  kAdditive = 9,
  kMultiplicative = 10,
  kUnary = 12,
  kPrimary = 15,
};

struct Operator {
  const char *text;
  int precedence;
};

// Signed operations are spelled with a trailing 's' rather than pretending
// C's operators carry signedness -- `<s` is a real distinction in the p-code
// and hiding it would be a lie.
//
// An optional rather than a pointer so the table stays a plain switch of
// literals; the alternative is a function-local static per case, which buries
// the table it is meant to be.
std::optional<Operator> binary_operator(Op opc);
// The string form of an unary operator or cast, or null when the opcode is
// not one. These two have no natural table -- one character each -- so null
// is the readable way to say "none".
const char *unary_operator(Op opc);
const char *cast_operator(Op opc);

std::string hex(uint64_t value);

// stack-vars labels the address of a frame slot `&var_18`. The slot itself is
// the variable a reader cares about, so a load or store through that address
// is written as the variable -- and the line computing the address stops being
// worth showing at all.
//
// Empty when the expression is not such an address; otherwise the slot's own
// name, ready to print. That the expression *is* one is a fact about the value
// behind it (Annotations::address_kind, carried on the Expr); the '&' the
// address is spelled with when it is shown on its own is not part of what a
// load through it is called.
std::string_view slot_name(ExprRef expr);

// Spells an expression out. `parent_precedence` is the binding power of the
// context it appears in: below it the expression needs parentheses, which is
// what keeps `a - (b - c)` from reading as `a - b - c`.
void render(std::ostream &os, ExprRef expr, int parent_precedence);

// Mirrors render(), emitting tokens instead of characters. A second walk rather
// than a shared one because the string form is the hot path for batch output
// and threading a sink through it earned nothing.
void emit(std::vector<Token> &out, ExprRef expr, int parent_precedence);

} // namespace ddd
