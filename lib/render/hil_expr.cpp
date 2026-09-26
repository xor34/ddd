#include "render/hil_expr.h"

#include "facts/knowledge.h"

#include <ostream>
#include <sstream>

namespace ddd {

std::optional<Operator> binary_operator(Op opc) {
  switch (opc) {
  case Op::INT_ADD: return Operator{"+", kAdditive};
  case Op::INT_SUB: return Operator{"-", kAdditive};
  case Op::INT_MULT: return Operator{"*", kMultiplicative};
  case Op::INT_DIV: return Operator{"/u", kMultiplicative};
  case Op::INT_SDIV: return Operator{"/s", kMultiplicative};
  case Op::INT_REM: return Operator{"%u", kMultiplicative};
  case Op::INT_SREM: return Operator{"%s", kMultiplicative};
  case Op::INT_AND: return Operator{"&", kBitAnd};
  case Op::INT_OR: return Operator{"|", kBitOr};
  case Op::INT_XOR: return Operator{"^", kBitXor};
  case Op::INT_LEFT: return Operator{"<<", kShift};
  case Op::INT_RIGHT: return Operator{">>u", kShift};
  case Op::INT_SRIGHT: return Operator{">>s", kShift};
  case Op::INT_EQUAL: return Operator{"==", kEquality};
  case Op::INT_NOTEQUAL: return Operator{"!=", kEquality};
  case Op::INT_LESS: return Operator{"<u", kRelational};
  case Op::INT_LESSEQUAL: return Operator{"<=u", kRelational};
  case Op::INT_SLESS: return Operator{"<s", kRelational};
  case Op::INT_SLESSEQUAL: return Operator{"<=s", kRelational};
  case Op::BOOL_AND: return Operator{"&&", kLogicalAnd};
  case Op::BOOL_OR: return Operator{"||", kLogicalOr};
  case Op::BOOL_XOR: return Operator{"^^", kBitXor};
  default: return std::nullopt;
  }
}

const char *unary_operator(Op opc) {
  switch (opc) {
  case Op::INT_NEGATE: return "~";
  case Op::INT_2COMP: return "-";
  case Op::BOOL_NEGATE: return "!";
  default: return nullptr;
  }
}

const char *cast_operator(Op opc) {
  switch (opc) {
  case Op::INT_ZEXT: return "zx";
  case Op::INT_SEXT: return "sx";
  default: return nullptr;
  }
}

std::string hex(uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << value;
  return os.str();
}

std::string_view slot_name(ExprRef expr) {
  if (expr == nullptr || expr->kind != ExprKind::Variable) return {};
  if (expr->slot == nullptr) return {};

  // `text` is the address's own spelling, `&var_18`; what a load through it is
  // called is the slot, `var_18`. Only the '&' is dropped, and only if it is
  // there: a name a user chose for the slot may not carry one, and then the
  // whole of it is the name.
  std::string_view text = expr->text;
  if (!text.empty() && text.front() == '&') text.remove_prefix(1);
  return text;
}

void render(std::ostream &os, ExprRef expr, int parent_precedence) {
  if (expr == nullptr) {
    os << "?";
    return;
  }

  const bool parenthesise = expr->precedence < parent_precedence;
  if (parenthesise) os << '(';

  switch (expr->kind) {
  case ExprKind::Constant:
  case ExprKind::Variable:
    os << expr->text;
    break;

  case ExprKind::Unary:
    os << expr->text;
    render(os, expr->operands[0], kUnary);
    break;

  case ExprKind::Binary:
    render(os, expr->operands[0], expr->precedence);
    os << ' ' << expr->text << ' ';
    // One higher on the right, so `a - (b - c)` keeps its parentheses.
    render(os, expr->operands[1], expr->precedence + 1);
    break;

  case ExprKind::Cast:
    os << expr->text << '(';
    render(os, expr->operands[0], kLowest);
    os << ')';
    break;

  case ExprKind::Load:
    if (const std::string_view slot = slot_name(expr->operands[0]);
        !slot.empty()) {
      os << slot;
      break;
    }
    os << '[';
    render(os, expr->operands[0], kLowest);
    os << ']';
    if (expr->size != 0) os << '.' << expr->size;
    break;

  case ExprKind::Unknown:
    os << expr->text;
    if (!expr->operands.empty()) {
      os << '(';
      for (size_t i = 0; i < expr->operands.size(); ++i) {
        if (i) os << ", ";
        if (i < expr->operand_blocks.size() && expr->operand_blocks[i].valid())
          os << expr->operand_blocks[i] << ": ";
        render(os, expr->operands[i], kLowest);
      }
      os << ')';
    }
    break;
  }

  if (parenthesise) os << ')';
}

// The opposite of an operator, where C has one to write. The orderings carry
// the `u` or `s` that says which comparison the machine computed, and their
// opposites carry it too -- `<s` is not the opposite of `>=u`.
bool opposite_operator(const std::string &text, std::string &out) {
  static const struct {
    const char *op;
    const char *opposite;
  } kTable[] = {
      {"==", "!="},   {"!=", "=="},   {"<", ">="},   {"<=", ">"},
      {">", "<="},    {">=", "<"},    {"<u", ">=u"}, {"<=u", ">u"},
      {">u", "<=u"},  {">=u", "<u"},  {"<s", ">=s"}, {"<=s", ">s"},
      {">s", "<=s"},  {">=s", "<s"},
  };

  for (const auto &entry : kTable)
    if (text == entry.op) {
      out = entry.opposite;
      return true;
    }
  return false;
}

void render_negated(std::ostream &os, ExprRef expr) {
  if (expr != nullptr && expr->kind == ExprKind::Binary) {
    std::string opposite;
    if (opposite_operator(expr->text, opposite)) {
      render(os, expr->operands[0], expr->precedence);
      os << ' ' << opposite << ' ';
      render(os, expr->operands[1], expr->precedence + 1);
      return;
    }
  }

  // Nothing to invert -- a name, a load, a sum. `!` is the word for it, and
  // rendering at unary precedence is what puts the parentheses back around
  // anything that would otherwise read as negating only its first term.
  os << '!';
  render(os, expr, kUnary);
}

void emit(std::vector<Token> &out, ExprRef expr, int parent_precedence) {
  if (expr == nullptr) {
    out.push_back({"op", "?", ""});
    return;
  }

  const bool parenthesise = expr->precedence < parent_precedence;
  if (parenthesise) out.push_back({"punct", "(", ""});

  switch (expr->kind) {
  case ExprKind::Constant:
    out.push_back({"const", expr->text, ""});
    break;

  case ExprKind::Variable:
    // The id is the displayed name: two occurrences of one variable share it,
    // and `RAX` and `RAX_2` do not.
    out.push_back({"var", expr->text, expr->text});
    break;

  case ExprKind::Unary:
    out.push_back({"op", expr->text, ""});
    emit(out, expr->operands[0], kUnary);
    break;

  case ExprKind::Binary:
    emit(out, expr->operands[0], expr->precedence);
    out.push_back({"op", expr->text, ""});
    emit(out, expr->operands[1], expr->precedence + 1);
    break;

  case ExprKind::Cast:
    out.push_back({"cast", expr->text, ""});
    out.push_back({"punct", "(", ""});
    emit(out, expr->operands[0], kLowest);
    out.push_back({"punct", ")", ""});
    break;

  case ExprKind::Load:
    if (const std::string_view slot = slot_name(expr->operands[0]);
        !slot.empty()) {
      const std::string name(slot);
      out.push_back({"var", name, name});
      break;
    }
    out.push_back({"punct", "[", ""});
    emit(out, expr->operands[0], kLowest);
    out.push_back({"punct", "]", ""});
    break;

  case ExprKind::Unknown:
    out.push_back({"op", expr->text, ""});
    if (!expr->operands.empty()) {
      out.push_back({"punct", "(", ""});
      for (size_t i = 0; i < expr->operands.size(); ++i) {
        if (i) out.push_back({"punct", ",", ""});
        // A phi says where each operand came from; the block token is what an
        // interface renders as the label it prints that block under.
        if (i < expr->operand_blocks.size() && expr->operand_blocks[i].valid()) {
          out.push_back({"block", std::to_string(expr->operand_blocks[i]), ""});
          out.push_back({"punct", ":", ""});
        }
        emit(out, expr->operands[i], kLowest);
      }
      out.push_back({"punct", ")", ""});
    }
    break;
  }

  if (parenthesise) out.push_back({"punct", ")", ""});
}

} // namespace ddd
