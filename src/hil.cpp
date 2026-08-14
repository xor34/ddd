#include "hil.h"

#include "pattern.h"

#include "opcodes.hh"

#include <algorithm>
#include <set>
#include <sstream>
#include <unordered_map>

namespace ddd {
namespace {

// C's table, so the parenthesising matches what a reader expects.
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
const Operator *binary_operator(OpCode opc) {
  switch (opc) {
  case ghidra::CPUI_INT_ADD:        { static const Operator o{"+", kAdditive}; return &o; }
  case ghidra::CPUI_INT_SUB:        { static const Operator o{"-", kAdditive}; return &o; }
  case ghidra::CPUI_INT_MULT:       { static const Operator o{"*", kMultiplicative}; return &o; }
  case ghidra::CPUI_INT_DIV:        { static const Operator o{"/u", kMultiplicative}; return &o; }
  case ghidra::CPUI_INT_SDIV:       { static const Operator o{"/s", kMultiplicative}; return &o; }
  case ghidra::CPUI_INT_REM:        { static const Operator o{"%u", kMultiplicative}; return &o; }
  case ghidra::CPUI_INT_SREM:       { static const Operator o{"%s", kMultiplicative}; return &o; }
  case ghidra::CPUI_INT_AND:        { static const Operator o{"&", kBitAnd}; return &o; }
  case ghidra::CPUI_INT_OR:         { static const Operator o{"|", kBitOr}; return &o; }
  case ghidra::CPUI_INT_XOR:        { static const Operator o{"^", kBitXor}; return &o; }
  case ghidra::CPUI_INT_LEFT:       { static const Operator o{"<<", kShift}; return &o; }
  case ghidra::CPUI_INT_RIGHT:      { static const Operator o{">>u", kShift}; return &o; }
  case ghidra::CPUI_INT_SRIGHT:     { static const Operator o{">>s", kShift}; return &o; }
  case ghidra::CPUI_INT_EQUAL:      { static const Operator o{"==", kEquality}; return &o; }
  case ghidra::CPUI_INT_NOTEQUAL:   { static const Operator o{"!=", kEquality}; return &o; }
  case ghidra::CPUI_INT_LESS:       { static const Operator o{"<u", kRelational}; return &o; }
  case ghidra::CPUI_INT_LESSEQUAL:  { static const Operator o{"<=u", kRelational}; return &o; }
  case ghidra::CPUI_INT_SLESS:      { static const Operator o{"<s", kRelational}; return &o; }
  case ghidra::CPUI_INT_SLESSEQUAL: { static const Operator o{"<=s", kRelational}; return &o; }
  case ghidra::CPUI_BOOL_AND:       { static const Operator o{"&&", kLogicalAnd}; return &o; }
  case ghidra::CPUI_BOOL_OR:        { static const Operator o{"||", kLogicalOr}; return &o; }
  case ghidra::CPUI_BOOL_XOR:       { static const Operator o{"^^", kBitXor}; return &o; }
  default: return nullptr;
  }
}

const char *unary_operator(OpCode opc) {
  switch (opc) {
  case ghidra::CPUI_INT_NEGATE: return "~";
  case ghidra::CPUI_INT_2COMP: return "-";
  case ghidra::CPUI_BOOL_NEGATE: return "!";
  default: return nullptr;
  }
}

const char *cast_operator(OpCode opc) {
  switch (opc) {
  case ghidra::CPUI_INT_ZEXT: return "zx";
  case ghidra::CPUI_INT_SEXT: return "sx";
  default: return nullptr;
  }
}

std::string hex(uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << value;
  return os.str();
}

// A leading `&` on a label means specifically a frame-slot address, set by
// stack-vars -- nothing else may use that spelling, or its definition would be
// hidden here as though it were one.
//
// stack-vars labels the address of a frame slot `&var_18`. The slot itself is
// the variable a reader cares about, so a load or store through that address
// is written as the variable -- and the line computing the address stops being
// worth showing at all.
const std::string *slot_name(ExprRef expr) {
  if (expr == nullptr || expr->kind != ExprKind::Variable) return nullptr;
  if (!is_slot_label(expr->text)) return nullptr;
  return &expr->text;
}

} // namespace

class HilBuilder {
public:
  HilBuilder(const SsaFunction &fn, const PassContext &ctx, Hil &hil)
      : fn_(fn), ctx_(ctx), hil_(hil) {}

  void run() {
    stack_pointer_ = ctx_.stack_pointer();
    count_versions();
    observable_ = observable_values(fn_, ctx_);

    hil_.blocks_.resize(fn_.size());
    for (int b = 0; b < fn_.size(); ++b) {
      hil_.blocks_[b].id = b;
      index_block(b);
      build_block(b);
    }
  }

  // ---- expression construction ------------------------------------------

  ExprRef make(Expr expr) {
    hil_.arena_.push_back(std::move(expr));
    return &hil_.arena_.back();
  }

  ExprRef variable(const SsaValue &value) {
    Expr expr;
    expr.kind = ExprKind::Variable;
    expr.value = &value;
    expr.size = value.storage.size;
    expr.precedence = kPrimary;
    expr.text = display_name(value);
    return make(std::move(expr));
  }

  ExprRef constant(uint64_t value, unsigned size) {
    Expr expr;
    expr.kind = ExprKind::Constant;
    expr.constant = value;
    expr.size = size;
    expr.precedence = kPrimary;
    expr.text = hex(value);
    return make(std::move(expr));
  }

  ExprRef binary(const char *op, int precedence, ExprRef left, ExprRef right) {
    Expr expr;
    expr.kind = ExprKind::Binary;
    expr.text = op;
    expr.precedence = precedence;
    expr.operands = {left, right};
    return make(std::move(expr));
  }

  // `x + 0xffffffffffffffec` is `x - 0x14`, and a stack offset written the
  // first way is close to unreadable. Only for add and subtract, where the
  // sign of the constant is what it means.
  ExprRef additive(const char *op, ExprRef left, ExprRef right) {
    const bool add = std::string(op) == "+";
    if (right != nullptr && right->kind == ExprKind::Constant && right->size != 0 &&
        right->size <= 8) {
      const uint64_t sign = uint64_t(1) << (right->size * 8 - 1);
      const uint64_t mask = right->size >= 8 ? ~uint64_t(0)
                                             : (uint64_t(1) << (right->size * 8)) - 1;
      const uint64_t bits = right->constant & mask;

      if ((bits & sign) != 0) {
        const uint64_t magnitude = (mask - bits + 1) & mask;
        return binary(add ? "-" : "+", kAdditive, left, constant(magnitude, right->size));
      }
    }
    return binary(op, kAdditive, left, right);
  }

  // The value of an operand, folded if it can be.
  ExprRef operand(const SsaOp &op, size_t index, int depth) {
    const SsaOperand &in = op.ins[index];

    if (in.is_constant()) return constant(in.constant(), in.raw.size);
    if (!in.is_tracked()) {
      Expr expr;
      expr.kind = ExprKind::Unknown;
      expr.precedence = kPrimary;
      expr.text = ctx_.name_of(op, index);
      return make(std::move(expr));
    }

    return value_of(*in.value, depth);
  }

  ExprRef value_of(const SsaValue &value, int depth) {
    if (depth > 64 || !folds_into_its_use(value)) return variable(value);

    ++hil_.folded_;
    return expression_for(*value.def, depth + 1);
  }

private:
  // ---- what becomes a variable ------------------------------------------

  // A register written once in the whole function does not need a version
  // suffix to be unambiguous, and reads much better without one.
  void count_versions() {
    for (int i = 0; i < fn_.value_count(); ++i)
      ++versions_[fn_.value(i).storage];
  }

  std::string display_name(const SsaValue &value) {
    // A name chosen for this listing wins outright -- it is already complete
    // and already unique.
    if (ctx_.annotations != nullptr && ctx_.annotations->has_display_name(value))
      return ctx_.annotations->display_name(value);

    // A Sleigh temporary's address within the unique space says nothing to a
    // reader -- `unique:0x7b000:8#2` is just a serial number written the long
    // way. Number them in the order they turn up instead.
    const bool labelled =
        ctx_.annotations != nullptr && ctx_.annotations->has_label(value);
    if (is_temporary(value.storage) && !labelled) {
      auto known = temporaries_.find(value.id);
      if (known == temporaries_.end())
        known = temporaries_.emplace(value.id, "t" + std::to_string(temporaries_.size())).first;
      return known->second;
    }

    auto it = versions_.find(value.storage);
    if (it == versions_.end() || it->second != 1) return ctx_.name_of(value);

    return ctx_.base_name_of(value);
  }

  bool hides_machine_state() const { return !ctx_.show_machine_state; }

  // The spelling stack-vars uses for "the stack pointer, at this offset".
  static bool is_frame_expression(const std::string &label) {
    if (label == "sp") return true;
    return label.size() > 3 && label.compare(0, 2, "sp") == 0 &&
           (label[2] == '+' || label[2] == '-');
  }

  // `&var_1c = sp - 0x14` says nothing once the accesses through it are
  // written as `var_1c`: it is the address-of a variable that is about to be
  // named directly.
  bool defines_slot_address(const SsaOp &op) const {
    if (op.out == nullptr || ctx_.annotations == nullptr) return false;
    if (ctx_.show_machine_state) return false;

    const std::string &label = ctx_.annotations->label(*op.out);
    return is_slot_label(label);
  }

  // Bookkeeping the machine does that the program did not ask for: keeping the
  // stack pointer up to date, and pushing a return address as part of making a
  // call. Both are real, both are already summarised elsewhere (the frame
  // layout, the call itself), and shown in full they bury everything else --
  // `RSP_122 = phi(RSP_79, RSP_121)` is not what anyone came to read.
  bool is_plumbing(const SsaOp &op, const std::set<uint64_t> &call_addresses) const {
    // Whatever the analysis already decided is bookkeeping.
    if (ctx_.annotations != nullptr && ctx_.annotations->is_plumbing(op)) return true;

    if (stack_pointer_.space == nullptr) return false;

    // A write to the stack pointer itself.
    if (op.out != nullptr && op.out->storage == stack_pointer_) return true;

    // Or to a temporary that stack-vars worked out holds the stack pointer at
    // a known offset -- `sp`, `sp-0x20`, `sp+0x8`. Sleigh routes the real
    // update through one of these, so checking only the register misses half
    // of the bookkeeping.
    if (op.out != nullptr && ctx_.annotations != nullptr &&
        is_frame_expression(ctx_.annotations->label(*op.out)))
      return true;

    // The return-address push, which shares the call instruction's address.
    if (op.opc == ghidra::CPUI_STORE && call_addresses.count(op.addr.getOffset()) != 0)
      return true;

    return false;
  }

  static bool is_constant_def(const SsaOp &op) {
    return op.opc == ghidra::CPUI_COPY && op.ins.size() == 1 && op.ins[0].is_constant();
  }

  void index_block(int block) {
    order_.clear();
    for (size_t i = 0; i < fn_[block].ops.size(); ++i)
      order_[fn_[block].ops[i]->id] = static_cast<int>(i);
  }

  // Exactly one use, in the same block, and nothing in between that would
  // make moving the computation to the use point change its meaning.
  bool folds_into_its_use(const SsaValue &value) const {
    if (value.def == nullptr || value.def->is_phi) return false;

    // Anything the outside world can see stays a statement, whatever else is
    // true of it: folding it away would hide the thing the function exists to
    // produce, or the argument it is about to pass. This has to come first --
    // a constant argument is still an argument.
    if (observable_.count(value.id) != 0) return false;

    // A name someone chose deliberately is worth keeping as a variable.
    if (ctx_.annotations != nullptr && ctx_.annotations->has_label(value)) return false;

    // A constant depends on nothing and costs nothing to repeat, so it folds
    // into every use however many there are. Otherwise a compare against a
    // literal leaves the literal parked in a variable of its own, which is
    // exactly the noise this is meant to remove.
    if (is_constant_def(*value.def)) return true;

    if (value.uses.size() != 1) return false;

    const SsaOp &def = *value.def;
    const SsaOp &use = *value.uses.front();
    if (def.block != use.block) return false; // no motion across control flow

    auto def_index = order_.find(def.id);
    auto use_index = order_.find(use.id);
    if (def_index == order_.end() || use_index == order_.end()) return false;
    if (use_index->second <= def_index->second) return false;

    // A load may only move down to its use if nothing in between could have
    // changed what it reads. Stores and calls could; arithmetic could not.
    if (def.opc == ghidra::CPUI_LOAD) {
      for (int i = def_index->second + 1; i < use_index->second; ++i) {
        const SsaOp &between = *fn_[def.block].ops[i];
        if (between.opc == ghidra::CPUI_STORE || between.opc == ghidra::CPUI_CALL ||
            between.opc == ghidra::CPUI_CALLIND || between.opc == ghidra::CPUI_CALLOTHER)
          return false;
      }
      return true;
    }

    return !has_side_effects(def.opc);
  }

  // ---- the rewrite table -------------------------------------------------

  // Matched against the def-use graph, following COPY chains, so a rule
  // describes the computation rather than the lowering. First match wins.
  //
  // Each rule builds its replacement from the captured slots, so adding one is
  // a pattern and a lambda -- there is no per-rule boilerplate to copy.
  struct Rewrite {
    Pattern pattern;
    ExprRef (HilBuilder::*build)(const Match &, const SsaOp &, int);
  };

  static const std::vector<Rewrite> &rewrites() {
    using namespace ddd::pat;
    using namespace ghidra;

    static const std::vector<Rewrite> table = {
        // The flag dance behind a signed compare: NG != OV over a
        // subtraction. Copy-skipping is what makes this expressible at all.
        // Either operand order: which flag lands on the left is an artefact of
        // the lowering, not of the comparison.
        {comm(CPUI_INT_NOTEQUAL, op(CPUI_INT_SLESS, {val(0), imm(0)}),
              op(CPUI_INT_SBORROW, {val(1), val(2)})),
         &HilBuilder::signed_less},

        // A comparison done by subtracting and testing the result.
        {op(CPUI_INT_EQUAL, {op(CPUI_INT_SUB, {val(0), val(1)}), imm(0)}),
         &HilBuilder::sub_equal},
        {op(CPUI_INT_NOTEQUAL, {op(CPUI_INT_SUB, {val(0), val(1)}), imm(0)}),
         &HilBuilder::sub_not_equal},

        // !(x == 0) is x != 0.
        {op(CPUI_BOOL_NEGATE, {op(CPUI_INT_EQUAL, {val(0), imm(0)})}),
         &HilBuilder::not_zero},

        // Self-cancelling arithmetic: the idiomatic register zeroing.
        {op(CPUI_INT_XOR, {val(0), val(0)}), &HilBuilder::always_zero},
        {op(CPUI_INT_SUB, {val(0), val(0)}), &HilBuilder::always_zero},
        {comm(CPUI_INT_AND, val(0), imm(0)), &HilBuilder::always_zero},
        {comm(CPUI_INT_MULT, val(0), imm(0)), &HilBuilder::always_zero},

        // Operations that are their own operand.
        {op(CPUI_INT_AND, {val(0), val(0)}), &HilBuilder::first_operand},
        {op(CPUI_INT_OR, {val(0), val(0)}), &HilBuilder::first_operand},
        {comm(CPUI_INT_ADD, val(0), imm(0)), &HilBuilder::first_operand},
    };
    return table;
  }

  ExprRef rewrite(const SsaOp &op, int depth) {
    for (const Rewrite &rule : rewrites()) {
      Match m;
      if (!rule.pattern.match(op, m)) continue;

      ++hil_.rewritten_;
      return (this->*rule.build)(m, op, depth);
    }
    return nullptr;
  }

  ExprRef signed_less(const Match &m, const SsaOp &, int depth) {
    return compare("<s", kRelational, m, 1, 2, depth);
  }
  ExprRef sub_equal(const Match &m, const SsaOp &, int depth) {
    return compare("==", kEquality, m, 0, 1, depth);
  }
  ExprRef sub_not_equal(const Match &m, const SsaOp &, int depth) {
    return compare("!=", kEquality, m, 0, 1, depth);
  }
  ExprRef not_zero(const Match &m, const SsaOp &, int depth) {
    return binary("!=", kEquality, value_of(*m.value(0), depth + 1), constant(0, 0));
  }
  ExprRef always_zero(const Match &, const SsaOp &op, int) {
    return constant(0, op.out != nullptr ? op.out->storage.size : 0);
  }
  ExprRef first_operand(const Match &m, const SsaOp &, int depth) {
    return value_of(*m.value(0), depth + 1);
  }

  ExprRef compare(const char *text, int precedence, const Match &m, int left,
                  int right, int depth) {
    return binary(text, precedence, value_of(*m.value(left), depth + 1),
                  value_of(*m.value(right), depth + 1));
  }

  // ---- one op as an expression ------------------------------------------

  ExprRef expression_for(const SsaOp &op, int depth) {
    if (ExprRef rewritten = rewrite(op, depth)) return rewritten;

    // A width-preserving copy is not an operation at all.
    if (op.opc == ghidra::CPUI_COPY && op.ins.size() == 1)
      return operand(op, 0, depth + 1);

    if (const Operator *binop = binary_operator(op.opc); binop != nullptr && op.ins.size() == 2) {
      ExprRef left = operand(op, 0, depth + 1);
      ExprRef right = operand(op, 1, depth + 1);
      if (op.opc == ghidra::CPUI_INT_ADD || op.opc == ghidra::CPUI_INT_SUB)
        return additive(binop->text, left, right);
      return binary(binop->text, binop->precedence, left, right);
    }

    if (const char *unop = unary_operator(op.opc); unop != nullptr && op.ins.size() == 1) {
      Expr expr;
      expr.kind = ExprKind::Unary;
      expr.text = unop;
      expr.precedence = kUnary;
      expr.operands = {operand(op, 0, depth + 1)};
      return make(std::move(expr));
    }

    if (const char *cast = cast_operator(op.opc); cast != nullptr && op.ins.size() == 1) {
      Expr expr;
      expr.kind = ExprKind::Cast;
      expr.precedence = kPrimary;
      expr.size = op.out != nullptr ? op.out->storage.size : 0;
      expr.text = std::string(cast) + "." + std::to_string(expr.size);
      expr.operands = {operand(op, 0, depth + 1)};
      return make(std::move(expr));
    }

    // SUBPIECE(x, 0) keeps the low bytes: that is a truncating cast, and
    // reads as one.
    if (op.opc == ghidra::CPUI_SUBPIECE && op.ins.size() == 2 &&
        op.ins[1].is_constant() && op.ins[1].constant() == 0) {
      Expr expr;
      expr.kind = ExprKind::Cast;
      expr.precedence = kPrimary;
      expr.size = op.out != nullptr ? op.out->storage.size : 0;
      expr.text = "trunc." + std::to_string(expr.size);
      expr.operands = {operand(op, 0, depth + 1)};
      return make(std::move(expr));
    }

    if (op.opc == ghidra::CPUI_LOAD && op.ins.size() >= 2) {
      Expr expr;
      expr.kind = ExprKind::Load;
      expr.precedence = kPrimary;
      expr.size = op.out != nullptr ? op.out->storage.size : 0;
      expr.operands = {operand(op, 1, depth + 1)};
      return make(std::move(expr));
    }

    // Anything with no higher-level form keeps its p-code name, so the output
    // never silently loses an operation it could not explain.
    Expr expr;
    expr.kind = ExprKind::Unknown;
    expr.precedence = kPrimary;
    expr.text = ghidra::get_opname(op.opc);
    for (size_t i = 0; i < op.ins.size(); ++i) {
      if (is_space_operand(op, i)) continue;
      expr.operands.push_back(operand(op, i, depth + 1));
    }
    return make(std::move(expr));
  }

  // ---- statements --------------------------------------------------------

  void build_block(int block) {
    std::vector<Statement> &out = hil_.blocks_[block].statements;
    const BasicBlock &raw = fn_.cfg()[block];

    for (const SsaOp *phi : fn_[block].phis) {
      if (hides_machine_state() && phi->out != nullptr &&
          stack_pointer_.space != nullptr && phi->out->storage == stack_pointer_)
        continue;

      Statement statement;
      statement.kind = StatementKind::Assign;
      statement.addr = phi->addr;
      statement.op = phi;
      statement.target = phi->out;
      statement.target_text = display_name(*phi->out);
      statement.value = phi_expression(*phi);
      out.push_back(statement);
    }

    // A call instruction lowers to the push of its own return address as well
    // as the transfer: those ops share the call's address.
    std::set<uint64_t> call_addresses;
    for (const SsaOp *op : fn_[block].ops)
      if (op->opc == ghidra::CPUI_CALL || op->opc == ghidra::CPUI_CALLIND ||
          op->opc == ghidra::CPUI_RETURN)
        call_addresses.insert(op->addr.getOffset());

    for (const SsaOp *op : fn_[block].ops) {
      if (op->out != nullptr && folds_into_its_use(*op->out)) continue;
      if (hides_machine_state() && is_plumbing(*op, call_addresses)) continue;
      if (defines_slot_address(*op)) continue;
      out.push_back(statement_for(*op, raw));
    }
  }

  ExprRef phi_expression(const SsaOp &phi) {
    Expr expr;
    expr.kind = ExprKind::Unknown;
    expr.precedence = kPrimary;
    expr.text = "phi";
    // Through operand(), not variable(): a phi argument whose definition was
    // folded away must show the expression, not a name with nothing defining
    // it. Only constants fold this far, because everything else lives in a
    // predecessor block and must not be moved.
    //
    // Each operand is labelled with the predecessor it arrives from. Without
    // that a phi is a list of names and no information: which branch produced
    // which value is the entire content of the node.
    const std::vector<int> &preds = fn_.cfg()[phi.block].preds;
    for (size_t i = 0; i < phi.ins.size(); ++i) {
      expr.operands.push_back(operand(phi, i, 0));
      expr.operand_blocks.push_back(i < preds.size() ? preds[i] : -1);
    }
    return make(std::move(expr));
  }

  Statement statement_for(const SsaOp &op, const BasicBlock &raw) {
    Statement statement;
    statement.addr = op.addr;
    statement.op = &op;

    switch (op.opc) {
    case ghidra::CPUI_STORE:
      if (op.ins.size() >= 3) {
        statement.kind = StatementKind::Store;
        statement.address = operand(op, 1, 0);
        statement.value = operand(op, 2, 0);
        return statement;
      }
      break;

    case ghidra::CPUI_CBRANCH:
      if (op.ins.size() >= 2) {
        statement.kind = StatementKind::CondBranch;
        statement.value = operand(op, 1, 0);
        for (const Edge &edge : raw.succs)
          (edge.conditional ? statement.taken : statement.fallthrough) = edge.target;
        return statement;
      }
      break;

    case ghidra::CPUI_BRANCH:
      statement.kind = StatementKind::Branch;
      if (!raw.succs.empty()) statement.taken = raw.succs.front().target;
      return statement;

    case ghidra::CPUI_CALL:
    case ghidra::CPUI_CALLIND:
      statement.kind = StatementKind::Call;
      if (!op.ins.empty()) statement.value = operand(op, 0, 0);
      return statement;

    case ghidra::CPUI_RETURN:
      statement.kind = StatementKind::Return;
      return statement;

    default:
      break;
    }

    if (op.out != nullptr) {
      statement.kind = StatementKind::Assign;
      statement.target = op.out;
      statement.target_text = display_name(*op.out);
      statement.value = expression_for(op, 0);
      return statement;
    }

    // Storage that was never renamed -- memory, or anything in a block the
    // renamer never reached -- still gets written, and saying so beats
    // printing a bare expression with no destination.
    if (op.has_raw_output) {
      statement.kind = StatementKind::Assign;
      statement.target_text = ctx_.name_of(op.raw_output);
      statement.value = expression_for(op, 0);
      return statement;
    }

    statement.kind = StatementKind::Effect;
    statement.value = expression_for(op, 0);
    return statement;
  }

  const SsaFunction &fn_;
  const PassContext &ctx_;
  Hil &hil_;
  std::unordered_map<Storage, int, StorageHash> versions_;
  std::unordered_map<int, int> order_; // op id -> index in the current block
  std::set<int> observable_;
  std::unordered_map<int, std::string> temporaries_;
  Storage stack_pointer_;
};

namespace {

void render(std::ostringstream &os, ExprRef expr, int parent_precedence) {
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
    if (const std::string *slot = slot_name(expr->operands[0])) {
      os << slot->substr(1);
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
        if (i < expr->operand_blocks.size())
          os << expr->operand_blocks[i] << ": ";
        render(os, expr->operands[i], kLowest);
      }
      os << ')';
    }
    break;
  }

  if (parenthesise) os << ')';
}

} // namespace

namespace {

// Mirrors render() above, emitting tokens instead of characters. Kept as a
// second walk rather than a shared one because the string form is the hot
// path for batch output and threading a sink through it earned nothing.
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
    if (const std::string *slot = slot_name(expr->operands[0])) {
      const std::string name = slot->substr(1);
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
        if (i < expr->operand_blocks.size()) {
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

} // namespace

std::vector<TokenBlock> tokenize(const Hil &hil, const SsaFunction &fn,
                                 const PassContext &ctx) {
  std::vector<TokenBlock> blocks;
  const Cfg &cfg = fn.cfg();

  for (const HilBlock &block : hil.blocks()) {
    const BasicBlock &raw = cfg[block.id];

    // A block nothing can reach is not part of this function. The sweep is
    // linear, so it decodes whatever was laid out after the last `ret` as
    // well, and showing it means showing the next function's flag arithmetic
    // under this one's name.
    if (!fn.dominance().reachable(block.id))
      continue;

    TokenBlock out;
    out.id = block.id;
    out.addr = raw.start.getOffset();
    out.entry = block.id == cfg.entry;
    out.preds = raw.preds;
    for (const Edge &edge : raw.succs) out.succs.push_back(edge.target);
    if (ctx.annotations != nullptr) out.comments = ctx.annotations->block_comments(block.id);

    for (const Statement &statement : block.statements) {
      TokenLine line;
      line.addr = statement.addr.getOffset();

      switch (statement.kind) {
      case StatementKind::Assign:
        line.tokens.push_back({"var", statement.target_text, statement.target_text});
        line.tokens.push_back({"op", "=", ""});
        emit(line.tokens, statement.value, kLowest);
        break;

      case StatementKind::Store:
        if (const std::string *slot = slot_name(statement.address)) {
          const std::string name = slot->substr(1);
          line.tokens.push_back({"var", name, name});
        } else {
          line.tokens.push_back({"punct", "[", ""});
          emit(line.tokens, statement.address, kLowest);
          line.tokens.push_back({"punct", "]", ""});
        }
        line.tokens.push_back({"op", "=", ""});
        emit(line.tokens, statement.value, kLowest);
        break;

      case StatementKind::CondBranch:
        line.tokens.push_back({"keyword", "if", ""});
        line.tokens.push_back({"punct", "(", ""});
        emit(line.tokens, statement.value, kLowest);
        line.tokens.push_back({"punct", ")", ""});
        line.tokens.push_back({"keyword", "goto", ""});
        line.tokens.push_back({"block", std::to_string(statement.taken), ""});
        if (statement.fallthrough >= 0) {
          line.tokens.push_back({"keyword", "else goto", ""});
          line.tokens.push_back({"block", std::to_string(statement.fallthrough), ""});
        }
        break;

      case StatementKind::Branch:
        line.tokens.push_back({"keyword", "goto", ""});
        line.tokens.push_back({"block", std::to_string(statement.taken), ""});
        break;

      case StatementKind::Call:
        line.tokens.push_back({"keyword", "call", ""});
        emit(line.tokens, statement.value, kPrimary);
        break;

      case StatementKind::Return:
        line.tokens.push_back({"keyword", "return", ""});
        break;

      case StatementKind::Effect:
        emit(line.tokens, statement.value, kLowest);
        break;
      }

      if (ctx.annotations != nullptr && statement.op != nullptr)
        line.comments = ctx.annotations->comments(*statement.op);

      out.lines.push_back(std::move(line));
    }

    blocks.push_back(std::move(out));
  }

  return blocks;
}

Hil build_hil(const SsaFunction &fn, const PassContext &ctx) {
  Hil hil;
  HilBuilder(fn, ctx, hil).run();
  return hil;
}

std::string to_string(const Hil &hil, const SsaFunction &fn, const PassContext &ctx) {
  std::ostringstream os;
  const Cfg &cfg = fn.cfg();

  for (const HilBlock &block : hil.blocks()) {
    const BasicBlock &raw = cfg[block.id];

    // As in tokenize: what nothing can reach is what the linear sweep walked
    // into after this function ended, not part of it.
    if (!fn.dominance().reachable(block.id)) continue;

    os << "block " << block.id << " @ 0x" << std::hex << raw.start.getOffset()
       << std::dec;
    if (block.id == cfg.entry) os << " (entry)";
    os << ":";
    if (!raw.preds.empty()) {
      os << "  from";
      for (int p : raw.preds) os << ' ' << p;
    }
    os << "\n";

    if (ctx.annotations != nullptr)
      for (const std::string &comment : ctx.annotations->block_comments(block.id))
        os << "  ; " << comment << "\n";

    for (const Statement &statement : block.statements) {
      std::ostringstream line;
      switch (statement.kind) {
      case StatementKind::Assign:
        line << statement.target_text << " = ";
        render(line, statement.value, kLowest);
        break;

      case StatementKind::Store:
        if (const std::string *slot = slot_name(statement.address)) {
          line << slot->substr(1) << " = ";
        } else {
          line << '[';
          render(line, statement.address, kLowest);
          line << "] = ";
        }
        render(line, statement.value, kLowest);
        break;

      case StatementKind::CondBranch:
        line << "if (";
        render(line, statement.value, kLowest);
        line << ") goto " << statement.taken;
        if (statement.fallthrough >= 0) line << " else goto " << statement.fallthrough;
        break;

      case StatementKind::Branch:
        line << "goto " << statement.taken;
        break;

      case StatementKind::Call:
        line << "call ";
        render(line, statement.value, kPrimary);
        break;

      case StatementKind::Return:
        line << "return";
        break;

      case StatementKind::Effect:
        render(line, statement.value, kLowest);
        break;
      }

      os << "  0x" << std::hex << statement.addr.getOffset() << std::dec << "  "
         << line.str();

      const std::vector<std::string> *comments =
          ctx.annotations != nullptr && statement.op != nullptr
              ? &ctx.annotations->comments(*statement.op)
              : nullptr;
      if (comments != nullptr && !comments->empty()) {
        os << "  ; " << comments->front();
        for (size_t i = 1; i < comments->size(); ++i)
          os << "\n          ; " << (*comments)[i];
      }
      os << "\n";
    }
  }

  return os.str();
}

} // namespace ddd
