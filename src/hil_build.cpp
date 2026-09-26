// hil_build.cpp -- folding SSA def-use chains into expressions.
//
// The rules for what folds and what stays a variable are the interesting part
// here, and they are all in one place: folds_into_its_use() decides for a
// whole value, and build_block() decides what is worth a line at all. Anything
// that survives those two is what a reader is meant to see.
//
// Idiom recognition is not here -- it is a table over the same graph and lives
// in hil_rewrite.cpp, reached through a narrow interface so that adding a rule
// never means editing this file.
#include "hil.h"

#include "hil_expr.h"
#include "hil_rewrite.h"
#include "reaching.h"

#include <set>
#include <unordered_map>

namespace ddd {
namespace detail {

class HilBuilder final : public RewriteSink {
public:
  HilBuilder(const SsaFunction &fn, const PassContext &ctx, Hil &hil)
      : fn_(fn), ctx_(ctx), hil_(hil) {}

  void run() {
    stack_pointer_ = ctx_.stack_pointer();
    count_versions();
    observable_ = observable_values(fn_, ctx_);
    collect_machine_flags();

    hil_.blocks_.resize(fn_.size());
    for (int b = 0; b < fn_.size(); ++b) {
      hil_.blocks_[b].id = BlockId{b};
      index_block(BlockId{b});
      build_block(BlockId{b});
    }
  }

  // ---- expression construction ------------------------------------------
  //
  // The three primitives a rule may build with, and the same three the builder
  // uses below. Public because RewriteSink is how a rule reaches them.

  ExprRef variable(const SsaValue &value) {
    Expr expr;
    expr.kind = ExprKind::Variable;
    expr.value = &value;
    expr.size = value.storage.size;
    expr.precedence = kPrimary;
    expr.text = display_name(value);
    return make(std::move(expr));
  }

  ExprRef constant(uint64_t value, unsigned size) override {
    Expr expr;
    expr.kind = ExprKind::Constant;
    expr.constant = value;
    expr.size = size;
    expr.precedence = kPrimary;
    expr.text = hex(value);
    return make(std::move(expr));
  }

  ExprRef binary(const char *op, int precedence, ExprRef left,
                 ExprRef right) override {
    Expr expr;
    expr.kind = ExprKind::Binary;
    expr.text = op;
    expr.precedence = precedence;
    expr.operands = {left, right};
    return make(std::move(expr));
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

  ExprRef value_of(const SsaValue &value, int depth) override {
    if (depth > 64 || !folds_into_its_use(value)) return variable(value);

    ++hil_.folded_;
    return expression_for(*value.def, depth + 1);
  }

private:
  ExprRef make(Expr expr) {
    hil_.arena_.push_back(std::move(expr));
    return &hil_.arena_.back();
  }

  // `x + 0xffffffffffffffec` is `x - 0x14`, and a stack offset written the
  // first way is close to unreadable. Only for add and subtract, where the
  // sign of the constant is what it means.
  ExprRef additive(const char *op, ExprRef left, ExprRef right) {
    const bool add = std::string(op) == "+";
    if (right != nullptr && right->kind == ExprKind::Constant &&
        right->size != 0 && right->size <= 8) {
      const uint64_t sign = uint64_t(1) << (right->size * 8 - 1);
      const uint64_t mask = right->size >= 8
                                ? ~uint64_t(0)
                                : (uint64_t(1) << (right->size * 8)) - 1;
      const uint64_t bits = right->constant & mask;

      if ((bits & sign) != 0) {
        const uint64_t magnitude = (mask - bits + 1) & mask;
        return binary(add ? "-" : "+", kAdditive, left,
                      constant(magnitude, right->size));
      }
    }
    return binary(op, kAdditive, left, right);
  }

  // ---- what becomes a variable ------------------------------------------

  // A register written once in the whole function does not need a version
  // suffix to be unambiguous, and reads much better without one.
  void count_versions() {
    for (int i = 0; i < fn_.value_count(); ++i)
      ++versions_[fn_.value(ValueId{i}).storage];
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
        known = temporaries_
                    .emplace(value.id,
                             "t" + std::to_string(temporaries_.size()))
                    .first;
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
  bool is_plumbing(const SsaOp &op,
                   const std::set<uint64_t> &call_addresses) const {
    // Whatever the analysis already decided is bookkeeping.
    if (ctx_.annotations != nullptr && ctx_.annotations->is_plumbing(op))
      return true;

    if (stack_pointer_.space == kNoSpace) return false;

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
    if (op.opc == Op::STORE && call_addresses.count(op.addr) != 0) return true;

    return false;
  }

  static bool is_constant_def(const SsaOp &op) {
    return op.opc == Op::COPY && op.ins.size() == 1 && op.ins[0].is_constant();
  }

  void index_block(BlockId block) {
    order_.clear();
    for (size_t i = 0; i < fn_[block].ops.size(); ++i)
      order_[fn_[block].ops[i]->id] = static_cast<int>(i);
  }

  // Exactly one use, in the same block, and nothing in between that would
  // make moving the computation to the use point change its meaning.
  // Writing machine state is a statement even though nothing reads it.
  //
  // `sti` is a constant written to the interrupt flag, and a constant folds
  // into its uses -- of which there are none, so it would fold into nothing at
  // all and the instruction would not appear. What the line does is the write
  // itself; there is nothing else to show.
  void collect_machine_flags() {
    flags_.clear();
    if (ctx_.translator() == nullptr || ctx_.spaces() == nullptr) return;

    for (const std::string &name : machine_flags()) {
      Varnode storage =
          register_storage(*ctx_.translator(), *ctx_.spaces(), name);
      if (storage.space != kNoSpace) flags_.insert(storage);
    }
  }

  bool is_machine_flag(const SsaValue &value) const {
    return flags_.count(value.storage) != 0;
  }

  bool folds_into_its_use(const SsaValue &value) const {
    if (value.def == nullptr || value.def->is_phi) return false;
    if (is_machine_flag(value)) return false;

    // Anything the outside world can see stays a statement, whatever else is
    // true of it: folding it away would hide the thing the function exists to
    // produce, or the argument it is about to pass. This has to come first --
    // a constant argument is still an argument.
    if (observable_.count(value.id) != 0) return false;

    // A name someone chose deliberately is worth keeping as a variable.
    if (ctx_.annotations != nullptr && ctx_.annotations->has_label(value))
      return false;

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
    if (def.opc == Op::LOAD) {
      for (int i = def_index->second + 1; i < use_index->second; ++i) {
        const SsaOp &between = *fn_[def.block].ops[i];
        if (between.opc == Op::STORE || between.opc == Op::CALL ||
            between.opc == Op::CALLIND || between.opc == Op::CALLOTHER)
          return false;
      }
      return true;
    }

    return !has_side_effects(def.opc);
  }

  // ---- one op as an expression ------------------------------------------

  ExprRef expression_for(const SsaOp &op, int depth) {
    // An idiom the table recognises reads as the computation, not the flags.
    // The counter is the builder's, not the table's: what is being counted is
    // how much of this listing was rewritten, which is a fact about the
    // listing.
    if (ExprRef rewritten = rewrite_op(op, depth, *this)) {
      ++hil_.rewritten_;
      return rewritten;
    }

    // A width-preserving copy is not an operation at all.
    if (op.opc == Op::COPY && op.ins.size() == 1) return operand(op, 0, depth + 1);

    if (auto binop = binary_operator(op.opc); binop && op.ins.size() == 2) {
      ExprRef left = operand(op, 0, depth + 1);
      ExprRef right = operand(op, 1, depth + 1);
      if (op.opc == Op::INT_ADD || op.opc == Op::INT_SUB)
        return additive(binop->text, left, right);
      return binary(binop->text, binop->precedence, left, right);
    }

    if (const char *unop = unary_operator(op.opc);
        unop != nullptr && op.ins.size() == 1) {
      Expr expr;
      expr.kind = ExprKind::Unary;
      expr.text = unop;
      expr.precedence = kUnary;
      expr.operands = {operand(op, 0, depth + 1)};
      return make(std::move(expr));
    }

    if (const char *cast = cast_operator(op.opc);
        cast != nullptr && op.ins.size() == 1) {
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
    if (op.opc == Op::SUBPIECE && op.ins.size() == 2 && op.ins[1].is_constant() &&
        op.ins[1].constant() == 0) {
      Expr expr;
      expr.kind = ExprKind::Cast;
      expr.precedence = kPrimary;
      expr.size = op.out != nullptr ? op.out->storage.size : 0;
      expr.text = "trunc." + std::to_string(expr.size);
      expr.operands = {operand(op, 0, depth + 1)};
      return make(std::move(expr));
    }

    if (op.opc == Op::LOAD && op.ins.size() >= 2) {
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
    expr.text = op_name(op.opc);
    for (size_t i = 0; i < op.ins.size(); ++i) {
      if (is_space_operand(op, i)) continue;
      expr.operands.push_back(operand(op, i, depth + 1));
    }
    return make(std::move(expr));
  }

  // ---- statements --------------------------------------------------------

  void build_block(BlockId block) {
    std::vector<Statement> &out = hil_.blocks_[block].statements;
    const BasicBlock &raw = fn_.cfg()[block];

    for (const SsaOp *phi : fn_[block].phis) {
      if (hides_machine_state() && phi->out != nullptr &&
          stack_pointer_.space != kNoSpace &&
          phi->out->storage == stack_pointer_)
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
      if (op->opc == Op::CALL || op->opc == Op::CALLIND || op->opc == Op::RETURN)
        call_addresses.insert(op->addr);

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
    const std::vector<BlockId> &preds = fn_.cfg()[phi.block].preds;
    for (size_t i = 0; i < phi.ins.size(); ++i) {
      expr.operands.push_back(operand(phi, i, 0));
      expr.operand_blocks.push_back(i < preds.size() ? preds[i] : BlockId{});
    }
    return make(std::move(expr));
  }

  Statement statement_for(const SsaOp &op, const BasicBlock &raw) {
    Statement statement;
    statement.addr = op.addr;
    statement.op = &op;

    switch (op.opc) {
    case Op::STORE:
      if (op.ins.size() >= 3) {
        statement.kind = StatementKind::Store;
        statement.address = operand(op, 1, 0);
        statement.value = operand(op, 2, 0);
        return statement;
      }
      break;

    case Op::CBRANCH:
      if (op.ins.size() >= 2) {
        statement.kind = StatementKind::CondBranch;
        statement.value = operand(op, 1, 0);
        for (const Edge &edge : raw.succs)
          (edge.conditional ? statement.taken : statement.fallthrough) = edge.target;
        // No block took the conditional edge because the destination is not in
        // this function: a conditional tail call.
        if (!statement.taken) statement.leaves_to = raw.leaves_to;
        return statement;
      }
      break;

    case Op::BRANCH:
      statement.kind = StatementKind::Branch;
      if (!raw.succs.empty()) statement.taken = raw.succs.front().target;
      else statement.leaves_to = raw.leaves_to;
      return statement;

    case Op::CALL:
    case Op::CALLIND:
      statement.kind = StatementKind::Call;
      if (!op.ins.empty()) statement.value = operand(op, 0, 0);
      return statement;

    case Op::RETURN:
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
  std::unordered_map<Varnode, int, VarnodeHash> versions_;
  std::unordered_map<OpId, int> order_; // op id -> index in the current block
  std::set<ValueId> observable_;
  std::set<Varnode> flags_;
  std::unordered_map<ValueId, std::string> temporaries_;
  Varnode stack_pointer_{};
};

} // namespace detail

Hil build_hil(const SsaFunction &fn, const PassContext &ctx) {
  Hil hil;
  detail::HilBuilder(fn, ctx, hil).run();
  return hil;
}

} // namespace ddd
