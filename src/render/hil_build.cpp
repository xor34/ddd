// hil_build.cpp -- folding SSA def-use chains into expressions.
//
// The rules for what folds and what stays a variable are the interesting part
// here, and they are all in one place: folds_into_its_use() decides for a
// whole value, and build_block() decides what is worth a line at all. Anything
// that survives those two is what a reader is meant to see -- except for what
// plan_elisions() took out first, which is a decision made once for the whole
// function rather than op by op, because half of it is whether a line that
// *is* printed depends on it.
//
// Idiom recognition is not here -- it is a table over the same graph and lives
// in hil_rewrite.cpp, reached through a narrow interface so that adding a rule
// never means editing this file.
#include "render/hil.h"

#include "render/hil_expr.h"
#include "render/hil_rewrite.h"
#include "ir/pattern.h"
#include "ir/reaching.h"

#include <map>
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
    observable_ = observable_values(fn_, ctx_.target);
    collect_machine_flags();
    collect_call_addresses();
    // Before plan_elisions, which has to know which register the convention
    // calls the result: the widening written into it is not a statement.
    find_result_storage();
    plan_elisions();
    // After plan_elisions, and after the fills it took out: a return's value
    // may only be moved onto the return line when the value was produced for
    // the return and nothing the listing prints reads it.
    find_return_values();

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

  // What a call left in a register it does not preserve. It is a value the
  // program reads, so it has to be spelled; it is not a name, because nothing
  // computes it and no line defines it. `unknown` says both, and says why the
  // reader cannot follow it any further.
  ExprRef unknown(int size) {
    Expr expr;
    expr.kind = ExprKind::Unknown;
    expr.size = size;
    expr.precedence = kPrimary;
    expr.text = "unknown";
    return make(std::move(expr));
  }

  ExprRef variable(const SsaValue &value) {
    if (value.is_clobber()) return unknown(value.storage.size);

    Expr expr;
    expr.kind = ExprKind::Variable;
    expr.value = &value;
    expr.size = value.storage.size;
    expr.precedence = kPrimary;
    expr.text = display_name(value);
    if (ctx_.annotations != nullptr)
      expr.address = ctx_.annotations->address_kind(value);
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
    if (depth > 64) return variable(value);

    // Reading a filled register reads the value it was filled with. The fill
    // has no line of its own, so naming it would name a line the listing does
    // not print -- the one thing HIL may never do.
    if (value.def != nullptr && is_result_width(*value.def))
      return operand(*value.def, 0, depth + 1);

    if (!folds_into_its_use(value)) return variable(value);

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

  // ---- the return value --------------------------------------------------

  // A RETURN says where it goes and never what it hands back. Which register
  // the value is in is the convention's answer -- `RAX` here, `x0` there --
  // and the value itself is whatever the last write to that register left.
  //
  // That is a question SSA has already answered, and answering it again with a
  // reaching-definitions map would be answering it twice. A register is
  // tracked, so if two paths arrive at the return with different values in it,
  // the returning block *has* a phi for it and the phi is the answer; if one
  // path does, the last op in the block that writes the register is. Nothing
  // else can reach, because the block ends the function.
  void find_return_values() {
    return_values_.clear();
    returned_.clear();
    if (result_storage_.space == kNoSpace) return;

    fn_.for_each_op([&](const SsaOp &op) {
      if (op.opc != Op::RETURN) return;

      const SsaOp *def = last_write_to_result(op);
      if (def == nullptr || def->out == nullptr) return;
      // A fill is hidden as a matter of course, and being hidden is no reason
      // to refuse it: it is the one line in the listing the return may speak
      // for, because it says only what the register's width is.
      if (hidden_.count(def->id) != 0 && !is_result_width(*def)) return;

      const ReturnPath path = trace_return(*def->out);

      // The value has to exist for the return and for nothing else. A value
      // the function also reads is a working value that happens to be sitting
      // in the result register when control leaves, and calling it the result
      // would be inventing a return for a function that has none:
      //
      //     void v9(int a) { volatile int b = a * 3; sink = b; }
      //
      // multiplies into EAX because EAX is free, stores the product through
      // it, and returns with it still there. The store reads the product, so
      // the product was not produced for the return, and the listing shows
      // this function returning nothing -- which is what it does.
      const std::set<const SsaOp *> way_back(path.plumbing.begin(),
                                             path.plumbing.end());
      bool only_for_the_return = true;
      for (const SsaValue *value : path.computed)
        if (read_by_the_listing(*value, way_back)) only_for_the_return = false;

      if (!only_for_the_return) {
        // Then the return says nothing, and neither do the ops that put a
        // value in the result register on the way to it: a phi over branches
        // that compute nothing is a merge of nothing. They go as a group, like
        // a saved register's trip through the stack, and only where the
        // listing is not reading them.
        for (const SsaOp *op : path.plumbing)
          if (op->out != nullptr && op->out->uses.empty())
            hidden_.insert(op->id);
        return;
      }

      return_values_[op.id] = def;

      // Some definitions keep their line whatever the return does with the
      // value. A phi is written by build_block's own loop, so its line is
      // never in question. A call is the same case for a different reason: it
      // is a side effect, and the line the answer came from is the line the
      // call happened on -- moving it onto the return would move the call.
      //
      // Anything else loses its line to the return -- unless an analysis had
      // something to say about it, because a comment belongs to the line it
      // was made about: `[0xc].4 ; 0xc -> "literal pool target"` is what makes
      // a load of a pool entry readable, and a comment about a line the
      // listing no longer prints is a comment about nothing.
      if (def->is_phi || def->opc == Op::CALL || def->opc == Op::CALLIND) return;
      if (ctx_.annotations != nullptr &&
          !ctx_.annotations->comments(*def).empty())
        return;
      returned_.insert(def->id);
    });
  }

  // Where the convention puts the result. Everything about returns is keyed on
  // this register, and the elision of its widening is too, so it is worked out
  // before either.
  void find_result_storage() {
    result_storage_ = Varnode{};
    if (ctx_.abi() == nullptr || ctx_.translator() == nullptr) return;
    result_storage_ = register_storage(*ctx_.translator(), *ctx_.spaces(),
                                       ctx_.abi()->result);
  }

  // The widening of the result register into itself.
  //
  // A 32-bit result lives in four bytes of an eight-byte register, so Sleigh
  // writes both -- `EAX = a * b ; RAX = INT_ZEXT EAX` -- and the second write
  // is the register's width being stated rather than something the program
  // did. Every 32-bit assignment in a function has one, which is why the
  // listing cannot afford to show them: `RAX = zx.8(EAX)` is a line that says
  // nothing, twice over.
  //
  // The narrower value is what the register holds, and reading one is reading
  // the other -- see value_of() and plan_elisions(). The same is true the other
  // way round: reading four bytes of an eight-byte register's answer, which is
  // the form every 32-bit use of a call takes, is reading the answer, and the
  // statement saying so is one SSA construction wrote rather than Sleigh.
  bool is_result_width(const SsaOp &op) const {
    if (result_storage_.space == kNoSpace || op.out == nullptr) return false;
    if (!same_register(op.out->storage, result_storage_)) return false;

    // Both directions are one input read at another width of the same
    // register, and only that. Anything else is an operation.
    const auto restates = [&](const SsaValue &inner) {
      return same_register(inner.storage, op.out->storage) &&
             inner.storage.size != op.out->storage.size;
    };

    // Widening into the register: `RAX = INT_ZEXT EAX`.
    if (op.ins.size() == 1 && op.ins[0].is_tracked())
      return restates(*op.ins[0].value);

    // Narrowing out of it: the low bytes, which is what reading a register's
    // half is. Shift zero, or it is a real extract of some other field.
    if (op.ins.size() == 2 && op.opc == Op::SUBPIECE && op.ins[1].is_constant() &&
        op.ins[1].constant() == 0 && op.ins[0].is_tracked())
      return restates(*op.ins[0].value);

    return false;
  }

  // What a return is made of. Following the result register back crosses two
  // kinds of op that are not statements of the program -- the fill above and
  // the phi that merges the paths onto the register -- and stops at the values
  // the function computed.
  //
  // The distinction is the whole point: those values are what the return is
  // about, and a phi or a fill in between says nothing about them that the
  // register's own storage did not already say.
  struct ReturnPath {
    std::vector<const SsaOp *> plumbing;   // fills and phis on the way back
    std::vector<const SsaValue *> computed; // what the walk stopped at
  };

  ReturnPath trace_return(const SsaValue &root) {
    ReturnPath path;
    std::vector<const SsaValue *> work{&root};
    std::set<const SsaValue *> seen;

    while (!work.empty()) {
      const SsaValue *value = work.back();
      work.pop_back();
      if (value == nullptr || !seen.insert(value).second) continue;

      const SsaOp *def = value->def;
      if (def != nullptr && def->is_phi) {
        path.plumbing.push_back(def);
        for (const SsaOperand &in : def->ins)
          if (in.is_tracked()) work.push_back(in.value);
        continue;
      }
      if (def != nullptr && is_result_width(*def)) {
        path.plumbing.push_back(def);
        work.push_back(def->ins[0].value);
        continue;
      }

      // A constant depends on nothing, so there is nothing to ask about it; a
      // live-in was handed to the function rather than computed by it, so
      // there is plenty to ask.
      if (def == nullptr || !is_constant_def(*def)) path.computed.push_back(value);
    }
    return path;
  }

  // Whether anything besides the return reads this value. A use that was
  // elided is not a read: a push and its pop, the stack pointer's own
  // arithmetic and the address of a frame slot are all bookkeeping the listing
  // summarises rather than shows, and a value they carry is not one the
  // program works with. The result register's widening is the same kind of
  // thing -- it restates a value rather than reading it -- whether or not this
  // listing is showing it. And the ops the return itself is made of are the
  // return reading the value, which is the one read that does not disqualify
  // it.
  bool read_by_the_listing(const SsaValue &value,
                           const std::set<const SsaOp *> &way_back) const {
    for (const SsaOp *use : value.uses) {
      if (way_back.count(use) != 0) continue;
      if (hidden_.count(use->id) == 0 && !is_result_width(*use)) return true;
    }
    return false;
  }

  // The last thing that put a value in the result register before this return,
  // looking in the block that holds it. A phi is looked at first because it is
  // at the top of its block and every op below it shadows it.
  const SsaOp *last_write_to_result(const SsaOp &ret) const {
    const SsaBlock &block = fn_[ret.block];

    const SsaOp *found = nullptr;
    for (const SsaOp *phi : block.phis)
      if (writes_result_register(*phi)) found = phi;

    for (const SsaOp *op : block.ops) {
      if (op == &ret) break;
      if (writes_result_register(*op)) found = op;
    }
    return found;
  }

  // Whether this op writes the result register. Matched by space and offset
  // rather than by the storage itself, so that a write to the low half counts:
  // a 32-bit function returns four bytes and whether Sleigh names that write
  // `RAX` or `EAX` is a detail of the spec, not a difference in the program.
  bool writes_result_register(const SsaOp &op) const {
    if (op.out == nullptr) return false;
    return op.out->storage.space == result_storage_.space &&
           op.out->storage.offset == result_storage_.offset;
  }

  // The expression a return hands back.
  //
  // Widening the result register into itself is the convention's doing and not
  // the program's, so the expression is the value below it -- see
  // expression_for(), which is where a fill stops being an operation at all.
  // What is left here is the same question one register over: a widening that
  // arrives from somewhere else, `RAX = INT_SEXT EDI`, which may be the
  // convention's or the source's.
  //
  // What it costs: `return x` and `return (long)x` compile to the same two
  // instructions, and without a prototype nothing in the p-code tells them
  // apart. So the value without the cast is what the reader is shown, and the
  // width the register was filled from is on the value itself.
  ExprRef returned_expression(const SsaOp &def) {
    ExprRef value = expression_for(def, 0);
    if (value == nullptr || def.out == nullptr) return value;

    const unsigned filled = def.out->storage.size;
    if (value->kind == ExprKind::Cast && value->size == filled &&
        operand_size(def, 0) < filled)
      return value->operands.front();
    return value;
  }

  // What a return hands back: the expression, or the name of it when the line
  // that computes it is one the listing prints above.
  ExprRef return_value(const SsaOp &def) {
    if (def.out == nullptr) return nullptr;
    if (!returned_.count(def.id)) return variable(*def.out);
    return returned_expression(def);
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
  //
  // Only for slots the program uses. The address of a save slot is owned by
  // find_saved_slots() below, which may have to keep it.
  bool defines_slot_address(const SsaOp &op) const {
    if (op.out == nullptr || ctx_.annotations == nullptr) return false;

    return names_slot(ctx_.annotations->address_kind(*op.out));
  }

  // Bookkeeping the machine does that the program did not ask for: keeping the
  // stack pointer up to date, and pushing a return address as part of making a
  // call. Both are real, both are already summarised elsewhere (the frame
  // layout, the call itself), and shown in full they bury everything else --
  // `RSP_122 = phi(RSP_79, RSP_121)` is not what anyone came to read.
  bool is_bookkeeping(const SsaOp &op) const {
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
    if (op.opc == Op::STORE && call_addresses_.count(op.addr) != 0) return true;

    return false;
  }

  // ---- what this listing leaves out --------------------------------------
  //
  // All of it serves one rule:
  //
  //   a name may be printed only if the line defining it is printed.
  //
  // Bookkeeping is left out and summarised instead -- `; frame:` for the
  // layout, `; saves:` for preserved registers -- which is a lie the moment a
  // line that *is* printed reads something the listing never defines. That is
  // exactly what `push rbx; pop rbx; ret` printed: `RBX = saved_RBX`, a
  // function that loads a variable out of nowhere. The push and the address it
  // writes through were dropped as bookkeeping, the pop folded into the copy
  // that lands the value in RBX, and the one line left named the slot the
  // dropped pair had filled.
  //
  // So the two halves of a save go as a pair or stay as a pair:
  //
  //  * nothing but the pair itself reads what the restore produced -- the
  //    register is being given back and the listing can say so in one word, so
  //    the address, the store, the load and the copy out of it all go;
  //  * anything else reads it -- then the restore is work the program does,
  //    and every line of the pair stays, including the address, because that
  //    is the line that defines the name the load is written with.
  //
  // The question is asked once per function rather than per op because the
  // answer is not a property of any single op: it is whether something
  // *outside* the group depends on it. Which is why an op cannot be judged by
  // looking at itself, and why this runs before any statement is built.

  // Keyed by the slot's name, not by an SSA value: the two accesses reach the
  // same slot through values of their own -- the pop's address is a copy of
  // the push's -- and they are the same slot because `stack_vars` gave them
  // the same label, which is the only thing that says so.
  struct SavedSlot {
    std::set<OpId> ops; // the accesses, the addresses they use, the copies out
    bool read = false;  // something that is neither reads what they produced
  };

  // A call instruction lowers to the push of its own return address as well as
  // the transfer: those ops share the call's address. Collected over the whole
  // function, because it is a property of the addresses in it and not of any
  // one block.
  void collect_call_addresses() {
    for (int b = 0; b < fn_.size(); ++b)
      for (const SsaOp *op : fn_[BlockId{b}].ops)
        if (op->opc == Op::CALL || op->opc == Op::CALLIND || op->opc == Op::RETURN)
          call_addresses_.insert(op->addr);
  }

  // Groups a preserved register's trip through the stack and decides whether
  // the listing can afford to leave it out. Fills `hidden_`, which is the
  // whole answer to what gets a line.
  void plan_elisions() {
    hidden_.clear();
    if (!hides_machine_state()) return;

    find_saved_slots();

    for (int b = 0; b < fn_.size(); ++b)
      for (const SsaOp *op : fn_[BlockId{b}].ops) {
        // A width of the result register restated: the widening Sleigh writes
        // after a 32-bit result, and the narrowing that is how a 32-bit read
        // of the convention's answer is spelled. Neither is an operation, and
        // the value is the one below either way -- the return line carries it
        // when it is the result, and when it is not, there is nothing there to
        // say.
        if (is_result_width(*op)) {
          hidden_.insert(op->id);
          continue;
        }
        // What the callee left in a register it does not preserve. The call
        // line is where that happened and the reader has the call to look at;
        // `RCX = unknown` underneath it would spend a line saying that
        // something is unknown, which the call already said.
        if (op->is_clobber) {
          hidden_.insert(op->id);
          continue;
        }
        // The group decides for itself first, and outright: some of its ops
        // are bookkeeping on their own account and some are not, and a group
        // that is shown has to be shown whole.
        if (member_.count(op->id) != 0) {
          if (!saved_slots_[member_[op->id]].read) hidden_.insert(op->id);
          continue;
        }
        if (is_bookkeeping(*op) || defines_slot_address(*op))
          hidden_.insert(op->id);
      }
  }

  void find_saved_slots() {
    if (ctx_.annotations == nullptr) return;

    // Every access stack-vars called bookkeeping, and the address it goes
    // through. The address itself is part of the group too -- it is a line
    // naming the slot when the group is shown, and it is the line the load is
    // written with.
    fn_.for_each_op([&](const SsaOp &op) {
      if ((op.opc != Op::LOAD && op.opc != Op::STORE) || op.ins.size() < 2)
        return;
      if (!ctx_.annotations->is_plumbing(op)) return;
      if (!op.ins[1].is_tracked()) return;

      const SsaValue &address = *op.ins[1].value;
      if (!names_slot(ctx_.annotations->address_kind(address))) return;

      const std::string &label = ctx_.annotations->label(address);

      join(label, op);
      if (address.def != nullptr) join(label, *address.def);
      if (op.opc == Op::LOAD && op.out != nullptr) carries_[op.out->id] = label;
    });

    // Out through the copies. Sleigh's `pop` names the register through a
    // temporary, so the value the program ends up with is a copy of the load,
    // and a group that stopped at the load would leave that copy -- the line
    // that names the register -- behind.
    //
    // Only what came out of the slot, never the address: a copy of the address
    // is the stack pointer being moved along, and following it would pull
    // every access in the frame into the group and keep every save in the
    // listing.
    bool changed = true;
    while (changed) {
      changed = false;
      fn_.for_each_op([&](const SsaOp &op) {
        if (op.opc != Op::COPY || op.ins.size() != 1 || op.out == nullptr)
          return;
        if (!op.ins[0].is_tracked() || member_.count(op.id) != 0) return;

        auto known = carries_.find(op.ins[0].value->id);
        if (known == carries_.end()) return;

        join(known->second, op);
        carries_[op.out->id] = known->second;
        changed = true;
      });
    }

    // And the question: does anything that is neither the group nor the
    // machine itself read what came out of the slot?
    for (const auto &entry : carries_)
      for (const SsaOp *use : fn_.value(entry.first).uses) {
        if (member_.count(use->id) != 0) continue;
        if (is_bookkeeping(*use)) continue;
        if (!shows(entry.first, *use)) continue;
        saved_slots_[entry.second].read = true;
      }
  }

  // Whether a line for this op would read that value.
  //
  // Only the operands the statement builds an expression from count, and that
  // is not all of them. A `ret` carries the return address in an operand, but
  // the address is one the machine put on the stack and the listing already
  // says where it came from -- counting it would put the save of a frame
  // pointer back into every function that has one.
  static bool shows(ValueId value, const SsaOp &use) {
    for (size_t i = 0; i < use.ins.size(); ++i) {
      if (!use.ins[i].is_tracked() || use.ins[i].value->id != value)
        continue;
      switch (use.opc) {
      case Op::RETURN:
      case Op::BRANCH:
        return false;
      case Op::STORE:
        return i == 1 || i == 2; // the address and the value
      case Op::CBRANCH:
        return i == 1; // the condition
      default:
        return true;
      }
    }
    return false;
  }

  void join(const std::string &slot, const SsaOp &op) {
    saved_slots_[slot].ops.insert(op.id);
    member_[op.id] = slot;
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

  // Whether anything this listing prints ends up reading this value.
  //
  // Not the same question as "does anything use it": a width restatement and a
  // hidden merge are elisions, not ends, so a value read only through them is
  // read by whatever reads the other end. That is the path a call's answer
  // takes to a 32-bit use -- `RAX = call f()` then `EAX = SUBPIECE RAX 0` --
  // and stopping at the restatement would report the answer as unwanted and
  // then print a line reading a name nothing defines.
  bool reaches_a_printed_line(const SsaValue &value) const {
    std::set<const SsaValue *> seen;
    std::vector<const SsaValue *> work{&value};

    while (!work.empty()) {
      const SsaValue *current = work.back();
      work.pop_back();
      if (current == nullptr || !seen.insert(current).second) continue;

      for (const SsaOp *use : current->uses) {
        if (hidden_.count(use->id) == 0) return true;
        if (use->out != nullptr && (is_result_width(*use) || use->is_phi))
          work.push_back(use->out);
      }
    }
    return false;
  }

  bool folds_into_its_use(const SsaValue &value) const {
    if (value.def == nullptr || value.def->is_phi) return false;
    if (is_machine_flag(value)) return false;

    // Nothing the listing left out folds into what it prints. A fold is
    // exactly how a name travels from a line that is not there into one that
    // is, which is the thing plan_elisions() exists to prevent.
    if (hidden_.count(value.def->id) != 0) return false;

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

    // And it does not fold into a line the listing is not printing either,
    // unless the listing accounts for that line somewhere else. Every other
    // elision here is summarised -- the saved registers by `; saves:`, the
    // frame slots by `; frame:` -- and folding into one of them is how a value
    // reaches its summary. The widening of the result register is the one
    // elision with nothing behind it, so a value folded into it is a value
    // gone: what the register was filled with shows under the register's own
    // name, unless a return is carrying it on the return line.
    if (hidden_.count(use.id) != 0 && is_result_width(use) &&
        returned_.count(use.id) == 0)
      return false;

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
    // A width of the result register restated is not an operation: the
    // register is eight bytes, the value is four, and the width is the
    // convention's business. What it holds is the value below it.
    if (is_result_width(op)) return operand(op, 0, depth + 1);

    // What a call left in a register. Reached only where the machine-state
    // view is showing the call's effects one at a time; the value itself is
    // spelled the same way wherever it is read.
    if (op.is_clobber) return unknown(op.out != nullptr ? op.out->storage.size : 0);

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

    // A product Sleigh widened and cut back down is the product. This has to
    // come before the branch below, which is the one that would otherwise spell
    // out the truncation this removes.
    if (ExprRef product = widened_product(op, depth)) return product;

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

  // `trunc.4(sx.8(a) * sx.8(b))` is `a * b`.
  //
  // x86's `imul` widens both operands to double width, multiplies, and keeps
  // the low half -- which is the low half of a product it had to widen to
  // produce, since the low half of the wide product *is* the product. `mul`
  // lowers the same way from zero extensions, and which extension it is does
  // not change that, so both are matched. What a reader gets back is the
  // multiplication they wrote, without the 64-bit arithmetic wrapped around it.
  //
  // The width is the whole of the soundness argument, and it is why this is
  // here rather than a rule in the rewrite table: a rule is a pattern and an
  // expression, and this needs a fact about two widths agreeing. The
  // truncation has to come back to exactly the width the operands were widened
  // from. `trunc.4(sx.16(a) * sx.16(b))` is the low four bytes of a
  // sixteen-byte product, and calling it `a * b` is right only while `a` is
  // four bytes; were it eight, the same shape would be a real truncation.
  ExprRef widened_product(const SsaOp &op, int depth) {
    if (op.out == nullptr) return nullptr;

    Match m;
    if (!matches_widened_product(op, m)) return nullptr;

    const unsigned width = op.out->storage.size;
    const SsaValue *left = m.value(0);
    const SsaValue *right = m.value(1);
    if (left == nullptr || right == nullptr) return nullptr;
    if (left->storage.size != width || right->storage.size != width)
      return nullptr;

    return binary("*", kMultiplicative, value_of(*left, depth + 1),
                  value_of(*right, depth + 1));
  }

  // The shape, in the same pattern language the rewrite table is written in,
  // which is what follows the COPYs between the truncation and the multiply.
  // Two patterns rather than one because the language has no "either".
  static bool matches_widened_product(const SsaOp &candidate, Match &m) {
    // `pat::` on every name: the parameter above is an SsaOp called `op`, and
    // an unqualified `op(...)` would be a call to it.
    static const Pattern sign_extended =
        pat::op(Op::SUBPIECE,
                {pat::op(Op::INT_MULT,
                         {pat::op(Op::INT_SEXT, {pat::val(0)}),
                          pat::op(Op::INT_SEXT, {pat::val(1)})}),
                 pat::imm(0)});
    static const Pattern zero_extended =
        pat::op(Op::SUBPIECE,
                {pat::op(Op::INT_MULT,
                         {pat::op(Op::INT_ZEXT, {pat::val(0)}),
                          pat::op(Op::INT_ZEXT, {pat::val(1)})}),
                 pat::imm(0)});

    return sign_extended.match(candidate, m) || zero_extended.match(candidate, m);
  }

  // ---- statements --------------------------------------------------------

  void build_block(BlockId block) {
    std::vector<Statement> &out = hil_.blocks_[block].statements;
    const BasicBlock &raw = fn_.cfg()[block];

    for (const SsaOp *phi : fn_[block].phis) {
      // A phi the listing took out is out here as well -- the stack pointer's
      // own, and the merge of a result register whose value is not the
      // function's result.
      if (hidden_.count(phi->id) != 0) continue;
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

    for (const SsaOp *op : fn_[block].ops) {
      if (op->out != nullptr && folds_into_its_use(*op->out)) continue;
      if (hidden_.count(op->id) != 0) continue;
      // Computed the function's result and nothing else: the value is on the
      // return line, where the reader wants it, and a second line naming it
      // would be the same value twice.
      if (returned_.count(op->id) != 0) continue;
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
      // A call that produces something says so, the way any other assignment
      // does: the value comes back in the convention's result register and
      // every read of it below is this line's answer. A call nobody takes a
      // result from -- `puts` -- is left bare, which is what the source said.
      if (op.out != nullptr && reaches_a_printed_line(*op.out))
        statement.target_text = display_name(*op.out);
      return statement;

    case Op::RETURN: {
      statement.kind = StatementKind::Return;
      const auto known = return_values_.find(op.id);
      if (known != return_values_.end())
        statement.value = return_value(*known->second);
      return statement;
    }

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

  // What plan_elisions() decided, plus the groups it decided with.
  std::set<OpId> hidden_;
  std::map<std::string, SavedSlot> saved_slots_;
  std::map<OpId, std::string> member_;    // op -> the slot it belongs to
  std::map<ValueId, std::string> carries_; // value -> the slot it came out of
  std::set<uint64_t> call_addresses_;

  // What find_return_values() worked out: the value each return hands back,
  // and which of the ops computing one lost its line to the return.
  std::map<OpId, const SsaOp *> return_values_;
  std::set<OpId> returned_;
  Varnode result_storage_{};

  Varnode stack_pointer_{};
};

} // namespace detail

Hil build_hil(const SsaFunction &fn, const PassContext &ctx) {
  Hil hil;
  detail::HilBuilder(fn, ctx, hil).run();
  return hil;
}

} // namespace ddd
