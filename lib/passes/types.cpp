// types -- work out what the variables are, not just how wide they are.
//
// Size comes free from the storage. Everything else has to be inferred from
// how a value is *used*, because a machine register carries no type: the same
// 8 bytes are a pointer, a signed count or a bitfield depending only on which
// instruction reads them next.
//
// So this is evidence-gathering rather than dataflow. Each op says something
// about its operands -- INT_SLESS means both sides are signed, a LOAD means
// its address operand is a pointer to something the width of the result -- and
// the evidence for a value is accumulated over every op that touches it. The
// def-use chains make that cheap: SSA already knows every use of every value.
//
// Pointer-ness then has to spread, because `base + index` is a pointer if
// `base` is, so the whole thing repeats to a fixed point.
//
// What it deliberately does not do: no structs, no arrays, no recovery of a
// pointee's fields. Those need a memory model this does not have. It answers
// "is this a signed integer, an unsigned one, a boolean, or a pointer to
// something N bytes wide", which is most of what makes a listing readable.
#include "passes/pass.h"
#include "facts/slot.h"
#include "app/project.h"

#include <map>
#include <ostream>
#include <set>
#include <sstream>

namespace ddd {
namespace {

struct Evidence {
  bool pointer = false;
  unsigned pointee = 0; // width of what it points at, 0 if unknown
  bool is_signed = false;
  bool is_unsigned = false;
  bool boolean = false;
  bool code = false;   // points at a function
  bool text = false;   // points at a C string
};

// Signed and unsigned operations name themselves in p-code, which is the whole
// reason the distinction is recoverable at all.
bool signed_op(Op op) {
  switch (op) {
  case Op::INT_SLESS:
  case Op::INT_SLESSEQUAL:
  case Op::INT_SRIGHT:
  case Op::INT_SEXT:
  case Op::INT_SDIV:
  case Op::INT_SREM:
  case Op::INT_SBORROW:
  case Op::INT_SCARRY:
    return true;
  default:
    return false;
  }
}

bool unsigned_op(Op op) {
  switch (op) {
  case Op::INT_LESS:
  case Op::INT_LESSEQUAL:
  case Op::INT_RIGHT:
  case Op::INT_ZEXT:
  case Op::INT_DIV:
  case Op::INT_REM:
  case Op::INT_CARRY:
    return true;
  default:
    return false;
  }
}

const char *integer_name(unsigned size, bool is_signed) {
  switch (size) {
  case 1: return is_signed ? "int8_t" : "uint8_t";
  case 2: return is_signed ? "int16_t" : "uint16_t";
  case 4: return is_signed ? "int32_t" : "uint32_t";
  case 8: return is_signed ? "int64_t" : "uint64_t";
  default: return is_signed ? "int" : "unsigned";
  }
}

std::string describe(const Evidence &evidence, unsigned size) {
  if (evidence.code) return "code *";
  if (evidence.text) return "char *";

  if (evidence.pointer) {
    if (evidence.pointee == 0) return "void *";
    return std::string(integer_name(evidence.pointee, false)) + " *";
  }

  if (evidence.boolean && size == 1) return "bool";

  // Unsigned unless something treated it as signed. Both is not a
  // contradiction worth reporting -- C does it constantly.
  return integer_name(size, evidence.is_signed && !evidence.is_unsigned);
}

// How many to put in the header before it stops being a summary.
constexpr int kMaxShown = 12;

// A type worth saying out loud: anything other than "an integer as wide as
// the register it sits in, with no evidence about its sign".
bool informative(const std::string &type) {
  if (type.find('*') != std::string::npos) return true; // pointer of any kind
  if (type == "bool") return true;
  return type.compare(0, 3, "int") == 0; // signed: something compared it
}

class Types final : public Pass {
public:
  std::string name() const override { return "types"; }
  std::string description() const override {
    return "infer signedness, booleans and pointers from how values are used";
  }

  void run(SsaFunction &fn, PassContext &ctx) override {
    evidence_.clear();
    evidence_.resize(fn.value_count());
    slots_.clear();
    declared_.clear();
    named_.clear();

    gather(fn, ctx);
    spread(fn);
    gather_slots(fn, ctx);
    announce(fn, ctx);
  }

private:
  Evidence *of(const SsaOperand &operand) {
    return operand.is_tracked() ? &evidence_[operand.value->id] : nullptr;
  }

  void gather(SsaFunction &fn, PassContext &ctx) {
    fn.for_each_op([&](SsaOp &op) {
      // An address operand is a pointer, and the access width says to what.
      if (op.opc == Op::LOAD && op.ins.size() >= 2) {
        if (Evidence *address = of(op.ins[1])) {
          address->pointer = true;
          if (op.out != nullptr) address->pointee = op.out->storage.size;
        }
      }
      if (op.opc == Op::STORE && op.ins.size() >= 3) {
        if (Evidence *address = of(op.ins[1])) {
          address->pointer = true;
          address->pointee = op.ins[2].raw.size;
        }
      }

      // The condition of a branch is a truth value.
      if (op.opc == Op::CBRANCH && op.ins.size() >= 2)
        if (Evidence *condition = of(op.ins[1])) condition->boolean = true;

      const bool is_signed = signed_op(op.opc);
      const bool is_unsigned = unsigned_op(op.opc);
      const bool is_boolean = op.opc == Op::BOOL_AND ||
                              op.opc == Op::BOOL_OR ||
                              op.opc == Op::BOOL_XOR ||
                              op.opc == Op::BOOL_NEGATE;

      for (const SsaOperand &in : op.ins) {
        Evidence *operand = of(in);
        if (operand == nullptr) continue;
        operand->is_signed |= is_signed;
        operand->is_unsigned |= is_unsigned;
        operand->boolean |= is_boolean;
      }

      // A comparison yields a truth value whatever its operands were.
      if (op.out != nullptr &&
          (is_boolean || op.opc == Op::INT_EQUAL ||
           op.opc == Op::INT_NOTEQUAL || is_signed || is_unsigned))
        if (op.out->storage.size == 1) evidence_[op.out->id].boolean = true;

      // A constant that lands on a function or a string is that kind of
      // pointer; data-refs and symbols already worked out which, and said so
      // as a fact rather than as a sentence this would have to read back.
      if (op.out != nullptr && ctx.knowledge != nullptr) {
        for (const PointsAt &found : ctx.knowledge->points_at(op)) {
          // A *named* function, which is what `&main` says. An unnamed one --
          // a literal pool entry the analysis followed one hop to -- is not
          // taken for a function pointer here, which is what this read before
          // and is the one place the two are not the same question.
          if (found.kind == PointsAt::Kind::Code && !found.text.empty())
            evidence_[op.out->id].code = true;
          if (found.kind == PointsAt::Kind::String)
            evidence_[op.out->id].text = true;
        }
      }
    });
  }

  // `base + index` is a pointer when `base` is, and the result of a copy is
  // whatever was copied. Repeat until nothing new is learned.
  void spread(SsaFunction &fn) {
    for (bool changed = true; changed;) {
      changed = false;

      fn.for_each_op([&](SsaOp &op) {
        if (op.out == nullptr) return;
        Evidence &result = evidence_[op.out->id];

        const bool additive = op.opc == Op::INT_ADD ||
                              op.opc == Op::INT_SUB;
        const bool copy = op.opc == Op::COPY ||
                          op.opc == Op::INT_ZEXT ||
                          op.opc == Op::INT_SEXT || op.is_phi;
        if (!additive && !copy) return;

        for (const SsaOperand &in : op.ins) {
          Evidence *operand = of(in);
          if (operand == nullptr) continue;

          if (operand->pointer && !result.pointer) {
            result.pointer = true;
            result.pointee = operand->pointee;
            changed = true;
          }
          // Backwards too: if the sum is a pointer the base was one.
          if (result.pointer && !operand->pointer && additive && in.raw.size >= 4) {
            operand->pointer = true;
            operand->pointee = result.pointee;
            changed = true;
          }
          if (copy) {
            if (operand->text && !result.text) { result.text = true; changed = true; }
            if (operand->code && !result.code) { result.code = true; changed = true; }
            // Signedness is a property of the value, so a copy of a value
            // compared signed is itself signed -- which is how the evidence
            // reaches a variable that is only ever read into a register first.
            if (operand->is_signed && !result.is_signed) { result.is_signed = true; changed = true; }
            if (result.is_signed && !operand->is_signed) { operand->is_signed = true; changed = true; }
          }
        }
      });
    }
  }

  // A frame slot is not an SSA value, so nothing above ever attributed
  // evidence to it. What it holds is whatever gets loaded out of it and
  // stored into it, so merge the evidence of those.
  void gather_slots(SsaFunction &fn, PassContext &ctx) {
    if (ctx.knowledge == nullptr) return;

    // Keyed by the slot's offset, which is the slot. Two accesses a function
    // computes separately are the same variable, and it is the number they
    // agree on, not a name either of them was spelled with.
    auto slot_of = [&](const SsaOperand &address) -> const Slot * {
      if (!address.is_tracked()) return nullptr;
      return ctx.knowledge->get<Slot>(address.value->id);
    };

    auto merge = [&](int64_t offset, const Evidence &from) {
      Evidence &into = slots_[offset];
      into.pointer |= from.pointer;
      if (into.pointee == 0) into.pointee = from.pointee;
      into.is_signed |= from.is_signed;
      into.is_unsigned |= from.is_unsigned;
      into.boolean |= from.boolean;
      into.code |= from.code;
      into.text |= from.text;
    };

    fn.for_each_op([&](SsaOp &op) {
      if (op.opc == Op::LOAD && op.ins.size() >= 2 && op.out != nullptr) {
        if (const Slot *slot = slot_of(op.ins[1]))
          merge(slot->offset, evidence_[op.out->id]);
      }
      if (op.opc == Op::STORE && op.ins.size() >= 3) {
        if (const Slot *slot = slot_of(op.ins[1]))
          if (op.ins[2].is_tracked())
            merge(slot->offset, evidence_[op.ins[2].value->id]);
      }
    });
  }

  // Only the variables that survive into the listing are worth naming a type
  // for; everything else folded into an expression.
  void announce(SsaFunction &fn, PassContext &ctx) {
    if (ctx.knowledge == nullptr) return;

    std::map<std::string, std::string> named;
    for (int i = 0; i < fn.value_count(); ++i) {
      const SsaValue &value = fn.value(ValueId{i});
      if (!ctx.knowledge->has_display_name(value)) continue;

      // A slot is shown under the name of its address, `&var_18`, and a
      // person naming it in a project file typed the name they saw -- without
      // the '&', which is how the address is spelled and not part of the
      // slot's name.
      const Slot *slot = ctx.knowledge->get<Slot>(value.id);
      std::string shown = ctx.knowledge->display_name(value);
      if (slot != nullptr && !shown.empty() && shown.front() == '&')
        shown.erase(0, 1);

      // The slot's type is the type of what is stored in it, which the
      // pointer evidence on its address already records.
      const Evidence &evidence = evidence_[value.id];
      unsigned size = value.storage.size;
      Evidence effective = evidence;

      // For a slot, the type wanted is that of its *contents*, gathered above.
      if (slot != nullptr) {
        auto contents = slots_.find(slot->offset);
        effective = contents != slots_.end() ? contents->second : Evidence{};
        size = evidence.pointee != 0 ? evidence.pointee : size;
      }

      // A declared type wins outright: inference is evidence, not knowledge.
      const uint64_t function = fn.cfg().code_begin;
      if (ctx.project != nullptr) {
        if (const std::string *declared = ctx.project->type(function, shown)) {
          named.emplace(shown, *declared);
          declared_.insert(shown);
          continue;
        }
      }

      named.emplace(shown, describe(effective, size));
    }

    if (named.empty()) return;

    // Only the types that say something. `uint64_t RAX_37` is the default
    // reading of a 64-bit register and repeating it for every SSA version of
    // every register buries the handful that matter -- the pointers, the
    // strings, the booleans, the things something treated as signed.
    std::ostringstream types;
    int shown = 0;
    int skipped = 0;
    for (const auto &entry : named) {
      // A declared type is shown whatever it is: filtering it out would
      // silently ignore what the user just typed.
      if (declared_.count(entry.first) == 0 && !informative(entry.second)) {
        ++skipped;
        continue;
      }
      if (shown == kMaxShown) {
        ++skipped;
        continue;
      }
      types << " " << entry.second << " " << entry.first << ";";
      ++shown;
    }

    if (shown != 0) {
      std::ostringstream comment;
      comment << "vars:" << types.str();
      if (skipped != 0) comment << " (+" << skipped << " plain)";
      if (fn.cfg().entry)
        ctx.knowledge->comment_block(*fn.cfg().entry, comment.str());
    }

    // Kept rather than described: the block comment above is the summary the
    // listing carries, and the full list is long enough that spelling it out
    // waits until someone asks for a report.
    named_ = std::move(named);
  }

  std::vector<std::string> report(const SsaFunction &,
                                  const PassContext &) const override {
    std::vector<std::string> lines;
    lines.push_back("typed " + std::to_string(named_.size()) + " variable(s)");
    for (const auto &entry : named_)
      lines.push_back("  " + entry.second + " " + entry.first);
    return lines;
  }

private:
  std::map<std::string, std::string> named_;
  std::vector<Evidence> evidence_;
  std::map<int64_t, Evidence> slots_; // by frame offset; see gather_slots()
  std::set<std::string> declared_;
};

DDD_REGISTER_PASS(Types);

} // namespace
} // namespace ddd
