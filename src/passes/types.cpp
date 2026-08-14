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
#include "../pass.h"
#include "../project.h"

#include "opcodes.hh"

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
bool signed_op(OpCode opc) {
  switch (opc) {
  case ghidra::CPUI_INT_SLESS:
  case ghidra::CPUI_INT_SLESSEQUAL:
  case ghidra::CPUI_INT_SRIGHT:
  case ghidra::CPUI_INT_SEXT:
  case ghidra::CPUI_INT_SDIV:
  case ghidra::CPUI_INT_SREM:
  case ghidra::CPUI_INT_SBORROW:
  case ghidra::CPUI_INT_SCARRY:
    return true;
  default:
    return false;
  }
}

bool unsigned_op(OpCode opc) {
  switch (opc) {
  case ghidra::CPUI_INT_LESS:
  case ghidra::CPUI_INT_LESSEQUAL:
  case ghidra::CPUI_INT_RIGHT:
  case ghidra::CPUI_INT_ZEXT:
  case ghidra::CPUI_INT_DIV:
  case ghidra::CPUI_INT_REM:
  case ghidra::CPUI_INT_CARRY:
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

    gather(fn, ctx);
    spread(fn);
    gather_slots(fn, ctx);
    report(fn, ctx);
  }

private:
  Evidence *of(const SsaOperand &operand) {
    return operand.is_tracked() ? &evidence_[operand.value->id] : nullptr;
  }

  void gather(SsaFunction &fn, PassContext &ctx) {
    fn.for_each_op([&](SsaOp &op) {
      // An address operand is a pointer, and the access width says to what.
      if (op.opc == ghidra::CPUI_LOAD && op.ins.size() >= 2) {
        if (Evidence *address = of(op.ins[1])) {
          address->pointer = true;
          if (op.out != nullptr) address->pointee = op.out->storage.size;
        }
      }
      if (op.opc == ghidra::CPUI_STORE && op.ins.size() >= 3) {
        if (Evidence *address = of(op.ins[1])) {
          address->pointer = true;
          address->pointee = op.ins[2].raw.size;
        }
      }

      // The condition of a branch is a truth value.
      if (op.opc == ghidra::CPUI_CBRANCH && op.ins.size() >= 2)
        if (Evidence *condition = of(op.ins[1])) condition->boolean = true;

      const bool is_signed = signed_op(op.opc);
      const bool is_unsigned = unsigned_op(op.opc);
      const bool is_boolean = op.opc == ghidra::CPUI_BOOL_AND ||
                              op.opc == ghidra::CPUI_BOOL_OR ||
                              op.opc == ghidra::CPUI_BOOL_XOR ||
                              op.opc == ghidra::CPUI_BOOL_NEGATE;

      for (const SsaOperand &in : op.ins) {
        Evidence *operand = of(in);
        if (operand == nullptr) continue;
        operand->is_signed |= is_signed;
        operand->is_unsigned |= is_unsigned;
        operand->boolean |= is_boolean;
      }

      // A comparison yields a truth value whatever its operands were.
      if (op.out != nullptr &&
          (is_boolean || op.opc == ghidra::CPUI_INT_EQUAL ||
           op.opc == ghidra::CPUI_INT_NOTEQUAL || is_signed || is_unsigned))
        if (op.out->storage.size == 1) evidence_[op.out->id].boolean = true;

      // A constant that lands on a function or a string is that kind of
      // pointer; data-refs and symbols already worked out which.
      if (op.out != nullptr && ctx.annotations != nullptr) {
        for (const std::string &comment : ctx.annotations->comments(op)) {
          if (comment.rfind("&", 0) == 0) evidence_[op.out->id].code = true;
          if (comment.find(" -> \"") != std::string::npos)
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

        const bool additive = op.opc == ghidra::CPUI_INT_ADD ||
                              op.opc == ghidra::CPUI_INT_SUB;
        const bool copy = op.opc == ghidra::CPUI_COPY ||
                          op.opc == ghidra::CPUI_INT_ZEXT ||
                          op.opc == ghidra::CPUI_INT_SEXT || op.is_phi;
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
    if (ctx.annotations == nullptr) return;

    auto slot_of = [&](const SsaOperand &address) -> const std::string * {
      if (!address.is_tracked()) return nullptr;
      const std::string &label = ctx.annotations->label(*address.value);
      if (!is_slot_label(label)) return nullptr;
      return &label;
    };

    auto merge = [&](const std::string &slot, const Evidence &from) {
      Evidence &into = slots_[slot.substr(1)];
      into.pointer |= from.pointer;
      if (into.pointee == 0) into.pointee = from.pointee;
      into.is_signed |= from.is_signed;
      into.is_unsigned |= from.is_unsigned;
      into.boolean |= from.boolean;
      into.code |= from.code;
      into.text |= from.text;
    };

    fn.for_each_op([&](SsaOp &op) {
      if (op.opc == ghidra::CPUI_LOAD && op.ins.size() >= 2 && op.out != nullptr) {
        if (const std::string *slot = slot_of(op.ins[1]))
          merge(*slot, evidence_[op.out->id]);
      }
      if (op.opc == ghidra::CPUI_STORE && op.ins.size() >= 3) {
        if (const std::string *slot = slot_of(op.ins[1]))
          if (op.ins[2].is_tracked()) merge(*slot, evidence_[op.ins[2].value->id]);
      }
    });
  }

  // Only the variables that survive into the listing are worth naming a type
  // for; everything else folded into an expression.
  void report(SsaFunction &fn, PassContext &ctx) {
    if (ctx.annotations == nullptr) return;

    std::map<std::string, std::string> named;
    for (int i = 0; i < fn.value_count(); ++i) {
      const SsaValue &value = fn.value(i);
      if (!ctx.annotations->has_display_name(value)) continue;

      std::string shown = ctx.annotations->display_name(value);
      if (is_slot_label(shown)) shown.erase(0, 1);

      // The slot's type is the type of what is stored in it, which the
      // pointer evidence on its address already records.
      const Evidence &evidence = evidence_[i];
      unsigned size = value.storage.size;
      Evidence effective = evidence;

      // For a slot, the type wanted is that of its *contents*, gathered above.
      if (is_slot_label(ctx.annotations->display_name(value))) {
        auto contents = slots_.find(shown);
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
      ctx.annotations->comment_block(fn.cfg().entry, comment.str());
    }

    // Everything, when asked: `e verbose=1` in the session, or the batch run.
    if (ctx.verbose) {
      ctx.stream() << "  typed " << named.size() << " variable(s)\n";
      for (const auto &entry : named)
        ctx.stream() << "    " << entry.second << " " << entry.first << "\n";
    }
  }

  std::vector<Evidence> evidence_;
  std::map<std::string, Evidence> slots_;
  std::set<std::string> declared_;
};

DDD_REGISTER_PASS(Types);

} // namespace
} // namespace ddd
