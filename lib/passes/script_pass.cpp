// script passes -- `--passes=py:name-strings.py`
//
// The function goes out as JSON, because that is what a Python script wants
// to receive; the reply comes back as one directive per line, because that is
// what is pleasant to *write* from Python and trivial to parse here. The
// asymmetry is deliberate -- it means no JSON parser in this binary and no
// serialisation library in the script.
//
//   $ cat name-strings.py
//   import json, sys
//   fn = json.load(sys.stdin)
//   for op in fn["ops"]:
//       if op["opcode"] == "COPY" and op.get("out") is not None:
//           print(f"comment {op['id']} touched by a script")
//
// Directives (unknown ones are reported and ignored):
//   comment <op-id> <text>
//   block-comment <block-id> <text>
//   label <value-id> <text>
//
// A script is not registered in the pass registry -- it is named by path at
// the point of use, so there is nothing to install and nothing to rebuild.
#include "passes/pass.h"
#include "base/script.h"

#include <iomanip>
#include <ostream>
#include <sstream>

namespace ddd {
namespace {

void write_escaped(std::ostringstream &os, const std::string &text) {
  os << '"';
  for (char c : text) {
    switch (c) {
    case '"':
      os << "\\\"";
      break;
    case '\\':
      os << "\\\\";
      break;
    case '\n':
      os << "\\n";
      break;
    case '\t':
      os << "\\t";
      break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        os << "\\u" << std::hex << std::setw(4) << std::setfill('0')
           << static_cast<int>(static_cast<unsigned char>(c)) << std::dec;
      } else {
        os << c;
      }
    }
  }
  os << '"';
}

void write_operand(std::ostringstream &os, const PassContext &ctx,
                   const SsaOp &op, size_t index) {
  const SsaOperand &in = op.ins[index];
  os << "{";
  os << "\"text\":";
  write_escaped(os, ctx.name_of(op, index));
  if (in.is_tracked()) {
    os << ",\"value\":" << in.value->id;
  } else if (in.is_constant()) {
    os << ",\"constant\":" << in.constant();
  }
  os << ",\"size\":" << in.raw.size;
  os << "}";
}

std::string to_json(const SsaFunction &fn, const PassContext &ctx) {
  std::ostringstream os;
  os << "{";

  os << "\"target\":";
  write_escaped(os, ctx.target != nullptr ? ctx.target->name : std::string());

  os << ",\"blocks\":[";
  bool first_block = true;
  for (const SsaBlock &block : fn.blocks()) {
    if (!first_block)
      os << ",";
    first_block = false;

    const BasicBlock &raw = fn.cfg()[block.id];
    os << "{\"id\":" << block.id;
    os << ",\"start\":" << raw.start;
    os << ",\"preds\":[";
    for (size_t i = 0; i < raw.preds.size(); ++i)
      os << (i ? "," : "") << raw.preds[i];
    os << "],\"succs\":[";
    for (size_t i = 0; i < raw.succs.size(); ++i)
      os << (i ? "," : "") << raw.succs[i].target;
    os << "]}";
  }
  os << "]";

  os << ",\"ops\":[";
  bool first_op = true;
  fn.for_each_op([&](const SsaOp &op) {
    if (!first_op)
      os << ",";
    first_op = false;

    os << "{\"id\":" << op.id;
    os << ",\"block\":" << op.block;
    os << ",\"address\":" << op.addr;
    os << ",\"opcode\":";
    write_escaped(os, op_name(op.opc));
    os << ",\"phi\":" << (op.is_phi ? "true" : "false");

    if (op.out != nullptr) {
      os << ",\"out\":" << op.out->id;
      os << ",\"out_name\":";
      write_escaped(os, ctx.name_of(*op.out));
    } else {
      os << ",\"out\":null";
    }

    const Instruction *instr = fn.cfg().instruction_at(op.addr);
    if (instr != nullptr) {
      os << ",\"instruction\":";
      write_escaped(os, instr->text);
    }

    os << ",\"ins\":[";
    for (size_t i = 0; i < op.ins.size(); ++i) {
      if (i)
        os << ",";
      write_operand(os, ctx, op, i);
    }
    os << "]}";
  });
  os << "]";

  os << ",\"values\":[";
  for (int i = 0; i < fn.value_count(); ++i) {
    const SsaValue &value = fn.value(ValueId{i});
    if (i)
      os << ",";
    os << "{\"id\":" << value.id;
    os << ",\"name\":";
    write_escaped(os, ctx.name_of(value));
    os << ",\"size\":" << value.storage.size;
    os << ",\"live_in\":" << (value.is_live_in() ? "true" : "false");
    os << ",\"uses\":" << value.uses.size();
    os << "}";
  }
  os << "]}";

  return os.str();
}

// One directive per line: <verb> <id> <text...>
int apply(const std::string &reply, SsaFunction &fn, PassContext &ctx) {
  std::istringstream lines(reply);
  std::string line;
  int applied = 0;

  while (std::getline(lines, line)) {
    if (line.empty() || line[0] == '#')
      continue;

    std::istringstream fields(line);
    std::string verb;
    int id = -1;
    fields >> verb >> id;
    if (!fields) {
      ctx.say("ignoring malformed directive: " + line);
      continue;
    }

    std::string text;
    std::getline(fields, text);
    if (!text.empty() && text.front() == ' ')
      text.erase(0, 1);

    if (verb == "comment") {
      if (id < 0 || id >= fn.op_count()) {
        ctx.say("no such op: " + std::to_string(id));
        continue;
      }
      ctx.knowledge->comment(fn.op(OpId{id}), text);
    } else if (verb == "block-comment") {
      if (id < 0 || id >= fn.size()) {
        ctx.say("no such block: " + std::to_string(id));
        continue;
      }
      ctx.knowledge->comment_block(BlockId{id}, text);
    } else if (verb == "label") {
      if (id < 0 || id >= fn.value_count()) {
        ctx.say("no such value: " + std::to_string(id));
        continue;
      }
      ctx.knowledge->set_label(fn.value(ValueId{id}), text);
    } else {
      ctx.say("unknown directive: " + verb);
      continue;
    }
    ++applied;
  }

  return applied;
}

class ScriptPass final : public Pass {
public:
  explicit ScriptPass(std::string path) : path_(std::move(path)) {}

  std::string name() const override { return "py:" + path_; }
  std::string description() const override { return "external script pass"; }

  void run(SsaFunction &fn, PassContext &ctx) override {
    std::string json = to_json(fn, ctx);
    std::vector<uint8_t> input(json.begin(), json.end());

    ScriptResult result = run_script(interpreter_for(path_), input);
    if (!result.ok) {
      ctx.say(path_ + ": " + result.error);
      return;
    }

    // Directives the script got wrong are reported by apply() through the same
    // channel: a script is a pass like any other, and the listing is the only
    // thing that should reach the stream.
    std::string reply(result.output.begin(), result.output.end());
    applied_ = apply(reply, fn, ctx);
  }

  std::vector<std::string> report(const SsaFunction &,
                                  const PassContext &) const override {
    return {"applied " + std::to_string(applied_) + " directive(s)"};
  }

private:
  std::string path_;
  int applied_ = 0;
};

} // namespace

std::unique_ptr<Pass> make_script_pass(const std::string &path) {
  return std::make_unique<ScriptPass>(path);
}

} // namespace ddd
