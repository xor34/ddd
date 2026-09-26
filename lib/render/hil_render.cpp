// hil_render.cpp -- turning a built Hil into text, or into tokens.
//
// Two outputs over the same statements, and they are different arrangements of
// them. The text form is for a reader: the blocks are put back into the shape
// the CFG had -- indented, braced, fallthrough unspoken -- by `structure`, and
// what follows the statements is only spelling. The token form is for an
// interface that has to make names clickable, and it is the flat list of blocks
// the Hil is, because that is what the studio draws.
//
// Nothing here decides anything about the function. Every question -- which
// values folded, what a target is, whether a block is reachable -- was answered
// while building, and an answer invented here would be a second one. Even the
// arrangement is not decided here: the walk hands over a tree, and this writes
// it down.
#include "render/hil.h"

#include "render/hil_expr.h"
#include "render/hil_shape.h"

#include <algorithm>
#include <ostream>
#include <sstream>

namespace ddd {
namespace {

// The text of a statement starts here, whatever its address is, so that the
// column belongs to the listing rather than to whichever instruction happened to
// be longest. Six hex digits and the `0x` fill it; a longer address takes the
// space it needs and pushes its own line out rather than the rest.
const int kAddrWidth = 10;

// A block, as the listing names it. Not the number the CFG uses, because a
// number in a jump reads as an operand: `goto 3;` is a hole in the arithmetic
// that happens to have a destination, where `goto L3;` is a place.
std::string label_of(BlockId block) {
  return "L" + std::to_string(block.index);
}

// The margin of a depth, before the address column.
std::string indent(int depth) { return std::string(2 + 2 * depth, ' '); }

// Where the code starts: what a brace or a label is written at, since it has no
// address of its own to put in the column.
std::string code_column(int depth) {
  return indent(depth) + std::string(kAddrWidth, ' ');
}

std::string addr_field(uint64_t addr) {
  std::string field = hex(addr);
  field.append(std::max<size_t>(kAddrWidth, field.size() + 1) - field.size(),
               ' ');
  return field;
}

// The text of a destination outside the function. Its own space needs no
// qualification -- every other address in the listing is in it -- but another
// space must be named, or the destination reads as somewhere it is not.
std::string destination_text(const Addr &leaves_to, SpaceId code_space,
                             const Spaces *spaces) {
  if (spaces == nullptr || leaves_to.space == code_space)
    return hex(leaves_to.offset);
  return to_string(leaves_to, *spaces);
}

// Where a branch goes, as a token and as something an interface can act on.
//
// Three answers, and they are not the same kind of thing. A block in this
// function is a label, and the interface prints the label it gave that block.
// An address outside it is a function -- a tail call is a call, however it is
// spelled -- so it goes out as an address for the interface to name and to
// follow. And a computed destination is genuinely unknown, which is worth
// saying rather than printing as a block that does not exist.
void emit_target(TokenLine &line, const Statement &statement,
                 const PassContext &ctx, const Cfg &cfg) {
  if (statement.taken) {
    line.taken = statement.taken;
    line.tokens.push_back({"block", std::to_string(*statement.taken), ""});
    return;
  }

  if (statement.leaves_to != Addr{}) {
    line.tokens.push_back(
        {"extern",
         destination_text(statement.leaves_to, cfg.code_space, ctx.spaces()), ""});
    // An image address exists only for a destination in this function's own
    // space; the tokens spell out the rest, space included.
    if (statement.leaves_to.space == cfg.code_space)
      line.leaves_to = statement.leaves_to.offset;
    return;
  }

  line.tokens.push_back({"extern", "?", ""});
}

// The same three answers, for the printer that has no interface behind it. A
// branch to a block is only printed when the shape could not take the edge over,
// and in that case the target is an address outside the function rather than a
// block -- so the label arm is the one that cannot happen here, and is kept so
// that a future caller reaching it gets a label rather than a bare number.
std::string target_text(const Statement &statement, const PassContext &ctx,
                        const Cfg &cfg) {
  if (statement.taken)
    return label_of(*statement.taken);
  if (statement.leaves_to != Addr{})
    return destination_text(statement.leaves_to, cfg.code_space, ctx.spaces());
  return "?";
}

// One statement, as the listing spells it. The branch kinds are here because a
// branch the shape could not take over is still a statement, and then it is the
// only thing that can say where that edge goes.
//
// The fallthrough is never printed: an edge that falls is an edge the walk
// followed, so `if (cond) goto 0x401136;` is the whole of what such a branch
// says and the statement after it is where the fall goes.
std::string statement_text(const Statement &statement, const PassContext &ctx,
                           const Cfg &cfg) {
  std::ostringstream line;
  switch (statement.kind) {
  case StatementKind::Assign:
    line << statement.target_text << " = ";
    render(line, statement.value, kLowest);
    break;

  case StatementKind::Store:
    if (const std::string_view slot = slot_name(statement.address);
        !slot.empty()) {
      line << slot << " = ";
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
    line << ") goto " << target_text(statement, ctx, cfg);
    break;

  case StatementKind::Branch:
    line << "goto " << target_text(statement, ctx, cfg);
    break;

  case StatementKind::Call:
    if (!statement.target_text.empty())
      line << statement.target_text << " = ";
    line << "call ";
    render(line, statement.value, kPrimary);
    break;

  case StatementKind::Return:
    line << "return";
    if (statement.value != nullptr) {
      line << ' ';
      render(line, statement.value, kLowest);
    }
    break;

  case StatementKind::Effect:
    render(line, statement.value, kLowest);
    break;
  }
  return line.str();
}

// Writes the tree `structure` built. Nothing is decided here: what is left is
// the address column, the braces, and the notes the passes recorded -- which
// stay beside the statement they are about, because a note that has drifted
// away from its instruction is worse than no note at all.
class Printer {
public:
  Printer(std::ostream &out, const HilShapes &shapes, const SsaFunction &fn,
          const PassContext &ctx)
      : out_(out), shapes_(shapes), ctx_(ctx), cfg_(fn.cfg()) {}

  void run() { lines(shapes_.shapes, 0); }

private:
  // A jump, without its address or its terminator, so that it can be written on
  // a line of its own or after an `if (cond)`.
  //
  // A `do-while` never reaches the `continue` arm. The peephole that makes one
  // fires only when the loop's single way back is the last thing the body does,
  // so a jump to the header from anywhere earlier would have kept the loop a
  // `while (1)` -- and there, going back to the top is exactly what `continue`
  // says.
  std::string jump_text(BlockId target) const {
    const Shape *inner = loops_.empty() ? nullptr : loops_.back();
    switch (jump_word(target, inner)) {
    case JumpWord::Break:
      return "break";
    case JumpWord::Continue:
      return "continue";
    case JumpWord::Goto:
      break;
    }
    return "goto " + label_of(target);
  }

  void lines(const std::vector<Shape> &shapes, int depth) {
    for (const Shape &shape : shapes)
      line(shape, depth);
  }

  void line(const Shape &shape, int depth) {
    switch (shape.kind) {
    case ShapeKind::Statements:
      statements(shape, depth);
      break;
    case ShapeKind::If:
      branch(shape, depth);
      break;
    case ShapeKind::Loop:
      loop(shape, depth);
      break;
    case ShapeKind::Jump:
      jump(shape, depth);
      break;
    }
  }

  // A block, where it stands: labelled when something jumps to it, preceded by
  // the comments the passes left on it -- the frame, the saves, the storage --
  // and then its statements.
  void statements(const Shape &shape, int depth) {
    if (shapes_.labelled.count(shape.block) != 0)
      out_ << code_column(depth) << label_of(shape.block) << ":\n";

    if (ctx_.knowledge != nullptr)
      for (const std::string &comment :
           ctx_.knowledge->block_comments(shape.block))
        out_ << indent(depth) << "; " << comment << "\n";

    for (const Statement *statement : shape.statements)
      statement_line(*statement, depth);
  }

  // `if (cond) { <then> }` or `if (cond) { <then> } else { <otherwise> }`. The
  // address and the notes belong to the branch, so they are on the `if` line;
  // the braces are punctuation and carry neither.
  //
  // The one-armed form is the fallthrough-is-the-join case: the arm is the taken
  // edge and the walk went on past the closing brace, so nothing follows it.
  void branch(const Shape &shape, int depth) {
    if (shape.statement == nullptr) {
      lines(shape.body, depth);
      return;
    }

    // An arm that is a single jump says everything the brace would say, and
    // `if (cond) continue;` is what the source would have written. Only an
    // unconditional jump: an arm that is itself a guarded jump would read as two
    // conditions on one line, which is not the same statement.
    if (shape.otherwise.empty() && shape.body.size() == 1 &&
        shape.body.front().kind == ShapeKind::Jump &&
        !shape.body.front().conditional) {
      out_ << indent(depth) << addr_field(shape.statement->addr) << "if (";
      render(out_, shape.statement->value, kLowest);
      out_ << ") " << jump_text(shape.body.front().block) << ";";
      notes(*shape.statement, depth);
      out_ << "\n";
      return;
    }

    condition(*shape.statement, depth, " {");
    lines(shape.body, depth + 1);
    if (shape.otherwise.empty()) {
      out_ << code_column(depth) << "}\n";
      return;
    }

    out_ << code_column(depth) << "} else {\n";
    lines(shape.otherwise, depth + 1);
    out_ << code_column(depth) << "}\n";
  }

  // `do { <body> } while (cond);` when the body's last act is to decide whether
  // to go round again, and `while (1) { <body> }` when it is not -- which is
  // what a loop with no such test is, and needs no invented condition to say.
  void loop(const Shape &shape, int depth) {
    if (shape.do_while && shape.statement != nullptr) {
      out_ << code_column(depth) << "do {\n";
      loops_.push_back(&shape);
      lines(shape.body, depth + 1);
      loops_.pop_back();

      out_ << code_column(depth) << "} while (";
      render(out_, shape.statement->value, kLowest);
      out_ << ");";
      notes(*shape.statement, depth);
      out_ << "\n";
      return;
    }

    out_ << code_column(depth) << "while (1) {\n";
    loops_.push_back(&shape);
    lines(shape.body, depth + 1);
    loops_.pop_back();
    out_ << code_column(depth) << "}\n";
  }

  // A jump the shape could not take over, or the two it can name. An invented
  // jump -- an edge into the join of an enclosing shape, which no instruction
  // said -- has no statement, so nothing but the label can be written for it.
  void jump(const Shape &shape, int depth) {
    const bool conditional = shape.conditional && shape.statement != nullptr;
    out_ << indent(depth)
         << (shape.statement != nullptr ? addr_field(shape.statement->addr)
                                        : std::string(kAddrWidth, ' '));

    if (conditional) {
      out_ << "if (";
      render(out_, shape.statement->value, kLowest);
      out_ << ") ";
    }

    out_ << jump_text(shape.block) << ";";

    if (shape.statement != nullptr)
      notes(*shape.statement, depth);
    out_ << "\n";
  }

  void statement_line(const Statement &statement, int depth) {
    out_ << indent(depth) << addr_field(statement.addr)
         << statement_text(statement, ctx_, cfg_) << ";";
    notes(statement, depth);
    out_ << "\n";
  }

  // The `if (cond)` a branch became.
  void condition(const Statement &statement, int depth,
                 const std::string &suffix) {
    out_ << indent(depth) << addr_field(statement.addr) << "if (";
    if (statement.value != nullptr)
      render(out_, statement.value, kLowest);
    else
      out_ << "?";
    out_ << ")" << suffix;
    notes(statement, depth);
    out_ << "\n";
  }

  // A statement's notes: the first beside it, the rest under it lined up with
  // the text rather than with the address, so the comment sits under the
  // statement it is about and not under its address.
  void notes(const Statement &statement, int depth) {
    if (ctx_.knowledge == nullptr || statement.op == nullptr)
      return;

    const std::vector<std::string> notes = ctx_.knowledge->notes(*statement.op);
    if (notes.empty())
      return;

    out_ << "  ; " << notes.front();
    const std::string pad = code_column(depth);
    for (size_t i = 1; i < notes.size(); ++i)
      out_ << "\n" << pad << "; " << notes[i];
  }

  std::ostream &out_;
  const HilShapes &shapes_;
  const PassContext &ctx_;
  const Cfg &cfg_;

  // The loops currently being printed, innermost last. A jump is spelled
  // against whichever is nearest, which is what `break` and `continue` mean.
  std::vector<const Shape *> loops_;
};

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
    out.addr = raw.start;
    out.entry = block.id == cfg.entry;
    out.preds = raw.preds;
    for (const Edge &edge : raw.succs) out.succs.push_back(edge.target);
    if (ctx.knowledge != nullptr)
      out.comments = ctx.knowledge->block_comments(block.id);

    for (const Statement &statement : block.statements) {
      TokenLine line;
      line.addr = statement.addr;

      switch (statement.kind) {
      case StatementKind::Assign:
        line.tokens.push_back({"var", statement.target_text, statement.target_text});
        line.tokens.push_back({"op", "=", ""});
        emit(line.tokens, statement.value, kLowest);
        break;

      case StatementKind::Store:
        if (const std::string_view slot = slot_name(statement.address);
            !slot.empty()) {
          const std::string name(slot);
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
        emit_target(line, statement, ctx, cfg);
        if (statement.fallthrough) {
          line.fallthrough = statement.fallthrough;
          line.tokens.push_back({"keyword", "else goto", ""});
          line.tokens.push_back({"block", std::to_string(*statement.fallthrough), ""});
        }
        break;

      case StatementKind::Branch:
        line.tokens.push_back({"keyword", "goto", ""});
        emit_target(line, statement, ctx, cfg);
        break;

      case StatementKind::Call:
        // A call whose answer something reads says where the answer lands
        // first, the way any other assignment does.
        if (!statement.target_text.empty()) {
          line.tokens.push_back(
              {"var", statement.target_text, statement.target_text});
          line.tokens.push_back({"op", "=", ""});
        }
        line.tokens.push_back({"keyword", "call", ""});
        emit(line.tokens, statement.value, kPrimary);
        break;

      case StatementKind::Return:
        line.tokens.push_back({"keyword", "return", ""});
        // A function that returns a value says so. What it hands back is the
        // thing the caller is about to make decisions with, and a bare
        // `return` is as silent about it as the p-code is.
        if (statement.value != nullptr) emit(line.tokens, statement.value, kLowest);
        break;

      case StatementKind::Effect:
        emit(line.tokens, statement.value, kLowest);
        break;
      }

      if (ctx.knowledge != nullptr && statement.op != nullptr)
        line.comments = ctx.knowledge->notes(*statement.op);

      out.lines.push_back(std::move(line));
    }

    blocks.push_back(std::move(out));
  }

  return blocks;
}

std::string to_string(const Hil &hil, const SsaFunction &fn,
                      const PassContext &ctx) {
  std::ostringstream os;
  Printer(os, structure(hil, fn), fn, ctx).run();
  return os.str();
}

} // namespace ddd
