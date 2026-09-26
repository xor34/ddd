// hil_render.cpp -- turning a built Hil into text, or into tokens.
//
// Two outputs over one walk of the same statements: a string, for batch output
// and tests, and a token stream, for a front end that has to make the names
// clickable. They are written out separately rather than sharing a sink
// because the string form is the hot path and the indirection earned nothing.
//
// Nothing here decides anything about the function. Every question -- which
// values folded, what a target is, whether a block is reachable -- was answered
// while building, and an answer invented here would be a second one.
#include "render/hil.h"

#include "render/hil_expr.h"

#include <ostream>
#include <sstream>

namespace ddd {
namespace {

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

// The same three answers, for the printer that has no interface behind it.
void render_target(std::ostream &out, const Statement &statement,
                   const PassContext &ctx, const Cfg &cfg) {
  if (statement.taken)
    out << *statement.taken;
  else if (statement.leaves_to != Addr{})
    out << destination_text(statement.leaves_to, cfg.code_space, ctx.spaces());
  else
    out << "?";
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
    out.addr = raw.start;
    out.entry = block.id == cfg.entry;
    out.preds = raw.preds;
    for (const Edge &edge : raw.succs) out.succs.push_back(edge.target);
    if (ctx.annotations != nullptr)
      out.comments = ctx.annotations->block_comments(block.id);

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

      if (ctx.annotations != nullptr && statement.op != nullptr)
        line.comments = ctx.annotations->comments(*statement.op);

      out.lines.push_back(std::move(line));
    }

    blocks.push_back(std::move(out));
  }

  return blocks;
}

std::string to_string(const Hil &hil, const SsaFunction &fn,
                      const PassContext &ctx) {
  std::ostringstream os;
  const Cfg &cfg = fn.cfg();

  for (const HilBlock &block : hil.blocks()) {
    const BasicBlock &raw = cfg[block.id];

    // As in tokenize: what nothing can reach is what the linear sweep walked
    // into after this function ended, not part of it.
    if (!fn.dominance().reachable(block.id)) continue;

    os << "block " << block.id << " @ 0x" << std::hex << raw.start << std::dec;
    if (block.id == cfg.entry) os << " (entry)";
    os << ":";
    if (!raw.preds.empty()) {
      os << "  from";
      for (BlockId p : raw.preds) os << ' ' << p;
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
        line << ") goto ";
        render_target(line, statement, ctx, cfg);
        if (statement.fallthrough) line << " else goto " << *statement.fallthrough;
        break;

      case StatementKind::Branch:
        line << "goto ";
        render_target(line, statement, ctx, cfg);
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

      os << "  0x" << std::hex << statement.addr << std::dec << "  " << line.str();

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
