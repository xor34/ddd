#include "facts/knowledge.h"

#include <ostream>
#include <sstream>

namespace ddd {
namespace {

const std::vector<std::string> &no_comments() {
  static const std::vector<std::string> empty;
  return empty;
}

std::string hex(uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << value;
  return os.str();
}

// A string as a listing spells it, so that a newline in the data does not
// break the line it is printed on.
std::string quoted(const std::string &text) {
  std::string out = "\"";
  for (char c : text) {
    switch (c) {
    case '\n': out += "\\n"; break;
    case '\t': out += "\\t"; break;
    case '"': out += "\\\""; break;
    case '\\': out += "\\\\"; break;
    default: out += c; break;
    }
  }
  return out + "\"";
}

// What a resolved reference says, in the words a reader has always read it in.
//
// One sentence per fact, and one home for it: the analysis records what it
// found and stops there, and every renderer gets the same sentence without
// knowing which analysis found it.
std::string sentence(const PointsAt &p) {
  // A named function: the constant *is* the function and the name is the whole
  // story. `&f` -- the line that puts its address somewhere -- and never
  // `calls f`, which is a different fact about a different opcode and has its
  // own kind of note.
  if (p.kind == PointsAt::Kind::Code && !p.text.empty() && !p.word_read)
    return "&" + p.text;

  // A literal pool entry: the constant points at a word, and what is worth
  // saying is at the end of that hop rather than the hop itself.
  if (p.word_read) {
    const std::string prefix = hex(p.address) + " -> " + hex(p.word);
    switch (p.kind) {
    case PointsAt::Kind::Code: return prefix + " (code)";
    case PointsAt::Kind::String: return prefix + " -> " + quoted(p.text);
    case PointsAt::Kind::Data: return prefix;
    }
  }

  switch (p.kind) {
  case PointsAt::Kind::String: return hex(p.address) + " -> " + quoted(p.text);
  case PointsAt::Kind::Code: return hex(p.address) + " -> code";
  case PointsAt::Kind::Data: return hex(p.address) + " -> data";
  }
  return {};
}

} // namespace

void Knowledge::comment(const SsaOp &op, std::string text) {
  Note note;
  note.kind = Note::Kind::Prose;
  note.text = std::move(text);
  op_notes_[op.id].push_back(std::move(note));
}

void Knowledge::comment_block(BlockId block, std::string text) {
  block_comments_[block].push_back(std::move(text));
}

void Knowledge::set_points_at(const SsaOp &op, PointsAt what) {
  Note note;
  note.kind = Note::Kind::PointsAt;
  note.fact = std::move(what);
  op_notes_[op.id].push_back(std::move(note));
}

std::vector<PointsAt> Knowledge::points_at(const SsaOp &op) const {
  std::vector<PointsAt> result;

  auto it = op_notes_.find(op.id);
  if (it == op_notes_.end()) return result;

  for (const Note &note : it->second)
    if (note.kind == Note::Kind::PointsAt) result.push_back(note.fact);

  return result;
}

void Knowledge::set_callee(const SsaOp &call, std::string name) {
  Note note;
  note.kind = Note::Kind::Callee;
  note.text = std::move(name);
  op_notes_[call.id].push_back(std::move(note));
}

const std::string *Knowledge::callee(const SsaOp &call) const {
  auto it = op_notes_.find(call.id);
  if (it == op_notes_.end()) return nullptr;

  for (const Note &note : it->second)
    if (note.kind == Note::Kind::Callee) return &note.text;

  return nullptr;
}

void Knowledge::set_label(const SsaValue &value, std::string label) {
  labels_[value.id] = std::move(label);
}

void Knowledge::set_alias(const SsaValue &value, const SsaValue &source) {
  if (&value == &source) return;
  aliases_[value.id] = &source;
}

const SsaValue &Knowledge::canonical(const SsaValue &value) const {
  const SsaValue *current = &value;

  // SSA copy chains cannot cycle -- a definition dominates its uses -- but
  // the bound keeps a malformed function from hanging the printer.
  for (int guard = 0; guard < 64; ++guard) {
    // A label beats an alias: something decided this value deserves a name of
    // its own, and following the copy past it would throw that away. The
    // branch condition named `cond` is where this shows.
    if (!label(*current).empty()) break;

    auto it = aliases_.find(current->id);
    if (it == aliases_.end()) break;
    current = it->second;
  }

  return *current;
}

void Knowledge::set_display_name(const SsaValue &value, std::string name) {
  display_names_[value.id] = std::move(name);
}

const std::string &Knowledge::display_name(const SsaValue &value) const {
  static const std::string none;
  auto it = display_names_.find(value.id);
  return it == display_names_.end() ? none : it->second;
}

// The prose and the facts' sentences, in one list, in the order they were
// recorded -- which is the order a reader has always seen them in, because the
// analyses happen to run in that order and the notes were written as they ran.
std::vector<std::string> Knowledge::notes(const SsaOp &op) const {
  std::vector<std::string> result;

  auto it = op_notes_.find(op.id);
  if (it == op_notes_.end()) return result;
  result.reserve(it->second.size());

  for (const Note &note : it->second) {
    switch (note.kind) {
    case Note::Kind::Prose: result.push_back(note.text); break;
    case Note::Kind::PointsAt: result.push_back(sentence(note.fact)); break;
    case Note::Kind::Callee: result.push_back("calls " + note.text); break;
    }
  }

  return result;
}

const std::vector<std::string> &Knowledge::block_comments(BlockId block) const {
  auto it = block_comments_.find(block);
  return it == block_comments_.end() ? no_comments() : it->second;
}

const std::string &Knowledge::label(const SsaValue &value) const {
  static const std::string none;
  auto it = labels_.find(value.id);
  return it == labels_.end() ? none : it->second;
}

void Knowledge::mark_plumbing(const SsaOp &op) { plumbing_.insert(op.id); }

bool Knowledge::is_plumbing(const SsaOp &op) const {
  return plumbing_.count(op.id) != 0;
}

} // namespace ddd
