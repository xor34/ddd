#include "annotations.h"

namespace ddd {
namespace {

const std::vector<std::string> &no_comments() {
  static const std::vector<std::string> empty;
  return empty;
}

} // namespace

void Annotations::comment(const SsaOp &op, std::string text) {
  op_comments_[op.id].push_back(std::move(text));
}

void Annotations::comment_block(int block, std::string text) {
  block_comments_[block].push_back(std::move(text));
}

void Annotations::set_label(const SsaValue &value, std::string label) {
  labels_[value.id] = std::move(label);
}

void Annotations::set_alias(const SsaValue &value, const SsaValue &source) {
  if (&value == &source) return;
  aliases_[value.id] = &source;
}

const SsaValue &Annotations::canonical(const SsaValue &value) const {
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

void Annotations::set_display_name(const SsaValue &value, std::string name) {
  display_names_[value.id] = std::move(name);
}

const std::string &Annotations::display_name(const SsaValue &value) const {
  static const std::string none;
  auto it = display_names_.find(value.id);
  return it == display_names_.end() ? none : it->second;
}

const std::vector<std::string> &Annotations::comments(const SsaOp &op) const {
  auto it = op_comments_.find(op.id);
  return it == op_comments_.end() ? no_comments() : it->second;
}

const std::vector<std::string> &Annotations::block_comments(int block) const {
  auto it = block_comments_.find(block);
  return it == block_comments_.end() ? no_comments() : it->second;
}

const std::string &Annotations::label(const SsaValue &value) const {
  static const std::string none;
  auto it = labels_.find(value.id);
  return it == labels_.end() ? none : it->second;
}

void Annotations::clear() {
  op_comments_.clear();
  block_comments_.clear();
  labels_.clear();
  aliases_.clear();
  display_names_.clear();
}

} // namespace ddd
