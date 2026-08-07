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
}

} // namespace ddd
