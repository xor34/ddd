#include "pcode/pcode.h"

#include <sstream>

namespace ddd {

const char *op_name(Op op) {
  static const char *const kNames[] = {
      "COPY", "LOAD", "STORE", "BRANCH", "CBRANCH", "BRANCHIND", "CALL",
      "CALLIND", "CALLOTHER", "RETURN",
      "INT_EQUAL", "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS",
      "INT_LESSEQUAL", "INT_ZEXT", "INT_SEXT", "INT_ADD", "INT_SUB",
      "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "INT_2COMP", "INT_NEGATE",
      "INT_XOR", "INT_AND", "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT",
      "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
      "BOOL_NEGATE", "BOOL_XOR", "BOOL_AND", "BOOL_OR",
      "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL",
      "FLOAT_NAN", "FLOAT_ADD", "FLOAT_DIV", "FLOAT_MULT", "FLOAT_SUB",
      "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT_INT2FLOAT",
      "FLOAT_FLOAT2FLOAT", "FLOAT_TRUNC", "FLOAT_CEIL", "FLOAT_FLOOR",
      "FLOAT_ROUND",
      "PIECE", "SUBPIECE", "CAST", "PTRADD", "PTRSUB", "SEGMENTOP",
      "CPOOLREF", "NEW", "INSERT", "ZPULL", "POPCOUNT", "LZCOUNT", "SPULL",
  };
  const size_t index = static_cast<size_t>(op);
  return index < sizeof(kNames) / sizeof(kNames[0]) ? kNames[index] : nullptr;
}

std::optional<Op> op_from_name(const std::string &name) {
  // The table op_name() indexes, walked rather than searched: there are fewer
  // than a hundred entries and this runs once per name a user wrote down.
  for (int i = 0; i < static_cast<int>(Op::kCount); ++i) {
    const Op op = static_cast<Op>(i);
    const char *candidate = op_name(op);
    if (candidate != nullptr && name == candidate)
      return op;
  }
  return std::nullopt;
}

bool is_terminator(Op op) {
  switch (op) {
  case Op::BRANCH:
  case Op::CBRANCH:
  case Op::BRANCHIND:
  case Op::CALL:
  case Op::CALLIND:
  case Op::RETURN:
    return true;
  default:
    return false;
  }
}

bool has_side_effects(Op op) {
  switch (op) {
  case Op::STORE:
  case Op::LOAD: // may be a device register read
  case Op::BRANCH:
  case Op::CBRANCH:
  case Op::BRANCHIND:
  case Op::CALL:
  case Op::CALLIND:
  case Op::CALLOTHER: // opaque userop
  case Op::RETURN:
    return true;
  default:
    return false;
  }
}

SpaceId Spaces::intern(std::string name, SpaceKind kind) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = by_name_.find(name);
  if (it != by_name_.end())
    return it->second;
  const SpaceId id = static_cast<SpaceId>(spaces_.size());
  spaces_.push_back(SpaceDesc{std::move(name), kind});
  by_name_[spaces_.back().name] = id;
  return id;
}

SpaceId Spaces::find(const std::string &name) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = by_name_.find(name);
  return it == by_name_.end() ? kNoSpace : it->second;
}

int Spaces::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return static_cast<int>(spaces_.size());
}

std::string Spaces::name(SpaceId id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return id >= 0 && id < static_cast<int>(spaces_.size())
             ? spaces_[id].name
             : "<none>";
}

SpaceKind Spaces::kind(SpaceId id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return id >= 0 && id < static_cast<int>(spaces_.size())
             ? spaces_[id].kind
             : SpaceKind::Other;
}

bool Spaces::is_kind(SpaceId id, SpaceKind kind) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return id >= 0 && id < static_cast<int>(spaces_.size()) &&
         spaces_[id].kind == kind;
}

std::string to_string(const Varnode &vn, const Spaces &spaces) {
  if (vn.space == kNoSpace)
    return "<null>";

  std::ostringstream os;
  if (is_constant(vn)) {
    os << "0x" << std::hex << vn.offset << ":" << std::dec << vn.size;
    return os.str();
  }
  os << spaces.name(vn.space) << ":0x" << std::hex << vn.offset << ":"
     << std::dec << vn.size;
  return os.str();
}

std::string to_string(const Addr &addr, const Spaces &spaces) {
  std::ostringstream os;
  if (addr.space == kNoSpace)
    os << "0x" << std::hex << addr.offset;
  else
    os << spaces.name(addr.space) << ":0x" << std::hex << addr.offset;
  return os.str();
}

} // namespace ddd
