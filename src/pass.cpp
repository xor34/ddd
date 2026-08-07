#include "pass.h"

#include "sleigh.hh"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace ddd {
namespace {

std::string storage_name(const PassContext &ctx, AddrSpace *space, uint64_t offset,
                         uint32_t size) {
  if (space == nullptr) return "?";
  if (ctx.translator != nullptr) {
    std::string reg = ctx.translator->getRegisterName(space, offset, size);
    if (!reg.empty()) return reg;
  }
  return to_string(Storage{space, offset, size});
}

} // namespace

std::ostream &PassContext::stream() const {
  return out != nullptr ? *out : std::cout;
}

std::string PassContext::name_of(const SsaValue &value) const {
  std::string base =
      storage_name(*this, value.storage.space, value.storage.offset, value.storage.size);
  if (value.is_live_in()) return base + "#in";
  return base + "#" + std::to_string(value.version);
}

std::string PassContext::name_of(const VarnodeData &vn) const {
  if (vn.space == nullptr) return "?";
  if (is_constant(vn)) {
    std::ostringstream os;
    os << "0x" << std::hex << vn.offset;
    return os.str();
  }
  return storage_name(*this, vn.space, static_cast<uint64_t>(vn.offset),
                      static_cast<uint32_t>(vn.size));
}

std::string PassContext::name_of(const SsaOperand &operand) const {
  if (operand.value != nullptr) return name_of(*operand.value);
  return name_of(operand.raw);
}

PassRegistry &PassRegistry::instance() {
  static PassRegistry registry;
  return registry;
}

void PassRegistry::add(Entry entry) { entries_.push_back(std::move(entry)); }

std::unique_ptr<Pass> PassRegistry::create(const std::string &name) const {
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const Entry &e) { return e.name == name; });
  return it == entries_.end() ? nullptr : it->create();
}

bool PassManager::add(const std::string &name) {
  std::unique_ptr<Pass> pass = PassRegistry::instance().create(name);
  if (pass == nullptr) return false;
  passes_.push_back(std::move(pass));
  return true;
}

void PassManager::run(SsaFunction &fn, PassContext &ctx) const {
  for (const std::shared_ptr<Pass> &pass : passes_) {
    if (ctx.verbose) ctx.stream() << "== " << pass->name() << " ==\n";
    pass->run(fn, ctx);
  }
}

} // namespace ddd
