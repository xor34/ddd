#include "passes/pass.h"

#include "sleigh.hh"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace ddd {
namespace {

// Register name for a storage, through the translator of the target the
// function was lifted with. Space identity being by *name* is what makes this
// sound: the id resolves to the same register bank in any decoder of the
// spec, so this is a display lookup, not an identity comparison.
std::string storage_name(const PassContext &ctx, SpaceId space,
                         uint64_t offset, uint32_t size) {
  if (space == kNoSpace)
    return "?";
  if (ctx.translator() != nullptr && ctx.spaces() != nullptr) {
    ghidra::AddrSpace *spc =
        ctx.translator()->getSpaceByName(ctx.spaces()->name(space));
    if (spc != nullptr) {
      std::string reg = ctx.translator()->getRegisterName(spc, offset, size);
      if (!reg.empty())
        return reg;
    }
  }
  if (ctx.spaces() != nullptr)
    return to_string(Varnode{space, offset, size}, *ctx.spaces());
  std::ostringstream os;
  os << "space" << space << ":0x" << std::hex << offset << ":" << std::dec
     << size;
  return os.str();
}

} // namespace

ghidra::Sleigh *PassContext::translator() const {
  return target != nullptr ? target->translator : nullptr;
}

const CallingConvention *PassContext::abi() const {
  return target != nullptr ? target->abi : nullptr;
}

Spaces *PassContext::spaces() const {
  return target != nullptr ? target->spaces : nullptr;
}

Varnode PassContext::stack_pointer() const {
  return target != nullptr ? target->stack_pointer : Varnode{};
}

std::ostream &PassContext::stream() const {
  return out != nullptr ? *out : std::cout;
}

std::string PassContext::name_of(const SsaValue &value) const {
  if (knowledge == nullptr) return declaration_of(value);

  // A complete name from `name-vars` is the whole answer: it already folded in
  // the version and is already unique. Anything written afterwards -- a call's
  // argument list, say -- then agrees with the listing rather than quoting SSA
  // names nothing else shows.
  if (knowledge->has_display_name(value)) return knowledge->display_name(value);

  return declaration_of(knowledge->canonical(value));
}

std::string PassContext::declaration_of(const SsaValue &value) const {
  const std::string *label =
      knowledge != nullptr ? &knowledge->label(value) : nullptr;
  std::string base = (label != nullptr && !label->empty())
                         ? *label
                         : storage_name(*this, value.storage.space,
                                        value.storage.offset,
                                        value.storage.size);
  if (value.is_live_in())
    return base + "#in";
  return base + "#" + std::to_string(value.version);
}

std::string PassContext::name_of(const Varnode &vn) const {
  if (vn.space == kNoSpace)
    return "?";
  if (is_constant(vn)) {
    std::ostringstream os;
    os << "0x" << std::hex << vn.offset;
    return os.str();
  }
  return storage_name(*this, vn.space, vn.offset, vn.size);
}

std::string PassContext::name_of(const SsaOperand &operand) const {
  if (operand.value != nullptr)
    return name_of(*operand.value);
  return name_of(operand.raw);
}

std::string PassContext::base_name_of(const SsaValue &value) const {
  const std::string full = name_of(value);
  const size_t hash = full.rfind('#');
  return hash == std::string::npos ? full : full.substr(0, hash);
}

std::string PassContext::name_of(const SsaOp &op, size_t index) const {
  const SsaOperand &operand = op.ins[index];

  // The address-space operand of a LOAD/STORE: its offset is the SpaceId of
  // the space it operates on, so the name is just a lookup.
  if (is_space_operand(op, index) && operand.is_constant() &&
      spaces() != nullptr)
    return spaces()->name(static_cast<SpaceId>(operand.raw.offset));

  return name_of(operand);
}

bool is_terminal_pass(const std::string &name) {
  return name == "hil" || name == "print-ssa" || name == "asm";
}

bool is_folded_listing(const std::string &name) { return name == "hil"; }

bool PassManager::add(const std::string &name) {
  // "py:<path>" runs an external script instead of a registered pass.
  if (name.rfind("py:", 0) == 0) {
    passes_.push_back(make_script_pass(name.substr(3)));
    return true;
  }

  std::unique_ptr<Pass> pass = PassRegistry::instance().create(name);
  if (pass == nullptr)
    return false;
  passes_.push_back(std::move(pass));
  return true;
}

void PassManager::run(SsaFunction &fn, PassContext &ctx) const {
  // A worker's copy of a target decodes and nothing else: the storage it names
  // comes from another Sleigh, so every register a pass compares against would
  // quietly fail to match. Better to stop here than to produce a listing with
  // no arguments, no stack frame and no explanation. See Target::decode_only.
  if (ctx.target != nullptr && ctx.target->decode_only) {
    std::cerr << "internal error: passes run against a decode-only target\n";
    std::abort();
  }

  for (const std::shared_ptr<Pass> &pass : passes_) {
    if (ctx.verbose)
      ctx.stream() << "== " << pass->name() << " ==\n";

    // Anything a previous pass left in the buffer is stale by definition --
    // this pass has not run yet.
    ctx.take_report();

    pass->run(fn, ctx);
    if (!ctx.verbose)
      continue;

    for (const std::string &line : ctx.take_report())
      ctx.stream() << "  " << line << "\n";
    for (const std::string &line : pass->report(fn, ctx))
      ctx.stream() << "  " << line << "\n";
  }
}

} // namespace ddd
