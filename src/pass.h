// pass.h -- passes over an SsaFunction, and a registry to look them up by
// name.
//
// A pass is one class with a name, a description and a run(). Dropping
// DDD_REGISTER_PASS(MyPass) at the bottom of its .cpp makes it available to
// --passes on the command line; nothing else in the tree needs to change.
#pragma once

#include "abi.h"
#include "annotations.h"
#include "image.h"
#include "ssa.h"
#include "target.h"

#include <functional>
#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {
class Sleigh;
}

namespace ddd {

// Everything a pass needs besides the function itself.
//
// `target` is the one for *this* function, not for the file: an image can
// hold more than one instruction set, and one instruction set can be used
// under more than one convention.
struct PassContext {
  const Target *target = nullptr;     // ISA + ABI in force here; may be null
  const Image *image = nullptr;       // the bytes, code and data; may be null
  Annotations *annotations = nullptr; // where passes record what they found
  std::ostream *out = nullptr;        // where passes report; defaults to stdout
  bool verbose = false;

  ghidra::Sleigh *translator() const;
  const CallingConvention *abi() const;
  Storage stack_pointer() const;

  std::ostream &stream() const;

  // Display names. With a translator these come out as real register names
  // ("RAX#3") instead of raw storage ("register:0x0:8#3").
  //
  // name_of() follows aliases, so a use shows the variable it really is.
  // declaration_of() does not, so the line that defines a value still names
  // it -- otherwise a copy would print as `x = COPY x`.
  std::string name_of(const SsaValue &value) const;
  std::string declaration_of(const SsaValue &value) const;
  std::string name_of(const VarnodeData &vn) const;
  std::string name_of(const SsaOperand &operand) const;
  // Operand by position, so the address-space constant of a LOAD/STORE comes
  // out as a space name rather than an encoded pointer.
  std::string name_of(const SsaOp &op, size_t index) const;
};

class Pass {
public:
  virtual ~Pass() = default;

  virtual std::string name() const = 0;
  virtual std::string description() const { return {}; }
  virtual void run(SsaFunction &fn, PassContext &ctx) = 0;
};

class PassRegistry {
public:
  using Factory = std::function<std::unique_ptr<Pass>()>;

  struct Entry {
    std::string name;
    std::string description;
    Factory create;
  };

  static PassRegistry &instance();

  void add(Entry entry);
  std::unique_ptr<Pass> create(const std::string &name) const;
  const std::vector<Entry> &entries() const { return entries_; }

private:
  std::vector<Entry> entries_;
};

template <typename T> struct PassRegistrar {
  PassRegistrar() {
    T probe;
    PassRegistry::instance().add(
        PassRegistry::Entry{probe.name(), probe.description(),
                            [] { return std::unique_ptr<Pass>(new T()); }});
  }
};

// Register a pass with the global registry. Put this at the bottom of the
// .cpp that defines it; name and description come from the pass itself.
#define DDD_REGISTER_PASS(Type)                                                \
  static const ::ddd::PassRegistrar<Type> ddd_registrar_##Type {}

// A pass that shells out to an external script (see passes/script_pass.cpp).
// Named by path at the point of use, so it is not in the registry.
std::unique_ptr<Pass> make_script_pass(const std::string &path);

// Runs a sequence of passes in order.
class PassManager {
public:
  // Looks the pass up by name, or builds a script pass for a "py:<path>"
  // name. Returns false if there is no such pass.
  bool add(const std::string &name);
  void run(SsaFunction &fn, PassContext &ctx) const;

  bool empty() const { return passes_.empty(); }

private:
  std::vector<std::shared_ptr<Pass>> passes_;
};

} // namespace ddd
