// pass.h -- passes over an SsaFunction, and a registry to look them up by
// name.
//
// A pass is one class with a name, a description and a run(). Dropping
// DDD_REGISTER_PASS(MyPass) at the bottom of its .cpp makes it available to
// --passes on the command line; nothing else in the tree needs to change.
#pragma once

#include "abi.h"
#include "image.h"
#include "ssa.h"

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
struct PassContext {
  ghidra::Sleigh *translator = nullptr;      // resolves register names; may be null
  const Image *image = nullptr;              // the bytes, code and data; may be null
  const CallingConvention *abi = nullptr;    // may be null
  Storage stack_pointer;                     // zeroed if unknown
  std::ostream *out = nullptr;               // where passes report; defaults to stdout
  bool verbose = false;

  std::ostream &stream() const;

  // Display names. With a translator these come out as real register names
  // ("RAX#3") instead of raw storage ("register:0x0:8#3").
  std::string name_of(const SsaValue &value) const;
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

template <typename T>
struct PassRegistrar {
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

// Runs a sequence of passes in order.
class PassManager {
public:
  // Looks the pass up by name; returns false if there is no such pass.
  bool add(const std::string &name);
  void run(SsaFunction &fn, PassContext &ctx) const;

  bool empty() const { return passes_.empty(); }

private:
  std::vector<std::shared_ptr<Pass>> passes_;
};

} // namespace ddd
