// registry.h -- the one mechanism both kinds of plugin are found through.
//
// A registry maps a name to a way of making one thing that answers to it: a
// pass over a function, an extractor over an image. The registrand differs --
// one transforms SSA, one reports on bytes -- but the mechanism does not, and
// writing it twice made the two subsystems look unrelated when they are the
// same idea. `passes/pass.h` and `extract/extract.h` are each then a `Base`, an
// `Entry`, and a macro naming which registry the macro registers into.
//
// Registration happens before main: one static object per registrand, so a
// registrant needs no list of its own to be found in.
#pragma once

#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace ddd {

template <typename Base> class Registry {
public:
  using Factory = std::function<std::unique_ptr<Base>()>;

  struct Entry {
    std::string name;
    std::string description;
    Factory create;
  };

  static Registry &instance() {
    static Registry registry;
    return registry;
  }

  void add(Entry entry) { entries_.push_back(std::move(entry)); }

  // Null when nothing is registered under that name; every caller reports
  // that in its own way, because "why is there no pass called that" has a
  // different answer at a command line than it does inside a session.
  std::unique_ptr<Base> create(const std::string &name) const {
    for (const Entry &entry : entries_)
      if (entry.name == name)
        return entry.create();
    return nullptr;
  }

  const std::vector<Entry> &entries() const { return entries_; }

private:
  std::vector<Entry> entries_;
};

// Constructs one probe of the registrand at startup, only to ask it its name
// and description -- which is why both ask those of a default-constructed
// object rather than of a call, and why `name()` must not depend on having
// been run.
template <typename Base, typename T> struct Registrar {
  Registrar() {
    T probe;
    Registry<Base>::instance().add(
        typename Registry<Base>::Entry{probe.name(), probe.description(), [] {
                                         return std::unique_ptr<Base>(new T());
                                       }});
  }
};

} // namespace ddd

// Put this at the bottom of the .cpp that defines the type -- `Base` is the
// registry to join, spelled out because a registrant does not otherwise know
// which of them wants it.
#define DDD_REGISTER(Base, Type)                                               \
  static const ::ddd::Registrar<Base, Type> ddd_registrar_##Type {}
