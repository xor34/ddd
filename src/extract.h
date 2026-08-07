// extract.h -- finding things in an image you were not told the layout of.
//
// Firmware does not come with a section table. Before anything can be lifted,
// something has to say where the code is, what architecture it is, and which
// stretches are compressed, encrypted, or just strings.
//
// Extractors are the same shape as passes: one class, one registration macro,
// one file. They read the image and report Findings. They do not decide what
// to analyse -- the caller does that, using the regions they suggest -- and
// they never mutate the image. A transform that produces *different* bytes
// (decompression, decryption) is a separate step; see `transform.h`.
//
// This is deliberately not a container-format parser. Nothing here knows what
// an ELF is. It answers "what is at offset N and what might it be", which is
// the part that is architecture- and format-independent.
#pragma once

#include "image.h"

#include <functional>
#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

namespace ddd {

struct Finding {
  uint64_t offset = 0;   // absolute address in the image
  uint64_t length = 0;   // 0 when the extent is unknown
  std::string kind;      // "gzip", "code", "high-entropy", "strings"
  std::string detail;
  double confidence = 1.0;

  // Set when the finding is worth disassembling and the extractor knows what
  // with -- a spec name, resolvable in the specs directory.
  std::string suggested_spec;
};

struct ExtractContext {
  std::string spec_dir = "specs";
  // Restrict architecture detection to these spec names. Empty means try
  // everything in spec_dir, which is thorough but slow.
  std::vector<std::string> candidate_specs;
  std::ostream *out = nullptr;
  bool verbose = false;

  std::ostream &stream() const;
};

class Extractor {
public:
  virtual ~Extractor() = default;

  virtual std::string name() const = 0;
  virtual std::string description() const = 0;
  virtual std::vector<Finding> scan(const Image &image, ExtractContext &ctx) = 0;
};

class ExtractorRegistry {
public:
  using Factory = std::function<std::unique_ptr<Extractor>()>;

  struct Entry {
    std::string name;
    std::string description;
    Factory create;
  };

  static ExtractorRegistry &instance();

  void add(Entry entry);
  std::unique_ptr<Extractor> create(const std::string &name) const;
  const std::vector<Entry> &entries() const { return entries_; }

private:
  std::vector<Entry> entries_;
};

template <typename T>
struct ExtractorRegistrar {
  ExtractorRegistrar() {
    T probe;
    ExtractorRegistry::instance().add(ExtractorRegistry::Entry{
        probe.name(), probe.description(),
        [] { return std::unique_ptr<Extractor>(new T()); }});
  }
};

#define DDD_REGISTER_EXTRACTOR(Type)                                           \
  static const ::ddd::ExtractorRegistrar<Type> ddd_extractor_##Type {}

// Runs the named extractors (all of them if `names` is empty) and returns
// every finding, sorted by offset.
std::vector<Finding> extract(const Image &image, ExtractContext &ctx,
                             const std::vector<std::string> &names = {});

std::string to_string(const Finding &finding);

} // namespace ddd
