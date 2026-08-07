#include "extract.h"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace ddd {

std::ostream &ExtractContext::stream() const {
  return out != nullptr ? *out : std::cout;
}

ExtractorRegistry &ExtractorRegistry::instance() {
  static ExtractorRegistry registry;
  return registry;
}

void ExtractorRegistry::add(Entry entry) { entries_.push_back(std::move(entry)); }

std::unique_ptr<Extractor> ExtractorRegistry::create(const std::string &name) const {
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const Entry &e) { return e.name == name; });
  return it == entries_.end() ? nullptr : it->create();
}

std::vector<Finding> extract(const Image &image, ExtractContext &ctx,
                             const std::vector<std::string> &names) {
  std::vector<Finding> findings;

  for (const ExtractorRegistry::Entry &entry : ExtractorRegistry::instance().entries()) {
    if (!names.empty() && std::find(names.begin(), names.end(), entry.name) == names.end())
      continue;

    std::unique_ptr<Extractor> extractor = entry.create();
    if (ctx.verbose) ctx.stream() << "== " << entry.name << " ==\n";

    for (Finding &finding : extractor->scan(image, ctx))
      findings.push_back(std::move(finding));
  }

  std::stable_sort(findings.begin(), findings.end(),
                   [](const Finding &a, const Finding &b) { return a.offset < b.offset; });
  return findings;
}

std::string to_string(const Finding &finding) {
  std::ostringstream os;
  os << "0x" << std::hex << finding.offset;
  if (finding.length != 0) os << "+0x" << finding.length;
  os << std::dec << "  " << finding.kind;
  if (!finding.detail.empty()) os << "  " << finding.detail;
  if (finding.confidence < 1.0)
    os << "  (" << std::fixed << std::setprecision(2) << finding.confidence << ")";
  if (!finding.suggested_spec.empty()) os << "  [--region spec: " << finding.suggested_spec << "]";
  return os.str();
}

} // namespace ddd
