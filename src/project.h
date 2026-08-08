// project.h -- what the person analysing the binary decided.
//
// Everything else in this tool is derived: run it again and you get the same
// answers. A name someone chose is not derived, and losing it on the next run
// makes the tool useless for the job it exists to do.
//
// So user decisions live here, keyed by things that survive re-analysis --
// addresses, and (function, generated name) pairs -- and are written to a
// plain text file that is readable and diffable.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace ddd {

class Project {
public:
  // A function, by the address it starts at.
  void rename_function(uint64_t address, std::string name);
  const std::string *function_name(uint64_t address) const;

  // A variable, by the function it lives in and the name the analysis gave it.
  // Keyed by generated name rather than by SSA value id because ids move when
  // anything upstream changes, and the name is what the user actually typed.
  void rename_variable(uint64_t function, std::string generated, std::string name);
  const std::string *variable_name(uint64_t function, const std::string &generated) const;

  void set_comment(uint64_t address, std::string text);
  const std::string *comment(uint64_t address) const;

  // A type the user declared. Inference is evidence-based and therefore
  // sometimes wrong; a person who knows the code outranks it.
  void set_type(uint64_t function, std::string variable, std::string type);
  const std::string *type(uint64_t function, const std::string &variable) const;
  const std::map<std::pair<uint64_t, std::string>, std::string> &types() const {
    return types_;
  }

  bool empty() const;

  // The file format is one directive per line, the same vocabulary the
  // interactive commands use, so a project file can be written by hand.
  bool load(const std::string &path);
  bool save(const std::string &path) const;

  const std::map<uint64_t, std::string> &functions() const { return functions_; }

private:
  std::map<uint64_t, std::string> functions_;
  std::map<std::pair<uint64_t, std::string>, std::string> variables_;
  std::map<uint64_t, std::string> comments_;
  std::map<std::pair<uint64_t, std::string>, std::string> types_;
};

} // namespace ddd
