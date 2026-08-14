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
#include <set>
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

  // A prototype someone wrote out, in the shape Binary Ninja takes one:
  //
  //   int compute(int n @ RDI, char *name @ RSI)
  //
  // Nothing in a binary records parameter names, types or even how many there
  // are, so this is the one place they can come from. `@ storage` is what makes
  // it applicable rather than decorative: it says which register or slot the
  // parameter arrives in, so the analysis can name that value.
  void set_signature(uint64_t function, std::string text);
  const std::string *signature(uint64_t function) const;

  // A stretch the user says is not code, whatever the sweep decided. The
  // sweep guesses; a person who has read the bytes does not.
  void mark_data(uint64_t begin, uint64_t end);
  // This is code after all. Anything overlapping is dropped rather than split:
  // a mark is a statement about a stretch, and half of one is not a smaller
  // statement.
  void unmark_data(uint64_t begin, uint64_t end);
  const std::map<uint64_t, uint64_t> &data_ranges() const { return data_; }

  // A function the user says is not one -- a jump table read as a prologue, a
  // string that disassembles. Discovery will not put it back.
  void undefine_function(uint64_t address);
  // Taking that back: it is a function after all.
  void define_function_again(uint64_t address) { undefined_.erase(address); }
  bool is_undefined(uint64_t address) const {
    return undefined_.count(address) != 0;
  }
  const std::set<uint64_t> &undefined() const { return undefined_; }

  // A stretch of the image and how to read it: an instruction set, and
  // optionally a convention. What --region says on the command line, kept so a
  // firmware image only has to be carved up once.
  struct RegionSpec {
    uint64_t begin = 0;
    uint64_t end = 0;
    std::string spec;
    std::string abi;
    std::string stack_pointer;
  };

  void add_region(RegionSpec region);
  const std::vector<RegionSpec> &regions() const { return regions_; }

  // A region of the tree someone marked out by hand: a string, a jump table,
  // an item inside a blob. Kept separately from the instruction-set regions
  // above, which are about how to *read* a stretch rather than what it is.
  struct Mark {
    uint64_t begin = 0;
    uint64_t end = 0;
    std::string kind;
    std::string name;
  };

  void add_mark(Mark mark);
  void remove_marks(uint64_t begin, uint64_t end);
  const std::vector<Mark> &marks() const { return marks_; }

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
  std::map<uint64_t, std::string> signatures_;
  std::map<uint64_t, uint64_t> data_; // begin -> end
  std::set<uint64_t> undefined_;
  std::vector<RegionSpec> regions_;
  std::vector<Mark> marks_;
};

} // namespace ddd
