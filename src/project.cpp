#include "project.h"
#include "text.h"

#include <fstream>
#include <iostream>
#include <sstream>

namespace ddd {
namespace {

std::string hex(uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << value;
  return os.str();
}

// Reads one token from `fields`, parses it as an address, and reports
// `path:number: <what>` on failure -- the same shape every directive below
// needs before it can do anything else.
bool read_address(std::istringstream &fields, const std::string &path, int number,
                  uint64_t &out, const char *what = "bad address") {
  std::string text;
  fields >> text;
  if (!parse_number(text, out)) {
    std::cerr << path << ":" << number << ": " << what << "\n";
    return false;
  }
  return true;
}

} // namespace

void Project::rename_function(uint64_t address, std::string name) {
  functions_[address] = std::move(name);
}

const std::string *Project::function_name(uint64_t address) const {
  auto it = functions_.find(address);
  return it == functions_.end() ? nullptr : &it->second;
}

void Project::rename_variable(uint64_t function, std::string generated, std::string name) {
  variables_[{function, std::move(generated)}] = std::move(name);
}

const std::string *Project::variable_name(uint64_t function,
                                          const std::string &generated) const {
  auto it = variables_.find({function, generated});
  return it == variables_.end() ? nullptr : &it->second;
}

void Project::set_comment(uint64_t address, std::string text) {
  comments_[address] = std::move(text);
}

const std::string *Project::comment(uint64_t address) const {
  auto it = comments_.find(address);
  return it == comments_.end() ? nullptr : &it->second;
}

void Project::set_type(uint64_t function, std::string variable, std::string type) {
  types_[{function, std::move(variable)}] = std::move(type);
}

const std::string *Project::type(uint64_t function,
                                 const std::string &variable) const {
  auto it = types_.find({function, variable});
  return it == types_.end() ? nullptr : &it->second;
}

void Project::set_signature(uint64_t function, std::string text) {
  signatures_[function] = std::move(text);
}

const std::string *Project::signature(uint64_t function) const {
  auto it = signatures_.find(function);
  return it == signatures_.end() ? nullptr : &it->second;
}

void Project::mark_data(uint64_t begin, uint64_t end) {
  if (end > begin)
    data_[begin] = end;
}

void Project::unmark_data(uint64_t begin, uint64_t end) {
  for (auto it = data_.begin(); it != data_.end();) {
    if (it->second <= begin || it->first >= end)
      ++it;
    else
      it = data_.erase(it);
  }
}

void Project::undefine_function(uint64_t address) {
  undefined_.insert(address);
  functions_.erase(address);
}

void Project::add_region(RegionSpec region) {
  if (region.end <= region.begin)
    return;

  // Naming the same stretch again replaces it, which is how you correct a
  // guess about an architecture without editing the file by hand.
  for (RegionSpec &existing : regions_) {
    if (existing.begin == region.begin && existing.end == region.end) {
      existing = std::move(region);
      return;
    }
  }
  regions_.push_back(std::move(region));
}

void Project::add_mark(Mark mark) {
  if (mark.end <= mark.begin)
    return;

  for (Mark &existing : marks_) {
    if (existing.begin == mark.begin && existing.end == mark.end) {
      existing = std::move(mark);
      return;
    }
  }
  marks_.push_back(std::move(mark));
}

void Project::remove_marks(uint64_t begin, uint64_t end) {
  std::vector<Mark> kept;
  for (Mark &mark : marks_)
    if (mark.end <= begin || mark.begin >= end)
      kept.push_back(std::move(mark));
  marks_ = std::move(kept);
}

bool Project::empty() const {
  return functions_.empty() && variables_.empty() && comments_.empty() &&
         types_.empty() && signatures_.empty() && data_.empty() &&
         undefined_.empty() && regions_.empty() && marks_.empty();
}

bool Project::load(const std::string &path) {
  std::ifstream file(path);
  if (!file) return false;

  std::string line;
  int number = 0;
  while (std::getline(file, line)) {
    ++number;
    if (line.empty() || line[0] == '#') continue;

    std::istringstream fields(line);
    std::string verb;
    fields >> verb;

    if (verb == "function") {
      uint64_t value = 0;
      if (!read_address(fields, path, number, value)) continue;
      rename_function(value, rest_of_line(fields));
    } else if (verb == "variable") {
      uint64_t value = 0;
      if (!read_address(fields, path, number, value)) continue;
      std::string generated;
      fields >> generated;
      rename_variable(value, generated, rest_of_line(fields));
    } else if (verb == "type") {
      uint64_t value = 0;
      if (!read_address(fields, path, number, value)) continue;
      std::string variable;
      fields >> variable;
      set_type(value, variable, rest_of_line(fields));
    } else if (verb == "comment") {
      uint64_t value = 0;
      if (!read_address(fields, path, number, value)) continue;
      set_comment(value, rest_of_line(fields));
    } else if (verb == "signature") {
      uint64_t value = 0;
      if (!read_address(fields, path, number, value)) continue;
      set_signature(value, rest_of_line(fields));
    } else if (verb == "data") {
      uint64_t from = 0, to = 0;
      if (!read_address(fields, path, number, from, "bad range") ||
          !read_address(fields, path, number, to, "bad range"))
        continue;
      mark_data(from, to);
    } else if (verb == "undefine") {
      uint64_t value = 0;
      if (!read_address(fields, path, number, value)) continue;
      undefine_function(value);
    } else if (verb == "region") {
      RegionSpec region;
      std::string begin, end;
      fields >> begin >> end >> region.spec >> region.abi >>
          region.stack_pointer;
      if (!parse_number(begin, region.begin) ||
          !parse_number(end, region.end) || region.spec.empty()) {
        std::cerr << path << ":" << number << ": bad region\n";
        continue;
      }
      // "-" is how the file spells "work it out from the spec", since the
      // fields are positional.
      if (region.abi == "-") region.abi.clear();
      if (region.stack_pointer == "-") region.stack_pointer.clear();
      add_region(std::move(region));
    } else if (verb == "mark") {
      Mark mark;
      std::string begin, end;
      fields >> begin >> end >> mark.kind;
      if (!parse_number(begin, mark.begin) || !parse_number(end, mark.end) ||
          mark.kind.empty()) {
        std::cerr << path << ":" << number << ": bad mark\n";
        continue;
      }
      mark.name = rest_of_line(fields);
      add_mark(std::move(mark));
    } else {
      std::cerr << path << ":" << number << ": unknown directive " << verb << "\n";
    }
  }

  return true;
}

bool Project::save(const std::string &path) const {
  std::ofstream file(path);
  if (!file) return false;

  file << "# ddd project file -- one decision per line, edit freely.\n";
  for (const auto &entry : functions_)
    file << "function " << hex(entry.first) << " " << entry.second << "\n";
  for (const auto &entry : variables_)
    file << "variable " << hex(entry.first.first) << " " << entry.first.second << " "
         << entry.second << "\n";
  for (const auto &entry : comments_)
    file << "comment " << hex(entry.first) << " " << entry.second << "\n";
  for (const auto &entry : types_)
    file << "type " << hex(entry.first.first) << " " << entry.first.second << " "
         << entry.second << "\n";
  for (const auto &entry : signatures_)
    file << "signature " << hex(entry.first) << " " << entry.second << "\n";
  for (const auto &entry : data_)
    file << "data " << hex(entry.first) << " " << hex(entry.second) << "\n";
  for (uint64_t address : undefined_)
    file << "undefine " << hex(address) << "\n";
  for (const Mark &mark : marks_)
    file << "mark " << hex(mark.begin) << " " << hex(mark.end) << " "
         << mark.kind << " " << mark.name << "\n";
  for (const RegionSpec &region : regions_)
    file << "region " << hex(region.begin) << " " << hex(region.end) << " "
         << region.spec << " " << (region.abi.empty() ? "-" : region.abi) << " "
         << (region.stack_pointer.empty() ? "-" : region.stack_pointer) << "\n";

  return true;
}

} // namespace ddd
