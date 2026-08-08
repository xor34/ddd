#include "project.h"

#include <fstream>
#include <iostream>
#include <sstream>

namespace ddd {
namespace {

bool parse_address(const std::string &text, uint64_t &out) {
  try {
    size_t consumed = 0;
    const int base =
        (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) ? 16 : 10;
    out = std::stoull(text, &consumed, base);
    return consumed == text.size();
  } catch (...) {
    return false;
  }
}

std::string hex(uint64_t value) {
  std::ostringstream os;
  os << "0x" << std::hex << value;
  return os.str();
}

// The rest of the line, with the leading space removed.
std::string tail(std::istringstream &fields) {
  std::string text;
  std::getline(fields, text);
  if (!text.empty() && text.front() == ' ') text.erase(0, 1);
  return text;
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

bool Project::empty() const {
  return functions_.empty() && variables_.empty() && comments_.empty() &&
         types_.empty();
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
      std::string address;
      fields >> address;
      uint64_t value = 0;
      if (!parse_address(address, value)) {
        std::cerr << path << ":" << number << ": bad address\n";
        continue;
      }
      rename_function(value, tail(fields));
    } else if (verb == "variable") {
      std::string address, generated;
      fields >> address >> generated;
      uint64_t value = 0;
      if (!parse_address(address, value)) {
        std::cerr << path << ":" << number << ": bad address\n";
        continue;
      }
      rename_variable(value, generated, tail(fields));
    } else if (verb == "type") {
      std::string address, variable;
      fields >> address >> variable;
      uint64_t value = 0;
      if (!parse_address(address, value)) {
        std::cerr << path << ":" << number << ": bad address\n";
        continue;
      }
      set_type(value, variable, tail(fields));
    } else if (verb == "comment") {
      std::string address;
      fields >> address;
      uint64_t value = 0;
      if (!parse_address(address, value)) {
        std::cerr << path << ":" << number << ": bad address\n";
        continue;
      }
      set_comment(value, tail(fields));
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

  return true;
}

} // namespace ddd
