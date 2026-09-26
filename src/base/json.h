// json.h -- just enough JSON to answer a request.
//
// Writing only. The server never parses JSON: requests arrive as command
// lines, the same vocabulary the interactive prompt uses, so there is nothing
// to parse and no library to depend on.
#pragma once

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace ddd {
namespace json {

inline std::string quote(const std::string &text) {
  std::ostringstream os;
  os << '"';
  for (char c : text) {
    switch (c) {
    case '"': os << "\\\""; break;
    case '\\': os << "\\\\"; break;
    case '\n': os << "\\n"; break;
    case '\r': os << "\\r"; break;
    case '\t': os << "\\t"; break;
    default:
      if (static_cast<unsigned char>(c) < 0x20) {
        // \u00XX, written by hand to keep the stream's formatting flags out
        // of it -- a stray std::hex here would corrupt every number after.
        static const char *digits = "0123456789abcdef";
        os << "\\u00" << digits[(c >> 4) & 0xf] << digits[c & 0xf];
      } else {
        os << c;
      }
    }
  }
  os << '"';
  return os.str();
}

// Numbers are written in decimal: JavaScript reads hex strings as strings, and
// an address that arrives as a number can be compared and sorted.
inline std::string number(uint64_t value) { return std::to_string(value); }

class Object {
public:
  Object &field(const std::string &name, const std::string &raw_value) {
    if (!first_) body_ << ',';
    first_ = false;
    body_ << quote(name) << ':' << raw_value;
    return *this;
  }

  Object &string_field(const std::string &name, const std::string &value) {
    return field(name, quote(value));
  }
  Object &number_field(const std::string &name, uint64_t value) {
    return field(name, number(value));
  }
  Object &bool_field(const std::string &name, bool value) {
    return field(name, value ? "true" : "false");
  }

  std::string str() const { return "{" + body_.str() + "}"; }

private:
  std::ostringstream body_;
  bool first_ = true;
};

inline std::string array(const std::vector<std::string> &elements) {
  std::ostringstream os;
  os << '[';
  for (size_t i = 0; i < elements.size(); ++i) {
    if (i) os << ',';
    os << elements[i];
  }
  os << ']';
  return os.str();
}

inline std::string string_array(const std::vector<std::string> &values) {
  std::vector<std::string> quoted;
  quoted.reserve(values.size());
  for (const std::string &value : values) quoted.push_back(quote(value));
  return array(quoted);
}

inline std::string number_array(const std::vector<int> &values) {
  std::vector<std::string> written;
  written.reserve(values.size());
  for (int value : values) written.push_back(std::to_string(value));
  return array(written);
}

} // namespace json
} // namespace ddd
