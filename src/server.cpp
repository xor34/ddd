#include "server.h"

#include "json.h"
#include "session.h"

#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

namespace ddd {
namespace {

std::string error_json(const std::string &message) {
  return json::Object().string_field("error", message).str();
}

std::string ok_json() { return json::Object().bool_field("ok", true).str(); }

std::string xrefs_json(Session &session, uint64_t address) {
  std::vector<std::string> rows;
  for (const Xref &xref : session.xrefs_to(address))
    rows.push_back(json::Object()
                       .number_field("from", xref.from)
                       .string_field("kind", xref.kind)
                       .string_field("in", session.function_name_at(xref.from))
                       .str());
  return json::array(rows);
}

// A listing goes out as tokens rather than text, because a string cannot be
// clicked on and highlighting every occurrence of a variable needs each name
// to arrive with an identity attached.
std::string line_json(const TokenLine &line) {
  std::vector<std::string> tokens;
  for (const Token &token : line.tokens) {
    json::Object object;
    object.string_field("k", token.kind).string_field("s", token.text);
    if (!token.id.empty())
      object.string_field("id", token.id);
    tokens.push_back(object.str());
  }

  return json::Object()
      .number_field("addr", line.addr)
      .field("tokens", json::array(tokens))
      .field("comments", json::string_array(line.comments))
      .str();
}

std::string block_json(Session &session, const TokenBlock &block) {
  std::vector<std::string> lines;
  for (const TokenLine &line : block.lines)
    lines.push_back(line_json(line));

  return json::Object()
      .number_field("id", block.id)
      .number_field("addr", block.addr)
      .bool_field("entry", block.entry)
      .field("preds", json::number_array(block.preds))
      .field("succs", json::number_array(block.succs))
      .field("comments", json::string_array(block.comments))
      .field("lines", json::array(lines))
      // References belong in the listing, not in a panel beside it: what jumps
      // here is a property of the block, and IDA has put it at the label for
      // thirty years because that is where you are looking.
      .field("xrefs", xrefs_json(session, block.addr))
      .str();
}

std::string listing_json(Session &session, uint64_t address) {
  Listing listing = session.listing_at(address);
  if (!listing.ok)
    return error_json(listing.error);

  session.build_xrefs();

  std::vector<std::string> blocks;
  for (const TokenBlock &block : listing.blocks)
    blocks.push_back(block_json(session, block));

  return json::Object()
      .string_field("name", listing.name)
      .number_field("addr", listing.addr)
      .number_field("end", listing.end)
      .field("blocks", json::array(blocks))
      .str();
}

std::string functions_json(Session &session, const std::string &pattern) {
  // Asking what functions are in the file is the point at which it is worth
  // working out, for a file that does not say. Costs a sweep, once.
  session.discover_functions();

  std::vector<std::string> rows;
  for (const FunctionInfo &function : session.functions(pattern))
    rows.push_back(json::Object()
                       .number_field("addr", function.addr)
                       .number_field("size", function.end - function.addr)
                       .string_field("name", function.name)
                       .string_field("symbol", function.symbol)
                       .str());
  return json::Object().field("functions", json::array(rows)).str();
}

std::string data_json(Session &session, uint64_t address, uint64_t count) {
  DataView view = session.data(address, count);

  std::vector<std::string> items;
  for (const DataItem &item : view.items) {
    json::Object object;
    object.number_field("addr", item.addr);
    if (!item.label.empty())
      object.string_field("label", item.label);

    std::vector<std::string> refs;
    for (const Xref &xref : item.xrefs)
      refs.push_back(json::Object()
                         .number_field("from", xref.from)
                         .string_field("kind", xref.kind)
                         .string_field("in", session.function_name_at(xref.from))
                         .str());
    object.field("xrefs", json::array(refs));

    object.string_field("kind", item.kind).number_field("size", item.size);
    if (item.kind == "string") {
      object.string_field("text", item.text);
    } else {
      object.number_field("value", item.value);
      if (!item.points.empty()) {
        object.string_field("points", item.points);
        if (!item.target.empty())
          object.string_field("target", item.target);
      }
    }
    items.push_back(object.str());
  }

  return json::Object()
      .number_field("addr", view.addr)
      .number_field("end", view.end)
      .bool_field("code", view.code)
      .field("items", json::array(items))
      .str();
}

std::string hex_json(Session &session, uint64_t address, uint64_t length) {
  HexView view = session.hex(address, length);

  static const char *digits = "0123456789abcdef";
  std::string bytes;
  bytes.reserve(view.bytes.size() * 2);
  for (uint8_t byte : view.bytes) {
    bytes.push_back(digits[byte >> 4]);
    bytes.push_back(digits[byte & 0xf]);
  }

  std::vector<std::string> strings;
  for (const auto &found : view.strings)
    strings.push_back(json::Object()
                          .number_field("addr", found.first)
                          .string_field("text", found.second)
                          .str());

  return json::Object()
      .number_field("addr", view.addr)
      .bool_field("code", view.code)
      .string_field("bytes", bytes)
      .field("strings", json::array(strings))
      .str();
}

// The rest of a line, with the leading space the reader left behind removed.
std::string rest_of(std::istringstream &fields) {
  std::string text;
  std::getline(fields, text);
  if (!text.empty() && text.front() == ' ')
    text.erase(0, 1);
  return text;
}

uint64_t number_or(const std::string &text, uint64_t fallback) {
  if (text.empty())
    return fallback;
  try {
    return std::stoull(text, nullptr, 0);
  } catch (...) {
    return fallback;
  }
}

} // namespace

int serve(Session &session, std::istream &in, std::ostream &out) {
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream fields(line);
    std::string verb;
    fields >> verb;
    if (verb.empty())
      continue;
    if (verb == "quit")
      break;

    if (verb == "info") {
      out << json::Object()
                 .string_field("describe", session.describe())
                 .number_field("entry", session.entry())
                 .number_field("base", session.image().base())
                 .number_field("limit", session.image().limit())
                 .string_field("project", session.project_path())
                 .str();

    } else if (verb == "functions") {
      std::string pattern;
      fields >> pattern;
      out << functions_json(session, pattern);

    } else if (verb == "function") {
      std::string where;
      fields >> where;
      uint64_t address = 0;
      if (!session.resolve(where, address))
        out << error_json("no code at " + where);
      else
        out << listing_json(session, address);

    } else if (verb == "xrefs") {
      std::string where;
      fields >> where;
      uint64_t address = 0;
      if (!session.resolve(where, address)) {
        out << error_json("cannot resolve " + where);
      } else {
        session.build_xrefs();
        out << json::Object()
                   .number_field("to", address)
                   .field("refs", xrefs_json(session, address))
                   .str();
      }

    } else if (verb == "data" || verb == "hex") {
      std::string where, count;
      fields >> where >> count;
      uint64_t address = 0;
      if (!session.resolve(where, address)) {
        out << error_json("cannot resolve " + where);
      } else if (verb == "data") {
        out << data_json(session, address, number_or(count, 64));
      } else {
        out << hex_json(session, address, number_or(count, 256));
      }

    } else if (verb == "undefine" || verb == "mark-data" || verb == "region" ||
               verb == "signature") {
      // Correcting what was inferred. Every one of these is a person
      // overruling a guess, and all of them are recorded in the project.
      std::string where;
      fields >> where;
      uint64_t address = 0;
      if (!session.resolve(where, address)) {
        out << error_json("cannot resolve " + where);

      } else if (verb == "undefine") {
        session.undefine_function(address);
        out << ok_json();

      } else if (verb == "signature") {
        session.project().set_signature(address, rest_of(fields));
        session.save_project();
        out << ok_json();

      } else {
        std::string second;
        fields >> second;
        uint64_t end = 0;
        if (!session.resolve(second, end)) {
          out << error_json("cannot resolve " + second);
        } else if (verb == "mark-data") {
          session.define_data(address, end);
          out << ok_json();
        } else {
          std::string spec, abi;
          fields >> spec >> abi;
          if (!session.add_region(address, end, spec, abi))
            out << error_json("no spec called " + spec);
          else
            out << ok_json();
        }
      }

    } else if (verb == "rename" || verb == "comment" || verb == "settype") {
      std::string where;
      fields >> where;
      uint64_t address = 0;
      if (!session.resolve(where, address)) {
        out << error_json("cannot resolve " + where);
      } else if (verb == "comment") {
        session.project().set_comment(address, rest_of(fields));
        session.save_project();
        out << ok_json();
      } else {
        // rename/settype <function> <variable> <value>; an empty variable
        // renames the function itself.
        std::string variable;
        fields >> variable;
        const std::string value = rest_of(fields);

        if (verb == "settype")
          session.project().set_type(address, variable, value);
        else if (variable == "-")
          session.project().rename_function(address, value);
        else
          session.project().rename_variable(address, variable, value);

        session.save_project();
        out << ok_json();
      }

    } else {
      out << error_json("unknown command " + verb);
    }

    out << std::endl;
  }

  session.save_project();
  return 0;
}

} // namespace ddd
