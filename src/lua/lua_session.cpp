// lua_session.cpp -- the loaded image, as Lua sees it.
//
// This is what an interface is written against. Everything it needs to draw a
// window full of a binary is here -- what functions there are, what one looks
// like, what refers to an address, what is stored at another, and how to
// record that the user renamed something -- and none of it says anything about
// how any of that should look.
//
// A listing arrives as tokens rather than as text, because a string cannot be
// clicked on: highlighting every occurrence of a variable the way IDA and
// Binary Ninja do needs each name to come with an identity attached, so the
// interface can match `var_c` here against `var_c` there without guessing at
// word boundaries -- which would be wrong anyway, since `RAX` appears inside
// `RAX_2`.
#include "../session.h"
#include "lua_util.h"

#include <string>
#include <vector>

namespace ddd {
namespace lua {
namespace {

constexpr const char *kSessionPointer = "ddd.session.pointer";
constexpr const char *kSessionApi = "ddd.session.api";

// Every function here is called through `ddd.session`, which only exists while
// there is one -- so this is never null in practice, and says so loudly if the
// invariant is ever broken.
Session *session(lua_State *L) {
  lua_getfield(L, LUA_REGISTRYINDEX, kSessionPointer);
  Session *found = static_cast<Session *>(lua_touserdata(L, -1));
  lua_pop(L, 1);
  if (found == nullptr)
    luaL_error(L, "no image is loaded");
  return found;
}

// ---- what is in the file ------------------------------------------------

int session_info(lua_State *L) {
  Session *self = session(L);

  lua_createtable(L, 0, 6);
  set_string(L, "describe", self->describe());
  set_number(L, "entry", static_cast<lua_Integer>(self->entry()));
  set_number(L, "base", static_cast<lua_Integer>(self->image().base()));
  set_number(L, "limit", static_cast<lua_Integer>(self->image().limit()));
  set_number(L, "code_begin",
             static_cast<lua_Integer>(self->image().code_begin()));
  set_number(L, "code_end", static_cast<lua_Integer>(self->image().code_end()));
  set_string(L, "project", self->project_path());

  // Enough of the convention for an interface to suggest a prototype.
  if (const CallingConvention *abi = self->abi()) {
    set_string(L, "abi", abi->name);
    set_string(L, "abi_result", abi->result);

    lua_createtable(L, static_cast<int>(abi->arguments.size()), 0);
    for (size_t i = 0; i < abi->arguments.size(); ++i) {
      lua_pushlstring(L, abi->arguments[i].data(), abi->arguments[i].size());
      lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    lua_setfield(L, -2, "abi_arguments");
  }

  // Whether anyone has decided anything about this binary yet, which is the
  // difference between opening a project and starting one.
  set_boolean(L, "project_empty", self->project().empty());
  return 1;
}

int session_functions(lua_State *L) {
  Session *self = session(L);
  const std::vector<FunctionInfo> found = self->functions(opt_string(L, 1));

  lua_createtable(L, static_cast<int>(found.size()), 0);
  for (size_t i = 0; i < found.size(); ++i) {
    lua_createtable(L, 0, 4);
    set_number(L, "addr", static_cast<lua_Integer>(found[i].addr));
    set_number(L, "size", static_cast<lua_Integer>(found[i].end - found[i].addr));
    set_string(L, "name", found[i].name);
    set_string(L, "symbol", found[i].symbol);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  return 1;
}

// A symbol, a name the user chose, or a number in any base.
int session_resolve(lua_State *L) {
  Session *self = session(L);
  uint64_t address = 0;
  if (!self->resolve(check_string(L, 1), address)) {
    lua_pushnil(L);
    return 1;
  }
  lua_pushinteger(L, static_cast<lua_Integer>(address));
  return 1;
}

void push_range(lua_State *L, const ElfRange &range) {
  lua_createtable(L, 0, 4);
  set_number(L, "addr", static_cast<lua_Integer>(range.begin));
  set_number(L, "end", static_cast<lua_Integer>(range.end));
  set_number(L, "size", static_cast<lua_Integer>(range.end - range.begin));
  set_string(L, "name", range.name);
}

// The function containing an address, or nil.
//
// Nil is the whole point: an address that is not in a function has to come
// back as one that is not in a function, or undefining one changes nothing an
// interface can see. What to *show* there is the interface's problem, and the
// answer is the bytes.
int session_function_at(lua_State *L) {
  Session *self = session(L);
  const uint64_t address = check_address(L, 1);

  const ElfRange *found = self->function_at(address);
  if (found == nullptr) {
    lua_pushnil(L);
    return 1;
  }

  ElfRange range = *found;
  if (const std::string *renamed = self->project().function_name(range.begin))
    range.name = *renamed;

  push_range(L, range);
  return 1;
}

// The stretch that would be lifted at an address, function or not -- which for
// a flat image with no symbols at all is the only way to see any code.
int session_range_at(lua_State *L) {
  Session *self = session(L);

  ElfRange range;
  if (!self->range_at(check_address(L, 1), range)) {
    lua_pushnil(L);
    return 1;
  }

  push_range(L, range);
  return 1;
}

// ---- the listing --------------------------------------------------------

void push_xrefs(lua_State *L, Session &self, uint64_t address) {
  const std::vector<Xref> refs = self.xrefs_to(address);

  lua_createtable(L, static_cast<int>(refs.size()), 0);
  for (size_t i = 0; i < refs.size(); ++i) {
    lua_createtable(L, 0, 4);
    set_number(L, "from", static_cast<lua_Integer>(refs[i].from));
    set_number(L, "to", static_cast<lua_Integer>(refs[i].to));
    set_string(L, "kind", refs[i].kind);
    set_string(L, "in", self.function_name_at(refs[i].from));
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
}

void push_strings(lua_State *L, const std::vector<std::string> &values) {
  lua_createtable(L, static_cast<int>(values.size()), 0);
  for (size_t i = 0; i < values.size(); ++i) {
    lua_pushlstring(L, values[i].data(), values[i].size());
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
}

void push_line(lua_State *L, const TokenLine &line) {
  lua_createtable(L, 0, 3);
  set_number(L, "addr", static_cast<lua_Integer>(line.addr));

  lua_createtable(L, static_cast<int>(line.tokens.size()), 0);
  for (size_t i = 0; i < line.tokens.size(); ++i) {
    const Token &token = line.tokens[i];
    lua_createtable(L, 0, 3);
    // Short names: a big function is tens of thousands of these, and the
    // interface reads every one of them on every redraw.
    set_string(L, "k", token.kind);
    set_string(L, "s", token.text);
    if (!token.id.empty())
      set_string(L, "id", token.id);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "tokens");

  push_strings(L, line.comments);
  lua_setfield(L, -2, "comments");
}

void push_block(lua_State *L, Session &self, const TokenBlock &block) {
  lua_createtable(L, 0, 8);
  set_number(L, "id", block.id);
  set_number(L, "addr", static_cast<lua_Integer>(block.addr));
  set_boolean(L, "entry", block.entry);

  lua_createtable(L, static_cast<int>(block.preds.size()), 0);
  for (size_t i = 0; i < block.preds.size(); ++i) {
    lua_pushinteger(L, block.preds[i]);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "preds");

  lua_createtable(L, static_cast<int>(block.succs.size()), 0);
  for (size_t i = 0; i < block.succs.size(); ++i) {
    lua_pushinteger(L, block.succs[i]);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "succs");

  push_strings(L, block.comments);
  lua_setfield(L, -2, "comments");

  lua_createtable(L, static_cast<int>(block.lines.size()), 0);
  for (size_t i = 0; i < block.lines.size(); ++i) {
    push_line(L, block.lines[i]);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "lines");

  // References belong in the listing, not in a panel beside it: what jumps
  // here is a property of the block, and IDA has put it at the label for
  // thirty years because that is where you are looking.
  push_xrefs(L, self, block.addr);
  lua_setfield(L, -2, "xrefs");
}

// A list of pass names out of the options table, if it has one.
std::vector<std::string> passes_from(lua_State *L, int index) {
  std::vector<std::string> passes;
  if (lua_isnoneornil(L, index))
    return passes;

  lua_getfield(L, index, "passes");
  if (lua_istable(L, -1)) {
    const lua_Integer count = luaL_len(L, -1);
    for (lua_Integer i = 1; i <= count; ++i) {
      lua_rawgeti(L, -1, i);
      if (lua_isstring(L, -1))
        passes.push_back(lua_tostring(L, -1));
      lua_pop(L, 1);
    }
  }
  lua_pop(L, 1);
  return passes;
}

bool flag_from(lua_State *L, int index, const char *key, bool fallback) {
  if (lua_isnoneornil(L, index))
    return fallback;
  lua_getfield(L, index, key);
  const bool value = lua_isnil(L, -1) ? fallback : lua_toboolean(L, -1);
  lua_pop(L, 1);
  return value;
}

// session.listing(address, { passes = {...}, tokens = true, machine = false })
int session_listing(lua_State *L) {
  Session *self = session(L);
  const uint64_t address = check_address(L, 1);

  ListingRequest request;
  request.passes = passes_from(L, 2);
  request.tokens = flag_from(L, 2, "tokens", true);
  request.machine = flag_from(L, 2, "machine", false);
  request.verbose = flag_from(L, 2, "verbose", false);

  Listing listing = self->listing_at(address, request);

  lua_createtable(L, 0, 7);
  set_boolean(L, "ok", listing.ok);
  if (!listing.ok) {
    set_string(L, "error", listing.error);
    return 1;
  }

  set_string(L, "name", listing.name);
  set_string(L, "target", listing.target);
  set_number(L, "addr", static_cast<lua_Integer>(listing.addr));
  set_number(L, "end", static_cast<lua_Integer>(listing.end));
  set_string(L, "text", listing.text);

  self->build_xrefs();

  lua_createtable(L, static_cast<int>(listing.blocks.size()), 0);
  for (size_t i = 0; i < listing.blocks.size(); ++i) {
    push_block(L, *self, listing.blocks[i]);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "blocks");

  return 1;
}

int session_xrefs(lua_State *L) {
  Session *self = session(L);
  self->build_xrefs();
  push_xrefs(L, *self, check_address(L, 1));
  return 1;
}

// Where the functions are in a file that does not say. Costs a sweep the first
// time and is remembered, so an interface can ask on the way up.
int session_discover_functions(lua_State *L) {
  Session *self = session(L);
  self->discover_functions();
  lua_pushinteger(L, static_cast<lua_Integer>(self->functions().size()));
  return 1;
}

// For a plugin with better evidence than "something calls it": a prologue
// scan, a signature database, a person who knows.
int session_define_function(lua_State *L) {
  Session *self = session(L);
  self->define_function(check_address(L, 1), check_address(L, 2),
                        check_string(L, 3));
  return 0;
}

int session_build_xrefs(lua_State *L) {
  Session *self = session(L);
  self->build_xrefs();
  lua_pushinteger(L, static_cast<lua_Integer>(self->xref_count()));
  return 1;
}

// ---- data ---------------------------------------------------------------

int session_data(lua_State *L) {
  Session *self = session(L);
  const uint64_t address = check_address(L, 1);
  const uint64_t count =
      lua_isnoneornil(L, 2) ? 64 : static_cast<uint64_t>(luaL_checkinteger(L, 2));

  DataView view = self->data(address, count);

  lua_createtable(L, 0, 4);
  set_number(L, "addr", static_cast<lua_Integer>(view.addr));
  set_number(L, "end", static_cast<lua_Integer>(view.end));
  set_boolean(L, "code", view.code);

  lua_createtable(L, static_cast<int>(view.items.size()), 0);
  for (size_t i = 0; i < view.items.size(); ++i) {
    const DataItem &item = view.items[i];

    lua_createtable(L, 0, 8);
    set_number(L, "addr", static_cast<lua_Integer>(item.addr));
    set_string(L, "kind", item.kind);
    set_number(L, "size", item.size);
    if (!item.label.empty())
      set_string(L, "label", item.label);

    if (item.kind == "string") {
      set_string(L, "text", item.text);
    } else {
      set_number(L, "value", static_cast<lua_Integer>(item.value));
      if (!item.points.empty()) {
        set_string(L, "points", item.points);
        if (!item.target.empty())
          set_string(L, "target", item.target);
      }
    }

    lua_createtable(L, static_cast<int>(item.xrefs.size()), 0);
    for (size_t j = 0; j < item.xrefs.size(); ++j) {
      lua_createtable(L, 0, 3);
      set_number(L, "from", static_cast<lua_Integer>(item.xrefs[j].from));
      set_string(L, "kind", item.xrefs[j].kind);
      set_string(L, "in", self->function_name_at(item.xrefs[j].from));
      lua_rawseti(L, -2, static_cast<lua_Integer>(j + 1));
    }
    lua_setfield(L, -2, "xrefs");

    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "items");

  return 1;
}

int session_hex(lua_State *L) {
  Session *self = session(L);
  const uint64_t address = check_address(L, 1);
  const uint64_t length = lua_isnoneornil(L, 2)
                              ? 256
                              : static_cast<uint64_t>(luaL_checkinteger(L, 2));

  HexView view = self->hex(address, length);

  lua_createtable(L, 0, 4);
  set_number(L, "addr", static_cast<lua_Integer>(view.addr));
  set_boolean(L, "code", view.code);

  // The bytes as a Lua string, one byte per character: an interface formats
  // them however it likes, and this costs one allocation rather than a table
  // of four thousand integers.
  lua_pushlstring(L, reinterpret_cast<const char *>(view.bytes.data()),
                  view.bytes.size());
  lua_setfield(L, -2, "bytes");

  lua_createtable(L, static_cast<int>(view.strings.size()), 0);
  for (size_t i = 0; i < view.strings.size(); ++i) {
    lua_createtable(L, 0, 2);
    set_number(L, "addr", static_cast<lua_Integer>(view.strings[i].first));
    set_string(L, "text", view.strings[i].second);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "strings");

  return 1;
}

// ---- what the user decided ----------------------------------------------

int session_rename_function(lua_State *L) {
  Session *self = session(L);
  self->project().rename_function(check_address(L, 1), check_string(L, 2));
  self->save_project();
  return 0;
}

int session_rename_variable(lua_State *L) {
  Session *self = session(L);
  self->project().rename_variable(check_address(L, 1), check_string(L, 2),
                                  check_string(L, 3));
  self->save_project();
  return 0;
}

int session_set_comment(lua_State *L) {
  Session *self = session(L);
  self->project().set_comment(check_address(L, 1), opt_string(L, 2));
  self->save_project();
  return 0;
}

int session_comment(lua_State *L) {
  Session *self = session(L);
  const std::string *text = self->project().comment(check_address(L, 1));
  if (text == nullptr)
    lua_pushnil(L);
  else
    lua_pushlstring(L, text->data(), text->size());
  return 1;
}

// ---- the region tree ----------------------------------------------------

void push_region(lua_State *L, const RegionTree &tree, int id) {
  const RegionNode &node = tree.node(id);

  lua_createtable(L, 0, 7);
  set_number(L, "id", id);
  set_string(L, "kind", node.kind);
  set_string(L, "name", node.name);
  set_number(L, "addr", static_cast<lua_Integer>(tree.address(id)));
  set_number(L, "size", static_cast<lua_Integer>(node.size));
  // Where it sits inside its parent, which is how it is stored: a block moves
  // with the function it is in.
  set_number(L, "offset", static_cast<lua_Integer>(node.offset));
  set_boolean(L, "user_defined", node.user_defined);
}

// Outermost first: image, segment, function, block. What a breadcrumb reads
// out, and what undefining walks up one step at a time.
int session_region_path(lua_State *L) {
  Session *self = session(L);
  const RegionTree &tree = self->regions_tree();
  const std::vector<int> path = tree.path(check_address(L, 1));

  lua_createtable(L, static_cast<int>(path.size()), 0);
  for (size_t i = 0; i < path.size(); ++i) {
    push_region(L, tree, path[i]);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  return 1;
}

int session_regions_in(lua_State *L) {
  Session *self = session(L);
  const RegionTree &tree = self->regions_tree();

  const int id = static_cast<int>(luaL_checkinteger(L, 1));
  const std::vector<int> children = tree.children_of(id);

  lua_createtable(L, static_cast<int>(children.size()), 0);
  for (size_t i = 0; i < children.size(); ++i) {
    push_region(L, tree, children[i]);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  return 1;
}

// session.define_region(addr, size, kind, name)
//
// Anything worth marking: a jump table, a string, a single integer inside a
// blob. The tree works out what it goes inside.
int session_define_region(lua_State *L) {
  Session *self = session(L);
  RegionTree &tree = self->regions_tree();

  const int id = self->define_region(check_address(L, 1), check_address(L, 2),
                                     check_string(L, 3), opt_string(L, 4));
  if (id < 0) {
    lua_pushnil(L);
    return 1;
  }

  push_region(L, tree, id);
  return 1;
}

// session.undefine_at(addr, levels) -- the innermost region, or `levels` steps
// out from it. Returns what was undefined.
int session_undefine_at(lua_State *L) {
  Session *self = session(L);
  const int levels =
      lua_isnoneornil(L, 2) ? 0 : static_cast<int>(luaL_checkinteger(L, 2));

  const std::string kind = self->undefine_at(check_address(L, 1), levels);
  if (kind.empty())
    lua_pushnil(L);
  else
    lua_pushlstring(L, kind.data(), kind.size());
  return 1;
}

// ---- correcting what was inferred ---------------------------------------

int session_undefine_function(lua_State *L) {
  session(L)->undefine_function(check_address(L, 1));
  return 0;
}

int session_define_data(lua_State *L) {
  session(L)->define_data(check_address(L, 1), check_address(L, 2));
  return 0;
}

// Code is blocks: this returns where the block that starts here ends, or nil.
int session_define_code(lua_State *L) {
  const uint64_t end = session(L)->define_code(check_address(L, 1));
  if (end == 0)
    lua_pushnil(L);
  else
    lua_pushinteger(L, static_cast<lua_Integer>(end));
  return 1;
}

// The stronger claim, with a name from the symbol table if there is one.
int session_define_function_at(lua_State *L) {
  const uint64_t end = session(L)->define_function_at(check_address(L, 1));
  if (end == 0)
    lua_pushnil(L);
  else
    lua_pushinteger(L, static_cast<lua_Integer>(end));
  return 1;
}

// The length of the string that was defined, or nil if there is nothing
// readable at that address.
int session_define_string(lua_State *L) {
  const uint64_t size = session(L)->define_string(check_address(L, 1));
  if (size == 0)
    lua_pushnil(L);
  else
    lua_pushinteger(L, static_cast<lua_Integer>(size));
  return 1;
}

// session.add_region(begin, end, spec, abi, stack_pointer)
int session_add_region(lua_State *L) {
  Session *self = session(L);
  const bool ok = self->add_region(check_address(L, 1), check_address(L, 2),
                                   check_string(L, 3), opt_string(L, 4),
                                   opt_string(L, 5));
  lua_pushboolean(L, ok);
  return 1;
}

int session_specs(lua_State *L) {
  const std::vector<std::string> specs = session(L)->available_specs();

  lua_createtable(L, static_cast<int>(specs.size()), 0);
  for (size_t i = 0; i < specs.size(); ++i) {
    lua_pushlstring(L, specs[i].data(), specs[i].size());
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  return 1;
}

// A prototype, in the shape Binary Ninja takes one:
//   int compute(int n @ RDI, char *name @ RSI)
int session_set_signature(lua_State *L) {
  Session *self = session(L);
  self->project().set_signature(check_address(L, 1), opt_string(L, 2));
  self->save_project();
  return 0;
}

int session_signature(lua_State *L) {
  Session *self = session(L);
  const std::string *text = self->project().signature(check_address(L, 1));
  if (text == nullptr)
    lua_pushnil(L);
  else
    lua_pushlstring(L, text->data(), text->size());
  return 1;
}

int session_set_type(lua_State *L) {
  Session *self = session(L);
  self->project().set_type(check_address(L, 1), check_string(L, 2),
                           check_string(L, 3));
  self->save_project();
  return 0;
}

int session_save(lua_State *L) {
  lua_pushboolean(L, session(L)->save_project());
  return 1;
}

const luaL_Reg kSessionFunctions[] = {
    {"info", session_info},
    {"functions", session_functions},
    {"resolve", session_resolve},
    {"function_at", session_function_at},
    {"range_at", session_range_at},
    {"listing", session_listing},
    {"xrefs", session_xrefs},
    {"build_xrefs", session_build_xrefs},
    {"discover_functions", session_discover_functions},
    {"define_function", session_define_function},
    {"data", session_data},
    {"hex", session_hex},
    {"rename_function", session_rename_function},
    {"rename_variable", session_rename_variable},
    {"set_comment", session_set_comment},
    {"comment", session_comment},
    {"set_type", session_set_type},
    {"region_path", session_region_path},
    {"regions_in", session_regions_in},
    {"define_region", session_define_region},
    {"undefine_at", session_undefine_at},
    {"undefine_function", session_undefine_function},
    {"define_data", session_define_data},
    {"define_code", session_define_code},
    {"define_function_at", session_define_function_at},
    {"define_string", session_define_string},
    {"add_region", session_add_region},
    {"specs", session_specs},
    {"set_signature", session_set_signature},
    {"signature", session_signature},
    {"save", session_save},
    {nullptr, nullptr}};

} // namespace

void open_session(lua_State *L) {
  // Built now, installed when there is an image to answer about. A plugin can
  // therefore test `if ddd.session then` and mean it.
  lua_newtable(L);
  luaL_setfuncs(L, kSessionFunctions, 0);
  lua_setfield(L, LUA_REGISTRYINDEX, kSessionApi);
}

void bind_session(lua_State *L, Session *session) {
  lua_pushlightuserdata(L, session);
  lua_setfield(L, LUA_REGISTRYINDEX, kSessionPointer);

  lua_getglobal(L, "ddd_core");
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    return;
  }

  if (session != nullptr)
    lua_getfield(L, LUA_REGISTRYINDEX, kSessionApi);
  else
    lua_pushnil(L);
  lua_setfield(L, -2, "session");

  lua_pop(L, 1);
}

} // namespace lua
} // namespace ddd
