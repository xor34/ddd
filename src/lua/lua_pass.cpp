// lua_pass.cpp -- registering things from Lua.
//
// A pass declared in a workflow's `passes` scope ends up in the same registry
// as one written in C++, under a name --passes can ask for, with a description
// --list_passes prints. Nothing downstream can tell the difference, which is
// the point: the split between the two languages is an implementation detail
// of this tool, not a category the user has to think about.
#include "../pass.h"
#include "lua_env.h"
#include "lua_util.h"

#include <ostream>
#include <string>

namespace ddd {
namespace lua {
namespace {

// The Lua function is kept in the registry: a pass outlives the call that
// declared it, and the stack it was passed on is long gone by the time the
// pipeline runs.
class LuaPass final : public Pass {
public:
  LuaPass(std::string name, std::string description, int run_ref)
      : name_(std::move(name)), description_(std::move(description)),
        run_ref_(run_ref) {}

  std::string name() const override { return name_; }
  std::string description() const override { return description_; }

  void run(SsaFunction &fn, PassContext &ctx) override {
    lua_State *L = LuaEnv::instance().state();

    lua_rawgeti(L, LUA_REGISTRYINDEX, run_ref_);
    push_function(L, &fn);
    push_context(L, &ctx);

    // A pass that raises is reported and skipped. One plugin throwing must not
    // abandon the rest of the pipeline, which is the whole listing.
    std::string error;
    if (!pcall(L, 2, 0, error))
      ctx.stream() << "  " << name_ << ": " << error << "\n";
  }

private:
  std::string name_;
  std::string description_;
  int run_ref_;
};

// Pulls a string field out of the table at `index`.
std::string field(lua_State *L, int index, const char *key,
                  const std::string &fallback = {}) {
  lua_getfield(L, index, key);
  const std::string value =
      lua_isstring(L, -1) ? std::string(lua_tostring(L, -1)) : fallback;
  lua_pop(L, 1);
  return value;
}

// Takes the function at `key` and moves it into the registry.
int function_ref(lua_State *L, int index, const char *key) {
  lua_getfield(L, index, key);
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 1);
    return LUA_NOREF;
  }
  return luaL_ref(L, LUA_REGISTRYINDEX);
}

// ddd.core.register_pass{name=, description=, run=function(fn, ctx) end}
int register_pass(lua_State *L) {
  luaL_checktype(L, 1, LUA_TTABLE);

  const std::string name = field(L, 1, "name");
  if (name.empty())
    return luaL_error(L, "a pass needs a name");

  const std::string description = field(L, 1, "description");
  const int run = function_ref(L, 1, "run");
  if (run == LUA_NOREF)
    return luaL_error(L, "pass '%s' has no run function", name.c_str());

  PassRegistry::instance().add(PassRegistry::Entry{
      name, description, [name, description, run] {
        return std::unique_ptr<Pass>(new LuaPass(name, description, run));
      }});

  lua_pushboolean(L, 1);
  return 1;
}

// ddd.core.register_ui{name=, description=, workflow=, run=function() end}
int register_ui(lua_State *L) {
  luaL_checktype(L, 1, LUA_TTABLE);

  UiEntry entry;
  entry.name = field(L, 1, "name");
  if (entry.name.empty())
    return luaL_error(L, "an interface needs a name");

  entry.description = field(L, 1, "description");
  entry.workflow = field(L, 1, "workflow");
  entry.run_ref = function_ref(L, 1, "run");
  if (entry.run_ref == LUA_NOREF)
    return luaL_error(L, "interface '%s' has no run function",
                      entry.name.c_str());

  UiRegistry::instance().add(std::move(entry));

  lua_pushboolean(L, 1);
  return 1;
}

// Every pass this binary knows about, C++ and Lua alike, in registration
// order -- what --list_passes prints and what a command palette offers.
int registered_passes(lua_State *L) {
  const std::vector<PassRegistry::Entry> &entries =
      PassRegistry::instance().entries();

  lua_createtable(L, static_cast<int>(entries.size()), 0);
  for (size_t i = 0; i < entries.size(); ++i) {
    lua_createtable(L, 0, 2);
    set_string(L, "name", entries[i].name);
    set_string(L, "description", entries[i].description);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  return 1;
}

int registered_uis(lua_State *L) {
  const std::vector<UiEntry> &entries = UiRegistry::instance().entries();

  lua_createtable(L, static_cast<int>(entries.size()), 0);
  for (size_t i = 0; i < entries.size(); ++i) {
    lua_createtable(L, 0, 3);
    set_string(L, "name", entries[i].name);
    set_string(L, "description", entries[i].description);
    set_string(L, "workflow", entries[i].workflow);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  return 1;
}

// The pipeline the command line asked for, which is what an interface should
// run when it has not been told otherwise.
int default_passes(lua_State *L) {
  const std::vector<std::string> &passes = LuaEnv::instance().default_passes();

  lua_createtable(L, static_cast<int>(passes.size()), 0);
  for (size_t i = 0; i < passes.size(); ++i) {
    lua_pushlstring(L, passes[i].data(), passes[i].size());
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  return 1;
}

const luaL_Reg kFunctions[] = {{"register_pass", register_pass},
                               {"register_ui", register_ui},
                               {"passes", registered_passes},
                               {"uis", registered_uis},
                               {"default_passes", default_passes},
                               {nullptr, nullptr}};

} // namespace

void open_pass(lua_State *L) { luaL_setfuncs(L, kFunctions, 0); }

} // namespace lua
} // namespace ddd
