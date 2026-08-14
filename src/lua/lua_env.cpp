#include "lua_env.h"

#include "lua_util.h"

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

namespace ddd {
namespace {

LuaEnv *g_instance = nullptr;

// The registry table that keeps one userdata per C++ pointer. Values are weak,
// so an object nothing in Lua holds is collected like anything else.
constexpr const char *kObjects = "ddd.objects";

int traceback_handler(lua_State *L) {
  const char *message = lua_tostring(L, 1);
  luaL_traceback(L, L, message != nullptr ? message : "(non-string error)", 1);
  return 1;
}

bool looks_like_root(const std::filesystem::path &path) {
  std::error_code ignored;
  return std::filesystem::exists(path / "ddd" / "init.lua", ignored);
}

// Walks up from `start` looking for a directory called `lua` that has the
// standard library in it.
std::string search_upwards(std::filesystem::path start) {
  std::error_code ignored;
  for (int depth = 0; depth < 8 && !start.empty(); ++depth) {
    const std::filesystem::path candidate = start / "lua";
    if (looks_like_root(candidate))
      return candidate.string();

    const std::filesystem::path parent = start.parent_path();
    if (parent == start)
      break;
    start = parent;
  }
  return {};
}

std::filesystem::path executable_directory() {
  std::error_code error;
  const std::filesystem::path exe =
      std::filesystem::read_symlink("/proc/self/exe", error);
  return error ? std::filesystem::path() : exe.parent_path();
}

} // namespace

std::string default_lua_root() {
  if (const char *from_environment = std::getenv("DDD_LUA");
      from_environment != nullptr && *from_environment != '\0')
    return from_environment;

  std::error_code error;
  if (std::string found = search_upwards(std::filesystem::current_path(error));
      !found.empty())
    return found;

  // Built into build/<plat>/<arch>/<mode>/, so the tree it was built from is
  // several levels up. Walking finds it wherever it is.
  if (std::filesystem::path exe = executable_directory(); !exe.empty())
    return search_upwards(exe);

  return {};
}

// ---- the environment ----------------------------------------------------

LuaEnv::LuaEnv() {
  state_ = luaL_newstate();
  luaL_openlibs(state_);

  // The identity tables for bound objects, one per type, filled in on demand.
  // This one holds them and is not itself weak.
  lua_newtable(state_);
  lua_setfield(state_, LUA_REGISTRYINDEX, kObjects);

  // `ddd.core` is what this file's bindings are; `require "ddd"` gets the Lua
  // library written on top of them, which is where the workflow DSL and the
  // interface toolkit live. Presetting package.loaded is what stops require
  // from going looking for a ddd/core.lua that does not exist.
  lua_newtable(state_);
  lua::open_ssa(state_);
  lua::open_pattern(state_);
  lua::open_pass(state_);
  lua::open_reaching(state_);
  lua::open_session(state_);

  lua_pushvalue(state_, -1);
  lua_setglobal(state_, "ddd_core");

  lua_getglobal(state_, "package");
  lua_getfield(state_, -1, "loaded");
  lua_pushvalue(state_, -3);
  lua_setfield(state_, -2, "ddd.core");
  lua_pop(state_, 3); // loaded, package, the core table

  g_instance = this;
}

LuaEnv::~LuaEnv() {
  if (g_instance == this)
    g_instance = nullptr;
  if (state_ != nullptr)
    lua_close(state_);
}

LuaEnv &LuaEnv::instance() {
  static LuaEnv env;
  return env;
}

bool LuaEnv::started() { return g_instance != nullptr; }

void LuaEnv::add_path(const std::string &root) {
  lua_getglobal(state_, "package");

  lua_getfield(state_, -1, "path");
  if (!lua_isstring(state_, -1))
    luaL_error(state_, "package.path is not a string");
  const std::string existing = lua_tostring(state_, -1);
  lua_pop(state_, 1);

  const std::string added =
      root + "/?.lua;" + root + "/?/init.lua;" + existing;
  lua_pushlstring(state_, added.data(), added.size());
  lua_setfield(state_, -2, "path");

  lua_pop(state_, 1);
}

bool LuaEnv::run_string(const std::string &chunk, const std::string &name,
                        std::string &error) {
  if (luaL_loadbuffer(state_, chunk.data(), chunk.size(), name.c_str()) !=
      LUA_OK) {
    error = lua_tostring(state_, -1);
    lua_pop(state_, 1);
    return false;
  }
  return lua::pcall(state_, 0, 0, error);
}

bool LuaEnv::run_file(const std::string &path, std::string &error) {
  if (luaL_loadfile(state_, path.c_str()) != LUA_OK) {
    error = lua_tostring(state_, -1);
    lua_pop(state_, 1);
    return false;
  }
  return lua::pcall(state_, 0, 0, error);
}

bool LuaEnv::load_plugins(const std::string &root, std::string &error) {
  add_path(root);

  const std::filesystem::path directory = std::filesystem::path(root) / "plugins";
  std::error_code ignored;
  if (!std::filesystem::is_directory(directory, ignored)) {
    error = "no plugins directory at " + directory.string();
    return false;
  }

  // Name order, so a plugin that others build on can be called 00-something
  // and there is a way to say what runs first that does not need a manifest.
  std::vector<std::filesystem::path> found;
  for (const auto &entry : std::filesystem::directory_iterator(directory)) {
    if (entry.is_regular_file() && entry.path().extension() == ".lua")
      found.push_back(entry.path());
    else if (entry.is_directory() &&
             std::filesystem::exists(entry.path() / "init.lua", ignored))
      found.push_back(entry.path() / "init.lua");
  }
  std::sort(found.begin(), found.end());

  // One broken plugin does not take the rest down with it: every failure is
  // collected and the loading carries on.
  bool ok = true;
  for (const std::filesystem::path &path : found) {
    std::string failure;
    if (run_file(path.string(), failure))
      continue;
    ok = false;
    if (!error.empty())
      error += "\n";
    error += failure;
  }

  return ok;
}

std::vector<std::string> LuaEnv::pipeline(const std::string &name) {
  std::vector<std::string> passes;

  lua_getglobal(state_, "require");
  lua_pushstring(state_, "ddd.workflow");

  std::string error;
  if (!lua::pcall(state_, 1, 1, error))
    return passes;

  lua_getfield(state_, -1, "pipeline");
  lua_pushlstring(state_, name.data(), name.size());
  if (!lua::pcall(state_, 1, 1, error)) {
    lua_pop(state_, 1);
    return passes;
  }

  if (lua_istable(state_, -1)) {
    const lua_Integer count = luaL_len(state_, -1);
    for (lua_Integer i = 1; i <= count; ++i) {
      lua_rawgeti(state_, -1, i);
      if (lua_isstring(state_, -1))
        passes.push_back(lua_tostring(state_, -1));
      lua_pop(state_, 1);
    }
  }

  lua_pop(state_, 2); // the result and the module
  return passes;
}

void LuaEnv::set_session(Session *session) {
  session_ = session;
  lua::bind_session(state_, session);
}

// ---- the interface registry ---------------------------------------------

UiRegistry &UiRegistry::instance() {
  static UiRegistry registry;
  return registry;
}

void UiRegistry::add(UiEntry entry) {
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const UiEntry &e) { return e.name == entry.name; });
  if (it != entries_.end())
    *it = std::move(entry);
  else
    entries_.push_back(std::move(entry));
}

const UiEntry *UiRegistry::find(const std::string &name) const {
  auto it = std::find_if(entries_.begin(), entries_.end(),
                         [&](const UiEntry &e) { return e.name == name; });
  return it == entries_.end() ? nullptr : &*it;
}

bool run_ui(LuaEnv &env, const std::string &name, std::string &error) {
  const UiEntry *entry = UiRegistry::instance().find(name);
  if (entry == nullptr) {
    error = "no interface called " + name;
    return false;
  }

  lua_State *L = env.state();
  lua_rawgeti(L, LUA_REGISTRYINDEX, entry->run_ref);
  return lua::pcall(L, 0, 0, error);
}

namespace lua {

void push_object(lua_State *L, void *pointer, const char *metatable) {
  if (pointer == nullptr) {
    lua_pushnil(L);
    return;
  }

  // One cache per type, not one for the whole process. Functions are analysed
  // one after another and the allocator reuses addresses, so a pointer alone
  // would eventually hand back the userdata made for a different kind of
  // object that used to live there -- and it would still be carrying the old
  // type's metatable.
  lua_getfield(L, LUA_REGISTRYINDEX, kObjects);
  if (lua_getfield(L, -1, metatable) != LUA_TTABLE) {
    lua_pop(L, 1);

    lua_newtable(L);
    lua_newtable(L);
    lua_pushstring(L, "v");
    lua_setfield(L, -2, "__mode");
    lua_setmetatable(L, -2);

    lua_pushvalue(L, -1);
    lua_setfield(L, -3, metatable);
  }
  lua_remove(L, -2); // the table of caches

  lua_pushlightuserdata(L, pointer);
  if (lua_rawget(L, -2) == LUA_TUSERDATA) {
    lua_remove(L, -2); // this type's cache
    return;
  }
  lua_pop(L, 1); // the nil

  // One user value: scratch space, so a pass can keep a counter on its context
  // without the binding having to know what a counter is.
  void **box = static_cast<void **>(lua_newuserdatauv(L, sizeof(void *), 1));
  *box = pointer;
  luaL_setmetatable(L, metatable);

  lua_pushlightuserdata(L, pointer);
  lua_pushvalue(L, -2);
  lua_rawset(L, -4);

  lua_remove(L, -2); // this type's cache
}

void *check_object(lua_State *L, int index, const char *metatable) {
  void **box = static_cast<void **>(luaL_checkudata(L, index, metatable));
  return *box;
}

void new_metatable(lua_State *L, const char *name, const luaL_Reg *methods,
                   const luaL_Reg *extra) {
  luaL_newmetatable(L, name);

  if (methods != nullptr) {
    lua_newtable(L);
    luaL_setfuncs(L, methods, 0);
    lua_setfield(L, -2, "__index");
  }
  if (extra != nullptr)
    luaL_setfuncs(L, extra, 0);

  lua_pushstring(L, name);
  lua_setfield(L, -2, "__name");

  lua_pop(L, 1);
}

bool pcall(lua_State *L, int nargs, int nresults, std::string &error) {
  const int base = lua_gettop(L) - nargs; // the function itself
  lua_pushcfunction(L, traceback_handler);
  lua_insert(L, base);

  const int status = lua_pcall(L, nargs, nresults, base);
  lua_remove(L, base);

  if (status == LUA_OK)
    return true;

  const char *message = lua_tostring(L, -1);
  error = message != nullptr ? message : "unknown error";
  lua_pop(L, 1);
  return false;
}

} // namespace lua
} // namespace ddd
