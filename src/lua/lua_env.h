// lua_env.h -- the Lua half of the tool.
//
// The engines stay in C++ -- lifting, SSA construction, dominance, the two
// dataflow solvers, the expression builder. Everything above them is a policy
// decision about how to read a binary, and policy is exactly what people want
// to change without recompiling: which analyses run, what an idiom means, what
// the interface looks like.
//
// So this embeds Lua, hands it the IR, and lets it register passes and
// interfaces that the rest of the tool cannot tell from the built-in ones.
#pragma once

#include <string>
#include <vector>

struct lua_State;

namespace ddd {

class Session;

// Where the standard library and the plugins live:
//
//   <root>/ddd/*.lua        require "ddd", "ddd.ui.pane", ...
//   <root>/plugins/*.lua    loaded at startup, in name order
//   <root>/plugins/*/init.lua
//
// Returns an empty string when nothing that looks like one can be found.
std::string default_lua_root();

class LuaEnv {
public:
  LuaEnv();
  ~LuaEnv();

  LuaEnv(const LuaEnv &) = delete;
  LuaEnv &operator=(const LuaEnv &) = delete;

  // The one this process uses. A pass registered from Lua has to find its way
  // back to the state that defined it, and it is handed nothing but an
  // SsaFunction to do it with.
  static LuaEnv &instance();
  static bool started();

  lua_State *state() const { return state_; }

  // Puts <root>/?.lua and <root>/?/init.lua on package.path.
  void add_path(const std::string &root);

  // Runs every plugin under <root>/plugins, in name order. Reports what
  // failed on `error` and keeps going: one broken plugin should not take the
  // rest of them down with it.
  bool load_plugins(const std::string &root, std::string &error);

  bool run_file(const std::string &path, std::string &error);
  bool run_string(const std::string &chunk, const std::string &name,
                  std::string &error);

  // A pipeline a workflow declared, by name. The order passes run in is a
  // decision about how to read a binary, so it is declared in Lua with the
  // passes themselves rather than duplicated in a flag's default value; this
  // is how the command line asks what it is.
  std::vector<std::string> pipeline(const std::string &name);

  // The session the interfaces work against; null in batch mode, in which case
  // `ddd.session` is nil and a plugin that needs one says so itself.
  void set_session(Session *session);
  Session *session() const { return session_; }

  // Anything the interfaces should be able to reach that is not in the
  // session: the default pipeline, mostly.
  void set_default_passes(std::vector<std::string> passes) {
    default_passes_ = std::move(passes);
  }
  const std::vector<std::string> &default_passes() const {
    return default_passes_;
  }

private:
  lua_State *state_ = nullptr;
  Session *session_ = nullptr;
  std::vector<std::string> default_passes_;
};

// ---- the interfaces Lua registers ---------------------------------------

// A user interface is a plugin like any other: it registers a name and a
// function, and `--ui=<name>` runs it. Nothing in C++ draws anything.
struct UiEntry {
  std::string name;
  std::string description;
  std::string workflow; // the workflow whose ui scope declared it
  int run_ref = 0;      // LUA_REGISTRYINDEX reference to the function
};

class UiRegistry {
public:
  static UiRegistry &instance();

  void add(UiEntry entry); // replaces an entry of the same name
  const UiEntry *find(const std::string &name) const;
  const std::vector<UiEntry> &entries() const { return entries_; }

private:
  std::vector<UiEntry> entries_;
};

// Runs the named interface. Returns false (with `error` set) if there is no
// such interface or it raised.
bool run_ui(LuaEnv &env, const std::string &name, std::string &error);

} // namespace ddd
