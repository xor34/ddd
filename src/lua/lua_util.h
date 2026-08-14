// lua_util.h -- the small amount of glue every binding file needs.
//
// Objects are handed to Lua as a pointer in a userdata with a metatable, and
// the same pointer always comes back as the same userdata, so `op == op` means
// what it looks like and a plugin can use one as a table key. They are valid
// for as long as the C++ object is -- which for an SsaFunction and everything
// in it means the pass it was handed to. A plugin that stashes one in an
// upvalue and reads it next time is holding a dangling pointer; nothing here
// can stop that, so it is written down instead.
#pragma once

#include <string>
#include <cstdint>

extern "C" {
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"
}

namespace ddd {

class SsaFunction;
struct SsaOp;
struct SsaValue;
struct PassContext;
struct Pattern;
class Session;

namespace lua {

// Metatable names, one per bound type.
inline constexpr const char *kFunction = "ddd.function";
inline constexpr const char *kOp = "ddd.op";
inline constexpr const char *kValue = "ddd.value";
inline constexpr const char *kContext = "ddd.context";
inline constexpr const char *kPattern = "ddd.pattern";

// ---- objects ------------------------------------------------------------

// Pushes `pointer` as a userdata of type `metatable`, reusing the one already
// made for it if there is one. Pushes nil for a null pointer.
void push_object(lua_State *L, void *pointer, const char *metatable);

// The pointer inside a userdata of type `metatable`, or a Lua error.
void *check_object(lua_State *L, int index, const char *metatable);

// Creates a metatable with `methods` reachable through __index, plus whatever
// else `extra` sets on the metatable itself (__index as a function, __tostring,
// __eq, ...). Leaves the stack as it found it.
void new_metatable(lua_State *L, const char *name, const luaL_Reg *methods,
                   const luaL_Reg *extra = nullptr);

// ---- calling ------------------------------------------------------------

// lua_pcall with a traceback handler installed. On failure `error` holds the
// message and the traceback, and the stack is back where it started.
bool pcall(lua_State *L, int nargs, int nresults, std::string &error);

// ---- small conveniences -------------------------------------------------

inline void set_string(lua_State *L, const char *key, const std::string &value) {
  lua_pushlstring(L, value.data(), value.size());
  lua_setfield(L, -2, key);
}

inline void set_number(lua_State *L, const char *key, lua_Integer value) {
  lua_pushinteger(L, value);
  lua_setfield(L, -2, key);
}

inline void set_boolean(lua_State *L, const char *key, bool value) {
  lua_pushboolean(L, value);
  lua_setfield(L, -2, key);
}

// Pushes `*value`, or nil if there is no such string -- which all over this
// binding layer means "nobody has said one", not an error.
inline void push_optional_string(lua_State *L, const std::string *value) {
  if (value == nullptr)
    lua_pushnil(L);
  else
    lua_pushlstring(L, value->data(), value->size());
}

// Pushes `address`, or nil for the zero that a Session method uses to mean
// "nothing there" -- 0 is never a real address in these calls, since it would
// be inside the ELF header.
inline void push_address_or_nil(lua_State *L, uint64_t address) {
  if (address == 0)
    lua_pushnil(L);
  else
    lua_pushinteger(L, static_cast<lua_Integer>(address));
}

// An address argument, which is a plain integer everywhere in this interface.
inline uint64_t check_address(lua_State *L, int index) {
  return static_cast<uint64_t>(luaL_checkinteger(L, index));
}

inline std::string check_string(lua_State *L, int index) {
  size_t length = 0;
  const char *text = luaL_checklstring(L, index, &length);
  return std::string(text, length);
}

inline std::string opt_string(lua_State *L, int index,
                              const std::string &fallback = {}) {
  if (lua_isnoneornil(L, index))
    return fallback;
  return check_string(L, index);
}

// ---- iterating ------------------------------------------------------------
//
// A stateful Lua iterator over indices 0..count-1 of an object sitting in
// upvalue 1, with upvalue 2 the next index to hand out. Instantiating this
// template *is* the iterator function -- `Fetch` gets the object back (a
// check_* / to_* function), `Count` says how many items it has, and `Push`
// puts the next one on the stack. Used for the `fn:values()` / `fn:blocks()`
// / `value:uses()` family, whose bodies would otherwise differ only in those
// three things.
//
// Not every iterator fits this shape: one that yields two values per step, or
// that walks something nested (blocks, then ops within a block), needs its
// own hand-rolled closure and is left as one.
template <typename Object, Object *(*Fetch)(lua_State *, int),
         int (*Count)(Object &), void (*Push)(lua_State *, Object &, int)>
int iterate(lua_State *L) {
  Object *object = Fetch(L, lua_upvalueindex(1));
  const int next = static_cast<int>(lua_tointeger(L, lua_upvalueindex(2)));

  if (next >= Count(*object))
    return 0;

  lua_pushinteger(L, next + 1);
  lua_replace(L, lua_upvalueindex(2));
  Push(L, *object, next);
  return 1;
}

// ---- the bound types ----------------------------------------------------

SsaOp *check_op(lua_State *L, int index);
SsaValue *check_value(lua_State *L, int index);
PassContext *check_context(lua_State *L, int index);

SsaFunction *check_function(lua_State *L, int index);

void push_function(lua_State *L, SsaFunction *fn);
void push_op(lua_State *L, SsaOp *op);
void push_value(lua_State *L, SsaValue *value);
void push_context(lua_State *L, PassContext *ctx);

// ---- module openers -----------------------------------------------------
//
// Each adds its part to the `ddd` table sitting on top of the stack.

void open_ssa(lua_State *L);     // fn, op, value, ctx, and the opcode names
void open_pattern(lua_State *L); // ddd.pat
void open_pass(lua_State *L);    // ddd.register_pass / register_ui
void open_reaching(lua_State *L); // ddd.reaching
void open_session(lua_State *L); // ddd.session

// The session the bindings act on, refreshed whenever the environment's one
// changes. `ddd.session` is nil while this is null.
void bind_session(lua_State *L, Session *session);

} // namespace lua
} // namespace ddd
