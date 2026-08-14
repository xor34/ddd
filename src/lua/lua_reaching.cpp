// lua_reaching.cpp -- "what was in this register here?", from Lua.
//
// SSA answers that for anything appearing as an operand, and not at all for
// storage an op never names. A CALL is the case that matters: in raw p-code it
// carries only its destination, so the argument registers are nowhere in its
// operand list. Replaying build_ssa's dominator-tree walk is what answers it,
// and that replay is an engine -- so it stays in C++ and is handed over as an
// object a pass holds for as long as it needs it.
//
//   local reaching = ddd.reaching(fn, ctx)
//   local value = reaching:before(op, "RDI")
#include "../abi.h"
#include "../pass.h"
#include "../reaching.h"
#include "../ssa.h"
#include "../target.h"
#include "lua_util.h"

#include "sleigh.hh"

#include <new>

namespace ddd {
namespace lua {
namespace {

constexpr const char *kReaching = "ddd.reaching";

// Holds the analysis and what it needs to turn a register name into storage.
struct Bound {
  ReachingValues values;
  ghidra::Sleigh *translator;
  const SsaFunction *fn;

  Bound(const SsaFunction &function, ghidra::Sleigh *sleigh)
      : values(function), translator(sleigh), fn(&function) {}
};

Bound *check_bound(lua_State *L, int index) {
  return static_cast<Bound *>(luaL_checkudata(L, index, kReaching));
}

// A register by name, or a zeroed storage the callers all treat as "no such
// register".
Storage storage_of(lua_State *L, Bound &bound, int index) {
  if (bound.translator == nullptr)
    return {};
  return register_storage(*bound.translator, check_string(L, index));
}

int reaching_gc(lua_State *L) {
  check_bound(L, 1)->~Bound();
  return 0;
}

int reaching_before(lua_State *L) {
  Bound *bound = check_bound(L, 1);
  SsaOp *op = check_op(L, 2);

  const Storage storage = storage_of(L, *bound, 3);
  if (storage.space == nullptr) {
    lua_pushnil(L);
    return 1;
  }

  push_value(L, bound->values.before(*op, storage));
  return 1;
}

int reaching_at_entry(lua_State *L) {
  Bound *bound = check_bound(L, 1);
  const int block = static_cast<int>(luaL_checkinteger(L, 2));

  const Storage storage = storage_of(L, *bound, 3);
  if (storage.space == nullptr) {
    lua_pushnil(L);
    return 1;
  }

  push_value(L, bound->values.at_entry(block, storage));
  return 1;
}

int reaching_at_exit(lua_State *L) {
  Bound *bound = check_bound(L, 1);
  const int block = static_cast<int>(luaL_checkinteger(L, 2));

  const Storage storage = storage_of(L, *bound, 3);
  if (storage.space == nullptr) {
    lua_pushnil(L);
    return 1;
  }

  push_value(L, bound->values.at_exit(block, storage));
  return 1;
}

// The value a register has on entry, if the function reads it before writing
// it -- which is what makes it a parameter rather than a scratch register.
int reaching_live_in(lua_State *L) {
  Bound *bound = check_bound(L, 1);

  const Storage storage = storage_of(L, *bound, 2);
  if (storage.space == nullptr) {
    lua_pushnil(L);
    return 1;
  }

  SsaFunction &fn = const_cast<SsaFunction &>(*bound->fn);
  for (int i = 0; i < fn.value_count(); ++i) {
    SsaValue &value = fn.value(i);
    if (value.is_live_in() && value.storage == storage) {
      push_value(L, &value);
      return 1;
    }
  }

  lua_pushnil(L);
  return 1;
}

const luaL_Reg kMethods[] = {{"before", reaching_before},
                             {"at_entry", reaching_at_entry},
                             {"at_exit", reaching_at_exit},
                             {"live_in", reaching_live_in},
                             {nullptr, nullptr}};

const luaL_Reg kMeta[] = {{"__gc", reaching_gc}, {nullptr, nullptr}};

// ddd.reaching(fn, ctx)
int make_reaching(lua_State *L) {
  SsaFunction *fn = check_function(L, 1);
  PassContext *ctx = check_context(L, 2);

  void *memory = lua_newuserdatauv(L, sizeof(Bound), 0);
  new (memory) Bound(*fn, ctx->translator());
  luaL_setmetatable(L, kReaching);
  return 1;
}

} // namespace

void open_reaching(lua_State *L) {
  new_metatable(L, kReaching, kMethods, kMeta);

  lua_pushcfunction(L, make_reaching);
  lua_setfield(L, -2, "reaching");
}

} // namespace lua
} // namespace ddd
