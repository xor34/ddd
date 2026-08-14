// lua_pattern.cpp -- the SSA matcher, as a Lua DSL.
//
//   local pat = ddd.pat
//   local zeroing = pat.op("INT_XOR", { pat.val(1), pat.val(1) })
//   local m = zeroing:match(op)     -- m.values[1] is what got zeroed
//
// The matcher itself stays in C++ -- it walks def-use edges and skips COPY
// chains, and doing that from Lua would mean crossing the boundary once per
// operand. What belongs in Lua is the table of shapes and what each one means,
// which is the part that changes.
//
// Slots are one-based here. Writing the same slot twice is how a pattern says
// "the same value in both places"; a slot used once matches anything.
#include "../pattern.h"
#include "lua_util.h"

#include "opcodes.hh"

#include <new>

namespace ddd {
namespace lua {
namespace {

Pattern *check_pattern(lua_State *L, int index) {
  return static_cast<Pattern *>(luaL_checkudata(L, index, kPattern));
}

// A Pattern owns a vector of sub-patterns, so it lives *in* the userdata and
// is destroyed by __gc rather than being a pointer to something else.
Pattern *push_pattern(lua_State *L) {
  void *memory = lua_newuserdatauv(L, sizeof(Pattern), 0);
  Pattern *pattern = new (memory) Pattern();
  luaL_setmetatable(L, kPattern);
  return pattern;
}

int pattern_gc(lua_State *L) {
  check_pattern(L, 1)->~Pattern();
  return 0;
}

int check_slot(lua_State *L, int index) {
  const lua_Integer slot = luaL_checkinteger(L, index);
  luaL_argcheck(L, slot >= 1 && slot <= Match::kSlots, index,
                "slot out of range");
  return static_cast<int>(slot - 1);
}

// Either a name ("INT_XOR") or a number out of ddd.opcodes.
OpCode check_opcode(lua_State *L, int index) {
  if (lua_type(L, index) == LUA_TNUMBER)
    return static_cast<OpCode>(luaL_checkinteger(L, index));

  const std::string name = check_string(L, index);
  OpCode opc = ghidra::get_opcode(name);
  if (opc == static_cast<OpCode>(0))
    luaL_error(L, "no p-code opcode called '%s'", name.c_str());
  return opc;
}

int pat_val(lua_State *L) {
  Pattern *pattern = push_pattern(L);
  pattern->kind = Pattern::Kind::Value;
  pattern->slot = check_slot(L, 1);
  return 1;
}

int pat_imm(lua_State *L) {
  const uint64_t constant = check_address(L, 1);
  Pattern *pattern = push_pattern(L);
  pattern->kind = Pattern::Kind::Constant;
  pattern->constant = constant;
  return 1;
}

int pat_cst(lua_State *L) {
  Pattern *pattern = push_pattern(L);
  pattern->kind = Pattern::Kind::AnyConst;
  pattern->slot = check_slot(L, 1);
  return 1;
}

// Copies the sub-patterns out of the table at `index` into `into`.
void collect(lua_State *L, int index, Pattern &into) {
  luaL_checktype(L, index, LUA_TTABLE);
  const lua_Integer count = luaL_len(L, index);

  for (lua_Integer i = 1; i <= count; ++i) {
    lua_rawgeti(L, index, i);
    into.ins.push_back(*check_pattern(L, -1));
    lua_pop(L, 1);
  }
}

int pat_op(lua_State *L) {
  const OpCode opc = check_opcode(L, 1);

  Pattern built;
  built.kind = Pattern::Kind::Op;
  built.opc = opc;
  if (!lua_isnoneornil(L, 2))
    collect(L, 2, built);

  Pattern *pattern = push_pattern(L);
  *pattern = std::move(built);
  return 1;
}

int pat_comm(lua_State *L) {
  const OpCode opc = check_opcode(L, 1);
  Pattern left = *check_pattern(L, 2);
  Pattern right = *check_pattern(L, 3);

  Pattern *pattern = push_pattern(L);
  pattern->kind = Pattern::Kind::Op;
  pattern->opc = opc;
  pattern->commutative = true;
  pattern->ins.push_back(std::move(left));
  pattern->ins.push_back(std::move(right));
  return 1;
}

// nil when it does not match, so a rule reads `if pattern:match(op) then`.
int pattern_match(lua_State *L) {
  Pattern *pattern = check_pattern(L, 1);
  SsaOp *op = check_op(L, 2);

  Match found;
  if (!pattern->match(*op, found)) {
    lua_pushnil(L);
    return 1;
  }

  lua_createtable(L, 0, 2);

  lua_createtable(L, Match::kSlots, 0);
  for (int slot = 0; slot < Match::kSlots; ++slot) {
    if (found.values[slot] == nullptr)
      continue;
    push_value(L, found.values[slot]);
    lua_rawseti(L, -2, slot + 1);
  }
  lua_setfield(L, -2, "values");

  lua_createtable(L, Match::kSlots, 0);
  for (int slot = 0; slot < Match::kSlots; ++slot) {
    if (!found.bound[slot])
      continue;
    lua_pushinteger(L, static_cast<lua_Integer>(found.constants[slot]));
    lua_rawseti(L, -2, slot + 1);
  }
  lua_setfield(L, -2, "constants");

  return 1;
}

const luaL_Reg kPatternMethods[] = {{"match", pattern_match},
                                    {nullptr, nullptr}};

const luaL_Reg kPatternMeta[] = {{"__gc", pattern_gc}, {nullptr, nullptr}};

const luaL_Reg kBuilders[] = {{"val", pat_val},   {"imm", pat_imm},
                              {"cst", pat_cst},   {"op", pat_op},
                              {"comm", pat_comm}, {nullptr, nullptr}};

} // namespace

void open_pattern(lua_State *L) {
  new_metatable(L, kPattern, kPatternMethods, kPatternMeta);

  lua_newtable(L);
  luaL_setfuncs(L, kBuilders, 0);
  lua_setfield(L, -2, "pat");
}

} // namespace lua
} // namespace ddd
