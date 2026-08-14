// lua_ssa.cpp -- the IR, as Lua sees it.
//
// A pass written in Lua is handed the same two things a pass written in C++
// is: the function, and the context. Ops and values are the C++ objects
// themselves rather than copies, so a pass reads a hundred-block function
// without anything being serialised, and what it records goes straight into
// the same Annotations every other pass writes to.
//
// Indices are one-based here, because that is what Lua counts from:
// `op:input(1)` is `op.ins[0]`.
#include "../abi.h"
#include "../annotations.h"
#include "../image.h"
#include "../pass.h"
#include "../project.h"
#include "../ssa.h"
#include "../target.h"
#include "lua_util.h"

#include "opcodes.hh"
#include "sleigh.hh"

#include <cctype>
#include <cstring>
#include <ostream>
#include <string>

namespace ddd {
namespace lua {
namespace {

// ---- fetching -----------------------------------------------------------

SsaFunction *to_function(lua_State *L, int index) {
  return static_cast<SsaFunction *>(check_object(L, index, kFunction));
}

// The methods table sits in an upvalue of the __index closure; anything that
// is not a property is looked up there, and then in the object's own scratch
// table -- which is where a pass keeps whatever it is counting.
int fall_back_to_methods(lua_State *L) {
  lua_pushvalue(L, 2);
  lua_gettable(L, lua_upvalueindex(1));
  if (!lua_isnil(L, -1))
    return 1;
  lua_pop(L, 1);

  if (lua_getiuservalue(L, 1, 1) == LUA_TTABLE) {
    lua_pushvalue(L, 2);
    lua_rawget(L, -2);
    return 1;
  }

  lua_pop(L, 1);
  lua_pushnil(L);
  return 1;
}

// Anything a plugin assigns goes in the scratch table rather than raising.
// A pipeline shares one context, so this is also how one pass leaves a note
// for a later one.
int scratch_newindex(lua_State *L) {
  if (lua_getiuservalue(L, 1, 1) != LUA_TTABLE) {
    lua_pop(L, 1);
    lua_newtable(L);
    lua_pushvalue(L, -1);
    lua_setiuservalue(L, 1, 1);
  }

  lua_pushvalue(L, 2);
  lua_pushvalue(L, 3);
  lua_rawset(L, -3);
  lua_pop(L, 1);
  return 0;
}

bool key_is(lua_State *L, const char *name) {
  const char *key = lua_tostring(L, 2);
  return key != nullptr && std::strcmp(key, name) == 0;
}

// Where a type's method table is kept, so a plugin can add to it.
std::string methods_key(const std::string &type) {
  return "ddd.methods." + type;
}

// Registers a type: a metatable whose __index is a closure over `methods`,
// falling back to them when `properties` does not answer.
//
// The method table is also kept in the registry under the type's short name,
// which is what makes `ddd.extend` possible: a plugin that wants every pass to
// be able to say `ctx:describe(op)` adds it there, and it is a method on the
// context from then on.
void new_class(lua_State *L, const char *name, const char *short_name,
               const luaL_Reg *methods, lua_CFunction properties,
               const luaL_Reg *extra = nullptr) {
  luaL_newmetatable(L, name);
  if (extra != nullptr)
    luaL_setfuncs(L, extra, 0);

  lua_newtable(L);
  if (methods != nullptr)
    luaL_setfuncs(L, methods, 0);

  lua_pushvalue(L, -1);
  lua_setfield(L, LUA_REGISTRYINDEX, methods_key(short_name).c_str());

  lua_pushcclosure(L, properties, 1);
  lua_setfield(L, -2, "__index");

  lua_pushstring(L, name);
  lua_setfield(L, -2, "__name");

  lua_pop(L, 1);
}

// ---- operands -----------------------------------------------------------
//
// An operand is a plain table: there are as many of them as there are ops
// times their arity, none of them outlive the loop that reads them, and
// nothing ever needs to compare two for identity.
void push_operand(lua_State *L, const SsaOp &op, size_t index) {
  const SsaOperand &in = op.ins[index];

  lua_createtable(L, 0, 6);
  set_number(L, "index", static_cast<lua_Integer>(index + 1));
  set_number(L, "size", in.raw.size);
  set_boolean(L, "is_constant", in.is_constant());
  set_boolean(L, "is_space", is_space_operand(op, index));

  if (in.is_tracked()) {
    push_value(L, in.value);
    lua_setfield(L, -2, "value");
  } else if (in.is_constant()) {
    set_number(L, "constant", static_cast<lua_Integer>(in.constant()));
  }

  // A branch or call destination is an address in the code space, carried as
  // the operand's offset rather than as a constant -- which is exactly what a
  // pass looking for "what does this call" needs.
  if (!in.is_tracked() && in.raw.space != nullptr && !in.is_constant())
    set_number(L, "offset", static_cast<lua_Integer>(in.raw.offset));
}

// ---- SsaValue -----------------------------------------------------------

int value_uses_iterator(lua_State *L) {
  SsaValue *value = check_value(L, lua_upvalueindex(1));
  const int next = static_cast<int>(lua_tointeger(L, lua_upvalueindex(2)));

  if (next >= static_cast<int>(value->uses.size()))
    return 0;

  lua_pushinteger(L, next + 1);
  lua_replace(L, lua_upvalueindex(2));
  push_op(L, value->uses[next]);
  return 1;
}

int value_uses(lua_State *L) {
  check_value(L, 1);
  lua_pushvalue(L, 1);
  lua_pushinteger(L, 0);
  lua_pushcclosure(L, value_uses_iterator, 2);
  return 1;
}

const luaL_Reg kValueMethods[] = {{"uses", value_uses}, {nullptr, nullptr}};

int value_properties(lua_State *L) {
  SsaValue *value = check_value(L, 1);

  if (key_is(L, "id"))
    lua_pushinteger(L, value->id);
  else if (key_is(L, "size"))
    lua_pushinteger(L, value->storage.size);
  else if (key_is(L, "offset"))
    lua_pushinteger(L, static_cast<lua_Integer>(value->storage.offset));
  else if (key_is(L, "space"))
    lua_pushstring(L, value->storage.space != nullptr
                          ? value->storage.space->getName().c_str()
                          : "");
  else if (key_is(L, "version"))
    lua_pushinteger(L, value->version);
  else if (key_is(L, "block"))
    lua_pushinteger(L, value->block);
  else if (key_is(L, "is_live_in"))
    lua_pushboolean(L, value->is_live_in());
  else if (key_is(L, "is_phi"))
    lua_pushboolean(L, value->is_phi());
  else if (key_is(L, "is_temporary"))
    // A Sleigh temporary: lowering plumbing rather than a variable anyone
    // wrote, which is why nothing should be renamed *to* one.
    lua_pushboolean(L, is_temporary(value->storage));
  else if (key_is(L, "use_count"))
    lua_pushinteger(L, static_cast<lua_Integer>(value->uses.size()));
  else if (key_is(L, "def"))
    push_op(L, value->def);
  else
    return fall_back_to_methods(L);

  return 1;
}

// ---- SsaOp --------------------------------------------------------------

int op_input(lua_State *L) {
  SsaOp *op = check_op(L, 1);
  const lua_Integer index = luaL_checkinteger(L, 2);
  if (index < 1 || index > static_cast<lua_Integer>(op->ins.size())) {
    lua_pushnil(L);
    return 1;
  }
  push_operand(L, *op, static_cast<size_t>(index - 1));
  return 1;
}

int op_inputs_iterator(lua_State *L) {
  SsaOp *op = check_op(L, lua_upvalueindex(1));
  const size_t next = static_cast<size_t>(lua_tointeger(L, lua_upvalueindex(2)));

  if (next >= op->ins.size())
    return 0;

  lua_pushinteger(L, static_cast<lua_Integer>(next + 1));
  lua_replace(L, lua_upvalueindex(2));

  lua_pushinteger(L, static_cast<lua_Integer>(next + 1));
  push_operand(L, *op, next);
  return 2;
}

int op_inputs(lua_State *L) {
  check_op(L, 1);
  lua_pushvalue(L, 1);
  lua_pushinteger(L, 0);
  lua_pushcclosure(L, op_inputs_iterator, 2);
  return 1;
}

const luaL_Reg kOpMethods[] = {
    {"input", op_input}, {"inputs", op_inputs}, {nullptr, nullptr}};

int op_properties(lua_State *L) {
  SsaOp *op = check_op(L, 1);

  if (key_is(L, "id"))
    lua_pushinteger(L, op->id);
  else if (key_is(L, "block"))
    lua_pushinteger(L, op->block);
  else if (key_is(L, "addr"))
    lua_pushinteger(L, static_cast<lua_Integer>(op->addr.getOffset()));
  else if (key_is(L, "opcode"))
    lua_pushstring(L, ghidra::get_opname(op->opc));
  else if (key_is(L, "is_phi"))
    lua_pushboolean(L, op->is_phi);
  else if (key_is(L, "nins"))
    lua_pushinteger(L, static_cast<lua_Integer>(op->ins.size()));
  else if (key_is(L, "out"))
    // Null for an op that produces nothing, and for one whose destination is
    // storage build_ssa chose not to rename -- memory, which `raw_out`
    // describes instead.
    push_value(L, op->out);
  else if (key_is(L, "raw_out")) {
    if (!op->has_raw_output) {
      lua_pushnil(L);
      return 1;
    }
    lua_createtable(L, 0, 3);
    set_number(L, "size", op->raw_output.size);
    set_number(L, "offset", static_cast<lua_Integer>(op->raw_output.offset));
    if (op->raw_output.space != nullptr)
      set_string(L, "space", op->raw_output.space->getName());
  } else if (key_is(L, "ins")) {
    lua_createtable(L, static_cast<int>(op->ins.size()), 0);
    for (size_t i = 0; i < op->ins.size(); ++i) {
      push_operand(L, *op, i);
      lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
  } else
    return fall_back_to_methods(L);

  return 1;
}

// ---- SsaFunction --------------------------------------------------------

int function_op(lua_State *L) {
  SsaFunction *fn = to_function(L, 1);
  const lua_Integer id = luaL_checkinteger(L, 2);
  if (id < 0 || id >= fn->op_count()) {
    lua_pushnil(L);
    return 1;
  }
  push_op(L, &fn->op(static_cast<int>(id)));
  return 1;
}

int function_value(lua_State *L) {
  SsaFunction *fn = to_function(L, 1);
  const lua_Integer id = luaL_checkinteger(L, 2);
  if (id < 0 || id >= fn->value_count()) {
    lua_pushnil(L);
    return 1;
  }
  push_value(L, &fn->value(static_cast<int>(id)));
  return 1;
}

// Every op of the function, phis first within each block, in block order --
// the same order for_each_op visits them in.
int function_ops_iterator(lua_State *L) {
  SsaFunction *fn = to_function(L, lua_upvalueindex(1));
  int block = static_cast<int>(lua_tointeger(L, lua_upvalueindex(2)));
  int index = static_cast<int>(lua_tointeger(L, lua_upvalueindex(3)));

  while (block < fn->size()) {
    const SsaBlock &current = (*fn)[block];
    const int phis = static_cast<int>(current.phis.size());
    const int total = phis + static_cast<int>(current.ops.size());

    if (index < total) {
      SsaOp *op = index < phis ? current.phis[index] : current.ops[index - phis];
      lua_pushinteger(L, block);
      lua_replace(L, lua_upvalueindex(2));
      lua_pushinteger(L, index + 1);
      lua_replace(L, lua_upvalueindex(3));
      push_op(L, op);
      return 1;
    }

    ++block;
    index = 0;
  }

  lua_pushinteger(L, block);
  lua_replace(L, lua_upvalueindex(2));
  return 0;
}

int function_ops(lua_State *L) {
  to_function(L, 1);
  lua_pushvalue(L, 1);
  lua_pushinteger(L, 0);
  lua_pushinteger(L, 0);
  lua_pushcclosure(L, function_ops_iterator, 3);
  return 1;
}

int function_values_iterator(lua_State *L) {
  SsaFunction *fn = to_function(L, lua_upvalueindex(1));
  const int next = static_cast<int>(lua_tointeger(L, lua_upvalueindex(2)));

  if (next >= fn->value_count())
    return 0;

  lua_pushinteger(L, next + 1);
  lua_replace(L, lua_upvalueindex(2));
  push_value(L, &fn->value(next));
  return 1;
}

int function_values(lua_State *L) {
  to_function(L, 1);
  lua_pushvalue(L, 1);
  lua_pushinteger(L, 0);
  lua_pushcclosure(L, function_values_iterator, 2);
  return 1;
}

// A block is a table: it is a list of ops and a couple of edge lists, and
// there is nothing in it worth an identity.
void push_block(lua_State *L, SsaFunction &fn, int id) {
  const SsaBlock &block = fn[id];
  const BasicBlock &raw = fn.cfg()[id];

  lua_createtable(L, 0, 7);
  set_number(L, "id", id);
  set_number(L, "addr", static_cast<lua_Integer>(raw.start.getOffset()));
  set_boolean(L, "entry", id == fn.cfg().entry);

  lua_createtable(L, static_cast<int>(raw.preds.size()), 0);
  for (size_t i = 0; i < raw.preds.size(); ++i) {
    lua_pushinteger(L, raw.preds[i]);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "preds");

  lua_createtable(L, static_cast<int>(raw.succs.size()), 0);
  for (size_t i = 0; i < raw.succs.size(); ++i) {
    lua_pushinteger(L, raw.succs[i].target);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "succs");

  lua_createtable(L, static_cast<int>(block.phis.size()), 0);
  for (size_t i = 0; i < block.phis.size(); ++i) {
    push_op(L, block.phis[i]);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "phis");

  lua_createtable(L, static_cast<int>(block.ops.size()), 0);
  for (size_t i = 0; i < block.ops.size(); ++i) {
    push_op(L, block.ops[i]);
    lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
  }
  lua_setfield(L, -2, "ops");
}

int function_block(lua_State *L) {
  SsaFunction *fn = to_function(L, 1);
  const lua_Integer id = luaL_checkinteger(L, 2);
  if (id < 0 || id >= fn->size()) {
    lua_pushnil(L);
    return 1;
  }
  push_block(L, *fn, static_cast<int>(id));
  return 1;
}

int function_blocks_iterator(lua_State *L) {
  SsaFunction *fn = to_function(L, lua_upvalueindex(1));
  const int next = static_cast<int>(lua_tointeger(L, lua_upvalueindex(2)));

  if (next >= fn->size())
    return 0;

  lua_pushinteger(L, next + 1);
  lua_replace(L, lua_upvalueindex(2));
  push_block(L, *fn, next);
  return 1;
}

int function_blocks(lua_State *L) {
  to_function(L, 1);
  lua_pushvalue(L, 1);
  lua_pushinteger(L, 0);
  lua_pushcclosure(L, function_blocks_iterator, 2);
  return 1;
}

// The machine instruction an op was lifted from, which is what a comment about
// that op is really about.
int function_instruction(lua_State *L) {
  SsaFunction *fn = to_function(L, 1);
  SsaOp *op = check_op(L, 2);

  const Instruction *instruction = fn->cfg().instruction_at(op->addr);
  if (instruction == nullptr) {
    lua_pushnil(L);
    return 1;
  }
  lua_pushstring(L, instruction->text.c_str());
  return 1;
}

int function_rebuild_uses(lua_State *L) {
  to_function(L, 1)->rebuild_uses();
  return 0;
}

const luaL_Reg kFunctionMethods[] = {{"op", function_op},
                                     {"value", function_value},
                                     {"block", function_block},
                                     {"ops", function_ops},
                                     {"values", function_values},
                                     {"blocks", function_blocks},
                                     {"instruction", function_instruction},
                                     {"rebuild_uses", function_rebuild_uses},
                                     {nullptr, nullptr}};

int function_properties(lua_State *L) {
  SsaFunction *fn = to_function(L, 1);

  if (key_is(L, "op_count"))
    lua_pushinteger(L, fn->op_count());
  else if (key_is(L, "value_count"))
    lua_pushinteger(L, fn->value_count());
  else if (key_is(L, "block_count"))
    lua_pushinteger(L, fn->size());
  else if (key_is(L, "entry"))
    lua_pushinteger(L, fn->cfg().entry);
  else if (key_is(L, "code_begin"))
    lua_pushinteger(L, static_cast<lua_Integer>(fn->cfg().code_begin));
  else if (key_is(L, "code_end"))
    lua_pushinteger(L, static_cast<lua_Integer>(fn->cfg().code_end));
  else
    return fall_back_to_methods(L);

  return 1;
}

// ---- PassContext --------------------------------------------------------

int context_comment(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  SsaOp *op = check_op(L, 2);
  ctx->annotations->comment(*op, check_string(L, 3));
  return 0;
}

int context_comment_block(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  ctx->annotations->comment_block(static_cast<int>(luaL_checkinteger(L, 2)),
                                  check_string(L, 3));
  return 0;
}

// Get with two arguments, set with three -- the display name for the storage
// part of a value, which the SSA listing still appends a version to.
int context_label(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  SsaValue *value = check_value(L, 2);

  if (lua_isnoneornil(L, 3)) {
    const std::string &label = ctx->annotations->label(*value);
    if (label.empty())
      lua_pushnil(L);
    else
      lua_pushlstring(L, label.data(), label.size());
    return 1;
  }

  ctx->annotations->set_label(*value, check_string(L, 3));
  return 0;
}

// Get with two arguments, set with three: the name the folded listing calls
// this value.
int context_display_name(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  SsaValue *value = check_value(L, 2);

  if (lua_isnoneornil(L, 3)) {
    const std::string &name = ctx->annotations->display_name(*value);
    if (name.empty())
      lua_pushnil(L);
    else
      lua_pushlstring(L, name.data(), name.size());
    return 1;
  }

  ctx->annotations->set_display_name(*value, check_string(L, 3));
  return 0;
}

int context_alias(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  ctx->annotations->set_alias(*check_value(L, 2), *check_value(L, 3));
  return 0;
}

int context_plumbing(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  ctx->annotations->mark_plumbing(*check_op(L, 2));
  return 0;
}

int context_is_plumbing(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  lua_pushboolean(L, ctx->annotations->is_plumbing(*check_op(L, 2)));
  return 1;
}

int context_name(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  const std::string name = ctx->name_of(*check_value(L, 2));
  lua_pushlstring(L, name.data(), name.size());
  return 1;
}

int context_declaration(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  const std::string name = ctx->declaration_of(*check_value(L, 2));
  lua_pushlstring(L, name.data(), name.size());
  return 1;
}

// How an operand prints -- which for the address space of a LOAD is a space
// name rather than the encoded pointer it is stored as.
int context_operand_name(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  SsaOp *op = check_op(L, 2);
  const lua_Integer index = luaL_checkinteger(L, 3);
  if (index < 1 || index > static_cast<lua_Integer>(op->ins.size())) {
    lua_pushnil(L);
    return 1;
  }
  const std::string name = ctx->name_of(*op, static_cast<size_t>(index - 1));
  lua_pushlstring(L, name.data(), name.size());
  return 1;
}

// Where a register lives, by name: space, offset and size. What a pass needs
// to find the value in a register a convention names -- and to notice that the
// function only ever touched a sub-register of it.
int context_register(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  if (ctx->translator() == nullptr) {
    lua_pushnil(L);
    return 1;
  }

  // As written, then upper, then lower. Ghidra spells x86 registers RAX and
  // ARM ones x0, and nobody writing a prototype should have to remember which
  // -- `void *arg @ ax` means the same thing as `@ AX`.
  std::string name = check_string(L, 2);
  Storage storage = register_storage(*ctx->translator(), name);

  if (storage.space == nullptr) {
    std::string upper = name;
    for (char &c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    storage = register_storage(*ctx->translator(), upper);
  }
  if (storage.space == nullptr) {
    std::string lower = name;
    for (char &c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    storage = register_storage(*ctx->translator(), lower);
  }

  if (storage.space == nullptr) {
    lua_pushnil(L);
    return 1;
  }

  lua_createtable(L, 0, 3);
  set_string(L, "space", storage.space->getName());
  set_number(L, "offset", static_cast<lua_Integer>(storage.offset));
  set_number(L, "size", storage.size);
  return 1;
}

int context_symbol(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  if (ctx->symbols == nullptr) {
    lua_pushnil(L);
    return 1;
  }
  auto it = ctx->symbols->find(check_address(L, 2));
  if (it == ctx->symbols->end())
    lua_pushnil(L);
  else
    lua_pushlstring(L, it->second.data(), it->second.size());
  return 1;
}

int context_read_int(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  if (ctx->image == nullptr) {
    lua_pushnil(L);
    return 1;
  }
  std::optional<uint64_t> value = ctx->image->read_int(
      check_address(L, 2), static_cast<unsigned>(luaL_checkinteger(L, 3)));
  if (!value)
    lua_pushnil(L);
  else
    lua_pushinteger(L, static_cast<lua_Integer>(*value));
  return 1;
}

int context_read_string(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  if (ctx->image == nullptr) {
    lua_pushnil(L);
    return 1;
  }
  std::optional<std::string> text = ctx->image->read_string(check_address(L, 2));
  if (!text)
    lua_pushnil(L);
  else
    lua_pushlstring(L, text->data(), text->size());
  return 1;
}

int context_is_code(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  lua_pushboolean(L, ctx->image != nullptr && ctx->image->is_code(check_address(L, 2)));
  return 1;
}

int context_is_data(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  lua_pushboolean(L, ctx->image != nullptr && ctx->image->is_data(check_address(L, 2)));
  return 1;
}

int context_contains(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  const size_t length =
      lua_isnoneornil(L, 3) ? 1 : static_cast<size_t>(luaL_checkinteger(L, 3));
  lua_pushboolean(L, ctx->image != nullptr &&
                         ctx->image->contains(check_address(L, 2), length));
  return 1;
}

// ---- what the user decided ----------------------------------------------

int context_user_name(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  if (ctx->project == nullptr) {
    lua_pushnil(L);
    return 1;
  }
  const std::string *chosen =
      ctx->project->variable_name(check_address(L, 2), check_string(L, 3));
  if (chosen == nullptr)
    lua_pushnil(L);
  else
    lua_pushlstring(L, chosen->data(), chosen->size());
  return 1;
}

int context_user_function_name(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  if (ctx->project == nullptr) {
    lua_pushnil(L);
    return 1;
  }
  const std::string *chosen = ctx->project->function_name(check_address(L, 2));
  if (chosen == nullptr)
    lua_pushnil(L);
  else
    lua_pushlstring(L, chosen->data(), chosen->size());
  return 1;
}

int context_user_comment(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  if (ctx->project == nullptr) {
    lua_pushnil(L);
    return 1;
  }
  const std::string *text = ctx->project->comment(check_address(L, 2));
  if (text == nullptr)
    lua_pushnil(L);
  else
    lua_pushlstring(L, text->data(), text->size());
  return 1;
}

// The prototype someone wrote for this function, if they wrote one. Nothing in
// a binary records parameter names or types, so this is where they come from.
int context_user_signature(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  if (ctx->project == nullptr) {
    lua_pushnil(L);
    return 1;
  }
  const std::string *text = ctx->project->signature(check_address(L, 2));
  if (text == nullptr)
    lua_pushnil(L);
  else
    lua_pushlstring(L, text->data(), text->size());
  return 1;
}

int context_user_type(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  if (ctx->project == nullptr) {
    lua_pushnil(L);
    return 1;
  }
  const std::string *type =
      ctx->project->type(check_address(L, 2), check_string(L, 3));
  if (type == nullptr)
    lua_pushnil(L);
  else
    lua_pushlstring(L, type->data(), type->size());
  return 1;
}

// What a pass says about its own work. Goes where the rest of the pipeline's
// narration goes, which in a drawn interface is a captured string and not the
// screen.
int context_log(lua_State *L) {
  PassContext *ctx = check_context(L, 1);
  const int count = lua_gettop(L);
  for (int i = 2; i <= count; ++i) {
    if (i > 2)
      ctx->stream() << " ";
    ctx->stream() << luaL_tolstring(L, i, nullptr);
    lua_pop(L, 1);
  }
  ctx->stream() << "\n";
  return 0;
}

const luaL_Reg kContextMethods[] = {
    {"comment", context_comment},
    {"comment_block", context_comment_block},
    {"label", context_label},
    {"display_name", context_display_name},
    {"alias", context_alias},
    {"plumbing", context_plumbing},
    {"is_plumbing", context_is_plumbing},
    {"name", context_name},
    {"declaration", context_declaration},
    {"operand_name", context_operand_name},
    {"symbol", context_symbol},
    {"register", context_register},
    {"read_int", context_read_int},
    {"read_string", context_read_string},
    {"is_code", context_is_code},
    {"is_data", context_is_data},
    {"contains", context_contains},
    {"user_name", context_user_name},
    {"user_function_name", context_user_function_name},
    {"user_comment", context_user_comment},
    {"user_type", context_user_type},
    {"user_signature", context_user_signature},
    {"log", context_log},
    {nullptr, nullptr}};

unsigned pointer_width(const PassContext &ctx) {
  if (ctx.target == nullptr || ctx.target->translator == nullptr)
    return 8;
  return ctx.target->translator->getDefaultCodeSpace()->getAddrSize();
}

int context_properties(lua_State *L) {
  PassContext *ctx = check_context(L, 1);

  if (key_is(L, "verbose"))
    lua_pushboolean(L, ctx->verbose);
  else if (key_is(L, "machine"))
    lua_pushboolean(L, ctx->show_machine_state);
  else if (key_is(L, "pointer_size"))
    lua_pushinteger(L, pointer_width(*ctx));
  else if (key_is(L, "image_base"))
    lua_pushinteger(L, ctx->image != nullptr
                           ? static_cast<lua_Integer>(ctx->image->base())
                           : 0);
  else if (key_is(L, "image_limit"))
    lua_pushinteger(L, ctx->image != nullptr
                           ? static_cast<lua_Integer>(ctx->image->limit())
                           : 0);
  else if (key_is(L, "code_begin"))
    lua_pushinteger(L, ctx->image != nullptr
                           ? static_cast<lua_Integer>(ctx->image->code_begin())
                           : 0);
  else if (key_is(L, "code_end"))
    lua_pushinteger(L, ctx->image != nullptr
                           ? static_cast<lua_Integer>(ctx->image->code_end())
                           : 0);
  else if (key_is(L, "big_endian"))
    lua_pushboolean(L, ctx->image != nullptr && ctx->image->big_endian());
  else if (key_is(L, "target")) {
    lua_createtable(L, 0, 4);
    if (ctx->target != nullptr) {
      set_string(L, "name", ctx->target->name);
      set_string(L, "spec", ctx->target->spec);
      if (ctx->target->abi != nullptr)
        set_string(L, "abi", ctx->target->abi->name);
    }
    set_number(L, "pointer_size", pointer_width(*ctx));
  } else if (key_is(L, "abi")) {
    // The whole convention, by register name. A pass that wants to say what a
    // call is passing needs the argument registers in order, and there is
    // nowhere else to get them: a .sla describes the instruction set, not the
    // ABI.
    const CallingConvention *abi = ctx->abi();
    if (abi == nullptr) {
      lua_pushnil(L);
      return 1;
    }

    lua_createtable(L, 0, 7);
    set_string(L, "name", abi->name);
    set_string(L, "result", abi->result);
    set_string(L, "stack_pointer", abi->stack_pointer);
    set_string(L, "return_address_register", abi->return_address_register);
    set_boolean(L, "return_address_on_stack", abi->return_address_on_stack);

    lua_createtable(L, static_cast<int>(abi->arguments.size()), 0);
    for (size_t i = 0; i < abi->arguments.size(); ++i) {
      lua_pushlstring(L, abi->arguments[i].data(), abi->arguments[i].size());
      lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    lua_setfield(L, -2, "arguments");

    lua_createtable(L, static_cast<int>(abi->preserved.size()), 0);
    for (size_t i = 0; i < abi->preserved.size(); ++i) {
      lua_pushlstring(L, abi->preserved[i].data(), abi->preserved[i].size());
      lua_rawseti(L, -2, static_cast<lua_Integer>(i + 1));
    }
    lua_setfield(L, -2, "preserved");
  } else
    return fall_back_to_methods(L);

  return 1;
}

// ddd.core.extend("context", { describe = function(ctx, op) ... end })
//
// Adding to a bound type from Lua, which is how a workflow gives its passes
// vocabulary the C++ side has never heard of.
int extend_type(lua_State *L) {
  const std::string type = check_string(L, 1);
  luaL_checktype(L, 2, LUA_TTABLE);

  if (lua_getfield(L, LUA_REGISTRYINDEX, methods_key(type).c_str()) !=
      LUA_TTABLE)
    return luaL_error(L, "nothing here called '%s' to extend", type.c_str());

  lua_pushnil(L);
  while (lua_next(L, 2) != 0) {
    lua_pushvalue(L, -2); // the key, for settable
    lua_pushvalue(L, -2); // the value
    lua_settable(L, -5);  // methods[key] = value
    lua_pop(L, 1);        // leave the key for the next lua_next
  }

  lua_pop(L, 1);
  return 0;
}

} // namespace

// ---- the accessors the other binding files use --------------------------

SsaFunction *check_function(lua_State *L, int index) {
  return static_cast<SsaFunction *>(check_object(L, index, kFunction));
}

SsaOp *check_op(lua_State *L, int index) {
  return static_cast<SsaOp *>(check_object(L, index, kOp));
}

SsaValue *check_value(lua_State *L, int index) {
  return static_cast<SsaValue *>(check_object(L, index, kValue));
}

PassContext *check_context(lua_State *L, int index) {
  return static_cast<PassContext *>(check_object(L, index, kContext));
}

void push_function(lua_State *L, SsaFunction *fn) {
  push_object(L, fn, kFunction);
}

void push_op(lua_State *L, SsaOp *op) { push_object(L, op, kOp); }

void push_value(lua_State *L, SsaValue *value) {
  push_object(L, value, kValue);
}

void push_context(lua_State *L, PassContext *ctx) {
  push_object(L, ctx, kContext);
}

void open_ssa(lua_State *L) {
  new_class(L, kFunction, "function", kFunctionMethods, function_properties);
  new_class(L, kOp, "op", kOpMethods, op_properties);
  new_class(L, kValue, "value", kValueMethods, value_properties);
  static const luaL_Reg kScratch[] = {{"__newindex", scratch_newindex},
                                      {nullptr, nullptr}};
  new_class(L, kContext, "context", kContextMethods, context_properties,
            kScratch);

  lua_pushcfunction(L, extend_type);
  lua_setfield(L, -2, "extend");

  // Every p-code opcode by name, so a plugin can write `ddd.opcodes.INT_XOR`
  // and find out at load time that it misspelled it rather than at match time.
  lua_createtable(L, 0, ghidra::CPUI_MAX);
  for (int opc = 1; opc < ghidra::CPUI_MAX; ++opc) {
    const char *name = ghidra::get_opname(static_cast<ghidra::OpCode>(opc));
    if (name == nullptr)
      continue;
    lua_pushinteger(L, opc);
    lua_setfield(L, -2, name);
  }
  lua_setfield(L, -2, "opcodes");
}

} // namespace lua
} // namespace ddd
