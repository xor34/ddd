-- calling-conv -- say what a call is being passed, and what the function itself
-- receives.
--
-- In raw p-code a CALL carries only its destination; the arguments are in
-- registers nobody named. `ddd.reaching` answers "what was in x0 here?", and the
-- calling convention says which registers to ask about.
--
-- Argument *count* is not recoverable without prototypes, so this reports the
-- argument registers the function actually wrote before the call. That is a
-- heuristic in both directions: a register set up long before for another
-- reason is reported, and one left deliberately untouched is not.
local ddd = require "ddd"

-- Whether this convention puts anything on the stack. On 32-bit x86 it puts
-- everything there, which is why a convention with no argument registers is
-- not the same thing as a convention nobody knows.
local function passes_on_stack(abi)
  return (abi.stack_slot or 0) > 0 and (abi.stack_count or 0) > 0
end

-- An argument register read before the function writes it is a parameter.
local function annotate_parameters(fn, ctx, reaching, abi)
  local named = {}

  for _, register in ipairs(abi.arguments) do
    local live_in = reaching:live_in(register)
    -- Arguments run out at the first register the function never reads: a
    -- convention passes them in order, so a gap means the end of the list.
    if not live_in or live_in.use_count == 0 then break end
    named[#named + 1] = register
  end

  -- And then the stack, which is where the rest of them are -- or, on 32-bit
  -- x86, all of them. Which slots the function actually reads is stack-vars'
  -- answer and it is in the frame comment; this says where they start.
  if passes_on_stack(abi) then
    named[#named + 1] = (#named > 0 and "then the stack from sp+0x%x"
                                    or "the stack, from sp+0x%x")
      :format(abi.stack_offset)
  end

  if #named == 0 then return end
  ctx:comment_block(fn.entry, ("parameters (%s): %s")
    :format(abi.name, table.concat(named, ", ")))
end

-- Where the return address lives on entry. On a link-register architecture it
-- is a live-in value worth naming; on a push-style one it is a stack slot,
-- which stack-vars names instead.
local function annotate_return_address(fn, ctx, reaching, abi)
  if abi.return_address_on_stack then
    ctx:comment_block(fn.entry,
                      "return address: pushed by the call, at the entry sp")
    return
  end

  if abi.return_address_register == "" then return end
  ctx:comment_block(fn.entry, "return address: " .. abi.return_address_register)

  -- The incoming value of that register *is* the return address, so say so
  -- wherever it is used -- typically the RETURN itself.
  local live_in = reaching:live_in(abi.return_address_register)
  if live_in then ctx:label(live_in, "retaddr") end
end

-- What was pushed for a call, on a convention that passes on the stack.
--
-- A `push` is a store to a frame slot, and stack-vars has already worked out
-- which slot -- so the arguments of a call are the stores standing between it
-- and whatever came before it, lowest address first, because that is the order
-- a caller pushes them in reverse. Nothing here reads the stack pointer: what
-- makes this work is that the slots are named, and a name is a fact the frame
-- analysis established rather than a guess this pass is making.
--
-- Conservative on purpose. The run is cut at the previous call, at a branch,
-- and at anything that writes a slot twice; a caller that reuses one stack
-- slot for two calls in a row reports the second, which is the one that is
-- true at the call being annotated.
-- Where in the frame an address points, or nil when it does not point into the
-- frame at all.
--
-- Either a slot -- which the frame analysis has an offset for, so nothing here
-- has to read a name -- or the frame expression the address carries when it
-- *is* the stack pointer, which is what the last push before a call looks
-- like.
--
-- A preserved register's home is a slot too, and not one of these: `push rbx`
-- saves a register for the callee, it does not pass an argument.
local function slot_offset(ctx, address)
  if not address then return nil end

  local slot = ctx:slot(address)
  if slot then
    return slot.saved_register and nil or slot.offset
  end

  return ctx:frame_pointer(address)
end

local function slot_name(offset)
  if offset < 0 then return ("var_%x"):format(-offset) end
  return ("arg_%x"):format(offset)
end

-- Through a copy to the constant behind it.
--
-- A push of a literal routes it through a Sleigh temporary, so the operand of
-- the store is `unique:0xa300` and saying that as the argument of a call is
-- saying nothing. One hop is all it takes and all that is safe.
local function constant_behind(value)
  local def = value and value.def
  if not def or def.opcode ~= "COPY" or def.nins ~= 1 then return nil end

  local operand = def.ins[1]
  return operand and operand.is_constant and operand.constant or nil
end

local function find_pushes(fn, ctx, abi)
  local by_call = {}
  local slot = abi.stack_slot

  for block in fn:blocks() do
    local pending = {}

    for _, op in ipairs(block.ops) do
      if op.opcode == "STORE" and op.nins >= 3 then
        local address = op.ins[2] and op.ins[2].value
        local offset = slot_offset(ctx, address)

        if offset then
          pending[offset] = { offset = offset, operand = op.ins[3],
                              addr = op.addr, slot = slot_name(offset) }
        end

      elseif op.opcode == "CALL" or op.opcode == "CALLIND" then
        -- The call pushes its own return address, and that push is part of
        -- the same instruction. It sits directly below the arguments, which
        -- is what says where they start.
        local base
        for offset, one in pairs(pending) do
          if one.addr == op.addr and (not base or offset < base) then
            base = offset
          end
        end

        -- Without one -- an architecture that does not push, or a call whose
        -- push was folded away -- the lowest slot written is the best guess.
        if not base then
          for offset in pairs(pending) do
            if not base or offset < base then base = offset - slot end
          end
        end

        -- Upwards from there while the slots are contiguous. A gap is the end
        -- of the argument list: what is above it was written for something
        -- else, and a local the caller happened to set before the call is not
        -- an argument however close it sits.
        local found = {}
        if base then
          local at = base + slot
          while pending[at] and #found < (abi.stack_count or 0) do
            found[#found + 1] = pending[at]
            at = at + slot
          end
        end

        if #found > 0 then by_call[op.id] = found end
        pending = {}
      end
    end
  end

  return by_call
end

ddd.workflow "readability" {
  passes = function(scope)
    scope.pass "calling-conv" {
      description = "annotate calls with their arguments, and the entry with "
                    .. "its parameters",

      -- Everything that is not per-op -- working out the ABI, building the
      -- reaching-definitions map, naming the parameters and the return
      -- address -- happens once, before the per-call loop each_op runs.
      before = function(fn, ctx)
        local abi = ctx.abi
        if not abi or (#abi.arguments == 0 and not passes_on_stack(abi)) then
          if ctx.verbose then ctx:log("  no calling convention known, skipping") end
          return
        end

        ctx.calling_conv_abi = abi
        ctx.calling_conv_reaching = ddd.reaching(fn, ctx)
        ctx.calling_conv_calls = 0
        ctx.calling_conv_pushed =
          passes_on_stack(abi) and find_pushes(fn, ctx, abi) or {}

        annotate_parameters(fn, ctx, ctx.calling_conv_reaching, abi)
        annotate_return_address(fn, ctx, ctx.calling_conv_reaching, abi)
      end,

      each_op = function(op, _, ctx)
        local abi = ctx.calling_conv_abi
        if not abi then return end
        if op.opcode ~= "CALL" and op.opcode ~= "CALLIND" then return end

        local reaching = ctx.calling_conv_reaching
        ctx.calling_conv_calls = ctx.calling_conv_calls + 1

        local arguments = {}
        for _, register in ipairs(abi.arguments) do
          local value = reaching:before(op, register)

          -- Either the function put something there for this call, or it is
          -- forwarding one of its own parameters. A register it neither wrote
          -- nor read was not set up for this call -- skip it rather than stop,
          -- so a gap does not hide the arguments after it.
          if value and not (value.is_live_in and value.use_count == 0) then
            arguments[#arguments + 1] = ("%s=%s"):format(register, ctx:name(value))
          end
        end

        -- On a stack convention the arguments were pushed rather than put in
        -- registers, and which pushes belong to which call is a question about
        -- the frame -- so stack-vars answers it, on the same line. Saying
        -- "no arguments detected" over the top of that answer would be wrong
        -- as well as unhelpful.
        -- And whatever was pushed for it, which on a stack convention is the
        -- rest of them -- or all of them.
        for _, one in ipairs(ctx.calling_conv_pushed[op.id] or {}) do
          local literal = one.operand.is_constant and one.operand.constant
            or constant_behind(one.operand.value)

          local what = literal and ("0x%x"):format(literal)
            or (one.operand.value and ctx:name(one.operand.value))
          arguments[#arguments + 1] = ("%s=%s"):format(one.slot, what or "?")
        end

        if #arguments > 0 then
          ctx:comment(op, "args: " .. table.concat(arguments, ", "))
        elseif not passes_on_stack(abi) then
          ctx:comment(op, "no arguments detected")
        end
        if abi.result ~= "" then
          ctx:comment(op, "returns in " .. abi.result)
        end
      end,

      after = function(_, ctx)
        if ctx.calling_conv_abi and ctx.verbose then
          ctx:log(("  annotated %d call(s)"):format(ctx.calling_conv_calls))
        end
      end,
    }
  end,
}
