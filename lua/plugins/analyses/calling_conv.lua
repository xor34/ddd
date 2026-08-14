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

local function annotate_calls(fn, ctx, reaching, abi)
  local calls = 0

  for op in fn:ops() do
    if op.opcode == "CALL" or op.opcode == "CALLIND" then
      calls = calls + 1

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

      ctx:comment(op, #arguments == 0 and "no arguments detected"
                      or ("args: " .. table.concat(arguments, ", ")))
      if abi.result ~= "" then
        ctx:comment(op, "returns in " .. abi.result)
      end
    end
  end

  return calls
end

ddd.workflow "readability" {
  passes = function(scope)
    scope.pass "calling-conv" {
      description = "annotate calls with their arguments, and the entry with "
                    .. "its parameters",

      run = function(fn, ctx)
        local abi = ctx.abi
        if not abi or #abi.arguments == 0 then
          if ctx.verbose then ctx:log("  no calling convention known, skipping") end
          return
        end

        local reaching = ddd.reaching(fn, ctx)

        annotate_parameters(fn, ctx, reaching, abi)
        annotate_return_address(fn, ctx, reaching, abi)
        local calls = annotate_calls(fn, ctx, reaching, abi)

        if ctx.verbose then
          ctx:log(("  annotated %d call(s)"):format(calls))
        end
      end,
    }
  end,
}
