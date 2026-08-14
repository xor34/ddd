-- rename -- give values names that come from what defines them.
--
-- SSA is what makes this safe: a value has exactly one definition, so a name
-- derived from that definition describes the value everywhere it is used, and
-- can never be invalidated by a later write to the same register.
--
-- The rules are deliberately few and each is one `if`. Run it after stack-vars,
-- whose slot names are the most useful thing to propagate.
local ddd = require "ddd"

-- A COPY produces the same variable under a new SSA name, so every use of the
-- result is really a use of the source.
--
-- This is the one rule here that needs no other pass to have invented a name
-- first -- it comes straight out of the SSA graph. Without it `rename` could
-- only relay labels that stack-vars had already set, so a function with no
-- stack slots got nothing at all out of it.
local function alias_copies(fn, ctx)
  local aliased = 0

  for op in fn:ops() do
    if op.opcode == "COPY" and op.nins == 1 and op.out then
      local source = op:input(1).value

      -- Only when the copy preserves width. A COPY between different sizes is
      -- a truncation or an extension, and calling the result the same variable
      -- would be a lie.
      --
      -- And never trade a register for a Sleigh temporary: following a copy is
      -- supposed to make the listing easier to read, and `unique:0x23700:8#0`
      -- is not an improvement on `x0#1`. The other direction -- naming a
      -- temporary after the register it came from -- is what this is for.
      if source and source.size == op.out.size
         and not (source.is_temporary and not op.out.is_temporary) then
        ctx:alias(op.out, source)
        aliased = aliased + 1
      end
    end
  end

  return aliased
end

-- A phi whose operands all agree on a name keeps it.
--
-- A load through a named stack address is deliberately *not* named: the
-- high-level listing writes the load as the slot itself, so naming its result
-- too would produce `var_1c = var_1c` and, worse, pin the result down as a
-- variable when it should fold into whatever reads it.
local function derive(op, ctx)
  if not op.is_phi or op.nins == 0 then return nil end

  local shared = nil
  for _, operand in op:inputs() do
    if not operand.value then return nil end

    local label = ctx:label(operand.value)
    if not label then return nil end
    if shared and label ~= shared then return nil end
    shared = label
  end

  return shared
end

ddd.workflow "readability" {
  passes = function(scope)
    scope.pass "rename" {
      description = "name values after their definitions",

      run = function(fn, ctx)
        local aliased = alias_copies(fn, ctx)
        local named = 0

        -- Names flow forward along def-use edges, so repeat until it settles.
        -- The chains are short; two or three rounds is typical.
        local changed = true
        while changed do
          changed = false

          for op in fn:ops() do
            if op.out and not ctx:label(op.out) then
              local label = derive(op, ctx)
              if label then
                ctx:label(op.out, label)
                named = named + 1
                changed = true
              end
            end
          end
        end

        -- The one-bit value a conditional branch tests is worth naming
        -- wherever it came from.
        for op in fn:ops() do
          if op.opcode == "CBRANCH" and op.nins >= 2 then
            local condition = op:input(2).value
            if condition and not ctx:label(condition) then
              ctx:label(condition, "cond")
              named = named + 1
            end
          end
        end

        if ctx.verbose then
          ctx:log(("  named %d value(s), followed %d copy/copies")
            :format(named, aliased))
        end
      end,
    }
  end,
}
