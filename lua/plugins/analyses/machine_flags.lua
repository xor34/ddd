-- machine-flags -- say what a write to a control flag actually is.
--
-- Sleigh models `sti` as `IF = 1` and `cli` as `IF = 0`, because that is what
-- the instruction does: there is no result, no expression, nothing but a piece
-- of machine state changing. Everything downstream is built for computations,
-- so those writes used to disappear -- dead-code elimination deleted them
-- (nothing reads the interrupt flag) and expression folding would have folded
-- the constant into the uses it does not have.
--
-- They survive now, and this is the other half: `IF = 0x1` is correct and says
-- nothing to a reader who is looking for where interrupts get turned back on.
local ddd = require "ddd"

-- register -> what writing each value to it means.
--
-- Only the flags whose whole purpose is the write. The arithmetic flags are
-- written by every instruction and mean nothing on their own, which is why
-- they are eliminated rather than explained.
local meanings = {
  IF = {
    [0] = "cli -- interrupts disabled",
    [1] = "sti -- interrupts enabled",
    any = "interrupt flag written",
  },
  DF = {
    [0] = "cld -- string operations count up",
    [1] = "std -- string operations count down",
    any = "direction flag written",
  },
  AC = { any = "alignment check flag written" },
  TF = { [1] = "single-step trap enabled", any = "trap flag written" },
  NT = { any = "nested task flag written" },
  PRIMASK = {
    [0] = "cpsie i -- interrupts enabled",
    [1] = "cpsid i -- interrupts disabled",
    any = "interrupt mask written",
  },
  FAULTMASK = { any = "fault mask written" },
  BASEPRI = { any = "interrupt priority threshold written" },
}

local function same_storage(value, storage)
  return storage and value.space == storage.space
    and value.offset == storage.offset
end

ddd.workflow "readability" {
  passes = function(scope)
    scope.pass "machine-flags" {
      description = "explain writes to interrupt and direction flags",

      before = function(_, ctx)
        ctx.machine_flags = {}
        ctx.machine_flags_found = 0

        for name, meaning in pairs(meanings) do
          local storage = ctx:register(name)
          if storage then
            ctx.machine_flags[#ctx.machine_flags + 1] =
              { name = name, storage = storage, meaning = meaning }
          end
        end
      end,

      each_op = function(op, _, ctx)
        local out = op.out
        if not out then return end

        for _, flag in ipairs(ctx.machine_flags or {}) do
          if same_storage(out, flag.storage) then
            -- What is being written, when that is knowable: a constant is the
            -- whole instruction here, and anything else is a value the
            -- listing already shows.
            local written
            for index, operand in op:inputs() do
              if index == 1 and operand.is_constant then written = operand.constant end
            end

            local says = written and flag.meaning[written] or flag.meaning.any
            if says then
              ctx:comment(op, says)
              ctx.machine_flags_found = ctx.machine_flags_found + 1
            end
            return
          end
        end
      end,

      after = function(_, ctx)
        if ctx.verbose and ctx.machine_flags_found > 0 then
          ctx:log(("  %d machine flag write(s)"):format(ctx.machine_flags_found))
        end
      end,
    }
  end,
}
