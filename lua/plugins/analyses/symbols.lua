-- symbols -- use the names the file already carries.
--
-- A call to 0x401136 says nothing; a call to `helper` says everything. When the
-- container had a symbol table, this is the cheapest readability win available,
-- and unlike every other naming pass here it is not a guess.
local ddd = require "ddd"

ddd.workflow "readability" {
  passes = function(scope)
    scope.pass "symbols" {
      description = "name calls and blocks from the container's symbol table",

      run = function(fn, ctx)
        local named = 0

        -- fn.code_begin, not the entry block's address: a block starts at its
        -- first *p-code op*, and an instruction can lower to none at all. An
        -- x86-64 function opening with `endbr64` has its entry block starting
        -- four bytes in, which matches no symbol.
        local symbol = ctx:symbol(fn.code_begin)
        if symbol then
          ctx:comment_block(fn.entry, "function: " .. symbol)
          named = named + 1
        end

        for op in fn:ops() do
          if op.opcode == "CALL" and op.nins > 0 then
            -- A direct CALL's destination is an address in the code space,
            -- carried as the operand's offset rather than as a constant.
            local target = op:input(1)
            local called = target.offset and ctx:symbol(target.offset)
            if called then
              ctx:comment(op, "calls " .. called)
              named = named + 1
            end
          else
            -- A constant that lands on a function is a function pointer --
            -- which is how main reaches __libc_start_main, and how any
            -- callback is passed.
            for _, operand in op:inputs() do
              if operand.is_constant and not operand.is_space then
                local pointed = ctx:symbol(operand.constant)
                if pointed then
                  -- The comment keeps the `&` to say this is the function's
                  -- address; the *label* must not, because a leading `&` is
                  -- how stack-vars marks a frame-slot address and the listing
                  -- hides those definitions.
                  ctx:comment(op, "&" .. pointed)
                  if op.out then ctx:label(op.out, pointed) end
                  named = named + 1
                end
              end
            end
          end
        end

        if ctx.verbose then
          ctx:log(("  resolved %d symbol(s)"):format(named))
        end
      end,
    }
  end,
}
