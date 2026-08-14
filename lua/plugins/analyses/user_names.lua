-- user-names -- the names a person chose beat the ones this tool invented.
--
-- Runs after name-vars, so it sees the generated names and can override them.
-- That ordering is also what makes the project file stable: the user renames
-- `var_1c` to `count`, and `var_1c` is what the analysis will call it again
-- next time, so the mapping still applies.
local ddd = require "ddd"

ddd.workflow "readability" {
  passes = function(scope)
    scope.pass "user-names" {
      description = "apply renames and comments from the project",

      run = function(fn, ctx)
        local func = fn.code_begin
        local applied = 0

        local renamed = ctx:user_function_name(func)
        if renamed then
          ctx:comment_block(fn.entry, "name: " .. renamed)
          applied = applied + 1
        end

        for value in fn:values() do
          local generated = ctx:display_name(value)
          if generated then
            -- A stack slot is displayed as `var_c` but held internally as the
            -- address `&var_c`, so look up what the user actually saw and
            -- typed.
            local slot = #generated > 1 and generated:sub(1, 1) == "&"
            local shown = slot and generated:sub(2) or generated

            local chosen = ctx:user_name(func, shown)
            if chosen then
              ctx:display_name(value, slot and ("&" .. chosen) or chosen)
              applied = applied + 1
            end
          end
        end

        -- A comment is attached to every op of that instruction, not just the
        -- first: an instruction lowers to several ops and the listing hides
        -- most of them, so picking one would often pick a hidden one and lose
        -- the comment. After dead-code elimination at most one of them usually
        -- survives.
        for op in fn:ops() do
          local text = ctx:user_comment(op.addr)
          if text then
            ctx:comment(op, text)
            applied = applied + 1
          end
        end

        if ctx.verbose then
          ctx:log(("  applied %d user name(s)"):format(applied))
        end
      end,
    }
  end,
}
