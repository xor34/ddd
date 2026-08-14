-- idioms -- recognise common instruction-selection shapes and say what they
-- mean.
--
-- Compilers say "zero this register" by xoring it with itself and "is x
-- signed-less-than y" by comparing two flag bits. Those read as noise in
-- p-code. Each rule below is a pattern plus a sentence; matching one attaches
-- the sentence to the op.
--
-- Adding a rule means adding one entry to the table -- and, now that the table
-- is Lua, without rebuilding anything.
local ddd = require "ddd"
local pat = ddd.pat

-- Slots are how a pattern says "the same thing twice": val(1) appearing twice
-- only matches if both operands are the identical SSA value. A slot used once
-- matches anything. Descending through an operand follows COPY chains, which
-- is what makes the flag dance below expressible at all -- an AArch64 signed
-- compare reaches its flags through four copies.
local rules = {
  {
    name = "zero-self-xor",
    pattern = pat.op("INT_XOR", { pat.val(1), pat.val(1) }),
    says = "always 0 -- idiomatic register zeroing",
  },
  {
    name = "zero-self-sub",
    pattern = pat.op("INT_SUB", { pat.val(1), pat.val(1) }),
    says = "always 0",
  },
  {
    name = "zero-mult",
    pattern = pat.comm("INT_MULT", pat.val(1), pat.imm(0)),
    says = "always 0",
  },
  {
    name = "zero-and",
    pattern = pat.comm("INT_AND", pat.val(1), pat.imm(0)),
    says = "always 0",
  },
  {
    name = "identity-and",
    pattern = pat.op("INT_AND", { pat.val(1), pat.val(1) }),
    says = "no-op (x & x)",
  },
  {
    name = "identity-or",
    pattern = pat.op("INT_OR", { pat.val(1), pat.val(1) }),
    says = "no-op (x | x)",
  },
  {
    name = "identity-add",
    pattern = pat.comm("INT_ADD", pat.val(1), pat.imm(0)),
    says = "no-op (x + 0)",
  },
  {
    name = "always-equal",
    pattern = pat.op("INT_EQUAL", { pat.val(1), pat.val(1) }),
    says = "always true",
  },
  {
    name = "truncate-32",
    pattern = pat.comm("INT_AND", pat.val(1), pat.imm(0xffffffff)),
    says = "truncate to 32 bits",
  },

  -- The flag dance behind a signed compare: NG != OV, where NG is the sign of
  -- the subtraction and OV is its signed borrow.
  {
    name = "signed-less-than",
    pattern = pat.op("INT_NOTEQUAL", {
      pat.op("INT_SLESS", { pat.val(1), pat.imm(0) }),
      pat.op("INT_SBORROW", { pat.val(2), pat.val(3) }),
    }),
    says = "signed <  (NG != OV)",
  },
  {
    name = "nonzero-test",
    pattern = pat.op("BOOL_NEGATE", {
      pat.op("INT_EQUAL", { pat.val(1), pat.imm(0) }),
    }),
    says = "x != 0",
  },

  -- A shift by a constant is a multiply or divide by a power of two; worth
  -- spelling out because the constant is the interesting part.
  {
    name = "shift-left-const",
    pattern = pat.op("INT_LEFT", { pat.val(1), pat.cst(1) }),
    describe = function(match)
      return ("x * %d"):format(1 << (match.constants[1] & 63))
    end,
  },
  {
    name = "shift-right-const",
    pattern = pat.op("INT_RIGHT", { pat.val(1), pat.cst(1) }),
    describe = function(match)
      return ("x / %d (unsigned)"):format(1 << (match.constants[1] & 63))
    end,
  },
}

ddd.workflow "readability" {
  passes = function(scope)
    scope.pass "idioms" {
      description = "recognise idiomatic instruction sequences",

      before = function(_, ctx) ctx.matched = 0 end,

      each_op = function(op, _, ctx)
        for _, rule in ipairs(rules) do
          local match = rule.pattern:match(op)
          if match then
            ctx:comment(op, rule.says or rule.describe(match, op, ctx))
            ctx.matched = ctx.matched + 1
            -- First rule wins; the table is ordered most-specific first.
            return
          end
        end
      end,

      after = function(_, ctx)
        if ctx.verbose then
          ctx:log(("  %d idiom(s) recognised"):format(ctx.matched))
        end
      end,
    }
  end,
}
