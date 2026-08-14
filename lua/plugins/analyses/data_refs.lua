-- data-refs -- resolve constants that point at data.
--
-- The sweep only decodes instructions, but the image it was given usually holds
-- more than that. A constant operand landing inside the image, outside the
-- range the sweep walked, is a pointer to data -- so say what is there instead
-- of leaving a bare number.
local ddd = require "ddd"

local escapes = { ["\n"] = "\\n", ["\t"] = "\\t", ['"'] = '\\"', ["\\"] = "\\\\" }

local function escape(text)
  return (text:gsub('[\n\t"\\]', escapes))
end

local function hex(value) return ("0x%x"):format(value) end

-- A constant is only worth resolving if it points somewhere that is data.
--
-- Reading a word always "succeeds" anywhere inside the image, so that on its
-- own is no evidence at all -- with a base of 0 every small immediate would
-- come back as a pointer. Two things separate a real reference:
--
--   * a NUL-terminated printable run is self-validating, and is reported
--     wherever it is found
--   * anything else has to point past the end of everything disassembled.
--     Small integers alias with the low addresses; the trailing data area does
--     not.
local function describe(ctx, address, width, loaded)
  if loaded then
    if not ctx:contains(address) then return nil end
  elseif not ctx:is_data(address) then
    return nil
  end

  if width == 0 or width > 8 then return nil end

  local text = ctx:read_string(address)
  if text then
    return ('%s -> "%s"'):format(hex(address), escape(text))
  end

  if not loaded and address < ctx.code_end then return nil end

  local word = ctx:read_int(address, width)
  if not word then return ("%s -> data"):format(hex(address)) end

  local described = ("%s -> %s"):format(hex(address), hex(word))

  -- One more hop, and no further: a literal pool entry is a pointer, and the
  -- thing worth reading is what it points at, not the pointer.
  local pointed = ctx:read_string(word)
  if pointed then
    return described .. (' -> "%s"'):format(escape(pointed))
  elseif word ~= 0 and ctx:is_code(word) then
    return described .. " (code)"
  end
  return described
end

-- Branch and call destinations are code; they are already shown as block edges
-- and would only add noise here.
local skip = { BRANCH = true, CBRANCH = true, CALL = true }

ddd.workflow "readability" {
  passes = function(scope)
    scope.pass "data-refs" {
      description = "resolve constants pointing into the image's data",

      before = function(_, ctx) ctx.resolved = 0 end,

      each_op = function(op, _, ctx)
        if skip[op.opcode] then return end

        for index, operand in op:inputs() do
          -- Some constant operands are not values at all: the address space of
          -- a LOAD or STORE, the userop index of a CALLOTHER.
          local structural = operand.is_space
            or (op.opcode == "CALLOTHER" and index == 1)

          if operand.is_constant and not structural then
            -- A load names its own width, and the fact that the program read
            -- the address as data is better evidence than any heuristic: an
            -- ARM literal pool sits *inside* .text, where is_data() says no.
            local loaded = op.opcode == "LOAD" and index == 2
            local width = ctx.pointer_size
            if loaded then
              if op.out then
                width = op.out.size
              elseif op.raw_out then
                width = op.raw_out.size
              end
            end

            local described = describe(ctx, operand.constant, width, loaded)
            if described then
              ctx:comment(op, described)
              ctx.resolved = ctx.resolved + 1
            end
          end
        end
      end,

      after = function(_, ctx)
        if ctx.verbose then
          ctx:log(("  %d data reference(s)"):format(ctx.resolved))
        end
      end,
    }
  end,
}
