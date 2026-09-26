-- data-refs -- resolve constants that point at data.
--
-- The sweep only decodes instructions, but the image it was given usually holds
-- more than that. A constant operand landing inside the image, outside the
-- range the sweep walked, is a pointer to data -- so say what is there instead
-- of leaving a bare number.
local ddd = require "ddd"

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
--
-- What comes back is the fact, not a sentence about it: what is at the end of
-- the reference, and -- for a literal pool entry -- the word on the way. How
-- that reads in a listing is the listing's business.
local function describe(ctx, address, width, loaded)
  if loaded then
    if not ctx:contains(address) then return nil end
  elseif not ctx:is_data(address) then
    return nil
  end

  if width == 0 or width > 8 then return nil end

  local text = ctx:read_string(address)
  if text then
    return { kind = "string", address = address, text = text }
  end

  if not loaded and address < ctx.code_end then return nil end

  local word = ctx:read_int(address, width)
  if not word then return { kind = "data", address = address } end

  -- One more hop, and no further: a literal pool entry is a pointer, and the
  -- thing worth reading is what it points at, not the pointer.
  local found = { address = address, word = word }
  local pointed = ctx:read_string(word)
  if pointed then
    found.kind = "string"
    found.text = pointed
  elseif word ~= 0 and ctx:is_code(word) then
    found.kind = "code"
  else
    found.kind = "data"
  end
  return found
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

            local found = describe(ctx, operand.constant, width, loaded)
            if found then
              ctx:points_at(op, found)
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
