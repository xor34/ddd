-- signatures -- the prototype someone wrote, applied to the function.
--
-- Nothing in a binary records what a function's parameters are called, what
-- types they have, or even how many there are. `calling-conv` reports the
-- argument registers that were written before a call, which is a heuristic in
-- both directions. A person who has read the code knows, and this is where they
-- say so:
--
--   int compute(int n @ RDI, char *name @ RSI)
--
-- The `@ storage` part is what makes it applicable rather than decorative: it
-- names the register the parameter arrives in, so its incoming value can be
-- given the parameter's name everywhere it is used. Leave it out and the
-- convention's own argument order is used instead.
local ddd = require "ddd"

local function trim(text) return (text:gsub("^%s*(.-)%s*$", "%1")) end

-- "char *name" -> type "char *", name "name". The name is the last identifier;
-- everything before it is the type, stars and all.
local function split_declaration(text)
  text = trim(text)
  if text == "" then return nil, nil end

  local name = text:match("([%a_][%w_]*)%s*$")
  if not name then return text, nil end

  local type_part = trim(text:sub(1, #text - #name))
  if type_part == "" then
    -- A bare word is a name if the parameter has storage, and a type
    -- otherwise; treating it as a name is the more useful guess.
    return nil, name
  end
  return type_part, name
end

-- Splits on commas that are not inside brackets, so a function-pointer
-- parameter does not come apart in the middle.
local function split_parameters(text)
  local parts, depth, current = {}, 0, {}

  for i = 1, #text do
    local c = text:sub(i, i)
    if c == "(" or c == "[" then depth = depth + 1 end
    if c == ")" or c == "]" then depth = depth - 1 end

    if c == "," and depth == 0 then
      parts[#parts + 1] = table.concat(current)
      current = {}
    else
      current[#current + 1] = c
    end
  end

  local last = table.concat(current)
  if trim(last) ~= "" then parts[#parts + 1] = last end
  return parts
end

-- Returns { name = ..., result = ..., parameters = { {type=, name=, at=} } }
-- or nil and a reason.
local function parse(text)
  text = trim(text or "")
  if text == "" then return nil, "empty" end

  local head, body = text:match("^(.-)%((.*)%)%s*$")
  if not head then return nil, "no parameter list" end

  local result, name = split_declaration(head)
  if not name then return nil, "no function name" end

  local signature = { name = name, result = result or "void", parameters = {} }

  for _, part in ipairs(split_parameters(body)) do
    local declaration, storage = part:match("^(.-)@(.*)$")
    declaration = declaration or part
    storage = storage and trim(storage) or nil

    local kind, parameter = split_declaration(declaration)
    if parameter or storage then
      signature.parameters[#signature.parameters + 1] = {
        type = kind,
        name = parameter,
        at = storage,
      }
    end
  end

  return signature
end

-- Exposed so an interface can check a prototype before recording it, and so
-- this is testable without a binary.
ddd.parse_signature = parse

-- The same thing one item per line, which is the shape it is edited in: what
-- you want to change is one argument's type, or its name, or where it arrives,
-- and finding that in a single line means counting commas.
--
--   int compute
--   int limit @ RDI
--   char *name @ RSI
function ddd.signature_lines(signature)
  if not signature then return "" end

  local lines = { ("%s %s"):format(signature.result or "void",
                                   signature.name or "f") }
  for _, parameter in ipairs(signature.parameters or {}) do
    -- `char *name` rather than `char * name`: a pointer's star belongs to the
    -- declarator, and writing it the other way looks like a typo to anyone who
    -- writes C.
    local kind = parameter.type or "void *"
    local gap = kind:sub(-1) == "*" and "" or " "
    lines[#lines + 1] = ("%s%s%s%s"):format(
      kind, gap, parameter.name or "arg",
      parameter.at and (" @ " .. parameter.at) or "")
  end
  return table.concat(lines, "\n")
end

-- And back, into the one-line form the project file keeps.
function ddd.signature_from_lines(text)
  local lines = {}
  for line in (text or ""):gmatch("[^\n]+") do
    if trim(line) ~= "" then lines[#lines + 1] = trim(line) end
  end
  if #lines == 0 then return "" end

  local head = table.remove(lines, 1)
  return ("%s(%s)"):format(head, table.concat(lines, ", "))
end

ddd.workflow "readability" {
  passes = function(scope)
    scope.pass "signatures" {
      description = "apply the prototype the user wrote for this function",

      run = function(fn, ctx)
        local text = ctx:user_signature(fn.code_begin)
        if not text or text == "" then return end

        local signature, problem = parse(text)
        if not signature then
          ctx:comment_block(fn.entry, ("signature: %s (%s)"):format(text, problem))
          return
        end

        -- The prototype as written, at the top of the function, which is what
        -- a reader wants to see whether or not every parameter could be
        -- located.
        ctx:comment_block(fn.entry, "signature: " .. text)

        local abi = ctx.abi
        local reaching = ddd.reaching(fn, ctx)
        local applied = 0

        -- The value a parameter arrives in. Not always the register the
        -- convention names: a 64-bit convention passes an int in RDI and the
        -- function reads EDI, which is a different storage entirely as far as
        -- SSA is concerned. Same space and same offset is what makes them the
        -- same parameter.
        local function locate(register)
          local exact = reaching:live_in(register)
          if exact then return exact end

          local want = ctx:register(register)
          if not want then return nil end

          for candidate in fn:values() do
            if candidate.is_live_in and candidate.space == want.space
               and candidate.offset == want.offset then
              return candidate
            end
          end
          return nil
        end

        for index, parameter in ipairs(signature.parameters) do
          -- Where it says, or where the convention would have put it.
          local storage = parameter.at
          if not storage and abi then storage = abi.arguments[index] end

          if storage and parameter.name then
            local value = locate(storage)
            if value then
              -- Both: the label is what the SSA listing shows beside the
              -- version, the display name is what the folded listing calls it.
              ctx:label(value, parameter.name)
              ctx:display_name(value, parameter.name)
              applied = applied + 1
            end
          end
        end

        if ctx.verbose then
          ctx:log(("  %d of %d parameter(s) located")
            :format(applied, #signature.parameters))
        end
      end,
    }
  end,
}
