-- ddd.format -- turning what the session answers into something to read.
--
-- Shared by every interface, because an address should look the same in the
-- function list, the listing and the status bar. Nothing in here knows about
-- any particular toolkit; it produces strings.
local M = {}

function M.addr(value)
  if not value then return "" end
  return string.format("0x%x", value)
end

-- Padded, for columns of them. Eight digits is the width of a 32-bit address
-- and the point at which a 64-bit one stops being read as a number and starts
-- being read as a place.
function M.addr_column(value)
  if not value then return string.rep(" ", 10) end
  return string.format("0x%08x", value)
end

function M.size(bytes)
  if not bytes then return "" end
  if bytes < 1024 then return string.format("%d B", bytes) end
  if bytes < 1024 * 1024 then return string.format("%.1f KB", bytes / 1024) end
  return string.format("%.1f MB", bytes / (1024 * 1024))
end

-- ---- spacing -------------------------------------------------------------
--
-- Tokens arrive with no whitespace in them, because whitespace is a rendering
-- decision and the analysis has no business making it. Putting a space between
-- every pair is what the first attempt did and it reads like `f ( a , b )`; the
-- rules below are the ordinary typographic ones.

local tight_before = { [")"] = true, ["]"] = true, [","] = true, [";"] = true,
                       [":"] = true }
local opens = { ["("] = true, ["["] = true }

-- `zx.8(x)`, `INT_SBORROW(a, b)` and `x[i]` hug their bracket; `if (c)` and
-- `RSI = [RSP]` do not. What separates them is whether the thing on the left is
-- a value or a name applied to one, rather than an operator or a keyword.
local function applies_to_bracket(token)
  if token.k == "cast" or token.k == "var" or token.k == "const" then return true end
  return token.k == "op" and token.s:match("^[%a_][%w_.]*$") ~= nil
end

-- An operator with nothing to its left is a prefix one -- `!c`, `-x` -- and
-- what follows it belongs to it.
--
-- "op" is also the kind an opcode with no higher-level form is given, so
-- `INT_SBORROW` and `ram:0x232e0:4` arrive as operators. Those are names, and a
-- name is never a prefix operator: a real one is punctuation.
local function operator_like(token)
  return token ~= nil and token.k == "op" and token.s:match("^%p+$") ~= nil
end

local function is_prefix(token, before)
  if not operator_like(token) then return false end
  if not before then return true end
  return operator_like(before) or before.k == "keyword"
    or opens[before.s] == true or before.s == ","
end

-- Whether a space goes before `token`, given the two tokens before it.
function M.space_before(token, previous, earlier)
  if not previous then return false end
  if tight_before[token.s] then return false end
  if opens[previous.s] then return false end
  if opens[token.s] and applies_to_bracket(previous) then return false end
  if is_prefix(previous, earlier) then return false end
  return true
end

-- A line of a listing as plain text, for anything that cannot draw tokens --
-- a log, an error message, a copy to the clipboard.
function M.line(line)
  local parts = {}
  local previous, earlier

  for _, token in ipairs(line.tokens) do
    if M.space_before(token, previous, earlier) then parts[#parts + 1] = " " end
    parts[#parts + 1] = token.s
    earlier, previous = previous, token
  end

  return table.concat(parts)
end

-- The whole listing as text, comments and all.
function M.listing(listing)
  local out = {}

  for _, block in ipairs(listing.blocks or {}) do
    out[#out + 1] = string.format("%s:", M.block_label(block))

    for _, ref in ipairs(block.xrefs or {}) do
      out[#out + 1] = string.format("  ; XREF %s %s%s", ref.kind,
        M.addr(ref.from), ref["in"] ~= "" and (" in " .. ref["in"]) or "")
    end
    for _, comment in ipairs(block.comments or {}) do
      out[#out + 1] = "  ; " .. comment
    end

    for _, line in ipairs(block.lines or {}) do
      for _, comment in ipairs(line.comments or {}) do
        out[#out + 1] = "    ; " .. comment
      end
      out[#out + 1] = string.format("  %s  %s", M.addr_column(line.addr),
                                    M.line(line))
    end
  end

  return table.concat(out, "\n")
end

function M.block_label(block)
  if block.entry then
    return string.format("block %d (entry)", block.id)
  end
  return string.format("block %d", block.id)
end

-- What a data item is, in one line.
function M.data_item(item)
  if item.kind == "string" then
    return string.format('%s  "%s"', M.addr_column(item.addr), item.text)
  end

  local text = string.format("%s  %s", M.addr_column(item.addr),
                             M.addr(item.value))
  if item.points == "string" then
    text = text .. string.format('  -> "%s"', item.target or "")
  elseif item.target and item.target ~= "" then
    text = text .. "  -> " .. item.target
  elseif item.points and item.points ~= "" then
    text = text .. "  (" .. item.points .. ")"
  end
  return text
end

-- Escaping, for the toolkits that read markup.
function M.escape(text)
  return (text:gsub("[&<>]", { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;" }))
end

return M
