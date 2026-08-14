-- The listing: linear, the way Binary Ninja's is.
--
-- Not one function at a time. A binary is a sequence of functions laid out in
-- address order, and reading one usually means glancing at the end of the one
-- before it; a view that shows exactly one and nothing else makes you navigate
-- to answer a question you could have answered by scrolling. So this renders a
-- run of functions around wherever you are.
--
-- Tokens arrive from the session with an identity attached rather than as a
-- string, which is what makes the two things a listing has to do possible:
-- colour each kind of thing differently, and light up every occurrence of the
-- variable under the pointer. Matching by word boundary would be wrong anyway
-- -- `RAX` appears inside `RAX_2`.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"
local format = require "ddd.format"

local Gtk = gtk.Gtk

local M = {}

-- How much to render around the anchor. Enough that scrolling runs on into the
-- next function, bounded so that landing in a binary with ten thousand of them
-- does not analyse all of them before drawing anything.
local kBefore = 1
local kAfter = 6
local kLineBudget = 2500

-- How much of a stretch of undefined bytes to dump before eliding the rest.
-- Enough to recognise what it is; not so much that scrolling past a megabyte
-- of data is the only way out of it.
local kGapBytes = 512

local View = {}
View.__index = View

-- ---- building ------------------------------------------------------------

local function make_tags(buffer, theme)
  local tags = {}

  local function tag(name, properties)
    properties.name = name
    local created = Gtk.TextTag(properties)
    buffer.tag_table:add(created)
    tags[name] = created
    return created
  end

  for kind, colour in pairs(theme.token) do
    tag(kind, { foreground = colour })
  end

  tag("default", { foreground = theme.colour.text })
  tag("heading", { foreground = theme.colour.text, weight = 700 })
  tag("highlight", { background = theme.colour.highlight })

  return tags
end

function M.build(ui, options)
  options = options or {}

  local self = setmetatable({
    ui = ui,
    printer = options.printer or "hil",
    lines = {},         -- line number -> { addr, target, tokens }
    painted = {},       -- every address that starts a line, in order
    by_id = {},         -- token id -> the places it appears
    line_of_addr = {},
    span = nil,         -- what is currently rendered: { from, to }
  }, View)

  self.buffer = Gtk.TextBuffer()
  self.tags = make_tags(self.buffer, ui.theme)

  self.view = Gtk.TextView {
    buffer = self.buffer,
    editable = false,
    cursor_visible = false,
    monospace = true,
    left_margin = 10,
    right_margin = 10,
    top_margin = 6,
    bottom_margin = 200, -- so the last line can still be scrolled to the top
    wrap_mode = Gtk.WrapMode.NONE,
  }
  self.view:add_css_class("ddd-listing")

  -- One click selects what is under it -- which is what rename, comment and
  -- cross-references then act on. Two follows it, if it names somewhere to go.
  --
  -- Where the click landed is read back off the buffer's own cursor rather than
  -- converted from coordinates: a text view already does that hit test to place
  -- the cursor, and it knows about the font, the margins and the scroll offset.
  -- The idle is what lets it happen first.
  local click = Gtk.GestureClick { button = 1 }
  click.on_pressed = function(_, presses, x, y)
    gtk.GLib.idle_add(gtk.GLib.PRIORITY_DEFAULT_IDLE, function()
      local iter = self.buffer:get_iter_at_mark(self.buffer:get_insert())
      local token, line = self:at_iter(iter)

      -- If the cursor did not move -- a build where clicking a non-editable
      -- view does not place it -- fall back to converting the coordinates.
      if not line then
        local bx, by = self.view:window_to_buffer_coords(
          Gtk.TextWindowType.WIDGET, math.floor(x), math.floor(y))
        if bx then
          token, line = self:at_iter(self.view:get_iter_at_location(bx, by))
        end
      end

      self:select(token, line)
      if presses >= 2 then self:follow(token, line) end
      return false
    end)
  end
  self.view:add_controller(click)

  self.widget = gtk.scrolled(self.view, { class = "ddd-listing" })

  ui:on("navigate", function(_, addr)
    ui.focus = addr
    self:show(addr)
  end)

  -- Both re-render, and both come back to where the user was looking rather
  -- than to where they last navigated.
  ui:on("invalidate", function()
    self.functions = nil
    self.span = nil
    self:show(ui.focus or ui.addr)
  end)
  ui:on("refresh", function()
    self.span = nil
    self:show(ui.focus or ui.addr)
  end)

  return self
end

-- ---- rendering -----------------------------------------------------------

-- Text is assembled whole and tagged afterwards. Inserting a token at a time
-- means a buffer signal and an iterator revalidation per token, and a screenful
-- of listing is thousands of them.
local Painter = {}
Painter.__index = Painter

local function painter()
  return setmetatable({ parts = {}, marks = {}, offset = 0, line = 0, column = 0 },
                      Painter)
end

function Painter:put(text, tag)
  if text == "" then return self.offset, self.offset end

  local length = utf8.len(text) or #text
  local from, to = self.offset, self.offset + length

  self.parts[#self.parts + 1] = text
  if tag then
    self.marks[#self.marks + 1] = { tag = tag, from = from, to = to }
  end

  self.offset = to
  self.column = self.column + length
  return from, to
end

function Painter:newline()
  self.parts[#self.parts + 1] = "\n"
  self.offset = self.offset + 1
  self.line = self.line + 1
  self.column = 0
end

function Painter:text() return table.concat(self.parts) end

-- An address anywhere in a token is somewhere you might want to go: a call
-- destination, a jump target, a pointer into data. Tokens do not carry one, so
-- it is read back out of the text -- which is exactly as approximate as it
-- sounds, and is why it is checked against the image before being offered.
local function address_in(text, info)
  local found = text:match("0x%x+")
  if not found then return nil end

  local addr = tonumber(found)
  if not addr or addr < info.base or addr >= info.limit then return nil end
  return addr
end

-- The functions of the image, in address order, remembered until something
-- changes them.
function View:function_list()
  if not self.functions then
    self.functions = self.ui.session.functions()
    self.index_of = {}
    for index, func in ipairs(self.functions) do
      self.index_of[func.addr] = index
    end
  end
  return self.functions
end

-- Which functions to render so that `addr` is in the middle of them.
function View:window_for(addr)
  local functions = self:function_list()
  if #functions == 0 then return 1, 0 end

  local func = self.ui.session.function_at(addr)
  local anchor = func and self.index_of[func.addr]

  if not anchor then
    -- Nowhere the function list knows about: show from the nearest one before.
    anchor = 1
    for index, one in ipairs(functions) do
      if one.addr > addr then break end
      anchor = index
    end
  end

  return math.max(1, anchor - kBefore), math.min(#functions, anchor + kAfter)
end

function View:show(addr)
  addr = addr or self.ui.addr
  if not addr then return end

  local from, to = self:window_for(addr)

  -- Already on screen: scroll rather than re-render, which is what makes
  -- following a call inside the window instant.
  if self.span and self.span.from == from and self.span.to == to
     and self:line_for(addr) then
    self:reveal(addr)
    self:highlight(self.selected_id)
    return
  end

  self:render(from, to)
  self:reveal(addr)
end

-- What to draw, in address order: the functions in the window, and the
-- stretches between them.
--
-- The gaps are the point. Bytes that are not part of a function are not
-- nothing -- they are data, or a jump table, or something that was called a
-- function until you said it was not -- and a view that draws only functions
-- makes undefining one look like it did nothing at all.
function View:layout(from, to)
  local functions = self:function_list()
  local items = {}
  local at = nil

  for index = from, to do
    local func = functions[index]

    if at and func.addr > at then
      items[#items + 1] = { kind = "gap", from = at, to = func.addr }
    end
    items[#items + 1] = { kind = "function", func = func }
    at = math.max(at or 0, func.addr + func.size)
  end

  -- Whatever follows the last function in the window, up to the next one or
  -- the end of the image.
  local following = functions[to + 1]
  local limit = following and following.addr or self.ui.info.limit
  if at and limit and limit > at then
    items[#items + 1] = { kind = "gap", from = at, to = limit }
  end

  return items
end

function View:render(from, to)
  local ui = self.ui
  local functions = self:function_list()

  self.lines = {}
  self.by_id = {}
  self.line_of_addr = {}
  self.painted = {}
  self.span = { from = from, to = to }

  local paint = painter()
  local info = ui.info

  local items = self:layout(from, to)
  if #items == 0 then
    self.buffer:set_text("nothing here", -1)
    return
  end

  for index, item in ipairs(items) do
    if item.kind == "gap" then
      self:paint_gap(paint, item.from, item.to)
    else
      local listing = ui:listing(item.func.addr, { printer = self.printer })
      if listing and listing.ok then
        self:paint_function(paint, listing, info)
      else
        paint:put(("%s  %s"):format(item.func.name,
                                    listing and listing.error or "?"), "comment")
        paint:newline()
        paint:newline()
      end
    end

    if paint.line > kLineBudget then
      paint:put(("... %d more; navigate to read them"):format(#items - index),
                "comment")
      paint:newline()
      break
    end
  end

  self.buffer:set_text(paint:text(), -1)

  -- Painted in address order almost everywhere, but a block whose address is
  -- lower than the one before it is possible, and the lookup below is a binary
  -- search.
  table.sort(self.painted)

  for _, mark in ipairs(paint.marks) do
    local tag = self.tags[mark.tag]
    if tag then
      self.buffer:apply_tag(tag, self.buffer:get_iter_at_offset(mark.from),
                            self.buffer:get_iter_at_offset(mark.to))
    end
  end

  if self.selected_id then self:highlight(self.selected_id) end
end

-- Bytes that are not code, drawn as bytes.
--
-- Sixteen to a row with the printable ones beside them, which is not
-- exploration but is the honest thing to show for a stretch nothing has
-- decided anything about yet. The Data view decodes; this one just says what
-- is there, so that undefining a function visibly turns it back into what it
-- was made of.
function View:paint_gap(paint, from, to)
  local ui = self.ui
  local size = to - from

  -- Whatever the region tree calls it, if anything does.
  local label = "data"
  for _, region in ipairs(ui.session.region_path(from)) do
    if region.kind == "data" or region.kind == "item" then
      label = region.name ~= "" and region.name or region.kind
    end
  end

  self.lines[paint.line] = { addr = from }
  paint:put(label, "heading")
  paint:put(("  0x%x-0x%x  %d byte%s"):format(from, to, size,
                                              size == 1 and "" or "s"),
            "address")
  paint:newline()

  local shown = math.min(size, kGapBytes)
  local view = ui.session.hex(from, shown)
  local bytes = view.bytes or ""

  for offset = 0, #bytes - 1, 16 do
    local row = bytes:sub(offset + 1, offset + 16)

    self.lines[paint.line] = { addr = from + offset }
    self:mark_line(from + offset, paint.line)

    paint:put(("  %08x  "):format(from + offset), "address")

    local hex, text = {}, {}
    for i = 1, 16 do
      local byte = row:byte(i)
      hex[#hex + 1] = byte and ("%02x"):format(byte) or "  "
      -- The printable column is where a string in the middle of a blob shows
      -- itself, which is usually why you are looking at raw bytes at all.
      text[#text + 1] = byte and byte >= 0x20 and byte < 0x7f
        and string.char(byte) or (byte and "." or " ")
    end

    paint:put(table.concat(hex, " ", 1, 8) .. "  "
              .. table.concat(hex, " ", 9, 16), "const")
    paint:put("   " .. table.concat(text), "string")
    paint:newline()
  end

  if size > shown then
    paint:put(("  ... %d more byte%s"):format(size - shown,
                                              size - shown == 1 and "" or "s"),
              "comment")
    paint:newline()
  end

  paint:newline()
end

function View:paint_function(paint, listing, info)
  -- A heading, because in a linear listing the thing you most need to know is
  -- which function you have scrolled into.
  paint:put(("%s"):format(listing.name), "heading")
  paint:put(("  0x%x-0x%x"):format(listing.addr, listing["end"]), "address")
  paint:newline()

  -- Block ids mean nothing to a reader; the label the block will be printed
  -- under does.
  local labels = {}
  for _, block in ipairs(listing.blocks) do
    labels[block.id] = ("loc_%x"):format(block.addr)
  end

  for _, block in ipairs(listing.blocks) do
    self.lines[paint.line] = { addr = block.addr }
    self:mark_line(block.addr, paint.line)

    if block.entry then
      paint:put(("%s:"):format(listing.name), "label")
    else
      paint:put(("%s:"):format(labels[block.id]), "label")
    end
    paint:newline()

    -- References at the label, where IDA has put them for thirty years,
    -- because that is where you are looking. Inside a function only the ones
    -- that come from outside it are news; the rest is the control flow the
    -- labels already show.
    for _, ref in ipairs(block.xrefs) do
      local interesting = block.entry or ref.kind ~= "data"
      if interesting then
        paint:put("  ; ", "xref")
        paint:put(("%s from "):format(ref.kind), "xref")
        local from, to = paint:put(("0x%x"):format(ref.from), "xref")
        if ref["in"] ~= "" then paint:put((" in %s"):format(ref["in"]), "xref") end

        self.lines[paint.line] = {
          addr = block.addr,
          target = ref.from,
          tokens = { { from = from, to = to, column = 0, width = math.huge,
                       addr = ref.from } },
        }
        paint:newline()
      end
    end

    for _, comment in ipairs(block.comments) do
      paint:put("  ; " .. comment, "comment")
      self.lines[paint.line] = { addr = block.addr }
      paint:newline()
    end

    for _, line in ipairs(block.lines) do
      -- The comment above the line it is about, so a long one does not push
      -- the code off the side of the window.
      for _, comment in ipairs(line.comments) do
        paint:put(("%s; %s"):format(string.rep(" ", 14), comment), "comment")
        self.lines[paint.line] = { addr = line.addr }
        paint:newline()
      end

      local record = { addr = line.addr, tokens = {} }
      paint:put(("  %08x  "):format(line.addr), "address")

      local previous, earlier
      for _, token in ipairs(line.tokens) do
        if format.space_before(token, previous, earlier) then paint:put(" ") end

        -- A branch target is a block number in the token stream and a label on
        -- the page; nothing but this view knows what to call it.
        local text = token.s
        local target = nil
        if token.k == "block" then
          text = labels[tonumber(token.s)] or ("block " .. token.s)
          target = tonumber(text:match("loc_(%x+)"), 16)
        end

        local column = paint.column
        local kind = self.tags[token.k] and token.k or "default"
        if token.k == "block" then kind = "label" end

        local at_from, at_to = paint:put(text, kind)

        local entry = {
          from = at_from,
          to = at_to,
          column = column,
          width = paint.column - column,
          id = token.id,
          text = text,
          addr = target or address_in(token.s, info),
        }
        record.tokens[#record.tokens + 1] = entry

        if token.id then
          local places = self.by_id[token.id]
          if not places then
            places = {}
            self.by_id[token.id] = places
          end
          places[#places + 1] = entry
        end

        earlier, previous = previous, token
      end

      self.lines[paint.line] = record
      self:mark_line(line.addr, paint.line)
      paint:newline()
    end
  end

  paint:newline()
end

-- Every address that begins a line, so that an address which merely *falls*
-- on one can be found later.
function View:mark_line(addr, line)
  if not addr or self.line_of_addr[addr] then return end

  self.line_of_addr[addr] = line
  self.painted[#self.painted + 1] = addr
end

-- Which line an address is on. Not every address has one of its own: a
-- hexdump row covers sixteen, and an instruction covers its own length. The
-- line that starts at or before the address is the one it is on.
function View:line_for(addr)
  if not addr then return nil end

  local exact = self.line_of_addr[addr]
  if exact then return exact end

  -- Painted in increasing address order, so this is already sorted.
  local addresses = self.painted
  local best, low, high = nil, 1, #addresses
  while low <= high do
    local middle = (low + high) // 2
    if addresses[middle] <= addr then
      best = addresses[middle]
      low = middle + 1
    else
      high = middle - 1
    end
  end

  return best and self.line_of_addr[best] or nil
end

-- Scrolls to where the user navigated, rather than to the top: coming back
-- from a callee should land on the call, not on a function header.
--
-- Getting this wrong is what makes an edit look like it did nothing: the view
-- re-renders, fails to find the line, stays at the top of the buffer, and the
-- change is somewhere off screen.
function View:reveal(addr)
  local line = self:line_for(addr)
  if not line then return end

  -- After the buffer has been laid out, or the scroll lands nowhere. The
  -- iterator is fetched inside the callback rather than captured: by then the
  -- buffer is the one on screen.
  gtk.GLib.idle_add(gtk.GLib.PRIORITY_DEFAULT_IDLE, function()
    local iter = self.buffer:get_iter_at_line(line)
    if iter then self.view:scroll_to_iter(iter, 0.0, true, 0.0, 0.35) end
    return false
  end)
end

-- ---- what is under the pointer -------------------------------------------

function View:at_iter(iter)
  if not iter then return nil, nil end

  local line = self.lines[iter:get_line()]
  if not line then return nil, nil end

  return self:token_at(line, iter:get_line_offset()), line
end

function View:token_at(line, column)
  for _, token in ipairs(line.tokens or {}) do
    if column >= token.column and column < token.column + token.width then
      return token
    end
  end
  return nil
end

function View:select(token, line)
  local ui = self.ui
  local addr = (line and line.addr) or ui.addr

  ui.selection = {
    id = token and token.id,
    text = token and token.text,
    addr = addr,
    target = token and token.addr,
    -- Which function the selection is *in*, which in a linear listing is not
    -- necessarily the one that was navigated to: renaming a variable three
    -- functions further down must record it against that function, or the
    -- rename is written under the wrong key and silently does nothing.
    func = addr and ui.session.function_at(addr),
  }

  -- Where the eye is, as opposed to where the last navigation went. Re-running
  -- the analysis after a rename re-renders from here, so the listing does not
  -- jump back to the function you arrived in.
  ui.focus = addr
  ui:emit("select", addr)

  self.selected_id = token and token.id or nil
  self:highlight(self.selected_id)

  if self.selected_id then
    ui:status(("%s -- %d occurrence(s); n renames it")
      :format(self.selected_id, #(self.by_id[self.selected_id] or {})))
  elseif line and line.addr then
    ui:status(("0x%x"):format(line.addr))
  end
end

function View:highlight(id)
  local buffer = self.buffer
  buffer:remove_tag(self.tags.highlight, buffer:get_start_iter(),
                    buffer:get_end_iter())
  if not id then return end

  for _, place in ipairs(self.by_id[id] or {}) do
    buffer:apply_tag(self.tags.highlight, buffer:get_iter_at_offset(place.from),
                     buffer:get_iter_at_offset(place.to))
  end
end

function View:follow(token, line)
  local target = (token and token.addr) or (line and line.target)
  if target then self.ui:navigate(target) end
end

-- Every place the selected variable appears, as references -- which is what
-- "what refers to this" means when the thing selected is a value rather than an
-- address.
function View:occurrences(id)
  local found = {}
  for line_number, line in pairs(self.lines) do
    for _, token in ipairs(line.tokens or {}) do
      if token.id == id then
        found[#found + 1] = { from = line.addr, kind = "use", ["in"] = id,
                              line = line_number }
        break
      end
    end
  end

  table.sort(found, function(a, b) return a.line < b.line end)
  return found
end

-- Clicking maps a place in the buffer to a token, and getting it wrong is
-- silent -- the click simply does nothing. The mapping is line and column
-- bookkeeping kept while painting, so it can be checked without a screen: take
-- a token, build an iterator where it was painted, and ask what is there.
function View:probe(wanted)
  local checked, matched = 0, 0
  local first_failure

  for line_number, line in pairs(self.lines) do
    for _, token in ipairs(line.tokens or {}) do
      if token.id and token.width ~= math.huge and checked < (wanted or 20) then
        checked = checked + 1

        local iter = self.buffer:get_iter_at_line_offset(line_number,
                                                         token.column)
        local found = self:at_iter(iter)

        if found and found.text == token.text then
          matched = matched + 1
        elseif not first_failure then
          first_failure = ("%s at line %d col %d -> %s"):format(
            token.text, line_number, token.column,
            found and found.text or "nothing")
        end
      end
    end
  end

  return ("hit test: %d/%d%s"):format(
    matched, checked,
    first_failure and ("  first miss: " .. first_failure) or "")
end

-- ---- registration --------------------------------------------------------

ddd.workflow "studio" {
  ui = function(scope)
    scope.view "listing" {
      title = "Listing",
      place = "main",
      order = 10,
      build = function(ui)
        local view = M.build(ui, { printer = "hil" })
        ui.listing_view = view
        view:show(ui.addr)
        return view.widget
      end,
    }
  end,
}

return M
