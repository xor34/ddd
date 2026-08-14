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
local kLineBudget = 40000

-- How much of a stretch of undefined bytes to dump before eliding the rest.
-- Enough to recognise what it is; not so much that scrolling past a megabyte
-- of data is the only way out of it.
local kGapBytes = ddd.ui.limits.gap_bytes

-- How far from an address a line may be and still count as showing it. One
-- instruction, or one row of a hexdump; further than that and the view has to
-- be rendered again around where it is going.
local kNearEnough = 16

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

  -- The line the cursor is on, which is not the same as what is on screen:
  -- scrolling moves the view, j and k move the cursor, and the two only meet
  -- when the cursor would otherwise go out of sight.
  tag("cursorline", { background = theme.colour.selection,
                      paragraph_background = theme.colour.selection })

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

      -- A reference line is nothing but a place to go: there is no variable on
      -- it to select and nothing else it could mean, so one click follows it.
      -- Everything else takes two, because one click there means "tell me
      -- about this".
      if presses >= 2 or (line and line.target) then
        self:follow(token, line)
      end
      return false
    end)
  end
  self.view:add_controller(click)

  -- Moving the cursor, on the view rather than on the window: a text view eats
  -- the arrow keys to move its own insertion point, so these have to be taken
  -- before it sees them. Everything else bubbles up to the window's keymap.
  local keys = Gtk.EventControllerKey()
  keys.propagation_phase = Gtk.PropagationPhase.CAPTURE
  keys.on_key_pressed = function(_, keyval)
    local name = gtk.Gdk.keyval_name(keyval)

    if name == "j" or name == "Down" then
      self:move_cursor(1)
      return true
    elseif name == "k" or name == "Up" then
      self:move_cursor(-1)
      return true
    elseif name == "Return" or name == "KP_Enter" then
      local line = self.cursor_line and self.lines[self.cursor_line]
      self:follow(line and line.tokens and line.tokens[1], line)
      return true
    end

    return false
  end
  self.view:add_controller(keys)

  self.widget = gtk.scrolled(self.view, { class = "ddd-listing" })

  -- Say which stretch of the file is on screen, so the map can show it the way
  -- a scrollbar does. Taken from the scroll position against the addresses
  -- painted rather than from text geometry: line heights differ between code
  -- and a hexdump, and this is an indicator rather than a measurement.
  local adjustment = self.widget:get_vadjustment()
  if adjustment then
    adjustment.on_value_changed = function() self:publish_viewport() end
  end

  -- A render that raises must not leave the line map describing one listing
  -- while the buffer shows another: everything downstream -- what a click
  -- selects, what a comment attaches to, where the cursor is said to be --
  -- reads that map. So a failure is reported and the previous state restored.
  local function safely(addr)
    local keep = {
      lines = self.lines, by_id = self.by_id, painted = self.painted,
      line_of_addr = self.line_of_addr, span = self.span,
    }

    local ok, problem = pcall(self.show, self, addr)
    if ok then return end

    self.lines, self.by_id = keep.lines, keep.by_id
    self.painted, self.line_of_addr = keep.painted, keep.line_of_addr
    self.span = keep.span

    ui:status("listing: " .. tostring(problem))
    ui:log("listing: " .. tostring(problem))
  end

  ui:on("navigate", function(_, addr)
    ui.focus = addr
    safely(addr)
  end)

  -- Both re-render, and both come back to where the user was looking rather
  -- than to where they last navigated.
  ui:on("invalidate", function()
    self.functions = nil
    self.span = nil
    safely(ui.focus or ui.addr)
  end)
  ui:on("refresh", function()
    self.span = nil
    safely(ui.focus or ui.addr)
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
  --
  -- "On screen" has to mean a line that is actually about this address, not
  -- merely the nearest one before it. A data region is dumped around wherever
  -- you were going, so an address deep inside one has no line until it is
  -- rendered again -- and taking this shortcut on the strength of a line ten
  -- kilobytes earlier is how going somewhere lands somewhere else.
  if self.span and self.span.from == from and self.span.to == to then
    local line = self:line_for(addr)
    local landed = line and self.lines[line] and self.lines[line].addr

    if landed and addr - landed <= kNearEnough then
      self:reveal(addr)
      self:highlight(self.selected_id)
      return
    end
  end

  self:render(from, to, addr)
  self:reveal(addr)
  self:publish_viewport()

  -- The cursor goes where the view went, so the keyboard carries on from
  -- whatever was navigated to.
  self:set_cursor(self:line_for(addr), { no_scroll = true, at = addr })
end

-- What to draw, in address order: the functions in the window, and the
-- stretches between them.
--
-- The gaps are the point. Bytes that are not part of a function are not
-- nothing -- they are data, or a jump table, or something that was called a
-- function until you said it was not -- and a view that draws only functions
-- makes undefining one look like it did nothing at all.
function View:layout(from, to, focus)
  local functions = self:function_list()
  local items = {}
  local at = nil

  -- What comes before the first function in the window, when that is where we
  -- are going. Without it, going to an address below the first function of the
  -- window finds no line at all and the view stays where it was.
  local first = functions[from]
  if focus and first and focus < first.addr then
    local previous = functions[from - 1]
    local begins = previous and (previous.addr + previous.size)
      or self.ui.info.base
    if focus >= begins then
      items[#items + 1] = { kind = "gap", from = begins, to = first.addr }
      at = first.addr
    end
  end

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

function View:render(from, to, focus)
  local ui = self.ui
  local functions = self:function_list()

  -- Built into fresh tables and committed at the end.
  --
  -- The buffer is only replaced once everything has been painted, so if any of
  -- this raises -- and it is a lot of code over data produced by analysis --
  -- the view keeps the listing it had, whole, instead of a line map describing
  -- text that is not on screen. That desync is invisible and vicious: the
  -- listing looks stale while the address under the pointer, what a comment
  -- attaches to, and what a click selects all come from somewhere else.
  self.lines = {}
  self.by_id = {}
  self.line_of_addr = {}
  self.painted = {}
  self.span = { from = from, to = to }

  local paint = painter()
  local info = ui.info

  local items = self:layout(from, to, focus)
  if #items == 0 then
    self.buffer:set_text("nothing here", -1)
    return
  end

  for index, item in ipairs(items) do
    if item.kind == "gap" then
      self:paint_gap(paint, item.from, item.to, focus)
    else
      local listing = ui:listing(item.func.addr, { printer = self.printer })
      if listing and listing.ok then
        -- Anything drawn has been through the pipeline, which is what the map
        -- colours blue -- so scrolling counts as analysing it too.
        ui.analysed = ui.analysed or {}
        ui.analysed[item.func.addr] = true

        self:paint_function(paint, listing, info)
      else
        -- Still a line at that address, even though there is nothing to show:
        -- navigating here has to land somewhere, or following a reference to a
        -- stub that does not disassemble silently does nothing at all.
        self.lines[paint.line] = { addr = item.func.addr }
        self:mark_line(item.func.addr, paint.line)

        paint:put(item.func.name, "heading")
        paint:put(("  0x%x  %s"):format(item.func.addr,
                                        listing and listing.error or "?"),
                  "comment")
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
function View:paint_gap(paint, from, to, focus)
  local ui = self.ui
  local size = to - from

  -- Whatever the region tree calls it, if anything does.
  local label = "data"
  for _, region in ipairs(ui.session.region_path(from)) do
    if region.kind == "data" or region.kind == "item" then
      label = region.name ~= "" and region.name or region.kind
    end
  end

  -- The heading does not claim the region's first address: the row of bytes
  -- below it does, and going to that address should land on the bytes rather
  -- than on the title above them. (When the dump starts further in, nothing
  -- else can claim it, and the marker below takes it instead.)
  self.lines[paint.line] = { addr = from }
  paint:put(label, "heading")
  paint:put(("  0x%x-0x%x  %d byte%s"):format(from, to, size,
                                              size == 1 and "" or "s"),
            "address")
  paint:newline()

  -- All of it.
  --
  -- Marking bytes as code is done by looking at them, and anything not shown
  -- cannot be clicked -- so a region is dumped from its first byte to its last
  -- rather than windowed around wherever you happen to be. The cap below is a
  -- backstop against a pathological image, not a display decision; every data
  -- region in an ordinary binary is well inside it.
  local start = from
  local shown = math.min(to - start, kGapBytes)

  local view = ui.session.hex(start, shown)
  local bytes = view.bytes or ""

  for offset = 0, #bytes - 1, 16 do
    local row = bytes:sub(offset + 1, offset + 16)

    self:mark_line(start + offset, paint.line)
    paint:put(("  %08x  "):format(start + offset), "address")

    -- One token per byte, each carrying its own address.
    --
    -- Marking bytes as code is the reason this view exists, and a row that is
    -- one token can only offer the address it starts at -- so anything not on
    -- a sixteen-byte boundary would be unreachable. Clicking a byte has to
    -- select that byte.
    local record = { addr = start + offset, tokens = {} }
    local text = {}

    for i = 1, 16 do
      local byte = row:byte(i)
      local at = start + offset + i - 1
      local column = paint.column
      local from, to = paint:put(byte and ("%02x"):format(byte) or "  ", "const")

      if byte then
        record.tokens[#record.tokens + 1] = {
          from = from, to = to, column = column,
          width = paint.column - column,
          at = at,
          text = ("%02x"):format(byte),
        }
      end

      paint:put(i == 8 and "  " or " ")

      -- The printable column is where a string in the middle of a blob shows
      -- itself, which is usually why you are looking at raw bytes at all.
      text[#text + 1] = byte and byte >= 0x20 and byte < 0x7f
        and string.char(byte) or (byte and "." or " ")
    end

    paint:put("  " .. table.concat(text), "string")

    self.lines[paint.line] = record
    paint:newline()
  end

  -- Only if the backstop bit, which for an ordinary binary it does not.
  local after = to - (start + shown)
  if after > 0 then
    self.lines[paint.line] = {
      addr = start + shown,
      target = start + shown,
      tokens = { { column = 0, width = math.huge, addr = start + shown } },
    }
    paint:put(("  ... %d more byte%s"):format(after, after == 1 and "" or "s"),
              "comment")
    paint:newline()
  end

  paint:newline()
end

function View:paint_function(paint, listing, info)
  -- A heading, because in a linear listing the thing you most need to know is
  -- which function you have scrolled into.
  --
  -- It owns the function's start address, which is not always where its first
  -- block starts: an instruction can lower to no p-code at all, so an x86-64
  -- PLT stub's first block begins four bytes in. Without this, following a
  -- call to one finds no line for the address it was told to go to.
  self.lines[paint.line] = { addr = listing.addr, signature = true }
  self:mark_line(listing.addr, paint.line)

  -- The prototype is the heading, when there is one. It is the most useful
  -- line about a function -- what it takes and what it gives back -- and
  -- keeping it in a comment underneath made it something you had to go and
  -- look for. Double-clicking it opens the editor.
  local written = self.ui.session.signature(listing.addr)
  local signature = written and ddd.parse_signature(written)

  if signature then
    paint:put(("%s "):format(signature.result or "void"), "cast")
    paint:put(listing.name, "heading")
    paint:put("(", "punct")

    for index, parameter in ipairs(signature.parameters) do
      if index > 1 then paint:put(", ", "punct") end

      local kind = parameter.type or "void *"
      paint:put(kind, "cast")
      paint:put(kind:sub(-1) == "*" and "" or " ")
      paint:put(parameter.name or "arg", "var")
      if parameter.at then
        paint:put(" @ ", "punct")
        paint:put(parameter.at, "address")
      end
    end
    paint:put(")", "punct")
  else
    paint:put(listing.name, "heading")
    paint:put("()", "punct")
  end

  paint:put(("  0x%x-0x%x"):format(listing.addr, listing["end"]), "address")
  paint:newline()

  -- Block ids mean nothing to a reader; the label the block will be printed
  -- under does. Kept beside the address it stands for, rather than the label
  -- being parsed back out of its own text later -- a branch whose target the
  -- sweep could not resolve arrives as `goto -1`, matches no label, and
  -- reading an address out of that is an error that takes the whole render
  -- with it.
  local labels, targets = {}, {}
  for _, block in ipairs(listing.blocks) do
    labels[block.id] = ("loc_%x"):format(block.addr)
    targets[block.id] = block.addr
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
    --
    -- And only a few: a string constant can be referenced from hundreds of
    -- places, and a screenful of them where the code should be is worse than a
    -- count and an `x` away.
    local limit = ddd.ui.limits.inline_xrefs
    local shown, wanted = 0, 0

    for _, ref in ipairs(block.xrefs) do
      local interesting = block.entry or ref.kind ~= "data"
      if interesting then wanted = wanted + 1 end
      if interesting and shown >= limit then interesting = false end
      if interesting then
        shown = shown + 1
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

    if wanted > shown then
      self.lines[paint.line] = { addr = block.addr }
      paint:put(("  ; ... %d more reference(s); x to list them")
        :format(wanted - shown), "xref")
      paint:newline()
    end

    for _, comment in ipairs(block.comments) do
      -- The prototype is the heading now; saying it twice is just noise. The
      -- text listing still wants the comment, which is why the pass emits it.
      if not (block.entry and comment:sub(1, 11) == "signature: ") then
        paint:put("  ; " .. comment, "comment")
        self.lines[paint.line] = { addr = block.addr }
        paint:newline()
      end
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
          local id = tonumber(token.s)
          text = (id and labels[id]) or ("block " .. token.s)
          target = id and targets[id] or nil
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

function View:publish_viewport()
  local ui = self.ui
  local first, last = self.painted[1], self.painted[#self.painted]
  if not first or not last or last <= first then return end

  local adjustment = self.widget:get_vadjustment()
  if not adjustment or adjustment.upper <= 0 then return end

  local span = last - first
  local top = adjustment.value / adjustment.upper
  local bottom = math.min(1, (adjustment.value + adjustment.page_size)
                             / adjustment.upper)

  ui.viewport_from = math.floor(first + span * top)
  ui.viewport_to = math.floor(first + span * bottom)
  ui:emit("viewport", ui.viewport_from, ui.viewport_to)
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

  local iter = self.buffer:get_iter_at_line(line)
  if not iter then return end

  -- Through a mark, not an iterator.
  --
  -- scroll_to_iter cannot scroll to a line the view has not laid out yet, and
  -- says so by quietly doing nothing -- which is precisely the case here,
  -- because the buffer was refilled a moment ago. The result is a listing that
  -- has moved in every respect except the one you can see: clicking lands on
  -- the new function's tokens while the old pixels are still on screen.
  --
  -- A mark is remembered across validation, so the view performs the scroll
  -- when it is able to.
  if not self.focus_mark or self.focus_mark:get_deleted() then
    self.focus_mark = self.buffer:create_mark("ddd-focus", iter, false)
  else
    self.buffer:move_mark(self.focus_mark, iter)
  end

  self.view:scroll_to_mark(self.focus_mark, 0.0, true, 0.0, 0.35)
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

-- ---- the cursor ----------------------------------------------------------
--
-- A line the keyboard moves, separate from what is scrolled into view.
-- Scrolling is for reading; the cursor is what the commands act on, and moving
-- it only scrolls when it would otherwise leave the screen.

function View:set_cursor(line, options)
  options = options or {}
  if not line or not self.lines[line] then return end

  local buffer = self.buffer
  buffer:remove_tag(self.tags.cursorline, buffer:get_start_iter(),
                    buffer:get_end_iter())

  local from = buffer:get_iter_at_line(line)
  local to = buffer:get_iter_at_line(line + 1) or buffer:get_end_iter()
  if from then
    buffer:apply_tag(self.tags.cursorline, from, to or buffer:get_end_iter())
  end

  self.cursor_line = line

  -- Selecting something on the line, so that a command acting on "what is
  -- selected" has something to act on after a keyboard move. The byte that was
  -- actually asked for, when one was: going to an address in the middle of a
  -- row should select that byte, not the start of the row.
  local record = self.lines[line]
  local chosen = record.tokens and record.tokens[1] or nil

  if options.at and record.tokens then
    for _, token in ipairs(record.tokens) do
      if token.at == options.at then
        chosen = token
        break
      end
    end
  end

  self:select(chosen, record, { keep_cursor = true })

  if not options.no_scroll then self:reveal_line(line) end
end

-- Just enough scrolling to bring a line into view, rather than centring it:
-- moving down one line should move the page by one line, not jump.
function View:reveal_line(line)
  local iter = self.buffer:get_iter_at_line(line)
  if not iter then return end

  if not self.cursor_mark or self.cursor_mark:get_deleted() then
    self.cursor_mark = self.buffer:create_mark("ddd-cursor", iter, false)
  else
    self.buffer:move_mark(self.cursor_mark, iter)
  end

  self.view:scroll_to_mark(self.cursor_mark, 0.08, false, 0.0, 0.0)
end

-- The next line that is about something -- an address, a byte, a reference.
-- Blank lines and headings between functions are skipped, so holding j walks
-- the listing rather than the page.
function View:move_cursor(delta)
  local line = self.cursor_line
  if not line then
    line = self:line_for(self.ui.focus or self.ui.addr)
    if line then self:set_cursor(line) end
    return
  end

  local at = line + delta
  local limit = self.buffer:get_line_count()

  while at >= 0 and at < limit do
    if self.lines[at] then
      self:set_cursor(at)
      return
    end
    at = at + delta
  end
end

function View:select(token, line, options)
  options = options or {}
  local ui = self.ui
  -- A byte in a hexdump is its own address; a token in a line of code is part
  -- of the statement at that line's address.
  local addr = (token and token.at) or (line and line.addr) or ui.addr

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
  -- A byte has no identity to match elsewhere, so the highlight is just that
  -- byte -- which is what tells you which one you are about to mark.
  self.selected_range = (not self.selected_id and token and token.at and token.from)
    and { from = token.from, to = token.to } or nil
  self:highlight(self.selected_id)

  -- A click moves the cursor line too, so the keyboard carries on from where
  -- the pointer left off.
  if not options.keep_cursor and line then
    for number, record in pairs(self.lines) do
      if record == line then
        self:set_cursor(number, { no_scroll = true })
        break
      end
    end
  end

  if self.selected_id then
    ui:status(("%s -- %d occurrence(s); n renames it")
      :format(self.selected_id, #(self.by_id[self.selected_id] or {})))
  elseif token and token.at then
    ui:status(("0x%x  %s   c makes it code, a a string, ctrl+d data")
      :format(token.at, token.text or ""))
  elseif line and line.addr then
    ui:status(("0x%x"):format(line.addr))
  end
end

function View:highlight(id)
  local buffer = self.buffer
  buffer:remove_tag(self.tags.highlight, buffer:get_start_iter(),
                    buffer:get_end_iter())

  if not id then
    local range = self.selected_range
    if range then
      buffer:apply_tag(self.tags.highlight,
                       buffer:get_iter_at_offset(range.from),
                       buffer:get_iter_at_offset(range.to))
    end
    return
  end

  for _, place in ipairs(self.by_id[id] or {}) do
    buffer:apply_tag(self.tags.highlight, buffer:get_iter_at_offset(place.from),
                     buffer:get_iter_at_offset(place.to))
  end
end

function View:follow(token, line)
  -- The heading is the prototype; following it means editing it.
  if line and line.signature then
    self.ui:run("signature")
    return
  end

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

-- Navigating somewhere has to put the focus mark on that address's line, in
-- the buffer that is now on screen. Whether the *view* then scrolls to the
-- mark is GTK's business, but everything up to that point is this file's, and
-- when it was wrong the listing appeared to ignore clicks entirely.
function View:probe_navigation(addresses)
  local checked, exact, nowhere = 0, 0, 0
  local drift, worst, worst_at = 0, 0, nil

  for _, addr in ipairs(addresses) do
    checked = checked + 1
    self:show(addr)

    local line = self:line_for(addr)
    local landed = line and self.lines[line] and self.lines[line].addr

    if not landed then
      nowhere = nowhere + 1
    elseif landed == addr then
      exact = exact + 1
    else
      -- Landing early is the fallback working: the line that starts at or
      -- before the address is the line the address is *on*. Landing a long way
      -- early means it is not on a line at all and the fallback walked back
      -- until it found one.
      local delta = addr - landed
      drift = drift + 1
      if delta > worst then
        worst, worst_at = delta, addr
      end
    end
  end

  return ("navigation: %d exact, %d early, %d nowhere, of %d%s"):format(
    exact, drift, nowhere, checked,
    worst_at and ("  worst: 0x%x by %d bytes"):format(worst_at, worst) or "")
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

        -- Not now: rendering is a pipeline run per function on screen, and
        -- doing it while the window is being constructed is time spent before
        -- anything is visible. One idle callback later the window is up.
        gtk.GLib.idle_add(gtk.GLib.PRIORITY_DEFAULT_IDLE, function()
          view:show(ui.addr)
          return false
        end)

        return view.widget
      end,
    }
  end,
}

return M
