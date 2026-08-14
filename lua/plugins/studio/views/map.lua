-- The map: the whole file, one strip, at a glance.
--
-- Two questions it answers before you have read anything. What is in here --
-- entropy separates instructions from padding from compressed blobs, and the
-- shape of a file is usually obvious from twenty pixels of it. And how much of
-- it is understood -- blue where the analysis has been, grey where it has not,
-- which is also a progress bar for the work happening in the background.
--
-- Analysis runs on startup rather than when you scroll to something: the strip
-- fills in as it goes, and by the time you have looked at the first function
-- the references and the rest of the listing are there. Grey is not "nothing
-- here" but "not read yet", and the listing shows exactly that -- the bytes --
-- for anything the strip has not coloured in.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local Gtk, GLib = gtk.Gtk, gtk.GLib

-- Dragging the map is a stream of motion events, and each one that reached
-- `navigate` re-ran the pipeline over a window of functions. Coalescing them
-- to one navigation every so often is the difference between a scrollbar and a
-- slideshow; the last position always lands, on release.
local kDragInterval = 90

-- The strip is redrawn as the analysis reports progress, which it does every
-- few milliseconds. Recounting every function and repainting eight hundred
-- rows at that rate costs more than the analysis it is reporting.
local kRedrawInterval = 200

local M = {}

-- Enough that a small function is still a visible mark on a big binary, and
-- few enough that redrawing is a loop over a screenful.
local kBuckets = 1024

local Map = {}
Map.__index = Map

local function rgb(hex)
  local r, g, b = hex:match("^#(%x%x)(%x%x)(%x%x)$")
  if not r then return 0.5, 0.5, 0.5 end
  return tonumber(r, 16) / 255, tonumber(g, 16) / 255, tonumber(b, 16) / 255
end

function M.build(ui)
  local self = setmetatable({
    ui = ui,
    entropy = {},
    known = {},    -- bucket -> true, a function is here
    analysed = {}, -- bucket -> true, and it has been through the pipeline
  }, Map)

  self.base = ui.info.base
  self.span = math.max(1, ui.info.limit - ui.info.base)

  self.area = Gtk.DrawingArea {
    width_request = 20,
    vexpand = true,
    tooltip_text = "the whole file: entropy, and blue where it has been read",
  }
  self.area:set_draw_func(function(_, cr, width, height)
    self:draw(cr, width, height)
  end)

  -- It is a scrollbar for the file, so it behaves like one: press to go there,
  -- drag to sweep through it. That is how you get from "there is something odd
  -- two thirds of the way down" to looking at it.
  --
  -- Going somewhere no longer means analysing what is there -- the listing
  -- draws the bytes and the analysis catches up -- but it still means painting
  -- a screenful, which is thousands of rows when the screenful is a hexdump.
  -- Positions are coalesced: one navigation per interval, and whatever the
  -- last position was when the finger came up.
  local function address_at(y)
    local height = self.area:get_height()
    if height <= 0 then return nil end
    return math.floor(self.base
                      + self.span * math.max(0, math.min(1, y / height)))
  end

  local pending

  local function go_now(y)
    local at = y and address_at(y) or pending
    pending = nil
    if at then ui:navigate(at) end
  end

  local function go_soon(y)
    local at = address_at(y)
    if not at or at == ui.addr then return end

    pending = at
    if self.navigating then return end

    self.navigating = true
    GLib.timeout_add(GLib.PRIORITY_DEFAULT, kDragInterval, function()
      self.navigating = false
      go_now(nil)
      return false
    end)
  end

  local click = Gtk.GestureClick { button = 1 }
  click.on_pressed = function(_, _, _, y) go_now(y) end
  self.area:add_controller(click)

  local drag = Gtk.GestureDrag { button = 1 }
  drag.on_drag_update = function(gesture, _, offset_y)
    local _, start_y = gesture:get_start_point()
    if not start_y then return end
    go_soon(start_y + offset_y)
  end
  drag.on_drag_end = function(gesture, _, offset_y)
    local _, start_y = gesture:get_start_point()
    if start_y then go_now(start_y + offset_y) end
  end
  self.area:add_controller(drag)

  self.widget = self.area

  -- Entropy is a pass over the file and does not change, so it is computed
  -- once and kept.
  self.entropy = ui.session.entropy(kBuckets)

  self:recount()

  -- Moving does not change the strip, only the two marks drawn over it, so
  -- these redraw without rebuilding anything.
  ui:on("navigate", function() self.area:queue_draw() end)
  ui:on("viewport", function() self.area:queue_draw() end)

  ui:on("invalidate", function() self:refresh() end)

  -- The analysis runs in the background with the window already up, and this
  -- is what watching it looks like: the strip colours in as it goes -- but at
  -- a rate a person can see rather than at the rate the analysis reports.
  ui:on("analysis", function() self:refresh(kRedrawInterval) end)

  ui.map_view = self
  return self
end

-- Analyses everything now rather than over the next few seconds, and draws the
-- strip to a file. What the test suite looks at, since the drawing is the
-- whole of this view and none of it needs a screen.
function Map:render_to(path, width, height)
  local cairo = gtk.lgi.cairo
  local surface = cairo.ImageSurface.create(cairo.Format.ARGB32, width, height)
  local cr = cairo.Context.create(surface)
  self:draw(cr, width, height)
  surface:write_to_png(path)
end

function Map:snapshot(path, width, height)
  local ui = self.ui

  for _, func in ipairs(ui.session.functions()) do
    local ok, listing = pcall(ui.listing, ui, func.addr)
    if ok and listing and listing.ok then ui.analysed[func.addr] = true end
  end
  self:recount()
  self.stale = true
  self:render_to(path, width, height)

  -- How long a redraw costs, since the strip is redrawn on every keystroke
  -- that moves the cursor and on every report from the analysis.
  local cairo = gtk.lgi.cairo
  local surface = cairo.ImageSurface.create(cairo.Format.ARGB32, width, height)
  local cr = cairo.Context.create(surface)

  local began = os.clock()
  for _ = 1, 100 do self:draw(cr, width, height) end
  local moving = (os.clock() - began) * 1000 / 100

  began = os.clock()
  for _ = 1, 100 do
    self.stale = true
    self:draw(cr, width, height)
  end
  local rebuilding = (os.clock() - began) * 1000 / 100

  io.write(("map draw: %.2fms moving, %.2fms rebuilding\n"):format(moving,
                                                                  rebuilding))

  -- What is actually on it, for a test that cannot look.
  local blue, grey = 0, 0
  for _, bucket in pairs(self.known) do if bucket then grey = grey + 1 end end
  for _, bucket in pairs(self.analysed) do if bucket then blue = blue + 1 end end
  return blue, grey
end

-- Rebuild what the strip is made of, and redraw it.
--
-- With an interval, at most once per that many milliseconds: the analysis
-- reports progress every few, and recounting every function in the binary and
-- repainting the strip at that rate costs more than the work being reported.
function Map:refresh(interval)
  if not interval then
    self:recount()
    self.stale = true
    self.area:queue_draw()
    return
  end

  if self.pending_redraw then return end
  self.pending_redraw = true

  GLib.timeout_add(GLib.PRIORITY_DEFAULT_IDLE, interval, function()
    self.pending_redraw = false
    self:recount()
    self.stale = true
    self.area:queue_draw()
    return false
  end)
end

-- Which buckets hold a function, and which of those have been analysed.
function Map:recount()
  local ui = self.ui
  self.known = {}
  self.analysed = {}

  for _, func in ipairs(ui.session.functions()) do
    local first = self:bucket(func.addr)
    local last = self:bucket(func.addr + math.max(1, func.size) - 1)

    for bucket = first, last do
      self.known[bucket] = true
      if ui.analysed[func.addr] then self.analysed[bucket] = true end
    end
  end
end

function Map:bucket(addr)
  local at = math.floor((addr - self.base) * kBuckets / self.span)
  return math.max(0, math.min(kBuckets - 1, at))
end

-- ---- drawing -------------------------------------------------------------

-- The strip itself, which only changes when the analysis does.
--
-- Kept as an image and blitted, because the two things drawn over it -- where
-- the listing is and where the cursor is -- change on every keystroke, and
-- repainting several hundred rows to move a two-pixel line is most of what
-- made this expensive.
function Map:strip(width, height)
  if self.surface and not self.stale
     and self.surface_width == width and self.surface_height == height then
    return self.surface
  end

  local cairo = gtk.lgi.cairo
  local surface = cairo.ImageSurface.create(cairo.Format.ARGB32, width, height)
  self:paint(cairo.Context.create(surface), width, height)

  self.surface = surface
  self.surface_width, self.surface_height = width, height
  self.stale = false
  return surface
end

function Map:draw(cr, width, height)
  if width <= 0 or height <= 0 then return end

  cr:set_source_surface(self:strip(width, height), 0, 0)
  cr:paint()
  self:overlay(cr, width, height)
end

function Map:paint(cr, width, height)
  local theme = self.ui.theme
  local br, bg, bb = rgb(theme.colour.background)
  local ar, ag, ab = rgb(theme.colour.accent)

  cr:set_source_rgb(br, bg, bb)
  cr:rectangle(0, 0, width, height)
  cr:fill()

  -- Adjacent rows that come out the same colour are one rectangle. A binary is
  -- mostly long stretches of the same thing, so this is usually a few dozen
  -- fills rather than one per pixel row.
  local run_from, run_r, run_g, run_b = nil, nil, nil, nil

  local function flush(to)
    if not run_from then return end
    cr:set_source_rgb(run_r, run_g, run_b)
    cr:rectangle(0, run_from, width, to - run_from)
    cr:fill()
    run_from = nil
  end

  for y = 0, height - 1 do
    local first = math.floor(y * kBuckets / height)
    local last = math.max(first, math.floor((y + 1) * kBuckets / height) - 1)

    -- One row usually covers several buckets; the busiest reading wins, so a
    -- small function does not disappear into a screenful of padding.
    local bits, known, analysed = 0, false, false
    for bucket = first, last do
      bits = math.max(bits, self.entropy[bucket + 1] or 0)
      known = known or self.known[bucket] or false
      analysed = analysed or self.analysed[bucket] or false
    end

    -- Entropy sets the brightness: padding is nearly black, code is mid, a
    -- compressed blob is bright.
    local level = math.min(1, bits / 8)
    local r, g, b

    if analysed then
      -- Blue, brightened by entropy rather than replaced by it, so the two
      -- readings are both legible in one strip.
      r, g, b = ar * (0.45 + 0.55 * level), ag * (0.45 + 0.55 * level),
                ab * (0.45 + 0.55 * level)
    else
      -- Not analysed is grey, whatever else is known about it: the one thing
      -- the colour has to say is whether the tool has read this or not. A
      -- function that has been found but not yet been through the pipeline is
      -- a slightly lighter grey, and it will be blue in a moment anyway.
      local grey = 0.12 + 0.55 * level
      if known then grey = math.min(1, grey * 1.2 + 0.04) end
      r, g, b = grey, grey, grey
    end

    if run_from and r == run_r and g == run_g and b == run_b then
      -- carry on with the run
    else
      flush(y)
      run_from, run_r, run_g, run_b = y, r, g, b
    end
  end
  flush(height)
end

-- The two marks that move: where the listing is, and where the cursor is.
function Map:overlay(cr, width, height)
  -- What is on screen in the listing, the way a scrollbar shows it.
  local from, to = self.ui.viewport_from, self.ui.viewport_to
  if from and to and to > from then
    local top = math.floor((from - self.base) * height / self.span)
    local bottom = math.ceil((to - self.base) * height / self.span)

    cr:set_source_rgba(1, 1, 1, 0.16)
    cr:rectangle(0, math.max(0, top), width,
                 math.max(3, math.min(height, bottom) - top))
    cr:fill()
  end

  -- And where the cursor is, which is not the same thing once you have
  -- scrolled away from it.
  local addr = self.ui.focus or self.ui.addr
  if addr then
    local y = math.floor((addr - self.base) * height / self.span)
    cr:set_source_rgb(1, 1, 1)
    cr:rectangle(0, math.max(0, math.min(height - 2, y)), width, 2)
    cr:fill()
  end
end

ddd.workflow "studio" {
  ui = function(scope)
    scope.view "map" {
      title = "Map",
      place = "right",
      bare = true, -- a strip down the edge, not a panel with a heading
      order = 10,
      build = function(ui) return M.build(ui).widget end,
    }
  end,
}

return M
