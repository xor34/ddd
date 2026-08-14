-- Analysing while the window is already up.
--
-- None of this is fast on a real binary: indexing every reference is a sweep of
-- the image, working out where the functions are is another, and each function
-- then has to go through the pipeline. Doing it before the window appears means
-- staring at nothing for however long that takes; doing it lazily means the map
-- is empty and the function list is short until you happen to scroll past
-- something.
--
-- So it runs on the idle handler, in slices, and says so as it goes.
--
-- Not on a thread. It looks like the obvious answer and it is not: a Sleigh
-- translator holds decode state and is shared per instruction set, and the
-- passes are Lua, which is one interpreter -- so two threads doing this would
-- spend their time waiting for each other, and the locking would be real. What
-- the UI actually needs is not to be blocked, and yielding gives that without
-- any of it.
--
-- Each tick works to a deadline rather than to a count of items. A count is
-- wrong at both ends: four small functions is a wasted frame, and four large
-- ones is a visible stall. A deadline is the thing that was actually wanted.
local gtk = require "plugins.studio.gtk"

local GLib = gtk.GLib

local M = {}

-- Milliseconds of work per tick. Long enough to make progress, short enough
-- that a keystroke lands in the same frame it was pressed.
local kBudget = 12

local function now() return GLib.get_monotonic_time() / 1000 end

local function later(work)
  GLib.idle_add(GLib.PRIORITY_LOW, function() return work() end)
end

function M.start(ui)
  ui.analysed = ui.analysed or {}
  ui.progress = { stage = "starting", done = 0, total = 0 }

  local function announce(stage, done, total, message)
    ui.progress = { stage = stage, done = done, total = total }
    ui:emit("analysis", ui.progress)
    if message then ui:status(message) end
  end

  -- Phase one: references, then function boundaries. Both are sweeps of the
  -- image, and both hand back control between slices.
  local function index()
    local deadline = now() + kBudget
    local step

    -- The instruction budget bounds one slice; the deadline bounds the tick.
    -- Both, because a slice that overruns is a dropped frame and a tick that
    -- stops after one slice wastes the rest of it.
    repeat
      step = ui.session.analyse_step(5)
    until step.finished or now() >= deadline

    announce(step.stage, step.done, step.total)

    if not step.finished then return true end

    -- Everything on screen was drawn without any of this: the listing had no
    -- cross-references in it and the address it is showing may be inside a
    -- function now.
    ui:invalidate()
    announce("functions", step.done, step.total,
             ("%d function(s)"):format(step.done))

    M.analyse(ui, announce)
    return false
  end

  later(index)
end

-- Phase two: each function through the pipeline. The one being looked at goes
-- first, so what is on screen stops being provisional immediately.
function M.analyse(ui, announce)
  local functions = ui.session.functions()
  local order = {}

  local here = ui.focus or ui.addr
  local first = here and ui.session.function_at(here)
  if first then order[#order + 1] = first.addr end
  for _, func in ipairs(functions) do
    if not first or func.addr ~= first.addr then order[#order + 1] = func.addr end
  end

  local index, done = 1, 0
  announce("analysing", 0, #order)

  later(function()
    local deadline = now() + kBudget

    repeat
      local addr = order[index]
      if not addr then break end
      index = index + 1

      -- Asking for the listing is what runs the pipeline; the context keeps
      -- it, so looking at this function later is then instant.
      local ok, listing = pcall(ui.listing, ui, addr)
      if ok and listing and listing.ok then
        ui.analysed[addr] = true
        done = done + 1
      end
    until now() >= deadline

    if index > #order then
      announce("done", done, #order, ("analysed %d function(s)"):format(done))
      return false
    end

    announce("analysing", done, #order)
    return true
  end)
end

return M
