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
-- Two rules make it stay out of the way:
--
--   * each tick works to a deadline rather than to a count of items. A count is
--     wrong at both ends: four small functions is a wasted frame, four large
--     ones is a visible stall.
--   * anything the user just did wins. Marking bytes as code invalidates the
--     reference index, and the work to rebuild it must not be queued in front
--     of the keystroke that comes next.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local GLib = gtk.GLib

-- The window has a monotonic clock; the shared library is not allowed to know
-- about one, so it is handed over here.
ddd.ui.clock = function() return GLib.get_monotonic_time() / 1000 end

local M = {}

-- Milliseconds of work per tick. Long enough to make progress, short enough
-- that a keystroke lands in the same frame it was pressed.
local kBudget = 12

-- How long to leave the background alone after the user does something. Long
-- enough to cover the re-render an edit causes, short enough not to feel like
-- the analysis has stopped.
local kYield = 250

-- How often to look for new work once there is none: an edit invalidates the
-- index, and this is what notices.
local kIdlePoll = 700

local function now() return ddd.ui.clock() end

function M.start(ui)
  ui.analysed = ui.analysed or {}
  ui.progress = { stage = "starting", done = 0, total = 0 }

  local function announce(stage, done, total, message)
    ui.progress = { stage = stage, done = done, total = total }
    ui:emit("analysis", ui.progress)
    if message then ui:status(message) end
  end

  -- The functions still to put through the pipeline, rebuilt whenever the set
  -- of functions changes.
  local queue, at = {}, 1

  local function refill()
    queue, at = {}, 1

    local here = ui.focus or ui.addr
    local first = here and ui.session.function_at(here)
    if first and not ui.analysed[first.addr] then
      queue[#queue + 1] = first.addr
    end

    for _, func in ipairs(ui.session.functions()) do
      if not ui.analysed[func.addr]
         and not (first and func.addr == first.addr) then
        queue[#queue + 1] = func.addr
      end
    end
  end

  local sweeping = true

  GLib.timeout_add(GLib.PRIORITY_LOW, 16, function()
    -- Whatever the user just did comes first. This is a single thread: the
    -- only way to service them before the queue is to get out of the way.
    if ui.last_action and now() - ui.last_action < kYield then
      return true
    end

    local deadline = now() + kBudget

    -- Phase one: references, then function boundaries. Both are sweeps of the
    -- image, and both hand back control between slices. An edit puts this back
    -- into `sweeping` -- the index it invalidated has to be rebuilt, and the
    -- one already there answers questions meanwhile.
    if sweeping then
      local step
      repeat
        step = ui.session.analyse_step(1500)
      until step.finished or now() >= deadline

      announce(step.stage, step.done, step.total)
      if not step.finished then return true end

      sweeping = false
      ui:invalidate()
      refill()
      announce("analysing", 0, #queue)
      return true
    end

    -- Phase two: each function through the pipeline. Asking for the listing is
    -- what runs it; the context keeps it, so looking at that function later is
    -- instant.
    if at <= #queue then
      repeat
        local addr = queue[at]
        at = at + 1

        if addr then
          local ok, listing = pcall(ui.listing, ui, addr)
          if ok and listing and listing.ok then ui.analysed[addr] = true end
        end
      until at > #queue or now() >= deadline

      announce("analysing", at - 1, #queue)
      if at > #queue then
        announce("done", #queue, #queue,
                 ("analysed %d function(s)"):format(#queue))
      end
      return true
    end

    -- Nothing to do. An edit will have invalidated the index, which
    -- analyse_step reports by not being finished; look again shortly rather
    -- than spinning.
    local step = ui.session.analyse_step(1)
    if not step.finished then
      sweeping = true
      return true
    end

    refill()
    if #queue > 0 then return true end

    GLib.timeout_add(GLib.PRIORITY_LOW, kIdlePoll, function()
      sweeping = true
      M.start(ui)
      return false
    end)
    return false
  end)
end

return M
