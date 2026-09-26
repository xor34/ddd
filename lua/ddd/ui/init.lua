-- ddd.ui -- what the ui scope registers into, and the context it hands out.
--
-- Views, commands and themes are registered globally rather than into whatever
-- interface happens to be running. That is deliberate: an interface is a host
-- that lays out whatever exists, so a plugin loaded years later can add a panel
-- to it without either of them knowing about the other. It is also what makes
-- two interfaces -- a window and a prompt -- able to offer the same commands.
--
-- The context is the other half. It is what a view or a command is given: the
-- session, where the user is, how to move, and how to say something happened.
-- Everything that draws reads it, and nothing that draws is in here.
local core = require "ddd.core"
local theme = require "ddd.ui.theme"

local M = {}

M.theme = theme
M.views = {}
M.commands = {}

-- Milliseconds, monotonically -- or as close as the standard library gets. An
-- interface with a real clock replaces this; nothing here may reach for a
-- toolkit to find one.
M.clock = function() return os.clock() * 1000 end

-- How much of a thing to put on screen before saying how much more there is.
--
-- Every one of these has a real case behind it: a string constant referenced
-- from four hundred places, a jump table with a thousand entries, a register
-- used on every line of a large function. Showing all of it is not thorough,
-- it is unreadable -- and the count that replaces the rest is the part that
-- was actually informative.
M.limits = {
  inline_xrefs = 6,  -- at a block label, in the listing
  rows = 300,        -- in a list: references, occurrences, data items
  functions = 3000,  -- in the function list, which is filtered instead
  -- Of a hexdump between functions. A backstop against a pathological image
  -- rather than a display decision: a data region is shown whole, because
  -- marking bytes as code is done by looking at them and anything not on the
  -- page cannot be clicked.
  gap_bytes = 256 * 1024,
}

-- How many listings to keep cached before evicting. A listing is a lot of
-- tokens, so this is a real budget, not a nicety.
local kCacheBudget = 400

-- How many of the least recently used entries to drop at once, when the budget
-- is exceeded. Evicting in a batch rather than one-at-a-time means eviction
-- happens rarely instead of on every listing past the budget.
local kCacheEvict = 200

local function replace_named(list, spec)
  for i, existing in ipairs(list) do
    if existing.name == spec.name then
      list[i] = spec
      return
    end
  end
  list[#list + 1] = spec
end

-- Registering the same name twice replaces, so a plugin can override a view or
-- a command it does not like without the original being removed from the tree.
function M.add_view(spec) replace_named(M.views, spec) end
function M.add_command(spec) replace_named(M.commands, spec) end

function M.views_at(place)
  local found = {}
  for _, view in ipairs(M.views) do
    if (view.place or "main") == place then found[#found + 1] = view end
  end
  table.sort(found, function(a, b) return (a.order or 50) < (b.order or 50) end)
  return found
end

function M.find_command(name)
  for _, command in ipairs(M.commands) do
    if command.name == name then return command end
  end
  return nil
end

-- A patch, not a replacement: a plugin that wants a different accent colour
-- should not have to restate the whole palette.
function M.set_theme(patch)
  local function merge(into, from)
    for key, value in pairs(from) do
      if type(value) == "table" and type(into[key]) == "table" then
        merge(into[key], value)
      else
        into[key] = value
      end
    end
  end
  merge(theme, patch)
end

-- ---- the context ---------------------------------------------------------

local Context = {}
Context.__index = Context

-- Where the user is. `addr` is the current address and `func` the function it
-- falls in, which is what almost everything on screen is about.
function Context:where() return self.addr, self.func end

function Context:on(event, handler)
  local handlers = self.handlers[event]
  if not handlers then
    handlers = {}
    self.handlers[event] = handlers
  end
  handlers[#handlers + 1] = handler
  return handler
end

function Context:emit(event, ...)
  for _, handler in ipairs(self.handlers[event] or {}) do
    -- A view that raises should not stop the rest of the window from being
    -- told what happened.
    local ok, problem = pcall(handler, self, ...)
    if not ok then self:log(("%s handler: %s"):format(event, problem)) end
  end
end

function Context:log(text)
  self.messages[#self.messages + 1] = text
  self:emit("log", text)
end

function Context:status(text)
  self.status_text = text
  self:emit("status", text)
end

-- ---- moving around -------------------------------------------------------

-- Where you are, for the history: the line the cursor is on, not the address
-- the last jump happened to land on.
--
-- Those are the same thing only until you move. Scrolling down forty lines and
-- following a call from there and pressing escape has to come back to that
-- call -- coming back to the top of the function you were in is coming back to
-- somewhere you have not been since you arrived, and then the call you were
-- reading has to be found again by hand.
local function standing_at(self)
  return self.focus or self.addr
end

-- Whether two addresses are different *places*.
--
-- The history is worth having only if going back goes somewhere else. Two
-- addresses in one function are one place: you can see both, and pressing
-- escape to move eleven lines is not what anybody means by back. Outside a
-- function -- a blob, a data region -- there is nothing to group by but
-- distance, and a screenful is the same rule by another route.
local kFarEnough = 512

local function elsewhere(self, from, to)
  if not from or not to then return true end

  local here = self.session.function_at(from)
  local there = self.session.function_at(to)
  if here and there then return here.addr ~= there.addr end
  if here or there then return true end

  return math.abs(to - from) > kFarEnough
end

-- Remembering one place, rather than every address on the way to it.
--
-- Jumping about inside a function -- following a branch, coming back, following
-- another -- is one entry that keeps moving, not eight. Otherwise getting out
-- of a function you have been reading for a minute is eight presses of escape,
-- each landing somewhere you can already see, which is the same as having no
-- history at all.
local function remember(self, list, addr)
  if not addr then return end

  local top = list[#list]
  if top and not elsewhere(self, top, addr) then
    list[#list] = addr
  else
    list[#list + 1] = addr
  end
end

-- Navigating somewhere records where you were, which is what makes going back
-- possible -- the single most-used thing in any disassembler.
function Context:navigate(addr, options)
  options = options or {}
  if not addr then return false end

  local from = standing_at(self)
  if from and from ~= addr and not options.replace then
    remember(self, self.history, from)
    self.future = {}
  end

  self.addr = addr
  self.focus = addr
  self.func = self.session.function_at(addr)
  self:emit("navigate", addr, self.func)
  return true
end

-- Anything that names a place: a symbol, a name the user chose, or a number.
function Context:navigate_to(what)
  local addr = tonumber(what) or self.session.resolve(what)
  if not addr then
    self:status(("cannot resolve %s"):format(what))
    return false
  end
  return self:navigate(addr)
end

function Context:back()
  local previous = table.remove(self.history)
  if not previous then return false end

  remember(self, self.future, standing_at(self))
  self.addr = previous
  self.focus = previous
  self.func = self.session.function_at(previous)
  self:emit("navigate", previous, self.func)
  return true
end

function Context:forward()
  local next_addr = table.remove(self.future)
  if not next_addr then return false end

  remember(self, self.history, standing_at(self))
  self.addr = next_addr
  self.focus = next_addr
  self.func = self.session.function_at(next_addr)
  self:emit("navigate", next_addr, self.func)
  return true
end

-- ---- what is there -------------------------------------------------------

-- What a listing is filed under.
--
-- Which printer ends the pipeline and whether the machine bookkeeping is shown
-- are part of what a listing *is*, so they are part of the key: two views of
-- one function are two listings, and switching between them should not re-run
-- the analysis every time.
local function cache_key(self, addr, options)
  local func = self.session.function_at(addr)
  local base = func and func.addr or addr

  local printer = options.printer or "hil"
  local machine = options.machine
  if machine == nil then machine = self.machine or false end

  return ("%d|%s|%s"):format(base, tostring(machine), printer)
end

-- The listing for `addr`, but only if it has already been analysed.
--
-- The difference between this and `listing` is most of how the window feels.
-- `listing` runs the pipeline, which takes however long the function takes, so
-- a view that calls it while painting cannot draw until it comes back -- and
-- painting a screenful means doing that several times over before a single
-- pixel changes. A view that asks for what is *ready* draws at once, shows
-- bytes for the rest, and says what it wanted; see `want` below.
function Context:ready(addr, options)
  addr = addr or self.addr
  if not addr then return nil end

  local key = cache_key(self, addr, options or {})
  local cached = self.cache[key]
  if cached and cached.generation == self.generation then
    self:touch(key)
    return cached.listing
  end
  return nil
end

-- Says a listing has just been read, for the eviction below.
--
-- What is worth keeping is what is being looked at, and the order listings were
-- *made* in says nothing about that: the analysis makes them in address order,
-- so on a binary with more functions than the budget the one on screen is
-- evicted for the sake of one nobody has opened -- and the view redraws it as
-- bytes. Reading one puts it back at the end of the queue.
function Context:touch(key)
  self.cached[#self.cached + 1] = key
end

-- What a view painted as bytes because there was no listing for it.
--
-- The background work drains this before its own queue: whatever is on screen
-- is what someone is waiting for, and the rest of the binary can be analysed
-- in whatever order it likes.
--
-- Asked for whether or not this function has been analysed before, because
-- those are different questions and the difference is visible: the cache is
-- bounded, so a function that was analysed an hour and four hundred listings
-- ago has been evicted, and a view that skipped it here because it was once
-- analysed would draw it as bytes and then wait for work nobody had queued.
-- Going somewhere and pressing escape is exactly that sequence. The background
-- queue still skips what has been analysed; this is only what is on screen.
function Context:want(addr)
  if not addr or self.wanted_set[addr] then return end

  self.wanted_set[addr] = true
  self.wanted[#self.wanted + 1] = addr
end

function Context:take_wanted()
  local addr = table.remove(self.wanted, 1)
  if not addr then return nil end

  self.wanted_set[addr] = nil
  return addr
end

-- The listing for whatever function `addr` is in, kept until something the
-- user did could have changed it. Navigating inside one function is the
-- commonest thing there is, and re-running the pipeline for each keystroke
-- would make the window feel like the thing this replaced.
function Context:listing(addr, options)
  addr = addr or self.addr
  if not addr then return nil end
  options = options or {}

  local key = cache_key(self, addr, options)
  local cached = self.cache[key]
  if cached and cached.generation == self.generation then
    self:touch(key)
    return cached.listing
  end

  local printer = options.printer or "hil"
  local machine = options.machine
  if machine == nil then machine = self.machine or false end

  local passes = options.passes or self.pipeline
  if printer ~= "hil" then
    passes = require("ddd.workflow").ending_in(passes, printer)
  end

  local listing = self.session.listing(addr, {
    passes = passes,
    machine = machine,
    tokens = options.tokens ~= false,
    verbose = options.verbose or false,
  })

  self.cache[key] = { generation = self.generation, listing = listing }
  self.cached[#self.cached + 1] = key

  -- Analysing a whole binary up front means a listing per function, and a
  -- listing is a lot of tokens. Keep the ones most recently read and let the
  -- rest go; a function that is wanted again is one analysis away.
  --
  -- `cached` is a log of mentions rather than a set, so a key is in it once per
  -- time it was made or read. The last mention of each is its age, and the
  -- entries with nothing but old mentions are the ones nobody has looked at.
  if #self.cached > kCacheBudget then
    local seen, recent = {}, {}
    for i = #self.cached, 1, -1 do
      local key = self.cached[i]
      if not seen[key] then
        seen[key] = true
        recent[#recent + 1] = key -- newest first
      end
    end

    local keep = kCacheBudget - kCacheEvict
    for i = keep + 1, #recent do self.cache[recent[i]] = nil end

    local kept = {}
    for i = math.min(keep, #recent), 1, -1 do kept[#kept + 1] = recent[i] end
    self.cached = kept
  end

  return listing
end

-- Something the user did at one address, rather than everywhere.
--
-- Almost every edit is local. Renaming a variable changes one function;
-- declaring a type changes one function; saying a stretch of bytes is a
-- function changes that function and the listings that mention it, which are
-- the ones that refer to it -- and what refers to an address is the one
-- question the reference index is a map for. Everything else in the binary
-- reads exactly as it did a moment ago, and throwing those listings away means
-- analysing the whole image again to redraw a line.
--
-- What survives is the point: the map keeps its colours, the background queue
-- stays empty, and the window comes back on the next frame instead of on the
-- next sweep.
function Context:invalidate_at(addr)
  if not addr then return self:invalidate() end

  local touched = {}
  local function touch(at)
    if not at then return end
    local func = self.session.function_at(at)
    touched[func and func.addr or at] = true
  end

  touch(addr)
  for _, ref in ipairs(self.session.xrefs(addr) or {}) do touch(ref.from) end

  -- The cache is keyed by function, then by how it is being shown, so what has
  -- to go is every key that begins with one of these addresses.
  local kept = {}
  for _, key in ipairs(self.cached) do
    local base = tonumber(key:match("^(%-?%d+)|"))
    if base and touched[base] then
      self.cache[key] = nil
    else
      kept[#kept + 1] = key
    end
  end
  self.cached = kept

  -- "Analysed" means "there is a listing for it", so the two go together: the
  -- map greys these out, and the background queue picks them up again.
  for base in pairs(touched) do self.analysed[base] = nil end

  self:emit("invalidate")
  self:emit("refresh")
end

-- The same thing when the change was not local: a new region, a different
-- instruction set, a sweep that has just found every function in the image.
--
-- Nothing that was analysed still is: the cache is what "analysed" means, and
-- a function whose listing has been thrown away has to go through the pipeline
-- again before it can be drawn as code. So the map greys out and colours back
-- in, and the background queue -- which skips whatever is already analysed --
-- refills with the whole binary rather than with nothing.
function Context:invalidate()
  self.generation = self.generation + 1
  self.cache = {}
  self.cached = {}
  self.analysed = {}
  self.wanted, self.wanted_set = {}, {}
  self:emit("invalidate")
  self:emit("refresh")
end

function Context:refresh() self:emit("refresh") end

-- ---- doing things --------------------------------------------------------

function Context:commands_available()
  local found = {}
  for _, command in ipairs(M.commands) do
    if not command.when or command.when(self) then found[#found + 1] = command end
  end
  table.sort(found, function(a, b)
    return (a.title or a.name) < (b.title or b.name)
  end)
  return found
end

function Context:run(name, ...)
  -- When the user last did something. Background work reads this and gets out
  -- of the way: an edit invalidates the reference index, and rebuilding it
  -- must not be queued in front of the next keystroke.
  self.last_action = M.clock()

  local command = M.find_command(name)
  if not command then
    self:status(("no command called %s"):format(name))
    return false
  end

  local ok, problem = pcall(command.run, self, ...)
  if not ok then
    self:status(("%s: %s"):format(name, problem))
    self:log(("%s: %s"):format(name, problem))
    return false
  end
  return true
end

-- key -> command, for whichever interface binds keys.
function Context:keymap()
  local map = {}
  for _, command in ipairs(M.commands) do
    if command.key then map[command.key] = command end
  end
  return map
end

function Context:quit() self:emit("quit") end

-- ---- building it ---------------------------------------------------------

function M.context(options)
  options = options or {}

  local session = core.session
  if not session then
    error("no image is loaded: an interface needs --file or --bytes", 2)
  end

  local pipeline = options.pipeline
  if type(pipeline) == "string" then
    pipeline = require("ddd.workflow").pipeline(pipeline)
  end
  pipeline = pipeline or require("ddd.workflow").pipeline()

  local context = setmetatable({
    session = session,
    workflow = options.workflow,
    interface = options.interface,
    pipeline = pipeline,
    theme = theme,
    views = M.views,
    commands = M.commands,

    addr = nil,
    func = nil,
    history = {},
    future = {},

    handlers = {},
    messages = {},
    status_text = "",

    cache = {},
    cached = {},   -- keys in the order they were added, for eviction
    generation = 0,

    analysed = {},    -- function address -> it has been through the pipeline
    wanted = {},      -- addresses a view is waiting for, in the order asked
    wanted_set = {},
  }, Context)

  -- Deliberately *not* analysing anything here. Indexing the references and
  -- working out where the functions are is a sweep of the whole image, and
  -- doing it before the window exists means staring at nothing while it
  -- happens. An interface starts empty, puts itself on screen, and fills in --
  -- see plugins/studio/analysis.lua.
  local info = session.info()
  context.info = info
  if info.entry and info.entry ~= 0 then
    context:navigate(info.entry, { replace = true })
  end

  return context
end

M.Context = Context

return M
