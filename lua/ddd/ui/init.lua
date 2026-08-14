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

-- Navigating somewhere records where you were, which is what makes going back
-- possible -- the single most-used thing in any disassembler.
function Context:navigate(addr, options)
  options = options or {}
  if not addr then return false end

  if self.addr and self.addr ~= addr and not options.replace then
    self.history[#self.history + 1] = self.addr
    self.future = {}
  end

  self.addr = addr
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

  self.future[#self.future + 1] = self.addr
  self.addr = previous
  self.func = self.session.function_at(previous)
  self:emit("navigate", previous, self.func)
  return true
end

function Context:forward()
  local next_addr = table.remove(self.future)
  if not next_addr then return false end

  self.history[#self.history + 1] = self.addr
  self.addr = next_addr
  self.func = self.session.function_at(next_addr)
  self:emit("navigate", next_addr, self.func)
  return true
end

-- ---- what is there -------------------------------------------------------

-- The listing for whatever function `addr` is in, kept until something the
-- user did could have changed it. Navigating inside one function is the
-- commonest thing there is, and re-running the pipeline for each keystroke
-- would make the window feel like the thing this replaced.
function Context:listing(addr, options)
  addr = addr or self.addr
  if not addr then return nil end
  options = options or {}

  local func = self.session.function_at(addr)
  local base = func and func.addr or addr

  -- Which printer ends the pipeline and whether the machine bookkeeping is
  -- shown are part of what a listing *is*, so they are part of the key: two
  -- views of one function are two listings, and switching between them should
  -- not re-run the analysis every time.
  local printer = options.printer or "hil"
  local machine = options.machine
  if machine == nil then machine = self.machine or false end

  local key = ("%d|%s|%s"):format(base, tostring(machine), printer)
  local cached = self.cache[key]
  if cached and cached.generation == self.generation then return cached.listing end

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
  return listing
end

-- Something the user did that the analysis has to be re-run to show: a rename,
-- a comment, a declared type.
function Context:invalidate()
  self.generation = self.generation + 1
  self.cache = {}
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
    generation = 0,
  }, Context)

  -- Before anything asks what functions there are. A file whose symbol table
  -- was stripped has none until this has run, and every analysis downstream is
  -- per-function -- so without it the interface would be showing one enormous
  -- "function" whose listing is unreadable for reasons that look like bugs in
  -- the passes.
  session.discover_functions()

  local info = session.info()
  context.info = info
  if info.entry and info.entry ~= 0 then
    context:navigate(info.entry, { replace = true })
  end

  return context
end

M.Context = Context

return M
