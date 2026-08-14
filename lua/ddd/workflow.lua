-- ddd.workflow -- what a plugin declares, and the scopes it declares it in.
--
-- A workflow is a name and a set of scopes. Each scope hands its contents a
-- context and puts them somewhere the tool will find them:
--
--   passes  -- runs during analysis, given a pass context: the function, the
--             image, the symbols, and somewhere to record what it worked out.
--             What it registers goes in the same registry as the C++ passes,
--             so --passes can name it and --list_passes prints it.
--
--   ui      -- runs inside an interface, given a UI context: the session, where
--             the user is, and how to move. What it registers is what an
--             interface draws; nothing here draws anything itself.
--
-- Scopes are functions rather than tables so that what they hand you is
-- lexically scoped: `scope.pass` exists inside `passes` and nowhere else,
-- which is the difference between a DSL and a pile of globals.
local core = require "ddd.core"
local ui = require "ddd.ui"

local M = {}

local registry = {}
local order = {}

-- Named sequences of passes. A workflow that arranges an analysis is mostly
-- deciding on one of these.
local pipelines = {}

local function check(condition, message, ...)
  if not condition then error(string.format(message, ...), 3) end
end

-- ---- the passes scope ----------------------------------------------------

-- Builds the run function a pass registers, from whichever of the three shapes
-- it was written in. `run` is the whole thing; `each_op` and `each_value` are
-- what most small analyses actually are, and spelling out the loop every time
-- adds nothing.
local function runner(name, spec)
  if spec.run then return spec.run end

  check(spec.each_op or spec.each_value,
        "pass %q needs a run, an each_op or an each_value", name)

  return function(fn, ctx)
    if spec.before then spec.before(fn, ctx) end

    if spec.each_op then
      for op in fn:ops() do spec.each_op(op, fn, ctx) end
    end
    if spec.each_value then
      for value in fn:values() do spec.each_value(value, fn, ctx) end
    end

    if spec.after then spec.after(fn, ctx) end
  end
end

local function pass_scope(workflow)
  local scope = {}

  -- scope.pass "name" { description = ..., run = function(fn, ctx) end }
  function scope.pass(name)
    check(type(name) == "string", "a pass is named with a string")

    return function(spec)
      check(type(spec) == "table", "pass %q needs a table", name)

      core.register_pass {
        name = name,
        description = spec.description or "",
        run = runner(name, spec),
      }

      workflow.passes[#workflow.passes + 1] = {
        name = name,
        description = spec.description or "",
      }
      return name
    end
  end

  -- scope.pipeline "default" { "stack-vars", "idioms", ... }
  --
  -- Order is the whole content of a pipeline: everything that annotates has to
  -- run before whatever renders, and the naming passes have to run after the
  -- analyses whose names they override.
  function scope.pipeline(name)
    check(type(name) == "string", "a pipeline is named with a string")

    return function(list)
      check(type(list) == "table", "pipeline %q needs a list of pass names", name)
      pipelines[name] = list
      workflow.pipelines[name] = list
      return list
    end
  end

  return scope
end

-- ---- the ui scope --------------------------------------------------------

local function ui_scope(workflow)
  local scope = {}

  -- scope.interface "studio" { description = ..., run = function(ctx) end }
  --
  -- An entry point --ui can name. Its run gets the UI context, built fresh for
  -- the run so that nothing survives between two of them.
  function scope.interface(name)
    check(type(name) == "string", "an interface is named with a string")

    return function(spec)
      check(type(spec.run) == "function", "interface %q needs a run", name)

      core.register_ui {
        name = name,
        description = spec.description or "",
        workflow = workflow.name,
        run = function()
          return spec.run(ui.context {
            workflow = workflow,
            interface = name,
            pipeline = spec.pipeline,
          })
        end,
      }

      workflow.interfaces[name] = spec
      return name
    end
  end

  -- scope.view "functions" { title = ..., place = "left", build = f }
  --
  -- A panel. Registered globally rather than per-interface, so a plugin can add
  -- one to an interface written before it existed -- which is the whole reason
  -- the interface is a host and not a layout.
  function scope.view(name)
    check(type(name) == "string", "a view is named with a string")

    return function(spec)
      spec.name = name
      spec.workflow = workflow.name
      ui.add_view(spec)
      workflow.views[#workflow.views + 1] = spec
      return name
    end
  end

  -- scope.command "rename" { title = ..., key = "n", run = function(ctx) end }
  --
  -- Everything a person can ask for: what the palette lists, and what a key
  -- binding is bound to.
  function scope.command(name)
    check(type(name) == "string", "a command is named with a string")

    return function(spec)
      spec.name = name
      spec.workflow = workflow.name
      ui.add_command(spec)
      workflow.commands[#workflow.commands + 1] = spec
      return name
    end
  end

  -- scope.theme { ... } -- colours and CSS, merged over what is there.
  function scope.theme(patch)
    check(type(patch) == "table", "a theme is a table")
    ui.set_theme(patch)
  end

  return scope
end

-- ---- declaring -----------------------------------------------------------

local scopes = { passes = pass_scope, ui = ui_scope }

function M.declare(name)
  check(type(name) == "string", "a workflow is named with a string")

  return function(spec)
    check(type(spec) == "table", "workflow %q needs a table of scopes", name)

    local workflow = registry[name]
    if not workflow then
      workflow = {
        name = name,
        passes = {},
        pipelines = {},
        views = {},
        commands = {},
        interfaces = {},
      }
      registry[name] = workflow
      order[#order + 1] = workflow
    end

    workflow.description = spec.description or workflow.description

    -- Misspelling a scope should say so rather than silently doing nothing,
    -- which is the failure mode every declarative interface has.
    for key in pairs(spec) do
      check(key == "description" or scopes[key],
            "workflow %q has no scope called %q", name, tostring(key))
    end

    -- In a fixed order, not the table's: the ui scope may name a pipeline the
    -- passes scope declares.
    for _, scope in ipairs { "passes", "ui" } do
      if spec[scope] then
        check(type(spec[scope]) == "function",
              "the %s scope of workflow %q is a function taking its scope",
              scope, name)
        spec[scope](scopes[scope](workflow), workflow)
      end
    end

    return workflow
  end
end

function M.all() return order end

function M.find(name) return registry[name] end

-- A named pipeline, or the one the command line asked for. An interface asks
-- for this rather than hardcoding a list, so --passes still means something
-- when a window is open.
function M.pipeline(name)
  if name and pipelines[name] then return pipelines[name] end
  if name == nil then
    local from_flags = core.default_passes()
    if from_flags and #from_flags > 0 then return from_flags end
    return pipelines.default
  end
  return nil
end

-- The same pipeline, rendered differently: everything that annotates, then one
-- printer instead of another. This is how an interface offers the folded
-- listing and the raw SSA without either being a separate pipeline that would
-- then have to be kept in step with --passes.
function M.ending_in(pipeline, printer)
  local out = {}
  for _, name in ipairs(pipeline or M.pipeline()) do
    if name ~= "hil" and name ~= "print-ssa" then out[#out + 1] = name end
  end
  out[#out + 1] = printer
  return out
end

M.pipelines = pipelines

return M
