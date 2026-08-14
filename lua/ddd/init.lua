-- ddd -- the Lua side of the decompiler.
--
-- Everything above the engines lives here. The C++ binary lifts p-code, builds
-- the CFG, puts it in SSA form, solves dataflow and folds expressions; what any
-- of that *means* -- which analyses run, what an idiom is, what a window looks
-- like -- is decided in Lua, because that is the part that is opinion rather
-- than machinery.
--
-- A plugin says what it contributes by declaring a workflow:
--
--     local ddd = require "ddd"
--
--     ddd.workflow "readability" {
--       passes = function(scope)
--         scope.pass "zeroing" {
--           description = "point out registers being zeroed",
--           each_op = function(op, fn, ctx)
--             if op.opcode == "INT_XOR" then ctx:comment(op, "always 0") end
--           end,
--         }
--       end,
--
--       ui = function(scope)
--         scope.view "strings" {
--           title = "Strings",
--           place = "right",
--           build = function(ui) ... end,
--         }
--       end,
--     }
--
-- The two scopes are the two halves of the tool. `passes` runs inside the
-- analysis and is handed a pass context: the function, and everything that can
-- be said about it. `ui` runs inside an interface and is handed a UI context:
-- the session, where the user is, and what they can do next. Neither knows the
-- other exists.
local core = require "ddd.core"

local M = {}

M.core = core

-- The p-code matcher, and the opcode names to write patterns against.
M.pat = core.pat
M.opcodes = core.opcodes

-- "What was in this register here?" -- the one question SSA cannot answer on
-- its own, because a CALL never names the registers it is passing.
M.reaching = core.reaching

-- Adding methods to a bound type: ddd.extend("context", { ... }) gives every
-- pass in the process a new way to ask a question.
M.extend = core.extend

-- What is registered, whoever registered it.
M.passes = core.passes
M.interfaces = core.uis
M.default_passes = core.default_passes

local workflow = require "ddd.workflow"

-- ddd.workflow "name" { passes = ..., ui = ... }
--
-- Naming a workflow that already exists adds to it, so two plugins can
-- contribute passes to the same one without either knowing about the other.
M.workflow = workflow.declare
M.workflows = workflow.all
M.pipeline = workflow.pipeline

M.ui = require "ddd.ui"
M.format = require "ddd.format"

-- `ddd.session` is nil until an image is loaded, and a plugin is allowed to be
-- loaded before one is -- so it is looked up on each access rather than
-- captured here, where it would be nil forever.
setmetatable(M, {
  __index = function(_, key)
    if key == "session" then return core.session end
    return nil
  end,
})

-- Plugins are small and there are a lot of them; making them all write the
-- same require line first is not worth the purity.
_G.ddd = M

return M
