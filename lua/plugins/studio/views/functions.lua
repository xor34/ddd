-- The function list.
--
-- The first thing anyone does with a binary is find out what is in it, and the
-- second is go somewhere. Filtering is on the name as it stands, so a function
-- the user has renamed is found under the name they gave it.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local Gtk = gtk.Gtk

local M = {}

-- Long enough to be everything in most binaries and short enough that building
-- the rows stays instant; the filter is how you find one in a big one.
local kMaxRows = ddd.ui.limits.functions

function M.build(ui)
  local self = { ui = ui }

  local sl = gtk.searchable_list(function(item) ui:navigate(item.addr) end, {
    placeholder = "Filter functions",
    noun = "function",
    limit = kMaxRows,

    items = function(pattern) return ui.session.functions(pattern or "") end,

    row = function(func)
      return ("<span foreground='%s'>%08x</span>  %s")
        :format(ui.theme.token.address, func.addr, ddd.format.escape(func.name))
    end,
  })

  local box = gtk.box(Gtk.Orientation.VERTICAL)
  box:append(sl.search)
  box:append(gtk.scrolled(sl.list.widget))
  box:append(sl.count)

  sl.fill()

  -- Following a call should move the selection here too, or the list stops
  -- agreeing with the listing about where you are.
  ui:on("navigate", function(_, _, func)
    if not func then return end
    for index, item in ipairs(sl.list.items) do
      if item.addr == func.addr then
        sl.list:select(index)
        return
      end
    end
  end)

  ui:on("invalidate", function() sl.fill(sl.search.text) end)

  self.widget = box
  return self
end

ddd.workflow "studio" {
  ui = function(scope)
    scope.view "functions" {
      title = "Functions",
      place = "left",
      order = 10,
      build = function(ui) return M.build(ui).widget end,
    }
  end,
}

return M
