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
local kMaxRows = 3000

function M.build(ui)
  local self = { ui = ui }

  local search = Gtk.SearchEntry { placeholder_text = "Filter functions" }
  search:add_css_class("ddd-search")
  search.margin_top = 6
  search.margin_bottom = 6
  search.margin_start = 8
  search.margin_end = 8

  local list = gtk.list(function(item) ui:navigate(item.addr) end)

  local count = gtk.label("", { "ddd-muted", "ddd-mono" })
  count.margin_start = 10
  count.margin_bottom = 4

  local function fill(pattern)
    list:clear()

    local functions = ui.session.functions(pattern or "")
    local shown = math.min(#functions, kMaxRows)

    for index = 1, shown do
      local func = functions[index]
      list:add(("<span foreground='%s'>%08x</span>  %s")
        :format(ui.theme.token.address, func.addr,
                ddd.format.escape(func.name)), func)
    end

    if #functions > shown then
      count.label = ("%d functions, %d shown"):format(#functions, shown)
    else
      count.label = ("%d function%s"):format(#functions, #functions == 1 and "" or "s")
    end
  end

  search.on_search_changed = function() fill(search.text) end

  local box = gtk.box(Gtk.Orientation.VERTICAL)
  box:append(search)
  box:append(gtk.scrolled(list.widget))
  box:append(count)

  fill()

  -- Following a call should move the selection here too, or the list stops
  -- agreeing with the listing about where you are.
  ui:on("navigate", function(_, _, func)
    if not func then return end
    for index, item in ipairs(list.items) do
      if item.addr == func.addr then
        list:select(index)
        return
      end
    end
  end)

  ui:on("invalidate", function() fill(search.text) end)

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
