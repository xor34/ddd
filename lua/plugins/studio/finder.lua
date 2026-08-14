-- Jump to a function, from a box over the middle of the window.
--
-- The function list down the side is for reading; this is for going somewhere
-- you can already name. Type part of a name, press enter, be there -- which in
-- a binary with three thousand functions is the difference between navigating
-- and hunting.
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local Gtk, Gdk = gtk.Gtk, gtk.Gdk

local M = {}

function M.open(ui)
  local window = Gtk.Window {
    transient_for = ui.window,
    modal = true,
    decorated = false,
    default_width = 620,
    default_height = 420,
  }
  window:add_css_class("ddd")

  local search = Gtk.SearchEntry { placeholder_text = "Function name or address" }
  search.margin_top = 8
  search.margin_bottom = 8
  search.margin_start = 8
  search.margin_end = 8

  local heading = gtk.label("", { "ddd-muted", "ddd-mono" })
  heading.margin_start = 10
  heading.margin_bottom = 4

  local list

  local function go(item)
    window:close()
    if item and item.addr then ui:navigate(item.addr) end
  end

  list = gtk.list(go)

  local limit = ddd.ui.limits.rows

  local function fill(pattern)
    list:clear()

    local functions = ui.session.functions(pattern or "")
    local shown = math.min(#functions, limit)

    for index = 1, shown do
      local func = functions[index]
      list:add(("<span foreground='%s'>%08x</span>  %s")
        :format(ui.theme.token.address, func.addr,
                ddd.format.escape(func.name)), func)
    end

    if #functions > shown then
      heading.label = ("%d functions, %d shown"):format(#functions, shown)
    else
      heading.label = ("%d function%s"):format(#functions,
                                               #functions == 1 and "" or "s")
    end
    list:select(1)
  end

  search.on_search_changed = function() fill(search.text) end

  search.on_activate = function()
    -- An address typed in goes there, whether or not it is a function: this is
    -- also the quickest way to reach one.
    local typed = search.text
    local addr = tonumber(typed) or (typed ~= "" and ui.session.resolve(typed))

    local row = list.widget:get_selected_row()
    local item = row and list.items[row:get_index() + 1] or list.items[1]

    if item then
      go(item)
    elseif addr then
      window:close()
      ui:navigate(addr)
    end
  end

  local keys = Gtk.EventControllerKey()
  keys.on_key_pressed = function(_, keyval)
    local name = Gdk.keyval_name(keyval)
    if name == "Escape" then
      window:close()
      return true
    end
    if name == "Down" or name == "Up" then
      local row = list.widget:get_selected_row()
      local index = row and row:get_index() or -1
      local next_row =
        list.widget:get_row_at_index(index + (name == "Down" and 1 or -1))
      if next_row then list.widget:select_row(next_row) end
      return true
    end
    return false
  end
  window:add_controller(keys)

  local box = gtk.box(Gtk.Orientation.VERTICAL)
  box:append(search)
  box:append(heading)
  box:append(gtk.scrolled(list.widget))
  window:set_child(box)

  fill()
  window:present()
  search:grab_focus()
  return window
end

return M
