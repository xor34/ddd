-- What refers to this.
--
-- Not a panel. A panel is showing you the answer to a question you did not ask,
-- taking a third of the window to do it, and it is stale the moment you look
-- somewhere else. This is the question asked deliberately -- `x` -- answered
-- over whatever is selected, and dismissed with escape.
--
-- Three things can be selected and all three have references worth having:
--
--   * an address, or a function: what calls or branches to it, from the index
--   * data: the same, which is how a literal pool entry tells you which load
--     reads it
--   * a variable: everywhere it appears in the listing, which is the same
--     question asked of a value rather than of a place
local gtk = require "plugins.studio.gtk"
local ddd = require "ddd"

local Gtk, Gdk = gtk.Gtk, gtk.Gdk

local M = {}

local function rows_for(ui, options)
  local theme = ui.theme.token

  -- A variable: every place it appears in what is on screen.
  if options.id and ui.listing_view then
    local rows = {}
    for _, place in ipairs(ui.listing_view:occurrences(options.id)) do
      rows[#rows + 1] = {
        addr = place.from,
        markup = ("<span foreground='%s'>%08x</span>  <span foreground='%s'>%s</span>")
          :format(theme.address, place.from or 0, theme.var, options.id),
      }
    end
    return rows, ("%d occurrence(s) of %s"):format(#rows, options.id)
  end

  local addr = options.addr
  if not addr then return {}, "nothing selected" end

  local rows = {}
  for _, ref in ipairs(ui.session.xrefs(addr)) do
    rows[#rows + 1] = {
      addr = ref.from,
      markup = ("<span foreground='%s'>%08x</span>  <span foreground='%s'>%-6s</span> %s")
        :format(theme.address, ref.from, theme.xref, ref.kind,
                ddd.format.escape(ref["in"] ~= "" and ref["in"] or "")),
    }
  end

  local func = ui.session.function_at(addr)
  local what = func and func.name or ddd.format.addr(addr)
  return rows, ("%d reference(s) to %s"):format(#rows, what)
end

function M.open(ui, options)
  options = options or {}
  ui.session.build_xrefs()

  local rows, heading = rows_for(ui, options)

  local window = Gtk.Window {
    transient_for = ui.window,
    modal = true,
    title = heading,
    default_width = 560,
    default_height = 360,
  }
  window:add_css_class("ddd")

  local label = gtk.label(heading, { "ddd-title" })

  local list = gtk.list(function(item)
    window:close()
    if item.addr then ui:navigate(item.addr) end
  end)

  for _, row in ipairs(rows) do list:add(row.markup, row) end
  if #rows == 0 then list:add("<i>nothing</i>", {}) end
  list:select(1)

  local keys = Gtk.EventControllerKey()
  keys.on_key_pressed = function(_, keyval)
    local name = Gdk.keyval_name(keyval)
    if name == "Escape" or name == "x" or name == "q" then
      window:close()
      return true
    end
    if name == "Return" or name == "KP_Enter" then
      local selected = list.widget:get_selected_row()
      local item = selected and list.items[selected:get_index() + 1]
      window:close()
      if item and item.addr then ui:navigate(item.addr) end
      return true
    end
    return false
  end
  window:add_controller(keys)

  local box = gtk.box(Gtk.Orientation.VERTICAL)
  box:append(label)
  box:append(gtk.scrolled(list.widget))
  window:set_child(box)

  window:present()
  list.widget:grab_focus()
  return window
end

return M
